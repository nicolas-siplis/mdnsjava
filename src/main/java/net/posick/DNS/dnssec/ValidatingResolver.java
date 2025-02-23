// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2005 VeriSign. All rights reserved.
// Copyright (c) 2013-2021 Ingo Bauersachs
package net.posick.DNS.dnssec;

import static java.util.concurrent.CompletableFuture.completedFuture;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import net.posick.DNS.CNAMERecord;
import net.posick.DNS.DClass;
import net.posick.DNS.DNAMERecord;
import net.posick.DNS.EDNSOption;
import net.posick.DNS.EDNSOption.Code;
import net.posick.DNS.ExtendedErrorCodeOption;
import net.posick.DNS.ExtendedFlags;
import net.posick.DNS.Flags;
import net.posick.DNS.Header;
import net.posick.DNS.Master;
import net.posick.DNS.Message;
import net.posick.DNS.NSECRecord;
import net.posick.DNS.Name;
import net.posick.DNS.NameTooLongException;
import net.posick.DNS.OPTRecord;
import net.posick.DNS.Rcode;
import net.posick.DNS.Record;
import net.posick.DNS.Resolver;
import net.posick.DNS.Section;
import net.posick.DNS.SimpleResolver;
import net.posick.DNS.TSIG;
import net.posick.DNS.TXTRecord;
import net.posick.DNS.Type;
import net.posick.DNS.dnssec.R;
import net.posick.DNS.dnssec.SecurityStatus;
import net.posick.DNS.dnssec.ValUtils.NsecProvesNodataResponse;

/**
 * This resolver validates responses with DNSSEC.
 *
 * @since 3.5
 */
@Slf4j
public final class ValidatingResolver implements Resolver {
  /**
   * The QCLASS being used for the injection of the reason why the validator came to the returned
   * result.
   */
  public static final int VALIDATION_REASON_QCLASS = 65280;

  /** This is the TTL to use when a trust anchor priming query failed to validate. */
  private static final long DEFAULT_TA_BAD_KEY_TTL = 60;

  /** This is a cache of validated, but expirable DNSKEY rrsets. */
  private final net.posick.DNS.dnssec.KeyCache keyCache;

  /**
   * A data structure holding all trust anchors. Trust anchors must be "primed" into the cache
   * before being used to validate.
   */
  private final net.posick.DNS.dnssec.TrustAnchorStore trustAnchors;

  /** The local validation utilities. */
  private final net.posick.DNS.dnssec.ValUtils valUtils;

  /** The local NSEC3 validation utilities. */
  private final net.posick.DNS.dnssec.NSEC3ValUtils n3valUtils;

  /** The resolver that performs the actual DNS lookups. */
  private final Resolver headResolver;

  /** The clock used to validate messages. */
  private final Clock clock;

  /**
   * If {@code true}, an additional record with the validation reason is added to the {@link
   * Section#ADDITIONAL} section. The record is available at {@code ./TXT/}{@value
   * #VALIDATION_REASON_QCLASS}.
   */
  @Getter @Setter private boolean isAddReasonToAdditional = true;

  /**
   * Creates a new instance of this class.
   *
   * @param headResolver The resolver to which queries for DS, DNSKEY and referring CNAME records
   *     are sent.
   */
  public ValidatingResolver(Resolver headResolver) {
    this(headResolver, Clock.systemUTC());
  }

  /**
   * Creates a new instance of this class.
   *
   * @param headResolver The resolver to which queries for DS, DNSKEY and referring CNAME records
   *     are sent.
   * @param clock the Clock to validate messages.
   */
  public ValidatingResolver(Resolver headResolver, Clock clock) {
    this.headResolver = headResolver;
    this.clock = clock;
    headResolver.setEDNS(0, 0, ExtendedFlags.DO);
    headResolver.setIgnoreTruncation(false);

    this.keyCache = new net.posick.DNS.dnssec.KeyCache();
    this.valUtils = new net.posick.DNS.dnssec.ValUtils();
    this.n3valUtils = new net.posick.DNS.dnssec.NSEC3ValUtils();
    this.trustAnchors = new net.posick.DNS.dnssec.TrustAnchorStore();
    try {
      init(System.getProperties());
    } catch (IOException e) {
      log.error("Could not initialize from system properties", e);
    }
  }

  // ---------------- Module Initialization -------------------

  /**
   * Initialize the module. Recognized configuration values:
   *
   * <dl>
   *   <dt>dnsjava.dnssec.trust_anchor_file
   *   <dd>A filename from where to load the trust anchors
   * </dl>
   *
   * See links for other initialized classes and their configuration values (or the readme).
   *
   * @see net.posick.DNS.dnssec.KeyCache#init(Properties)
   * @see net.posick.DNS.dnssec.ValUtils#init(Properties)
   * @see net.posick.DNS.dnssec.NSEC3ValUtils#init(Properties)
   * @param config The configuration data for this module.
   * @throws IOException When the file specified in the config does not exist or cannot be read.
   */
  public void init(Properties config) throws IOException {
    this.keyCache.init(config);
    this.n3valUtils.init(config);
    this.valUtils.init(config);

    // Load trust anchors
    String s = config.getProperty("dnsjava.dnssec.trust_anchor_file");
    if (s != null) {
      log.debug("Reading trust anchor file: {}", s);
      this.loadTrustAnchors(new FileInputStream(s));
    }
  }

  /**
   * Load the trust anchor file into the trust anchor store. The trust anchors are currently stored
   * in a zone file format list of DNSKEY or DS records.
   *
   * @param data The trust anchor data.
   * @throws IOException when the trust anchor data could not be read.
   */
  public void loadTrustAnchors(InputStream data) throws IOException {
    // First read in the whole trust anchor file.
    List<Record> records = new ArrayList<>();
    try (Master master = new Master(data, Name.root, 0)) {
      Record mr;
      while ((mr = master.nextRecord()) != null) {
        records.add(mr);
      }
    }

    // Record.compareTo() should sort them into DNSSEC canonical order.
    // Don't care about canonical order per se, but do want them to be
    // formable into RRsets.
    Collections.sort(records);

    net.posick.DNS.dnssec.SRRset currentRrset = new net.posick.DNS.dnssec.SRRset();
    for (Record r : records) {
      // Skip RR types that cannot be used as trust anchors.
      if (r.getType() != Type.DNSKEY && r.getType() != Type.DS) {
        continue;
      }

      // If our current set is empty, we can just add it.
      if (currentRrset.size() == 0) {
        currentRrset.addRR(r);
        continue;
      }

      // If this record matches our current RRset, we can just add it.
      if (currentRrset.getName().equals(r.getName())
          && currentRrset.getType() == r.getType()
          && currentRrset.getDClass() == r.getDClass()) {
        currentRrset.addRR(r);
        continue;
      }

      // Otherwise, we add the rrset to our set of trust anchors and begin
      // a new set
      this.trustAnchors.store(currentRrset);
      currentRrset = new net.posick.DNS.dnssec.SRRset();
      currentRrset.addRR(r);
    }

    // add the last rrset (if it was not empty)
    if (currentRrset.size() > 0) {
      this.trustAnchors.store(currentRrset);
    }
  }

  /**
   * Gets the store with the loaded trust anchors.
   *
   * @return The store with the loaded trust anchors.
   */
  public net.posick.DNS.dnssec.TrustAnchorStore getTrustAnchors() {
    return this.trustAnchors;
  }

  /**
   * For messages that are not referrals, if the chase reply contains an unsigned NS record in the
   * authority section it could have been inserted by a (BIND) forwarder that thinks the zone is
   * insecure, and that has an NS record without signatures in cache. Remove the NS record since the
   * reply does not hinge on that record (in the authority section), but do not remove it if it
   * removes the last record from the answer+authority sections.
   *
   * @param response: the chased reply, we have a key for this contents, so we should have
   *     signatures for these rrsets and not having signatures means it will be bogus.
   */
  private void removeSpuriousAuthority(net.posick.DNS.dnssec.SMessage response) {
    // if no answer and only 1 auth RRset, do not remove that one
    if (response.getSectionRRsets(Section.ANSWER).isEmpty()
        && response.getSectionRRsets(Section.AUTHORITY).size() == 1) {
      return;
    }

    // search authority section for unsigned NS records
    Iterator<net.posick.DNS.dnssec.SRRset> authRrsetIterator = response.getSectionRRsets(Section.AUTHORITY).iterator();
    while (authRrsetIterator.hasNext()) {
      net.posick.DNS.dnssec.SRRset rrset = authRrsetIterator.next();
      if (rrset.getType() == Type.NS && rrset.sigs().isEmpty()) {
        log.trace(
            "Removing spurious unsigned NS record (likely inserted by forwarder) {}/{}/{}",
            rrset.getName(),
            Type.string(rrset.getType()),
            DClass.string(rrset.getDClass()));
        authRrsetIterator.remove();
      }
    }
  }

  /**
   * Given a "postive" response -- a response that contains an answer to the question, and no CNAME
   * chain, validate this response. This generally consists of verifying the answer RRset and the
   * authority RRsets.
   *
   * <p>Given an "ANY" response -- a response that contains an answer to a qtype==ANY question, with
   * answers. This consists of simply verifying all present answer/auth RRsets, with no checking
   * that all types are present.
   *
   * <p>NOTE: it may be possible to get parent-side delegation point records here, which won't all
   * be signed. Right now, this routine relies on the upstream iterative resolver to not return
   * these responses -- instead treating them as referrals.
   *
   * <p>NOTE: RFC 4035 is silent on this issue, so this may change upon clarification.
   *
   * @param request The request that generated this response.
   * @param response The response to validate.
   */
  private CompletionStage<Void> validatePositiveResponse(Message request, net.posick.DNS.dnssec.SMessage response) {
    Map<Name, Name> wcs = new HashMap<>(1);
    List<net.posick.DNS.dnssec.SRRset> nsec3s = new ArrayList<>(0);
    List<net.posick.DNS.dnssec.SRRset> nsecs = new ArrayList<>(0);

    return this.validateAnswerAndGetWildcards(response, request.getQuestion().getType(), wcs)
        .thenCompose(
            success -> {
              if (Boolean.TRUE.equals(success)) {
                // validate the AUTHORITY section as well - this will generally be the
                // NS rrset (which could be missing, no problem)
                int[] sections;
                if (request.getQuestion().getType() == Type.ANY) {
                  sections = new int[] {Section.ANSWER, Section.AUTHORITY};
                } else {
                  sections = new int[] {Section.AUTHORITY};
                }

                return this.validatePositiveResponseRecursive(
                    response,
                    wcs,
                    nsec3s,
                    nsecs,
                    sections,
                    new AtomicInteger(0),
                    new AtomicInteger(0));
              }

              return completedFuture(false);
            })
        .thenAccept(
            success -> {
              if (!Boolean.TRUE.equals(success)) {
                return;
              }

              // If this is a positive wildcard response, and we have NSEC records,
              // try to use them to
              // 1) prove that qname doesn't exist and
              // 2) that the correct wildcard was used.
              if (wcs.size() > 0) {
                for (Map.Entry<Name, Name> wc : wcs.entrySet()) {
                  boolean wcNsecOk = false;
                  for (net.posick.DNS.dnssec.SRRset set : nsecs) {
                    NSECRecord nsec = (NSECRecord) set.first();
                    if (net.posick.DNS.dnssec.ValUtils.nsecProvesNameError(set, nsec, wc.getKey())) {
                      try {
                        Name nsecWc = net.posick.DNS.dnssec.ValUtils.nsecWildcard(wc.getKey(), set, nsec);
                        if (wc.getValue().equals(nsecWc)) {
                          wcNsecOk = true;
                          break;
                        }
                      } catch (NameTooLongException e) {
                        // COVERAGE:OFF -> a NTLE can only be thrown when
                        // the qname is equal to the NSEC owner or NSEC next
                        // name, so that the wildcard is appended to
                        // CE=qname=owner=next. This would however indicate
                        // that the qname exists, which is proofed not the
                        // be the case beforehand.
                        throw new IllegalStateException(
                            net.posick.DNS.dnssec.R.get("failed.positive.wildcardgeneration"));
                      }
                    }
                  }

                  // If this was a positive wildcard response that we haven't
                  // already proven, and we have NSEC3 records, try to prove it
                  // using the NSEC3 records.
                  if (!wcNsecOk && !nsec3s.isEmpty()) {
                    if (this.n3valUtils.allNSEC3sIgnoreable(nsec3s, this.keyCache)) {
                      response.setStatus(
                          net.posick.DNS.dnssec.SecurityStatus.INSECURE, -1, net.posick.DNS.dnssec.R.get("failed.nsec3_ignored"));
                      return;
                    }

                    net.posick.DNS.dnssec.SecurityStatus status =
                        this.n3valUtils.proveWildcard(
                            nsec3s, wc.getKey(), nsec3s.get(0).getSignerName(), wc.getValue());
                    if (status == net.posick.DNS.dnssec.SecurityStatus.INSECURE) {
                      response.setStatus(status, -1);
                      return;
                    } else if (status == net.posick.DNS.dnssec.SecurityStatus.SECURE) {
                      wcNsecOk = true;
                    }
                  }

                  // If after all this, we still haven't proven the positive
                  // wildcard response, fail.
                  if (!wcNsecOk) {
                    response.setBogus(net.posick.DNS.dnssec.R.get("failed.positive.wildcard_too_broad"));
                    return;
                  }
                }
              }

              response.setStatus(net.posick.DNS.dnssec.SecurityStatus.SECURE, -1);
            });
  }

  private CompletionStage<Boolean> validatePositiveResponseRecursive(
      net.posick.DNS.dnssec.SMessage response,
      Map<Name, Name> wcs,
      List<net.posick.DNS.dnssec.SRRset> nsec3s,
      List<net.posick.DNS.dnssec.SRRset> nsecs,
      int[] sections,
      AtomicInteger sectionIndex,
      AtomicInteger setIndex) {
    // reached the end of the sections to validate, end recursion, success
    if (sectionIndex.get() >= sections.length) {
      return completedFuture(true);
    }

    List<net.posick.DNS.dnssec.SRRset> sectionRRsets = response.getSectionRRsets(sections[sectionIndex.get()]);

    // reached the end of the rrset in the current section, advance to next section
    if (setIndex.get() >= sectionRRsets.size()) {
      sectionIndex.getAndIncrement();
      setIndex.set(0);
      return this.validatePositiveResponseRecursive(
          response, wcs, nsec3s, nsecs, sections, sectionIndex, setIndex);
    }

    net.posick.DNS.dnssec.SRRset set = sectionRRsets.get(setIndex.getAndIncrement());
    return this.prepareFindKey(set)
        .thenCompose(
            ke -> {
              net.posick.DNS.dnssec.JustifiedSecStatus kve = ke.validateKeyFor(set.getSignerName());
              if (kve != null) {
                kve.applyToResponse(response);
                return completedFuture(false);
              }

              net.posick.DNS.dnssec.JustifiedSecStatus res = this.valUtils.verifySRRset(set, ke, this.clock.instant());
              // If anything in the authority section fails to be secure, we
              // have a bad message.
              if (res.status != net.posick.DNS.dnssec.SecurityStatus.SECURE) {
                response.setBogus(net.posick.DNS.dnssec.R.get("failed.authority.positive", set));
                return completedFuture(false);
              }

              if (wcs.size() > 0) {
                if (set.getType() == Type.NSEC) {
                  nsecs.add(set);
                } else if (set.getType() == Type.NSEC3) {
                  nsec3s.add(set);
                }
              }

              return this.validatePositiveResponseRecursive(
                  response, wcs, nsec3s, nsecs, sections, sectionIndex, setIndex);
            });
  }

  private CompletionStage<Boolean> validateAnswerAndGetWildcards(
          net.posick.DNS.dnssec.SMessage response, int qtype, Map<Name, Name> wcs) {
    return this.validateAnswerAndGetWildcardsRecursive(response, qtype, wcs, new AtomicInteger(0));
  }

  private CompletionStage<Boolean> validateAnswerAndGetWildcardsRecursive(
          net.posick.DNS.dnssec.SMessage response, int qtype, Map<Name, Name> wcs, AtomicInteger setIndex) {
    // validate the ANSWER section - this will be the answer itself
    List<net.posick.DNS.dnssec.SRRset> sectionRRsets = response.getSectionRRsets(Section.ANSWER);

    // reached the end of the answer section, success
    if (setIndex.get() >= sectionRRsets.size()) {
      return completedFuture(true);
    }

    net.posick.DNS.dnssec.SRRset set = sectionRRsets.get(setIndex.get());
    // Verify the answer rrset.
    return this.prepareFindKey(set)
        .thenCompose(
            ke -> {
              net.posick.DNS.dnssec.JustifiedSecStatus kve = ke.validateKeyFor(set.getSignerName());
              if (kve != null) {
                kve.applyToResponse(response);
                return completedFuture(false);
              }

              net.posick.DNS.dnssec.JustifiedSecStatus res = this.valUtils.verifySRRset(set, ke, this.clock.instant());
              // If the answer rrset failed to validate, then this message is BAD
              if (res.status != net.posick.DNS.dnssec.SecurityStatus.SECURE) {
                response.setBogus(net.posick.DNS.dnssec.R.get("failed.answer.positive", set));
                return completedFuture(false);
              }

              // Check to see if the rrset is the result of a wildcard expansion.
              // If so, an additional check will need to be made in the authority
              // section.
              Name wc;
              try {
                wc = net.posick.DNS.dnssec.ValUtils.rrsetWildcard(set);
              } catch (RuntimeException ex) {
                response.setBogus(net.posick.DNS.dnssec.R.get(ex.getMessage(), set.getName()));
                return completedFuture(false);
              }

              if (wc != null) {
                // RFC 4592, Section 4.4 does not allow wildcarded DNAMEs
                if (set.getType() == Type.DNAME) {
                  response.setBogus(net.posick.DNS.dnssec.R.get("failed.dname.wildcard", set.getName()));
                  return completedFuture(false);
                }

                wcs.put(set.getName(), wc);
              }

              // Notice a DNAME that should be followed by an unsigned CNAME.
              if (qtype != Type.DNAME && set.getType() == Type.DNAME) {
                DNAMERecord dname = (DNAMERecord) set.first();
                if (setIndex.getAndIncrement() < sectionRRsets.size()) {
                  net.posick.DNS.dnssec.SRRset cnameSet = sectionRRsets.get(setIndex.get());
                  // Validate the CNAME following a (validated) DNAME is correctly
                  // synthesized.
                  if (cnameSet.getType() == Type.CNAME && dname != null) {
                    if (cnameSet.size() > 1) {
                      response.setBogus(net.posick.DNS.dnssec.R.get("failed.synthesize.multiple"));
                      return completedFuture(false);
                    }

                    CNAMERecord cname = (CNAMERecord) cnameSet.first();
                    try {
                      Name expected =
                          Name.concatenate(
                              cname.getName().relativize(dname.getName()), dname.getTarget());
                      if (!expected.equals(cname.getTarget())) {
                        response.setBogus(
                            net.posick.DNS.dnssec.R.get("failed.synthesize.nomatch", cname.getTarget(), expected));
                        return completedFuture(false);
                      }
                    } catch (NameTooLongException e) {
                      response.setBogus(net.posick.DNS.dnssec.R.get("failed.synthesize.toolong"));
                      return completedFuture(false);
                    }

                    cnameSet.setSecurityStatus(net.posick.DNS.dnssec.SecurityStatus.SECURE);
                  }
                }
              }

              setIndex.getAndIncrement();
              return this.validateAnswerAndGetWildcardsRecursive(response, qtype, wcs, setIndex);
            });
  }

  /**
   * Validate a NOERROR/NODATA signed response -- a response that has a NOERROR Rcode but no ANSWER
   * section RRsets. This consists of verifying the authority section rrsets and making certain that
   * the authority section NSEC/NSEC3s proves that the qname does exist and the qtype doesn't.
   *
   * <p>Note that by the time this method is called, the process of finding the trusted DNSKEY rrset
   * that signs this response must already have been completed.
   *
   * @param request The request that generated this response.
   * @param response The response to validate.
   */
  private CompletionStage<Void> validateNodataResponse(Message request, net.posick.DNS.dnssec.SMessage response) {
    Name intermediateQname = request.getQuestion().getName();
    int qtype = request.getQuestion().getType();

    // Since we are here, the ANSWER section is either empty (and hence
    // there's only the NODATA to validate) OR it contains an incomplete
    // chain. In this case, the records were already validated before and we
    // can concentrate on following the qname that lead to the NODATA
    // classification
    for (net.posick.DNS.dnssec.SRRset set : response.getSectionRRsets(Section.ANSWER)) {
      if (set.getSecurityStatus() != net.posick.DNS.dnssec.SecurityStatus.SECURE) {
        response.setBogus(net.posick.DNS.dnssec.R.get("failed.answer.cname_nodata", set.getName()));
        return completedFuture(null);
      }

      if (set.getType() == Type.CNAME) {
        intermediateQname = ((CNAMERecord) set.first()).getTarget();
      }
    }

    // validate the AUTHORITY section
    Name qname = intermediateQname;
    return this.validateNodataResponseRecursive(response, new AtomicInteger(0))
        .handleAsync(
            (result, ex) -> {
              if (ex != null) {
                return null;
              }

              // If true, then the NODATA has been proven.
              boolean hasValidNSEC = false;

              // for wildcard nodata responses. This is the proven closest encloser.
              Name ce = null;

              // for wildcard nodata responses. This is the wildcard NSEC.
              NsecProvesNodataResponse ndp = new NsecProvesNodataResponse();

              // A collection of NSEC3 RRs found in the authority section.
              List<net.posick.DNS.dnssec.SRRset> nsec3s = new ArrayList<>(0);

              // The RRSIG signer field for the NSEC3 RRs.
              Name nsec3Signer = null;

              int edeReason = ExtendedErrorCodeOption.NSEC_MISSING;
              for (net.posick.DNS.dnssec.SRRset set : response.getSectionRRsets(Section.AUTHORITY)) {
                // If we encounter an NSEC record, try to use it to prove NODATA.
                // This needs to handle the empty non-terminal (ENT) NODATA case.
                if (set.getType() == Type.NSEC) {
                  NSECRecord nsec = (NSECRecord) set.first();
                  ndp = net.posick.DNS.dnssec.ValUtils.nsecProvesNodata(set, nsec, qname, qtype);
                  if (ndp.result) {
                    hasValidNSEC = true;
                  } else {
                    edeReason = ExtendedErrorCodeOption.DNSSEC_BOGUS;
                  }

                  if (net.posick.DNS.dnssec.ValUtils.nsecProvesNameError(set, nsec, qname)) {
                    ce = net.posick.DNS.dnssec.ValUtils.closestEncloser(qname, set.getName(), nsec.getNext());
                  }
                }

                // Collect any NSEC3 records present.
                if (set.getType() == Type.NSEC3) {
                  nsec3s.add(set);
                  nsec3Signer = set.getSignerName();
                }
              }

              // check to see if we have a wildcard NODATA proof.

              // The wildcard NODATA is 1 NSEC proving that qname does not exist (and
              // also proving what the closest encloser is), and 1 NSEC showing the
              // matching wildcard, which must be *.closest_encloser.
              if (ndp.wc != null && (ce == null || (!ce.equals(ndp.wc) && !qname.equals(ce)))) {
                edeReason = ExtendedErrorCodeOption.DNSSEC_BOGUS;
                hasValidNSEC = false;
              }

              this.n3valUtils.stripUnknownAlgNSEC3s(nsec3s);
              if (!hasValidNSEC && !nsec3s.isEmpty()) {
                log.debug("Using NSEC3 records");

                // try to prove NODATA with our NSEC3 record(s)
                if (this.n3valUtils.allNSEC3sIgnoreable(nsec3s, this.keyCache)) {
                  response.setBogus(net.posick.DNS.dnssec.R.get("failed.nsec3_ignored"));
                  return null;
                }

                net.posick.DNS.dnssec.JustifiedSecStatus res =
                    this.n3valUtils.proveNodata(nsec3s, qname, qtype, nsec3Signer);
                edeReason = res.edeReason;
                if (res.status == net.posick.DNS.dnssec.SecurityStatus.INSECURE) {
                  response.setStatus(net.posick.DNS.dnssec.SecurityStatus.INSECURE, -1);
                  return null;
                }

                hasValidNSEC = res.status == net.posick.DNS.dnssec.SecurityStatus.SECURE;
              }

              if (!hasValidNSEC) {
                response.setBogus(net.posick.DNS.dnssec.R.get("failed.nodata"), edeReason);
                log.trace("Failed NODATA for {}", qname);
                return null;
              }

              log.trace("Successfully validated NODATA response");
              response.setStatus(net.posick.DNS.dnssec.SecurityStatus.SECURE, -1);
              return null;
            });
  }

  private CompletionStage<Void> validateNodataResponseRecursive(
          net.posick.DNS.dnssec.SMessage response, AtomicInteger setIndex) {
    if (setIndex.get() >= response.getSectionRRsets(Section.AUTHORITY).size()) {
      return completedFuture(null);
    }

    net.posick.DNS.dnssec.SRRset set = response.getSectionRRsets(Section.AUTHORITY).get(setIndex.getAndIncrement());
    return this.prepareFindKey(set)
        .thenComposeAsync(
            ke -> {
              net.posick.DNS.dnssec.JustifiedSecStatus kve = ke.validateKeyFor(set.getSignerName());
              if (kve != null) {
                kve.applyToResponse(response);
                return this.failedFuture(new Exception(kve.reason));
              }

              net.posick.DNS.dnssec.JustifiedSecStatus res = this.valUtils.verifySRRset(set, ke, this.clock.instant());
              if (res.status != net.posick.DNS.dnssec.SecurityStatus.SECURE) {
                response.setBogus(net.posick.DNS.dnssec.R.get("failed.authority.nodata", set));
                return this.failedFuture(new Exception("failed.authority.nodata"));
              }

              return this.validateNodataResponseRecursive(response, setIndex);
            });
  }

  private <T> CompletionStage<T> failedFuture(Throwable e) {
    CompletableFuture<T> f = new CompletableFuture<>();
    f.completeExceptionally(e);
    return f;
  }

  /**
   * Validate a NAMEERROR signed response -- a response that has a NXDOMAIN Rcode. This consists of
   * verifying the authority section rrsets and making certain that the authority section NSEC
   * proves that the qname doesn't exist and the covering wildcard also doesn't exist..
   *
   * <p>Note that by the time this method is called, the process of finding the trusted DNSKEY rrset
   * that signs this response must already have been completed.
   *
   * @param request The request to be proved to not exist.
   * @param response The response to validate.
   */
  private CompletionStage<Void> validateNameErrorResponse(Message request, net.posick.DNS.dnssec.SMessage response) {
    Name intermediateQname = request.getQuestion().getName();

    // The ANSWER section is either empty OR it contains an xNAME chain that
    // ultimately lead to the NAMEERROR response. In this case the ANSWER
    // section has already been validated before and we can concentrate on
    // following the xNAMEs to find the qname that caused the NXDOMAIN.
    for (net.posick.DNS.dnssec.SRRset set : response.getSectionRRsets(Section.ANSWER)) {
      if (set.getSecurityStatus() != net.posick.DNS.dnssec.SecurityStatus.SECURE) {
        response.setBogus(net.posick.DNS.dnssec.R.get("failed.nxdomain.cname_nxdomain", set));
        return completedFuture(null);
      }

      if (set.getType() == Type.CNAME) {
        intermediateQname = ((CNAMERecord) set.first()).getTarget();
      }
    }

    // validate the AUTHORITY section
    Name qname = intermediateQname;
    return this.validateNameErrorResponseRecursive(response, new AtomicInteger(0))
        .thenComposeAsync(
            v -> {
              // Validate the authority section -- all RRsets in the authority section
              // must be signed and valid.
              // In addition, the NSEC record(s) must prove the NXDOMAIN condition.
              boolean hasValidNSEC = false;
              boolean hasValidWCNSEC = false;
              List<net.posick.DNS.dnssec.SRRset> nsec3s = new ArrayList<>(0);
              Name nsec3Signer = null;
              int previousClosestEncloseLabels = 0;

              for (net.posick.DNS.dnssec.SRRset set : response.getSectionRRsets(Section.AUTHORITY)) {
                // If we encounter an NSEC record, try to use it to prove NODATA.
                // This needs to handle the empty non-terminal (ENT) NODATA case.
                if (set.getType() == Type.NSEC) {
                  NSECRecord nsec = (NSECRecord) set.first();
                  if (net.posick.DNS.dnssec.ValUtils.nsecProvesNameError(set, nsec, qname)) {
                    hasValidNSEC = true;
                  }

                  Name next = nsec.getNext();
                  int closestEncloserLabels =
                      net.posick.DNS.dnssec.ValUtils.closestEncloser(qname, set.getName(), next).labels();
                  if (closestEncloserLabels > previousClosestEncloseLabels
                      || (closestEncloserLabels == previousClosestEncloseLabels
                          && !hasValidWCNSEC)) {
                    hasValidWCNSEC = net.posick.DNS.dnssec.ValUtils.nsecProvesNoWC(set, nsec, qname);
                  }

                  previousClosestEncloseLabels = closestEncloserLabels;
                }

                if (set.getType() == Type.NSEC3) {
                  nsec3s.add(set);
                  nsec3Signer = set.getSignerName();
                }
              }

              this.n3valUtils.stripUnknownAlgNSEC3s(nsec3s);
              if ((!hasValidNSEC || !hasValidWCNSEC) && !nsec3s.isEmpty()) {
                log.debug("Validating nxdomain: using NSEC3 records");

                // Attempt to prove name error with nsec3 records.
                if (this.n3valUtils.allNSEC3sIgnoreable(nsec3s, this.keyCache)) {
                  response.setStatus(net.posick.DNS.dnssec.SecurityStatus.INSECURE, -1, net.posick.DNS.dnssec.R.get("failed.nsec3_ignored"));
                  return completedFuture(null);
                }

                net.posick.DNS.dnssec.SecurityStatus status = this.n3valUtils.proveNameError(nsec3s, qname, nsec3Signer);
                if (status != net.posick.DNS.dnssec.SecurityStatus.SECURE) {
                  if (status == net.posick.DNS.dnssec.SecurityStatus.INSECURE) {
                    response.setStatus(status, -1, net.posick.DNS.dnssec.R.get("failed.nxdomain.nsec3_insecure"));
                  } else {
                    response.setStatus(
                        status,
                        ExtendedErrorCodeOption.DNSSEC_BOGUS,
                        net.posick.DNS.dnssec.R.get("failed.nxdomain.nsec3_bogus"));
                  }

                  return completedFuture(null);
                }

                // Note that we assume that the NSEC3ValUtils proofs encompass the
                // wildcard part of the proof.
                hasValidNSEC = true;
                hasValidWCNSEC = true;
              }

              if (!hasValidNSEC || !hasValidWCNSEC) {
                boolean hasValidNSEC2 = hasValidNSEC;

                // Be lenient with RCODE in NSEC NameError responses
                return this.validateNodataResponse(request, response)
                    .thenRun(
                        () -> {
                          if (response.getStatus() == net.posick.DNS.dnssec.SecurityStatus.SECURE) {
                            response.getHeader().setRcode(Rcode.NOERROR);
                          } else {
                            // If the message fails to prove either condition, it is bogus.
                            if (!hasValidNSEC2) {
                              response.setBogus(
                                  net.posick.DNS.dnssec.R.get(
                                      "failed.nxdomain.exists", response.getQuestion().getName()));
                              return;
                            }

                            response.setBogus(net.posick.DNS.dnssec.R.get("failed.nxdomain.haswildcard"));
                          }
                        });
              }

              // Otherwise, we consider the message secure.
              log.trace("Successfully validated NAME ERROR response");
              response.setStatus(net.posick.DNS.dnssec.SecurityStatus.SECURE, -1);
              return completedFuture(null);
            })
        .exceptionally(ex -> null);
  }

  private CompletionStage<Void> validateNameErrorResponseRecursive(
          net.posick.DNS.dnssec.SMessage response, AtomicInteger setIndex) {
    if (setIndex.get() >= response.getSectionRRsets(Section.AUTHORITY).size()) {
      return completedFuture(null);
    }

    net.posick.DNS.dnssec.SRRset set = response.getSectionRRsets(Section.AUTHORITY).get(setIndex.getAndIncrement());
    return this.prepareFindKey(set)
        .thenCompose(
            ke -> {
              net.posick.DNS.dnssec.JustifiedSecStatus kve = ke.validateKeyFor(set.getSignerName());
              if (kve != null) {
                kve.applyToResponse(response);
                return this.failedFuture(new Exception(kve.reason));
              }

              net.posick.DNS.dnssec.JustifiedSecStatus res = this.valUtils.verifySRRset(set, ke, this.clock.instant());
              if (res.status != net.posick.DNS.dnssec.SecurityStatus.SECURE) {
                response.setBogus(net.posick.DNS.dnssec.R.get("failed.nxdomain.authority", set));
                return this.failedFuture(new Exception("failed.nxdomain.authority"));
              }

              return this.validateNameErrorResponseRecursive(response, setIndex);
            });
  }

  private CompletionStage<net.posick.DNS.dnssec.SMessage> sendRequest(Message request) {
    Record q = request.getQuestion();
    log.trace(
        "Sending request: <{}/{}/{}>",
        q.getName(),
        Type.string(q.getType()),
        DClass.string(q.getDClass()));

    // Send the request along by using a local copy of the request
    Message localRequest = request.clone();
    localRequest.getHeader().setFlag(Flags.CD);
    return this.headResolver.sendAsync(localRequest).thenApply(net.posick.DNS.dnssec.SMessage::new);
  }

  private CompletionStage<net.posick.DNS.dnssec.KeyEntry> prepareFindKey(net.posick.DNS.dnssec.SRRset rrset) {
    net.posick.DNS.dnssec.FindKeyState state = new net.posick.DNS.dnssec.FindKeyState();
    state.signerName = rrset.getSignerName();
    state.qclass = rrset.getDClass();

    if (state.signerName == null) {
      state.signerName = rrset.getName();
    }

    net.posick.DNS.dnssec.SRRset trustAnchorRRset = this.trustAnchors.find(state.signerName, rrset.getDClass());
    if (trustAnchorRRset == null) {
      // response isn't under a trust anchor, so we cannot validate.
      net.posick.DNS.dnssec.KeyEntry ke =
          net.posick.DNS.dnssec.KeyEntry.newNullKeyEntry(state.signerName, rrset.getDClass(), DEFAULT_TA_BAD_KEY_TTL);
      return completedFuture(ke);
    }

    state.keyEntry = this.keyCache.find(state.signerName, rrset.getDClass());
    if (state.keyEntry == null
        || (!state.keyEntry.getName().equals(state.signerName) && state.keyEntry.isGood())) {
      // start the FINDKEY phase with the trust anchor
      state.dsRRset = trustAnchorRRset;
      state.keyEntry = null;
      state.currentDSKeyName = new Name(trustAnchorRRset.getName(), 1);

      // and otherwise, don't continue processing this event.
      // (it will be reactivated when the priming query returns).
      return this.processFindKey(state).thenApply(v -> state.keyEntry);
    }

    return completedFuture(state.keyEntry);
  }

  /**
   * Process the FINDKEY state. Generally this just calculates the next name to query and either
   * issues a DS or a DNSKEY query. It will check to see if the correct key has already been
   * reached, in which case it will advance the event to the next state.
   *
   * @param state The state associated with the current key finding phase.
   */
  private CompletionStage<Void> processFindKey(net.posick.DNS.dnssec.FindKeyState state) {
    // We know that state.keyEntry is not a null or bad key -- if it were,
    // then previous processing should have directed this event to a
    // different state.
    int qclass = state.qclass;
    Name targetKeyName = state.signerName;
    Name currentKeyName = Name.empty;
    if (state.keyEntry != null) {
      currentKeyName = state.keyEntry.getName();
    }

    if (state.currentDSKeyName != null) {
      currentKeyName = state.currentDSKeyName;
      state.currentDSKeyName = null;
    }

    // If our current key entry matches our target, then we are done.
    if (currentKeyName.equals(targetKeyName)) {
      return completedFuture(null);
    }

    if (state.emptyDSName != null) {
      currentKeyName = state.emptyDSName;
    }

    // Calculate the next lookup name.
    int targetLabels = targetKeyName.labels();
    int currentLabels = currentKeyName.labels();
    int l = targetLabels - currentLabels - 1;

    // the next key name would be trying to invent a name, so we stop here
    if (l < 0) {
      return completedFuture(null);
    }

    Name nextKeyName = new Name(targetKeyName, l);
    log.trace(
        "Key search: targetKeyName = {}, currentKeyName = {}, nextKeyName = {}",
        targetKeyName,
        currentKeyName,
        nextKeyName);

    // The next step is either to query for the next DS, or to query for the
    // next DNSKEY.
    if (state.dsRRset == null || !state.dsRRset.getName().equals(nextKeyName)) {
      Message dsRequest = Message.newQuery(Record.newRecord(nextKeyName, Type.DS, qclass));
      return this.sendRequest(dsRequest)
          .thenComposeAsync(dsResponse -> this.processDSResponse(dsRequest, dsResponse, state));
    }

    // Otherwise, it is time to query for the DNSKEY
    Message dnskeyRequest =
        Message.newQuery(Record.newRecord(state.dsRRset.getName(), Type.DNSKEY, qclass));
    return this.sendRequest(dnskeyRequest)
        .thenComposeAsync(
            dnskeyResponse -> this.processDNSKEYResponse(dnskeyRequest, dnskeyResponse, state));
  }

  /**
   * Given a DS response, the DS request, and the current key rrset, validate the DS response,
   * returning a KeyEntry.
   *
   * @param response The DS response.
   * @param request The DS request.
   * @param keyRrset The current DNSKEY rrset from the forEvent state.
   * @return A KeyEntry, bad if the DS response fails to validate, null if the DS response indicated
   *     an end to secure space, good if the DS validated. It returns null if the DS response
   *     indicated that the request wasn't a delegation point.
   */
  private net.posick.DNS.dnssec.KeyEntry dsResponseToKE(net.posick.DNS.dnssec.SMessage response, Message request, net.posick.DNS.dnssec.SRRset keyRrset) {
    Name qname = request.getQuestion().getName();
    int qclass = request.getQuestion().getDClass();

    net.posick.DNS.dnssec.JustifiedSecStatus res;
    net.posick.DNS.dnssec.ResponseClassification subtype = net.posick.DNS.dnssec.ValUtils.classifyResponse(request, response);

    net.posick.DNS.dnssec.KeyEntry bogusKE = net.posick.DNS.dnssec.KeyEntry.newBadKeyEntry(qname, qclass, DEFAULT_TA_BAD_KEY_TTL);
    switch (subtype) {
      case POSITIVE:
        // Verify only returns BOGUS or SECURE. If the rrset is bogus,
        // then we are done.
        net.posick.DNS.dnssec.SRRset dsRrset = response.findAnswerRRset(qname, Type.DS, qclass);
        res = this.valUtils.verifySRRset(dsRrset, keyRrset, this.clock.instant());
        if (res.status != net.posick.DNS.dnssec.SecurityStatus.SECURE) {
          bogusKE.setBadReason(res.edeReason, res.reason);
          return bogusKE;
        }

        if (!valUtils.atLeastOneSupportedAlgorithm(dsRrset)) {
          net.posick.DNS.dnssec.KeyEntry nullKey = net.posick.DNS.dnssec.KeyEntry.newNullKeyEntry(qname, qclass, dsRrset.getTTL());
          nullKey.setBadReason(
              ExtendedErrorCodeOption.UNSUPPORTED_DNSKEY_ALGORITHM,
              net.posick.DNS.dnssec.R.get("insecure.ds.noalgorithms", qname));
          return nullKey;
        }

        // Otherwise, we return the positive response.
        log.trace("DS RRset was good");
        return net.posick.DNS.dnssec.KeyEntry.newKeyEntry(dsRrset);

      case CNAME:
        // Verify only returns BOGUS or SECURE. If the rrset is bogus,
        // then we are done.
        net.posick.DNS.dnssec.SRRset cnameRrset = response.findAnswerRRset(qname, Type.CNAME, qclass);
        res = this.valUtils.verifySRRset(cnameRrset, keyRrset, this.clock.instant());
        if (res.status == net.posick.DNS.dnssec.SecurityStatus.SECURE) {
          return null;
        }

        bogusKE.setBadReason(ExtendedErrorCodeOption.DNSSEC_BOGUS, net.posick.DNS.dnssec.R.get("failed.ds.cname"));
        return bogusKE;

      case NODATA:
      case NAMEERROR:
        return this.dsReponseToKeForNodata(response, request, keyRrset);

      default:
        // We've encountered an unhandled classification for this
        // response.
        bogusKE.setBadReason(
            ExtendedErrorCodeOption.DNSSEC_BOGUS, net.posick.DNS.dnssec.R.get("failed.ds.notype", subtype));
        return bogusKE;
    }
  }

  /**
   * Given a DS response, the DS request, and the current key rrset, validate the DS response for
   * the NODATA case, returning a KeyEntry.
   *
   * @param response The DS response.
   * @param request The DS request.
   * @param keyRrset The current DNSKEY rrset from the forEvent state.
   * @return A KeyEntry, bad if the DS response fails to validate, null if the DS response indicated
   *     an end to secure space, good if the DS validated. It returns null if the DS response
   *     indicated that the request wasn't a delegation point.
   */
  private net.posick.DNS.dnssec.KeyEntry dsReponseToKeForNodata(net.posick.DNS.dnssec.SMessage response, Message request, net.posick.DNS.dnssec.SRRset keyRrset) {
    Name qname = request.getQuestion().getName();
    int qclass = request.getQuestion().getDClass();
    net.posick.DNS.dnssec.KeyEntry bogusKE = net.posick.DNS.dnssec.KeyEntry.newBadKeyEntry(qname, qclass, DEFAULT_TA_BAD_KEY_TTL);

    if (!this.valUtils.hasSignedNsecs(response)) {
      bogusKE.setBadReason(
          ExtendedErrorCodeOption.RRSIGS_MISSING, net.posick.DNS.dnssec.R.get("failed.ds.nonsec", qname));
      return bogusKE;
    }

    // Try to prove absence of the DS with NSEC
    net.posick.DNS.dnssec.JustifiedSecStatus status =
        this.valUtils.nsecProvesNodataDsReply(request, response, keyRrset, this.clock.instant());
    switch (status.status) {
      case SECURE:
        net.posick.DNS.dnssec.KeyEntry nullKey = net.posick.DNS.dnssec.KeyEntry.newNullKeyEntry(qname, qclass, DEFAULT_TA_BAD_KEY_TTL);
        nullKey.setBadReason(-1, net.posick.DNS.dnssec.R.get("insecure.ds.nsec"));
        return nullKey;
      case INSECURE:
        return null;
      case BOGUS:
        bogusKE.setBadReason(status.edeReason, status.reason);
        return bogusKE;
      default:
        // NSEC proof did not work, try NSEC3
        break;
    }

    // Or it could be using NSEC3.
    List<net.posick.DNS.dnssec.SRRset> nsec3Rrsets = response.getSectionRRsets(Section.AUTHORITY, Type.NSEC3);
    List<net.posick.DNS.dnssec.SRRset> nsec3s = new ArrayList<>(0);
    Name nsec3Signer = null;
    long nsec3TTL = -1;
    if (!nsec3Rrsets.isEmpty()) {
      // Attempt to prove no DS with NSEC3s.
      for (net.posick.DNS.dnssec.SRRset nsec3set : nsec3Rrsets) {
        net.posick.DNS.dnssec.JustifiedSecStatus res =
            this.valUtils.verifySRRset(nsec3set, keyRrset, this.clock.instant());
        if (res.status != net.posick.DNS.dnssec.SecurityStatus.SECURE) {
          // We could just fail here as there is an invalid rrset, but
          // skipping doesn't matter because we might not need it or
          // the proof will fail anyway.
          log.debug("Skipping bad NSEC3");
          continue;
        }

        nsec3Signer = nsec3set.getSignerName();
        if (nsec3TTL < 0 || nsec3set.getTTL() < nsec3TTL) {
          nsec3TTL = nsec3set.getTTL();
        }

        nsec3s.add(nsec3set);
      }

      switch (this.n3valUtils.proveNoDS(nsec3s, qname, nsec3Signer)) {
        case INSECURE:
          // case insecure also continues to unsigned space.
          // If nsec3-iter-count too high or optout, then treat below as unsigned
        case SECURE:
          net.posick.DNS.dnssec.KeyEntry nullKey = net.posick.DNS.dnssec.KeyEntry.newNullKeyEntry(qname, qclass, nsec3TTL);
          nullKey.setBadReason(-1, net.posick.DNS.dnssec.R.get("insecure.ds.nsec3"));
          return nullKey;
        case INDETERMINATE:
          log.debug("NSEC3s for the referral proved no delegation");
          return null;
        case BOGUS:
          bogusKE.setBadReason(ExtendedErrorCodeOption.DNSSEC_BOGUS, net.posick.DNS.dnssec.R.get("failed.ds.nsec3"));
          return bogusKE;
        default:
          bogusKE.setBadReason(ExtendedErrorCodeOption.DNSSEC_BOGUS, net.posick.DNS.dnssec.R.get("unknown.ds.nsec3"));
          return bogusKE;
      }
    }

    // Apparently no available NSEC/NSEC3 proved NODATA, so this is
    // BOGUS.
    bogusKE.setBadReason(ExtendedErrorCodeOption.DNSSEC_BOGUS, net.posick.DNS.dnssec.R.get("failed.ds.unknown"));
    return bogusKE;
  }

  /**
   * This handles the responses to locally generated DS queries.
   *
   * @param request The request for which the response is processed.
   * @param response The response to process.
   * @param state The state associated with the current key finding phase.
   */
  private CompletionStage<Void> processDSResponse(
          Message request, net.posick.DNS.dnssec.SMessage response, net.posick.DNS.dnssec.FindKeyState state) {
    Name qname = request.getQuestion().getName();

    state.emptyDSName = null;
    state.dsRRset = null;

    net.posick.DNS.dnssec.KeyEntry dsKE = this.dsResponseToKE(response, request, state.keyEntry);
    if (dsKE == null) {
      // DS response indicated that we aren't on a delegation point.
      state.emptyDSName = qname;
    } else if (dsKE.isGood()) {
      state.dsRRset = dsKE;
      state.currentDSKeyName = new Name(dsKE.getName(), 1);
    } else {
      // The reason for the DS to be not good (that is, either bad
      // or null) should have been logged by dsResponseToKE.
      state.keyEntry = dsKE;
      if (dsKE.isNull()) {
        this.keyCache.store(dsKE);
      }

      // The FINDKEY phase has ended, so move on.
      return completedFuture(null);
    }

    return this.processFindKey(state);
  }

  private CompletionStage<Void> processDNSKEYResponse(
          Message request, net.posick.DNS.dnssec.SMessage response, net.posick.DNS.dnssec.FindKeyState state) {
    Name qname = request.getQuestion().getName();
    int qclass = request.getQuestion().getDClass();

    net.posick.DNS.dnssec.SRRset dnskeyRrset = response.findAnswerRRset(qname, Type.DNSKEY, qclass);
    if (dnskeyRrset == null) {
      // If the DNSKEY rrset was missing, this is the end of the line.
      state.keyEntry = net.posick.DNS.dnssec.KeyEntry.newBadKeyEntry(qname, qclass, DEFAULT_TA_BAD_KEY_TTL);
      state.keyEntry.setBadReason(
          ExtendedErrorCodeOption.DNSKEY_MISSING, net.posick.DNS.dnssec.R.get("dnskey.no_rrset", qname));
      return completedFuture(null);
    }

    state.keyEntry =
        this.valUtils.verifyNewDNSKEYs(
            dnskeyRrset, state.dsRRset, DEFAULT_TA_BAD_KEY_TTL, this.clock.instant());

    // If the key entry isBad or isNull, then we can move on to the next
    // state.
    if (!state.keyEntry.isGood()) {
      return completedFuture(null);
    }

    // The DNSKEY validated, so cache it as a trusted key rrset.
    this.keyCache.store(state.keyEntry);

    // If good, we stay in the FINDKEY state.
    return this.processFindKey(state);
  }

  private CompletionStage<net.posick.DNS.dnssec.SMessage> processValidate(Message request, net.posick.DNS.dnssec.SMessage response) {
    net.posick.DNS.dnssec.ResponseClassification subtype = net.posick.DNS.dnssec.ValUtils.classifyResponse(request, response);
    if (subtype != net.posick.DNS.dnssec.ResponseClassification.REFERRAL) {
      this.removeSpuriousAuthority(response);
    }

    CompletionStage<Void> completionStage;
    switch (subtype) {
      case POSITIVE:
      case CNAME:
      case ANY:
        log.trace("Validating a positive response");
        completionStage = this.validatePositiveResponse(request, response);
        break;

      case NODATA:
        log.trace("Validating a nodata response");
        completionStage = this.validateNodataResponse(request, response);
        break;

      case CNAME_NODATA:
        log.trace("Validating a CNAME_NODATA response");
        completionStage =
            this.validatePositiveResponse(request, response)
                .thenCompose(
                    v -> {
                      if (response.getStatus() != net.posick.DNS.dnssec.SecurityStatus.INSECURE) {
                        response.setStatus(net.posick.DNS.dnssec.SecurityStatus.UNCHECKED, -1);
                        return this.validateNodataResponse(request, response);
                      }

                      return completedFuture(null);
                    });
        break;

      case NAMEERROR:
        log.trace("Validating a nxdomain response");
        completionStage = this.validateNameErrorResponse(request, response);
        break;

      case CNAME_NAMEERROR:
        log.trace("Validating a cname_nxdomain response");
        completionStage =
            this.validatePositiveResponse(request, response)
                .thenCompose(
                    v -> {
                      if (response.getStatus() != net.posick.DNS.dnssec.SecurityStatus.INSECURE) {
                        response.setStatus(net.posick.DNS.dnssec.SecurityStatus.UNCHECKED, -1);
                        return this.validateNameErrorResponse(request, response);
                      }

                      return completedFuture(null);
                    });
        break;

      default:
        response.setBogus(R.get("validate.response.unknown", subtype));
        completionStage = completedFuture(null);
        break;
    }

    return completionStage.thenApply(v -> this.processFinishedState(request, response));
  }

  /**
   * Apply any final massaging to a response before returning up the pipeline. Primarily this means
   * setting the AD bit or not and possibly stripping DNSSEC data.
   */
  private net.posick.DNS.dnssec.SMessage processFinishedState(Message request, net.posick.DNS.dnssec.SMessage response) {
    // If the response message validated, set the AD bit.
    SecurityStatus status = response.getStatus();
    String reason = response.getBogusReason();
    int edeReason = response.getEdeReason();
    switch (status) {
      case BOGUS:
        // For now, in the absence of any other API information, we
        // return SERVFAIL.
        int code = response.getHeader().getRcode();
        if (code == Rcode.NOERROR || code == Rcode.NXDOMAIN) {
          code = Rcode.SERVFAIL;
        }

        response = ValidatingResolver.errorMessage(request, code);
        break;
      case SECURE:
        response.getHeader().setFlag(Flags.AD);
        break;
      case UNCHECKED:
      case INSECURE:
        break;
      default:
        throw new IllegalArgumentException("unexpected security status");
    }

    response.setStatus(status, edeReason, reason);
    return response;
  }

  // Resolver-interface implementation --------------------------------------

  /**
   * Forwards the data to the head resolver passed at construction time.
   *
   * @param port The IP destination port for the queries sent.
   * @see Resolver#setPort(int)
   */
  public void setPort(int port) {
    this.headResolver.setPort(port);
  }

  /**
   * Forwards the data to the head resolver passed at construction time.
   *
   * @param flag <code>true</code> to enable TCP, <code>false</code> to disable it.
   * @see Resolver#setTCP(boolean)
   */
  public void setTCP(boolean flag) {
    this.headResolver.setTCP(flag);
  }

  /**
   * This is a no-op, truncation is never ignored.
   *
   * @param flag unused
   */
  public void setIgnoreTruncation(boolean flag) {
    // never ignore
  }

  /**
   * The method is forwarded to the resolver, but always ensure that the level is 0 and the flags
   * contains DO.
   *
   * @param version The EDNS level to use. 0 indicates EDNS0.
   * @param payloadSize The maximum DNS packet size that this host is capable of receiving over UDP.
   *     If 0 is specified, the default (1280) is used.
   * @param flags EDNS extended flags to be set in the OPT record, {@link ExtendedFlags#DO} is
   *     always appended.
   * @param options EDNS options to be set in the OPT record, specified as a List of
   *     OPTRecord.Option elements.
   * @see Resolver#setEDNS(int, int, int, List)
   */
  public void setEDNS(int version, int payloadSize, int flags, List<EDNSOption> options) {
    if (version == -1) {
      throw new IllegalArgumentException("EDNS cannot be disabled");
    }

    this.headResolver.setEDNS(version, payloadSize, flags | ExtendedFlags.DO, options);
  }

  /**
   * Forwards the data to the head resolver passed at construction time.
   *
   * @param key The key.
   * @see Resolver#setTSIGKey(TSIG)
   */
  public void setTSIGKey(TSIG key) {
    this.headResolver.setTSIGKey(key);
  }

  @Override
  public Duration getTimeout() {
    return this.headResolver.getTimeout();
  }

  @Override
  public void setTimeout(Duration duration) {
    this.headResolver.setTimeout(duration);
  }

  /**
   * Asynchronously sends a message and validates the response with DNSSEC before returning it.
   *
   * @param query The query to send.
   * @return A future that completes when the query is finished.
   */
  @Override
  public CompletionStage<Message> sendAsync(Message query) {
    return this.sendRequest(query)
        .thenCompose(
            response -> {
              response.getHeader().unsetFlag(Flags.AD);

              // If the CD bit is set, do not process the (cached) validation status.
              if (query.getHeader().getFlag(Flags.CD)) {
                return completedFuture(response.getMessage());
              }

              // Positive RRSIG responses cannot be validated as there are no
              // signatures on signatures. Negative answers CAN be validated.
              Message rrsigResponse = response.getMessage();
              if (query.getQuestion().getType() == Type.RRSIG
                  && rrsigResponse.getHeader().getRcode() == Rcode.NOERROR
                  && !rrsigResponse.getSectionRRsets(Section.ANSWER).isEmpty()) {
                rrsigResponse.getHeader().unsetFlag(Flags.AD);
                return completedFuture(rrsigResponse);
              }

              return this.processValidate(query, response)
                  .thenApply(
                      validated -> {
                        Message m = validated.getMessage();
                        String reason = validated.getBogusReason();
                        if (reason != null) {
                          applyEdeToOpt(validated, m);
                          if (isAddReasonToAdditional) {
                            addValidationReasonTxtRecord(m, reason);
                          }
                        }

                        return m;
                      });
            });
  }

  private void applyEdeToOpt(net.posick.DNS.dnssec.SMessage validated, Message m) {
    if (validated.getEdeReason() <= -1) {
      return;
    }

    OPTRecord old = m.getOPT();
    OPTRecord newOpt;
    List<EDNSOption> options = new ArrayList<>();
    options.add(new ExtendedErrorCodeOption(validated.getEdeReason(), validated.getBogusReason()));
    if (old != null) {
      options.addAll(
          old.getOptions().stream()
              .filter(o -> o.getCode() != Code.EDNS_EXTENDED_ERROR)
              .collect(Collectors.toList()));
      newOpt =
          new OPTRecord(
              old.getPayloadSize(),
              old.getExtendedRcode(),
              old.getVersion(),
              old.getFlags(),
              options);
      m.removeRecord(m.getOPT(), Section.ADDITIONAL);
    } else {
      newOpt = new OPTRecord(SimpleResolver.DEFAULT_EDNS_PAYLOADSIZE, 0, 0, 0, options);
    }
    m.addRecord(newOpt, Section.ADDITIONAL);
  }

  private void addValidationReasonTxtRecord(Message m, String reason) {
    final int maxTxtRecordStringLength = 255;
    String[] parts = new String[reason.length() / maxTxtRecordStringLength + 1];
    for (int i = 0; i < parts.length; i++) {
      int length = Math.min((i + 1) * maxTxtRecordStringLength, reason.length());
      parts[i] = reason.substring(i * maxTxtRecordStringLength, length);
    }

    m.addRecord(
        new TXTRecord(Name.root, VALIDATION_REASON_QCLASS, 0, Arrays.asList(parts)),
        Section.ADDITIONAL);
  }

  /**
   * Creates a response message with the given return code.
   *
   * @param request The request for which the response belongs.
   * @param rcode The response code, @see Rcode
   * @return The response message for <code>request</code>.
   */
  private static net.posick.DNS.dnssec.SMessage errorMessage(Message request, int rcode) {
    net.posick.DNS.dnssec.SMessage m = new net.posick.DNS.dnssec.SMessage(request.getHeader().getID(), request.getQuestion());
    Header h = m.getHeader();
    h.setRcode(rcode);
    h.setFlag(Flags.QR);

    return m;
  }
}
