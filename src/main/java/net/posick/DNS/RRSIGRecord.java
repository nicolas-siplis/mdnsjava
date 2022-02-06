// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.DNSSEC;
import net.posick.DNS.KEYRecord;
import net.posick.DNS.Name;
import net.posick.DNS.RRset;
import net.posick.DNS.Type;

import java.time.Instant;
import java.util.Date;

/**
 * Resource Record Signature - An RRSIG provides the digital signature of an RRset, so that the data
 * can be authenticated by a DNSSEC-capable resolver. The signature is generated by a key contained
 * in a DNSKEY Record.
 *
 * @see RRset
 * @see DNSSEC
 * @see KEYRecord
 * @see <a href="https://tools.ietf.org/html/rfc4034">RFC 4034: Resource Records for the DNS
 *     Security Extensions</a>
 * @author Brian Wellington
 */
public class RRSIGRecord extends net.posick.DNS.SIGBase {
  RRSIGRecord() {}

  /**
   * Creates an RRSIG Record from the given data
   *
   * @param covered The RRset type covered by this signature
   * @param alg The cryptographic algorithm of the key that generated the signature
   * @param origttl The original TTL of the RRset
   * @param expire The time at which the signature expires
   * @param timeSigned The time at which this signature was generated
   * @param footprint The footprint/key id of the signing key.
   * @param signer The owner of the signing key
   * @param signature Binary data representing the signature
   */
  public RRSIGRecord(
      net.posick.DNS.Name name,
      int dclass,
      long ttl,
      int covered,
      int alg,
      long origttl,
      Instant expire,
      Instant timeSigned,
      int footprint,
      net.posick.DNS.Name signer,
      byte[] signature) {
    super(
        name,
        net.posick.DNS.Type.RRSIG,
        dclass,
        ttl,
        covered,
        alg,
        origttl,
        expire,
        timeSigned,
        footprint,
        signer,
        signature);
  }

  /**
   * Creates an RRSIG Record from the given data
   *
   * @param covered The RRset type covered by this signature
   * @param alg The cryptographic algorithm of the key that generated the signature
   * @param origttl The original TTL of the RRset
   * @param expire The time at which the signature expires
   * @param timeSigned The time at which this signature was generated
   * @param footprint The footprint/key id of the signing key.
   * @param signer The owner of the signing key
   * @param signature Binary data representing the signature
   * @deprecated use {@link #RRSIGRecord(net.posick.DNS.Name, int, long, int, int, long, Instant, Instant, int,
   *     net.posick.DNS.Name, byte[])}
   */
  @Deprecated
  public RRSIGRecord(
      net.posick.DNS.Name name,
      int dclass,
      long ttl,
      int covered,
      int alg,
      long origttl,
      Date expire,
      Date timeSigned,
      int footprint,
      Name signer,
      byte[] signature) {
    super(
        name,
        Type.RRSIG,
        dclass,
        ttl,
        covered,
        alg,
        origttl,
        expire.toInstant(),
        timeSigned.toInstant(),
        footprint,
        signer,
        signature);
  }
}