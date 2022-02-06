// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2002-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import net.posick.DNS.AAAARecord;
import net.posick.DNS.ARecord;
import net.posick.DNS.CNAMERecord;
import net.posick.DNS.Cache;
import net.posick.DNS.Credibility;
import net.posick.DNS.DClass;
import net.posick.DNS.DNAMERecord;
import net.posick.DNS.ExtendedResolver;
import net.posick.DNS.Message;
import net.posick.DNS.Name;
import net.posick.DNS.NameTooLongException;
import net.posick.DNS.NioClient;
import net.posick.DNS.PacketLogger;
import net.posick.DNS.RRset;
import net.posick.DNS.Rcode;
import net.posick.DNS.Record;
import net.posick.DNS.Resolver;
import net.posick.DNS.ResolverConfig;
import net.posick.DNS.SetResponse;
import net.posick.DNS.TextParseException;
import net.posick.DNS.Type;
import net.posick.DNS.hosts.HostsFileParser;

/**
 * The Lookup object issues queries to the local hosts database ({@code /etc/hosts}) and to
 * recursive DNS servers. The input consists of a name, an optional type, and an optional class.
 * Caching is enabled by default and used when possible to reduce the number of DNS requests. A
 * {@link Resolver}, which defaults to an {@link ExtendedResolver} initialized with the resolvers
 * located by the {@link ResolverConfig} class, performs the queries. A search path of domain
 * suffixes is used to resolve relative names, and is also determined by the {@link ResolverConfig}
 * class.
 *
 * <p>A Lookup object may be reused, but should not be used by multiple threads.
 *
 * <p>Lookup is considered legacy (but not yet deprecated). Use {@link
 * net.posick.DNS.lookup.LookupSession} instead, which is thread safe and fully async.
 *
 * @see net.posick.DNS.lookup.LookupSession
 * @see net.posick.DNS.Cache
 * @see Resolver
 * @see ResolverConfig
 * @see HostsFileParser
 * @author Brian Wellington
 */
@Slf4j
public final class Lookup {

  private static Resolver defaultResolver;
  private static List<net.posick.DNS.Name> defaultSearchPath;
  private static Map<Integer, net.posick.DNS.Cache> defaultCaches;
  private static int defaultNdots;
  private static HostsFileParser defaultHostsFileParser;

  private Resolver resolver;
  private List<net.posick.DNS.Name> searchPath;
  private int ndots;
  private net.posick.DNS.Cache cache;
  private boolean temporary_cache;
  private int credibility;
  private final net.posick.DNS.Name name;
  private final int type;
  private final int dclass;
  private int iterations;
  private boolean foundAlias;
  private boolean done;
  private boolean doneCurrent;
  private List<net.posick.DNS.Name> aliases;
  private net.posick.DNS.Record[] answers;
  private int result;
  private String error;
  private boolean nxdomain;
  private boolean badresponse;
  private String badresponse_error;
  private boolean networkerror;
  private boolean timedout;
  private boolean nametoolong;
  private boolean referral;
  private boolean cycleResults = true;
  private final int maxIterations;

  /**
   * Gets or sets the local hosts database parser to use for lookup before using a {@link Resolver}.
   *
   * @since 3.4
   */
  @Getter @Setter private HostsFileParser hostsFileParser;

  private static final net.posick.DNS.Name[] noAliases = new net.posick.DNS.Name[0];

  /** The lookup was successful. */
  public static final int SUCCESSFUL = 0;

  /** The lookup failed due to a data or server error. Repeating the lookup would not be helpful. */
  public static final int UNRECOVERABLE = 1;

  /** The lookup failed due to a network error. Repeating the lookup may be helpful. */
  public static final int TRY_AGAIN = 2;

  /** The host does not exist. */
  public static final int HOST_NOT_FOUND = 3;

  /** The host exists, but has no records associated with the queried type. */
  public static final int TYPE_NOT_FOUND = 4;

  public static synchronized void refreshDefault() {
    defaultResolver = new ExtendedResolver();
    defaultSearchPath = ResolverConfig.getCurrentConfig().searchPath();
    defaultCaches = new HashMap<>();
    defaultNdots = ResolverConfig.getCurrentConfig().ndots();
    defaultHostsFileParser = new HostsFileParser();
  }

  static {
    refreshDefault();
  }

  /**
   * Gets the Resolver that will be used as the default by future Lookups.
   *
   * @return The default resolver.
   */
  public static synchronized Resolver getDefaultResolver() {
    return defaultResolver;
  }

  /**
   * Sets the default Resolver to be used as the default by future Lookups.
   *
   * @param resolver The default resolver.
   */
  public static synchronized void setDefaultResolver(Resolver resolver) {
    defaultResolver = resolver;
  }

  /**
   * Gets the Cache that will be used as the default for the specified class by future Lookups.
   *
   * @param dclass The class whose cache is being retrieved.
   * @return The default cache for the specified class.
   */
  public static synchronized net.posick.DNS.Cache getDefaultCache(int dclass) {
    DClass.check(dclass);
    net.posick.DNS.Cache c = defaultCaches.get(dclass);
    if (c == null) {
      c = new net.posick.DNS.Cache(dclass);
      defaultCaches.put(dclass, c);
    }
    return c;
  }

  /**
   * Sets the Cache to be used as the default for the specified class by future Lookups.
   *
   * @param cache The default cache for the specified class.
   * @param dclass The class whose cache is being set.
   */
  public static synchronized void setDefaultCache(net.posick.DNS.Cache cache, int dclass) {
    DClass.check(dclass);
    defaultCaches.put(dclass, cache);
  }

  /**
   * Gets the search path that will be used as the default by future Lookups.
   *
   * @return The default search path.
   */
  public static synchronized List<net.posick.DNS.Name> getDefaultSearchPath() {
    return defaultSearchPath;
  }

  /**
   * Sets the search path to be used as the default by future Lookups.
   *
   * @param domains The default search path.
   * @throws IllegalArgumentException if a domain in the search path is not absolute and cannot be
   *     made absolute.
   */
  public static synchronized void setDefaultSearchPath(List<net.posick.DNS.Name> domains) {
    defaultSearchPath = convertSearchPathDomainList(domains);
  }

  /**
   * Sets the search path to be used as the default by future Lookups.
   *
   * @param domains The default search path.
   * @throws IllegalArgumentException if a domain in the search path is not absolute and cannot be
   *     made absolute.
   */
  public static synchronized void setDefaultSearchPath(net.posick.DNS.Name... domains) {
    setDefaultSearchPath(Arrays.asList(domains));
  }

  /**
   * Sets the search path that will be used as the default by future Lookups.
   *
   * @param domains The default search path.
   * @throws net.posick.DNS.TextParseException A name in the array is not a valid DNS name.
   */
  public static synchronized void setDefaultSearchPath(String... domains)
      throws net.posick.DNS.TextParseException {
    if (domains == null) {
      defaultSearchPath = null;
      return;
    }

    List<net.posick.DNS.Name> newdomains = new ArrayList<>(domains.length);
    for (String domain : domains) {
      newdomains.add(net.posick.DNS.Name.fromString(domain, net.posick.DNS.Name.root));
    }

    defaultSearchPath = newdomains;
  }

  /**
   * Gets the default {@link HostsFileParser} to use for new Lookup instances.
   *
   * @since 3.4
   */
  public static synchronized HostsFileParser getDefaultHostsFileParser() {
    return defaultHostsFileParser;
  }

  /**
   * Sets the default {@link HostsFileParser} to use for new Lookup instances.
   *
   * @since 3.4
   */
  public static synchronized void setDefaultHostsFileParser(HostsFileParser hostsFileParser) {
    defaultHostsFileParser = hostsFileParser;
  }

  private static List<net.posick.DNS.Name> convertSearchPathDomainList(List<net.posick.DNS.Name> domains) {
    try {
      return domains.stream()
          .map(
              n -> {
                try {
                  return net.posick.DNS.Name.concatenate(n, net.posick.DNS.Name.root);
                } catch (net.posick.DNS.NameTooLongException e) {
                  throw new RuntimeException(e);
                }
              })
          .collect(Collectors.toList());
    } catch (RuntimeException e) {
      if (e.getCause() instanceof net.posick.DNS.NameTooLongException) {
        throw new IllegalArgumentException(e.getCause());
      } else {
        throw e;
      }
    }
  }

  /**
   * Sets a custom logger that will be used to log the sent and received packets.
   *
   * @param logger The logger
   */
  public static synchronized void setPacketLogger(PacketLogger logger) {
    NioClient.setPacketLogger(logger);
  }

  private void reset() {
    iterations = 0;
    foundAlias = false;
    done = false;
    doneCurrent = false;
    aliases = null;
    answers = null;
    result = -1;
    error = null;
    nxdomain = false;
    badresponse = false;
    badresponse_error = null;
    networkerror = false;
    timedout = false;
    nametoolong = false;
    referral = false;
    if (temporary_cache) {
      cache.clearCache();
    }
  }

  /**
   * Create a Lookup object that will find records of the given name, type, and class. The lookup
   * will use the default cache, resolver, and search path, and look for records that are reasonably
   * credible.
   *
   * @param name The name of the desired records
   * @param type The type of the desired records
   * @param dclass The class of the desired records
   * @throws IllegalArgumentException The type is a meta type other than ANY.
   * @see net.posick.DNS.Cache
   * @see Resolver
   * @see net.posick.DNS.Credibility
   * @see net.posick.DNS.Name
   * @see net.posick.DNS.Type
   * @see DClass
   */
  public Lookup(net.posick.DNS.Name name, int type, int dclass) {
    net.posick.DNS.Type.check(type);
    DClass.check(dclass);
    if (!net.posick.DNS.Type.isRR(type) && type != net.posick.DNS.Type.ANY) {
      throw new IllegalArgumentException("Cannot query for meta-types other than ANY");
    }
    this.name = name;
    this.type = type;
    this.dclass = dclass;
    synchronized (Lookup.class) {
      this.resolver = getDefaultResolver();
      this.searchPath = getDefaultSearchPath();
      this.cache = getDefaultCache(dclass);
    }
    this.ndots = defaultNdots;
    this.credibility = Credibility.NORMAL;
    this.result = -1;
    this.maxIterations =
        Integer.parseInt(System.getProperty("dnsjava.lookup.max_iterations", "16"));
    if (Boolean.parseBoolean(System.getProperty("dnsjava.lookup.use_hosts_file", "true"))) {
      this.hostsFileParser = getDefaultHostsFileParser();
    }
  }

  /**
   * Create a Lookup object that will find records of the given name and type in the IN class.
   *
   * @param name The name of the desired records
   * @param type The type of the desired records
   * @throws IllegalArgumentException The type is a meta type other than ANY.
   * @see #Lookup(net.posick.DNS.Name,int,int)
   */
  public Lookup(net.posick.DNS.Name name, int type) {
    this(name, type, DClass.IN);
  }

  /**
   * Create a Lookup object that will find records of type A at the given name in the IN class.
   *
   * @param name The name of the desired records
   * @see #Lookup(net.posick.DNS.Name,int,int)
   */
  public Lookup(net.posick.DNS.Name name) {
    this(name, net.posick.DNS.Type.A, DClass.IN);
  }

  /**
   * Create a Lookup object that will find records of the given name, type, and class.
   *
   * @param name The name of the desired records
   * @param type The type of the desired records
   * @param dclass The class of the desired records
   * @throws net.posick.DNS.TextParseException The name is not a valid DNS name
   * @throws IllegalArgumentException The type is a meta type other than ANY.
   * @see #Lookup(net.posick.DNS.Name,int,int)
   */
  public Lookup(String name, int type, int dclass) throws net.posick.DNS.TextParseException {
    this(net.posick.DNS.Name.fromString(name), type, dclass);
  }

  /**
   * Create a Lookup object that will find records of the given name and type in the IN class.
   *
   * @param name The name of the desired records
   * @param type The type of the desired records
   * @throws net.posick.DNS.TextParseException The name is not a valid DNS name
   * @throws IllegalArgumentException The type is a meta type other than ANY.
   * @see #Lookup(net.posick.DNS.Name,int,int)
   */
  public Lookup(String name, int type) throws net.posick.DNS.TextParseException {
    this(net.posick.DNS.Name.fromString(name), type, DClass.IN);
  }

  /**
   * Create a Lookup object that will find records of type A at the given name in the IN class.
   *
   * @param name The name of the desired records
   * @throws net.posick.DNS.TextParseException The name is not a valid DNS name
   * @see #Lookup(net.posick.DNS.Name,int,int)
   */
  public Lookup(String name) throws net.posick.DNS.TextParseException {
    this(net.posick.DNS.Name.fromString(name), net.posick.DNS.Type.A, DClass.IN);
  }

  /**
   * Sets the resolver to use when performing this lookup. This overrides the default value.
   *
   * @param resolver The resolver to use.
   */
  public void setResolver(Resolver resolver) {
    this.resolver = resolver;
  }

  /**
   * Sets the search path to use when performing this lookup. This overrides the default value.
   *
   * @param domains An array of names containing the search path.
   * @throws IllegalArgumentException if a domain in the search path is not absolute and cannot be
   *     made absolute.
   */
  public void setSearchPath(List<net.posick.DNS.Name> domains) {
    this.searchPath = convertSearchPathDomainList(domains);
  }

  /**
   * Sets the search path to use when performing this lookup. This overrides the default value.
   *
   * @param domains An array of names containing the search path.
   * @throws IllegalArgumentException if a domain in the search path is not absolute and cannot be
   *     made absolute.
   */
  public void setSearchPath(net.posick.DNS.Name... domains) {
    setSearchPath(Arrays.asList(domains));
  }

  /**
   * Sets the search path to use when performing this lookup. This overrides the default value.
   *
   * @param domains An array of names containing the search path.
   * @throws net.posick.DNS.TextParseException A name in the array is not a valid DNS name.
   */
  public void setSearchPath(String... domains) throws TextParseException {
    if (domains == null) {
      this.searchPath = null;
      return;
    }

    List<net.posick.DNS.Name> newdomains = new ArrayList<>(domains.length);
    for (String domain : domains) {
      newdomains.add(net.posick.DNS.Name.fromString(domain, net.posick.DNS.Name.root));
    }
    this.searchPath = newdomains;
  }

  /**
   * Sets the cache to use when performing this lookup. This overrides the default value. If the
   * results of this lookup should not be permanently cached, null can be provided here.
   *
   * @param cache The cache to use.
   */
  public void setCache(net.posick.DNS.Cache cache) {
    if (cache == null) {
      this.cache = new Cache(dclass);
      this.temporary_cache = true;
    } else {
      this.cache = cache;
      this.temporary_cache = false;
    }
  }

  /**
   * Sets the default ndots to use when performing a lookup, overriding the default value.
   * Specifically, this refers to the number of "dots" which, if present in a name, indicate that a
   * lookup for the absolute name should be attempted before appending any search path elements.
   *
   * @param ndots The ndots value to use, which must be greater than or equal to 0.
   */
  public static void setDefaultNdots(int ndots) {
    if (ndots < 0) {
      throw new IllegalArgumentException("Illegal ndots value: " + ndots);
    }
    defaultNdots = ndots;
  }

  /**
   * Sets ndots to use when performing this lookup, overriding the default value. Specifically, this
   * refers to the number of "dots" which, if present in a name, indicate that a lookup for the
   * absolute name should be attempted before appending any search path elements.
   *
   * @param ndots The ndots value to use, which must be greater than or equal to 0.
   */
  public void setNdots(int ndots) {
    if (ndots < 0) {
      throw new IllegalArgumentException("Illegal ndots value: " + ndots);
    }
    this.ndots = ndots;
  }

  /**
   * Sets the minimum credibility level that will be accepted when performing the lookup. This
   * defaults to Credibility.NORMAL.
   *
   * @param credibility The minimum credibility level.
   */
  public void setCredibility(int credibility) {
    this.credibility = credibility;
  }

  /**
   * Controls the behavior if results being returned from the cache should be cycled in a
   * round-robin style (true) or if the raw lookup results should be returned (false).
   *
   * @param cycleResults The desired behavior of the order of the results
   */
  public void setCycleResults(boolean cycleResults) {
    this.cycleResults = cycleResults;
  }

  private void follow(net.posick.DNS.Name name, net.posick.DNS.Name oldname) {
    foundAlias = true;
    badresponse = false;
    networkerror = false;
    timedout = false;
    nxdomain = false;
    referral = false;
    iterations++;
    if (iterations >= maxIterations || name.equals(oldname)) {
      result = UNRECOVERABLE;
      error = "CNAME loop";
      done = true;
      return;
    }
    if (aliases == null) {
      aliases = new ArrayList<>();
    }
    aliases.add(oldname);
    lookup(name);
  }

  private void processResponse(net.posick.DNS.Name name, net.posick.DNS.SetResponse response) {
    if (response.isSuccessful()) {
      List<net.posick.DNS.RRset> rrsets = response.answers();
      List<net.posick.DNS.Record> l = new ArrayList<>();

      for (RRset set : rrsets) {
        l.addAll(set.rrs(cycleResults));
      }

      result = SUCCESSFUL;
      answers = l.toArray(new net.posick.DNS.Record[0]);
      done = true;
    } else if (response.isNXDOMAIN()) {
      nxdomain = true;
      doneCurrent = true;
      if (iterations > 0) {
        result = HOST_NOT_FOUND;
        done = true;
      }
    } else if (response.isNXRRSET()) {
      result = TYPE_NOT_FOUND;
      answers = null;
      done = true;
    } else if (response.isCNAME()) {
      CNAMERecord cname = response.getCNAME();
      follow(cname.getTarget(), name);
    } else if (response.isDNAME()) {
      DNAMERecord dname = response.getDNAME();
      try {
        follow(name.fromDNAME(dname), name);
      } catch (net.posick.DNS.NameTooLongException e) {
        result = UNRECOVERABLE;
        error = "Invalid DNAME target";
        done = true;
      }
    } else if (response.isDelegation()) {
      // We shouldn't get a referral.  Ignore it.
      referral = true;
    }
  }

  private void lookup(net.posick.DNS.Name current) {
    if (lookupFromHostsFile(current)) {
      return;
    }

    SetResponse sr = cache.lookupRecords(current, type, credibility);
    log.debug("Lookup for {}/{}, cache answer: {}", current, net.posick.DNS.Type.string(type), sr);

    processResponse(current, sr);
    if (done || doneCurrent) {
      return;
    }

    net.posick.DNS.Record question = net.posick.DNS.Record.newRecord(current, type, dclass);
    net.posick.DNS.Message query = net.posick.DNS.Message.newQuery(question);
    Message response;
    try {
      response = resolver.send(query);
    } catch (IOException e) {
      log.debug(
          "Lookup for {}/{}, id={} failed using resolver {}",
          current,
          net.posick.DNS.Type.string(query.getQuestion().getType()),
          query.getHeader().getID(),
          resolver,
          e);

      // A network error occurred.  Press on.
      if (e instanceof InterruptedIOException) {
        timedout = true;
      } else {
        networkerror = true;
      }
      return;
    }
    int rcode = response.getHeader().getRcode();
    if (rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN) {
      // The server we contacted is broken or otherwise unhelpful.
      // Press on.
      badresponse = true;
      badresponse_error = Rcode.string(rcode);
      return;
    }

    if (!query.getQuestion().equals(response.getQuestion())) {
      // The answer doesn't match the question.  That's not good.
      badresponse = true;
      badresponse_error = "response does not match query";
      return;
    }

    sr = cache.addMessage(response);
    if (sr == null) {
      sr = cache.lookupRecords(current, type, credibility);
    }

    log.debug(
        "Queried {}/{}, id={}: {}", current, net.posick.DNS.Type.string(type), response.getHeader().getID(), sr);
    processResponse(current, sr);
  }

  private boolean lookupFromHostsFile(net.posick.DNS.Name current) {
    if (hostsFileParser != null && (type == net.posick.DNS.Type.A || type == net.posick.DNS.Type.AAAA)) {
      try {
        Optional<InetAddress> localLookup = hostsFileParser.getAddressForHost(current, type);
        if (localLookup.isPresent()) {
          result = SUCCESSFUL;
          done = true;
          if (type == net.posick.DNS.Type.A) {
            answers = new net.posick.DNS.ARecord[] {new ARecord(current, dclass, 0L, localLookup.get())};
          } else {
            answers = new net.posick.DNS.AAAARecord[] {new AAAARecord(current, dclass, 0L, localLookup.get())};
          }

          return true;
        }
      } catch (IOException e) {
        log.debug("Local hosts database parsing failed, ignoring and using resolver", e);
      }
    }

    return false;
  }

  private void resolve(net.posick.DNS.Name current, net.posick.DNS.Name suffix) {
    doneCurrent = false;
    net.posick.DNS.Name tname;
    if (suffix == null) {
      tname = current;
    } else {
      try {
        tname = net.posick.DNS.Name.concatenate(current, suffix);
      } catch (NameTooLongException e) {
        nametoolong = true;
        return;
      }
    }
    lookup(tname);
  }

  /**
   * Performs the lookup, using the specified Cache, Resolver, and search path.
   *
   * @return The answers, or null if none are found.
   */
  public net.posick.DNS.Record[] run() {
    if (done) {
      reset();
    }
    if (name.isAbsolute()) {
      resolve(name, null);
    } else if (searchPath == null) {
      resolve(name, net.posick.DNS.Name.root);
    } else {
      if (name.labels() > ndots) {
        resolve(name, net.posick.DNS.Name.root);
      }
      if (done) {
        return answers;
      }

      for (net.posick.DNS.Name value : searchPath) {
        resolve(name, value);
        if (done) {
          return answers;
        } else if (foundAlias) {
          break;
        }
      }

      resolve(name, net.posick.DNS.Name.root);
    }
    if (!done) {
      if (badresponse) {
        result = TRY_AGAIN;
        error = badresponse_error;
        done = true;
      } else if (timedout) {
        result = TRY_AGAIN;
        error = "timed out";
        done = true;
      } else if (networkerror) {
        result = TRY_AGAIN;
        error = "network error";
        done = true;
      } else if (nxdomain) {
        result = HOST_NOT_FOUND;
        done = true;
      } else if (referral) {
        result = UNRECOVERABLE;
        error = "referral";
        done = true;
      } else if (nametoolong) {
        result = UNRECOVERABLE;
        error = "name too long";
        done = true;
      }
    }
    return answers;
  }

  private void checkDone() {
    if (done && result != -1) {
      return;
    }
    StringBuilder sb = new StringBuilder("Lookup of " + name + " ");
    if (dclass != DClass.IN) {
      sb.append(DClass.string(dclass)).append(" ");
    }
    sb.append(Type.string(type)).append(" isn't done");
    throw new IllegalStateException(sb.toString());
  }

  /**
   * Returns the answers from the lookup.
   *
   * @return The answers, or null if none are found.
   * @throws IllegalStateException The lookup has not completed.
   */
  public Record[] getAnswers() {
    checkDone();
    return answers;
  }

  /**
   * Returns all known aliases for this name. Whenever a CNAME/DNAME is followed, an alias is added
   * to this array. The last element in this array will be the owner name for records in the answer,
   * if there are any.
   *
   * @return The aliases.
   * @throws IllegalStateException The lookup has not completed.
   */
  public net.posick.DNS.Name[] getAliases() {
    checkDone();
    if (aliases == null) {
      return noAliases;
    }
    return aliases.toArray(new Name[0]);
  }

  /**
   * Returns the result code of the lookup.
   *
   * @return The result code, which can be SUCCESSFUL, UNRECOVERABLE, TRY_AGAIN, HOST_NOT_FOUND, or
   *     TYPE_NOT_FOUND.
   * @throws IllegalStateException The lookup has not completed.
   */
  public int getResult() {
    checkDone();
    return result;
  }

  /**
   * Returns an error string describing the result code of this lookup.
   *
   * @return A string, which may either directly correspond the result code or be more specific.
   * @throws IllegalStateException The lookup has not completed.
   */
  public String getErrorString() {
    checkDone();
    if (error != null) {
      return error;
    }
    switch (result) {
      case SUCCESSFUL:
        return "successful";
      case UNRECOVERABLE:
        return "unrecoverable error";
      case TRY_AGAIN:
        return "try again";
      case HOST_NOT_FOUND:
        return "host not found";
      case TYPE_NOT_FOUND:
        return "type not found";
    }
    throw new IllegalStateException("unknown result");
  }
}
