// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Compression;
import net.posick.DNS.DNSInput;
import net.posick.DNS.DNSOutput;
import net.posick.DNS.Name;
import net.posick.DNS.Options;
import net.posick.DNS.Record;
import net.posick.DNS.Tokenizer;
import net.posick.DNS.Type;

import java.io.IOException;

/**
 * Start of Authority - describes properties of a zone.
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035: Domain Names - Implementation and
 *     Specification</a>
 */
public class SOARecord extends Record {
  private net.posick.DNS.Name host, admin;
  private long serial, refresh, retry, expire, minimum;

  SOARecord() {}

  /**
   * Creates an SOA Record from the given data
   *
   * @param host The primary name server for the zone
   * @param admin The zone administrator's address
   * @param serial The zone's serial number
   * @param refresh The amount of time until a secondary checks for a new serial number
   * @param retry The amount of time between a secondary's checks for a new serial number
   * @param expire The amount of time until a secondary expires a zone
   * @param minimum The minimum TTL for records in the zone
   */
  public SOARecord(
      net.posick.DNS.Name name,
      int dclass,
      long ttl,
      net.posick.DNS.Name host,
      net.posick.DNS.Name admin,
      long serial,
      long refresh,
      long retry,
      long expire,
      long minimum) {
    super(name, Type.SOA, dclass, ttl);
    this.host = checkName("host", host);
    this.admin = checkName("admin", admin);
    this.serial = checkU32("serial", serial);
    this.refresh = checkU32("refresh", refresh);
    this.retry = checkU32("retry", retry);
    this.expire = checkU32("expire", expire);
    this.minimum = checkU32("minimum", minimum);
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    host = new net.posick.DNS.Name(in);
    admin = new net.posick.DNS.Name(in);
    serial = in.readU32();
    refresh = in.readU32();
    retry = in.readU32();
    expire = in.readU32();
    minimum = in.readU32();
  }

  @Override
  protected void rdataFromString(Tokenizer st, net.posick.DNS.Name origin) throws IOException {
    host = st.getName(origin);
    admin = st.getName(origin);
    serial = st.getUInt32();
    refresh = st.getTTLLike();
    retry = st.getTTLLike();
    expire = st.getTTLLike();
    minimum = st.getTTLLike();
  }

  /** Convert to a String */
  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(host);
    sb.append(" ");
    sb.append(admin);
    if (Options.check("multiline")) {
      sb.append(" (\n\t\t\t\t\t");
      sb.append(serial);
      sb.append("\t; serial\n\t\t\t\t\t");
      sb.append(refresh);
      sb.append("\t; refresh\n\t\t\t\t\t");
      sb.append(retry);
      sb.append("\t; retry\n\t\t\t\t\t");
      sb.append(expire);
      sb.append("\t; expire\n\t\t\t\t\t");
      sb.append(minimum);
      sb.append(" )\t; minimum");
    } else {
      sb.append(" ");
      sb.append(serial);
      sb.append(" ");
      sb.append(refresh);
      sb.append(" ");
      sb.append(retry);
      sb.append(" ");
      sb.append(expire);
      sb.append(" ");
      sb.append(minimum);
    }
    return sb.toString();
  }

  /** Returns the primary name server */
  public net.posick.DNS.Name getHost() {
    return host;
  }

  /** Returns the zone administrator's address */
  public Name getAdmin() {
    return admin;
  }

  /** Returns the zone's serial number */
  public long getSerial() {
    return serial;
  }

  /** Returns the zone refresh interval */
  public long getRefresh() {
    return refresh;
  }

  /** Returns the zone retry interval */
  public long getRetry() {
    return retry;
  }

  /** Returns the time until a secondary expires a zone */
  public long getExpire() {
    return expire;
  }

  /** Returns the minimum TTL for records in the zone */
  public long getMinimum() {
    return minimum;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    host.toWire(out, c, canonical);
    admin.toWire(out, c, canonical);
    out.writeU32(serial);
    out.writeU32(refresh);
    out.writeU32(retry);
    out.writeU32(expire);
    out.writeU32(minimum);
  }
}
