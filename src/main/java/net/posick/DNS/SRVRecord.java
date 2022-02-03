// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Compression;
import net.posick.DNS.DNSInput;
import net.posick.DNS.DNSOutput;
import net.posick.DNS.Name;
import net.posick.DNS.Record;
import net.posick.DNS.Tokenizer;
import net.posick.DNS.Type;

import java.io.IOException;

/**
 * Server Selection Record - finds hosts running services in a domain. An SRV record will normally
 * be named _&lt;service&gt;._&lt;protocol&gt;.domain - examples would be _sips._tcp.example.org
 * (for the secure SIP protocol) and _http._tcp.example.com (if HTTP used SRV records)
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc2782">RFC 2782: A DNS RR for specifying the location
 *     of services (DNS SRV)</a>
 */
public class SRVRecord extends Record {
  private int priority, weight, port;
  private net.posick.DNS.Name target;

  SRVRecord() {}

  /**
   * Creates an SRV Record from the given data
   *
   * @param priority The priority of this SRV. Records with lower priority are preferred.
   * @param weight The weight, used to select between records at the same priority.
   * @param port The TCP/UDP port that the service uses
   * @param target The host running the service
   */
  public SRVRecord(
          net.posick.DNS.Name name, int dclass, long ttl, int priority, int weight, int port, net.posick.DNS.Name target) {
    super(name, Type.SRV, dclass, ttl);
    this.priority = checkU16("priority", priority);
    this.weight = checkU16("weight", weight);
    this.port = checkU16("port", port);
    this.target = checkName("target", target);
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    priority = in.readU16();
    weight = in.readU16();
    port = in.readU16();
    target = new net.posick.DNS.Name(in);
  }

  @Override
  protected void rdataFromString(Tokenizer st, net.posick.DNS.Name origin) throws IOException {
    priority = st.getUInt16();
    weight = st.getUInt16();
    port = st.getUInt16();
    target = st.getName(origin);
  }

  /** Converts rdata to a String */
  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(priority).append(" ");
    sb.append(weight).append(" ");
    sb.append(port).append(" ");
    sb.append(target);
    return sb.toString();
  }

  /** Returns the priority */
  public int getPriority() {
    return priority;
  }

  /** Returns the weight */
  public int getWeight() {
    return weight;
  }

  /** Returns the port that the service runs on */
  public int getPort() {
    return port;
  }

  /** Returns the host running that the service */
  public net.posick.DNS.Name getTarget() {
    return target;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU16(priority);
    out.writeU16(weight);
    out.writeU16(port);
    target.toWire(out, null, canonical);
  }

  @Override
  public Name getAdditionalName() {
    return target;
  }
}
