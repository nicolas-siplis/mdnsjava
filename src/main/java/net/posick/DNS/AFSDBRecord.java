// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Name;
import net.posick.DNS.Type;

/**
 * AFS Data Base Record - maps a domain name to the name of an AFS cell database server.
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1183">RFC 1183: New DNS RR Definitions</a>
 */
public class AFSDBRecord extends net.posick.DNS.U16NameBase {
  AFSDBRecord() {}

  /**
   * Creates an AFSDB Record from the given data.
   *
   * @param subtype Indicates the type of service provided by the host.
   * @param host The host providing the service.
   */
  public AFSDBRecord(net.posick.DNS.Name name, int dclass, long ttl, int subtype, net.posick.DNS.Name host) {
    super(name, Type.AFSDB, dclass, ttl, subtype, "subtype", host, "host");
  }

  /** Gets the subtype indicating the service provided by the host. */
  public int getSubtype() {
    return getU16Field();
  }

  /** Gets the host providing service for the domain. */
  public Name getHost() {
    return getNameField();
  }
}
