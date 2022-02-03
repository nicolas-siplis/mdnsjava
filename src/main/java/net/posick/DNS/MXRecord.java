// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Compression;
import net.posick.DNS.DNSOutput;
import net.posick.DNS.Name;
import net.posick.DNS.Type;

/**
 * Mail Exchange - specifies where mail to a domain is sent
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035: Domain Names - Implementation and
 *     Specification</a>
 * @see <a href="https://tools.ietf.org/html/rfc7505">RFC 7505: A "Null MX" No Service Resource
 *     Record for Domains That Accept No Mail</a>
 */
public class MXRecord extends net.posick.DNS.U16NameBase {
  MXRecord() {}

  /**
   * Creates an MX Record from the given data
   *
   * @param priority The priority of this MX. Records with lower priority are preferred.
   * @param target The host that mail is sent to
   */
  public MXRecord(net.posick.DNS.Name name, int dclass, long ttl, int priority, net.posick.DNS.Name target) {
    super(name, Type.MX, dclass, ttl, priority, "priority", target, "target");
  }

  /** Returns the target of the MX record */
  public net.posick.DNS.Name getTarget() {
    return getNameField();
  }

  /** Returns the priority of this MX record */
  public int getPriority() {
    return getU16Field();
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU16(u16Field);
    nameField.toWire(out, c, canonical);
  }

  @Override
  public Name getAdditionalName() {
    return getNameField();
  }
}
