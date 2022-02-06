// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Name;
import net.posick.DNS.Type;

/**
 * CNAME Record - maps an alias to its real name
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035: Domain Names - Implementation and
 *     Specification</a>
 */
public class CNAMERecord extends net.posick.DNS.SingleCompressedNameBase {
  CNAMERecord() {}

  /**
   * Creates a new CNAMERecord with the given data
   *
   * @param alias The name to which the CNAME alias points
   */
  public CNAMERecord(net.posick.DNS.Name name, int dclass, long ttl, net.posick.DNS.Name alias) {
    super(name, Type.CNAME, dclass, ttl, alias, "alias");
  }

  /** Gets the target of the CNAME Record */
  public net.posick.DNS.Name getTarget() {
    return getSingleName();
  }

  /**
   * Gets the name of this record, aka the <i>alias</i> or <i>label</i> to the <i>canonical name</i>
   * specified in {@link #getTarget()}.
   *
   * @deprecated use {@link #getName()}
   */
  @Deprecated
  public Name getAlias() {
    return getName();
  }
}
