// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Name;
import net.posick.DNS.Type;

/**
 * DNAME Record - maps a nonterminal alias (subtree) to a different domain
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc6672">RFC 6672: DNAME Redirection in the DNS</a>
 */
public class DNAMERecord extends SingleNameBase {
  DNAMERecord() {}

  /**
   * Creates a new DNAMERecord with the given data
   *
   * @param alias The name to which the DNAME alias points
   */
  public DNAMERecord(net.posick.DNS.Name name, int dclass, long ttl, net.posick.DNS.Name alias) {
    super(name, Type.DNAME, dclass, ttl, alias, "alias");
  }

  /** Gets the target of the DNAME Record */
  public net.posick.DNS.Name getTarget() {
    return getSingleName();
  }

  /**
   * Gets the name of this record, aka the <i>alias</i> or <i>label</i> to the <i>delegation
   * name</i> specified in {@link #getTarget()}.
   *
   * @deprecated use {@link #getName()}
   */
  @Deprecated
  public Name getAlias() {
    return getName();
  }
}
