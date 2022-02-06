// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Name;
import net.posick.DNS.Type;

/**
 * Mail Destination Record - specifies a mail agent which delivers mail for a domain (obsolete)
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc973">RFC 973: Domain System Changes and
 *     Observations</a>
 */
public class MDRecord extends net.posick.DNS.SingleNameBase {
  MDRecord() {}

  /**
   * Creates a new MD Record with the given data
   *
   * @param mailAgent The mail agent that delivers mail for the domain.
   */
  public MDRecord(net.posick.DNS.Name name, int dclass, long ttl, net.posick.DNS.Name mailAgent) {
    super(name, Type.MD, dclass, ttl, mailAgent, "mail agent");
  }

  /** Gets the mail agent for the domain */
  public net.posick.DNS.Name getMailAgent() {
    return getSingleName();
  }

  @Override
  public Name getAdditionalName() {
    return getSingleName();
  }
}
