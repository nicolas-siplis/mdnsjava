// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Name;
import net.posick.DNS.Type;

/**
 * Mail Forwarder Record - specifies a mail agent which forwards mail for a domain (obsolete)
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc973">RFC 973: Domain System Changes and
 *     Observations</a>
 */
public class MFRecord extends SingleNameBase {
  MFRecord() {}

  /**
   * Creates a new MF Record with the given data
   *
   * @param mailAgent The mail agent that forwards mail for the domain.
   */
  public MFRecord(Name name, int dclass, long ttl, Name mailAgent) {
    super(name, Type.MF, dclass, ttl, mailAgent, "mail agent");
  }

  /** Gets the mail agent for the domain */
  public Name getMailAgent() {
    return getSingleName();
  }

  @Override
  public Name getAdditionalName() {
    return getSingleName();
  }
}
