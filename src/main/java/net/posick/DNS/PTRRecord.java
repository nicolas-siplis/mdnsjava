// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Name;
import net.posick.DNS.Type;

/**
 * Pointer Record - maps a domain name representing an Internet Address to a hostname.
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035: Domain Names - Implementation and
 *     Specification</a>
 */
public class PTRRecord extends SingleCompressedNameBase {
  PTRRecord() {}

  /**
   * Creates a new PTR Record with the given data
   *
   * @param target The name of the machine with this address
   */
  public PTRRecord(Name name, int dclass, long ttl, Name target) {
    super(name, Type.PTR, dclass, ttl, target, "target");
  }

  /** Gets the target of the PTR Record */
  public Name getTarget() {
    return getSingleName();
  }
}
