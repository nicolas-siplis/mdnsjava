// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Name;
import net.posick.DNS.Type;

/**
 * Key Exchange - delegation of authority
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc2230">RFC 2230: Key Exchange Delegation Record for
 *     the DNS</a>
 */
public class KXRecord extends net.posick.DNS.U16NameBase {
  KXRecord() {}

  /**
   * Creates a KX Record from the given data
   *
   * @param preference The preference of this KX. Records with lower priority are preferred.
   * @param target The host that authority is delegated to
   */
  public KXRecord(net.posick.DNS.Name name, int dclass, long ttl, int preference, net.posick.DNS.Name target) {
    super(name, Type.KX, dclass, ttl, preference, "preference", target, "target");
  }

  /** Returns the target of the KX record */
  public net.posick.DNS.Name getTarget() {
    return getNameField();
  }

  /** Returns the preference of this KX record */
  public int getPreference() {
    return getU16Field();
  }

  @Override
  public Name getAdditionalName() {
    return getNameField();
  }
}
