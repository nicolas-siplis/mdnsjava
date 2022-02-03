// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Name;
import net.posick.DNS.Type;

/**
 * Route Through Record - lists a route preference and intermediate host.
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035: Domain Names - Implementation and
 *     Specification</a>
 */
public class RTRecord extends U16NameBase {
  RTRecord() {}

  /**
   * Creates an RT Record from the given data
   *
   * @param preference The preference of the route. Smaller numbers indicate more preferred routes.
   * @param intermediateHost The domain name of the host to use as a router.
   */
  public RTRecord(net.posick.DNS.Name name, int dclass, long ttl, int preference, net.posick.DNS.Name intermediateHost) {
    super(
        name, Type.RT, dclass, ttl, preference, "preference", intermediateHost, "intermediateHost");
  }

  /** Gets the preference of the route. */
  public int getPreference() {
    return getU16Field();
  }

  /** Gets the host to use as a router. */
  public Name getIntermediateHost() {
    return getNameField();
  }
}
