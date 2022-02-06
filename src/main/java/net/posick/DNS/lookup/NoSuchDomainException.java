// SPDX-License-Identifier: BSD-3-Clause
package net.posick.DNS.lookup;

import net.posick.DNS.Name;
import net.posick.DNS.lookup.LookupFailedException;

/**
 * Thrown to indicate that no data is associated with the given name, as indicated by the NXDOMAIN
 * response code as specified in RF2136 Section 2.2.
 */
public class NoSuchDomainException extends LookupFailedException {
  public NoSuchDomainException(Name name, int type) {
    super(name, type);
  }
}
