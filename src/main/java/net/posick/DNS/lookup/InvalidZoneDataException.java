// SPDX-License-Identifier: BSD-3-Clause
package net.posick.DNS.lookup;

import net.posick.DNS.lookup.LookupFailedException;

/**
 * Sometimes DNS zone data involved in the lookup might be violating specifications. For example, a
 * DNAME expansion might result in names that are too long or a query response might hold multiple
 * CNAME records.
 */
public class InvalidZoneDataException extends LookupFailedException {
  InvalidZoneDataException(String message, Throwable inner) {
    super(message, inner);
  }

  public InvalidZoneDataException(String message) {
    super(message);
  }
}
