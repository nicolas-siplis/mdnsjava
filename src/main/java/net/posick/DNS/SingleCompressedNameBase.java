// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Compression;
import net.posick.DNS.DNSOutput;
import net.posick.DNS.Name;

/**
 * Implements common functionality for the many record types whose format is a single compressed
 * name.
 *
 * @author Brian Wellington
 */
abstract class SingleCompressedNameBase extends SingleNameBase {
  protected SingleCompressedNameBase() {}

  protected SingleCompressedNameBase(
          Name name, int type, int dclass, long ttl, Name singleName, String description) {
    super(name, type, dclass, ttl, singleName, description);
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    singleName.toWire(out, c, canonical);
  }
}
