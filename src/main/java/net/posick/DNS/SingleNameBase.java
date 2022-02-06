// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Compression;
import net.posick.DNS.DNSInput;
import net.posick.DNS.DNSOutput;
import net.posick.DNS.Name;
import net.posick.DNS.Record;
import net.posick.DNS.Tokenizer;

import java.io.IOException;

/**
 * Implements common functionality for the many record types whose format is a single name.
 *
 * @author Brian Wellington
 */
abstract class SingleNameBase extends Record {
  protected net.posick.DNS.Name singleName;

  protected SingleNameBase() {}

  protected SingleNameBase(net.posick.DNS.Name name, int type, int dclass, long ttl) {
    super(name, type, dclass, ttl);
  }

  protected SingleNameBase(
          net.posick.DNS.Name name, int type, int dclass, long ttl, net.posick.DNS.Name singleName, String description) {
    super(name, type, dclass, ttl);
    this.singleName = checkName(description, singleName);
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    singleName = new net.posick.DNS.Name(in);
  }

  @Override
  protected void rdataFromString(Tokenizer st, net.posick.DNS.Name origin) throws IOException {
    singleName = st.getName(origin);
  }

  @Override
  protected String rrToString() {
    return singleName.toString();
  }

  protected Name getSingleName() {
    return singleName;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    singleName.toWire(out, null, canonical);
  }
}
