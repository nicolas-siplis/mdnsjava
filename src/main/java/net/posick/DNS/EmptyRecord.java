// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Compression;
import net.posick.DNS.DNSInput;
import net.posick.DNS.DNSOutput;
import net.posick.DNS.Name;
import net.posick.DNS.Record;
import net.posick.DNS.Tokenizer;

/**
 * A class implementing Records with no data; that is, records used in the question section of
 * messages and meta-records in dynamic update.
 *
 * @author Brian Wellington
 */
class EmptyRecord extends Record {
  EmptyRecord() {}

  @Override
  protected void rrFromWire(DNSInput in) {}

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) {}

  @Override
  protected String rrToString() {
    return "";
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {}
}
