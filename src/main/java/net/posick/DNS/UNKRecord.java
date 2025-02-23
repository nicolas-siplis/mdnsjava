// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Compression;
import net.posick.DNS.DNSInput;
import net.posick.DNS.DNSOutput;
import net.posick.DNS.Name;
import net.posick.DNS.Record;
import net.posick.DNS.Tokenizer;

import java.io.IOException;

/**
 * A class implementing Records of unknown and/or unimplemented types. This class can only be
 * initialized using static Record initializers.
 *
 * @author Brian Wellington
 */
public class UNKRecord extends Record {
  private byte[] data;

  UNKRecord() {}

  @Override
  protected void rrFromWire(DNSInput in) {
    data = in.readByteArray();
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    throw st.exception("invalid unknown RR encoding");
  }

  /** Converts this Record to the String "unknown format" */
  @Override
  protected String rrToString() {
    return unknownToString(data);
  }

  /** Returns the contents of this record. */
  public byte[] getData() {
    return data;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeByteArray(data);
  }
}
