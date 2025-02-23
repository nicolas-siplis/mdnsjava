// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Compression;
import net.posick.DNS.DNSInput;
import net.posick.DNS.DNSOutput;
import net.posick.DNS.Name;
import net.posick.DNS.Record;
import net.posick.DNS.Tokenizer;
import net.posick.DNS.Type;

import java.io.IOException;

/**
 * The NULL Record. This has no defined purpose, but can be used to hold arbitrary data.
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035: Domain Names - Implementation and
 *     Specification</a>
 */
public class NULLRecord extends Record {
  private byte[] data;

  NULLRecord() {}

  /**
   * Creates a NULL record from the given data.
   *
   * @param data The contents of the record.
   */
  public NULLRecord(net.posick.DNS.Name name, int dclass, long ttl, byte[] data) {
    super(name, Type.NULL, dclass, ttl);

    if (data.length > 0xFFFF) {
      throw new IllegalArgumentException("data must be <65536 bytes");
    }
    this.data = data;
  }

  @Override
  protected void rrFromWire(DNSInput in) {
    data = in.readByteArray();
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    throw st.exception("no defined text format for NULL records");
  }

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
