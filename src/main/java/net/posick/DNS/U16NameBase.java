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
 * Implements common functionality for the many record types whose format is an unsigned 16 bit
 * integer followed by a name.
 *
 * @author Brian Wellington
 */
abstract class U16NameBase extends Record {
  protected int u16Field;
  protected net.posick.DNS.Name nameField;

  protected U16NameBase() {}

  protected U16NameBase(net.posick.DNS.Name name, int type, int dclass, long ttl) {
    super(name, type, dclass, ttl);
  }

  protected U16NameBase(
      net.posick.DNS.Name name,
      int type,
      int dclass,
      long ttl,
      int u16Field,
      String u16Description,
      net.posick.DNS.Name nameField,
      String nameDescription) {
    super(name, type, dclass, ttl);
    this.u16Field = checkU16(u16Description, u16Field);
    this.nameField = checkName(nameDescription, nameField);
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    u16Field = in.readU16();
    nameField = new net.posick.DNS.Name(in);
  }

  @Override
  protected void rdataFromString(Tokenizer st, net.posick.DNS.Name origin) throws IOException {
    u16Field = st.getUInt16();
    nameField = st.getName(origin);
  }

  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(u16Field);
    sb.append(" ");
    sb.append(nameField);
    return sb.toString();
  }

  protected int getU16Field() {
    return u16Field;
  }

  protected Name getNameField() {
    return nameField;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU16(u16Field);
    nameField.toWire(out, null, canonical);
  }
}
