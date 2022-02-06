// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Compression;
import net.posick.DNS.DNSInput;
import net.posick.DNS.DNSOutput;
import net.posick.DNS.Name;
import net.posick.DNS.Record;
import net.posick.DNS.TextParseException;
import net.posick.DNS.Tokenizer;
import net.posick.DNS.Type;

import java.io.IOException;

/**
 * Host Information - describes the CPU and OS of a host
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc1035">RFC 1035: Domain Names - Implementation and
 *     Specification</a>
 */
public class HINFORecord extends Record {
  private byte[] cpu, os;

  HINFORecord() {}

  /**
   * Creates an HINFO Record from the given data
   *
   * @param cpu A string describing the host's CPU
   * @param os A string describing the host's OS
   * @throws IllegalArgumentException One of the strings has invalid escapes
   */
  public HINFORecord(net.posick.DNS.Name name, int dclass, long ttl, String cpu, String os) {
    super(name, Type.HINFO, dclass, ttl);
    try {
      this.cpu = byteArrayFromString(cpu);
      this.os = byteArrayFromString(os);
    } catch (TextParseException e) {
      throw new IllegalArgumentException(e.getMessage());
    }
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    cpu = in.readCountedString();
    os = in.readCountedString();
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    try {
      cpu = byteArrayFromString(st.getString());
      os = byteArrayFromString(st.getString());
    } catch (TextParseException e) {
      throw st.exception(e.getMessage());
    }
  }

  /** Returns the host's CPU */
  public String getCPU() {
    return byteArrayToString(cpu, false);
  }

  /** Returns the host's OS */
  public String getOS() {
    return byteArrayToString(os, false);
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeCountedString(cpu);
    out.writeCountedString(os);
  }

  /** Converts to a string */
  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(byteArrayToString(cpu, true));
    sb.append(" ");
    sb.append(byteArrayToString(os, true));
    return sb.toString();
  }
}
