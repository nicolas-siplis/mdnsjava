// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Address;
import net.posick.DNS.Compression;
import net.posick.DNS.DNSInput;
import net.posick.DNS.DNSOutput;
import net.posick.DNS.Name;
import net.posick.DNS.Record;
import net.posick.DNS.Tokenizer;
import net.posick.DNS.Type;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * A6 Record - maps a domain name to an IPv6 address (historic)
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc6563">RFC 6563: Moving A6 to Historic Status</a>
 */
public class A6Record extends Record {
  private int prefixBits;
  private InetAddress suffix;
  private net.posick.DNS.Name prefix;

  A6Record() {}

  /**
   * Creates an A6 Record from the given data
   *
   * @param prefixBits The number of bits in the address prefix
   * @param suffix The address suffix
   * @param prefix The name of the prefix
   */
  public A6Record(
          net.posick.DNS.Name name, int dclass, long ttl, int prefixBits, InetAddress suffix, net.posick.DNS.Name prefix) {
    super(name, Type.A6, dclass, ttl);
    this.prefixBits = checkU8("prefixBits", prefixBits);
    if (suffix != null && Address.familyOf(suffix) != Address.IPv6) {
      throw new IllegalArgumentException("invalid IPv6 address");
    }
    this.suffix = suffix;
    if (prefix != null) {
      this.prefix = checkName("prefix", prefix);
    }
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    prefixBits = in.readU8();
    int suffixbits = 128 - prefixBits;
    int suffixbytes = (suffixbits + 7) / 8;
    if (prefixBits < 128) {
      byte[] bytes = new byte[16];
      in.readByteArray(bytes, 16 - suffixbytes, suffixbytes);
      suffix = InetAddress.getByAddress(bytes);
    }
    if (prefixBits > 0) {
      prefix = new net.posick.DNS.Name(in);
    }
  }

  @Override
  protected void rdataFromString(Tokenizer st, net.posick.DNS.Name origin) throws IOException {
    prefixBits = st.getUInt8();
    if (prefixBits > 128) {
      throw st.exception("prefix bits must be [0..128]");
    } else if (prefixBits < 128) {
      String s = st.getString();
      try {
        suffix = Address.getByAddress(s, Address.IPv6);
      } catch (UnknownHostException e) {
        throw st.exception("invalid IPv6 address: " + s);
      }
    }
    if (prefixBits > 0) {
      prefix = st.getName(origin);
    }
  }

  /** Converts rdata to a String */
  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(prefixBits);
    if (suffix != null) {
      sb.append(" ");
      sb.append(suffix.getHostAddress());
    }
    if (prefix != null) {
      sb.append(" ");
      sb.append(prefix);
    }
    return sb.toString();
  }

  /** Returns the number of bits in the prefix */
  public int getPrefixBits() {
    return prefixBits;
  }

  /** Returns the address suffix */
  public InetAddress getSuffix() {
    return suffix;
  }

  /** Returns the address prefix */
  public Name getPrefix() {
    return prefix;
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU8(prefixBits);
    if (suffix != null) {
      int suffixbits = 128 - prefixBits;
      int suffixbytes = (suffixbits + 7) / 8;
      byte[] data = suffix.getAddress();
      out.writeByteArray(data, 16 - suffixbytes, suffixbytes);
    }
    if (prefix != null) {
      prefix.toWire(out, null, canonical);
    }
  }
}
