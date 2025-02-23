// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2008 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import java.io.IOException;

import net.posick.DNS.Compression;
import net.posick.DNS.DNSInput;
import net.posick.DNS.DNSOutput;
import net.posick.DNS.Name;
import net.posick.DNS.Record;
import net.posick.DNS.Tokenizer;
import net.posick.DNS.Type;
import net.posick.DNS.utils.base64;

/**
 * DHCID - Dynamic Host Configuration Protocol (DHCP) ID (RFC 4701)
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc4701">RFC 4701: A DNS Resource Record (RR) for
 *     Encoding Dynamic Host Configuration Protocol (DHCP) Information (DHCID RR)</a>
 */
public class DHCIDRecord extends Record {
  private byte[] data;

  DHCIDRecord() {}

  /**
   * Creates an DHCID Record from the given data
   *
   * @param data The binary data, which is opaque to DNS.
   */
  public DHCIDRecord(net.posick.DNS.Name name, int dclass, long ttl, byte[] data) {
    super(name, Type.DHCID, dclass, ttl);
    this.data = data;
  }

  @Override
  protected void rrFromWire(DNSInput in) {
    data = in.readByteArray();
  }

  @Override
  protected void rdataFromString(Tokenizer st, Name origin) throws IOException {
    data = st.getBase64();
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeByteArray(data);
  }

  @Override
  protected String rrToString() {
    return base64.toString(data);
  }

  /** Returns the binary data. */
  public byte[] getData() {
    return data;
  }
}
