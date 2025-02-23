// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)
package net.posick.DNS;

import net.posick.DNS.DNSInput;
import net.posick.DNS.DNSOutput;
import net.posick.DNS.Record;
import net.posick.DNS.utils.base16;

/**
 * An EDNSOption with no internal structure.
 *
 * @author Ming Zhou &lt;mizhou@bnivideo.com&gt;, Beaumaris Networks
 * @author Brian Wellington
 */
public class GenericEDNSOption extends net.posick.DNS.EDNSOption {

  private byte[] data;

  GenericEDNSOption(int code) {
    super(code);
  }

  /**
   * Construct a generic EDNS option.
   *
   * @param data The contents of the option.
   */
  public GenericEDNSOption(int code, byte[] data) {
    super(code);
    this.data = Record.checkByteArrayLength("option data", data, 0xFFFF);
  }

  @Override
  void optionFromWire(DNSInput in) {
    data = in.readByteArray();
  }

  @Override
  void optionToWire(DNSOutput out) {
    out.writeByteArray(data);
  }

  @Override
  String optionToString() {
    return "<" + base16.toString(data) + ">";
  }
}
