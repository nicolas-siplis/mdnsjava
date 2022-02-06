// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.GenericEDNSOption;
import net.posick.DNS.OPTRecord;

/**
 * The Name Server Identifier Option
 *
 * @see OPTRecord
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc5001">RFC 5001: DNS Name Server Identifier (NSID)
 *     Option</a>
 */
public class NSIDOption extends GenericEDNSOption {
  NSIDOption() {
    super(Code.NSID);
  }

  /**
   * Construct an NSID option.
   *
   * @param data The contents of the option.
   */
  public NSIDOption(byte[] data) {
    super(Code.NSID, data);
  }
}
