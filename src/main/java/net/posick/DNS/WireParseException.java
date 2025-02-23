// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import java.io.IOException;

/**
 * An exception thrown when a DNS message is invalid.
 *
 * @author Brian Wellington
 */
public class WireParseException extends IOException {

  public WireParseException() {
    super();
  }

  public WireParseException(String s) {
    super(s);
  }

  public WireParseException(String s, Throwable cause) {
    super(s);
    initCause(cause);
  }
}
