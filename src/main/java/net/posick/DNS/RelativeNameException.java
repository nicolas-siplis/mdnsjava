// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2003-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

import net.posick.DNS.Name;

/**
 * An exception thrown when a relative name is passed as an argument to a method requiring an
 * absolute name.
 *
 * @author Brian Wellington
 */
public class RelativeNameException extends IllegalArgumentException {

  public RelativeNameException(Name name) {
    super("'" + name + "' is not an absolute name");
  }

  public RelativeNameException(String s) {
    super(s);
  }
}
