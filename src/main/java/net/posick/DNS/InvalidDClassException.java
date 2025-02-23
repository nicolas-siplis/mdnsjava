// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2003-2004 Brian Wellington (bwelling@xbill.org)

package net.posick.DNS;

/**
 * An exception thrown when an invalid dclass code is specified.
 *
 * @author Brian Wellington
 */
public class InvalidDClassException extends IllegalArgumentException {

  public InvalidDClassException(int dclass) {
    super("Invalid DNS class: " + dclass);
  }
}
