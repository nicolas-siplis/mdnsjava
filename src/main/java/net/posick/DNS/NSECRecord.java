// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)

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
 * Next SECure name - this record contains the following name in an ordered list of names in the
 * zone, and a set of types for which records exist for this name. The presence of this record in a
 * response signifies a negative response from a DNSSEC-signed zone.
 *
 * <p>This replaces the NXT record.
 *
 * @author Brian Wellington
 * @author David Blacka
 * @see <a href="https://tools.ietf.org/html/rfc4034">RFC 4034: Resource Records for the DNS
 *     Security Extensions</a>
 */
public class NSECRecord extends Record {
  private net.posick.DNS.Name next;
  private net.posick.DNS.TypeBitmap types;

  NSECRecord() {}

  /**
   * Creates an NSEC Record from the given data.
   *
   * @param next The following name in an ordered list of the zone
   * @param types An array containing the types present.
   */
  public NSECRecord(net.posick.DNS.Name name, int dclass, long ttl, net.posick.DNS.Name next, int[] types) {
    super(name, net.posick.DNS.Type.NSEC, dclass, ttl);
    this.next = checkName("next", next);
    for (int value : types) {
      Type.check(value);
    }
    this.types = new net.posick.DNS.TypeBitmap(types);
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    next = new net.posick.DNS.Name(in);
    types = new net.posick.DNS.TypeBitmap(in);
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    // Note: The next name is not lowercased.
    next.toWire(out, null, false);
    types.toWire(out);
  }

  @Override
  protected void rdataFromString(Tokenizer st, net.posick.DNS.Name origin) throws IOException {
    next = st.getName(origin);
    types = new net.posick.DNS.TypeBitmap(st);
  }

  /** Converts rdata to a String */
  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(next);
    if (!types.empty()) {
      sb.append(' ');
      sb.append(types.toString());
    }
    return sb.toString();
  }

  /** Returns the next name */
  public Name getNext() {
    return next;
  }

  /** Returns the set of types defined for this name */
  public int[] getTypes() {
    return types.toArray();
  }

  /** Returns whether a specific type is in the set of types. */
  public boolean hasType(int type) {
    return types.contains(type);
  }
}
