// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2004 Brian Wellington (bwelling@xbill.org)

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
 * X.400 mail mapping record.
 *
 * @author Brian Wellington
 * @see <a href="https://tools.ietf.org/html/rfc2163">RFC 2163: Using the Internet DNS to Distribute
 *     MIXER Conformant Global Address Mapping (MCGAM)</a>
 */
public class PXRecord extends Record {
  private int preference;
  private net.posick.DNS.Name map822;
  private net.posick.DNS.Name mapX400;

  PXRecord() {}

  /**
   * Creates an PX Record from the given data
   *
   * @param preference The preference of this mail address.
   * @param map822 The RFC 822 component of the mail address.
   * @param mapX400 The X.400 component of the mail address.
   */
  public PXRecord(net.posick.DNS.Name name, int dclass, long ttl, int preference, net.posick.DNS.Name map822, net.posick.DNS.Name mapX400) {
    super(name, Type.PX, dclass, ttl);

    this.preference = checkU16("preference", preference);
    this.map822 = checkName("map822", map822);
    this.mapX400 = checkName("mapX400", mapX400);
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    preference = in.readU16();
    map822 = new net.posick.DNS.Name(in);
    mapX400 = new net.posick.DNS.Name(in);
  }

  @Override
  protected void rdataFromString(Tokenizer st, net.posick.DNS.Name origin) throws IOException {
    preference = st.getUInt16();
    map822 = st.getName(origin);
    mapX400 = st.getName(origin);
  }

  /** Converts the PX Record to a String */
  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    sb.append(preference);
    sb.append(" ");
    sb.append(map822);
    sb.append(" ");
    sb.append(mapX400);
    return sb.toString();
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU16(preference);
    map822.toWire(out, null, canonical);
    mapX400.toWire(out, null, canonical);
  }

  /** Gets the preference of the route. */
  public int getPreference() {
    return preference;
  }

  /** Gets the RFC 822 component of the mail address. */
  public net.posick.DNS.Name getMap822() {
    return map822;
  }

  /** Gets the X.400 component of the mail address. */
  public Name getMapX400() {
    return mapX400;
  }
}
