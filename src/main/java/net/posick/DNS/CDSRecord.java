// SPDX-License-Identifier: BSD-3-Clause
package net.posick.DNS;

import net.posick.DNS.DNSKEYRecord;
import net.posick.DNS.DNSSEC;
import net.posick.DNS.DSRecord;
import net.posick.DNS.Name;
import net.posick.DNS.Type;

/**
 * Child Delegation Signer record as specified in RFC 8078.
 *
 * @see net.posick.DNS.DNSSEC
 * @see <a href="https://tools.ietf.org/html/rfc8078">RFC 8078: Managing DS Records from the Parent
 *     via CDS/CDNSKEY</a>
 */
public class CDSRecord extends DSRecord {
  CDSRecord() {}

  /**
   * Creates a CDS Record from the given data
   *
   * @param footprint The original KEY record's footprint (keyid).
   * @param alg The original key algorithm.
   * @param digestid The digest id code.
   * @param digest A hash of the original key.
   */
  public CDSRecord(
          net.posick.DNS.Name name, int dclass, long ttl, int footprint, int alg, int digestid, byte[] digest) {
    super(name, Type.CDS, dclass, ttl, footprint, alg, digestid, digest);
  }

  /**
   * Creates a CDS Record from the given data
   *
   * @param digestid The digest id code.
   * @param key The key to digest
   */
  public CDSRecord(Name name, int dclass, long ttl, int digestid, DNSKEYRecord key) {
    super(
        name,
        Type.CDS,
        dclass,
        ttl,
        key.getFootprint(),
        key.getAlgorithm(),
        digestid,
        DNSSEC.generateDSDigest(key, digestid));
  }
}
