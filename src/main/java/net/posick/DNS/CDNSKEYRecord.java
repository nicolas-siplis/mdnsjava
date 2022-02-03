// SPDX-License-Identifier: BSD-3-Clause
package net.posick.DNS;

import net.posick.DNS.DNSKEYRecord;
import net.posick.DNS.DNSSEC;
import net.posick.DNS.Name;
import net.posick.DNS.Type;

import java.security.PublicKey;

/**
 * Child DNSKEY record as specified in RFC 8078.
 *
 * @see net.posick.DNS.DNSSEC
 * @see <a href="https://tools.ietf.org/html/rfc8078">RFC 8078: Managing DS Records from the Parent
 *     via CDS/CDNSKEY</a>
 */
public class CDNSKEYRecord extends DNSKEYRecord {
  CDNSKEYRecord() {}

  /**
   * Creates a CDNSKEY Record from the given data
   *
   * @param flags Flags describing the key's properties
   * @param proto The protocol that the key was created for
   * @param alg The key's algorithm
   * @param key Binary representation of the key
   */
  public CDNSKEYRecord(net.posick.DNS.Name name, int dclass, long ttl, int flags, int proto, int alg, byte[] key) {
    super(name, net.posick.DNS.Type.CDNSKEY, dclass, ttl, flags, proto, alg, key);
  }

  /**
   * Creates a CDNSKEY Record from the given data
   *
   * @param flags Flags describing the key's properties
   * @param proto The protocol that the key was created for
   * @param alg The key's algorithm
   * @param key The key as a PublicKey
   * @throws net.posick.DNS.DNSSEC.DNSSECException The PublicKey could not be converted into DNS format.
   */
  public CDNSKEYRecord(
          Name name, int dclass, long ttl, int flags, int proto, int alg, PublicKey key)
      throws net.posick.DNS.DNSSEC.DNSSECException {
    super(name, Type.CDNSKEY, dclass, ttl, flags, proto, alg, DNSSEC.fromPublicKey(key, alg));
  }
}
