// SPDX-License-Identifier: BSD-3-Clause
package net.posick.DNS;

import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import net.posick.DNS.Compression;
import net.posick.DNS.DNSInput;
import net.posick.DNS.DNSOutput;
import net.posick.DNS.DNSSEC;
import net.posick.DNS.DNSSEC.DNSSECException;
import net.posick.DNS.DNSSEC.UnsupportedAlgorithmException;
import net.posick.DNS.IPSECKEYRecord.Algorithm;
import net.posick.DNS.Name;
import net.posick.DNS.Options;
import net.posick.DNS.Record;
import net.posick.DNS.Tokenizer;
import net.posick.DNS.Tokenizer.Token;
import net.posick.DNS.Type;
import net.posick.DNS.utils.base16;
import net.posick.DNS.utils.base64;

/**
 * Host Identity Protocol (HIP) Record as defined in RFC 8005.
 *
 * @see Algorithm for PK algorithm numbers
 */
public class HIPRecord extends Record {
  private byte[] hit;
  private int pkAlgorithm;
  private byte[] publicKey;
  private final List<net.posick.DNS.Name> rvServers = new ArrayList<>();

  HIPRecord() {}

  public HIPRecord(
          net.posick.DNS.Name name, int dclass, long ttl, byte[] hit, int alg, byte[] key, List<net.posick.DNS.Name> servers) {
    super(name, Type.HIP, dclass, ttl);
    this.hit = hit;
    this.pkAlgorithm = alg;
    this.publicKey = key;
    if (servers != null) {
      this.rvServers.addAll(servers);
    }
  }

  public HIPRecord(net.posick.DNS.Name name, int dclass, long ttl, byte[] hit, int alg, byte[] key) {
    this(name, dclass, ttl, hit, alg, key, null);
  }

  public HIPRecord(
          net.posick.DNS.Name name, int dclass, long ttl, byte[] hit, int alg, PublicKey key, List<net.posick.DNS.Name> servers)
      throws DNSSECException {
    this(name, dclass, ttl, hit, alg, net.posick.DNS.DNSSEC.fromPublicKey(key, mapAlgTypeToDnssec(alg)), servers);
  }

  public HIPRecord(net.posick.DNS.Name name, int dclass, long ttl, byte[] hit, int alg, PublicKey key)
      throws DNSSECException {
    this(name, dclass, ttl, hit, alg, key, null);
  }

  public byte[] getHit() {
    return hit;
  }

  /**
   * Gets the PK algorithm number as defined in <a
   * href="https://www.iana.org/assignments/ipseckey-rr-parameters/ipseckey-rr-parameters.xhtml#ipseckey-rr-parameters-1">IPSECKEY
   * Resource Record Parameters</a>
   *
   * @see Algorithm
   */
  public int getAlgorithm() {
    return pkAlgorithm;
  }

  /** Gets the raw public key bytes. The format is defined by {@link #getAlgorithm()}. */
  public byte[] getKey() {
    return publicKey;
  }

  /**
   * Gets the public key of this RR as a Java {@link PublicKey}. Only supported for RSA/DSA PK
   * algorithm (ECDSA lacks the information about which curve is used).
   */
  public PublicKey getPublicKey() throws DNSSECException {
    return net.posick.DNS.DNSSEC.toPublicKey(mapAlgTypeToDnssec(pkAlgorithm), publicKey, this);
  }

  public List<net.posick.DNS.Name> getRvServers() {
    return Collections.unmodifiableList(rvServers);
  }

  private static int mapAlgTypeToDnssec(int alg) throws UnsupportedAlgorithmException {
    switch (alg) {
      case Algorithm.DSA:
        return net.posick.DNS.DNSSEC.Algorithm.DSA;
      case Algorithm.RSA:
        return DNSSEC.Algorithm.RSASHA1;
      case Algorithm.ECDSA:
      default:
        throw new UnsupportedAlgorithmException(alg);
    }
  }

  @Override
  protected String rrToString() {
    StringBuilder sb = new StringBuilder();
    if (net.posick.DNS.Options.check("multiline")) {
      sb.append("( ");
    }

    String separator = net.posick.DNS.Options.check("multiline") ? "\n\t" : " ";
    sb.append(pkAlgorithm);
    sb.append(" ");
    sb.append(base16.toString(hit));
    sb.append(separator);

    sb.append(base64.toString(publicKey));
    if (!rvServers.isEmpty()) {
      sb.append(separator);
    }

    sb.append(rvServers.stream().map(net.posick.DNS.Name::toString).collect(Collectors.joining(separator)));
    if (Options.check("multiline")) {
      sb.append(" )");
    }

    return sb.toString();
  }

  @Override
  protected void rdataFromString(Tokenizer st, net.posick.DNS.Name origin) throws IOException {
    pkAlgorithm = st.getUInt8();
    hit = st.getHexString();
    publicKey = base64.fromString(st.getString());
    Token t;
    while ((t = st.get()).isString()) {
      rvServers.add(new net.posick.DNS.Name(t.value));
    }
  }

  @Override
  protected void rrToWire(DNSOutput out, Compression c, boolean canonical) {
    out.writeU8(hit.length);
    out.writeU8(pkAlgorithm);
    out.writeU16(publicKey.length);
    out.writeByteArray(hit);
    out.writeByteArray(publicKey);
    rvServers.forEach(n -> n.toWire(out, null, canonical));
  }

  @Override
  protected void rrFromWire(DNSInput in) throws IOException {
    int hitLength = in.readU8();
    pkAlgorithm = in.readU8();
    int pkLength = in.readU16();
    hit = in.readByteArray(hitLength);
    publicKey = in.readByteArray(pkLength);
    while (in.remaining() > 0) {
      rvServers.add(new Name(in));
    }
  }
}
