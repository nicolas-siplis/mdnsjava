// SPDX-License-Identifier: BSD-3-Clause
package net.posick.DNS;

import net.posick.DNS.Name;
import net.posick.DNS.SVCBBase;
import net.posick.DNS.Type;

import java.util.List;

/**
 * Service Location and Parameter Binding Record
 *
 * @see <a
 *     href="https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-06">draft-ietf-dnsop-svcb-https</a>
 * @since 3.3
 */
public class SVCBRecord extends SVCBBase {
  SVCBRecord() {}

  public SVCBRecord(
          net.posick.DNS.Name name, int dclass, long ttl, int priority, Name domain, List<ParameterBase> params) {
    super(name, Type.SVCB, dclass, ttl, priority, domain, params);
  }
}
