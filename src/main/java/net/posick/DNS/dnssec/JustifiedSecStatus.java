// SPDX-License-Identifier: BSD-3-Clause
package net.posick.DNS.dnssec;

import net.posick.DNS.dnssec.SecurityStatus;

/**
 * Codes for DNSSEC security statuses along with a reason why the status was determined.
 *
 * @since 3.5
 */
final class JustifiedSecStatus {
  net.posick.DNS.dnssec.SecurityStatus status;
  int edeReason;
  String reason;

  /**
   * Creates a new instance of this class.
   *
   * @param status The security status.
   * @param reason The reason why the status was determined.
   */
  JustifiedSecStatus(SecurityStatus status, int edeReason, String reason) {
    this.status = status;
    this.edeReason = edeReason;
    this.reason = reason;
  }

  /**
   * Applies this security status to a response message.
   *
   * @param response The response to which to apply this status.
   */
  void applyToResponse(net.posick.DNS.dnssec.SMessage response) {
    response.setStatus(this.status, edeReason, this.reason);
  }
}
