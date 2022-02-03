// SPDX-License-Identifier: BSD-3-Clause
package net.posick.DNS.lookup;

import net.posick.DNS.lookup.LookupFailedException;

/**
 * Represents a server failure, that the upstream server responding to the request returned a
 * SERVFAIL status.
 */
public class ServerFailedException extends LookupFailedException {}
