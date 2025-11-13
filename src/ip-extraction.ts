/**
 * Client IP extraction and parsing utilities.
 *
 * @packageDocumentation
 */

import { INVALID_IP_TOKENS } from './constants';

/**
 * Extracts the client IP from request headers based on precedence order.
 *
 * @param headers - The request Headers object.
 * @param precedence - Ordered list of header names to check.
 * @returns The extracted IP address or null if not found.
 * @internal
 */
export function extractClientIp(
  headers: Headers,
  precedence: ReadonlyArray<string>
): string | null {
  for (const headerName of precedence) {
    const value = headers.get(headerName);
    if (value === null) {
      continue;
    }

    const normalizedName = headerName.toLowerCase();
    if (normalizedName === 'forwarded') {
      const parsed = parseForwarded(value);
      const ip = normalizeIpCandidate(parsed);
      if (ip !== null) {
        return ip;
      }
      continue;
    }

    const candidate =
      normalizedName === 'x-forwarded-for'
        ? takeFirstListEntry(value)
        : value.trim();
    const ip = normalizeIpCandidate(candidate);
    if (ip !== null) {
      return ip;
    }
  }

  return null;
}

/**
 * Parses the RFC 7239 Forwarded header to extract the client IP.
 *
 * @param value - The Forwarded header value.
 * @returns The extracted IP or null.
 * @internal
 */
function parseForwarded(value: string): string | null {
  const entries = value.split(',');
  for (const entry of entries) {
    const directives = entry.trim().split(';');
    for (const directive of directives) {
      const [rawKey, rawValue] = directive.split('=');
      if (rawKey === undefined || rawValue === undefined) {
        continue;
      }

      if (rawKey.trim().toLowerCase() !== 'for') {
        continue;
      }

      const cleaned = cleanForwardedIdentifier(rawValue.trim());
      if (cleaned !== null) {
        return cleaned;
      }
    }
  }

  return null;
}

/**
 * Cleans a Forwarded header identifier by removing quotes and extracting IP from brackets/ports.
 *
 * @param value - The raw identifier value.
 * @returns The cleaned IP or null.
 * @internal
 */
function cleanForwardedIdentifier(value: string): string | null {
  const unquoted =
    value.startsWith('"') && value.endsWith('"') && value.length >= 2
      ? value.slice(1, -1)
      : value;
  const trimmed = unquoted.trim();
  if (trimmed === '') {
    return null;
  }

  if (trimmed.startsWith('[')) {
    const closingIndex = trimmed.indexOf(']');
    if (closingIndex > 1) {
      return trimmed.slice(1, closingIndex);
    }
    return null;
  }

  if (trimmed.includes(':') && trimmed.includes('.')) {
    const colonIndex = trimmed.lastIndexOf(':');
    if (colonIndex > -1) {
      return trimmed.slice(0, colonIndex);
    }
  }

  return trimmed;
}

/**
 * Takes the first entry from a comma-separated list (e.g., X-Forwarded-For).
 *
 * @param value - The header value.
 * @returns The first entry, trimmed.
 * @internal
 */
function takeFirstListEntry(value: string): string {
  const [first = ''] = value.split(',');
  return first.trim();
}

/**
 * Normalizes and validates an IP candidate, stripping ports if present.
 *
 * @param value - The IP candidate.
 * @returns The normalized IP or null if invalid.
 * @internal
 */
function normalizeIpCandidate(value: string | null): string | null {
  if (value === null) {
    return null;
  }

  const trimmed = value.trim();
  if (trimmed === '') {
    return null;
  }

  if (INVALID_IP_TOKENS.has(trimmed.toLowerCase())) {
    return null;
  }

  if (trimmed.includes(':') && trimmed.includes('.')) {
    const colonIndex = trimmed.lastIndexOf(':');
    if (colonIndex > -1) {
      return trimmed.slice(0, colonIndex);
    }
  }

  return trimmed;
}
