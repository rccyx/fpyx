import { INVALID_IP_TOKENS } from './constants';
import { Optional } from './types';

const IPV4_WITH_PORT_RE = /^(?:\d{1,3}\.){3}\d{1,3}:\d+$/;

/**
 * Extracts the client IP from request headers based on precedence order.
 *
 * @param headers - The request Headers object.
 * @param precedence - Ordered list of header names to check.
 * @returns The extracted IP address or null if not found.
 * @internal
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7239 RFC 7239: Forwarded HTTP Extension}
 */
export function extractClientIp(
  headers: Headers,
  precedence: ReadonlyArray<string>
): Optional<string> {
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
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7239 RFC 7239: Forwarded HTTP Extension}
 */
function parseForwarded(value: string): Optional<string> {
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
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7239 RFC 7239: Forwarded HTTP Extension}
 */
function cleanForwardedIdentifier(value: string): Optional<string> {
  const unquoted =
    value.startsWith('"') && value.endsWith('"') && value.length >= 2
      ? value.slice(1, -1)
      : value;

  const trimmed = unquoted.trim();
  if (trimmed === '') {
    return null;
  }

  // node ABNF uses square brackets for IPv6, with optional :port after the closing bracket.
  if (trimmed.startsWith('[')) {
    const closingIndex = trimmed.indexOf(']');
    if (closingIndex > 1) {
      return trimmed.slice(1, closingIndex);
    }
    return null;
  }

  // need to only strip ports for plain IPv4:port.
  // Do NOT use "contains ':' and '.'" heuristics,
  // because IPv6 forms like ::ffff:203.0.113.10 contain dots and colons.
  if (IPV4_WITH_PORT_RE.test(trimmed)) {
    return trimmed.slice(0, trimmed.lastIndexOf(':'));
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
 * Normalizes and validates an IP candidate, stripping ports/brackets where relevant.
 *
 * @param value - The IP candidate.
 * @returns The normalized IP or null if invalid.
 * @internal
 */
function normalizeIpCandidate(value: Optional<string>): Optional<string> {
  if (value === null) {
    return null;
  }

  const trimmed = value.trim();
  if (trimmed === '') {
    return null;
  }

  const lower = trimmed.toLowerCase();
  if (INVALID_IP_TOKENS.has(lower)) {
    return null;
  }

  // obfuscated identifiers MUST start with "_" and are not IP addresses.
  if (trimmed.startsWith('_')) {
    return null;
  }

  // accept bracketed IPv6 (optionally with :port after the bracket) in any header, not just Forwarded.
  if (trimmed.startsWith('[')) {
    const closingIndex = trimmed.indexOf(']');
    if (closingIndex > 1) {
      return trimmed.slice(1, closingIndex);
    }
    return null;
  }

  // only strip ports for plain IPv4:port.
  if (IPV4_WITH_PORT_RE.test(trimmed)) {
    return trimmed.slice(0, trimmed.lastIndexOf(':'));
  }

  return trimmed;
}
