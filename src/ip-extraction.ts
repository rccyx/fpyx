import { INVALID_IP_TOKENS } from './constants';
import { Optional } from './types';

const IPV4_WITH_PORT_RE = /^(?:\d{1,3}\.){3}\d{1,3}:\d+$/;

type Ipv4Tuple = [number, number, number, number];

/**
 * extract a client ip from headers using a precedence list.
 *
 * this function only accepts ip literals (ipv4 dotted quad, or ipv6 literal).
 * rfc 7239 explicitly allows "unknown" and obfuscated identifiers (for example "hidden")
 * in the forwarded header. those are not ip addresses. accepting them would let an attacker
 * supply arbitrary strings and poison an abuse anchor.
 *
 * also: this function does not determine whether a header is trustworthy.
 * you must only use headers that your own edge proxy overwrites.
 *
 * @param headers request headers
 * @param precedence ordered list of headers to check
 * @returns an ip literal string, or null if none found
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7239
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Forwarded
 */
export function extractClientIp(
  headers: Headers,
  precedence: readonly string[]
): Optional<string> {
  for (const headerName of precedence) {
    const value = headers.get(headerName);
    if (value === null) continue;

    const normalizedName = headerName.toLowerCase();

    if (normalizedName === 'forwarded') {
      const parsed = parseForwarded(value);
      const ip = normalizeIpCandidate(parsed);
      if (ip !== null) return ip;
      continue;
    }

    const candidate =
      normalizedName === 'x-forwarded-for'
        ? takeFirstListEntry(value)
        : value.trim();

    const ip = normalizeIpCandidate(candidate);
    if (ip !== null) return ip;
  }

  return null;
}

function parseForwarded(value: string): Optional<string> {
  const entries = value.split(',');

  for (const entry of entries) {
    const directives = entry.trim().split(';');

    for (const directive of directives) {
      const [rawKey, rawValue] = directive.split('=');
      if (rawKey === undefined || rawValue === undefined) continue;

      if (rawKey.trim().toLowerCase() !== 'for') continue;

      const cleaned = cleanForwardedIdentifier(rawValue.trim());
      if (cleaned !== null) return cleaned;
    }
  }

  return null;
}

function cleanForwardedIdentifier(value: string): Optional<string> {
  const unquoted =
    value.startsWith('"') && value.endsWith('"') && value.length >= 2
      ? value.slice(1, -1)
      : value;

  const trimmed = unquoted.trim();
  if (trimmed === '') return null;

  if (trimmed.startsWith('[')) {
    const closingIndex = trimmed.indexOf(']');
    if (closingIndex > 1) return trimmed.slice(1, closingIndex);
    return null;
  }

  // only strip ports for plain ipv4:port to avoid false positives on ipv6 forms.
  if (IPV4_WITH_PORT_RE.test(trimmed)) {
    return trimmed.slice(0, trimmed.lastIndexOf(':'));
  }

  return trimmed;
}

function takeFirstListEntry(value: string): string {
  const [first = ''] = value.split(',');
  return first.trim();
}

function normalizeIpCandidate(value: Optional<string>): Optional<string> {
  if (value === null) return null;

  const trimmed = value.trim();
  if (trimmed === '') return null;

  const lower = trimmed.toLowerCase();
  if (INVALID_IP_TOKENS.has(lower)) return null;

  // rfc 7239 defines "_" prefixed obfuscated identifiers.
  // some stacks may not follow the prefix rule, so we also validate ip literals below.
  if (trimmed.startsWith('_')) return null;

  let candidate = trimmed;

  // accept bracketed ipv6 in any header, not just forwarded.
  if (candidate.startsWith('[')) {
    const closingIndex = candidate.indexOf(']');
    if (closingIndex > 1) {
      candidate = candidate.slice(1, closingIndex);
    } else {
      return null;
    }
  }

  if (IPV4_WITH_PORT_RE.test(candidate)) {
    candidate = candidate.slice(0, candidate.lastIndexOf(':'));
  }

  if (isIpv4Literal(candidate)) return candidate;
  if (isIpv6Literal(candidate)) return candidate;

  // reject non-ip values
  return null;
}

function isIpv4Literal(input: string): boolean {
  const parts = input.split('.');
  if (parts.length !== 4) return false;

  for (const part of parts) {
    if (part === '') return false;
    if (!/^\d+$/.test(part)) return false;

    const n = Number.parseInt(part, 10);
    if (!Number.isFinite(n) || n < 0 || n > 255) return false;

    // avoid ambiguous forms like 010 which some parsers treat as octal.
    if (part.length > 1 && part.startsWith('0')) return false;
  }

  return true;
}

function isIpv6Literal(input: string): boolean {
  // zone identifiers are allowed in some contexts (scoped addresses), see rfc 6874 and rfc 4007.
  // for request identity, the zone is not part of the address bits, so we ignore it.
  const zoneCut = input.indexOf('%');
  const raw = (zoneCut >= 0 ? input.slice(0, zoneCut) : input).toLowerCase();
  if (!raw.includes(':')) return false;
  return parseIpv6ToBytes(raw) !== null;
}

/**
 * minimal ipv6 parser used only to validate literals.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc4291
 */
function parseIpv6ToBytes(input: string): Optional<Uint8Array> {
  const s = input.trim();
  if (s === '') return null;

  const dbl = s.indexOf('::');

  let leftParts: string[] = [];
  let rightParts: string[] = [];

  if (dbl >= 0) {
    // only one "::" is allowed in a valid ipv6 literal.
    if (s.indexOf('::', dbl + 1) !== -1) return null;

    const leftRaw = s.slice(0, dbl);
    const rightRaw = s.slice(dbl + 2);

    leftParts = leftRaw === '' ? [] : leftRaw.split(':');
    rightParts = rightRaw === '' ? [] : rightRaw.split(':');
  } else {
    leftParts = s.split(':');
  }

  const leftGroups = parseIpv6Groups(leftParts);
  if (leftGroups === null) return null;

  const rightGroups = parseIpv6Groups(rightParts);
  if (rightGroups === null) return null;

  if (dbl < 0) {
    if (leftGroups.length !== 8) return null;
    return groupsToBytes(leftGroups);
  }

  const total = leftGroups.length + rightGroups.length;
  if (total > 8) return null;

  const missing = 8 - total;
  const groups: number[] = [
    ...leftGroups,
    ...new Array(missing).fill(0),
    ...rightGroups,
  ];

  return groupsToBytes(groups);
}

function parseIpv6Groups(parts: string[]): Optional<number[]> {
  const out: number[] = [];

  for (let i = 0; i < parts.length; i++) {
    const p = parts[i]!;
    if (p === '') return null;

    // rfc 4291 allows an embedded ipv4 dotted quad in the last two groups.
    if (p.includes('.')) {
      if (i !== parts.length - 1) return null;
      const v4 = parseIpv4(p);
      if (v4 === null) return null;
      out.push((v4[0] << 8) | v4[1]);
      out.push((v4[2] << 8) | v4[3]);
      continue;
    }

    if (p.length > 4) return null;
    const n = Number.parseInt(p, 16);
    if (!Number.isFinite(n) || n < 0 || n > 0xffff) return null;
    out.push(n);
  }

  return out;
}

function groupsToBytes(groups: number[]): Optional<Uint8Array> {
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);

  for (let i = 0; i < 8; i++) {
    const v = groups[i]!;
    bytes[i * 2]! = (v >> 8) & 0xff;
    bytes[i * 2 + 1]! = v & 0xff;
  }

  return bytes;
}

function parseIpv4(s: string): Optional<Ipv4Tuple> {
  const parts = s.split('.');
  if (parts.length !== 4) return null;

  const out: number[] = [];

  for (const part of parts) {
    if (part === '') return null;
    if (!/^\d+$/.test(part)) return null;

    const n = Number.parseInt(part, 10);
    if (!Number.isFinite(n) || n < 0 || n > 255) return null;

    if (part.length > 1 && part.startsWith('0')) return null;

    out.push(n);
  }

  return [out[0]!, out[1]!, out[2]!, out[3]!];
}
