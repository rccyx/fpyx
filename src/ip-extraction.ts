import { INVALID_IP_TOKENS } from './constants';
import type { Ipv4Tuple, Optional } from './types';

const IPV4_WITH_PORT_RE = /^(?:\d{1,3}\.){3}\d{1,3}:\d+$/;

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
      const candidates = parseForwardedForIdentifiers(value);
      for (const c of candidates) {
        const ip = normalizeIpCandidate(c);
        if (ip !== null) return ip;
      }
      continue;
    }

    if (normalizedName === 'x-forwarded-for') {
      const ip = scanXForwardedFor(value);
      if (ip !== null) return ip;
      continue;
    }

    const ip = normalizeIpCandidate(value.trim());
    if (ip !== null) return ip;
  }

  return null;
}

function scanXForwardedFor(value: string): Optional<string> {
  const parts = value.split(',');
  for (const part of parts) {
    const ip = normalizeIpCandidate(part.trim());
    if (ip !== null) return ip;
  }
  return null;
}

function parseForwardedForIdentifiers(value: string): readonly string[] {
  const entries = splitOutsideQuotes(value, ',');
  const out: string[] = [];

  for (const entry of entries) {
    const directives = splitOutsideQuotes(entry, ';');

    for (const directive of directives) {
      const trimmed = directive.trim();
      if (trimmed === '') continue;

      const eq = trimmed.indexOf('=');
      if (eq < 0) continue;

      const rawKey = trimmed.slice(0, eq).trim().toLowerCase();
      if (rawKey !== 'for') continue;

      const rawValue = trimmed.slice(eq + 1).trim();
      const parsedValue = parseForwardedValue(rawValue);
      if (parsedValue === null) continue;

      const cleaned = cleanForwardedIdentifier(parsedValue);
      if (cleaned !== null) out.push(cleaned);
    }
  }

  return out;
}

/**
 * splits on a single separator char, but only when not inside a quoted-string.
 * supports backslash escapes inside quotes so \" does not terminate the quote.
 */
function splitOutsideQuotes(input: string, sep: ',' | ';'): string[] {
  const out: string[] = [];
  let cur = '';
  let inQuotes = false;
  let escaped = false;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i]!;

    if (inQuotes) {
      if (escaped) {
        cur += ch;
        escaped = false;
        continue;
      }
      if (ch === '\\') {
        cur += ch;
        escaped = true;
        continue;
      }
      if (ch === '"') {
        cur += ch;
        inQuotes = false;
        continue;
      }
      cur += ch;
      continue;
    }

    if (ch === '"') {
      cur += ch;
      inQuotes = true;
      continue;
    }

    if (ch === sep) {
      out.push(cur);
      cur = '';
      continue;
    }

    cur += ch;
  }

  out.push(cur);
  return out;
}

function parseForwardedValue(raw: string): Optional<string> {
  const s = raw.trim();
  if (s === '') return null;

  if (s.startsWith('"')) {
    return parseQuotedString(s);
  }

  // token form. we keep it as-is (trimmed) and validate later as ip literal only.
  if (/\s/.test(s)) return null;

  return s;
}

/**
 * parses a quoted-string, returning the unescaped content.
 * rejects garbage after the closing quote (only ows is allowed).
 */
function parseQuotedString(input: string): Optional<string> {
  if (!input.startsWith('"')) return null;

  let out = '';
  let escaped = false;

  for (let i = 1; i < input.length; i++) {
    const ch = input[i]!;

    if (escaped) {
      out += ch;
      escaped = false;
      continue;
    }

    if (ch === '\\') {
      escaped = true;
      continue;
    }

    if (ch === '"') {
      const rest = input.slice(i + 1).trim();
      if (rest !== '') return null;
      return out;
    }

    out += ch;
  }

  return null;
}

function cleanForwardedIdentifier(value: string): Optional<string> {
  const trimmed = value.trim();
  if (trimmed === '') return null;

  // tolerate accidental quoting if upstream parsing didn't already unquote.
  const unquoted =
    trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2
      ? trimmed.slice(1, -1).trim()
      : trimmed;

  if (unquoted === '') return null;

  if (unquoted.startsWith('[')) {
    return stripBracketedIpv6AndOptionalPort(unquoted);
  }

  // only strip ports for plain ipv4:port to avoid false positives on ipv6 forms.
  if (IPV4_WITH_PORT_RE.test(unquoted)) {
    return unquoted.slice(0, unquoted.lastIndexOf(':'));
  }

  return unquoted;
}

function stripBracketedIpv6AndOptionalPort(value: string): Optional<string> {
  const closingIndex = value.indexOf(']');
  if (closingIndex <= 1) return null;

  const inside = value.slice(1, closingIndex);
  const rest = value.slice(closingIndex + 1);

  if (rest === '') return inside;

  if (!rest.startsWith(':')) return null;

  const portStr = rest.slice(1);
  if (!/^\d+$/.test(portStr)) return null;

  const port = Number.parseInt(portStr, 10);
  if (!Number.isFinite(port) || port < 0 || port > 65535) return null;

  return inside;
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

  // accept bracketed ipv6 in any header, not just forwarded, but only with optional :port.
  if (candidate.startsWith('[')) {
    const stripped = stripBracketedIpv6AndOptionalPort(candidate);
    if (stripped === null) return null;
    candidate = stripped;
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
    if (!/^[0-9a-f]{1,4}$/i.test(p)) return null;

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
