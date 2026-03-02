import type { Ipv4Tuple, Optional } from './types';

/**
 * Normalizes an IP address string for bucket-based identity use.
 *
 * This function ensures a consistent "bucket" identity key for network addresses,
 * supporting both IPv4 and IPv6. It applies the following normalization steps:
 *
 * - **Zone Stripping:** Removes any IPv6 zone identifier (e.g., `fe80::1%eth0`), as this is an interface-local routing hint, not part of the address bits.
 * - **IPv6 Normalization and Masking:** For IPv6, applies a subnet mask (default prefix length `/56`, common for residential allocations)
 *   to mitigate excessive granularity from privacy extensions. This results in a normalized, masked IPv6 string.
 * - **IPv4-Mapped IPv6:** If the address is an IPv4-mapped IPv6 (`::ffff:a.b.c.d`), it is converted back to an IPv4 string to avoid
 *   double-bucketing and collapsing distinct IPv4s via IPv6 subnetting.
 * - **Case Normalization:** Lowercases all hexadecimal characters for canonicalization.
 *
 * This normalization is RFC-compliant and suitable for deriving privacy-friendly, consistent identity keys in edge fingerprinting, rate limiting, and similar use cases.
 *
 * #### Examples
 * ```typescript
 * normalizeIpForBucket("8.8.8.8");                    // "8.8.8.8"
 * normalizeIpForBucket("2001:db8:abcd:ef01::1234");   // "2001:db8:abcd:ef00:0000:0000:0000:0000"
 * normalizeIpForBucket("::FFFF:192.0.2.1");           // "192.0.2.1"
 * normalizeIpForBucket("fe80::1%eth0");               // "fe80:0000:0000:0000:0000:0000:0000:0000"
 * ```
 *
 * @param ip - The input IP address string (IPv4, IPv6, or IPv4-mapped IPv6). May be `null`.
 * @param ipv6Subnet - Optional. The IPv6 subnet prefix length to apply as a mask (integer, 1–128). Defaults to 56.
 * @returns The normalized, canonicalized network address string, or `null` if the input was `null`.
 *
 * @throws {RangeError} If `ipv6Subnet` is not an integer in the range 1–128.
 *
 * @see [RFC 4291: IPv6 Addressing Architecture](https://datatracker.ietf.org/doc/html/rfc4291)
 * @see [RFC 5952: IPv6 Text Representation](https://datatracker.ietf.org/doc/html/rfc5952)
 * @see [IANA IPv6 Special-Purpose Registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml)
 * @see [RFC 4007: IPv6 Scoped Address Architecture](https://datatracker.ietf.org/doc/html/rfc4007)
 * @see [RFC 6874: Zone Identifiers in IPv6 Addresses](https://datatracker.ietf.org/doc/html/rfc6874)
 */
export function normalizeIpForBucket(
  ip: Optional<string>,
  ipv6Subnet?: number
): Optional<string> {
  if (ip === null) return null;

  const zoneCut = ip.indexOf('%');
  const raw = (zoneCut >= 0 ? ip.slice(0, zoneCut) : ip).toLowerCase();

  if (!raw.includes(':')) return raw;

  const prefix = ipv6Subnet ?? 56;

  if (!Number.isInteger(prefix) || prefix < 1 || prefix > 128) {
    throw new RangeError('ipv6Subnet must be an integer in range 1..128');
  }

  const bytes = parseIpv6ToBytes(raw);
  if (bytes === null) return raw;

  if (isIpv4MappedIpv6(bytes)) {
    return `${bytes[12]!}.${bytes[13]!}.${bytes[14]!}.${bytes[15]!}`;
  }

  maskBytes(bytes, prefix);
  return bytesToFullIpv6(bytes);
}

function isIpv4MappedIpv6(bytes: Uint8Array): boolean {
  for (let i = 0; i < 10; i++) {
    if (bytes[i]! !== 0) return false;
  }
  return bytes[10]! === 0xff && bytes[11]! === 0xff;
}

function maskBytes(bytes: Uint8Array, prefix: number): void {
  const fullBytes = Math.floor(prefix / 8);
  const rem = prefix % 8;

  if (fullBytes >= 16) return;

  if (rem !== 0) {
    const mask = (0xff << (8 - rem)) & 0xff;
    bytes[fullBytes]! &= mask;
    for (let i = fullBytes + 1; i < 16; i++) {
      bytes[i]! = 0;
    }
  } else {
    for (let i = fullBytes; i < 16; i++) {
      bytes[i]! = 0;
    }
  }
}

function bytesToFullIpv6(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    const hi = bytes[i]!;
    const lo = bytes[i + 1]!;
    const value = (hi << 8) | lo;
    parts.push(value.toString(16).padStart(4, '0'));
  }
  return parts.join(':');
}

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

  const nums: number[] = [];

  for (const part of parts) {
    if (part === '') return null;
    if (!/^\d+$/.test(part)) return null;

    const n = Number.parseInt(part, 10);
    if (!Number.isFinite(n) || n < 0 || n > 255) return null;

    if (part.length > 1 && part.startsWith('0')) return null;

    nums.push(n);
  }

  return [nums[0]!, nums[1]!, nums[2]!, nums[3]!];
}
