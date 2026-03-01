import type { Optional } from './types';
import type { SizedTuple } from 'typyx';

export function normalizeIpForBucket(
  ip: Optional<string>,
  ipv6Subnet?: number
): Optional<string> {
  if (ip === null) return null;

  const zoneCut = ip.indexOf('%');
  const raw = (zoneCut >= 0 ? ip.slice(0, zoneCut) : ip).toLowerCase();

  // not IPv6
  if (!raw.includes(':')) return raw;

  const prefix = ipv6Subnet ?? 56;

  if (!Number.isInteger(prefix) || prefix < 1 || prefix > 128) {
    throw new RangeError('ipv6Subnet must be an integer in range 1..128');
  }

  const bytes = parseIpv6ToBytes(raw);
  if (bytes === null) return raw;

  // normalize ipv4-mapped ipv6 (::ffff:x.y.z.w) to ipv4 to avoid collapsing to 0 under subnet masking
  if (isIpv4MappedIpv6(bytes)) {
    return `${bytes[12]!}.${bytes[13]!}.${bytes[14]!}.${bytes[15]!}`;
  }

  maskBytes(bytes, prefix);
  return bytesToFullIpv6(bytes);
}

// Check for ::ffff:x.y.z.w ipv4-mapped addresses
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

function parseIpv4(s: string): Optional<SizedTuple<number, 4>> {
  const parts = s.split('.');
  if (parts.length !== 4) return null;

  const nums = parts.map((x) => Number.parseInt(x, 10));
  if (nums.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) {
    return null;
  }

  return [nums[0]!, nums[1]!, nums[2]!, nums[3]!];
}
