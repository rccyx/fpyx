import { describe, expect, it } from 'vitest';

import { normalizeIpForBucket } from '../src/ip-subnet';

describe('normalizeIpForBucket', () => {
  it('returns null for null', () => {
    expect(normalizeIpForBucket(null, undefined)).toBeNull();
  });

  it('returns IPv4 unchanged (ipv6Subnet does not apply)', () => {
    expect(normalizeIpForBucket('203.0.113.10', undefined)).toBe(
      '203.0.113.10'
    );
    expect(normalizeIpForBucket('203.0.113.10', 56)).toBe('203.0.113.10');
  });

  it('handles :: correctly', () => {
    expect(normalizeIpForBucket('::', 56)).toBe(
      '0000:0000:0000:0000:0000:0000:0000:0000'
    );
  });

  it('handles leading compression', () => {
    expect(normalizeIpForBucket('::1', 128)).toBe(
      '0000:0000:0000:0000:0000:0000:0000:0001'
    );
  });

  it('handles trailing compression', () => {
    expect(normalizeIpForBucket('2001:db8::', 128)).toBe(
      '2001:0db8:0000:0000:0000:0000:0000:0000'
    );
  });

  it('rejects multiple :: sequences', () => {
    expect(normalizeIpForBucket('2001::db8::1', 56)).toBe('2001::db8::1');
  });

  it('preserves full IPv6 when prefix is 128', () => {
    expect(normalizeIpForBucket('2001:db8::1', 128)).toBe(
      '2001:0db8:0000:0000:0000:0000:0000:0001'
    );
  });

  it('does not treat non-mapped IPv6 as IPv4', () => {
    expect(normalizeIpForBucket('::fffe:203.0.113.10', 56)).not.toBe(
      '203.0.113.10'
    );
  });

  it('handles non-byte-aligned prefix like /57', () => {
    const result = normalizeIpForBucket('2001:db8:abcd:1234::1', 57);
    expect(result).toMatch(/^2001:0db8:/);
  });

  it('returns raw value for invalid IPv6', () => {
    expect(normalizeIpForBucket('not-an-ip', 56)).toBe('not-an-ip');
  });

  it('defaults to /56 masking for IPv6 and canonicalizes output', () => {
    const a = '2001:db8:abcd:12ff:aaaa:bbbb:cccc:dddd';
    const b = '2001:db8:abcd:1234:1111:2222:3333:4444';

    const expected = '2001:0db8:abcd:1200:0000:0000:0000:0000';

    expect(normalizeIpForBucket(a, undefined)).toBe(expected);
    expect(normalizeIpForBucket(b, undefined)).toBe(expected);
  });

  it('masks to /64 when configured', () => {
    const a = '2001:db8:abcd:1234:aaaa:bbbb:cccc:dddd';
    const b = '2001:db8:abcd:1234:1111:2222:3333:4444';

    const expected = '2001:0db8:abcd:1234:0000:0000:0000:0000';

    expect(normalizeIpForBucket(a, 64)).toBe(expected);
    expect(normalizeIpForBucket(b, 64)).toBe(expected);
  });

  it('preserves full IPv6 when configured to /128 (canonicalized)', () => {
    expect(normalizeIpForBucket('2001:db8:cafe::17', 128)).toBe(
      '2001:0db8:cafe:0000:0000:0000:0000:0017'
    );
  });

  it('strips zone identifiers before parsing and masking', () => {
    expect(normalizeIpForBucket('fe80::1%eth0', 56)).toBe(
      'fe80:0000:0000:0000:0000:0000:0000:0000'
    );
  });

  it('normalizes IPv4-mapped IPv6 to IPv4 (prevents /56 collapse)', () => {
    expect(normalizeIpForBucket('::ffff:203.0.113.10', undefined)).toBe(
      '203.0.113.10'
    );
    expect(normalizeIpForBucket('0:0:0:0:0:ffff:203.0.113.10', 56)).toBe(
      '203.0.113.10'
    );
  });

  it('throws for invalid subnet prefixes', () => {
    expect(() => normalizeIpForBucket('2001:db8::1', 0)).toThrow(RangeError);
    expect(() => normalizeIpForBucket('2001:db8::1', 129)).toThrow(RangeError);
  });
});
