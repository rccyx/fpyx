import { describe, expect, it } from 'vitest';

import { extractClientIp } from '../src/ip-extraction';

describe('extractClientIp', () => {
  it('returns null when none of the precedence headers exist', () => {
    const headers = new Headers();
    expect(
      extractClientIp(headers, ['forwarded', 'x-forwarded-for'])
    ).toBeNull();
  });

  it('respects precedence order across headers', () => {
    const headers = new Headers();
    headers.set('x-forwarded-for', '198.51.100.8, 198.51.100.9');
    headers.set('fly-client-ip', '203.0.113.5');

    expect(extractClientIp(headers, ['fly-client-ip', 'x-forwarded-for'])).toBe(
      '203.0.113.5'
    );
    expect(extractClientIp(headers, ['x-forwarded-for', 'fly-client-ip'])).toBe(
      '198.51.100.8'
    );
  });

  it('takes the first X-Forwarded-For entry (leftmost) and trims whitespace', () => {
    const headers = new Headers();
    headers.set('x-forwarded-for', ' 198.51.100.8 , 198.51.100.9 ');

    expect(extractClientIp(headers, ['x-forwarded-for'])).toBe('198.51.100.8');
  });

  it('scans X-Forwarded-For and returns the first valid ip literal (skips unknown/garbage)', () => {
    const headers = new Headers();
    headers.set('x-forwarded-for', 'unknown, 203.0.113.10');

    expect(extractClientIp(headers, ['x-forwarded-for'])).toBe('203.0.113.10');
  });

  it('falls back to the next header when Forwarded has no valid for= value', () => {
    const headers = new Headers();
    headers.set('forwarded', 'for=unknown');
    headers.set('x-forwarded-for', '203.0.113.195, 198.51.100.178');

    expect(extractClientIp(headers, ['forwarded', 'x-forwarded-for'])).toBe(
      '203.0.113.195'
    );
  });

  it('rejects RFC 7239 obfuscated identifiers (leading underscore) as non-IPs', () => {
    const headers = new Headers();
    headers.set('forwarded', 'for="_gazonk"');

    expect(extractClientIp(headers, ['forwarded'])).toBeNull();
  });

  it('parses RFC 7239 Forwarded with IPv4, IPv4:port, and directives', () => {
    const headers = new Headers();

    headers.set('forwarded', 'for=192.0.2.60;proto=http;by=203.0.113.43');
    expect(extractClientIp(headers, ['forwarded'])).toBe('192.0.2.60');

    headers.set(
      'forwarded',
      'for="192.0.2.60:47011";proto=http;by=203.0.113.43'
    );
    expect(extractClientIp(headers, ['forwarded'])).toBe('192.0.2.60');
  });

  it('parses RFC 7239 Forwarded with bracketed IPv6 and optional :port', () => {
    const headers = new Headers();

    headers.set('forwarded', 'for="[2001:db8:cafe::17]"');
    expect(extractClientIp(headers, ['forwarded'])).toBe('2001:db8:cafe::17');

    headers.set('forwarded', 'for="[2001:db8:cafe::17]:4711"');
    expect(extractClientIp(headers, ['forwarded'])).toBe('2001:db8:cafe::17');

    headers.set(
      'forwarded',
      'for="[2001:db8:cafe::17]:4711";proto=https;by=203.0.113.43'
    );
    expect(extractClientIp(headers, ['forwarded'])).toBe('2001:db8:cafe::17');
  });

  it('rejects malformed bracketed ipv6 with garbage after ] (only optional :port allowed)', () => {
    const headers = new Headers();
    headers.set('forwarded', 'for="[2001:db8::1]lol"');

    expect(extractClientIp(headers, ['forwarded'])).toBeNull();
  });

  it('handles quoted-string values containing semicolons/commas without breaking parsing', () => {
    const headers = new Headers();

    headers.set(
      'forwarded',
      'for="2001:db8::1;evil", for=203.0.113.60;proto=https'
    );
    expect(extractClientIp(headers, ['forwarded'])).toBe('203.0.113.60');

    headers.set(
      'forwarded',
      'for="2001:db8::1,evil", for=203.0.113.61;proto=https'
    );
    expect(extractClientIp(headers, ['forwarded'])).toBe('203.0.113.61');
  });

  it('handles multiple Forwarded entries and returns the first valid for= ip', () => {
    const headers = new Headers();
    headers.set(
      'forwarded',
      'for=unknown;proto=https, for=203.0.113.61;proto=https'
    );

    expect(extractClientIp(headers, ['forwarded'])).toBe('203.0.113.61');
  });

  it('strips bracketed IPv6 :port even in non-Forwarded headers', () => {
    const headers = new Headers();
    headers.set('x-forwarded-for', '[2001:db8::1]:4711, 198.51.100.9');

    expect(extractClientIp(headers, ['x-forwarded-for'])).toBe('2001:db8::1');
  });

  it('rejects bracketed IPv6 with garbage after ] in non-Forwarded headers', () => {
    const headers = new Headers();
    headers.set('x-forwarded-for', '[2001:db8::1]lol, 198.51.100.9');

    expect(extractClientIp(headers, ['x-forwarded-for'])).toBe('198.51.100.9');
  });

  it('does not corrupt IPv4-mapped IPv6 addresses like ::ffff:203.0.113.10', () => {
    const headers = new Headers();
    headers.set('x-real-ip', '::ffff:203.0.113.10');

    expect(extractClientIp(headers, ['x-real-ip'])).toBe('::ffff:203.0.113.10');
  });

  it('strips IPv4 :port only for plain IPv4:port (avoids IPv6 dot/colon false positives)', () => {
    const headers = new Headers();
    headers.set('x-real-ip', '203.0.113.10:1234');

    expect(extractClientIp(headers, ['x-real-ip'])).toBe('203.0.113.10');
  });

  it('treats quoted unknown in Forwarded as invalid', () => {
    const headers = new Headers();
    headers.set('forwarded', 'for="unknown"');

    expect(extractClientIp(headers, ['forwarded'])).toBeNull();
  });

  it('strips ipv4 :port in X-Forwarded-For (first valid entry)', () => {
    const headers = new Headers();
    headers.set('x-forwarded-for', '203.0.113.10:1234, 198.51.100.9');

    expect(extractClientIp(headers, ['x-forwarded-for'])).toBe('203.0.113.10');
  });

  it('rejects RFC 7239 obfuscated identifiers that are not IP literals', () => {
    const headers = new Headers();
    headers.set('forwarded', 'for=hidden');

    expect(extractClientIp(headers, ['forwarded'])).toBeNull();
  });

  it('rejects quoted RFC 7239 obfuscated identifiers that are not IP literals', () => {
    const headers = new Headers();
    headers.set('forwarded', 'for="hidden"');

    expect(extractClientIp(headers, ['forwarded'])).toBeNull();
  });

  it('falls back when X-Forwarded-For has no valid ip and a later header has a valid ip', () => {
    const headers = new Headers();
    headers.set('x-forwarded-for', 'hidden, unknown');
    headers.set('x-real-ip', '203.0.113.10');

    expect(extractClientIp(headers, ['x-forwarded-for', 'x-real-ip'])).toBe(
      '203.0.113.10'
    );
  });

  it('rejects invalid ipv6 hextets that parseInt would otherwise partially accept', () => {
    const headers = new Headers();
    headers.set('x-real-ip', '2001:db8:0x1::1');

    expect(extractClientIp(headers, ['x-real-ip'])).toBeNull();
  });

  it('rejects invalid ipv4 that parseInt would otherwise partially accept', () => {
    const headers = new Headers();
    headers.set('x-real-ip', '203.0.113.10abc');

    expect(extractClientIp(headers, ['x-real-ip'])).toBeNull();
  });
});
