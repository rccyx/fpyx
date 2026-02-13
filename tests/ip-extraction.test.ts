import { describe, expect, it } from 'vitest';

import { extractClientIp } from '../src/ip-extraction.js';

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

  it('falls back to the next header when the first candidate is invalid (RFC 7239 unknown)', () => {
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

  it('handles multiple Forwarded entries and returns the first "for=" found', () => {
    const headers = new Headers();
    headers.set(
      'forwarded',
      'for=203.0.113.60;proto=https, for=203.0.113.61;proto=https'
    );

    expect(extractClientIp(headers, ['forwarded'])).toBe('203.0.113.60');
  });

  it('strips bracketed IPv6 :port even in non-Forwarded headers', () => {
    const headers = new Headers();
    headers.set('x-forwarded-for', '[2001:db8::1]:4711, 198.51.100.9');

    expect(extractClientIp(headers, ['x-forwarded-for'])).toBe('2001:db8::1');
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
});
