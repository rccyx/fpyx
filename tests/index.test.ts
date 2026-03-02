import { describe, expect, it } from 'vitest';

import { fingerprint, fnv1a64Hex } from '../src/index';

const encoder = new TextEncoder();

describe('fnv1a64Hex', () => {
  it('matches known test vector for "hello"', () => {
    expect(fnv1a64Hex(encoder.encode('hello'))).toBe('a430d84680aabd0b');
  });
});

describe('fingerprint', () => {
  it('builds a stable payload from the identity anchor plus optional scope', () => {
    const request = new Request('https://api.example.com/v1/resource', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '203.0.113.10',
      },
    });

    const result = fingerprint(request, { scope: 'users.create' });

    expect(result.traits).toEqual({
      actorId: null,
      ip: '203.0.113.10',
      scope: 'users.create',
    });

    expect(result.parts).toEqual(['ip:203.0.113.10', 'scope:users.create']);

    expect(result.hash).toBe(
      fnv1a64Hex(encoder.encode(result.parts.join('|')))
    );
  });

  it('respects ip header precedence when anchoring on network identity', () => {
    const headers = new Headers();
    headers.set('x-forwarded-for', '198.51.100.8, 198.51.100.9');
    headers.set('fly-client-ip', '203.0.113.5');

    const result = fingerprint({ headers }, {});
    expect(result.traits.ip).toBe('203.0.113.5');
    expect(result.parts[0]).toBe('ip:203.0.113.5');
  });

  it('parses Forwarded header with ipv6 and port', () => {
    const headers = new Headers();
    headers.set(
      'Forwarded',
      'for="[2001:db8:cafe::17]:4711";proto=https;by=203.0.113.43'
    );

    const result = fingerprint(
      { headers },
      { ipHeaders: ['forwarded'], ipv6Subnet: 128 }
    );

    expect(result.traits).toEqual({
      actorId: null,
      ip: '2001:0db8:cafe:0000:0000:0000:0000:0017',
      scope: null,
    });

    expect(result.parts).toEqual([
      'ip:2001:0db8:cafe:0000:0000:0000:0000:0017',
    ]);
  });

  it('ignores unknown Forwarded identifiers', () => {
    const headers = new Headers();
    headers.set('Forwarded', 'for=unknown');

    const result = fingerprint({ headers }, { ipHeaders: ['forwarded'] });
    expect(result.traits.ip).toBeNull();
    expect(result.parts[0]).toBe('ip:');
  });

  it('uses actorId as a full replacement anchor (no mixing with ip)', () => {
    const request = new Request('https://api.example.com/v1/resource', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '203.0.113.10',
        'x-forwarded-for': '198.51.100.8, 198.51.100.9',
      },
    });

    const result = fingerprint(request, {
      actorId: 'user_123',
      scope: 'auth.login',
    });

    expect(result.traits).toEqual({
      actorId: 'user_123',
      ip: null,
      scope: 'auth.login',
    });

    expect(result.parts).toEqual(['actor:user_123', 'scope:auth.login']);
  });

  it('accepts custom hash functions', () => {
    const request = new Request('https://example.com/hello', {
      headers: {
        'cf-connecting-ip': '203.0.113.10',
      },
    });

    const hashFn = (data: Uint8Array): string =>
      Array.from(data)
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');

    const result = fingerprint(request, { hashFn, scope: 'read' });

    const expected = hashFn(encoder.encode(result.parts.join('|')));
    expect(result.hash).toBe(expected);
  });

  it('trims actorId and uses it as the anchor', () => {
    const request = new Request('https://api.example.com/v1/resource', {
      headers: {
        'cf-connecting-ip': '203.0.113.10',
      },
    });

    const result = fingerprint(request, { actorId: '  user_123  ' });

    expect(result.traits).toEqual({
      actorId: 'user_123',
      ip: null,
      scope: null,
    });

    expect(result.parts).toEqual(['actor:user_123']);
  });

  it('treats empty/whitespace actorId as absent and falls back to ip anchor', () => {
    const request = new Request('https://api.example.com/v1/resource', {
      headers: {
        'cf-connecting-ip': '203.0.113.10',
      },
    });

    const result = fingerprint(request, { actorId: '   ' });

    expect(result.traits.actorId).toBeNull();
    expect(result.traits.ip).toBe('203.0.113.10');
    expect(result.parts[0]).toBe('ip:203.0.113.10');
  });

  it('trims scope and includes it when non-empty', () => {
    const request = new Request('https://api.example.com/v1/resource', {
      headers: {
        'cf-connecting-ip': '203.0.113.10',
      },
    });

    const result = fingerprint(request, { scope: '  read  ' });

    expect(result.traits).toEqual({
      actorId: null,
      ip: '203.0.113.10',
      scope: 'read',
    });

    expect(result.parts).toEqual(['ip:203.0.113.10', 'scope:read']);
  });

  it('treats empty/whitespace scope as absent', () => {
    const request = new Request('https://api.example.com/v1/resource', {
      headers: {
        'cf-connecting-ip': '203.0.113.10',
      },
    });

    const result = fingerprint(request, { scope: '   ' });

    expect(result.traits).toEqual({
      actorId: null,
      ip: '203.0.113.10',
      scope: null,
    });

    expect(result.parts).toEqual(['ip:203.0.113.10']);
  });

  it('applies default ipv6 /56 masking when anchored on ipv6', () => {
    const request = new Request('https://api.example.com/v1/resource', {
      headers: {
        'cf-connecting-ip': '2001:db8:abcd:12ff:aaaa:bbbb:cccc:dddd',
      },
    });

    const result = fingerprint(request);

    expect(result.traits).toEqual({
      actorId: null,
      ip: '2001:0db8:abcd:1200:0000:0000:0000:0000',
      scope: null,
    });
  });

  it('normalizes ipv4-mapped ipv6 to ipv4 at the fingerprint level', () => {
    const headers = new Headers();
    headers.set('x-real-ip', '::ffff:203.0.113.10');

    const result = fingerprint({ headers }, { ipHeaders: ['x-real-ip'] });

    expect(result.traits.ip).toBe('203.0.113.10');
    expect(result.parts[0]).toBe('ip:203.0.113.10');
  });

  it('produces deterministic output even when no ip is present', () => {
    const request = new Request('https://api.example.com/v1/resource', {
      method: 'POST',
      headers: {},
    });

    const result = fingerprint(request, { scope: 'auth.login' });

    expect(result.traits).toEqual({
      actorId: null,
      ip: null,
      scope: 'auth.login',
    });
    expect(result.parts).toEqual(['ip:', 'scope:auth.login']);
    expect(result.hash).toBe(
      fnv1a64Hex(encoder.encode(result.parts.join('|')))
    );
  });
});
