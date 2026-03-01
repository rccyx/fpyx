import { describe, expect, it } from 'vitest';

import { fingerprint, fnv1a64Hex } from '../src/index';

const encoder = new TextEncoder();

describe('fnv1a64Hex', () => {
  it('matches known test vector for "hello"', () => {
    expect(fnv1a64Hex(encoder.encode('hello'))).toBe('a430d84680aabd0b');
  });
});

describe('fingerprint', () => {
  it('builds a stable payload from the identity anchor plus optional scoping', () => {
    const request = new Request('https://api.example.com/v1/resource', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '203.0.113.10',
        'user-agent': 'TestAgent/1.0',
        'accept-language': 'en-US,en;q=0.9',
      },
    });

    const result = fingerprint(request, {
      includeMethod: true,
      includePath: true,
    });

    expect(result.traits).toEqual({
      actorId: null,
      ip: '203.0.113.10',
      method: 'POST',
      path: '/v1/resource',
    });

    expect(result.parts).toEqual([
      'ip:203.0.113.10',
      'method:POST',
      'path:/v1/resource',
    ]);

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
      method: null,
      path: null,
    });
  });

  it('ignores unknown Forwarded identifiers', () => {
    const headers = new Headers();
    headers.set('Forwarded', 'for=unknown');

    const result = fingerprint({ headers }, { ipHeaders: ['forwarded'] });
    expect(result.traits.ip).toBeNull();
    expect(result.parts[0]).toBe('ip:');
  });

  it('supports path normalization', () => {
    const request = new Request('https://api.example.com/users/123/profile', {
      method: 'GET',
      headers: {
        'cf-connecting-ip': '203.0.113.10',
      },
    });

    const result = fingerprint(request, {
      includePath: true,
      pathNormalizer: (path) => path.replace(/\d+/g, ':id'),
    });

    expect(result.traits.path).toBe('/users/:id/profile');
    expect(result.parts).toEqual([
      'ip:203.0.113.10',
      'path:/users/:id/profile',
    ]);
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
      includeMethod: true,
      includePath: true,
    });

    expect(result.traits).toEqual({
      actorId: 'user_123',
      ip: null,
      method: 'POST',
      path: '/v1/resource',
    });

    expect(result.parts[0]).toBe('actor:user_123');
    expect(result.parts).toEqual([
      'actor:user_123',
      'method:POST',
      'path:/v1/resource',
    ]);
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

    const result = fingerprint(request, { hashFn });

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
      method: null,
      path: null,
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

  it('does not throw when includePath is true but url is missing on object source', () => {
    const headers = new Headers();
    headers.set('cf-connecting-ip', '203.0.113.10');

    const result = fingerprint({ headers }, { includePath: true });

    expect(result.traits).toEqual({
      actorId: null,
      ip: '203.0.113.10',
      method: null,
      path: null,
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

    expect(result.traits.ip).toBe('2001:0db8:abcd:1200:0000:0000:0000:0000');
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

    const result = fingerprint(request, {
      includeMethod: true,
      includePath: true,
    });

    expect(result.traits).toEqual({
      actorId: null,
      ip: null,
      method: 'POST',
      path: '/v1/resource',
    });

    expect(result.parts).toEqual(['ip:', 'method:POST', 'path:/v1/resource']);
    expect(result.hash).toBe(
      fnv1a64Hex(encoder.encode(result.parts.join('|')))
    );
  });
});
