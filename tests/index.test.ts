import { describe, expect, it } from 'vitest';

import { fingerprintRequest, fnv1a64Hex } from '../src/index.js';

const encoder = new TextEncoder();

describe('fnv1a64Hex', () => {
  it('matches known test vector for "hello"', () => {
    expect(fnv1a64Hex(encoder.encode('hello'))).toBe('a430d84680aabd0b');
  });
});

describe('fingerprintRequest', () => {
  it('builds a stable payload from core request traits', () => {
    const request = new Request('https://api.example.com/v1/resource', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': '203.0.113.10',
        'user-agent': 'TestAgent/1.0',
        'accept-language': 'en-US,en;q=0.9',
      },
    });

    const result = fingerprintRequest(request, {
      includeMethod: true,
      includePath: true,
    });

    expect(result.traits).toEqual({
      ip: '203.0.113.10',
      userAgent: 'TestAgent/1.0',
      acceptLanguage: 'en-US,en;q=0.9',
      method: 'POST',
      path: '/v1/resource',
    });
    expect(result.parts).toEqual([
      'ip:203.0.113.10',
      'ua:TestAgent/1.0',
      'al:en-US,en;q=0.9',
      'method:POST',
      'path:/v1/resource',
    ]);
    expect(result.hash).toBe(
      fnv1a64Hex(encoder.encode(result.parts.join('|')))
    );
  });

  it('respects IP header precedence', () => {
    const headers = new Headers();
    headers.set('x-forwarded-for', '198.51.100.8, 198.51.100.9');
    headers.set('fly-client-ip', '203.0.113.5');

    const result = fingerprintRequest({ headers }, {});
    expect(result.traits.ip).toBe('203.0.113.5');
  });

  it('parses Forwarded header with IPv6 and port', () => {
    const headers = new Headers();
    headers.set(
      'Forwarded',
      'for="[2001:db8:cafe::17]:4711";proto=https;by=203.0.113.43'
    );

    const result = fingerprintRequest(
      { headers },
      { ipHeaders: ['forwarded'] }
    );
    expect(result.traits.ip).toBe('2001:db8:cafe::17');
  });

  it('ignores unknown Forwarded identifiers', () => {
    const headers = new Headers();
    headers.set('Forwarded', 'for=unknown');

    const result = fingerprintRequest(
      { headers },
      { ipHeaders: ['forwarded'] }
    );
    expect(result.traits.ip).toBeNull();
  });

  it('supports path normalization', () => {
    const request = new Request('https://api.example.com/users/123/profile', {
      method: 'GET',
      headers: {
        'cf-connecting-ip': '203.0.113.10',
      },
    });

    const result = fingerprintRequest(request, {
      includePath: true,
      pathNormalizer: (path) => path.replace(/\d+/g, ':id'),
    });

    expect(result.traits.path).toBe('/users/:id/profile');
  });

  it('accepts custom hash functions', () => {
    const request = new Request('https://example.com/hello', {
      headers: {
        'user-agent': 'CustomAgent',
      },
    });

    const hashFn = (data: Uint8Array): string =>
      Array.from(data)
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('');

    const result = fingerprintRequest(request, {
      hashFn,
    });

    const expected = hashFn(encoder.encode(result.parts.join('|')));
    expect(result.hash).toBe(expected);
  });
});
