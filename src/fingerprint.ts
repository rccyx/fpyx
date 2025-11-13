/**
 * Main fingerprint function implementation.
 *
 * @packageDocumentation
 */

import type {
  FingerprintSource,
  FingerprintOptions,
  FingerprintResult,
  FingerprintTraits,
  HashFunction,
} from './types';
import { DEFAULT_IP_HEADERS } from './constants';
import { fnv1a64Hex } from './hash';
import { extractClientIp } from './ip-extraction';
import {
  safeTrim,
  extractMethod,
  extractPath,
  buildParts,
  isRequestLike,
} from './utils';

const textEncoder = new TextEncoder();

/**
 * Derive a compact, anonymous rate limiting fingerprint from Fetch-style request data.
 *
 * This function combines coarse request traits (trusted client IP, User-Agent, Accept-Language,
 * and optionally HTTP method and URL path) into a stable identifier suitable for rate limiting
 * and quota buckets. The traits are serialized, UTF-8 encoded, and hashed with FNV-1a 64-bit.
 *
 * **Security model:** This is for rate limiting and resource allocation, not identity or
 * authentication. Trust only IP headers set by your own edge proxy (Cloudflare, Fastly, Fly.io,
 * Akamai, etc.). Configure your proxy to overwrite client-supplied headers. Return HTTP 429
 * when limits are exceeded.
 *
 * **Cross-runtime:** Works in Node.js 18+, Bun, Deno, Cloudflare Workers, Fastly Compute,
 * Vercel Edge, Netlify Edge, and modern browsers. Zero dependencies, zero I/O, zero crypto APIs.
 *
 * @param source - The Fetch `Request` or request-like data to fingerprint. Accepts standard
 * Request objects or plain objects with `{ headers, method?, url? }`.
 * @param options - Optional configuration:
 * - `ipHeaders`: Ordered list of trusted IP headers (default: platform-specific headers)
 * - `includeMethod`: Scope fingerprints per HTTP method (default: `false`)
 * - `includePath`: Scope fingerprints per URL path (default: `false`)
 * - `pathNormalizer`: Optional function to normalize paths (e.g., collapse IDs)
 * - `hashFn`: Override the hash function (default: FNV-1a 64)
 * @returns A `FingerprintResult` containing:
 * - `hash`: The 16-character hexadecimal fingerprint
 * - `parts`: The individual payload segments (e.g., `["ip:203.0.113.10", "ua:curl/8.0"]`)
 * - `traits`: Parsed request traits used to build the fingerprint
 *
 * @example
 * **Basic usage with Fetch Request**
 * ```typescript
 * import { fingerprint } from 'fpyx';
 *
 * const req = new Request('https://api.example.com/resource', {
 *   headers: {
 *     'cf-connecting-ip': '203.0.113.10',
 *     'user-agent': 'curl/8.0.1',
 *     'accept-language': 'en-US,en;q=0.9',
 *   },
 * });
 *
 * const { hash, traits } = fingerprint(req);
 * console.log(hash); // "a7f3c21b8d4e9012"
 * console.log(traits.ip); // "203.0.113.10"
 * ```
 *
 * @example
 * **Rate limiting with Redis**
 * ```typescript
 * import { fingerprint } from 'fpyx';
 * import { Redis } from '@upstash/redis';
 *
 * const redis = new Redis({ url: process.env.REDIS_URL });
 *
 * export async function rateLimit(req: Request): Promise<boolean> {
 *   const { hash } = fingerprint(req, {
 *     ipHeaders: ['cf-connecting-ip', 'x-forwarded-for'],
 *   });
 *
 *   const key = `ratelimit:${hash}`;
 *   const count = await redis.incr(key);
 *
 *   if (count === 1) {
 *     await redis.expire(key, 60); // 60-second window
 *   }
 *
 *   return count <= 100; // 100 requests per minute
 * }
 *
 * // In your handler:
 * if (!(await rateLimit(request))) {
 *   return new Response('Too many requests', { status: 429 });
 * }
 * ```
 *
 * @example
 * **Path-specific limits (e.g., /api/search vs /api/users)**
 * ```typescript
 * const { hash } = fingerprint(req, {
 *   includePath: true,
 *   pathNormalizer: (path) => path.replace(/\d+/g, ':id'), // /users/123 -> /users/:id
 * });
 * ```
 *
 * @example
 * **Method-specific limits (e.g., POST vs GET)**
 * ```typescript
 * const { hash } = fingerprint(req, {
 *   includeMethod: true,
 * });
 * ```
 *
 * @example
 * **Cloudflare Workers with KV**
 * ```typescript
 * export default {
 *   async fetch(req: Request, env: Env): Promise<Response> {
 *     const { hash } = fingerprint(req, {
 *       ipHeaders: ['cf-connecting-ip'],
 *     });
 *
 *     const key = `rl:${hash}`;
 *     const current = (await env.KV.get(key)) || '0';
 *     const count = parseInt(current, 10) + 1;
 *
 *     if (count > 50) {
 *       return new Response('Rate limit exceeded', { status: 429 });
 *     }
 *
 *     await env.KV.put(key, count.toString(), { expirationTtl: 60 });
 *     return new Response('OK');
 *   },
 * };
 * ```
 *
 * @example
 * **Custom hash function (e.g., SHA-256)**
 * ```typescript
 * import { fingerprint } from 'fpyx';
 *
 * const customHash = (data: Uint8Array): string => {
 *   // Use your own hash (must be deterministic)
 *   return myHashFunction(data);
 * };
 *
 * const { hash } = fingerprint(req, { hashFn: customHash });
 * ```
 *
 * @see {@link https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/ | OWASP API4:2023}
 * @see {@link https://developers.cloudflare.com/fundamentals/reference/http-headers/ | Cloudflare HTTP headers}
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Forwarded | Forwarded header - MDN}
 */
export function fingerprint(
  source: FingerprintSource,
  options?: FingerprintOptions
): FingerprintResult {
  const headers = source.headers;
  const traits: FingerprintTraits = {
    ip: extractClientIp(headers, options?.ipHeaders ?? DEFAULT_IP_HEADERS),
    userAgent: safeTrim(headers.get('user-agent')),
    acceptLanguage: safeTrim(headers.get('accept-language')),
    method: options?.includeMethod === true ? extractMethod(source) : null,
    path:
      options?.includePath === true
        ? extractPath(
            isRequestLike(source) ? source.url : source.url,
            options?.pathNormalizer
          )
        : null,
  };

  const parts = buildParts(traits);
  const payload = textEncoder.encode(parts.join('|'));
  const hashFn: HashFunction = options?.hashFn ?? fnv1a64Hex;
  return {
    hash: hashFn(payload),
    parts,
    traits,
  };
}
