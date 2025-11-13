# fpyx

Hardened, cross-runtime request fingerprinting for anonymous rate limiting.

Zero dependencies. Zero I/O. Zero crypto APIs. Works everywhere JavaScript runs: Node.js 18+, Bun, Deno, Cloudflare Workers, Fastly Compute, Vercel Edge, Netlify Edge, and browsers.

## What it does?

fpyx builds stable, compact identifiers from HTTP request traits, trusted client IP, User-Agent, Accept-Language, and optional method/path, then hashes them with FNV-1a 64-bit for fast, cheap rate limiting keys.

This is for rate limiting and quota buckets, not identity or authentication. Follows OWASP API4:2023 guidance: enforce limits server-side, trust only IP headers your own proxy sets, and return HTTP 429 when limits are exceeded.

## Installation

```bash
npm i fpyx
# or 
pnpm add fpyx
# or 
bun add fpyx
```

## Quick Start

### Rate Limiting with Redis

```typescript
import { fingerprint } from 'fpyx';
import { Redis } from '@upstash/redis';

const redis = new Redis({ url: process.env.REDIS_URL });

export async function rateLimit(req: Request): Promise<boolean> {
  const { hash } = fingerprint(req, {
    ipHeaders: ['cf-connecting-ip', 'x-forwarded-for'],
  });

  const key = `ratelimit:${hash}`;
  const count = await redis.incr(key);

  if (count === 1) {
    await redis.expire(key, 60); // 60-second window
  }

  return count <= 100; // 100 requests per minute
}

// In your handler:
if (!(await rateLimit(request))) {
  return new Response('Too many requests', { status: 429 });
}
```

### Cloudflare Workers with KV

```typescript
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const { hash } = fingerprint(req, {
      ipHeaders: ['cf-connecting-ip'],
    });

    const key = `rl:${hash}`;
    const current = (await env.KV.get(key)) || '0';
    const count = parseInt(current, 10) + 1;

    if (count > 50) {
      return new Response('Rate limit exceeded', { status: 429 });
    }

    await env.KV.put(key, count.toString(), { expirationTtl: 60 });
    return new Response('OK');
  },
};
```

## Features

### Cross-Runtime
Works everywhere JavaScript runs:

- Node.js 18+ (including 20, 21, 22+)
- Bun 1.0+
- Deno 1.30+
- Cloudflare Workers
- Fastly Compute
- Vercel Edge Functions
- Netlify Edge Functions
- AWS Lambda@Edge
- Modern browsers (Chrome, Firefox, Safari, Edge)

No Node.js crypto API. No file system. No network calls. Pure Fetch-standard APIs and TextEncoder.

### Performance
FNV-1a is extremely fast:

- 0.4-0.8 microseconds to hash a few hundred bytes on modern CPUs
- 100,000+ fingerprints per second on a single CPU core
- 800,000+ fingerprints per second on a modest 8-core instance
- ~10-20x faster than JSON parsing for small objects
- Zero overhead from dependencies, I/O, or async crypto

A typical API or edge worker can handle millions of requests per day without breaking a sweat. FNV-1a is so cheap you won't notice it in your profiler.

### Security Model
This library follows OWASP API4:2023 guidance for preventing resource exhaustion attacks.

What it does:
- Combines coarse traits (IP, User-Agent, Accept-Language) into a stable identifier for rate limiting buckets

What it doesn't do:
- Identity tracking, user authentication, unique fingerprinting, or cryptographic verification

Critical security considerations:
- Trust your proxy: Only use IP headers your edge proxy sets. Configure your proxy to overwrite client-supplied headers
- Expect collisions: Shared IPs (NAT, VPNs, corporate networks) will collide. That's acceptable for rate limiting
- Not for identity: Do not use fingerprints to track individual users or as an authentication factor
- Enforce server-side: Always validate limits in your backend. Return HTTP 429 when exceeded
- Non-cryptographic: FNV-1a is fast and deterministic, but not cryptographic. If you need cryptographic integrity or unforgeability, swap hashFn for a keyed HMAC

### Configuration

```typescript
fingerprint(request, {
  // Trusted IP headers (in precedence order)
  ipHeaders: ['cf-connecting-ip', 'x-forwarded-for'],

  // Include HTTP method (scope limits per GET/POST/PUT/etc.)
  includeMethod: true,

  // Include URL path (scope limits per route)
  includePath: true,

  // Normalize paths (collapse IDs, UUIDs, etc.)
  pathNormalizer: (path) => path.replace(/\d+/g, ':id'),

  // Override hash function (e.g., for longer digests)
  hashFn: (data) => myCustomHash(data),
});
```

### Zero Dependencies
No third-party libraries. No bloat. No supply chain risk. Just TypeScript.

### Fully Typed
Complete TypeScript definitions included. Strict mode compatible. exactOptionalPropertyTypes ready.

## Usage Examples

### Express.js Middleware

```typescript
import express from 'express';
import { fingerprint } from 'fpyx';
import { Redis } from 'ioredis';

const redis = new Redis();
const app = express();

app.use(async (req, res, next) => {
  const { hash } = fingerprint(
    {
      headers: req.headers,
      method: req.method,
      url: req.url,
    },
    {
      ipHeaders: ['x-forwarded-for', 'x-real-ip'],
    }
  );

  const key = `rl:${hash}`;
  const count = await redis.incr(key);

  if (count === 1) {
    await redis.expire(key, 60);
  }

  if (count > 100) {
    res.status(429).send('Too many requests');
    return;
  }

  next();
});
```

### Fastify Plugin

```typescript
import Fastify from 'fastify';
import { fingerprint } from 'fpyx';

const fastify = Fastify();

fastify.addHook('onRequest', async (request, reply) => {
  const { hash } = fingerprint(
    {
      headers: new Headers(Object.entries(request.headers)),
      method: request.method,
      url: request.url,
    },
    {
      ipHeaders: ['fastly-client-ip', 'x-forwarded-for'],
    }
  );

  // Apply rate limiting logic with your store
  const count = await yourStore.increment(`rl:${hash}`, 60);
  if (count > 100) {
    reply.status(429).send({ error: 'Too many requests' });
  }
});
```

### Hono on Cloudflare Workers

```typescript
import { Hono } from 'hono';
import { fingerprint } from 'fpyx';

const app = new Hono();

app.use('*', async (c, next) => {
  const { hash } = fingerprint(c.req.raw, {
    ipHeaders: ['cf-connecting-ip'],
  });

  const key = `rl:${hash}`;
  const current = (await c.env.KV.get(key)) || '0';
  const count = parseInt(current, 10) + 1;

  if (count > 100) {
    return c.text('Too many requests', 429);
  }

  await c.env.KV.put(key, count.toString(), { expirationTtl: 60 });
  await next();
});

export default app;
```

### Next.js App Router Middleware

```typescript
import { NextRequest, NextResponse } from 'next/server';
import { fingerprint } from 'fpyx';
import { Redis } from '@upstash/redis';

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
});

export async function middleware(request: NextRequest) {
  const { hash } = fingerprint(request, {
    ipHeaders: ['x-forwarded-for', 'x-real-ip'],
  });

  const key = `rl:${hash}`;
  const count = await redis.incr(key);

  if (count === 1) {
    await redis.expire(key, 60);
  }

  if (count > 100) {
    return NextResponse.json({ error: 'Too many requests' }, { status: 429 });
  }

  return NextResponse.next();
}

export const config = {
  matcher: '/api/:path*',
};
```

## API Reference

### fingerprint(source, options?)

Derives a compact, anonymous rate limiting fingerprint from request data.

**Parameters:**

source: `Request | { headers: Headers; method?: string; url?: string | URL }`

The Fetch Request object or a request-like object containing headers and optionally method/URL.

`options?`: `FingerprintOptions` (optional)

Configuration object with the following properties:
- `ipHeaders?`: `ReadonlyArray<string>` - Ordered list of trusted IP headers to check. Default: `DEFAULT_IP_HEADERS` (Cloudflare, Fastly, Fly.io, Akamai, standard headers)
- `includeMethod?`: `boolean` - Include HTTP method in fingerprint. Default: `false`. Set to true to scope limits per `GET/POST/PUT/DELETE`
- `includePath?`: `boolean` - Include URL path in fingerprint. Default: `false`. Set to true to scope limits per route
- `pathNormalizer?:` `(path: string)` `=> string` - Optional function to normalize paths before fingerprinting. Useful for collapsing IDs, UUIDs, or timestamps
- `hashFn?: (data: Uint8Array) => string` - Override the hash function. Default: `fnv1a64Hex`. Must return a deterministic string digest

**Returns:** FingerprintResult

```typescript
interface FingerprintResult {
  hash: string; // 16-character hex string
  parts: ReadonlyArray<string>; // ["ip:203.0.113.10", "ua:curl/8.0", ...]
  traits: FingerprintTraits;
}

interface FingerprintTraits {
  ip: string | null;
  userAgent: string | null;
  acceptLanguage: string | null;
  method: string | null;
  path: string | null;
}
```

**Example:**

```typescript
import { fingerprint } from 'fpyx';

const result = fingerprint(request, {
  ipHeaders: ['cf-connecting-ip'],
  includeMethod: true,
  includePath: true,
  pathNormalizer: (path) => path.replace(/\d+/g, ':id'),
});

console.log(result.hash); // "a7f3c21b8d4e9012"
console.log(result.traits.ip); // "203.0.113.10"
console.log(result.traits.method); // "POST"
console.log(result.traits.path); // "/users/:id"
```

### fnv1a64Hex(data)

Computes the FNV-1a 64-bit hash over UTF-8 input.

**Parameters:**

`data`: `Uint8Array` - The bytes to hash

**Returns:** `string` - 16-character zero-padded lowercase hexadecimal string

**Example:**

```typescript
import { fnv1a64Hex } from 'fpyx';

const encoder = new TextEncoder();
const hash = fnv1a64Hex(encoder.encode('hello'));
console.log(hash); // "a430d84680aabd0b"
```

### DEFAULT_IP_HEADERS

Default trusted IP header precedence. Override via options.ipHeaders.

```typescript
export const DEFAULT_IP_HEADERS: readonly string[] = [
  'cf-connecting-ip', // Cloudflare
  'fastly-client-ip', // Fastly
  'fly-client-ip', // Fly.io
  'true-client-ip', // Akamai
  'forwarded', // RFC 7239 standard
  'x-forwarded-for', // Common, but easy to spoof
  'x-real-ip', // Common, but easy to spoof
];
```

## Configuration Guide

### IP Headers (ipHeaders)

Specifies which headers to trust for client IP detection, in precedence order. The first header found wins.

Why this matters: Client-supplied IP headers like `X-Forwarded-For` are trivial to spoof. You must trust only headers your own proxy sets.

Default behavior: Uses `DEFAULT_IP_HEADERS`, which checks platform-specific headers first (Cloudflare, Fastly, Fly.io, Akamai), then standard headers.

When to override:

If you're on Cloudflare only:
```typescript
fingerprint(req, { ipHeaders: ['cf-connecting-ip'] });
```

If you're behind Nginx with a trusted X-Real-IP:
```typescript
fingerprint(req, { ipHeaders: ['x-real-ip'] });
```

If you're using the standard Forwarded header:
```typescript
fingerprint(req, { ipHeaders: ['forwarded'] });
```

Critical: Configure your proxy to overwrite client-supplied headers. Without this, attackers can bypass rate limits by spoofing IPs.

Cloudflare automatically sets cf-connecting-ip. [Docs](https://developers.cloudflare.com/fundamentals/reference/http-headers/)

Fastly sets fastly-client-ip. [Docs](https://developer.fastly.com/reference/http/http-headers/Fastly-Client-IP/)

Fly.io sets fly-client-ip. [Docs](https://fly.io/docs/reference/runtime-environment/#fly-client-ip)

Akamai sets true-client-ip. [Docs](https://techdocs.akamai.com/origin-ip-acl/docs/true-client-ip)

### Include Method (includeMethod)

When true, the HTTP method (GET, POST, PUT, DELETE, etc.) is included in the fingerprint.

Use case: Apply different rate limits per method.

Example:
```typescript
const { hash, traits } = fingerprint(req, { includeMethod: true });

// Different limits for read vs write operations
const limit = traits.method === 'GET' ? 1000 : 100;
const key = `rl:${hash}`;
// ... apply limit
```

### Include Path (includePath)

When true, the URL path is included in the fingerprint.

Use case: Apply different rate limits per route.

Example:
```typescript
fingerprint(req, { includePath: true });
// /api/search gets different limit than /api/users
```

### Path Normalizer (pathNormalizer)

A function that normalizes the URL path before fingerprinting. Useful for collapsing dynamic segments.

Use case: Treat `/users/123 and /users/456` as the same route for rate limiting.

Example:
```typescript
fingerprint(req, {
  includePath: true,
  pathNormalizer: (path) => {
    return path
      .replace(/\d+/g, ':id') // /users/123 -> /users/:id
      .replace(
        /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
        ':uuid'
      ); // Collapse UUIDs
  },
});
```

### Custom Hash Function (hashFn)

Override the default FNV-1a hash with your own function. Must be deterministic and return a string.

Use case: Use a longer hash (SHA-256) or integrate with existing hash infrastructure.

Example:
```typescript
function customHash(data: Uint8Array): string {
  // Your deterministic hash implementation
  return myHashFunction(data);
}

fingerprint(req, { hashFn: customHash });
```

Note: The default FNV-1a is extremely fast (0.4-0.8 microseconds for typical payloads). Switching to a cryptographic hash like SHA-256 will be slower but provides longer digests and lower collision rates.

## How It Works

fpyx extracts coarse request traits, serializes them into a deterministic payload, and hashes with FNV-1a 64-bit.

**Step 1:** Extract Traits

From the request, fpyx extracts:
1. Client IP: From trusted proxy headers (e.g., cf-connecting-ip)
2. User-Agent: Browser or client identifier
3. Accept-Language: Language preferences
4. Method (if includeMethod: true): HTTP verb
5. Path (if includePath: true): URL path, optionally normalized

**Step 2:** Serialize

Traits are joined into a deterministic string:

```
ip:203.0.113.10|ua:curl/8.0.1|al:en-US,en;q=0.9
```

If method and path are included:

```
ip:203.0.113.10|ua:curl/8.0.1|al:en-US,en;q=0.9|method:POST|path:/api/users/:id
```

**Step 3:** Hash

The payload is UTF-8 encoded and hashed with FNV-1a 64-bit, producing a 16-character hex string:

```typescript
const encoder = new TextEncoder();
const bytes = encoder.encode(payload);
const hash = fnv1a64Hex(bytes); // "a7f3c21b8d4e9012"
```

**Step 4:** Use for Rate Limiting

Store the hash in your data store (Redis, KV, database) with a TTL:

```typescript
const key = `ratelimit:${hash}`;
await redis.incr(key);
await redis.expire(key, 60); // 60-second window
```

## License

MIT (c) [@rccyx](https://rccyx.com)
