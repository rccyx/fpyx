
<div align="center">

# fpyx

<p>
  <strong>Hardened, cross-runtime request fingerprinting for anonymous rate limiting.</strong>
</p>

<p>
  <a href="https://www.npmjs.com/package/fpyx">
    <img src="https://img.shields.io/npm/v/fpyx.svg" alt="npm version" />
  </a>
  <a href="https://bundlephobia.com/package/fpyx">
    <img alt="Bundle Size" src="https://img.shields.io/bundlephobia/minzip/fpyx?label=bundle"/>
  </a>
  <a href="https://www.npmjs.com/package/fpyx">
    <img src="https://img.shields.io/badge/dependencies-0-brightgreen.svg" alt="zero dependencies" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/npm/l/fpyx.svg" alt="MIT license" />
  </a>
</p>

</div>

## What

Zero dependencies. Zero I/O. Zero crypto APIs. Works everywhere JavaScript runs with Fetch-standard `Request`/`Headers`: Node.js 18+, Bun, Deno, Cloudflare Workers, Fastly Compute, Vercel Edge, Netlify Edge, and modern browsers.


> [!IMPORTANT]
> This is for rate limiting and quota buckets, **not identity or authentication.**

## Why 

Wondering how this differs from express-rate-limit, rate-limiter-flexible, Upstash Rate Limit, FingerprintJS, or simple IP-based key generators? See the full [comparison](./comparison) over why fpyx exists.


TL;DR: `req.ip` is not enough, and can cause you to get DDoS'd.
No one in the ecosystem has a tool for getting the exact fngerpitng hash, extremely fast, and GDPR compliant, express-rate lilit does somthing like it (where it deos a bunch of shit with IPV6) but it's just for express, what if you change your framework or don't like the full bloat? you just want an identifier to plug into any rate limiter of choice you have?

See this is the problem,

"I use vercel/CF", great, which means you protect the whole site; but what if u want to throttle /login differently than /dashboard? or you want to throttle a logged in sessioned user or a random anaomous person? you're going to use the IP? well, not good enough, it looks like it's working till you get fucked, (it happened to me), so what's the soltuion?

fpyx solevs this, it does one job & one job only, give u a fingerint hash to plug in any limiter or counter etc, ue FN-1V for super fast hashing, unlike SHA256 which is slower, 
it just answers one question, given this request, "Who, exactly, is this request coming from?"

so, the probelm is that
Modern internet providers give every home a "prefix" (usually a /56 or /64) that contains trillions of IP addresses. A bot can switch IPs for every single request. fpyx masks the IP. It says: "I don't care if your last few digits changed; you're still in the same house. You are the same person."

The official standard for forwarding IPs (Forwarded: for=...) is a nightmare to read. It allows quotes, semicolons, and backslashes. Most simple code breaks when it sees a complex one.
req.headers['x-forwarded-for']; is a nightmare , fpyx uses a "State Machine" to read it character-by-character, making sure an attacker hasn't hidden a second "identity" inside a pair of quotes.

Instead of giving you a messy string, it gives you a 64-bit Hash (like a430d84680aabd0b).

If the user is logged in: The hash is based on their User ID.

If the user is a guest: The hash is based on their Real IP (Masked).

The library is the Refining Plant.

Input: A messy, potentially faked HTTP Request.

Output: A clean, honest, 16-character ID.

"but why not just supply the actor ID" well u can, porblem is 
if you block them on dashboard spams, u diont want to block the mto the rest

Without fpyx: You'd have to manually write user_123 + "POST" + "/login".

With fpyx: You just flip a switch: includeMethod: true.


now methods 
You might allow:

100 GETs per minute

10 POSTs per minute

If you don’t include method, they collapse into one counter.

Path is the URL pathname only, not the domain, not query string.

For:

https://api.example.com/users/123/profile?tab=settings

Path is:

/users/123/profile

When you enable includePath, you’re saying:

“Treat different endpoints as different buckets.”

Without path scoping:

ip:203.0.113.10

With path scoping:

ip:203.0.113.10|path:/users/123/profile

Now each route has independent limits.


now why would we need a normalizer

Problem:

Dynamic routes explode cardinality.

If you fingerprint raw path:

/users/1
/users/2
/users/3
/users/999999

Each becomes a different bucket.

That’s bad.


Rate limiting should usually apply to route pattern, not instance.

You don’t want 1 million separate buckets for 1 million user IDs.

So pathNormalizer lets you transform the path before hashing.

Example:

pathNormalizer: (path) => path.replace(/\d+/g, ':id')

Now:

/users/123/profile
/users/456/profile

Both normalize to:

/users/:id/profile

Now they collapse into one bucket.

In a real framework, you might do:

Express:

pathOverride: req.route.path

Hono:

pathOverride: c.req.routePath

Next.js:

pathOverride: req.nextUrl.pathname

If your framework already gives you the pattern, you don’t even need pathNormalizer.

So conceptually:

Actor → who
IP → fallback who
Method → what type of action
Path → what resource
Path normalizer → collapse dynamic variance


It handles "poisoning" attempts. For example, it correctly parses quoted strings in headers and ignores "unknown" or obfuscated tokens that could be used to trick a simpler fingerprinting script.



## Installation

```bash
npm i fpyx
# or
pnpm add fpyx
# or
bun add fpyx
```


## Quick Start

### Rate Limiting with Redis (Upstash)

```typescript
import { fingerprint } from 'fpyx';
import { Redis } from '@upstash/redis';

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
});

export async function rateLimit(req: Request): Promise<boolean> {
  const { hash } = fingerprint(req, {
    ipHeaders: ['cf-connecting-ip', 'x-forwarded-for'],
  });

  const key = `ratelimit:${hash}`;
  const count = await redis.incr(key);

  if (count === 1) {
    await redis.expire(key, 60);
  }

  return count <= 100;
}

if (!(await rateLimit(request))) {
  return new Response('Too many requests', { status: 429 });
}
```

### Cloudflare Workers with KV

```typescript
import { fingerprint } from 'fpyx';

type Env = {
  KV: KVNamespace;
};

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const { hash } = fingerprint(req, {
      ipHeaders: ['cf-connecting-ip'],
    });

    const key = `rl:${hash}`;
    const current = (await env.KV.get(key)) ?? '0';
    const count = Number.parseInt(current, 10) + 1;

    if (count > 50) {
      return new Response('Rate limit exceeded', { status: 429 });
    }

    await env.KV.put(key, String(count), { expirationTtl: 60 });
    return new Response('OK');
  },
};
```

## Features

### Cross-Runtime

Works everywhere JavaScript runs (Fetch-standard APIs):

* Node.js 18+ (including 20, 21, 22+)
* Bun 1.0+
* Deno 1.30+
* Cloudflare Workers
* Fastly Compute
* Vercel Edge Functions
* Netlify Edge Functions
* Modern browsers (Chrome, Firefox, Safari, Edge)

No Node.js crypto API. No file system. No network calls. Pure Fetch-standard APIs and `TextEncoder`.

### Performance

FNV-1a is extremely fast:

* 0.4-0.8 microseconds to hash a few hundred bytes on modern CPUs
* 100,000+ fingerprints per second on a single CPU core
* 800,000+ fingerprints per second on a modest 8-core instance
* ~10-20x faster than JSON parsing for small objects
* Zero overhead from dependencies, I/O, or async crypto

A typical API or edge worker can handle millions of requests per day without breaking a sweat. FNV-1a is so cheap you won't notice it in your profiler.

### Configuration

```typescript
fingerprint(request, {
  ipHeaders: ['cf-connecting-ip', 'x-forwarded-for'],
  includeMethod: true,
  includePath: true,
  pathNormalizer: (path) => path.replace(/\d+/g, ':id'),
  hashFn: (data) => myCustomHash(data),
});
```

### Zero Dependencies

No third-party libraries. No bloat. No supply chain risk. Just TypeScript.

### Fully Typed

Complete TypeScript definitions included. Strict mode compatible. `exactOptionalPropertyTypes` ready.

## Usage Examples

### Express.js Middleware

```typescript
import express from 'express';
import { fingerprint } from 'fpyx';
import { Redis } from 'ioredis';

function headersFromNode(headers: Record<string, unknown>): Headers {
  const h = new Headers();
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined || value === null) {
      continue;
    }
    if (Array.isArray(value)) {
      h.set(key, value.map(String).join(','));
      continue;
    }
    h.set(key, String(value));
  }
  return h;
}

const redis = new Redis();
const app = express();

app.use(async (req, res, next) => {
  const { hash } = fingerprint(
    {
      headers: headersFromNode(req.headers as Record<string, unknown>),
      method: req.method,
      url: req.originalUrl ?? req.url,
    },
    {
      ipHeaders: ['x-real-ip', 'x-forwarded-for'],
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

function headersFromNode(headers: Record<string, unknown>): Headers {
  const h = new Headers();
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined || value === null) {
      continue;
    }
    if (Array.isArray(value)) {
      h.set(key, value.map(String).join(','));
      continue;
    }
    h.set(key, String(value));
  }
  return h;
}

const fastify = Fastify();

fastify.addHook('onRequest', async (request, reply) => {
  const { hash } = fingerprint(
    {
      headers: headersFromNode(request.headers as Record<string, unknown>),
      method: request.method,
      url: request.url,
    },
    {
      ipHeaders: ['fastly-client-ip', 'x-forwarded-for'],
    }
  );

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

type Env = {
  KV: KVNamespace;
};

const app = new Hono<{ Bindings: Env }>();

app.use('*', async (c, next) => {
  const { hash } = fingerprint(c.req.raw, {
    ipHeaders: ['cf-connecting-ip'],
  });

  const key = `rl:${hash}`;
  const current = (await c.env.KV.get(key)) ?? '0';
  const count = Number.parseInt(current, 10) + 1;

  if (count > 100) {
    return c.text('Too many requests', 429);
  }

  await c.env.KV.put(key, String(count), { expirationTtl: 60 });
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

* `ipHeaders?`: `ReadonlyArray<string>` - Ordered list of trusted IP headers to check. Default: `DEFAULT_IP_HEADERS`
* `includeMethod?`: `boolean` - Include HTTP method in fingerprint. Default: `false`
* `includePath?`: `boolean` - Include URL path in fingerprint. Default: `false`
* `pathNormalizer?`: `(path: string) => string` - Optional function to normalize paths before fingerprinting
* `hashFn?`: `(data: Uint8Array) => string` - Override the hash function. Default: `fnv1a64Hex`

**Returns:** FingerprintResult

```typescript
interface FingerprintResult {
  hash: string;
  parts: ReadonlyArray<string>;
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

console.log(result.hash);
console.log(result.traits.ip);
console.log(result.traits.method);
console.log(result.traits.path);
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
console.log(hash);
```

### DEFAULT_IP_HEADERS

Default trusted IP header precedence. Override via options.ipHeaders.

```typescript
export const DEFAULT_IP_HEADERS: readonly string[] = [
  'cf-connecting-ip',
  'fastly-client-ip',
  'fly-client-ip',
  'true-client-ip',
  'forwarded',
  'x-forwarded-for',
  'x-real-ip',
];
```

## License

MIT (c) [@rccyx](https://rccyx.com)
