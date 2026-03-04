should epxlain how we do IPV6, what's scope & wht's actor & why
should epxlain all the attack vectors & how weprohibit agains tthem,

should epxlain how this is a lissing pice in the OSS community

<div align="center">

# fpyx

<p>
  <strong>Transport-agnostic identity anchoring for anonymous rate limiting.</strong>
</p>

<p>
  <a href="https://www.npmjs.com/package/fpyx">
    <img src="https://img.shields.io/npm/v/fpyx.svg" alt="npm version" />
  </a>
  <a href="https://bundlephobia.com/package/fpyx">
    <img alt="Bundle Size" src="https://img.shields.io/bundlephobia/minzip/fpyx?label=bundle"/>
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/npm/l/fpyx.svg" alt="MIT license" />
  </a>
</p>

</div>

have to mension the IP shit we mention in [IP extraction](/src/ip-extraction.ts)
It turns a messy inbound request into a deterministic bucket key you can safely use for abuse controls.

It exists because:

Raw req.ip is naïve and spoofable if headers are mishandled.
IPv6 makes naive IP limiting useless.
Proxy headers are easy to parse incorrectly.
Application routing semantics don’t belong inside a low-level primitive.

So instead of giving you a rate limiter, it gives you the clean identity substrate that any limiter can sit on top of.

fpyx is a tiny, zero-io primitive that turns a request into a deterministic bucket key for abuse controls like rate limiting, quotas, throttling, and anti-spam counters. It is not authentication, not “device fingerprinting”, and not a user tracking system. It’s an identity anchor for the one problem you always end up rewriting badly: “given this inbound event, what stable bucket should it increment”.

The model is intentionally minimal: a single identity anchor plus an optional caller-defined scope. The library does not interpret transport semantics. No method. No path. No route normalization. No GraphQL parsing. No framework coupling. That logic belongs to you.

## What it outputs

`fingerprint()` returns:

1. `traits`: what anchor was resolved (`actorId` or `ip`) plus the optional `scope`
2. `parts`: the canonical string segments used to build the key
3. `hash`: a fast 64-bit FNV-1a hash of `parts.join('|')` rendered as 16-char lowercase hex

Examples of `parts`:

`ip:203.0.113.10`  
`ip:203.0.113.10|scope:users.create`  
`actor:user_123`  
`actor:user_123|scope:auth.login`

Scope is opaque and caller-defined. A good scope is stable and low-cardinality: a route template, a procedure name, an operation name, or a coarse partition like `read` / `write`. If you don’t want partitioning, omit it.

## Identity anchoring rules

The anchor is exclusive, never mixed:

If `actorId` is provided and non-empty after trimming, it becomes the sole anchor. IP is ignored entirely.

Otherwise, fpyx extracts the client IP from headers using a precedence list (default includes common reverse-proxy headers plus RFC 7239 `Forwarded`), then normalizes it into a bucket.

IPv6 is masked by default to `/56` to avoid privacy extension churn creating trillions of “new identities” per household. IPv4 is kept exact. IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is normalized to IPv4 to avoid collapsing under the IPv6 mask.

## Trust model

fpyx can parse headers correctly, but it cannot decide which headers are trustworthy. Only pass headers that your edge proxy overwrites on every request. If you accept arbitrary `x-forwarded-for` from the internet, a client can spoof their IP and bypass IP-based controls. This library is a refining plant, not a trust oracle.

## Installation

```bash
npm i fpyx
# or
pnpm add fpyx
# or
bun add fpyx
```

## Quick start

Minimal anonymous rate limit key:

```ts
import { fingerprint } from 'fpyx';

export function keyFromRequest(req: Request): string {
  return fingerprint(req, {
    ipHeaders: ['cf-connecting-ip', 'x-forwarded-for'],
  }).hash;
}
```

Same identity, partitioned by a caller-defined operation scope:

```ts
import { fingerprint } from 'fpyx';

export function key(req: Request, scope: string): string {
  return fingerprint(req, {
    ipHeaders: ['cf-connecting-ip', 'x-forwarded-for'],
    scope,
  }).hash;
}
```

Actor override (logged-in user, API key, session, etc):

```ts
import { fingerprint } from 'fpyx';

export function key(req: Request, actorId: string, scope?: string): string {
  return fingerprint(req, {
    actorId,
    scope,
    ipHeaders: ['cf-connecting-ip', 'x-forwarded-for'],
  }).hash;
}
```

## Example: Upstash Redis rate limiting

```ts
import { fingerprint } from 'fpyx';
import { Redis } from '@upstash/redis';

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
});

export async function rateLimit(req: Request): Promise<boolean> {
  const { hash } = fingerprint(req, {
    ipHeaders: ['cf-connecting-ip', 'x-forwarded-for'],
    scope: 'auth.login',
  });

  const key = `rl:${hash}`;
  const count = await redis.incr(key);

  if (count === 1) await redis.expire(key, 60);

  return count <= 10;
}
```

## Example: Cloudflare Workers KV

```ts
import { fingerprint } from 'fpyx';

type Env = { KV: KVNamespace };

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const { hash } = fingerprint(req, {
      ipHeaders: ['cf-connecting-ip'],
      scope: 'global',
    });

    const key = `rl:${hash}`;
    const cur = (await env.KV.get(key)) ?? '0';
    const next = Number.parseInt(cur, 10) + 1;

    if (next > 100) return new Response('Too many requests', { status: 429 });

    await env.KV.put(key, String(next), { expirationTtl: 60 });
    return new Response('OK');
  },
};
```

## Choosing scopes (caller-owned)

You decide what “operation” means. Keep it stable and low-cardinality.

REST route template:

`/users/:id`
`/users.create`

RPC procedure:

`rpc.getUser`
`rpc.updateUser`

GraphQL operation:

`gql:GetUserProfile`

Read/write partition:

`read`
`write`

Global limiter:

omit scope

The point is explicit intent. fpyx will never guess this for you.

## API

### fingerprint(source, options?)

```ts
import type {
  FingerprintResult,
  FingerprintOptions,
  FingerprintSource,
} from 'fpyx';

declare function fingerprint(
  source: FingerprintSource,
  options?: FingerprintOptions
): FingerprintResult;
```

`source` is:

`Request` or `{ headers: Headers }`

`options`:

- `actorId?: string | null` trusted actor identity (trimmed, ignored if blank)
- `scope?: string | null` opaque namespace partition (trimmed, ignored if blank)
- `ipHeaders?: readonly string[]` ordered precedence list for client IP extraction
- `ipv6Subnet?: number` subnet mask for IPv6 buckets (default `/56`, range `1..128`)
- `hashFn?: (input: Uint8Array) => string` override hashing

Returns:

```ts
type Optional<T> = T | null;

interface FingerprintResult {
  readonly hash: string;
  readonly parts: readonly string[];
  readonly traits: FingerprintTraits;
}

interface FingerprintTraits {
  readonly actorId: Optional<string>;
  readonly ip: Optional<string>;
  readonly scope: Optional<string>;
}
```

### fnv1a64Hex(data)

```ts
import { fnv1a64Hex } from 'fpyx';

const encoder = new TextEncoder();
fnv1a64Hex(encoder.encode('hello')); // a430d84680aabd0b
```

### DEFAULT_IP_HEADERS

Default header precedence list used for IP extraction (override via `ipHeaders`):

```ts
import { DEFAULT_IP_HEADERS } from 'fpyx';
```

## Notes

This library is intentionally not a rate limiter. It outputs a deterministic key you can plug into any counter store you want. It’s also intentionally not a “fingerprinting” product in the tracking sense. It is an abuse anchor primitive: actor identity if you have it, otherwise an IP bucket hardened against common proxy-header parsing traps.

## License

MIT (c) rccyx
