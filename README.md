
<div align="center">

# fpyx

<p>
  Transport-agnostic identity anchoring for anonymous rate limiting
</p>
<p>
  <a href="https://www.npmjs.com/package/fpyx">
    <img src="https://img.shields.io/npm/v/fpyx?style=flat&logo=npm&logoColor=white" />
  </a>
  <a href="https://www.typescriptlang.org/">
    <img src="https://img.shields.io/badge/TypeScript-5%2B-blue?style=flat&logo=typescript&logoColor=white" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/npm/l/fpyx?style=flat&color=blue" />
  </a>
</p>

</div>


## What

Rate limiting requires a key. Getting that key right is harder than it looks. No other library does it currently for the whole ecosystem.

Every rate limiter boils down to one operation: incrementing a counter for a key. If your key is wrong, your rate limiter does nothing useful.

Most developers just grab `req.ip` or naively split `x-forwarded-for`. When you do that in production, you get hit by three things:

1.  **Proxies:** Behind a load balancer, `req.ip` is the proxy's IP. Every request lands in the same bucket. Shot your own foot.
2.  **Spoofing:** Blindly reading `x-forwarded-for` lets attackers inject arbitrary strings and rotate their "IP" on every request.
3.  **IPv6:** Modern OS privacy extensions rotate IPv6 interface identifiers constantly, abusers too. Rate limiting on a full `/128` means attackers bypass your limits just by waiting.

Cloudflare handles DDoS, but it doesn't know your app's business logic. That logic lives in your app, and it needs a correct key.

`fpyx` gives you that key. It takes a request, extracts the correct IP from headers your infrastructure actually controls, handles the IPv6 edge cases, and returns a stable FNV-1a fast hash.

Zero dependencies. Works everywhere JavaScript runs with Fetch-standard `Request`/`Headers` (Node 18+, Bun, Deno, Cloudflare Workers, Vercel Edge).


> [!IMPORTANT]
> This is not for identity or authentication.

## Why 

### Deep dive.

Read the [docs/why](./docs/why.md) document, along with the [docs/security](./docs/security.md) (attack vectors in IP-based rate limiting) and how `fpyx` handles them.

### Comparison 

How this differs from `express-rate-limit`, `rate-limiter-flexible`, Upstash Rate Limit, etc? See the full [docs/comparison](/docs/comparison.md) document.


## Install

```bash
npm install fpyx
# or 
pnpm install fpyx
# or
bun add fpyx
```


## How it works

The place fpyx earns its keep is pre-auth surfaces: login, signup, password reset, public endpoints, anything where a user hasn't proven who they are yet and IP is the only anchor you have.

For authenticated requests, pass `actorId` and `fpyx` uses it exclusively, IP is ignored entirely.

You call one function. Pass the request. Get an object back. Hand the hash to whatever counting layer you use (Redis, Upstash, memory).

```ts
import { fingerprint } from "fpyx";
import { ratelimit } from "./my-redis-setup";

const result = fingerprint(request, {
  // Primary Anchor: If logged in, use their ID. Ignores IP entirely.
  actorId: session?.userId,

  // Fallback Anchor: Strict extraction from headers you control.
  ipHeaders: ["cf-connecting-ip", "x-forwarded-for"],

  // Scope: Separate buckets per endpoint.
  scope: "auth/login",
});

await ratelimit.limit(result.hash);
```


### The Output

If the user is unauthenticated (relying on IP):

```ts
{
  hash: 'c72a1d8e90b3f445', // The key. Hand this to your counter.

  parts: [
    'ip:2001:0db8:abcd:1200:0000:0000:0000:0000', // IPv6 masked to /56
    'scope:auth/login'
  ],

  traits: {
    actorId: null,
    ip: '2001:0db8:abcd:1200:0000:0000:0000:0000',
    scope: 'auth/login'
  }
}
```

If the user is authenticated (relying on `actorId`):

```ts
{
  hash: 'a3f1c8e2b4d09571',
  parts: ['actor:user_abc123', 'scope:auth/login'],
  traits: {
    actorId: 'user_abc123',
    ip: null, // Ignored entirely
    scope: 'auth/login'
  }
}
```

## API

### `fingerprint(source, options?)`

| Option | Type | Default | Description |
|---|---|---|---|
| `actorId` | `string \| null` | `null` | Verified user, session, or API key. Takes full precedence over IP when present. |
| `ipHeaders` | `string[]` | see below | Ordered list of headers to check for client IP. |
| `ipv6Subnet` | `number` | `56` | Prefix length for IPv6 subnet masking. Integer 1-128. |
| `scope` | `string \| null` | `null` | Opaque string for key space partitioning. |
| `hashFn` | `HashFunction` | `fnv1a64Hex` | Custom hash function. |

Default `ipHeaders` precedence: `cf-connecting-ip`, `fastly-client-ip`, `fly-client-ip`, `true-client-ip`, `forwarded`, `x-forwarded-for`, `x-real-ip`.

Returns `{ hash, parts, traits }`.

| Field | Type | Description |
|---|---|---|
| `hash` | `string` | 16-character hex string. Hand this to your counter. |
| `parts` | `string[]` | The components that produced the hash, before joining and hashing. |
| `traits` | `FingerprintTraits` | The resolved identity: `actorId`, `ip`, `scope`. |

### `fnv1a64Hex(data)`

The default hash function. FNV-1a 64-bit, returns a 16-character zero-padded lowercase hex string. Not cryptographic. Fast.

You can override it.

## License

MIT (c) [@rccyx](https://rccyx.com)
