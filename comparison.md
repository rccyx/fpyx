# Comparison

fpyx is the missing layer _under_ rate limiters: a hardened, cross-runtime request fingerprint/key generator for anonymous quota buckets.

Most libraries either:

1. do rate limiting but assume a good key (often `req.ip`), or
2. extract IP only, or
3. do browser/device fingerprinting (identity-ish), which is a different problem.

fpyx focuses on: **stable key generation across Node + edge + browser runtimes**, using **Fetch-standard Request/Headers**, with **trusted proxy header precedence**, and **fast deterministic hashing**.

## Usage

**Category:** request fingerprinting for rate limiting keys  
**Primary job:** produce a compact identifier you can feed into Redis/KV/Upstash/any store  
**Threat model:** do not trust arbitrary client headers; trust only headers your proxy overwrites  
**Not for:** identity, authentication, “anti-fraud”, or long-lived tracking

## Comparison Table

| Category                        | Library / Approach                | What it does                                                                                  | Typical identifier strategy                  | Runtime scope              | What you still have to do                                                         | Where fpyx differs                                                                    |
| ------------------------------- | --------------------------------- | --------------------------------------------------------------------------------------------- | -------------------------------------------- | -------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Browser fingerprinting          | FingerprintJS                     | Generates a browser fingerprint from many browser attributes (tracking / device intelligence) | “visitor ID” based on browser/device signals | Browser                    | Decide how to map it to rate limiting; accept tracking semantics; heavier surface | fpyx is server/edge-safe, minimal, and explicitly _not_ identity/tracking             |
| Browser fingerprinting          | ThumbmarkJS                       | Browser fingerprinting (“thumbmark”)                                                          | Device/browser fingerprint                   | Browser                    | Same as above                                                                     | Same: fpyx targets rate limiting buckets, not device identity                         |
| Rate limiting                   | express-rate-limit                | Rate limiting middleware for Express                                                          | default key is `req.ip`                      | Node/Express               | Correctly configure `trust proxy`, handle proxy headers safely                    | fpyx provides a safer, portable key that doesn’t depend on Express internals          |
| Rate limiting                   | rate-limiter-flexible             | Rate limiting primitives (Redis/memory/etc)                                                   | “consume points by key” (often `req.ip`)     | Node                       | Provide a robust key; handle proxies consistently                                 | fpyx is the cross-runtime key generator to feed into it                               |
| Rate limiting (edge/serverless) | Upstash Rate Limit                | HTTP-based rate limiting designed for serverless/edge; you call `limit(identifier)`           | you must supply `identifier`                 | Node + edge + more         | Build a stable identifier string yourself                                         | fpyx produces a deterministic hashed identifier designed for this exact call style    |
| Framework middleware            | hono-rate-limiter / Hono examples | Rate limiting middleware requires a `keyGenerator` function                                   | often `x-forwarded-for` directly             | Edge + Node (via adapters) | Avoid trusting spoofable headers; normalize correctly                             | fpyx centralizes safe header precedence + normalization, then hashes                  |
| IP extraction helper            | request-ip                        | Extract client IP from many possible headers                                                  | returns an IP string                         | Mostly Node HTTP/Express   | Still build a composite fingerprint; still hash; still handle method/path scoping | fpyx includes IP precedence + builds the full payload + hashes + returns traits/parts |
| IP extraction helper            | get-client-ip                     | Extract client IP with header precedence                                                      | returns an IP string                         | General JS                 | Same as above                                                                     | Same: fpyx is “IP extraction + fingerprint assembly + hashing”                        |
| Hash-only helper                | @sindresorhus/fnv1a (and similar) | Implements FNV-1a                                                                             | you provide bytes/string                     | General JS                 | Still define what to hash; still normalize; still proxy-hardening                 | fpyx defines the payload structure and extraction rules, not just the hash            |

## Why fpyx exists

### 1) Fetch-native, cross-runtime input surface

fpyx takes `Request` or `{ headers: Headers; method?; url? }`. That means it’s compatible with:

- Cloudflare Workers / Vercel Edge / Netlify Edge / Fastly Compute
- Deno / Bun
- Node 18+ (via global Fetch / undici)

Most Node rate limiting libs take Express/Node request objects; most edge examples are ad-hoc.

### 2) Explicit proxy header precedence

fpyx defaults to a precedence chain that starts with CDN/provider headers (e.g. Cloudflare/Fastly/Fly/Akamai), then standards (`Forwarded`), then common-but-spoofable headers (`X-Forwarded-For`, `X-Real-IP`).

This is where most “keyGenerator: x-forwarded-for” examples are naïve.

### 3) RFC 7239 Forwarded parsing + XFF first-hop handling

fpyx parses `Forwarded` (for=...) and also takes the first entry from `X-Forwarded-For`, matching common “client, proxy1, proxy2” semantics.

### 4) Deterministic payload structure + debuggability

You don’t just get a hash. You get:

- `traits` (ip/ua/al/method/path)
- `parts` (the exact segments that were hashed)

That’s really useful when debugging false positives / false negatives in rate limiting, and almost no “key generator” helpers do this cleanly.

### 5) Method/path scoping + path normalization

If you want per-route quotas (e.g. `/login` vs `/search`) you can include `path`, and normalize dynamic IDs (`/users/123 -> /users/:id`).

Most rate limiters either:

- treat everything per-IP globally, or
- leave route normalization as an exercise.

### 6) Fast, dependency-free hashing (FNV-1a 64-bit)

FNV-1a is non-cryptographic but extremely fast and stable. For anonymous quota buckets, that’s often the correct tradeoff: cheap keys, predictable behavior, no crypto APIs.

> [!NOTE]
> If you need a cryptographic digest, fpyx supports `hashFn` override.

## Integration examples

### With Upstash Rate Limit

Use `fingerprint(req).hash` as your identifier:

- `identifier = fingerprint(req, { includePath: true, includeMethod: true }).hash`
- then `ratelimit.limit(identifier)`

### With rate-limiter-flexible / Redis

Use the same `hash` as the Redis key suffix:

- `key = rl:${fingerprint(req).hash}`

### With Hono middleware

Set `keyGenerator` to fpyx’s output rather than raw headers:

- `keyGenerator: (c) => fingerprint(c.req.raw, { includePath: true }).hash`
