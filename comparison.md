tldr:

FingerprintJS is too heavy and privacy-invasive for simple API protection.
rate-limiter-flexible is amazing at math/storage but leaves the "key" part entirely up to you, which chances are, you'll mess it up.
express-rate-limit is too tied to Express.

fpyx was built to be the standard key-cutter, a specialized tool that does one thing (turning a Request into a Hash) perfectly, so it can be plugged into any engine anywhere JS runs, your logic stays the same when you change clouds, frameworks or runtimes.

### fpyx

- **What it is:** a tiny, cross-runtime function that turns a Fetch-style request into a stable **rate-limit key**: `{ hash, traits, parts }`.
- **What it consumes:** `Request` or `{ headers: Headers; method?; url? }`.
- **What it outputs:** a compact identifier you can feed into _any_ limiter or datastore.
- **Core rule:** it only trusts IP headers by _your precedence list_, and parses `Forwarded` according to RFC 7239.
- **Why it exists:** most rate limiters assume `req.ip` or ad hoc header parsing; fpyx makes that part consistent across Node, Bun, Deno, Workers, edge.

### What fpyx is not

- Not a rate limiter (no windows, counters, tokens, Redis, KV, nothing).
- Not identity, not anti-fraud, not “this user is the same human.” It’s a **bucket key**, on purpose.

### Browser/device fingerprinting libraries (different universe)

### FingerprintJS

- **What it’s for:** identifying a browser/device by collecting many browser-exposed attributes and producing a “visitor id.”
- **How it works conceptually:** it leans on browser surfaces like canvas/WebGL/audio/fonts and other environment traits to build a stable-ish identifier. That’s fraud/abuse analytics territory, not “key for Redis counter.”
- **Why it’s not fpyx:** it runs in the browser, is heavier, and is aimed at _recognizing a device_, not generating a clean server-side quota key, super fast.

### ThumbmarkJS

- **What it’s for:** also browser fingerprinting. It markets itself as a browser fingerprinting library to generate “thumbmarks” for anti-spam/anti-scam type use cases.
- **Why it’s not fpyx:** same mismatch. It’s device identification, you’re doing server/edge quota buckets.

fpyx is here because you don’t need a GPU canvas signature to rate limit an API behind a trusted proxy chain to stop a spammer, also, you can't stop a spammer with just an IP and end up blocking 500 other innocent users.

## Rate limiters

you feed them the key

### express-rate-limit

- **What it’s for:** Express middleware that blocks requests when a key exceeds a window.
- **Default behavior:** keys are typically derived from `req.ip`, and you have to get proxy trust correct or you get global throttling mistakes.
- **Where fpyx fits:** you replace “whatever Express thinks the IP is” with a stable cross-runtime key, and you keep the rest of the limiter.

### rate-limiter-flexible

- **What it’s for:** primitives for counting “points” per key (Redis/memory/etc). It’s basically “consume points by key.”
- **Where fpyx fits:** you give it `fingerprint(...).hash` as the key. It does the rest.

### Upstash Rate Limit

- **What it’s for:** rate limiting designed for serverless and edge, “connectionless (HTTP based).”
- **How it’s used:** you call `ratelimit.limit(identifier)` and you must supply `identifier`.
- **Where fpyx fits:** fpyx is a clean way to generate that identifier consistently in any runtime.

So basically these are engines. fpyx is the key.

## IP extraction helpers

These stop too realy.

### request-ip

- **What it’s for:** extracts the client IP by checking a precedence list of headers.
- **Where it stops:** returns an IP string.
- **Where fpyx differs:** fpyx does IP extraction _plus_ payload assembly _plus_ hashing _plus_ method/path scoping _plus_ returns debuggable `traits` and `parts`, with arguments you control.

### get-client-ip

- **What it’s for:** another header-precedence IP extractor.
- **Where fpyx differs:** same point. These libs give you a raw string. fpyx gives you a stable quota key you can drop into any limiter.

Also: MDN explicitly warns that X-Forwarded-For is easy to misuse and becomes a risk if you trust it from the open internet. fpyx’s entire value is “make the trusted chain explicit.”

## Hash-only libs

they don’t decide what to hash

### @sindresorhus/fnv1a

- **What it’s for:** implements FNV-1a hashing.
- **Where it stops:** you still have to decide what bytes to hash and how to normalize headers across environments.
- **Where fpyx differs:** fpyx defines the payload structure and extraction rules, not just the hash.

fpyx is the missing layer under rate limiters: a cross-runtime request key generator that turns trusted proxy headers + a few coarse traits into a deterministic hash you can feed into any limiter, anywhere.
