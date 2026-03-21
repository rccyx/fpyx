# How fpyx relates to other libraries

Cool, but I already use "some-lib".

fpyx can be compared to things it has nothing to do with, so this page exists to draw the lines clearly.


## @upstash/ratelimit

Upstash's rate limiting library is serverless-first, HTTP-based, and backed by Upstash Redis. It's a good fit for edge runtimes where you can't maintain a persistent TCP connection to Redis. It implements fixed window, sliding window, and token bucket algorithms and is designed for Cloudflare Workers, Vercel Edge, and similar environments.

Like rate-limiter-flexible, it takes an identifier you supply. Their own docs suggest using a `userID`, `apiKey`, or IP address, but deriving a correct, stable IP from the incoming request is not their problem. They assume you've already solved that.

fpyx produces the identifier. @upstash/ratelimit consumes it. Again, these fit together directly:

```ts
import { fingerprint } from 'fpyx';
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '10 s'),
});

const { hash } = fingerprint(request, {
  // if logged in, good we take actorId and hash it with scope
  actorId: session?.userId, 
  // else, we use the API
  ipHeaders: ['cf-connecting-ip'],
  // automatically
  scope: 'api/v1',
});

const { success } = await ratelimit.limit(hash);
```


## express-rate-limit

This is the closest thing to an overlapping use case, and it's still not really the same.

express-rate-limit is a full rate limiting middleware for Express. It manages counters, enforces thresholds, sets response headers, and plugs into a store. It does handle IPv6 subnetting via an `ipv6Subnet` option, which was a meaningful addition. But it derives the client IP by reading `req.ip`, which means it fully inherits Express's `trust proxy` configuration and all of the failure modes that come with it.

Their own docs document this as a known configuration footgun: if you're behind a proxy and `trust proxy` isn't set correctly, `req.ip` returns the proxy's address and every request lands in the same bucket. The RFC 7239 `Forwarded` header is explicitly unsupported as of express@5 because Express's trust proxy logic only handles `X-Forwarded-For`. Their error codes page logs a warning when it detects the `Forwarded` header for exactly this reason.

Beyond the IP extraction issues, express-rate-limit is coupled to Express specifically.

fpyx takes any object with a `.headers: Headers` property, which covers every modern server environment.

fpyx is not a replacement for express-rate-limit. If you need rate limiting in Express and the defaults work for your infrastructure, express-rate-limit is fine. fpyx is useful when you want the key derivation to be correct and portable, separate from whichever counting layer you're using.


## FingerprintJS and ThumbmarkJS

These are not rate limiting tools. They are browser fingerprinting libraries, which is a completely different problem.

FingerprintJS and ThumbmarkJS run client-side JavaScript inside the browser to interrogate the device: canvas rendering, WebGL output, installed fonts, audio API behavior, screen resolution, hardware concurrency, and a dozen other signals. They hash all of that together into a visitor ID that persists across incognito mode and cookie clearing. The point is long-term device recognition, usually for fraud detection, bot scoring, or analytics. The identifier lives in the browser and is sent to your backend as a token.

fpyx does none of this. It runs on the server, sees only the HTTP request, and extracts an IP address from headers your infrastructure controls. It has no visibility into the browser environment, makes no external calls, and produces no persistent identifier. If someone clears cookies or switches to incognito, fpyx doesn't care and doesn't notice, because it was never looking at any of that in the first place.

## rate-limiter-flexible

rate-limiter-flexible is a comprehensive rate limiting library with support for in-memory storage, Redis, MongoDB, PostgreSQL, and others. It handles sliding windows, token buckets, insurance strategies, and a lot of other policy concerns. It's framework-agnostic and well-maintained.

It also expects you to supply the key. The library's job is counting, not identity derivation. You call `rateLimiterRedis.consume(key)` and you've already decided what `key` is. If you pass a raw IP from `req.headers['x-forwarded-for'].split(',')[0]`, you get the same injection and spoofing issues as anything else that does that naively.

fpyx is what you use to produce the `key` argument. The two fit together directly.