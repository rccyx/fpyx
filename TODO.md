# Getting started

## Install

```bash
npm install fpyx
```

## The basics

fpyx exports one function. It takes a request and returns a hash, the parts that produced it, and the resolved traits.

```ts
import { fingerprint } from 'fpyx';

const { hash, traits } = fingerprint(request);
```

`hash` is a 16-character hex string derived from the resolved identity. Hand it to whatever counter you're using.

## Telling fpyx which headers to trust

By default fpyx checks a built-in precedence list that covers the most common CDN and proxy headers: `cf-connecting-ip`, `fastly-client-ip`, `fly-client-ip`, `true-client-ip`, `forwarded`, `x-forwarded-for`, and `x-real-ip`, in that order.

You can override this with your own list:

```ts
const { hash } = fingerprint(request, {
  ipHeaders: ['cf-connecting-ip'],
});
```

Only include headers your infrastructure controls and guarantees to set. If you include a header your edge doesn't strip and rewrite, clients can spoof it. See the [security docs](/docs/sec.md).

## Authenticated requests

When you have a verified user, pass their ID as `actorId`. fpyx will use it as the sole identity anchor and ignore the IP entirely.

```ts
const { hash, traits } = fingerprint(request, {
  actorId: session.userId,
});

// traits.actorId === 'user_abc123'
// traits.ip === null
```

`actorId` and IP are mutually exclusive. fpyx never mixes them.

## Scoping keys to an endpoint

If you want separate rate limit buckets per endpoint or feature, use `scope`:

```ts
const { hash } = fingerprint(request, {
  actorId: session?.userId,
  scope: 'auth/login',
});
```

The scope partitions the key space without affecting the identity anchor. The same user hitting two different scoped endpoints gets two different hashes.

## Checking whether identity resolved

If neither `actorId` nor a valid IP was found, both will be null on `traits`. You should check this and decide how your app handles it:

```ts
const result = fingerprint(request, { ipHeaders: ['cf-connecting-ip'] });

if (result.traits.actorId === null && result.traits.ip === null) {
  // no identity anchor resolved, log it and decide: block, pass, or alert
  logger.warn('fpyx: unresolved identity');
}
```

fpyx returns null explicitly rather than falling back silently. What you do with an unresolved identity is your call.

## Wiring it up with Upstash

```ts
import { fingerprint } from 'fpyx';
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(5, '60 s'),
});

export async function POST(request: Request) {
  const { hash } = fingerprint(request, {
    ipHeaders: ['cf-connecting-ip'],
    scope: 'auth/login',
  });

  const { success } = await ratelimit.limit(hash);

  if (!success) {
    return new Response('Too many requests', { status: 429 });
  }

  // handle login...
}
```

## Wiring it up with rate-limiter-flexible

```ts
import { fingerprint } from 'fpyx';
import { RateLimiterRedis } from 'rate-limiter-flexible';
import { createClient } from 'redis';

const client = createClient();
await client.connect();

const limiter = new RateLimiterRedis({
  storeClient: client,
  points: 5,
  duration: 60,
});

app.post('/auth/login', async (req, res) => {
  const { hash } = fingerprint(req, {
    ipHeaders: ['x-forwarded-for'],
    scope: 'auth/login',
  });

  try {
    await limiter.consume(hash);
  } catch {
    return res.status(429).send('Too many requests');
  }

  // handle login...
});
```

## IPv6 subnet configuration

fpyx masks IPv6 addresses to `/56` by default, which aligns with typical residential allocation sizes. You can configure this:

```ts
fingerprint(request, {
  ipv6Subnet: 64, // mask to /64 instead
});
```

Valid range is 1 to 128. See the [security docs](/docs/sec.md) for why this matters.