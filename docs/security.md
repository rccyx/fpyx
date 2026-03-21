# Attack vectors in naive IP-based rate limiting

Before anything else: this library cannot stop spoofing. Nothing can. What it does is give you a clean, consistent key derived from whatever headers you tell it to trust, and that trust relationship is entirely on you. Feed it a header your edge doesn't control, and you've handed the attacker the keys. The library did exactly what you asked.

IP-based rate limiting fails in a cluster of predictable ways, and the failures tend to compound each other silently. None of them show up in local development. Most of them only become visible once someone is actively exploiting them.

The most fundamental problem is that `req.ip` (the thing most frameworks hand you by default) reflects the last network hop, not the client. Behind any reverse proxy, load balancer, or CDN, that's going to be a loopback address or an internal VPC node. Every single request lands in the same bucket. Your rate limiter either trips immediately on legitimate traffic or does nothing at all, depending on your threshold. This library sidesteps this entirely by ignoring `req.ip` and reading only from an explicit list of headers you provide:

```ts
fingerprint(request, {
  ipHeaders: ['cf-connecting-ip', 'x-forwarded-for'],
});
```

If none of those headers contain a valid IP literal, you get `null` back in `traits.ip`, not a silent fallback to something useless. You can see this in the `FingerprintTraits` shape, `ip` is typed `string | null` and will be explicitly null rather than quietly wrong.

The proxy forwarding headers themselves are another surface. `X-Forwarded-For` is append-only: each hop appends to the right, which means the leftmost entry is whatever the client or the first untrusted hop put there. If your edge doesn't strip and rewrite it before the request hits your app, a client can send this:

```
X-Forwarded-For: 1.2.3.4
```

and your app receives:

```
X-Forwarded-For: 1.2.3.4, <real-client-ip>
```

A naive `split(',')[0]` implementation hands the attacker full control over their own bucket key. They pick any IP, rotate it freely, and your rate limiter never sees the same key twice.

The RFC 7239 `Forwarded` header has its own version of this. The spec explicitly allows `unknown` and underscore-prefixed tokens as valid `for=` values for cases where the IP can't be disclosed. A naive parser that doesn't validate the extracted value as a strict IP literal will use `unknown` as a bucket key directly, collapsing every client that sends `for=unknown` into the same counter, or letting an attacker rotate arbitrary `_gazonk`-style tokens to get a fresh key on every request.

On top of that, the `Forwarded` grammar allows quoted strings that contain commas and semicolons, the same characters used as entry and directive delimiters. A parser that doesn't track quote state will misparse something like this:

```
Forwarded: for="2001:db8::1;evil=injected", for=203.0.113.60
```

and may interpret `evil=injected` as a separate directive. The parser in this library handles all of it: comma and semicolon splitting only outside quoted strings, backslash escape handling inside quotes, bracket notation for IPv6, port stripping, and strict IP literal validation on every extracted value. Tokens like `unknown`, `none`, `null`, and anything with a leading underscore are explicitly rejected before they can reach a bucket key.

Even when you get a real IP out, IPv6 creates a different problem. Privacy extensions (RFC 4941), enabled by default on most modern operating systems, rotate the interface identifier per connection or on a timer. A single residential ISP allocation is typically a `/48` or `/56` prefix, which contains between 65,536 and 16,777,216 valid `/128` addresses. A single device can present a completely distinct address on every request without any deliberate action on the user's part.

Rate limiting on the full `/128` is therefore trivially bypassed just by waiting. The library masks IPv6 addresses down to a configurable prefix before using them as bucket keys:

```ts
fingerprint(request, {
  ipv6Subnet: 56, // default
});
```

With a `/56` mask, `2001:db8:abcd:12ff:aaaa:bbbb:cccc:dddd` and `2001:db8:abcd:1234:1111:2222:3333:4444` both resolve to `2001:0db8:abcd:1200:0000:0000:0000:0000`, the same bucket, regardless of interface identifier rotation.

There's also a subtler issue with IPv4-mapped IPv6 addresses. When an IPv4 client connects through a dual-stack server, it may be presented to the application as `::ffff:203.0.113.10` rather than plain `203.0.113.10`. If you apply a `/56` mask to the mapped form directly, you zero out the last three octets of the embedded IPv4 address, meaning `::ffff:203.0.113.10` and `::ffff:203.0.113.200` (completely different clients) collapse into the same bucket. The same client can also arrive in both forms across different requests, producing two separate bucket entries for one real identity. Both problems are fixed by detecting the `::ffff:0:0/96` prefix and unwrapping it back to plain IPv4 before any masking is applied. IPv4 addresses are never subnet-masked.

These issues don't stay isolated. A single request can present an RFC 7239 obfuscated identifier (`for=_hidden`) that causes fallthrough to an `X-Forwarded-For` chain where the first entry is `unknown`, which also fails, which falls through to a `cf-connecting-ip` containing an IPv6 address in IPv4-mapped form that's rotating on every connection due to privacy extensions. Each of these independently breaks rate limiting. In combination, they reduce IP-based controls to completely ineffective against anyone who knows what they're doing, and the failure is invisible under normal load, only surfacing once it's already being exploited.
