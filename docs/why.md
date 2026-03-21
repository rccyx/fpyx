# Why fpyx

"I don't need it, I already have Cloudflare."

Cloudflare protects against abuse at the network level. DDoS, bot floods, known malicious IPs, volumetric attacks, all of that. It's excellent at what it does. But Cloudflare has no idea how your application works.

It doesn't know that your login endpoint should allow five attempts before introducing a delay. It doesn't know that password reset should be limited to three emails per hour per IP regardless of which account is being targeted. It doesn't know that your free tier allows ten API calls per minute but your paid tier allows five hundred. That logic lives in your application, and Cloudflare can't express it. So you still end up writing rate limiting code, but you're in a hurry, and that's where the problem starts.

## The key is the whole problem

Every rate limiter, regardless of library, framework, or storage backend, boils down to one operation: increment a counter for a key, check if it's over the limit. The policy, the window, the storage, all of that comes after the key is set.

The key is everything. If the key wrong, your rate limiter either does nothing or throttles the wrong people.

In local development it always works fine, so it never feels urgent. You grab `req.ip`, it returns something sensible, you move on. The problem is that `req.ip` in production behind a proxy doesn't return the client's IP. It returns the proxy's IP. Every single request, from every single client, resolves to the same key. Your rate limiter either immediately trips on legitimate traffic or does nothing useful at all, and it does this silently. Nothing throws an error. Nothing looks broken. You find out when someone complains or when you're getting hammered and nothing is stopping it.

Even when you fix the proxy problem and start reading the right header, IPv6 creates another one. Privacy extensions rotate the interface identifier per connection on most modern operating systems. One device, one person, can present a completely different `/128` address on every request without doing anything deliberate. If you're rate limiting on the full address, that person is functionally exempt. And again, this is invisible in development because you were probably testing on a stable IPv4 address.

## What fpyx is

fpyx is that primitive. It takes a request, extracts the correct IP from whatever headers your infrastructure provides, handles the IPv6 edge cases, and returns a stable hash you can hand to whatever counter you're already using. No Redis client. No middleware. No framework coupling. No rate limiting policy. Just the key, derived correctly.

For authenticated endpoints, use the user ID. That's what `actorId` is for, and when it's present the IP is ignored entirely. The place fpyx earns its keep is pre-auth surfaces: login, signup, password reset, public endpoints, anything where IP is the only anchor you have and you actually need it to be right.

## What's broken

`req.ip` cannot be trusted. Read the [security docs](/docs/security.md) for the full breakdown.
