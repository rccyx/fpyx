/**
 * A hardened request fingerprint helper for anonymous rate limiting buckets.
 *
 * It combines coarse request traits (trusted client IP header, User-Agent, Accept-Language,
 * and optional method + path) into a deterministic UTF-8 payload, then hashes it with
 * FNV-1a 64. The output is a compact identifier suitable for rate limiting keys.
 *
 * This does not provide identity, tracking, or authentication. Pair with server-side
 * quotas and trusted proxy configuration as recommended by OWASP API4:2023.
 *
 * @packageDocumentation
 */

export { fingerprint } from './fingerprint';
export { fnv1a64Hex } from './hash';
export { DEFAULT_IP_HEADERS } from './constants';
export type {
  FingerprintResult,
  FingerprintTraits,
  FingerprintSource,
  FingerprintOptions,
  HashFunction,
} from './types';
