import type {
  FingerprintSource,
  FingerprintOptions,
  FingerprintResult,
  FingerprintTraits,
  HashFunction,
  Optional,
} from './types';
import { DEFAULT_IP_HEADERS } from './constants';
import { fnv1a64Hex } from './hash';
import { extractClientIp } from './ip-extraction';
import { buildParts } from './utils';
import { normalizeIpForBucket } from './ip-subnet';
import { Maybe } from 'typyx';

const textEncoder = new TextEncoder();

/**
 * Normalize a potential actor identifier (such as a user, session, or API key).
 *
 * Trims whitespace and returns `null` if the value is missing or empty.
 * This ensures consistency and prevents accidental misuse of blank identifiers.
 *
 * @param value - The input actor identifier.
 * @returns The normalized actorId, or `null` if not provided or empty.
 */
function normalizeActorId(value: Maybe<string>): Optional<string> {
  if (value === undefined || value === null) return null;
  const trimmed = value.trim();
  return trimmed === '' ? null : trimmed;
}

/**
 * Normalize an optional user-specified fingerprint scope string.
 *
 * Trims excess whitespace and returns `null` for empty, undefined, or null values.
 * Used to logically partition keyspaces without introducing identity entropy.
 *
 * @param value - The input scope value.
 * @returns The normalized scope string, or `null`.
 */
function normalizeScope(value: Maybe<string>): Optional<string> {
  if (value === undefined || value === null) return null;
  const trimmed = value.trim();
  return trimmed === '' ? null : trimmed;
}

/**
 * Generates a cryptographically-stable, abuse-resistant identity fingerprint for HTTP requests.
 *
 * This function derives a canonical, stable fingerprint string for a given request source and options,
 * optimized for use in rate limiting, abuse detection, quotas, and similar shaping controls.
 * 
 * ### Identity Anchor
 * - The anchor is chosen in strict priority order:
 *   1. **Actor ID:** If `actorId` is provided and non-empty, it takes precedence (e.g., user/session/API key).
 *      - When actorId is present, the client network address (IP) is ignored.
 *   2. **IP Address:** If no actorId is present, the client IP (normalized and subnet-masked) is used.
 *
 * ### Scope Partitioning
 * - An optional, user-provided opaque string (`scope`) may be appended for logical partitioning of the
 *   key space (e.g., distinguishing between different product environments, tenants, or endpoints).
 *   - The scope is always trimmed and set to `null` if empty.
 *   - It participates in partitioning only, never in the core identity entropy.
 *
 * ### Trust Model & Security
 * - Network identity is extracted from trusted headers only. The caller **must** ensure only trustworthy headers
 *   (usually injected by a tightly-controlled edge/proxy) are provided.
 * - This function **does not** attempt to verify downstream authenticity.
 * - See [RFC 7239](https://datatracker.ietf.org/doc/html/rfc7239) and [RFC 4291](https://datatracker.ietf.org/doc/html/rfc4291)
 *   for guidance on network identity and IPv6 subnets.
 *
 * ### Example
 * ```ts
 * const result = fingerprint(request, {
 *   actorId: user.id,
 *   ipHeaders: ['x-forwarded-for'],
 *   scope: 'api/v1/quotas'
 * });
 * // result: { hash, parts, traits }
 * ```
 *
 * @param source   - A Fetch `Request` or `{headers: Headers}` object (env-agnostic).
 * @param options  - Fingerprinting options (actorId, ip headers, scope, hash function, etc).
 * @returns        - A canonical fingerprint result: hash, parts (components), and resolved traits.
 */
export function fingerprint(
  source: FingerprintSource,
  options?: FingerprintOptions
): FingerprintResult {
  const actorId = normalizeActorId(options?.actorId);
  const scope = normalizeScope(options?.scope);
  const traits = {
    actorId,
    ip:
      actorId === null
        ? normalizeIpForBucket(
            extractClientIp(
              source.headers,
              options?.ipHeaders ?? DEFAULT_IP_HEADERS
            ),
            options?.ipv6Subnet
          )
        : null,
    scope,
  } satisfies FingerprintTraits;

  const parts = buildParts(traits);
  const hashFn = options?.hashFn ?? fnv1a64Hex satisfies HashFunction;
  const hash = hashFn(textEncoder.encode(parts.join('|')));

  return {
    hash,
    parts,
    traits,
  };
}
