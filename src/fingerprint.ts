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
import { extractMethod, extractPath, buildParts } from './utils';
import { normalizeIpForBucket } from './ip-subnet';

const textEncoder = new TextEncoder();

function normalizeActorId(
  value: Optional<string> | undefined
): Optional<string> {
  if (value === undefined || value === null) return null;
  const trimmed = value.trim();
  return trimmed === '' ? null : trimmed;
}

/**
 * derive an abuse-aware identity key for request shaping (rate limits, quotas, throttles).
 *
 * the library is intentionally opinionated and abuse-first:
 * it does not mix entropy sources and it does not include attacker-controlled headers
 * (for example user-agent or accept-language) in the identity surface.
 *
 * identity precedence is explicit:
 * if `actorId` is provided and non-empty, it fully replaces network identity.
 * otherwise identity anchors on a normalized, subnet-masked client ip bucket.
 *
 * optional scoping (`includeMethod`, `includePath`) can be appended to partition namespaces.
 * scoping is not treated as identity entropy. it is just a key-space partition.
 *
 * trust model:
 * `extractClientIp` only parses. it cannot establish trust.
 * you must only rely on headers that your edge proxy overwrites.
 *
 * @param source fetch request or a lightweight `{ headers, method?, url? }` object
 * @param options configuration for identity precedence, ip parsing, scoping, and hashing
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7239
 * @see https://datatracker.ietf.org/doc/html/rfc4291
 */
export function fingerprint(
  source: FingerprintSource,
  options?: FingerprintOptions
): FingerprintResult {
  const actorId = normalizeActorId(options?.actorId);

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
    method: options?.includeMethod === true ? extractMethod(source) : null,
    path:
      options?.includePath === true
        ? extractPath(source.url, options?.pathNormalizer)
        : null,
  } satisfies FingerprintTraits;

  const parts = buildParts(traits);

  const payload = textEncoder.encode(parts.join('|'));

  const hashFn: HashFunction = options?.hashFn ?? fnv1a64Hex;

  return {
    hash: hashFn(payload),
    parts,
    traits,
  };
}
