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

/**
 * Normalizes a caller-supplied actor ID to a trimmed string, or `null` if the
 * value is absent, explicitly `null`, or blank after trimming.
 */
function normalizeActorId(
  value: Optional<string> | undefined
): Optional<string> {
  if (value === undefined || value === null) return null;
  const trimmed = value.trim();
  return trimmed === '' ? null : trimmed;
}

/**
 * Derives an abuse-aware identity key suitable for request shaping such as
 * rate limiting, quotas, and throttling.
 *
 * ---
 *
 * ### Identity precedence
 *
 * If `actorId` is provided and non-empty after trimming, it becomes the sole
 * identity anchor. No IP information is included. This is the preferred mode
 * when a trusted, authenticated identity is available (e.g. a session ID, API
 * key, or user ID).
 *
 * When `actorId` is absent or blank, identity anchors on the client IP
 * address, normalized to a subnet bucket via {@link normalizeIpForBucket}.
 * The two anchors are never mixed.
 *
 * ### Scoping
 *
 * `includeMethod` and `includePath` append the HTTP method and URL pathname to
 * the key, partitioning the key space so that different operations on the same
 * identity produce distinct fingerprints. Scoping dimensions are not treated
 * as identity entropy, they are purely additive namespace separators.
 *
 * ### Trust model
 *
 * {@link extractClientIp} parses headers but cannot establish trust. You must
 * only pass headers that your edge proxy is guaranteed to overwrite. If an
 * upstream header is forwarded as-is, a client can supply an arbitrary IP and
 * bypass IP-based rate limiting.
 *
 * @param source - A Fetch API `Request`, or a lightweight
 *   `{ headers, method?, url? }` object compatible with edge runtimes.
 * @param options - Configuration for identity precedence, IP parsing, scoping,
 *   and hashing.
 * @returns A {@link FingerprintResult} containing the hash, the ordered parts
 *   used to produce it, and the resolved identity traits.
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
  const hashFn: HashFunction = options?.hashFn ?? fnv1a64Hex;
  const hash = hashFn(textEncoder.encode(parts.join('|')));

  return {
    hash,
    parts,
    traits,
  };
}
