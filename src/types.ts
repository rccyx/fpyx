export type Optional<T> = T | null;
export type Possible<T> = T | undefined;
export type Maybe<T> = Possible<Optional<T>>;

/**
 * The result type returned by the {@link fingerprint} function.
 *
 * This object describes the canonical fingerprint for a set of input traits and options.
 * - `hash` is computed by applying the (configurable) hash function to the canonical string built from `parts`.
 * - `parts` are the stable, ordered fingerprint key components prior to hashing.
 * - `traits` describes the resolved set of input traits used to compute the fingerprint.
 */
export interface FingerprintResult {
  /**
   * The canonical hash string, derived from all key parts
   * using the configured hash function (default: {@link fnv1a64Hex}).
   */
  readonly hash: string;
  /**
   * The array of string parts that are joined and hashed
   * to form the fingerprint. Stable and ordered.
   */
  readonly parts: readonly string[];
  /**
   * The set of derived identity traits used for the fingerprint.
   */
  readonly traits: FingerprintTraits;
}

/**
 * Describes resolved identity traits used as the basis for fingerprinting.
 *
 * - `actorId` and `ip` are mutually exclusive as the primary identity anchor.
 *   - If `actorId` is present and non-null, it is always used as the sole anchor, and `ip` is null.
 *   - If `actorId` is null, the fingerprint falls back to `ip` (which may itself be null if unavailable).
 * - `scope` is an additive, optional string for logical partitioning (has no role in identity).
 */
export interface FingerprintTraits {
  /**
   * The trusted, application-provided actor identifier such as user ID, session ID, or API key.
   * This always overrides network-based identity when provided.
   */
  readonly actorId: Optional<string>;
  /**
   * The network-derived client IP address, normalized and masked as appropriate,
   * or `null` if no valid address was found.
   */
  readonly ip: Optional<string>;
  /**
   * An optional, user-defined, opaque scope string partitioning the key space.
   * Trimmed and set to null if empty.
   */
  readonly scope: Optional<string>;
}

/**
 * The accepted input for the {@link fingerprint} function.
 *
 * Can be:
 *   - A full Fetch API {@link Request} object (supports all environments).
 *   - A minimal object matching `{ headers: Headers }`, used for edge/serverless environments.
 */
export type FingerprintSource =
  | Request
  | {
      readonly headers: Headers;
    };

/**
 * Configuration options for the {@link fingerprint} function.
 */
export interface FingerprintOptions {
  /**
   * Optional custom hash function to produce the canonical fingerprint.
   * If omitted, {@link fnv1a64Hex} is used as default.
   */
  readonly hashFn?: HashFunction;

  /**
   * Specifies the ordered list of HTTP headers to consult
   * when extracting the client IP address from the request.
   *
   * Only include headers that your infrastructure guarantees to set and control;
   * do **not** include untrusted headers.
   */
  readonly ipHeaders?: readonly string[];

  /**
   * The IPv6 subnet prefix length to use when masking client IPv6 addresses.
   * Must be an integer from 1 to 128 (inclusive). Default: `56`.
   */
  readonly ipv6Subnet?: number;

  /**
   * Application-provided trusted actor identifier, such as a session ID,
   * user ID, API key, or other authenticated principal.
   * When non-empty after trimming, this will fully override any network-based identity
   * (i.e., fingerprinting will *not* mix actor and IP as anchors).
   */
  readonly actorId?: Optional<string>;

  /**
   * Optional, caller-defined, opaque logical namespace for further partitioning of fingerprints.
   * Value is trimmed and ignored if empty after trimming, making scope opt-in only.
   */
  readonly scope?: Optional<string>;
}

/**
 * Function interface for hashing a byte array and returning a hash string.
 *
 * Used to customize the fingerprinting hash algorithm.
 */
export type HashFunction = (input: Uint8Array) => string;

/**
 * Tuple type representing an IPv4 address as four octets.
 *
 * Each octet must be an integer in the 0–255 range.
 *
 * Example: `[192, 168, 0, 1]`
 */
export type Ipv4Tuple = [number, number, number, number];
