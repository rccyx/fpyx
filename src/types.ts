export type Optional<T> = T | null;
export type Possible<T> = T | undefined;

/**
 * compact result returned by `fingerprint`.
 *
 * `hash` is derived from `parts.join('|')` hashed with the configured hash function.
 */
export interface FingerprintResult {
  readonly hash: string;
  readonly parts: readonly string[];
  readonly traits: FingerprintTraits;
}

/**
 * identity traits used to derive the fingerprint.
 *
 * invariant:
 * actorId and ip are mutually exclusive anchors.
 * if actorId is non-null, it is the anchor and ip is null.
 * otherwise ip is the anchor and actorId is null.
 */
export interface FingerprintTraits {
  readonly actorId: Optional<string>;
  readonly ip: Optional<string>;
  readonly method: Optional<string>;
  readonly path: Optional<string>;
}

/**
 * data source accepted by `fingerprint`.
 *
 * supports fetch request objects and lightweight objects for edge runtimes.
 */
export type FingerprintSource =
  | Request
  | {
      readonly headers: Headers;
      readonly method?: string;
      readonly url?: string | URL;
    };

/**
 * options for identity derivation.
 *
 * the core decision is anchor precedence:
 * provide `actorId` when you have a trusted authenticated identity.
 * otherwise fpyx anchors on the client ip bucket.
 */
export interface FingerprintOptions {
  /**
   * include the http method in the key as a scoping dimension.
   */
  readonly includeMethod?: boolean;

  /**
   * include the url pathname in the key as a scoping dimension.
   */
  readonly includePath?: boolean;

  /**
   * override the hash function used to hash the payload bytes.
   *
   * must be deterministic.
   */
  readonly hashFn?: HashFunction;

  /**
   * ordered list of headers to consult for client ip extraction.
   *
   * only include headers that your edge overwrites.
   */
  readonly ipHeaders?: readonly string[];

  /**
   * normalize a pathname before it is included when `includePath` is enabled.
   */
  readonly pathNormalizer?: (path: string) => string;

  /**
   * ipv6 subnet prefix length for masking.
   *
   * if undefined, defaults to /56.
   */
  readonly ipv6Subnet?: number;

  /**
   * trusted caller-provided actor identity (session id, api key, user id).
   *
   * if present and non-empty after trim, it fully replaces ip anchoring.
   * fpyx will not concatenate this with ip.
   */
  readonly actorId?: Optional<string>;
}

export type HashFunction = (input: Uint8Array) => string;
