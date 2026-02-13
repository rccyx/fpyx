export type Optional<T> = T | null;
export type Possible<T> = T | undefined;

/**
 * Compact result returned by the fingerprint function.
 */
export interface FingerprintResult {
  /**
   * Deterministic 64-bit FNV-1a hexadecimal digest.
   */
  readonly hash: string;
  /**
   * Individual payload segments (e.g. `ip:198.51.100.7`).
   */
  readonly parts: ReadonlyArray<string>;
  /**
   * Parsed request traits used to derive the fingerprint.
   */
  readonly traits: FingerprintTraits;
}

/**
 * Structured request traits extracted from headers and request metadata.
 */
export interface FingerprintTraits {
  readonly ip: Optional<string>;
  readonly userAgent: Optional<string>;
  readonly acceptLanguage: Optional<string>;
  readonly method: Optional<string>;
  readonly path: Optional<string>;
}

/**
 * Data source accepted by fingerprint function. Works with Fetch-standard Request
 * objects and with lightweight header-only inputs.
 */
export type FingerprintSource =
  | Request
  | {
      readonly headers: Headers;
      readonly method?: string;
      readonly url?: string | URL;
    };

/**
 * Optional knobs to control how fingerprints are produced.
 */
export interface FingerprintOptions {
  /**
   * Whether to scope fingerprints per HTTP method. Defaults to `false`.
   */
  readonly includeMethod?: boolean;
  /**
   * Whether to scope fingerprints per URL path. Defaults to `false`.
   */
  readonly includePath?: boolean;
  /**
   * Override the hashing function. Must return a deterministic string digest.
   */
  readonly hashFn?: HashFunction;
  /**
   * Header precedence list for trusted client IP detection.
   */
  readonly ipHeaders?: ReadonlyArray<string>;
  /**
   * Optional normalizer for the extracted URL path (e.g. to collapse IDs).
   */
  readonly pathNormalizer?: (path: string) => string;
}

/**
 * Hash function type that takes UTF-8 bytes and returns a deterministic string digest.
 */
export type HashFunction = (input: Uint8Array) => string;
