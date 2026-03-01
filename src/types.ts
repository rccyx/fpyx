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
  readonly parts: readonly string[];
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
 * Options to configure fingerprint generation.
 *
 * Controls inclusion of request properties and behavior of the hashing process.
 */
export interface FingerprintOptions {
  /**
   * If true, include the HTTP method (e.g., GET, POST) in the fingerprint.
   * 
   * GET /login and POST /login will yield different fingerprints.
   * Defaults to false (optional).
   */
  readonly includeMethod?: boolean;

  /**
   * If true, include the request URL pathname (e.g., /login) in the fingerprint.
   * 
   * /login and /dashboard will yield different fingerprints.
   * Defaults to false (optional).
   */
  readonly includePath?: boolean;

  /**
   * Custom hash function to use for fingerprint calculation.
   * 
   * Must be deterministic; receives the UTF-8 bytes of the fingerprint payload.
   * Defaults to internal FNV-1a 64-bit hash implementation.
   */
  readonly hashFn?: HashFunction;

  /**
   * List of headers (in priority order) to use for extracting the client IP address.
   * 
   * Only use headers set by your trusted edge proxy or load balancer. 
   * Do not include headers that may be supplied by clients directly.
   * The default is a platform-aware, secure list.
   */
  readonly ipHeaders?: readonly string[];

  /**
   * Function to normalize a URL path before fingerprinting.
   * 
   * Useful for bucket collapsing (e.g., transforming /users/123 to /users/:id).
   * Allows grouping similar endpoint requests that share only dynamic segments.
   */
  readonly pathNormalizer?: (path: string) => string;

  /**
   * IPv6 subnet prefix length for masking client IPv6 addresses.
   * 
   * - If specified (1–128), IPv6 addresses are masked to this prefix.
   * - If false, disables masking and uses the full address.
   * - If undefined, uses the default of /56 (recommended for most environments).
   * 
   * Masking reduces over-granularity due to IPv6 privacy extensions.
   * 
   * Typical allocations:
   *   /64  - single LAN (granular)
   *   /56  - residential (typical default)
   *   /48  - larger organization/site (coarser)
   */
  readonly ipv6Subnet?: number;
}


/**
 * Hash function type that takes UTF-8 bytes and returns a deterministic string digest.
 */
export type HashFunction = (input: Uint8Array) => string;
