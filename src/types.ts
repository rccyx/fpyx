import { SizedTuple } from "typyx";

export type Optional<T> = T | null;
export type Possible<T> = T | undefined;

/**
 * The result returned by {@link fingerprint}.
 *
 * `hash` is produced by hashing `parts.join('|')` with the configured hash
 * function (default: {@link fnv1a64Hex}).
 */
export interface FingerprintResult {
  readonly hash: string;
  readonly parts: readonly string[];
  readonly traits: FingerprintTraits;
}

/**
 * The resolved identity traits used to derive the fingerprint.
 *
 * **Invariant:** `actorId` and `ip` are mutually exclusive identity anchors.
 * When `actorId` is non-null it is the sole anchor and `ip` is `null`.
 * When `actorId` is `null`, `ip` is the anchor (and may itself be `null` if
 * no valid IP could be extracted from the request headers).
 */
export interface FingerprintTraits {
  readonly actorId: Optional<string>;
  readonly ip: Optional<string>;
  readonly method: Optional<string>;
  readonly path: Optional<string>;
}

/**
 * The request data source accepted by {@link fingerprint}.
 *
 * Accepts a standard Fetch API `Request` object, or a lightweight plain
 * object carrying only the fields that `fingerprint` needs. The plain-object
 * form is useful in edge runtimes where constructing a full `Request` is
 * unnecessary.
 */
export type FingerprintSource =
  | Request
  | {
      readonly headers: Headers;
      readonly method?: string;
      readonly url?: string | URL;
    };

/**
 * Configuration options for {@link fingerprint}.
 *
 * All fields are optional. When omitted, `fingerprint` anchors identity on
 * the client IP extracted from {@link DEFAULT_IP_HEADERS}, hashed with
 * {@link fnv1a64Hex}, with no method or path scoping and IPv6 masked to `/56`.
 */
export interface FingerprintOptions {
  /**
   * When `true`, the HTTP method is appended to the key as a scoping
   * dimension, producing distinct fingerprints for different methods on the
   * same identity (e.g. `GET /users` vs. `POST /users`).
   */
  readonly includeMethod?: boolean;

  /**
   * When `true`, the URL pathname is appended to the key as a scoping
   * dimension. Use `pathNormalizer` to collapse dynamic segments (e.g. user
   * IDs) into a consistent pattern before they are included.
   */
  readonly includePath?: boolean;

  /**
   * Overrides the hash function used to hash the assembled key parts.
   *
   * The function receives a `Uint8Array` of UTF-8 encoded bytes and must
   * return a deterministic string. The default is {@link fnv1a64Hex}.
   */
  readonly hashFn?: HashFunction;

  /**
   * Overrides the ordered list of headers consulted when extracting the client
   * IP address.
   *
   * Only include headers that your edge proxy is guaranteed to overwrite on
   * every inbound request. See {@link DEFAULT_IP_HEADERS} for the built-in
   * precedence list.
   */
  readonly ipHeaders?: readonly string[];

  /**
   * A function applied to the URL pathname before it is included in the key.
   * Only called when `includePath` is `true`.
   *
   * Use this to normalize dynamic route segments into stable patterns, for
   * example replacing numeric IDs with `:id` so that
   * `/users/123` and `/users/456` map to the same rate-limit bucket.
   */
  readonly pathNormalizer?: (path: string) => string;

  /**
   * The IPv6 subnet prefix length used when masking the client IP bucket.
   *
   * Must be an integer in the range `[1, 128]`. Defaults to `56`.
   *
   * A `/56` default reflects common residential ISP allocation granularity,
   * grouping all addresses within a typical household prefix into one bucket
   * regardless of IPv6 privacy extensions.
   */
  readonly ipv6Subnet?: number;

  /**
   * A trusted, caller-provided actor identity such as a session ID, user ID,
   * or API key.
   *
   * When present and non-empty after trimming, this value fully replaces
   * network-based identity. No IP address is extracted or included in the
   * fingerprint. The two anchor types are never mixed.
   */
  readonly actorId?: Optional<string>;
}

/** A function that hashes a `Uint8Array` and returns a string. */
export type HashFunction = (input: Uint8Array) => string;

export type Ipv4Tuple = SizedTuple<number, 4>;
