/**
 * @see https://datatracker.ietf.org/doc/rfc9923/
 */
export const FNV_OFFSET_BASIS_64 = 0xcbf29ce484222325n;

/**
 * @see https://datatracker.ietf.org/doc/rfc9923/
 */
export const FNV_PRIME_64 = 0x100000001b3n;

/**
 * mask used to truncate bigint multiplication back to 64 bits.
 *
 * js bigint does unbounded precision, fnv-1a is defined over fixed-width unsigned integers.
 *
 * @see https://datatracker.ietf.org/doc/rfc9923/
 */
export const FNV_MASK_64 = 0xffffffffffffffffn;

/**
 * ordered list of common reverse-proxy headers that may carry the client ip.
 *
 * this list is about interoperability, not trust. you must ensure your edge overwrites
 * these headers, otherwise clients can spoof them.
 *
 * note: "forwarded" is the standardized header. "x-forwarded-for" is de facto.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7239
 */
export const DEFAULT_IP_HEADERS = [
  'cf-connecting-ip',
  'fastly-client-ip',
  'fly-client-ip',
  'true-client-ip',
  'forwarded',
  'x-forwarded-for',
  'x-real-ip',
] as const;

/**
 * tokens that frequently show up as placeholders in proxy chains.
 *
 * "unknown" is explicitly defined by rfc 7239 for forwarded.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc7239
 */
export const INVALID_IP_TOKENS = new Set(['', 'unknown', 'null', 'none']);
