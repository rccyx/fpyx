/** FNV-1a 64-bit offset basis constant. */
export const FNV_OFFSET_BASIS_64 = 0xcbf29ce484222325n;

/** FNV-1a 64-bit prime constant. */
export const FNV_PRIME_64 = 0x100000001b3n;

/** FNV-1a 64-bit mask for overflow handling. */
export const FNV_MASK_64 = 0xffffffffffffffffn;

/** Default precedence of client IP headers. Override to match your trusted proxy chain. */
export const DEFAULT_IP_HEADERS = [
  'cf-connecting-ip',
  'fastly-client-ip',
  'fly-client-ip',
  'true-client-ip',
  'forwarded',
  'x-forwarded-for',
  'x-real-ip',
] as const;

/** Invalid IP tokens that should be treated as null. */
export const INVALID_IP_TOKENS = new Set(['', 'unknown', 'null', 'none']);
