export const FNV_OFFSET_BASIS_64 = 0xcbf29ce484222325n;

export const FNV_PRIME_64 = 0x100000001b3n;

export const FNV_MASK_64 = 0xffffffffffffffffn;

export const DEFAULT_IP_HEADERS = [
  'cf-connecting-ip',
  'fastly-client-ip',
  'fly-client-ip',
  'true-client-ip',
  'forwarded',
  'x-forwarded-for',
  'x-real-ip',
] as const;

export const INVALID_IP_TOKENS = new Set(['', 'unknown', 'null', 'none']);
