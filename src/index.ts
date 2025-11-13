/**
 * A hardened request fingerprint helper for anonymous rate limiting buckets.
 *
 * It combines coarse request traits (trusted client IP header, User-Agent, Accept-Language,
 * and optional method + path) into a deterministic UTF-8 payload, then hashes it with
 * FNV-1a 64. The output is a compact identifier suitable for rate limiting keys.
 *
 * This does not provide identity, tracking, or authentication. Pair with server-side
 * quotas and trusted proxy configuration as recommended by OWASP API4:2023.
 *
 * @packageDocumentation
 */

const FNV_OFFSET_BASIS_64 = 0xcbf29ce484222325n;
const FNV_PRIME_64 = 0x100000001b3n;
const FNV_MASK_64 = 0xffffffffffffffffn;

/** Default precedence of client IP headers. Override to match your trusted proxy chain. */
export const DEFAULT_IP_HEADERS: readonly string[] = [
  'cf-connecting-ip',
  'fastly-client-ip',
  'fly-client-ip',
  'true-client-ip',
  'forwarded',
  'x-forwarded-for',
  'x-real-ip',
] as const;

const INVALID_IP_TOKENS = new Set(['', 'unknown', 'null', 'none']);
const textEncoder = new TextEncoder();

type HashFunction = (input: Uint8Array) => string;

/**
 * Compact result returned by {@link fingerprintRequest}.
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
  readonly ip: string | null;
  readonly userAgent: string | null;
  readonly acceptLanguage: string | null;
  readonly method: string | null;
  readonly path: string | null;
}

/**
 * Data source accepted by {@link fingerprintRequest}. Works with Fetch-standard Request
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
 * FNV-1a 64-bit hash over UTF-8 input, serialized as a zero-padded lowercase hex string.
 */
export function fnv1a64Hex(data: Uint8Array): string {
  let hash = FNV_OFFSET_BASIS_64;
  for (const byte of data) {
    hash ^= BigInt(byte);
    hash = (hash * FNV_PRIME_64) & FNV_MASK_64;
  }
  return hash.toString(16).padStart(16, '0');
}

/**
 * Derive a compact, anonymous rate limiting fingerprint from Fetch-style request data.
 *
 * @param source - The Fetch Request or request-like data to fingerprint.
 * @param options - Optional tweaks for headers, method/path scoping, or hashing.
 * @returns A stable fingerprint hash plus the contributing request traits.
 */
export function fingerprintRequest(
  source: FingerprintSource,
  options?: FingerprintOptions
): FingerprintResult {
  const headers = source.headers;
  const traits: FingerprintTraits = {
    ip: extractClientIp(headers, options?.ipHeaders ?? DEFAULT_IP_HEADERS),
    userAgent: safeTrim(headers.get('user-agent')),
    acceptLanguage: safeTrim(headers.get('accept-language')),
    method: options?.includeMethod === true ? extractMethod(source) : null,
    path:
      options?.includePath === true
        ? extractPath(
            isRequestLike(source) ? source.url : source.url,
            options?.pathNormalizer
          )
        : null,
  };

  const parts = buildParts(traits);
  const payload = textEncoder.encode(parts.join('|'));
  const hashFn: HashFunction = options?.hashFn ?? fnv1a64Hex;
  return {
    hash: hashFn(payload),
    parts,
    traits,
  };
}

function buildParts(traits: FingerprintTraits): ReadonlyArray<string> {
  const segments: string[] = [
    `ip:${traits.ip ?? ''}`,
    `ua:${traits.userAgent ?? ''}`,
    `al:${traits.acceptLanguage ?? ''}`,
  ];

  if (traits.method !== null) {
    segments.push(`method:${traits.method}`);
  }

  if (traits.path !== null) {
    segments.push(`path:${traits.path}`);
  }

  return segments;
}

function extractMethod(source: FingerprintSource): string | null {
  if (isRequestLike(source)) {
    return source.method ?? null;
  }

  return source.method ?? null;
}

function extractPath(
  urlValue: string | URL | undefined,
  normalizer?: (path: string) => string
): string | null {
  if (urlValue === undefined) {
    return null;
  }

  let path: string | null = null;
  if (urlValue instanceof URL) {
    path = urlValue.pathname;
  } else {
    try {
      const parsed = new URL(urlValue, 'http://localhost');
      path = parsed.pathname;
    } catch {
      path = urlValue.startsWith('/') ? urlValue : null;
    }
  }

  if (path === null) {
    return null;
  }

  const normalized = normalizer?.(path) ?? path;
  return normalized;
}

function extractClientIp(
  headers: Headers,
  precedence: ReadonlyArray<string>
): string | null {
  for (const headerName of precedence) {
    const value = headers.get(headerName);
    if (value === null) {
      continue;
    }

    const normalizedName = headerName.toLowerCase();
    if (normalizedName === 'forwarded') {
      const parsed = parseForwarded(value);
      const ip = normalizeIpCandidate(parsed);
      if (ip !== null) {
        return ip;
      }
      continue;
    }

    const candidate =
      normalizedName === 'x-forwarded-for'
        ? takeFirstListEntry(value)
        : value.trim();
    const ip = normalizeIpCandidate(candidate);
    if (ip !== null) {
      return ip;
    }
  }

  return null;
}

function parseForwarded(value: string): string | null {
  const entries = value.split(',');
  for (const entry of entries) {
    const directives = entry.trim().split(';');
    for (const directive of directives) {
      const [rawKey, rawValue] = directive.split('=');
      if (rawKey === undefined || rawValue === undefined) {
        continue;
      }

      if (rawKey.trim().toLowerCase() !== 'for') {
        continue;
      }

      const cleaned = cleanForwardedIdentifier(rawValue.trim());
      if (cleaned !== null) {
        return cleaned;
      }
    }
  }

  return null;
}

function cleanForwardedIdentifier(value: string): string | null {
  const unquoted =
    value.startsWith('"') && value.endsWith('"') && value.length >= 2
      ? value.slice(1, -1)
      : value;
  const trimmed = unquoted.trim();
  if (trimmed === '') {
    return null;
  }

  if (trimmed.startsWith('[')) {
    const closingIndex = trimmed.indexOf(']');
    if (closingIndex > 1) {
      return trimmed.slice(1, closingIndex);
    }
    return null;
  }

  if (trimmed.includes(':') && trimmed.includes('.')) {
    const colonIndex = trimmed.lastIndexOf(':');
    if (colonIndex > -1) {
      return trimmed.slice(0, colonIndex);
    }
  }

  return trimmed;
}

function takeFirstListEntry(value: string): string {
  const [first = ''] = value.split(',');
  return first.trim();
}

function normalizeIpCandidate(value: string | null): string | null {
  if (value === null) {
    return null;
  }

  const trimmed = value.trim();
  if (trimmed === '') {
    return null;
  }

  if (INVALID_IP_TOKENS.has(trimmed.toLowerCase())) {
    return null;
  }

  if (trimmed.includes(':') && trimmed.includes('.')) {
    const colonIndex = trimmed.lastIndexOf(':');
    if (colonIndex > -1) {
      return trimmed.slice(0, colonIndex);
    }
  }

  return trimmed;
}

function safeTrim(value: string | null): string | null {
  if (value === null) {
    return null;
  }

  const trimmed = value.trim();
  return trimmed === '' ? null : trimmed;
}

function isRequestLike(value: FingerprintSource): value is Request {
  return (
    typeof (value as Request).method === 'string' &&
    typeof (value as Request).url === 'string'
  );
}
