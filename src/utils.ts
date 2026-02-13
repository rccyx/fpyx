/**
 * Utility functions for fingerprinting.
 *
 * @packageDocumentation
 */

import type {
  FingerprintSource,
  FingerprintTraits,
  Optional,
  Possible,
} from './types';

/**
 * Safely trims a string or returns null if empty.
 *
 * @param value - The value to trim.
 * @returns The trimmed string or null.
 * @internal
 */
export function safeTrim(value: Optional<string>): Optional<string> {
  if (value === null) {
    return null;
  }

  const trimmed = value.trim();
  return trimmed === '' ? null : trimmed;
}

/**
 * Type guard to check if a source is a Request-like object.
 *
 * @param value - The source to check.
 * @returns True if the source is Request-like.
 * @internal
 */
export function isRequestLike(value: FingerprintSource): value is Request {
  return (
    typeof (value as Request).method === 'string' &&
    typeof (value as Request).url === 'string'
  );
}

/**
 * Extracts the HTTP method from a fingerprint source.
 *
 * @param source - The fingerprint source.
 * @returns The HTTP method or null.
 * @internal
 */
export function extractMethod(source: FingerprintSource): Optional<string> {
  if (isRequestLike(source)) {
    return source.method ?? null;
  }

  return source.method ?? null;
}

/**
 * Extracts and optionally normalizes the URL path from a fingerprint source.
 *
 * @param urlValue - The URL value to extract from.
 * @param normalizer - Optional path normalizer function.
 * @returns The extracted/normalized path or null.
 * @internal
 */
export function extractPath(
  urlValue: Possible<URL>,
  normalizer?: (path: string) => string
): Optional<string> {
  if (urlValue === undefined) {
    return null;
  }

  let path: Optional<string> = null;
  if (urlValue instanceof URL) {
    path = urlValue.pathname;
  } else {
    try {
      const parsed = new URL(urlValue, 'http://localhost');
      path = parsed.pathname;
    } catch {
      path = null;
    }
  }

  if (path === null) {
    return null;
  }

  const normalized = normalizer?.(path) ?? path;
  return normalized;
}

/**
 * Builds the payload parts array from fingerprint traits.
 *
 * @param traits - The extracted traits.
 * @returns An array of payload segments.
 * @internal
 */
export function buildParts(traits: FingerprintTraits): ReadonlyArray<string> {
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
