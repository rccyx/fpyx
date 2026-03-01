import type {
  FingerprintSource,
  FingerprintTraits,
  Optional,
  Possible,
} from './types';

export function isRequestLike(value: FingerprintSource): value is Request {
  return (
    typeof (value as Request).method === 'string' &&
    typeof (value as Request).url === 'string'
  );
}

export function extractMethod(source: FingerprintSource): Optional<string> {
  if (isRequestLike(source)) return source.method ?? null;
  return source.method ?? null;
}

/**
 * extract pathname from a url, optionally normalized by caller.
 */
export function extractPath(
  urlValue: Possible<string | URL>,
  normalizer?: (path: string) => string
): Optional<string> {
  if (urlValue === undefined) return null;

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

  if (path === null) return null;

  return normalizer?.(path) ?? path;
}

/**
 * anchor is explicit and non-mixed (actor OR ip).
 * method and path, if present, are appended only as key-space partitioning.
 */
export function buildParts(traits: FingerprintTraits): readonly string[] {
  const segments: string[] = [];

  if (traits.actorId !== null) {
    segments.push(`actor:${traits.actorId}`);
  } else {
    segments.push(`ip:${traits.ip ?? ''}`);
  }

  if (traits.method !== null) {
    segments.push(`method:${traits.method}`);
  }

  if (traits.path !== null) {
    segments.push(`path:${traits.path}`);
  }

  return segments;
}
