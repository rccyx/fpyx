import type { FingerprintTraits } from './types';

/**
 * anchor is explicit and non-mixed (actor OR ip).
 * scope, if present, is appended only as key-space partitioning.
 */
export function buildParts(traits: FingerprintTraits): readonly string[] {
  const segments: string[] = [];

  if (traits.actorId !== null) {
    segments.push(`actor:${traits.actorId}`);
  } else {
    segments.push(`ip:${traits.ip ?? ''}`);
  }

  if (traits.scope !== null) {
    segments.push(`scope:${traits.scope}`);
  }

  return segments;
}
