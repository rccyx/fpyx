import { FNV_OFFSET_BASIS_64, FNV_PRIME_64, FNV_MASK_64 } from './constants';

/**
 * Computes the FNV-1a 64-bit hash over UTF-8 input, returned as a 16-character lowercase hex string.
 *
 * FNV-1a (Fowler-Noll-Vo) is a fast, non-cryptographic hash function suitable for hash tables,
 * checksums, and fingerprinting. It is **not** suitable for cryptographic purposes or security-sensitive
 * applications where collision resistance or unforgeability is required.
 *
 * **Performance:** FNV-1a is extremely fast, typically computing a hash in 0.4–0.8 microseconds for
 * a few hundred bytes on modern CPUs. A single CPU core can easily compute 100,000+ hashes per second.
 *
 * @param data - The UTF-8 encoded input to hash.
 * @returns A 16-character zero-padded lowercase hexadecimal string representing the 64-bit hash.
 *
 * @example
 * ```typescript
 * import { fnv1a64Hex } from 'fpyx';
 *
 * const encoder = new TextEncoder();
 * const hash = fnv1a64Hex(encoder.encode('hello'));
 * console.log(hash); // "a430d84680aabd0b"
 * ```
 */
export function fnv1a64Hex(data: Uint8Array): string {
  let hash = FNV_OFFSET_BASIS_64;
  for (const byte of data) {
    hash ^= BigInt(byte);
    hash = (hash * FNV_PRIME_64) & FNV_MASK_64;
  }
  return hash.toString(16).padStart(16, '0');
}
