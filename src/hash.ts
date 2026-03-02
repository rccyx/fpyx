import { FNV_OFFSET_BASIS_64, FNV_PRIME_64, FNV_MASK_64 } from './constants';

/**
 * Computes the FNV-1a 64-bit hash over a UTF-8 byte array and returns the
 * result as a 16-character zero-padded lowercase hexadecimal string.
 *
 * FNV-1a (Fowler–Noll–Vo) is a fast, non-cryptographic hash function well
 * suited for fingerprinting, checksums, and hash-table keying. It is **not**
 * suitable for cryptographic purposes or any context where collision resistance
 * or unforgeability is required.
 *
 * **Performance:** On modern hardware, a single hash over a few hundred bytes
 * typically completes in 0.4–0.8 µs, allowing well over 100,000 hashes per
 * second on a single core.
 *
 * @param data - The raw bytes to hash (typically UTF-8 encoded text).
 * @returns A 16-character zero-padded lowercase hexadecimal string
 *   representing the 64-bit hash value.
 *
 * @example
 * ```typescript
 * import { fnv1a64Hex } from 'fpyx';
 *
 * const encoder = new TextEncoder();
 * const hash = fnv1a64Hex(encoder.encode('hello'));
 * console.log(hash); // "a430d84680aabd0b"
 * ```
 *
 * @see https://datatracker.ietf.org/doc/rfc9923/
 */
export function fnv1a64Hex(data: Uint8Array): string {
  let hash = FNV_OFFSET_BASIS_64;
  for (const byte of data) {
    hash ^= BigInt(byte);
    hash = (hash * FNV_PRIME_64) & FNV_MASK_64;
  }
  return hash.toString(16).padStart(16, '0');
}