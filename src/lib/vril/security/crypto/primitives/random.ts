/**
 * Vril.js — Browser-native cryptographic randomness.
 *
 * All entropy for cryptographic operations must come from crypto.getRandomValues.
 */

function getCrypto(): Crypto {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('[VRIL Random] crypto.getRandomValues is required for cryptographic randomness');
  }
  return crypto;
}

const GET_RANDOM_VALUES_MAX_BYTES = 65_536;

/**
 * Fill an existing Uint8Array with cryptographically secure random bytes.
 *
 * The input array is mutated in-place and returned for convenience. Large
 * arrays are filled in chunks because browsers limit getRandomValues() to
 * 65,536 bytes per call.
 */
export function fillRandomBytes(bytes: Uint8Array): Uint8Array {
  const runtimeCrypto = getCrypto();
  for (let offset = 0; offset < bytes.byteLength; offset += GET_RANDOM_VALUES_MAX_BYTES) {
    const end = Math.min(offset + GET_RANDOM_VALUES_MAX_BYTES, bytes.byteLength);
    runtimeCrypto.getRandomValues(bytes.subarray(offset, end));
  }
  return bytes;
}

/** Allocate and return cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new Error('[VRIL Random] length must be a non-negative safe integer');
  }
  return fillRandomBytes(new Uint8Array(length));
}
