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

/** Fill an existing Uint8Array with cryptographically secure random bytes. */
export function fillRandomBytes(bytes: Uint8Array): Uint8Array {
  getCrypto().getRandomValues(bytes);
  return bytes;
}

/** Allocate and return cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 0) {
    throw new Error('[VRIL Random] length must be a non-negative safe integer');
  }
  return fillRandomBytes(new Uint8Array(length));
}
