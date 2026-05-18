/**
 * Vril.js — Clean-room FIPS PQC Provider.
 *
 * Bridges the clean-room FIPS 203/204/205 engine into the Vril.js PQCProvider
 * interface. All operations are performed synchronously in JavaScript using
 * zero external dependencies (only in-tree FIPS 202/180-4 primitives).
 *
 * This provider covers every algorithm from FIPS 203, FIPS 204, and FIPS 205.
 */

import type { KEMResult, PQCAlgorithm, PQCKeyPair, PQCProvider, PQCValidationEvidence, SignatureResult } from './pqc';
import { mlKEMKeyGen, mlKEMEncaps, mlKEMDecaps, type MLKEMVariant } from './fips203';
import { mlDSAKeyGen, mlDSASign, mlDSAVerify, type MLDSAVariant } from './fips204';
import { slhDSAKeyGen, slhDSASign, slhDSAVerify, type SLHDSAVariant } from './fips205';

// ─── Algorithm routing tables ─────────────────────────────────────────────────

const FIPS203_ALGORITHMS: ReadonlySet<string> = new Set([
  'ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024',
]);

const FIPS204_ALGORITHMS: ReadonlySet<string> = new Set([
  'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87',
]);

const FIPS205_ALGORITHMS: ReadonlySet<string> = new Set([
  'SLH-DSA-SHAKE-128s', 'SLH-DSA-SHAKE-128f',
  'SLH-DSA-SHAKE-192s', 'SLH-DSA-SHAKE-192f',
  'SLH-DSA-SHAKE-256s', 'SLH-DSA-SHAKE-256f',
  'SLH-DSA-SHA2-128s',  'SLH-DSA-SHA2-128f',
  'SLH-DSA-SHA2-192s',  'SLH-DSA-SHA2-192f',
  'SLH-DSA-SHA2-256s',  'SLH-DSA-SHA2-256f',
]);

const FIPS_STANDARD_MAP: Partial<Record<string, PQCValidationEvidence['standard']>> = {
  'ML-KEM-512':  'FIPS 203', 'ML-KEM-768':  'FIPS 203', 'ML-KEM-1024': 'FIPS 203',
  'ML-DSA-44':   'FIPS 204', 'ML-DSA-65':   'FIPS 204', 'ML-DSA-87':   'FIPS 204',
  'SLH-DSA-SHAKE-128s': 'FIPS 205', 'SLH-DSA-SHAKE-128f': 'FIPS 205',
  'SLH-DSA-SHAKE-192s': 'FIPS 205', 'SLH-DSA-SHAKE-192f': 'FIPS 205',
  'SLH-DSA-SHAKE-256s': 'FIPS 205', 'SLH-DSA-SHAKE-256f': 'FIPS 205',
  'SLH-DSA-SHA2-128s':  'FIPS 205', 'SLH-DSA-SHA2-128f':  'FIPS 205',
  'SLH-DSA-SHA2-192s':  'FIPS 205', 'SLH-DSA-SHA2-192f':  'FIPS 205',
  'SLH-DSA-SHA2-256s':  'FIPS 205', 'SLH-DSA-SHA2-256f':  'FIPS 205',
};

function unsupported(algorithm: PQCAlgorithm): Error {
  return new Error(`[VRIL FIPS PQC] Unsupported algorithm: ${algorithm}`);
}

// ─── Provider implementation ──────────────────────────────────────────────────

/**
 * Clean-room FIPS 203/204/205 PQC provider.
 *
 * Register this provider with the PQCHandler to replace the noble-post-quantum
 * backend with a fully in-tree, zero-dependency FIPS implementation.
 *
 * @example
 * ```ts
 * import { pqc } from '@/lib/vril/security';
 * import { fipsPQCProvider } from '@/lib/vril/security/crypto/fips-provider';
 * pqc.registerProvider(fipsPQCProvider);
 * ```
 */
export const fipsPQCProvider: PQCProvider = {
  name: 'Vril.js Clean-room FIPS 203/204/205 PQC Engine',

  getValidationEvidence(algorithm: PQCAlgorithm): PQCValidationEvidence | null {
    const standard = FIPS_STANDARD_MAP[algorithm];
    if (!standard) return null;
    return {
      algorithm,
      standard,
      moduleName: 'Vril.js clean-room FIPS 203/204/205 engine (zero-dependency, in-tree)',
      providerName: 'VrilLabs',
      standardsConformant: true,
    };
  },

  async generateKeyPair(algorithm: PQCAlgorithm): Promise<PQCKeyPair> {
    // native:true signals a Vril.js built-in implementation (not a platform Web Crypto call)
    if (FIPS203_ALGORITHMS.has(algorithm)) {
      const { ek, dk } = mlKEMKeyGen(algorithm as MLKEMVariant);
      return { publicKey: ek, privateKey: dk, algorithm, native: true, createdAt: Date.now() };
    }
    if (FIPS204_ALGORITHMS.has(algorithm)) {
      const { pk, sk } = mlDSAKeyGen(algorithm as MLDSAVariant);
      return { publicKey: pk, privateKey: sk, algorithm, native: true, createdAt: Date.now() };
    }
    if (FIPS205_ALGORITHMS.has(algorithm)) {
      const { pk, sk } = slhDSAKeyGen(algorithm as SLHDSAVariant);
      return { publicKey: pk, privateKey: sk, algorithm, native: true, createdAt: Date.now() };
    }
    throw unsupported(algorithm);
  },

  async encapsulate(publicKey: Uint8Array, algorithm: PQCAlgorithm): Promise<KEMResult> {
    if (!FIPS203_ALGORITHMS.has(algorithm)) throw unsupported(algorithm);
    const { sharedSecret, ciphertext } = mlKEMEncaps(publicKey, algorithm as MLKEMVariant);
    return { ciphertext, sharedSecret, algorithm, native: true };
  },

  async decapsulate(ciphertext: Uint8Array, privateKey: Uint8Array, algorithm: PQCAlgorithm): Promise<KEMResult> {
    if (!FIPS203_ALGORITHMS.has(algorithm)) throw unsupported(algorithm);
    const sharedSecret = mlKEMDecaps(privateKey, ciphertext, algorithm as MLKEMVariant);
    return { ciphertext, sharedSecret, algorithm, native: true };
  },

  async sign(message: Uint8Array, privateKey: Uint8Array, algorithm: PQCAlgorithm): Promise<SignatureResult> {
    if (FIPS204_ALGORITHMS.has(algorithm)) {
      const { signature } = mlDSASign(privateKey, message, algorithm as MLDSAVariant);
      return { signature, algorithm, native: true, signedAt: Date.now() };
    }
    if (FIPS205_ALGORITHMS.has(algorithm)) {
      const { signature } = slhDSASign(privateKey, message, algorithm as SLHDSAVariant);
      return { signature, algorithm, native: true, signedAt: Date.now() };
    }
    throw unsupported(algorithm);
  },

  async verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array, algorithm: PQCAlgorithm): Promise<boolean> {
    if (FIPS204_ALGORITHMS.has(algorithm)) {
      return mlDSAVerify(publicKey, message, signature, algorithm as MLDSAVariant);
    }
    if (FIPS205_ALGORITHMS.has(algorithm)) {
      return slhDSAVerify(publicKey, message, signature, algorithm as SLHDSAVariant);
    }
    throw unsupported(algorithm);
  },
};
