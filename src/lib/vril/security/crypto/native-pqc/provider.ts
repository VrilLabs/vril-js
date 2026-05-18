import {
  ml_dsa65,
  ml_dsa87,
  ml_kem1024,
  ml_kem768,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_256f,
} from './noble-post-quantum.js';
import type { KEMResult, PQCAlgorithm, PQCKeyPair, PQCProvider, PQCValidationEvidence, SignatureResult } from '../pqc';

type NativeKEM = {
  keygen: () => { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate: (publicKey: Uint8Array) => { cipherText: Uint8Array; sharedSecret: Uint8Array };
  decapsulate: (cipherText: Uint8Array, secretKey: Uint8Array) => Uint8Array;
};

type NativeSigner = {
  keygen: () => { publicKey: Uint8Array; secretKey: Uint8Array };
  sign: (message: Uint8Array, secretKey: Uint8Array) => Uint8Array;
  verify: (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => boolean;
};

const KEM_ALGORITHMS = {
  'ML-KEM-768': ml_kem768 as NativeKEM,
  'ML-KEM-1024': ml_kem1024 as NativeKEM,
} satisfies Partial<Record<PQCAlgorithm, NativeKEM>>;

const SIGNATURE_ALGORITHMS = {
  'ML-DSA-65': ml_dsa65 as NativeSigner,
  'ML-DSA-87': ml_dsa87 as NativeSigner,
  'SLH-DSA-SHA2-128s': slh_dsa_sha2_128s as NativeSigner,
  'SLH-DSA-SHA2-256f': slh_dsa_sha2_256f as NativeSigner,
} satisfies Partial<Record<PQCAlgorithm, NativeSigner>>;

const FIPS_STANDARD: Partial<Record<PQCAlgorithm, PQCValidationEvidence['standard']>> = {
  'ML-KEM-768': 'FIPS 203',
  'ML-KEM-1024': 'FIPS 203',
  'ML-DSA-65': 'FIPS 204',
  'ML-DSA-87': 'FIPS 204',
  'SLH-DSA-SHA2-128s': 'FIPS 205',
  'SLH-DSA-SHA2-256f': 'FIPS 205',
};

function isNativeKEMAlgorithm(algorithm: PQCAlgorithm): algorithm is keyof typeof KEM_ALGORITHMS {
  return algorithm in KEM_ALGORITHMS;
}

function isNativeSignatureAlgorithm(algorithm: PQCAlgorithm): algorithm is keyof typeof SIGNATURE_ALGORITHMS {
  return algorithm in SIGNATURE_ALGORITHMS;
}

function unsupportedNativeAlgorithm(algorithm: PQCAlgorithm): Error {
  return new Error(`[VRIL Native PQC] Unsupported native PQC algorithm: ${algorithm}`);
}

export const nativePQCProvider: PQCProvider = {
  name: 'Vril.js Native Active Surface PQC',

  getValidationEvidence(algorithm: PQCAlgorithm): PQCValidationEvidence | null {
    const standard = FIPS_STANDARD[algorithm];
    if (!standard) return null;
    return {
      algorithm,
      standard,
      moduleName: 'Vril.js native Active Surface PQC bundle (@noble/post-quantum@0.6.1 derived)',
      providerName: 'Vril.js',
      standardsConformant: true,
    };
  },

  async generateKeyPair(algorithm: PQCAlgorithm): Promise<PQCKeyPair> {
    if (isNativeKEMAlgorithm(algorithm)) {
      const keyPair = KEM_ALGORITHMS[algorithm].keygen();
      return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.secretKey,
        algorithm,
        native: true,
        createdAt: Date.now(),
      };
    }

    if (isNativeSignatureAlgorithm(algorithm)) {
      const keyPair = SIGNATURE_ALGORITHMS[algorithm].keygen();
      return {
        publicKey: keyPair.publicKey,
        privateKey: keyPair.secretKey,
        algorithm,
        native: true,
        createdAt: Date.now(),
      };
    }

    throw unsupportedNativeAlgorithm(algorithm);
  },

  async encapsulate(publicKey: Uint8Array, algorithm: PQCAlgorithm): Promise<KEMResult> {
    if (!isNativeKEMAlgorithm(algorithm)) throw unsupportedNativeAlgorithm(algorithm);
    const result = KEM_ALGORITHMS[algorithm].encapsulate(publicKey);
    return {
      ciphertext: result.cipherText,
      sharedSecret: result.sharedSecret,
      algorithm,
      native: true,
    };
  },

  async decapsulate(ciphertext: Uint8Array, privateKey: Uint8Array, algorithm: PQCAlgorithm): Promise<KEMResult> {
    if (!isNativeKEMAlgorithm(algorithm)) throw unsupportedNativeAlgorithm(algorithm);
    return {
      ciphertext,
      sharedSecret: KEM_ALGORITHMS[algorithm].decapsulate(ciphertext, privateKey),
      algorithm,
      native: true,
    };
  },

  async sign(message: Uint8Array, privateKey: Uint8Array, algorithm: PQCAlgorithm): Promise<SignatureResult> {
    if (!isNativeSignatureAlgorithm(algorithm)) throw unsupportedNativeAlgorithm(algorithm);
    return {
      signature: SIGNATURE_ALGORITHMS[algorithm].sign(message, privateKey),
      algorithm,
      native: true,
      signedAt: Date.now(),
    };
  },

  async verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array, algorithm: PQCAlgorithm): Promise<boolean> {
    if (!isNativeSignatureAlgorithm(algorithm)) throw unsupportedNativeAlgorithm(algorithm);
    return SIGNATURE_ALGORITHMS[algorithm].verify(signature, message, publicKey);
  },
};
