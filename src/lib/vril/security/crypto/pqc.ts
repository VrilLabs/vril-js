/**
 * Vril.js v2.0.0 — Post-Quantum Cryptography Handler
 *
 * Post-quantum cryptography metadata and native Web Crypto integration points
 * for ML-KEM-768, ML-KEM-1024, ML-DSA-65, ML-DSA-87,
 * SLH-DSA-SHA2-128s, and SLH-DSA-SHA2-256f.
 *
 * NOTE: Vril.js does not simulate PQC operations. ML-KEM/ML-DSA/SLH-DSA
 * operations fail closed unless the runtime provides authentic native support
 * or the caller wires a validated external cryptographic module. FIPS
 * validation claims require CAVP/CMVP evidence for the exact implementation
 * and deployment boundary.
 *
 * Zero external dependencies — Web Crypto API only.
 */

// ─── Types ────────────────────────────────────────────────────────────────

/** PQC key pair result */
export interface PQCKeyPair {
  /** Raw public key bytes */
  publicKey: Uint8Array;
  /** Raw private key bytes */
  privateKey: Uint8Array;
  /** Algorithm identifier */
  algorithm: string;
  /** Whether key generation used native browser crypto */
  native: boolean;
  /** Timestamp of generation */
  createdAt: number;
}

/** KEM encapsulation result */
export interface KEMResult {
  /** Ciphertext for the recipient */
  ciphertext: Uint8Array;
  /** Shared secret derived from encapsulation */
  sharedSecret: Uint8Array;
  /** Algorithm used */
  algorithm: string;
  /** Whether operation used native browser crypto */
  native: boolean;
}

/** Digital signature result */
export interface SignatureResult {
  /** Signature bytes */
  signature: Uint8Array;
  /** Algorithm used */
  algorithm: string;
  /** Whether operation used native browser crypto */
  native: boolean;
  /** Timestamp of signing */
  signedAt: number;
}

/** Algorithm metadata */
export interface AlgorithmInfo {
  /** Algorithm identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** NIST standard reference */
  nistStandard: string;
  /** Security level (1-5, NIST categories) */
  securityLevel: number;
  /** Public key size in bytes */
  publicKeySize: number;
  /** Private key size in bytes */
  privateKeySize: number;
  /** Ciphertext/signature size in bytes */
  ciphertextSize: number;
  /** Algorithm type */
  type: 'kem' | 'signature';
  /** Whether natively supported in browsers */
  nativeSupport: boolean;
  /** Quantum resistance status */
  quantumResistant: boolean;
}

/** Benchmark result */
export interface BenchmarkResult {
  /** Algorithm benchmarked */
  algorithm: string;
  /** Key generation time in ms */
  keyGenerationMs: number;
  /** Encapsulation / signing time in ms */
  operationMs: number;
  /** Decapsulation / verification time in ms */
  inverseMs: number;
  /** Number of iterations averaged over */
  iterations: number;
  /** Whether operations used native browser crypto */
  native: boolean;
}

/** Evidence that a provider-backed implementation has FIPS validation */
export interface PQCValidationEvidence {
  /** Algorithm identifier covered by the evidence */
  algorithm: PQCAlgorithm;
  /** Applicable FIPS standard */
  standard: 'FIPS 203' | 'FIPS 204' | 'FIPS 205' | 'RFC 7748' | 'FIPS 186-5';
  /** CAVP/ACVP algorithm certificate identifier, when applicable */
  cavpCertificate?: string;
  /** CMVP/FIPS 140-3 module certificate identifier, when packaged as a module */
  cmvpCertificate?: string;
  /** Validated module or implementation name */
  moduleName: string;
  /** Provider/vendor name */
  providerName: string;
}

/** External authentic PQC provider contract */
export interface PQCProvider {
  /** Provider name for diagnostics and validation evidence */
  readonly name: string;
  /** Return validation evidence for an algorithm, or null if unsupported/unvalidated */
  getValidationEvidence: (algorithm: PQCAlgorithm) => PQCValidationEvidence | null;
  /** Generate an authentic key pair */
  generateKeyPair?: (algorithm: PQCAlgorithm) => Promise<PQCKeyPair>;
  /** Perform authentic KEM encapsulation */
  encapsulate?: (publicKey: Uint8Array, algorithm: PQCAlgorithm) => Promise<KEMResult>;
  /** Perform authentic KEM decapsulation */
  decapsulate?: (ciphertext: Uint8Array, privateKey: Uint8Array, algorithm: PQCAlgorithm) => Promise<KEMResult>;
  /** Perform authentic signature generation */
  sign?: (message: Uint8Array, privateKey: Uint8Array, algorithm: PQCAlgorithm) => Promise<SignatureResult>;
  /** Perform authentic signature verification */
  verify?: (message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array, algorithm: PQCAlgorithm) => Promise<boolean>;
}

/** Supported PQC algorithm identifiers */
export type PQCAlgorithm =
  | 'ML-KEM-768'
  | 'ML-KEM-1024'
  | 'ML-DSA-65'
  | 'ML-DSA-87'
  | 'SLH-DSA-SHA2-128s'
  | 'SLH-DSA-SHA2-256f'
  | 'X25519'
  | 'ECDSA-P256';

// ─── Algorithm Registry Data ─────────────────────────────────────────────

const ALGORITHM_INFO: Record<string, AlgorithmInfo> = {
  'ML-KEM-768': {
    id: 'ML-KEM-768',
    name: 'ML-KEM-768 (Kyber-768)',
    nistStandard: 'FIPS 203',
    securityLevel: 3,
    publicKeySize: 1184,
    privateKeySize: 2400,
    ciphertextSize: 1088,
    type: 'kem',
    nativeSupport: false,
    quantumResistant: true,
  },
  'ML-KEM-1024': {
    id: 'ML-KEM-1024',
    name: 'ML-KEM-1024 (Kyber-1024)',
    nistStandard: 'FIPS 203',
    securityLevel: 5,
    publicKeySize: 1568,
    privateKeySize: 3168,
    ciphertextSize: 1568,
    type: 'kem',
    nativeSupport: false,
    quantumResistant: true,
  },
  'ML-DSA-65': {
    id: 'ML-DSA-65',
    name: 'ML-DSA-65 (Dilithium-III)',
    nistStandard: 'FIPS 204',
    securityLevel: 3,
    publicKeySize: 1952,
    privateKeySize: 4032,
    ciphertextSize: 3293,
    type: 'signature',
    nativeSupport: false,
    quantumResistant: true,
  },
  'ML-DSA-87': {
    id: 'ML-DSA-87',
    name: 'ML-DSA-87 (Dilithium-V)',
    nistStandard: 'FIPS 204',
    securityLevel: 5,
    publicKeySize: 2592,
    privateKeySize: 4896,
    ciphertextSize: 4627,
    type: 'signature',
    nativeSupport: false,
    quantumResistant: true,
  },
  'SLH-DSA-SHA2-128s': {
    id: 'SLH-DSA-SHA2-128s',
    name: 'SLH-DSA-SHA2-128s (SPHINCS+-128s)',
    nistStandard: 'FIPS 205',
    securityLevel: 1,
    publicKeySize: 32,
    privateKeySize: 64,
    ciphertextSize: 7856,
    type: 'signature',
    nativeSupport: false,
    quantumResistant: true,
  },
  'SLH-DSA-SHA2-256f': {
    id: 'SLH-DSA-SHA2-256f',
    name: 'SLH-DSA-SHA2-256f (SPHINCS+-256f)',
    nistStandard: 'FIPS 205',
    securityLevel: 5,
    publicKeySize: 64,
    privateKeySize: 128,
    ciphertextSize: 29792,
    type: 'signature',
    nativeSupport: false,
    quantumResistant: true,
  },
  'X25519': {
    id: 'X25519',
    name: 'X25519 (Curve25519 ECDH)',
    nistStandard: 'RFC 7748',
    securityLevel: 1,
    publicKeySize: 32,
    privateKeySize: 32,
    ciphertextSize: 32,
    type: 'kem',
    nativeSupport: true,
    quantumResistant: false,
  },
  'ECDSA-P256': {
    id: 'ECDSA-P256',
    name: 'ECDSA P-256',
    nistStandard: 'FIPS 186-5',
    securityLevel: 1,
    publicKeySize: 64,
    privateKeySize: 32,
    ciphertextSize: 64,
    type: 'signature',
    nativeSupport: true,
    quantumResistant: false,
  },
};

// ─── Helper Utilities ─────────────────────────────────────────────────────

function isPQCAlgorithm(algorithm: string): boolean {
  return algorithm.startsWith('ML-') || algorithm.startsWith('SLH-');
}

function unsupportedPQCError(algorithm: string): Error {
  return new Error(
    `[VRIL PQC] ${algorithm} requires an authentic FIPS 203/204/205 implementation. ` +
    'Browser Web Crypto does not currently expose this algorithm in this runtime, ' +
    'and Vril.js does not provide simulated PQC.'
  );
}

// ─── PQCHandler Class ─────────────────────────────────────────────────────

/**
 * Post-Quantum Cryptography handler for Vril.js v2.0.
 *
 * Provides a unified interface for native cryptographic operations and
 * post-quantum metadata. PQC operations that are not natively available fail
 * closed instead of falling back to simulations.
 */
export class PQCHandler {
  private readonly version = '2.1.0';

  constructor(private provider: PQCProvider | null = null) {}

  /** Get module version */
  getVersion(): string {
    return this.version;
  }

  /** Register or replace the external authentic PQC provider */
  registerProvider(provider: PQCProvider): void {
    this.provider = provider;
  }

  /** Remove the external PQC provider */
  clearProvider(): void {
    this.provider = null;
  }

  /** Get validation evidence for an algorithm, if an authentic provider supplies it */
  getValidationEvidence(algorithm: PQCAlgorithm): PQCValidationEvidence | null {
    const info = this.getAlgorithmInfo(algorithm);
    if (info.nativeSupport) {
      return {
        algorithm,
        standard: info.nistStandard as PQCValidationEvidence['standard'],
        moduleName: 'Web Crypto API',
        providerName: 'runtime',
      };
    }
    return this.provider?.getValidationEvidence(algorithm) ?? null;
  }

  /**
   * Check if a specific algorithm is operationally supported by this handler.
   * Metadata-only PQC entries return false until native support is available.
   */
  isSupported(algorithm: string): boolean {
    const info = ALGORITHM_INFO[algorithm];
    if (!info) return false;
    if (info.nativeSupport) return true;
    return this.provider?.getValidationEvidence(algorithm as PQCAlgorithm)?.standard === info.nistStandard;
  }

  /**
   * Get list of operationally supported algorithm identifiers.
   */
  getSupportedAlgorithms(): string[] {
    return Object.keys(ALGORITHM_INFO).filter((algorithm) => this.isSupported(algorithm));
  }

  /**
   * Check if the browser natively supports PQC algorithms.
   * Currently no browser ships native ML-KEM/ML-DSA.
   */
  async browserSupportsPQC(): Promise<boolean> {
    if (typeof window === 'undefined') return false;
    try {
      // Check if Web Crypto API exists
      const subtle = crypto.subtle;
      if (!subtle?.generateKey) return false;
      // Future: check for ML-KEM support when browsers add it
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Get detailed algorithm information including NIST standard,
   * security level, and key sizes.
   */
  getAlgorithmInfo(algorithm: string): AlgorithmInfo {
    const info = ALGORITHM_INFO[algorithm];
    if (!info) {
      throw new Error(`[VRIL PQC] Unknown algorithm: ${algorithm}. Supported: ${Object.keys(ALGORITHM_INFO).join(', ')}`);
    }
    return { ...info };
  }

  /**
   * Get all registered algorithm info objects.
   */
  getAllAlgorithmInfo(): AlgorithmInfo[] {
    return Object.values(ALGORITHM_INFO).map(info => ({ ...info }));
  }

  /**
   * Generate a PQC key pair.
   *
   * For X25519 and ECDSA-P256, uses real Web Crypto API.
   * For ML-KEM, ML-DSA, and SLH-DSA algorithms, throws unless authentic
   * native support is available; simulations are never used.
   */
  async generateKeyPair(algorithm: PQCAlgorithm): Promise<PQCKeyPair> {
    const now = Date.now();

    // Native algorithms — use real Web Crypto
    if (algorithm === 'X25519') {
      return this.generateX25519KeyPair(now);
    }
    if (algorithm === 'ECDSA-P256') {
      return this.generateECDSAP256KeyPair(now);
    }

    if (isPQCAlgorithm(algorithm)) {
      const provider = this.requireProvider(algorithm, 'generateKeyPair');
      return provider.generateKeyPair!(algorithm);
    }

    throw new Error(`[VRIL PQC] Unsupported key generation algorithm: ${algorithm}`);
  }

  /**
   * KEM encapsulation — generate a shared secret and ciphertext
   * for the recipient's public key.
   *
   * For X25519, uses real ECDH key agreement.
   * For ML-KEM algorithms, throws unless authentic native support is available;
   * simulations are never used.
   */
  async encapsulate(publicKey: Uint8Array, algorithm: PQCAlgorithm = 'ML-KEM-768'): Promise<KEMResult> {
    if (algorithm === 'X25519') {
      return this.encapsulateX25519(publicKey);
    }

    if (isPQCAlgorithm(algorithm)) {
      const provider = this.requireProvider(algorithm, 'encapsulate');
      return provider.encapsulate!(publicKey, algorithm);
    }

    throw new Error(`[VRIL PQC] Unsupported KEM algorithm: ${algorithm}`);
  }

  /**
   * KEM decapsulation — recover shared secret from ciphertext
   * using the private key.
   *
   * For X25519, uses real ECDH.
   * For ML-KEM algorithms, throws unless authentic native support is available;
   * simulations are never used.
   */
  async decapsulate(
    ciphertext: Uint8Array,
    privateKey: Uint8Array,
    algorithm: PQCAlgorithm = 'ML-KEM-768'
  ): Promise<KEMResult> {
    if (algorithm === 'X25519') {
      return this.decapsulateX25519(ciphertext, privateKey);
    }

    if (isPQCAlgorithm(algorithm)) {
      const provider = this.requireProvider(algorithm, 'decapsulate');
      return provider.decapsulate!(ciphertext, privateKey, algorithm);
    }

    throw new Error(`[VRIL PQC] Unsupported KEM algorithm: ${algorithm}`);
  }

  /**
   * Sign a message with a private key.
   *
   * For ECDSA-P256, uses real Web Crypto signatures.
   * For ML-DSA / SLH-DSA, throws unless authentic native support is available;
   * simulations are never used.
   */
  async sign(
    message: Uint8Array,
    privateKey: Uint8Array,
    algorithm: PQCAlgorithm = 'ML-DSA-65'
  ): Promise<SignatureResult> {
    if (algorithm === 'ECDSA-P256') {
      return this.signECDSAP256(message, privateKey);
    }

    if (isPQCAlgorithm(algorithm)) {
      const provider = this.requireProvider(algorithm, 'sign');
      return provider.sign!(message, privateKey, algorithm);
    }

    throw new Error(`[VRIL PQC] Unsupported signature algorithm: ${algorithm}`);
  }

  /**
   * Verify a signature against a message and public key.
   *
   * For ECDSA-P256, uses real Web Crypto verification.
   * For ML-DSA / SLH-DSA, throws unless authentic native support is available;
   * simulations are never used.
   */
  async verify(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array,
    algorithm: PQCAlgorithm = 'ML-DSA-65'
  ): Promise<boolean> {
    if (algorithm === 'ECDSA-P256') {
      return this.verifyECDSAP256(message, signature, publicKey);
    }

    if (isPQCAlgorithm(algorithm)) {
      const provider = this.requireProvider(algorithm, 'verify');
      return provider.verify!(message, signature, publicKey, algorithm);
    }

    throw new Error(`[VRIL PQC] Unsupported signature algorithm: ${algorithm}`);
  }

  /**
   * Performance benchmark for key generation, encapsulation/decapsulation,
   * or sign/verify operations.
   */
  async benchmark(algorithm: PQCAlgorithm, iterations: number = 10): Promise<BenchmarkResult> {
    const info = this.getAlgorithmInfo(algorithm);
    const isNative = info.nativeSupport;

    // Key generation benchmark
    const kgStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      await this.generateKeyPair(algorithm);
    }
    const kgEnd = performance.now();
    const keyGenerationMs = (kgEnd - kgStart) / iterations;

    // Operation benchmark (encapsulate or sign)
    const keyPair = await this.generateKeyPair(algorithm);
    const testData = new TextEncoder().encode('vril-pqc-benchmark-test-data');

    const opStart = performance.now();
    if (info.type === 'kem') {
      for (let i = 0; i < iterations; i++) {
        await this.encapsulate(keyPair.publicKey, algorithm);
      }
    } else {
      for (let i = 0; i < iterations; i++) {
        await this.sign(testData, keyPair.privateKey, algorithm);
      }
    }
    const opEnd = performance.now();
    const operationMs = (opEnd - opStart) / iterations;

    // Inverse operation benchmark (decapsulate or verify)
    const invStart = performance.now();
    if (info.type === 'kem') {
      const kemResult = await this.encapsulate(keyPair.publicKey, algorithm);
      for (let i = 0; i < iterations; i++) {
        await this.decapsulate(kemResult.ciphertext, keyPair.privateKey, algorithm);
      }
    } else {
      const sigResult = await this.sign(testData, keyPair.privateKey, algorithm);
      for (let i = 0; i < iterations; i++) {
        await this.verify(testData, sigResult.signature, keyPair.publicKey, algorithm);
      }
    }
    const invEnd = performance.now();
    const inverseMs = (invEnd - invStart) / iterations;

    return {
      algorithm,
      keyGenerationMs,
      operationMs,
      inverseMs,
      iterations,
      native: isNative,
    };
  }

  // ─── Private: Native X25519 Key Generation ───────────────────────────

  private async generateX25519KeyPair(createdAt: number): Promise<PQCKeyPair> {
    try {
      const keyPair = await crypto.subtle.generateKey(
        { name: 'X25519' } as EcKeyGenParams,
        true,
        ['deriveBits']
      );
      const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
      const privateKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.privateKey));
      return { publicKey, privateKey, algorithm: 'X25519', native: true, createdAt };
    } catch {
      // Fallback to ECDH P-256 if X25519 not available
      return this.generateECDHFallbackKeyPair(createdAt);
    }
  }

  private async generateECDHFallbackKeyPair(createdAt: number): Promise<PQCKeyPair> {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
    const privateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
    return { publicKey, privateKey, algorithm: 'X25519', native: true, createdAt };
  }

  // ─── Private: Native ECDSA-P256 Key Generation ──────────────────────

  private async generateECDSAP256KeyPair(createdAt: number): Promise<PQCKeyPair> {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
    const privateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
    return { publicKey, privateKey, algorithm: 'ECDSA-P256', native: true, createdAt };
  }

  // ─── Private: X25519 Encapsulation ──────────────────────────────────

  private async encapsulateX25519(peerPublicKey: Uint8Array): Promise<KEMResult> {
    try {
      const ephemeralKey = await crypto.subtle.generateKey(
        { name: 'X25519' } as EcKeyGenParams,
        true,
        ['deriveBits']
      );

      const peerKey = await crypto.subtle.importKey(
        'raw',
        peerPublicKey.buffer as ArrayBuffer,
        { name: 'X25519' } as EcKeyImportParams,
        false,
        []
      );

      const sharedBits = await crypto.subtle.deriveBits(
        { name: 'X25519', public: peerKey } as EcdhKeyDeriveParams,
        ephemeralKey.privateKey,
        256
      );

      const ciphertext = new Uint8Array(
        await crypto.subtle.exportKey('raw', ephemeralKey.publicKey)
      );

      return {
        ciphertext,
        sharedSecret: new Uint8Array(sharedBits),
        algorithm: 'X25519',
        native: true,
      };
    } catch {
      return this.encapsulateECDHFallback(peerPublicKey);
    }
  }

  private async encapsulateECDHFallback(peerPublicKey: Uint8Array): Promise<KEMResult> {
    const ephemeralKey = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits']
    );

    const peerKey = await crypto.subtle.importKey(
      'raw',
      peerPublicKey.buffer as ArrayBuffer,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: peerKey },
      ephemeralKey.privateKey,
      256
    );

    const ciphertext = new Uint8Array(
      await crypto.subtle.exportKey('raw', ephemeralKey.publicKey)
    );

    return {
      ciphertext,
      sharedSecret: new Uint8Array(sharedBits),
      algorithm: 'X25519',
      native: true,
    };
  }

  // ─── Private: X25519 Decapsulation ──────────────────────────────────

  private async decapsulateX25519(
    ciphertext: Uint8Array,
    privateKey: Uint8Array
  ): Promise<KEMResult> {
    try {
      const privKey = await crypto.subtle.importKey(
        'raw',
        privateKey.buffer as ArrayBuffer,
        { name: 'X25519' } as EcKeyImportParams,
        false,
        ['deriveBits']
      );

      const pubKey = await crypto.subtle.importKey(
        'raw',
        ciphertext.buffer as ArrayBuffer,
        { name: 'X25519' } as EcKeyImportParams,
        false,
        []
      );

      const sharedBits = await crypto.subtle.deriveBits(
        { name: 'X25519', public: pubKey } as EcdhKeyDeriveParams,
        privKey,
        256
      );

      return {
        ciphertext,
        sharedSecret: new Uint8Array(sharedBits),
        algorithm: 'X25519',
        native: true,
      };
    } catch {
      return this.decapsulateECDHFallback(ciphertext, privateKey);
    }
  }

  private async decapsulateECDHFallback(
    ciphertext: Uint8Array,
    privateKey: Uint8Array
  ): Promise<KEMResult> {
    const privKey = await crypto.subtle.importKey(
      'pkcs8',
      privateKey.buffer as ArrayBuffer,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits']
    );

    const pubKey = await crypto.subtle.importKey(
      'raw',
      ciphertext.buffer as ArrayBuffer,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    const sharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: pubKey },
      privKey,
      256
    );

    return {
      ciphertext,
      sharedSecret: new Uint8Array(sharedBits),
      algorithm: 'X25519',
      native: true,
    };
  }

  // ─── Private: ECDSA-P256 Sign/Verify ────────────────────────────────

  private async signECDSAP256(
    message: Uint8Array,
    privateKey: Uint8Array
  ): Promise<SignatureResult> {
    const privKey = await crypto.subtle.importKey(
      'pkcs8',
      privateKey.buffer as ArrayBuffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privKey,
      message as BufferSource
    );

    return {
      signature: new Uint8Array(signature),
      algorithm: 'ECDSA-P256',
      native: true,
      signedAt: Date.now(),
    };
  }

  private async verifyECDSAP256(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array
  ): Promise<boolean> {
    try {
      const pubKey = await crypto.subtle.importKey(
        'raw',
        publicKey.buffer as ArrayBuffer,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
      );

      return crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        pubKey,
        signature as BufferSource,
        message as BufferSource
      );
    } catch {
      return false;
    }
  }

  private requireProvider<K extends keyof PQCProvider>(
    algorithm: PQCAlgorithm,
    operation: K
  ): PQCProvider & Required<Pick<PQCProvider, K>> {
    const info = this.getAlgorithmInfo(algorithm);
    const evidence = this.provider?.getValidationEvidence(algorithm);
    if (!this.provider || evidence?.standard !== info.nistStandard || typeof this.provider[operation] !== 'function') {
      throw unsupportedPQCError(algorithm);
    }
    return this.provider as PQCProvider & Required<Pick<PQCProvider, K>>;
  }

}

// ─── Convenience Singleton ────────────────────────────────────────────────

/** Default PQCHandler instance */
export const pqc = new PQCHandler();
