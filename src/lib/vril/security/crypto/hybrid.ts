/**
 * Vril.js v2.0.0 — Hybrid Cryptography Module
 *
 * Combines classical (X25519, ECDSA-P256) with post-quantum (ML-KEM-768,
 * ML-DSA-65) algorithms. Uses KDF combiner to merge shared secrets so
 * the result is secure as long as AT LEAST ONE component algorithm
 * remains unbroken — defense in depth against quantum adversaries.
 *
 * Key combiner: SHA-256(classicalSecret || pqcSecret || contextInfo)
 *
 * Zero external dependencies — Web Crypto API only.
 */

import { PQCHandler, type PQCKeyPair, type PQCAlgorithm } from './pqc';

// ─── Types ────────────────────────────────────────────────────────────────

/** Result of hybrid KEM encapsulation */
export interface HybridKEMResult {
  /** Combined shared secret (post-KDF) */
  sharedSecret: Uint8Array;
  /** Classical KEM ciphertext */
  classicalCiphertext: Uint8Array;
  /** PQC KEM ciphertext */
  pqcCiphertext: Uint8Array;
  /** Classical algorithm used */
  classicalAlgorithm: string;
  /** PQC algorithm used */
  pqcAlgorithm: string;
  /** Whether the combined secret was derived from real or simulated PQC */
  nativePQC: boolean;
  /** Timestamp */
  createdAt: number;
}

/** Result of hybrid signature */
export interface HybridSignatureResult {
  /** Classical signature bytes */
  classicalSignature: Uint8Array;
  /** PQC signature bytes */
  pqcSignature: Uint8Array;
  /** Classical algorithm used */
  classicalAlgorithm: string;
  /** PQC algorithm used */
  pqcAlgorithm: string;
  /** Whether PQC signature was native or simulated */
  nativePQC: boolean;
  /** Timestamp */
  signedAt: number;
}

/** Key rotation policy configuration */
export interface KeyRotationPolicy {
  /** Maximum key age in milliseconds before rotation is required */
  maxKeyAgeMs: number;
  /** Overlap period in ms — old and new keys both valid */
  overlapPeriodMs: number;
  /** Whether to auto-rotate keys on policy expiry */
  autoRotate: boolean;
  /** Minimum number of rotations to keep in history */
  historySize: number;
}

/** Hybrid key pair with metadata */
export interface HybridKeyPair {
  /** Classical key pair */
  classical: PQCKeyPair;
  /** PQC key pair */
  pqc: PQCKeyPair;
  /** Combined public key (concatenated) */
  combinedPublicKey: Uint8Array;
  /** Key pair identifier */
  id: string;
  /** Creation timestamp */
  createdAt: number;
  /** Rotation state */
  rotationState: 'active' | 'rotating' | 'expired';
}

/** Key rotation event */
export interface KeyRotationEvent {
  /** Old key pair ID */
  oldKeyId: string;
  /** New key pair ID */
  newKeyId: string;
  /** Rotation timestamp */
  timestamp: number;
  /** Reason for rotation */
  reason: 'scheduled' | 'manual' | 'policy' | 'compromise';
  /** Whether overlap period is active */
  inOverlap: boolean;
}

/** Default rotation policy */
const DEFAULT_ROTATION_POLICY: KeyRotationPolicy = {
  maxKeyAgeMs: 90 * 24 * 60 * 60 * 1000, // 90 days
  overlapPeriodMs: 7 * 24 * 60 * 60 * 1000, // 7 days
  autoRotate: false,
  historySize: 5,
};

// ─── Helper Utilities ─────────────────────────────────────────────────────

function concatArrays(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

function generateId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// constantTimeEqual removed — use TimingAttackMitigation.constantTimeEqual instead

// ─── HybridKEM Class ──────────────────────────────────────────────────────

/**
 * Hybrid Key Encapsulation Mechanism combining classical + PQC.
 *
 * X25519MLKEM768 — Combines X25519 + ML-KEM-768 with SHA-256 KDF combiner.
 * The combined shared secret is: SHA256(x25519Secret || mlkem768Secret || contextInfo)
 *
 * Security guarantee: The result is secure if EITHER X25519 OR ML-KEM-768
 * remains unbroken — providing quantum resistance while maintaining
 * classical security as a fallback.
 */
export class HybridKEM {
  private readonly pqc: PQCHandler;
  private readonly version = '2.1.0';
  private classicalAlgorithm: string;
  private pqcAlgorithm: string;
  private contextInfo: string;

  constructor(
    mode: 'X25519MLKEM768' | 'ECDSAP256MLDSA65' = 'X25519MLKEM768',
    contextInfo: string = 'vril-hybrid-kem-v2'
  ) {
    this.pqc = new PQCHandler();
    this.contextInfo = contextInfo;

    if (mode === 'X25519MLKEM768') {
      this.classicalAlgorithm = 'X25519';
      this.pqcAlgorithm = 'ML-KEM-768';
    } else {
      this.classicalAlgorithm = 'ECDSA-P256';
      this.pqcAlgorithm = 'ML-DSA-65';
    }
  }

  /** Get module version */
  getVersion(): string {
    return this.version;
  }

  /** Get the classical algorithm identifier */
  getClassicalAlgorithm(): string {
    return this.classicalAlgorithm;
  }

  /** Get the PQC algorithm identifier */
  getPQCAlgorithm(): string {
    return this.pqcAlgorithm;
  }

  /**
   * Generate a hybrid key pair (classical + PQC).
   */
  async generateKeyPair(): Promise<HybridKeyPair> {
    const [classical, pqc] = await Promise.all([
      this.pqc.generateKeyPair(this.classicalAlgorithm as PQCAlgorithm),
      this.pqc.generateKeyPair(this.pqcAlgorithm as PQCAlgorithm),
    ]);

    const combinedPublicKey = concatArrays(classical.publicKey, pqc.publicKey);

    return {
      classical,
      pqc,
      combinedPublicKey,
      id: generateId(),
      createdAt: Date.now(),
      rotationState: 'active',
    };
  }

  /**
   * Perform hybrid KEM encapsulation.
   *
   * Generates an ephemeral classical key pair, performs classical KEM,
   * performs PQC KEM, then combines the shared secrets using SHA-256 KDF:
   *   combined = SHA256(classicalSecret || pqcSecret || contextInfo)
   */
  async encapsulate(recipientHybridPublicKey: Uint8Array): Promise<HybridKEMResult> {
    // Split the combined public key
    const classicalInfo = this.pqc.getAlgorithmInfo(this.classicalAlgorithm);
    const pqcInfo = this.pqc.getAlgorithmInfo(this.pqcAlgorithm);

    const classicalPubKey = recipientHybridPublicKey.slice(0, classicalInfo.publicKeySize);
    const pqcPubKey = recipientHybridPublicKey.slice(
      classicalInfo.publicKeySize,
      classicalInfo.publicKeySize + pqcInfo.publicKeySize
    );

    // Perform classical KEM
    const classicalResult = await this.pqc.encapsulate(
      classicalPubKey,
      this.classicalAlgorithm as PQCAlgorithm
    );

    // Perform PQC KEM
    const pqcResult = await this.pqc.encapsulate(
      pqcPubKey,
      this.pqcAlgorithm as PQCAlgorithm
    );

    // Combine shared secrets using SHA-256 KDF
    const contextBytes = new TextEncoder().encode(this.contextInfo);
    const combinedInput = concatArrays(
      classicalResult.sharedSecret,
      pqcResult.sharedSecret,
      contextBytes
    );
    const combinedSecret = new Uint8Array(
      await crypto.subtle.digest('SHA-256', combinedInput as BufferSource)
    );

    return {
      sharedSecret: combinedSecret,
      classicalCiphertext: classicalResult.ciphertext,
      pqcCiphertext: pqcResult.ciphertext,
      classicalAlgorithm: this.classicalAlgorithm,
      pqcAlgorithm: this.pqcAlgorithm,
      nativePQC: pqcResult.native,
      createdAt: Date.now(),
    };
  }

  /**
   * Perform hybrid KEM decapsulation.
   *
   * Decapsulates both classical and PQC ciphertexts using the hybrid
   * private key, then recombines shared secrets via SHA-256 KDF.
   */
  async decapsulate(
    hybridKeyPair: HybridKeyPair,
    kemResult: HybridKEMResult
  ): Promise<Uint8Array> {
    // Decapsulate classical component
    const classicalResult = await this.pqc.decapsulate(
      kemResult.classicalCiphertext,
      hybridKeyPair.classical.privateKey,
      this.classicalAlgorithm as PQCAlgorithm
    );

    // Decapsulate PQC component
    const pqcResult = await this.pqc.decapsulate(
      kemResult.pqcCiphertext,
      hybridKeyPair.pqc.privateKey,
      this.pqcAlgorithm as PQCAlgorithm
    );

    // Combine shared secrets using same KDF
    const contextBytes = new TextEncoder().encode(this.contextInfo);
    const combinedInput = concatArrays(
      classicalResult.sharedSecret,
      pqcResult.sharedSecret,
      contextBytes
    );
    const combinedSecret = new Uint8Array(
      await crypto.subtle.digest('SHA-256', combinedInput as BufferSource)
    );

    return combinedSecret;
  }
}

// ─── HybridSigner Class ───────────────────────────────────────────────────

/**
 * Hybrid digital signature combining classical + PQC algorithms.
 *
 * ECDSAP256MLDSA65 — Signs with both ECDSA-P256 and ML-DSA-65.
 * Verification uses AND logic — BOTH signatures must verify for
 * the overall verification to succeed.
 */
export class HybridSigner {
  private readonly pqc: PQCHandler;
  private readonly version = '2.1.0';
  private classicalAlgorithm: string;
  private pqcAlgorithm: string;

  constructor(mode: 'X25519MLKEM768' | 'ECDSAP256MLDSA65' = 'ECDSAP256MLDSA65') {
    this.pqc = new PQCHandler();

    if (mode === 'X25519MLKEM768') {
      this.classicalAlgorithm = 'X25519';
      this.pqcAlgorithm = 'ML-KEM-768';
    } else {
      this.classicalAlgorithm = 'ECDSA-P256';
      this.pqcAlgorithm = 'ML-DSA-65';
    }
  }

  /** Get module version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Generate a hybrid signing key pair.
   */
  async generateKeyPair(): Promise<HybridKeyPair> {
    const [classical, pqc] = await Promise.all([
      this.pqc.generateKeyPair(this.classicalAlgorithm as PQCAlgorithm),
      this.pqc.generateKeyPair(this.pqcAlgorithm as PQCAlgorithm),
    ]);

    const combinedPublicKey = concatArrays(classical.publicKey, pqc.publicKey);

    return {
      classical,
      pqc,
      combinedPublicKey,
      id: generateId(),
      createdAt: Date.now(),
      rotationState: 'active',
    };
  }

  /**
   * Sign a message with both classical and PQC algorithms.
   *
   * Returns both signatures independently so verifiers can
   * check each one separately.
   */
  async sign(
    message: Uint8Array,
    hybridKeyPair: HybridKeyPair
  ): Promise<HybridSignatureResult> {
    const [classicalSig, pqcSig] = await Promise.all([
      this.pqc.sign(message, hybridKeyPair.classical.privateKey, this.classicalAlgorithm as PQCAlgorithm),
      this.pqc.sign(message, hybridKeyPair.pqc.privateKey, this.pqcAlgorithm as PQCAlgorithm),
    ]);

    return {
      classicalSignature: classicalSig.signature,
      pqcSignature: pqcSig.signature,
      classicalAlgorithm: this.classicalAlgorithm,
      pqcAlgorithm: this.pqcAlgorithm,
      nativePQC: pqcSig.native,
      signedAt: Date.now(),
    };
  }

  /**
   * Verify a hybrid signature.
   *
   * Uses AND logic — BOTH classical and PQC signatures must verify
   * for the overall result to be true. This ensures that even if a
   * quantum adversary can forge the classical signature, the PQC
   * signature still provides protection.
   */
  async verify(
    message: Uint8Array,
    hybridSignature: HybridSignatureResult,
    hybridPublicKey: Uint8Array
  ): Promise<boolean> {
    const classicalInfo = this.pqc.getAlgorithmInfo(this.classicalAlgorithm);
    const pqcInfo = this.pqc.getAlgorithmInfo(this.pqcAlgorithm);

    const classicalPubKey = hybridPublicKey.slice(0, classicalInfo.publicKeySize);
    const pqcPubKey = hybridPublicKey.slice(
      classicalInfo.publicKeySize,
      classicalInfo.publicKeySize + pqcInfo.publicKeySize
    );

    // Verify BOTH signatures — AND logic
    const [classicalValid, pqcValid] = await Promise.all([
      this.pqc.verify(
        message,
        hybridSignature.classicalSignature,
        classicalPubKey,
        this.classicalAlgorithm as PQCAlgorithm
      ),
      this.pqc.verify(
        message,
        hybridSignature.pqcSignature,
        pqcPubKey,
        this.pqcAlgorithm as PQCAlgorithm
      ),
    ]);

    return classicalValid && pqcValid;
  }

  /**
   * Verify signatures individually — returns result for each.
   */
  async verifyIndividual(
    message: Uint8Array,
    hybridSignature: HybridSignatureResult,
    hybridPublicKey: Uint8Array
  ): Promise<{ classicalValid: boolean; pqcValid: boolean; overallValid: boolean }> {
    const classicalInfo = this.pqc.getAlgorithmInfo(this.classicalAlgorithm);
    const pqcInfo = this.pqc.getAlgorithmInfo(this.pqcAlgorithm);

    const classicalPubKey = hybridPublicKey.slice(0, classicalInfo.publicKeySize);
    const pqcPubKey = hybridPublicKey.slice(
      classicalInfo.publicKeySize,
      classicalInfo.publicKeySize + pqcInfo.publicKeySize
    );

    const [classicalValid, pqcValid] = await Promise.all([
      this.pqc.verify(
        message,
        hybridSignature.classicalSignature,
        classicalPubKey,
        this.classicalAlgorithm as PQCAlgorithm
      ),
      this.pqc.verify(
        message,
        hybridSignature.pqcSignature,
        pqcPubKey,
        this.pqcAlgorithm as PQCAlgorithm
      ),
    ]);

    return {
      classicalValid,
      pqcValid,
      overallValid: classicalValid && pqcValid,
    };
  }
}

// ─── HybridKeyRotation Class ──────────────────────────────────────────────

/**
 * Key rotation management for hybrid key pairs with overlap periods.
 *
 * During the overlap period, both old and new key pairs are valid,
 * allowing for a smooth transition without service interruption.
 * The rotation history is maintained for audit purposes.
 */
export class HybridKeyRotation {
  private readonly version = '2.1.0';
  private policy: KeyRotationPolicy;
  private keyPairs: Map<string, HybridKeyPair> = new Map();
  private activeKeyId: string | null = null;
  private rotationHistory: KeyRotationEvent[] = [];
  private kem: HybridKEM;

  constructor(policy: Partial<KeyRotationPolicy> = {}) {
    this.policy = { ...DEFAULT_ROTATION_POLICY, ...policy };
    this.kem = new HybridKEM();
  }

  /** Get module version */
  getVersion(): string {
    return this.version;
  }

  /** Get the current rotation policy */
  getPolicy(): KeyRotationPolicy {
    return { ...this.policy };
  }

  /** Update the rotation policy */
  setPolicy(update: Partial<KeyRotationPolicy>): void {
    this.policy = { ...this.policy, ...update };
  }

  /**
   * Initialize with a new hybrid key pair.
   */
  async initialize(): Promise<HybridKeyPair> {
    const keyPair = await this.kem.generateKeyPair();
    this.keyPairs.set(keyPair.id, keyPair);
    this.activeKeyId = keyPair.id;
    return keyPair;
  }

  /**
   * Get the currently active key pair.
   */
  getActiveKeyPair(): HybridKeyPair | null {
    if (!this.activeKeyId) return null;
    return this.keyPairs.get(this.activeKeyId) ?? null;
  }

  /**
   * Get a key pair by ID.
   */
  getKeyPair(id: string): HybridKeyPair | null {
    return this.keyPairs.get(id) ?? null;
  }

  /**
   * Check if a key pair needs rotation based on the policy.
   */
  needsRotation(keyId?: string): boolean {
    const id = keyId ?? this.activeKeyId;
    if (!id) return false;
    const keyPair = this.keyPairs.get(id);
    if (!keyPair) return false;

    const age = Date.now() - keyPair.createdAt;
    return age >= this.policy.maxKeyAgeMs;
  }

  /**
   * Check if a key pair is within its overlap period.
   */
  isInOverlap(keyId: string): boolean {
    const keyPair = this.keyPairs.get(keyId);
    if (!keyPair) return false;

    // Find the rotation event for this key
    const rotationEvent = this.rotationHistory.find(
      e => e.newKeyId === keyId || e.oldKeyId === keyId
    );
    if (!rotationEvent) return false;

    const overlapEnd = rotationEvent.timestamp + this.policy.overlapPeriodMs;
    return Date.now() < overlapEnd;
  }

  /**
   * Get all keys that are currently valid (active + in-overlap).
   */
  getValidKeyIds(): string[] {
    const validIds: string[] = [];

    // Active key is always valid
    if (this.activeKeyId) {
      validIds.push(this.activeKeyId);
    }

    // Check overlap keys
    for (const [id] of this.keyPairs) {
      if (id !== this.activeKeyId && this.isInOverlap(id)) {
        validIds.push(id);
      }
    }

    return validIds;
  }

  /**
   * Perform key rotation — generate new key pair and transition.
   */
  async rotate(reason: KeyRotationEvent['reason'] = 'scheduled'): Promise<{
    oldKeyId: string;
    newKeyId: string;
    newKeyPair: HybridKeyPair;
  }> {
    const oldKeyId = this.activeKeyId;
    const oldKeyPair = oldKeyId ? this.keyPairs.get(oldKeyId) : null;

    if (oldKeyPair) {
      oldKeyPair.rotationState = 'rotating';
    }

    const newKeyPair = await this.kem.generateKeyPair();
    this.keyPairs.set(newKeyPair.id, newKeyPair);
    this.activeKeyId = newKeyPair.id;

    const event: KeyRotationEvent = {
      oldKeyId: oldKeyId ?? 'none',
      newKeyId: newKeyPair.id,
      timestamp: Date.now(),
      reason,
      inOverlap: true,
    };
    this.rotationHistory.push(event);

    // Prune old keys beyond history size
    this.pruneOldKeys();

    return {
      oldKeyId: oldKeyId ?? 'none',
      newKeyId: newKeyPair.id,
      newKeyPair,
    };
  }

  /**
   * Get rotation history.
   */
  getRotationHistory(): KeyRotationEvent[] {
    return [...this.rotationHistory];
  }

  /**
   * Check policy and auto-rotate if needed.
   */
  async checkAndRotate(): Promise<{
    rotated: boolean;
    oldKeyId?: string;
    newKeyId?: string;
  }> {
    if (this.policy.autoRotate && this.needsRotation()) {
      const result = await this.rotate('policy');
      return { rotated: true, oldKeyId: result.oldKeyId, newKeyId: result.newKeyId };
    }
    return { rotated: false };
  }

  /**
   * Mark overlap period as ended for a specific key.
   */
  endOverlap(keyId: string): void {
    const keyPair = this.keyPairs.get(keyId);
    if (keyPair && keyPair.rotationState === 'rotating') {
      keyPair.rotationState = 'expired';
    }
  }

  /**
   * Get status summary of all key pairs.
   */
  getStatus(): {
    activeKeyId: string | null;
    totalKeyPairs: number;
    validKeyCount: number;
    nextRotationNeeded: boolean;
    rotationHistoryCount: number;
  } {
    return {
      activeKeyId: this.activeKeyId,
      totalKeyPairs: this.keyPairs.size,
      validKeyCount: this.getValidKeyIds().length,
      nextRotationNeeded: this.needsRotation(),
      rotationHistoryCount: this.rotationHistory.length,
    };
  }

  // ─── Private ──────────────────────────────────────────────────────

  private pruneOldKeys(): void {
    // Keep active + up to historySize old keys
    const allIds = Array.from(this.keyPairs.keys());
    const validIds = new Set(this.getValidKeyIds());

    const expiredIds = allIds.filter(id => !validIds.has(id));
    if (expiredIds.length > this.policy.historySize) {
      // Remove oldest expired keys beyond history size
      const toRemove = expiredIds
        .sort((a, b) => {
          const ka = this.keyPairs.get(a);
          const kb = this.keyPairs.get(b);
          return (ka?.createdAt ?? 0) - (kb?.createdAt ?? 0);
        })
        .slice(0, expiredIds.length - this.policy.historySize);

      for (const id of toRemove) {
        this.keyPairs.delete(id);
      }
    }
  }
}
