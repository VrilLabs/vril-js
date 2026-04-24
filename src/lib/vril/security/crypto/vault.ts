/**
 * Vril.js v2.0.0 — AES-256-GCM Vault (ΩVault)
 *
 * Zero-knowledge client-side encryption with PBKDF2-SHA-512.
 * Supports text encryption, binary blob encryption, key wrapping,
 * key derivation, passphrase rotation, and secure memory handling.
 *
 * All operations use AES-256-GCM + PBKDF2-SHA-512 with configurable
 * iterations. Bundle format v2 includes version field for forward
 * compatibility.
 *
 * Zero external dependencies — Web Crypto API only.
 */

// ─── Types ────────────────────────────────────────────────────────────────

/** Vault configuration */
export interface VaultConfig {
  /** PBKDF2 iteration count (default: 600000) */
  kdfIterations: number;
  /** Salt size in bytes (default: 16) */
  saltSize: number;
  /** IV size in bytes (default: 12 for AES-GCM) */
  ivSize: number;
  /** Bundle format version */
  version: number;
  /** Additional authenticated data (AAD) for GCM */
  aad?: Uint8Array;
}

/** Text encryption result (v2 format) */
export interface EncryptionResult {
  /** Bundle format version */
  v: number;
  /** Base64-encoded salt */
  salt: string;
  /** Base64-encoded IV */
  iv: string;
  /** Base64-encoded ciphertext */
  ciphertext: string;
  /** Encryption algorithm */
  algorithm: string;
  /** Key derivation function */
  kdf: string;
  /** PBKDF2 iteration count */
  kdfIterations: number;
  /** Timestamp of encryption */
  encryptedAt?: number;
}

/** Decryption result */
export interface DecryptionResult {
  /** Decrypted plaintext */
  plaintext: string;
  /** Algorithm used */
  algorithm: string;
  /** Whether GCM authentication tag verified */
  verified: boolean;
}

/** Binary blob encryption result */
export interface BlobEncryptionResult {
  /** Bundle format version */
  v: number;
  /** Salt bytes */
  salt: Uint8Array;
  /** IV bytes */
  iv: Uint8Array;
  /** Encrypted data bytes */
  ciphertext: Uint8Array;
  /** Encryption algorithm */
  algorithm: string;
  /** Key derivation function */
  kdf: string;
  /** PBKDF2 iteration count */
  kdfIterations: number;
  /** Original data size before encryption */
  originalSize: number;
  /** Timestamp */
  encryptedAt: number;
}

/** Key wrap result */
export interface KeyWrapResult {
  /** Wrapped (encrypted) key bytes */
  wrappedKey: Uint8Array;
  /** IV used for wrapping */
  iv: Uint8Array;
  /** Algorithm used for wrapping */
  algorithm: string;
}

/** Password strength assessment */
export interface StrengthAssessment {
  /** Numeric score (0-max) */
  score: number;
  /** Maximum possible score */
  max: number;
  /** Human-readable label */
  label: 'very-weak' | 'weak' | 'moderate' | 'strong' | 'very-strong';
  /** Estimated crack time in seconds */
  estimatedCrackTimeSeconds: number;
  /** Specific feedback */
  feedback: string[];
}

/** Default vault configuration */
const DEFAULT_CONFIG: VaultConfig = {
  kdfIterations: 600000,
  saltSize: 16,
  ivSize: 12,
  version: 2,
};

// ─── VrilVault Class ──────────────────────────────────────────────────────

/**
 * AES-256-GCM Vault for zero-knowledge client-side encryption.
 *
 * Features:
 * - Text and binary blob encryption/decryption
 * - Key derivation from passphrases (PBKDF2-SHA-512)
 * - Key wrapping/unwrapping (AES-KW)
 * - Data key generation
 * - Passphrase rotation (re-encrypt without exposing plaintext)
 * - Public key import/export
 * - Password strength assessment
 * - Secure memory zeroing
 */
export class VrilVault {
  private config: VaultConfig;
  private readonly version = '2.1.0';

  constructor(config: Partial<VaultConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /** Get module version */
  getVersion(): string {
    return this.version;
  }

  /** Get current vault configuration */
  getConfig(): VaultConfig {
    return { ...this.config };
  }

  /** Update vault configuration */
  setConfig(update: Partial<VaultConfig>): void {
    this.config = { ...this.config, ...update };
  }

  // ─── Private Helpers ────────────────────────────────────────────────

  private ab2b64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  private b642ab(b64: string): ArrayBuffer {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  /**
   * Derive an AES-256-GCM key from a passphrase and salt.
   */
  private async deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt as BufferSource,
        iterations: this.config.kdfIterations,
        hash: 'SHA-512',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Derive an AES-256-GCM key with additional usages for wrapping.
   */
  private async deriveWrappingKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt as BufferSource,
        iterations: this.config.kdfIterations,
        hash: 'SHA-512',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );
  }

  // ─── Text Encryption/Decryption ────────────────────────────────────

  /**
   * Encrypt a plaintext string with a passphrase.
   *
   * Uses AES-256-GCM with PBKDF2-SHA-512 key derivation.
   * Returns a v2 bundle with version, salt, IV, and ciphertext.
   */
  async encrypt(passphrase: string, plaintext: string): Promise<EncryptionResult> {
    const salt = crypto.getRandomValues(new Uint8Array(this.config.saltSize));
    const iv = crypto.getRandomValues(new Uint8Array(this.config.ivSize));
    const key = await this.deriveKey(passphrase, salt);

    const aad = this.config.aad ?? undefined;
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        ...(aad ? { additionalData: aad } : {}),
      },
      key,
      new TextEncoder().encode(plaintext)
    );

    return {
      v: this.config.version,
      salt: this.ab2b64(salt.buffer as ArrayBuffer),
      iv: this.ab2b64(iv.buffer as ArrayBuffer),
      ciphertext: this.ab2b64(ciphertext),
      algorithm: 'AES-256-GCM',
      kdf: 'PBKDF2-SHA-512',
      kdfIterations: this.config.kdfIterations,
      encryptedAt: Date.now(),
    };
  }

  /**
   * Decrypt an encryption bundle with a passphrase.
   *
   * Supports both v1 and v2 bundle formats.
   * GCM authentication tag is verified automatically.
   */
  async decrypt(passphrase: string, bundle: EncryptionResult): Promise<DecryptionResult> {
    if (bundle.v !== 1 && bundle.v !== 2) {
      throw new Error(`[VRIL Vault] Unsupported bundle version: ${bundle.v}`);
    }
    if (!bundle.salt || !bundle.iv || !bundle.ciphertext) {
      throw new Error('[VRIL Vault] Invalid bundle format: missing required fields');
    }

    const salt = new Uint8Array(this.b642ab(bundle.salt));
    const iv = new Uint8Array(this.b642ab(bundle.iv));
    const ciphertextBuf = this.b642ab(bundle.ciphertext);

    const iterations = bundle.kdfIterations ?? this.config.kdfIterations;
    const originalIterations = this.config.kdfIterations;
    this.config.kdfIterations = iterations;

    try {
      const key = await this.deriveKey(passphrase, salt);

      const aad = this.config.aad ?? undefined;
      const decrypted = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv as BufferSource,
          ...(aad ? { additionalData: aad } : {}),
        },
        key,
        ciphertextBuf
      );

      return {
        plaintext: new TextDecoder().decode(decrypted),
        algorithm: 'AES-256-GCM',
        verified: true,
      };
    } catch {
      throw new Error('[VRIL Vault] Decryption failed: invalid passphrase or corrupted data');
    } finally {
      this.config.kdfIterations = originalIterations;
    }
  }

  // ─── Binary Blob Encryption/Decryption ──────────────────────────────

  /**
   * Encrypt binary data (ArrayBuffer) with a passphrase.
   *
   * Returns a BlobEncryptionResult with raw byte arrays
   * (no base64 encoding) for performance with large data.
   */
  async encryptBlob(data: ArrayBuffer, passphrase: string): Promise<BlobEncryptionResult> {
    const salt = crypto.getRandomValues(new Uint8Array(this.config.saltSize));
    const iv = crypto.getRandomValues(new Uint8Array(this.config.ivSize));
    const key = await this.deriveKey(passphrase, salt);

    const aad = this.config.aad ?? undefined;
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        ...(aad ? { additionalData: aad } : {}),
      },
      key,
      data
    );

    return {
      v: this.config.version,
      salt,
      iv,
      ciphertext: new Uint8Array(ciphertext),
      algorithm: 'AES-256-GCM',
      kdf: 'PBKDF2-SHA-512',
      kdfIterations: this.config.kdfIterations,
      originalSize: data.byteLength,
      encryptedAt: Date.now(),
    };
  }

  /**
   * Decrypt a binary blob encryption result.
   *
   * Returns the original ArrayBuffer.
   */
  async decryptBlob(bundle: BlobEncryptionResult, passphrase: string): Promise<ArrayBuffer> {
    if (bundle.v !== 2) {
      throw new Error(`[VRIL Vault] Unsupported blob version: ${bundle.v}`);
    }

    const iterations = bundle.kdfIterations ?? this.config.kdfIterations;
    const originalIterations = this.config.kdfIterations;
    this.config.kdfIterations = iterations;

    try {
      const key = await this.deriveKey(passphrase, bundle.salt);

      const aad = this.config.aad ?? undefined;
      const decrypted = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: bundle.iv as BufferSource,
          ...(aad ? { additionalData: aad } : {}),
        },
        key,
        bundle.ciphertext as BufferSource
      );

      return decrypted;
    } catch {
      throw new Error('[VRIL Vault] Blob decryption failed: invalid passphrase or corrupted data');
    } finally {
      this.config.kdfIterations = originalIterations;
    }
  }

  // ─── Key Derivation ─────────────────────────────────────────────────

  /**
   * Derive a CryptoKey from a passphrase and salt.
   *
   * Exposes key derivation for reuse by other modules.
   * The returned key can be used for encrypt/decrypt/wrap/unwrap.
   */
  async deriveKeyFromPassphrase(
    passphrase: string,
    salt: Uint8Array,
    usages: KeyUsage[] = ['encrypt', 'decrypt']
  ): Promise<CryptoKey> {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt as BufferSource,
        iterations: this.config.kdfIterations,
        hash: 'SHA-512',
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      usages
    );
  }

  // ─── Key Wrapping ───────────────────────────────────────────────────

  /**
   * Wrap (encrypt) a CryptoKey using a wrapping key.
   *
   * Uses AES-GCM for key wrapping (AES-KW requires 64-bit alignment
   * which isn't always available, so we use AES-GCM as a robust
   * alternative).
   */
  async wrapKey(key: CryptoKey, wrappingKey: CryptoKey): Promise<KeyWrapResult> {
    const iv = crypto.getRandomValues(new Uint8Array(this.config.ivSize));

    const wrappedKey = await crypto.subtle.wrapKey('raw', key, wrappingKey, {
      name: 'AES-GCM',
      iv,
    });

    return {
      wrappedKey: new Uint8Array(wrappedKey),
      iv,
      algorithm: 'AES-256-GCM-KW',
    };
  }

  /**
   * Unwrap (decrypt) a wrapped key using an unwrapping key.
   *
   * Returns the unwrapped CryptoKey ready for use.
   */
  async unwrapKey(
    wrappedKey: Uint8Array,
    unwrappingKey: CryptoKey,
    iv: Uint8Array,
    keyAlgorithm: AlgorithmIdentifier,
    keyUsages: KeyUsage[] = ['encrypt', 'decrypt']
  ): Promise<CryptoKey> {
    return crypto.subtle.unwrapKey(
      'raw',
      wrappedKey as unknown as BufferSource,
      unwrappingKey,
      { name: 'AES-GCM', iv: iv as BufferSource },
      keyAlgorithm,
      false,
      keyUsages
    );
  }

  // ─── Data Key Generation ────────────────────────────────────────────

  /**
   * Generate a random AES-256-GCM data encryption key.
   *
   * This key can be used for envelope encryption patterns:
   * encrypt data with the data key, then encrypt the data key
   * with a key encryption key (KEK) derived from a passphrase.
   */
  async generateDataKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );
  }

  // ─── Passphrase Rotation ────────────────────────────────────────────

  /**
   * Re-encrypt data with a new passphrase without exposing plaintext.
   *
   * 1. Decrypt with old passphrase
   * 2. Re-encrypt with new passphrase
   * 3. Return new bundle
   *
   * The old bundle should be securely deleted after rotation.
   */
  async rotatePassphrase(
    oldPassphrase: string,
    newPassphrase: string,
    bundle: EncryptionResult
  ): Promise<EncryptionResult> {
    // Decrypt with old passphrase
    const { plaintext, verified } = await this.decrypt(oldPassphrase, bundle);
    if (!verified) {
      throw new Error('[VRIL Vault] Cannot rotate: original data integrity check failed');
    }

    // Re-encrypt with new passphrase
    const newBundle = await this.encrypt(newPassphrase, plaintext);

    // Securely clear the plaintext from memory (best-effort)
    SecureMemory.zeroString(plaintext);

    return newBundle;
  }

  // ─── Key Import/Export ──────────────────────────────────────────────

  /**
   * Export a public key as raw bytes.
   */
  async exportPublicKey(key: CryptoKey): Promise<Uint8Array> {
    const raw = await crypto.subtle.exportKey('raw', key);
    return new Uint8Array(raw);
  }

  /**
   * Import a public key from raw bytes.
   */
  async importPublicKey(
    rawData: Uint8Array,
    algorithm: AlgorithmIdentifier,
    usages: KeyUsage[] = ['verify']
  ): Promise<CryptoKey> {
    return crypto.subtle.importKey('raw', rawData as BufferSource, algorithm, false, usages);
  }

  // ─── Password Strength Assessment ──────────────────────────────────

  /**
   * Assess the strength of a passphrase.
   *
   * Returns a score, label, estimated crack time, and specific
   * feedback for improving the passphrase.
   */
  assessStrength(passphrase: string): StrengthAssessment {
    let score = 0;
    const feedback: string[] = [];
    const len = passphrase.length;

    // Length checks
    if (len >= 4) score++;
    if (len >= 8) score++;
    if (len >= 12) score++;
    if (len >= 16) score++;
    if (len < 8) feedback.push('Use at least 8 characters');
    if (len < 12) feedback.push('Consider using 12+ characters for strong security');

    // Character variety
    const hasLower = /[a-z]/.test(passphrase);
    const hasUpper = /[A-Z]/.test(passphrase);
    const hasDigit = /\d/.test(passphrase);
    const hasSpecial = /[^A-Za-z0-9]/.test(passphrase);

    if (hasLower) score++;
    else feedback.push('Add lowercase letters');

    if (hasUpper) score++;
    else feedback.push('Add uppercase letters');

    if (hasDigit) score++;
    else feedback.push('Add numbers');

    if (hasSpecial) score++;
    else feedback.push('Add special characters');

    // Entropy estimation
    let charsetSize = 0;
    if (hasLower) charsetSize += 26;
    if (hasUpper) charsetSize += 26;
    if (hasDigit) charsetSize += 10;
    if (hasSpecial) charsetSize += 32;

    // Common pattern checks
    if (/^[a-zA-Z]+$/.test(passphrase)) {
      score = Math.max(0, score - 1);
      feedback.push('Avoid using only letters');
    }
    if (/^[0-9]+$/.test(passphrase)) {
      score = Math.max(0, score - 2);
      feedback.push('Avoid using only numbers');
    }
    if (/(.)\1{2,}/.test(passphrase)) {
      score = Math.max(0, score - 1);
      feedback.push('Avoid repeated characters');
    }
    if (/^(123|abc|qwerty|password)/i.test(passphrase)) {
      score = 0;
      feedback.push('Avoid common sequences and passwords');
    }

    // Estimated crack time (assuming 10 billion guesses/sec)
    const combinations = Math.pow(charsetSize || 1, len);
    const guessesPerSecond = 10_000_000_000;
    const estimatedCrackTimeSeconds = combinations / (2 * guessesPerSecond);

    const max = 10;
    let label: StrengthAssessment['label'];
    if (score <= 2) label = 'very-weak';
    else if (score <= 4) label = 'weak';
    else if (score <= 6) label = 'moderate';
    else if (score <= 8) label = 'strong';
    else label = 'very-strong';

    if (feedback.length === 0) {
      feedback.push('Passphrase meets all strength requirements');
    }

    return { score, max, label, estimatedCrackTimeSeconds, feedback };
  }
}

// ─── SecureMemory Class ───────────────────────────────────────────────────

/**
 * Secure memory utilities for zeroing sensitive data.
 *
 * In JavaScript, true secure memory is impossible due to garbage
 * collection and string immutability. This class provides best-effort
 * zeroing for Uint8Arrays and ArrayBuffer views.
 *
 * For strings, we convert to Uint8Array, zero it, and hope the GC
 * reclaims the original string memory promptly.
 */
export class SecureMemory {
  private static readonly version = '2.1.0';

  /** Get module version */
  static getVersion(): string {
    return SecureMemory.version;
  }

  /**
   * Zero out a Uint8Array or ArrayBuffer in place.
   *
   * This is reliable for typed arrays since we can write
   * directly to the underlying buffer.
   */
  static zero(data: Uint8Array | ArrayBuffer): void {
    if (data instanceof ArrayBuffer) {
      const view = new Uint8Array(data);
      crypto.getRandomValues(view); // Overwrite with random first
      view.fill(0); // Then zero
    } else {
      crypto.getRandomValues(data); // Overwrite with random first
      data.fill(0); // Then zero
    }
  }

  /**
   * Best-effort zeroing of a string's memory representation.
   *
   * Since JavaScript strings are immutable, we cannot truly zero
   * them. Instead, we create a Uint8Array copy, zero it, and
   * hope the GC reclaims the original string soon.
   */
  static zeroString(str: string): void {
    const bytes = new TextEncoder().encode(str);
    SecureMemory.zero(bytes);
  }

  /**
   * Create a secure Uint8Array that will be automatically zeroed
   * when the callback completes.
   */
  static async withSecureBuffer<T>(
    size: number,
    callback: (buffer: Uint8Array) => Promise<T>
  ): Promise<T> {
    const buffer = new Uint8Array(size);
    try {
      return await callback(buffer);
    } finally {
      SecureMemory.zero(buffer);
    }
  }

  /**
   * Create a secure Uint8Array from sensitive data that tracks
   * its zeroed state.
   */
  static createSecureBuffer(data: Uint8Array): {
    data: Uint8Array;
    zero: () => void;
    isZeroed: () => boolean;
  } {
    const copy = new Uint8Array(data);
    let zeroed = false;

    return {
      data: copy,
      zero: () => {
        if (!zeroed) {
          SecureMemory.zero(copy);
          zeroed = true;
        }
      },
      isZeroed: () => zeroed,
    };
  }

  /**
   * Compare two Uint8Arrays in constant time to prevent timing attacks.
   */
  static constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }
}
