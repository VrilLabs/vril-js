/**
 * Vril.js v2.0.0 — Central Type Definitions
 * All shared types, interfaces, and type utilities for the framework
 *
 * VrilRuntime · VrilFeature · SecureString · Encrypted<T> · Hashed<T>
 * Signed<T> · PQCVerified · AlgorithmIdentifier · SecurityLevel
 * DeepPartial · DeepReadonly · Branded · Nominal
 */

// ─── Runtime & Environment Types ──────────────────────────────────

/** Runtime environment identifiers */
export type VrilRuntime =
  | 'browser'
  | 'node'
  | 'edge'
  | 'deno'
  | 'bun'
  | 'workerd'
  | 'unknown';

/** Feature flag identifier for framework capabilities */
export type VrilFeature =
  | 'signals'
  | 'post-quantum-crypto'
  | 'crypto-agility'
  | 'trusted-types'
  | 'api-membrane'
  | 'streaming-ssr'
  | 'selective-hydration'
  | 'csp'
  | 'permissions-policy'
  | 'csrf-protection'
  | 'request-signing'
  | 'encrypted-state'
  | 'time-travel'
  | 'state-persistence'
  | 'diagnostics'
  | 'bundle-analysis';

// ─── Security Branded Types ───────────────────────────────────────

/**
 * Branded type for security-validated strings.
 * Use this to mark strings that have passed security validation
 * (e.g., sanitized HTML, validated URLs).
 */
export type SecureString<T extends string = string> = T & {
  readonly __secure_brand: unique symbol;
};

/**
 * Branded type for encrypted data.
 * Wraps a type to indicate the value is stored in encrypted form.
 */
export type Encrypted<T> = T & {
  readonly __encrypted_brand: unique symbol;
};

/**
 * Branded type for hashed data.
 * Indicates the value is a one-way hash of the original data.
 */
export type Hashed<T> = string & {
  readonly __hashed_brand: unique symbol;
};

/**
 * Branded type for signed data.
 * Indicates the value has been cryptographically signed.
 */
export type Signed<T> = T & {
  readonly __signed_brand: unique symbol;
  readonly __signature: string;
};

/**
 * Post-quantum verification marker.
 * Indicates a value has been verified using post-quantum algorithms.
 */
export interface PQCVerified {
  /** Algorithm used for verification */
  readonly pqcAlgorithm: string;
  /** Timestamp of verification */
  readonly verifiedAt: number;
  /** Whether the verification was native or simulated */
  readonly nativeVerification: boolean;
  /** NIST security level (1-5) */
  readonly securityLevel: number;
}

// ─── Algorithm Types ──────────────────────────────────────────────

/** All supported cryptographic algorithm identifiers */
export type AlgorithmIdentifier =
  | 'AES-256-GCM'
  | 'AES-128-GCM'
  | 'PBKDF2-SHA-256'
  | 'PBKDF2-SHA-512'
  | 'HMAC-SHA-256'
  | 'HMAC-SHA-384'
  | 'HMAC-SHA-512'
  | 'SHA-256'
  | 'SHA-384'
  | 'SHA-512'
  | 'ECDSA-P256'
  | 'ECDSA-P384'
  | 'ECDSA-P521'
  | 'X25519'
  | 'ECDH-P256'
  | 'ML-KEM-768'
  | 'ML-KEM-1024'
  | 'ML-DSA-65'
  | 'ML-DSA-87'
  | 'SLH-DSA-SHA2-128s'
  | 'SLH-DSA-SHA2-256f'
  | 'X25519-ML-KEM-768'
  | 'ECDSA-P256-ML-DSA-65';

/** Algorithm category classification */
export type AlgorithmCategory =
  | 'symmetric-encryption'
  | 'asymmetric-encryption'
  | 'key-derivation'
  | 'hashing'
  | 'signing'
  | 'key-exchange'
  | 'kem'
  | 'hybrid-kem'
  | 'hybrid-signing';

/** Algorithm status in the agility framework */
export type AlgorithmStatus = 'active' | 'deprecated' | 'planned' | 'end-of-life';

// ─── Security Levels ──────────────────────────────────────────────

/** Security level enum based on NIST categories */
export enum SecurityLevel {
  /** NIST Level 1 — equivalent to AES-128 */
  Level1 = 1,
  /** NIST Level 2 */
  Level2 = 2,
  /** NIST Level 3 — equivalent to AES-192 */
  Level3 = 3,
  /** NIST Level 4 */
  Level4 = 4,
  /** NIST Level 5 — equivalent to AES-256 */
  Level5 = 5,
}

/** Security classification for data sensitivity */
export type DataClassification =
  | 'public'
  | 'internal'
  | 'confidential'
  | 'restricted'
  | 'top-secret';

// ─── Crypto Key Types ─────────────────────────────────────────────

/** Key usage permissions for CryptoKey objects */
export type KeyUsage =
  | 'encrypt'
  | 'decrypt'
  | 'sign'
  | 'verify'
  | 'deriveKey'
  | 'deriveBits'
  | 'wrapKey'
  | 'unwrapKey';

/** Key type classification */
export type KeyType = 'secret' | 'public' | 'private';

/** Key format for import/export operations */
export type KeyFormat = 'raw' | 'pkcs8' | 'spki' | 'jwk';

/** Crypto key metadata */
export interface CryptoKeyMetadata {
  /** Algorithm the key is used with */
  algorithm: AlgorithmIdentifier;
  /** Key type */
  keyType: KeyType;
  /** Key usage permissions */
  usages: KeyUsage[];
  /** Whether the key is extractable */
  extractable: boolean;
  /** Key creation timestamp */
  createdAt: number;
  /** Key expiration timestamp (if applicable) */
  expiresAt?: number;
  /** Key ID for rotation tracking */
  keyId: string;
}

// ─── CSP & Security Header Types ──────────────────────────────────

/** CSP directive name */
export type CSPDirective =
  | 'default-src'
  | 'script-src'
  | 'style-src'
  | 'img-src'
  | 'font-src'
  | 'connect-src'
  | 'frame-src'
  | 'object-src'
  | 'media-src'
  | 'manifest-src'
  | 'worker-src'
  | 'base-uri'
  | 'form-action'
  | 'frame-ancestors'
  | 'navigate-to'
  | 'report-uri'
  | 'report-to';

/** Permissions policy directive */
export type PermissionsPolicyDirective =
  | 'accelerometer'
  | 'ambient-light-sensor'
  | 'autoplay'
  | 'battery'
  | 'camera'
  | 'compute-pressure'
  | 'cross-origin-isolated'
  | 'display-capture'
  | 'document-domain'
  | 'encrypted-media'
  | 'execution-while-not-rendered'
  | 'execution-while-out-of-viewport'
  | 'fullscreen'
  | 'geolocation'
  | 'gyroscope'
  | 'hid'
  | 'identity-credentials-get'
  | 'idle-detection'
  | 'local-fonts'
  | 'magnetometer'
  | 'microphone'
  | 'midi'
  | 'otp-credentials'
  | 'payment'
  | 'picture-in-picture'
  | 'publickey-credentials-get'
  | 'screen-wake-lock'
  | 'serial'
  | 'speaker-selection'
  | 'storage-access'
  | 'sync-xhr'
  | 'unload'
  | 'usb'
  | 'vertical-scroll'
  | 'web-share'
  | 'window-management'
  | 'xr-spatial-tracking';

// ─── Signal & State Types ─────────────────────────────────────────

/** Signal node kind for the dependency graph */
export type SignalKind =
  | 'signal'
  | 'computed'
  | 'effect'
  | 'lazy'
  | 'async'
  | 'resource'
  | 'debounced'
  | 'throttled'
  | 'persisted'
  | 'encrypted';

/** Store action types */
export type StoreActionType =
  | 'SET_STATE'
  | 'UNDO'
  | 'REDO'
  | 'RESET'
  | 'PATCH'
  | string;

// ─── Network & Request Types ──────────────────────────────────────

/** HTTP methods */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';

/** Request signing algorithm */
export type RequestSigningAlgorithm = 'HMAC-SHA-256' | 'ECDSA-P256' | 'ML-DSA-65';

/** CSRF token source */
export type CSRFTokenSource = 'meta' | 'cookie' | 'header' | 'custom';

// ─── Utility Types ────────────────────────────────────────────────

/**
 * Make all properties of T recursively optional.
 * Unlike Partial<T>, this applies to nested objects as well.
 */
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object
    ? T[P] extends Array<infer U>
      ? Array<DeepPartial<U>>
      : T[P] extends Function
        ? T[P]
        : DeepPartial<T[P]>
    : T[P];
};

/**
 * Make all properties of T recursively readonly.
 * Unlike Readonly<T>, this applies to nested objects as well.
 */
export type DeepReadonly<T> = {
  readonly [P in keyof T]: T[P] extends object
    ? T[P] extends Function
      ? T[P]
      : DeepReadonly<T[P]>
    : T[P];
};

/**
 * Branded type constructor.
 * Creates a nominal type that is structurally compatible with T
 * but distinct in the type system.
 *
 * @example
 * type USD = Branded<number, 'USD'>;
 * type EUR = Branded<number, 'EUR'>;
 * // USD and EUR are not assignable to each other
 */
export type Branded<T, Brand extends string> = T & {
  readonly __brand: Brand;
};

/**
 * Nominal type constructor.
 * Similar to Branded but uses a symbol for the brand to prevent
 * accidental structural compatibility.
 */
export type Nominal<T, Name extends string> = T & {
  readonly __nominal: unique symbol;
  readonly __name: Name;
};

/**
 * Extract the inner type from a branded type.
 */
export type Unbrand<B> = B extends Branded<infer T, string> ? T : B;

/**
 * Make specific keys of T required.
 */
export type RequireKeys<T, K extends keyof T> = T & Required<Pick<T, K>>;

/**
 * Make specific keys of T optional.
 */
export type OptionalKeys<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

/**
 * Non-nullable type (removes null and undefined).
 */
export type NonNullable<T> = T extends null | undefined ? never : T;

/**
 * Exact type — ensures no extra properties.
 */
export type Exact<T, Shape> = T extends Shape
  ? Exclude<keyof T, keyof Shape> extends never
    ? T
    : never
  : never;

/**
 * Promise value type — unwraps Promise<T> to T.
 */
export type Awaited<T> = T extends Promise<infer U> ? U : T;

/**
 * Tuple type from array.
 */
export type TupleOf<T, N extends number, R extends T[] = []> =
  R['length'] extends N ? R : TupleOf<T, N, [...R, T]>;

// ─── Diagnostic Types ─────────────────────────────────────────────

/** Diagnostic severity levels */
export type DiagnosticSeverity = 'info' | 'warning' | 'error' | 'critical';

/** Performance metric category */
export type MetricCategory = 'render' | 'signal' | 'api' | 'crypto' | 'memory' | 'custom';

/** Health check status */
export type HealthStatus = 'healthy' | 'degraded' | 'unhealthy' | 'unknown';

// ─── Version & Migration Types ────────────────────────────────────

/** Semantic version string */
export type SemVer = `${number}.${number}.${number}`;

/** Migration direction */
export type MigrationDirection = 'upgrade' | 'downgrade';

/** Compatibility level between versions */
export type CompatibilityLevel = 'full' | 'partial' | 'breaking' | 'none';
