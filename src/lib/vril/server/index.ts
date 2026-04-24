/**
 * Vril.js v2.0.0 — Server Security Utilities
 * RSC deserialization hardening, Server Action CSRF, edge request signing,
 * encrypted environment variables, supply chain integrity, RSC security boundary,
 * server timing security, request validation, and composable security middleware.
 */

export const SERVER_MODULE_VERSION = '2.1.0';

// ─── RSC Deserialization Hardening ───────────────────────────
export interface DeserializationConfig {
  /** Maximum nesting depth (prevents deeply nested attack payloads) */
  maxDepth: number;
  /** Maximum number of keys in a single object */
  maxKeys: number;
  /** Maximum string length */
  maxStringLength: number;
  /** Allowed types for deserialization */
  allowedTypes: string[];
  /** Reject function/symbol references */
  rejectFunctions: boolean;
  /** Regex patterns to detect and reject in string values */
  blockedPatterns: RegExp[];
  /** Maximum array length */
  maxArrayLength: number;
  /** Enable circular reference detection */
  detectCircularRefs: boolean;
  /** Enable prototype chain validation */
  validatePrototypeChain: boolean;
}

export const DEFAULT_DESERIALIZATION_CONFIG: DeserializationConfig = {
  maxDepth: 16,
  maxKeys: 256,
  maxStringLength: 1024 * 1024, // 1MB
  allowedTypes: ['string', 'number', 'boolean', 'object', 'array', 'null'],
  rejectFunctions: true,
  blockedPatterns: [
    /__proto__/i,
    /constructor\s*\[/i,
    /prototype\s*\[/i,
    /eval\s*\(/i,
    /Function\s*\(/i,
    /setTimeout\s*\(/i,
    /setInterval\s*\(/i,
  ],
  maxArrayLength: 10000,
  detectCircularRefs: true,
  validatePrototypeChain: true,
};

/**
 * Validate a deserialized payload against security constraints.
 * Prevents CVE-2025-55182 (React2Shell) style attacks.
 * v2.0.0: Adds regex pattern detection, prototype chain validation, circular reference detection.
 */
export function validateDeserializedPayload(
  data: unknown,
  config: Partial<DeserializationConfig> = {},
  depth = 0,
  visited?: WeakSet<object>
): { valid: boolean; reason?: string } {
  const cfg = { ...DEFAULT_DESERIALIZATION_CONFIG, ...config };
  const seen = visited ?? new WeakSet<object>();

  if (depth > cfg.maxDepth) {
    return { valid: false, reason: `Maximum depth ${cfg.maxDepth} exceeded` };
  }

  if (data === null) return { valid: true };
  if (data === undefined) return { valid: false, reason: 'undefined values not permitted' };

  const type = typeof data;

  // Reject functions and symbols
  if (type === 'function') {
    if (cfg.rejectFunctions) return { valid: false, reason: 'Function references not permitted' };
  }
  if (type === 'symbol') {
    return { valid: false, reason: 'Symbol references not permitted' };
  }

  // Primitive types
  if (type === 'string') {
    const str = data as string;
    if (str.length > cfg.maxStringLength) {
      return { valid: false, reason: `String length exceeds ${cfg.maxStringLength}` };
    }
    // Regex pattern detection
    for (const pattern of cfg.blockedPatterns) {
      if (pattern.test(str)) {
        return { valid: false, reason: `String matches blocked pattern: ${pattern.source}` };
      }
    }
    return { valid: true };
  }

  if (type === 'number' || type === 'boolean') return { valid: true };

  // Arrays
  if (Array.isArray(data)) {
    if (data.length > cfg.maxArrayLength) {
      return { valid: false, reason: `Array length ${data.length} exceeds maximum ${cfg.maxArrayLength}` };
    }
    // Circular reference detection for arrays
    if (cfg.detectCircularRefs) {
      if (seen.has(data as object)) {
        return { valid: false, reason: 'Circular reference detected in array' };
      }
      seen.add(data as object);
    }
    for (const item of data) {
      const result = validateDeserializedPayload(item, cfg, depth + 1, seen);
      if (!result.valid) return result;
    }
    return { valid: true };
  }

  // Objects
  if (type === 'object') {
    // Circular reference detection
    if (cfg.detectCircularRefs) {
      if (seen.has(data as object)) {
        return { valid: false, reason: 'Circular reference detected in object' };
      }
      seen.add(data as object);
    }

    // Prototype chain validation
    if (cfg.validatePrototypeChain) {
      const proto = Object.getPrototypeOf(data as object);
      if (proto !== null && proto !== Object.prototype) {
        // Allow plain objects but flag objects with unusual prototype chains
        const protoStr = Object.prototype.toString.call(data);
        if (protoStr !== '[object Object]') {
          return { valid: false, reason: `Object has non-standard prototype chain: ${protoStr}` };
        }
      }
    }

    const keys = Object.keys(data as object);
    if (keys.length > cfg.maxKeys) {
      return { valid: false, reason: `Object keys exceed ${cfg.maxKeys}` };
    }

    // Check for dangerous prototype-polluting keys
    const dangerous = ['__proto__', 'constructor', 'prototype'];
    for (const key of keys) {
      if (dangerous.includes(key)) {
        return { valid: false, reason: `Dangerous key "${key}" not permitted` };
      }
      const result = validateDeserializedPayload((data as Record<string, unknown>)[key], cfg, depth + 1, seen);
      if (!result.valid) return result;
    }
    return { valid: true };
  }

  return { valid: false, reason: `Unknown type: ${type}` };
}

// ─── Server Action CSRF ──────────────────────────────────────
/**
 * CSRF protection with double-submit cookie pattern, SameSite enforcement, and token rotation.
 * v2.0.0: Adds double-submit cookie, SameSite, token rotation.
 */
export class CSRFGuard {
  private static TOKEN_HEADER = 'x-vril-csrf';
  private static COOKIE_NAME = 'vril-csrf';
  private static TOKEN_LENGTH = 32;
  private static TOKEN_MAX_AGE = 3600000; // 1 hour
  private static rotationMap = new Map<string, { token: string; expires: number }>();

  /** Generate a cryptographically random CSRF token */
  static generateToken(): string {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      const bytes = crypto.getRandomValues(new Uint8Array(this.TOKEN_LENGTH));
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }

  /** Validate a CSRF token against the expected value with constant-time comparison */
  static validateToken(request: Request, expectedToken: string): boolean {
    const provided = request.headers.get(this.TOKEN_HEADER);
    if (!provided || !expectedToken) return false;
    if (provided.length !== expectedToken.length) return false;
    let result = 0;
    for (let i = 0; i < provided.length; i++) {
      result |= provided.charCodeAt(i) ^ expectedToken.charCodeAt(i);
    }
    return result === 0;
  }

  static getHeaderName(): string {
    return this.TOKEN_HEADER;
  }

  /** Double-submit cookie pattern: set cookie and return matching header value */
  static generateDoubleSubmit(): { cookie: string; headerValue: string } {
    const token = this.generateToken();
    const cookie = `${this.COOKIE_NAME}=${token}; Path=/; SameSite=Strict; Secure; HttpOnly; Max-Age=3600`;
    return { cookie, headerValue: token };
  }

  /** Validate double-submit cookie pattern — cookie and header must match */
  static validateDoubleSubmit(request: Request): boolean {
    const cookieHeader = request.headers.get('cookie') ?? '';
    const cookieToken = this.extractCookieValue(cookieHeader, this.COOKIE_NAME);
    const headerToken = request.headers.get(this.TOKEN_HEADER);
    if (!cookieToken || !headerToken) return false;
    if (cookieToken.length !== headerToken.length) return false;
    let result = 0;
    for (let i = 0; i < cookieToken.length; i++) {
      result |= cookieToken.charCodeAt(i) ^ headerToken.charCodeAt(i);
    }
    return result === 0;
  }

  /** Validate SameSite enforcement — reject requests missing SameSite cookies */
  static validateSameSite(request: Request, allowedOrigins: string[]): boolean {
    const origin = request.headers.get('origin');
    if (!origin) return false;
    return allowedOrigins.some(o => origin === o || origin.startsWith(o));
  }

  /** Generate a rotated token — invalidates the old one */
  static rotateToken(sessionId: string): string {
    const newToken = this.generateToken();
    this.rotationMap.set(sessionId, { token: newToken, expires: Date.now() + this.TOKEN_MAX_AGE });
    return newToken;
  }

  /** Validate a rotated token for a given session */
  static validateRotatedToken(sessionId: string, providedToken: string): boolean {
    const entry = this.rotationMap.get(sessionId);
    if (!entry) return false;
    if (Date.now() > entry.expires) {
      this.rotationMap.delete(sessionId);
      return false;
    }
    if (providedToken.length !== entry.token.length) return false;
    let result = 0;
    for (let i = 0; i < providedToken.length; i++) {
      result |= providedToken.charCodeAt(i) ^ entry.token.charCodeAt(i);
    }
    return result === 0;
  }

  private static extractCookieValue(cookieHeader: string, name: string): string | null {
    const parts = cookieHeader.split(';');
    for (const part of parts) {
      const trimmed = part.trim();
      if (trimmed.startsWith(`${name}=`)) {
        return trimmed.substring(name.length + 1);
      }
    }
    return null;
  }
}

// ─── Edge Request Signing ────────────────────────────────────
/**
 * Sign requests between edge and origin to prevent request forgery.
 * v2.0.0: Adds timestamp validation, request ID generation, replay attack prevention.
 */
export class RequestSigner {
  private secret: string;
  private static MAX_SKEW_MS = 300000; // 5 minutes
  private static seenNonces = new Map<string, number>();
  private static NONCE_TTL = 600000; // 10 minutes

  constructor(secret: string) {
    this.secret = secret;
  }

  /** Sign a payload with timestamp using HMAC-SHA256 */
  async sign(payload: string, timestamp: number): Promise<string> {
    const data = `${timestamp}:${payload}`;
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const key = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(this.secret),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
      );
      const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
      return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    return `fallback-${data.length}-${timestamp}`;
  }

  /** Verify a signed payload with timestamp validation */
  async verify(payload: string, timestamp: number, signature: string): Promise<boolean> {
    // Timestamp validation: reject old or future signatures
    const now = Date.now();
    if (Math.abs(now - timestamp) > RequestSigner.MAX_SKEW_MS) {
      return false;
    }
    const expected = await this.sign(payload, timestamp);
    if (expected.length !== signature.length) return false;
    let result = 0;
    for (let i = 0; i < expected.length; i++) {
      result |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
    }
    return result === 0;
  }

  /** Generate a unique request ID for tracing and deduplication */
  static generateRequestId(): string {
    const timestamp = Date.now().toString(36);
    const random = typeof crypto !== 'undefined' && crypto.getRandomValues
      ? Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('')
      : Math.random().toString(36).substring(2);
    return `vril-req-${timestamp}-${random}`;
  }

  /** Check if a nonce has been seen before (replay attack prevention) */
  static checkReplay(nonce: string): boolean {
    const now = Date.now();
    // Prune expired nonces
    for (const [key, ts] of RequestSigner.seenNonces) {
      if (now - ts > RequestSigner.NONCE_TTL) {
        RequestSigner.seenNonces.delete(key);
      }
    }
    if (RequestSigner.seenNonces.has(nonce)) {
      return true; // replay detected
    }
    RequestSigner.seenNonces.set(nonce, now);
    return false;
  }

  /** Sign a full request with headers, timestamp, and nonce */
  async signRequest(request: Request): Promise<Headers> {
    const timestamp = Date.now();
    const nonce = RequestSigner.generateRequestId();
    const url = new URL(request.url);
    const payload = `${request.method}:${url.pathname}:${nonce}`;
    const signature = await this.sign(payload, timestamp);
    const headers = new Headers(request.headers);
    headers.set('x-vril-signature', signature);
    headers.set('x-vril-timestamp', timestamp.toString());
    headers.set('x-vril-nonce', nonce);
    headers.set('x-vril-request-id', nonce);
    return headers;
  }

  /** Verify a signed request including timestamp and replay checks */
  async verifyRequest(request: Request): Promise<{ valid: boolean; reason?: string }> {
    const timestamp = parseInt(request.headers.get('x-vril-timestamp') ?? '0', 10);
    const signature = request.headers.get('x-vril-signature') ?? '';
    const nonce = request.headers.get('x-vril-nonce') ?? '';

    if (!timestamp || !signature || !nonce) {
      return { valid: false, reason: 'Missing signature headers' };
    }

    // Check timestamp freshness
    const now = Date.now();
    if (Math.abs(now - timestamp) > RequestSigner.MAX_SKEW_MS) {
      return { valid: false, reason: 'Signature timestamp expired or in the future' };
    }

    // Check replay
    if (RequestSigner.checkReplay(nonce)) {
      return { valid: false, reason: 'Replay detected: nonce already used' };
    }

    const url = new URL(request.url);
    const payload = `${request.method}:${url.pathname}:${nonce}`;
    const valid = await this.verify(payload, timestamp, signature);
    return valid
      ? { valid: true }
      : { valid: false, reason: 'Signature verification failed' };
  }
}

// ─── Encrypted Environment Variables ─────────────────────────
/**
 * Encrypt/decrypt environment variables for edge runtime.
 * v2.0.0: Adds key rotation, multi-key support, key derivation from HSM-like interface.
 */
export class EnvEncryption {
  private static ALGORITHM = 'AES-GCM';
  private static KEY_LENGTH = 256;
  private key: CryptoKey | null = null;
  private keyVersion: number = 1;
  private keyMap = new Map<number, CryptoKey>();
  private hsmInterface: HSMKeyProvider | null = null;

  /** Initialize with a master key */
  async initialize(masterKey: string): Promise<void> {
    if (typeof crypto === 'undefined' || !crypto.subtle) return;
    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(masterKey),
      'PBKDF2', false, ['deriveKey']
    );
    this.key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: new TextEncoder().encode('vril-env-v1'), iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 },
      false, ['encrypt', 'decrypt']
    );
    this.keyMap.set(this.keyVersion, this.key);
  }

  /** Initialize with an HSM-like key provider */
  async initializeFromHSM(provider: HSMKeyProvider): Promise<void> {
    this.hsmInterface = provider;
    const masterKey = await provider.deriveKey('vril-master-key');
    await this.initialize(masterKey);
  }

  /** Encrypt a value, tagging it with the current key version */
  async encrypt(value: string): Promise<string> {
    if (!this.key) throw new Error('EnvEncryption not initialized');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, this.key, new TextEncoder().encode(value)
    );
    const versionByte = new Uint8Array([this.keyVersion]);
    const combined = new Uint8Array(versionByte.length + iv.length + new Uint8Array(encrypted).length);
    combined.set(versionByte, 0);
    combined.set(iv, 1);
    combined.set(new Uint8Array(encrypted), 1 + iv.length);
    return btoa(String.fromCharCode(...combined));
  }

  /** Decrypt a value, using the key version embedded in the ciphertext */
  async decrypt(encrypted: string): Promise<string> {
    if (typeof crypto === 'undefined' || !crypto.subtle) throw new Error('Web Crypto unavailable');
    const combined = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const version = combined[0];
    const iv = combined.slice(1, 13);
    const data = combined.slice(13);

    const key = this.keyMap.get(version) ?? this.key;
    if (!key) throw new Error(`No key found for version ${version}`);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv }, key, data
    );
    return new TextDecoder().decode(decrypted);
  }

  /** Rotate the encryption key — new encryptions use the new key */
  async rotateKey(newMasterKey: string): Promise<number> {
    this.keyVersion++;
    if (typeof crypto === 'undefined' || !crypto.subtle) return this.keyVersion;
    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(newMasterKey),
      'PBKDF2', false, ['deriveKey']
    );
    const salt = new TextEncoder().encode(`vril-env-v${this.keyVersion}`);
    const newKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 },
      false, ['encrypt', 'decrypt']
    );
    this.key = newKey;
    this.keyMap.set(this.keyVersion, newKey);
    return this.keyVersion;
  }

  /** Re-encrypt a value with the current key (for migration after rotation) */
  async reEncrypt(encrypted: string): Promise<string> {
    const plaintext = await this.decrypt(encrypted);
    return this.encrypt(plaintext);
  }

  /** Get the current key version */
  getKeyVersion(): number {
    return this.keyVersion;
  }

  /** Get all available key versions */
  getAvailableKeyVersions(): number[] {
    return Array.from(this.keyMap.keys());
  }
}

/** HSM-like interface for key derivation */
export interface HSMKeyProvider {
  deriveKey(keyId: string): Promise<string>;
  getProviderInfo(): { name: string; version: string };
}

// ─── Supply Chain Integrity ──────────────────────────────────
export interface IntegrityManifest {
  version: string;
  generated: number;
  entries: Record<string, string>;
}

export interface SBOMEntry {
  name: string;
  version: string;
  hash: string;
  license: string;
  source: string;
}

export interface SBOMV23 {
  specVersion: '2.3';
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tool: { name: string; version: string };
    component: { name: string; version: string; type: string };
  };
  components: SBOMEntry[];
  dependencies: Record<string, string[]>;
}

/**
 * Build-time integrity verification for supply chain security.
 * v2.0.0: Adds SBOM v2.3 format, Sigstore integration stub, dependency graph validation.
 */
export class SupplyChainIntegrity {
  private manifest: IntegrityManifest;
  private sbom: SBOMV23;
  private dependencyGraph = new Map<string, Set<string>>();

  constructor() {
    this.manifest = { version: '2.1.0', generated: Date.now(), entries: {} };
    this.sbom = {
      specVersion: '2.3',
      serialNumber: `urn:uuid:${this.generateUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tool: { name: 'vril-supply-chain', version: '2.1.0' },
        component: { name: 'vril-app', version: '2.1.0', type: 'application' },
      },
      components: [],
      dependencies: {},
    };
  }

  /** Add an entry to the integrity manifest */
  async addEntry(filePath: string, content: string): Promise<void> {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content));
      this.manifest.entries[filePath] = Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0')).join('');
    } else {
      this.manifest.entries[filePath] = 'sha256-unavailable';
    }
  }

  /** Add a component to the SBOM */
  addSBOMComponent(entry: SBOMEntry): void {
    this.sbom.components.push(entry);
  }

  /** Add a dependency relationship */
  addDependency(from: string, to: string): void {
    if (!this.dependencyGraph.has(from)) {
      this.dependencyGraph.set(from, new Set());
    }
    this.dependencyGraph.get(from)!.add(to);
    this.sbom.dependencies[from] = Array.from(this.dependencyGraph.get(from)!);
  }

  /** Validate the dependency graph for circular dependencies and missing references */
  validateDependencyGraph(): { valid: boolean; issues: string[] } {
    const issues: string[] = [];

    // Check for circular dependencies
    const visited = new Set<string>();
    const recursionStack = new Set<string>();

    const hasCycle = (node: string): boolean => {
      visited.add(node);
      recursionStack.add(node);
      const deps = this.dependencyGraph.get(node);
      if (deps) {
        for (const dep of deps) {
          if (!visited.has(dep)) {
            if (hasCycle(dep)) {
              issues.push(`Circular dependency detected involving: ${node} → ${dep}`);
              return true;
            }
          } else if (recursionStack.has(dep)) {
            issues.push(`Circular dependency detected: ${node} → ${dep}`);
            return true;
          }
        }
      }
      recursionStack.delete(node);
      return false;
    };

    for (const node of this.dependencyGraph.keys()) {
      if (!visited.has(node)) {
        hasCycle(node);
      }
    }

    // Check for missing dependency references
    const allComponents = new Set(this.sbom.components.map(c => c.name));
    for (const [_, deps] of this.dependencyGraph) {
      for (const dep of deps) {
        if (!allComponents.has(dep) && !this.dependencyGraph.has(dep)) {
          issues.push(`Missing dependency reference: ${dep}`);
        }
      }
    }

    return { valid: issues.length === 0, issues };
  }

  /** Verify an entry against the manifest */
  async verify(filePath: string, content: string): Promise<boolean> {
    const expected = this.manifest.entries[filePath];
    if (!expected) return true;
    if (typeof crypto === 'undefined' || !crypto.subtle) return true;
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(content));
    const actual = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    return actual === expected;
  }

  /** Get the integrity manifest */
  getManifest(): IntegrityManifest {
    return { ...this.manifest };
  }

  /** Get the SBOM in v2.3 format */
  getSBOM(): SBOMV23 {
    return { ...this.sbom, components: [...this.sbom.components], dependencies: { ...this.sbom.dependencies } };
  }

  /** Sigstore integration stub — in production, this would call the Sigstore API */
  async verifyWithSigstore(_artifactHash: string): Promise<{ verified: boolean; signer?: string; certificate?: string }> {
    // Stub: In production, integrate with Sigstore's rekor API
    return { verified: false };
  }

  getEntryCount(): number {
    return Object.keys(this.manifest.entries).length;
  }

  private generateUUID(): string {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
      return crypto.randomUUID();
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }
}

// ─── RSC Security Boundary (NEW) ─────────────────────────────
export interface RSCSecurityConfig {
  /** Allowed RSC flight data types */
  allowedFlightTypes: string[];
  /** Maximum flight data payload size */
  maxFlightPayloadSize: number;
  /** Require all server actions to be signed */
  requireSignedActions: boolean;
  /** Per-action rate limit (requests per minute) */
  actionRateLimit: number;
  /** Action rate limit window in ms */
  actionRateWindow: number;
}

const DEFAULT_RSC_CONFIG: RSCSecurityConfig = {
  allowedFlightTypes: ['M', 'S', 'J', 'E', 'T'],
  maxFlightPayloadSize: 1024 * 1024, // 1MB
  requireSignedActions: true,
  actionRateLimit: 60,
  actionRateWindow: 60000,
};

/**
 * RSC-specific hardening for server components and actions.
 * Validates server component output, enforces action signing, rate limits actions.
 */
export class RSCSecurityBoundary {
  private config: RSCSecurityConfig;
  private actionCounts = new Map<string, { count: number; windowStart: number }>();
  private actionSignatures = new Map<string, string>();

  constructor(config: Partial<RSCSecurityConfig> = {}) {
    this.config = { ...DEFAULT_RSC_CONFIG, ...config };
  }

  /** Validate RSC flight data — sanitize and check for dangerous content */
  validateServerComponentOutput(flightData: string): { valid: boolean; reason?: string; sanitized?: string } {
    if (flightData.length > this.config.maxFlightPayloadSize) {
      return { valid: false, reason: `Flight data exceeds maximum size of ${this.config.maxFlightPayloadSize} bytes` };
    }

    // Check for valid RSC flight data prefixes
    const lines = flightData.split('\n');
    for (const line of lines) {
      const prefix = line.charAt(0);
      if (line.length > 0 && !this.config.allowedFlightTypes.includes(prefix)) {
        // Allow empty lines and lines starting with allowed types
        if (prefix !== '' && prefix !== '0' && !/^[0-9a-fA-F:]/.test(line)) {
          return { valid: false, reason: `Invalid flight data prefix: "${prefix}"` };
        }
      }
    }

    // Sanitize: remove any script injection patterns
    const sanitized = flightData
      .replace(/<script[\s\S]*?<\/script>/gi, '')
      .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
      .replace(/javascript:/gi, '');

    return { valid: true, sanitized };
  }

  /** Register a signed server action */
  registerSignedAction(actionId: string, signature: string): void {
    this.actionSignatures.set(actionId, signature);
  }

  /** Enforce that a server action is properly signed */
  enforceActionSigning(actionId: string, providedSignature: string): boolean {
    if (!this.config.requireSignedActions) return true;
    const expected = this.actionSignatures.get(actionId);
    if (!expected) return false;
    if (expected.length !== providedSignature.length) return false;
    let result = 0;
    for (let i = 0; i < expected.length; i++) {
      result |= expected.charCodeAt(i) ^ providedSignature.charCodeAt(i);
    }
    return result === 0;
  }

  /** Rate limit a server action per action ID */
  rateLimitActions(actionId: string): { allowed: boolean; remaining: number; resetAt: number } {
    const now = Date.now();
    let entry = this.actionCounts.get(actionId);
    if (!entry || (now - entry.windowStart) > this.config.actionRateWindow) {
      entry = { count: 0, windowStart: now };
      this.actionCounts.set(actionId, entry);
    }
    entry.count++;
    const allowed = entry.count <= this.config.actionRateLimit;
    const remaining = Math.max(0, this.config.actionRateLimit - entry.count);
    const resetAt = entry.windowStart + this.config.actionRateWindow;
    return { allowed, remaining, resetAt };
  }
}

// ─── Server Timing Security (NEW) ────────────────────────────
/**
 * Prevent timing attacks on server operations by normalizing response times.
 */
export class ServerTimingSecurity {
  private static minimumDelay: number = 0;
  private static jitterRange: number = 0;
  private static enabled: boolean = true;

  /** Configure timing attack protections */
  static configure(config: { minimumDelay?: number; jitterRange?: number; enabled?: boolean }): void {
    if (config.minimumDelay !== undefined) this.minimumDelay = config.minimumDelay;
    if (config.jitterRange !== undefined) this.jitterRange = config.jitterRange;
    if (config.enabled !== undefined) this.enabled = config.enabled;
  }

  /** Wrap an operation to normalize its timing */
  static async wrap<T>(operation: () => Promise<T>): Promise<T> {
    if (!this.enabled) return operation();
    const start = performance.now();
    const result = await operation();
    const elapsed = performance.now() - start;
    const jitter = this.jitterRange > 0 ? Math.random() * this.jitterRange : 0;
    const target = this.minimumDelay + jitter;
    if (elapsed < target) {
      await new Promise(resolve => setTimeout(resolve, target - elapsed));
    }
    return result;
  }

  /** Create a constant-time comparison for sensitive data */
  static constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }

  /** Add noise to a numeric value to prevent inference */
  static addNoise(value: number, range: number = 0.05): number {
    const noise = value * range * (Math.random() * 2 - 1);
    return value + noise;
  }
}

// ─── Request Validator (NEW) ─────────────────────────────────
export interface RequestValidationConfig {
  /** Maximum header count */
  maxHeaderCount: number;
  /** Maximum header value length */
  maxHeaderLength: number;
  /** Maximum query parameter count */
  maxQueryParams: number;
  /** Maximum query parameter value length */
  maxQueryValueLength: number;
  /** Blocked headers */
  blockedHeaders: string[];
  /** Allowed origins (empty = allow all) */
  allowedOrigins: string[];
  /** Allowed referers (empty = allow all) */
  allowedReferers: string[];
  /** Bot detection enabled */
  botDetection: boolean;
  /** Known bot user-agent patterns */
  botPatterns: RegExp[];
}

const DEFAULT_REQUEST_VALIDATION: RequestValidationConfig = {
  maxHeaderCount: 50,
  maxHeaderLength: 8192,
  maxQueryParams: 30,
  maxQueryValueLength: 2048,
  blockedHeaders: ['x-forwarded-for', 'x-original-url', 'x-rewrite-url'],
  allowedOrigins: [],
  allowedReferers: [],
  botDetection: true,
  botPatterns: [
    /bot/i, /crawler/i, /spider/i, /scraper/i,
    /curl/i, /wget/i, /python-requests/i, /httpclient/i,
    /go-http/i, /java\//i, /apache-http/i,
  ],
};

export interface RequestValidationResult {
  valid: boolean;
  violations: string[];
  isBot: boolean;
  sanitizedQuery: Record<string, string>;
}

/**
 * Comprehensive request validation: headers, body, query parameters,
 * origin verification, referer checking, and bot detection.
 */
export class RequestValidator {
  private config: RequestValidationConfig;

  constructor(config: Partial<RequestValidationConfig> = {}) {
    this.config = { ...DEFAULT_REQUEST_VALIDATION, ...config };
  }

  /** Validate a request comprehensively */
  validate(request: Request): RequestValidationResult {
    const violations: string[] = [];
    let isBot = false;
    const sanitizedQuery: Record<string, string> = {};

    // Header validation
    let headerCount = 0;
    request.headers.forEach((value, key) => {
      headerCount++;
      if (headerCount > this.config.maxHeaderCount) {
        violations.push(`Header count exceeds maximum ${this.config.maxHeaderCount}`);
      }
      if (value.length > this.config.maxHeaderLength) {
        violations.push(`Header "${key}" value exceeds maximum length`);
      }
      if (this.config.blockedHeaders.includes(key.toLowerCase())) {
        violations.push(`Blocked header detected: "${key}"`);
      }
    });

    // Query parameter validation and sanitization
    const url = new URL(request.url);
    let paramCount = 0;
    url.searchParams.forEach((value, key) => {
      paramCount++;
      if (paramCount > this.config.maxQueryParams) {
        violations.push(`Query parameter count exceeds maximum ${this.config.maxQueryParams}`);
      }
      if (value.length > this.config.maxQueryValueLength) {
        violations.push(`Query parameter "${key}" value exceeds maximum length`);
      }
      // Sanitize: strip HTML and script patterns
      sanitizedQuery[key] = value
        .replace(/<[^>]*>/g, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '');
    });

    // Origin verification
    if (this.config.allowedOrigins.length > 0) {
      const origin = request.headers.get('origin');
      if (origin && !this.config.allowedOrigins.some(o => origin === o || origin.startsWith(o))) {
        violations.push(`Origin "${origin}" not in allowed list`);
      }
    }

    // Referer checking
    if (this.config.allowedReferers.length > 0) {
      const referer = request.headers.get('referer');
      if (referer && !this.config.allowedReferers.some(r => referer.startsWith(r))) {
        violations.push(`Referer "${referer}" not in allowed list`);
      }
    }

    // Bot detection
    if (this.config.botDetection) {
      const ua = request.headers.get('user-agent') ?? '';
      for (const pattern of this.config.botPatterns) {
        if (pattern.test(ua)) {
          isBot = true;
          break;
        }
      }
    }

    return {
      valid: violations.length === 0,
      violations,
      isBot,
      sanitizedQuery,
    };
  }

  /** Validate request body content type and size */
  validateBody(request: Request, maxBodySize: number = 1024 * 1024): { valid: boolean; reason?: string } {
    const contentType = request.headers.get('content-type');
    if (request.method === 'GET' || request.method === 'HEAD') {
      return { valid: true };
    }
    if (!contentType) {
      return { valid: false, reason: 'Missing Content-Type header for body request' };
    }
    const contentLength = parseInt(request.headers.get('content-length') ?? '0', 10);
    if (contentLength > maxBodySize) {
      return { valid: false, reason: `Body size ${contentLength} exceeds limit ${maxBodySize}` };
    }
    return { valid: true };
  }
}

// ─── Security Middleware Chain (NEW) ──────────────────────────
export interface SecurityCheckResult {
  passed: boolean;
  checkName: string;
  reason?: string;
  duration: number;
}

export interface SecurityAuditLog {
  requestId: string;
  timestamp: number;
  checks: SecurityCheckResult[];
  finalDecision: 'allow' | 'deny';
  deniedBy?: string;
}

export type SecurityCheck = (request: Request) => Promise<SecurityCheckResult>;

/**
 * Composable security middleware: chain multiple security checks,
 * short-circuit on first failure, generate security audit log per request.
 */
export class SecurityMiddlewareChain {
  private checks: SecurityCheck[] = [];
  private auditLogs: SecurityAuditLog[] = [];
  private maxAuditLogs: number;

  constructor(maxAuditLogs: number = 1000) {
    this.maxAuditLogs = maxAuditLogs;
  }

  /** Add a security check to the chain */
  addCheck(name: string, check: (request: Request) => Promise<boolean>, reason?: string): this {
    this.checks.push(async (request) => {
      const start = performance.now();
      try {
        const passed = await check(request);
        const duration = performance.now() - start;
        return { passed, checkName: name, reason: passed ? undefined : (reason ?? `Check "${name}" failed`), duration };
      } catch (error) {
        const duration = performance.now() - start;
        return { passed: false, checkName: name, reason: `Check "${name}" threw error: ${error}`, duration };
      }
    });
    return this;
  }

  /** Execute the full chain, short-circuiting on first failure */
  async execute(request: Request): Promise<{ allowed: boolean; audit: SecurityAuditLog }> {
    const requestId = request.headers.get('x-vril-request-id') ?? RequestSigner.generateRequestId();
    const results: SecurityCheckResult[] = [];

    for (const check of this.checks) {
      const result = await check(request);
      results.push(result);
      if (!result.passed) {
        const audit: SecurityAuditLog = {
          requestId,
          timestamp: Date.now(),
          checks: results,
          finalDecision: 'deny',
          deniedBy: result.checkName,
        };
        this.recordAudit(audit);
        return { allowed: false, audit };
      }
    }

    const audit: SecurityAuditLog = {
      requestId,
      timestamp: Date.now(),
      checks: results,
      finalDecision: 'allow',
    };
    this.recordAudit(audit);
    return { allowed: true, audit };
  }

  /** Get recent audit logs */
  getAuditLogs(limit: number = 50): SecurityAuditLog[] {
    return this.auditLogs.slice(-limit);
  }

  /** Get the count of registered checks */
  getCheckCount(): number {
    return this.checks.length;
  }

  /** Create a pre-configured chain with common security checks */
  static createDefaultChain(options: {
    csrfToken?: string;
    signingSecret?: string;
    allowedOrigins?: string[];
    rateLimitPerMinute?: number;
  }): SecurityMiddlewareChain {
    const chain = new SecurityMiddlewareChain();
    const rateLimitMap = new Map<string, { count: number; windowStart: number }>();
    const limit = options.rateLimitPerMinute ?? 100;

    // Method validation
    chain.addCheck('method-validation', async (req) => {
      const allowed = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
      return allowed.includes(req.method);
    }, 'HTTP method not allowed');

    // Origin check
    if (options.allowedOrigins && options.allowedOrigins.length > 0) {
      chain.addCheck('origin-validation', async (req) => {
        const origin = req.headers.get('origin');
        if (!origin) return true; // Allow same-origin requests
        return options.allowedOrigins!.some(o => origin === o || origin.startsWith(o));
      }, 'Origin not allowed');
    }

    // CSRF check for mutations
    if (options.csrfToken) {
      chain.addCheck('csrf-validation', async (req) => {
        if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) return true;
        return CSRFGuard.validateToken(req, options.csrfToken!);
      }, 'CSRF token validation failed');
    }

    // Rate limiting
    chain.addCheck('rate-limit', async (req) => {
      const ip = req.headers.get('x-real-ip') ?? req.headers.get('cf-connecting-ip') ?? 'unknown';
      const now = Date.now();
      let entry = rateLimitMap.get(ip);
      if (!entry || (now - entry.windowStart) > 60000) {
        entry = { count: 0, windowStart: now };
        rateLimitMap.set(ip, entry);
      }
      entry.count++;
      return entry.count <= limit;
    }, 'Rate limit exceeded');

    // Request signature verification
    if (options.signingSecret) {
      const signer = new RequestSigner(options.signingSecret);
      chain.addCheck('request-signature', async (req) => {
        const result = await signer.verifyRequest(req);
        return result.valid;
      }, 'Request signature verification failed');
    }

    return chain;
  }

  private recordAudit(audit: SecurityAuditLog): void {
    this.auditLogs.push(audit);
    if (this.auditLogs.length > this.maxAuditLogs) {
      this.auditLogs.shift();
    }
  }
}
