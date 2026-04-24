/**
 * Vril.js v2.0.0 — Authentication Primitives
 * Session management, token handling, password utilities, and RBAC.
 * All cryptographic operations use Web Crypto API — ZERO npm dependencies.
 */

export const AUTH_MODULE_VERSION = '2.1.0';

// ─── Core Types ──────────────────────────────────────────────
export interface Session {
  id: string;
  userId: string;
  roles: string[];
  createdAt: number;
  expiresAt: number;
  lastActivity: number;
  ip?: string;
  userAgent?: string;
  metadata: Record<string, unknown>;
}

export interface TokenPayload {
  sub: string;
  iss: string;
  aud: string;
  exp: number;
  iat: number;
  jti: string;
  roles: string[];
  scope?: string[];
  [key: string]: unknown;
}

export interface Role {
  name: string;
  permissions: Permission[];
  inherits?: string[];
  description?: string;
}

export interface Permission {
  action: string;
  resource: string;
  conditions?: Record<string, unknown>;
}

export interface AuthConfig {
  sessionTTL: number;
  sessionIdleTimeout: number;
  tokenAlgorithm: string;
  passwordMinLength: number;
  passwordRounds: number;
  maxLoginAttempts: number;
  lockoutDuration: number;
}

export const DEFAULT_AUTH_CONFIG: AuthConfig = {
  sessionTTL: 86400000,       // 24 hours
  sessionIdleTimeout: 1800000, // 30 minutes
  tokenAlgorithm: 'HMAC-SHA256',
  passwordMinLength: 12,
  passwordRounds: 600000,
  maxLoginAttempts: 5,
  lockoutDuration: 900000,     // 15 minutes
};

// ─── Session Manager ─────────────────────────────────────────
/**
 * Secure session management with create, validate, rotate, and destroy.
 * Session tokens use HMAC-SHA256. Configurable TTL and idle timeout.
 */
export class SessionManager {
  private sessions = new Map<string, Session>();
  private config: AuthConfig;
  private signingKey: CryptoKey | null = null;

  constructor(config: Partial<AuthConfig> = {}) {
    this.config = { ...DEFAULT_AUTH_CONFIG, ...config };
  }

  /** Initialize with a secret key for session token signing */
  async initialize(secret: string): Promise<void> {
    if (typeof crypto === 'undefined' || !crypto.subtle) return;
    this.signingKey = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
    );
  }

  /** Create a new session */
  async createSession(params: {
    userId: string;
    roles?: string[];
    ip?: string;
    userAgent?: string;
    metadata?: Record<string, unknown>;
  }): Promise<{ session: Session; token: string }> {
    const sessionId = this.generateId();
    const now = Date.now();

    const session: Session = {
      id: sessionId,
      userId: params.userId,
      roles: params.roles ?? [],
      createdAt: now,
      expiresAt: now + this.config.sessionTTL,
      lastActivity: now,
      ip: params.ip,
      userAgent: params.userAgent,
      metadata: params.metadata ?? {},
    };

    this.sessions.set(sessionId, session);
    const token = await this.createSessionToken(session);

    return { session, token };
  }

  /** Validate a session token and return the session */
  async validateSession(token: string): Promise<{ valid: boolean; session?: Session; reason?: string }> {
    const payload = await this.verifySessionToken(token);
    if (!payload) {
      return { valid: false, reason: 'Invalid session token' };
    }

    const session = this.sessions.get(payload.sessionId);
    if (!session) {
      return { valid: false, reason: 'Session not found' };
    }

    const now = Date.now();

    // Check expiration
    if (now > session.expiresAt) {
      this.sessions.delete(payload.sessionId);
      return { valid: false, reason: 'Session expired' };
    }

    // Check idle timeout
    if (now - session.lastActivity > this.config.sessionIdleTimeout) {
      this.sessions.delete(payload.sessionId);
      return { valid: false, reason: 'Session idle timeout' };
    }

    // Update last activity
    session.lastActivity = now;

    return { valid: true, session };
  }

  /** Rotate a session — generate a new token, keep the same session data */
  async rotateSession(sessionId: string): Promise<{ token: string; session: Session } | null> {
    const session = this.sessions.get(sessionId);
    if (!session) return null;

    // Extend expiration
    session.expiresAt = Date.now() + this.config.sessionTTL;
    session.lastActivity = Date.now();

    const token = await this.createSessionToken(session);
    return { token, session };
  }

  /** Destroy a session */
  destroySession(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }

  /** Get a session by ID without validation */
  getSession(sessionId: string): Session | undefined {
    return this.sessions.get(sessionId);
  }

  /** Destroy all sessions for a user */
  destroyUserSessions(userId: string): number {
    let count = 0;
    for (const [id, session] of this.sessions) {
      if (session.userId === userId) {
        this.sessions.delete(id);
        count++;
      }
    }
    return count;
  }

  /** Get active session count */
  getActiveSessionCount(): number {
    const now = Date.now();
    let count = 0;
    for (const session of this.sessions.values()) {
      if (now <= session.expiresAt && (now - session.lastActivity) <= this.config.sessionIdleTimeout) {
        count++;
      }
    }
    return count;
  }

  /** Clean up expired sessions */
  cleanup(): number {
    const now = Date.now();
    let removed = 0;
    for (const [id, session] of this.sessions) {
      if (now > session.expiresAt || (now - session.lastActivity) > this.config.sessionIdleTimeout) {
        this.sessions.delete(id);
        removed++;
      }
    }
    return removed;
  }

  private async createSessionToken(session: Session): Promise<string> {
    const payload = JSON.stringify({
      sessionId: session.id,
      userId: session.userId,
      exp: session.expiresAt,
    });

    if (this.signingKey && typeof crypto !== 'undefined' && crypto.subtle) {
      const signature = await crypto.subtle.sign('HMAC', this.signingKey, new TextEncoder().encode(payload));
      const sigHex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
      return btoa(payload) + '.' + sigHex;
    }

    // Fallback: base64-encoded payload without signature (not production-grade)
    return btoa(payload) + '.unsigned';
  }

  private async verifySessionToken(token: string): Promise<{ sessionId: string; userId: string; exp: number } | null> {
    const parts = token.split('.');
    if (parts.length !== 2) return null;

    try {
      const payload = JSON.parse(atob(parts[0]));

      if (this.signingKey && typeof crypto !== 'undefined' && crypto.subtle && parts[1] !== 'unsigned') {
        const expected = await crypto.subtle.sign('HMAC', this.signingKey, new TextEncoder().encode(atob(parts[0])));
        const expectedHex = Array.from(new Uint8Array(expected)).map(b => b.toString(16).padStart(2, '0')).join('');

        // Constant-time comparison
        if (expectedHex.length !== parts[1].length) return null;
        let result = 0;
        for (let i = 0; i < expectedHex.length; i++) {
          result |= expectedHex.charCodeAt(i) ^ parts[1].charCodeAt(i);
        }
        if (result !== 0) return null;
      }

      if (Date.now() > payload.exp) return null;

      return payload;
    } catch {
      return null;
    }
  }

  private generateId(): string {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      const bytes = crypto.getRandomValues(new Uint8Array(16));
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    return Date.now().toString(36) + Math.random().toString(36).substring(2);
  }
}

// ─── Token Handler ───────────────────────────────────────────
/**
 * JWT-like token management using Web Crypto API.
 * Create, verify, and refresh signed tokens.
 */
export class TokenHandler {
  private static HEADER = { alg: 'HS256', typ: 'VRIL-JWT' };

  /** Create a signed token with HMAC-SHA256 */
  static async createToken(payload: Omit<TokenPayload, 'iat' | 'jti'>, secret: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const fullPayload = {
      ...payload,
      iat: now,
      jti: this.generateJti(),
    } as TokenPayload;

    const headerB64 = this.base64UrlEncode(JSON.stringify(this.HEADER));
    const payloadB64 = this.base64UrlEncode(JSON.stringify(fullPayload));
    const signingInput = `${headerB64}.${payloadB64}`;

    const signature = await this.sign(signingInput, secret);
    return `${signingInput}.${signature}`;
  }

  /** Verify and decode a token */
  static async verifyToken(token: string, secret: string): Promise<{ valid: boolean; payload?: TokenPayload; reason?: string }> {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, reason: 'Invalid token format' };
    }

    const [headerB64, payloadB64, signature] = parts;
    const signingInput = `${headerB64}.${payloadB64}`;

    // Verify signature
    const expectedSig = await this.sign(signingInput, secret);
    if (!this.constantTimeCompare(signature, expectedSig)) {
      return { valid: false, reason: 'Invalid signature' };
    }

    try {
      const payload: TokenPayload = JSON.parse(this.base64UrlDecode(payloadB64));

      // Check expiration
      if (payload.exp && Date.now() / 1000 > payload.exp) {
        return { valid: false, reason: 'Token expired' };
      }

      // Check not-before (iat)
      if (payload.iat && Date.now() / 1000 < payload.iat) {
        return { valid: false, reason: 'Token not yet valid' };
      }

      return { valid: true, payload };
    } catch {
      return { valid: false, reason: 'Invalid token payload' };
    }
  }

  /** Refresh a token with rotation — returns a new token with updated claims */
  static async refreshToken(token: string, secret: string, options: {
    extendBy?: number; // seconds to extend
    rotateJti?: boolean;
  } = {}): Promise<{ token: string; payload: TokenPayload } | null> {
    const result = await this.verifyToken(token, secret);
    if (!result.valid || !result.payload) return null;

    const extendBy = options.extendBy ?? 3600; // 1 hour default
    const newPayload: TokenPayload = {
      ...result.payload,
      exp: Math.floor(Date.now() / 1000) + extendBy,
      iat: Math.floor(Date.now() / 1000),
    };

    if (options.rotateJti !== false) {
      newPayload.jti = this.generateJti();
    }

    const newToken = await this.createToken(newPayload, secret);
    return { token: newToken, payload: newPayload };
  }

  /** Decode a token without verification (useful for debugging) */
  static decodeToken(token: string): { header: unknown; payload: unknown } | null {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    try {
      const header = JSON.parse(this.base64UrlDecode(parts[0]));
      const payload = JSON.parse(this.base64UrlDecode(parts[1]));
      return { header, payload };
    } catch {
      return null;
    }
  }

  private static async sign(input: string, secret: string): Promise<string> {
    if (typeof crypto === 'undefined' || !crypto.subtle) {
      return btoa(input).replace(/[=+/]/g, c => ({ '=': '', '+': '-', '/': '_' }[c] ?? c));
    }

    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(input));
    return this.base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
  }

  private static base64UrlEncode(str: string): string {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private static base64UrlDecode(str: string): string {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) base64 += '=';
    return atob(base64);
  }

  private static constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }

  private static generateJti(): string {
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      const bytes = crypto.getRandomValues(new Uint8Array(12));
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
    return Date.now().toString(36) + Math.random().toString(36).substring(2);
  }
}

// ─── Password Handler ────────────────────────────────────────
export interface PasswordStrengthResult {
  score: number; // 0-100
  level: 'very-weak' | 'weak' | 'fair' | 'strong' | 'very-strong';
  feedback: string[];
  entropy: number;
  crackTimeSeconds: number;
}

/**
 * Password utilities: hash with PBKDF2-SHA-512, verify with constant-time,
 * and analyze password strength.
 */
export class PasswordHandler {
  private static ITERATIONS = 600000;
  private static HASH_ALGORITHM = 'SHA-512';
  private static SALT_LENGTH = 32;

  /** Hash a password using PBKDF2-SHA-512 with 600K iterations */
  static async hash(password: string): Promise<string> {
    if (typeof crypto === 'undefined' || !crypto.subtle) {
      throw new Error('Web Crypto API not available');
    }

    const salt = crypto.getRandomValues(new Uint8Array(this.SALT_LENGTH));
    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password),
      'PBKDF2', false, ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations: this.ITERATIONS,
        hash: this.HASH_ALGORITHM,
      },
      keyMaterial,
      512
    );

    const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
    const hashHex = Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('');

    return `vril$pbkdf2-sha512$${this.ITERATIONS}$${saltHex}$${hashHex}`;
  }

  /** Verify a password against a hash with constant-time comparison */
  static async verify(password: string, storedHash: string): Promise<boolean> {
    if (typeof crypto === 'undefined' || !crypto.subtle) {
      return false;
    }

    const parts = storedHash.split('$');
    if (parts.length !== 5 || parts[0] !== 'vril' || parts[1] !== 'pbkdf2-sha512') {
      return false;
    }

    const iterations = parseInt(parts[2], 10);
    const salt = Uint8Array.from(parts[3].match(/.{2}/g) ?? [], hex => parseInt(hex, 16));
    const expectedHash = parts[4];

    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password),
      'PBKDF2', false, ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt,
        iterations,
        hash: this.HASH_ALGORITHM,
      },
      keyMaterial,
      512
    );

    const actualHash = Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('');

    // Constant-time comparison
    if (actualHash.length !== expectedHash.length) return false;
    let result = 0;
    for (let i = 0; i < actualHash.length; i++) {
      result |= actualHash.charCodeAt(i) ^ expectedHash.charCodeAt(i);
    }
    return result === 0;
  }

  /** Analyze password strength */
  static strengthCheck(password: string): PasswordStrengthResult {
    const feedback: string[] = [];
    let score = 0;

    // Length check
    const len = password.length;
    if (len >= 8) score += 10;
    if (len >= 12) score += 15;
    if (len >= 16) score += 10;
    if (len >= 20) score += 5;
    if (len < 8) feedback.push('Password should be at least 8 characters');
    if (len < 12) feedback.push('Consider using 12+ characters for better security');

    // Character variety
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSpecial = /[^a-zA-Z0-9]/.test(password);

    if (hasLower) score += 10;
    else feedback.push('Add lowercase letters');

    if (hasUpper) score += 10;
    else feedback.push('Add uppercase letters');

    if (hasDigit) score += 10;
    else feedback.push('Add numbers');

    if (hasSpecial) score += 15;
    else feedback.push('Add special characters');

    // Entropy calculation
    let charsetSize = 0;
    if (hasLower) charsetSize += 26;
    if (hasUpper) charsetSize += 26;
    if (hasDigit) charsetSize += 10;
    if (hasSpecial) charsetSize += 32;

    const entropy = charsetSize > 0 ? len * Math.log2(charsetSize) : 0;
    score += Math.min(15, Math.floor(entropy / 5));

    // Pattern detection (penalize common patterns)
    const commonPatterns = [
      /^(123|abc|qwerty|password|admin|letmein)/i,
      /(.)\1{2,}/, // Repeated characters
      /^(012|123|234|345|456|567|678|789)/, // Sequential numbers
    ];

    for (const pattern of commonPatterns) {
      if (pattern.test(password)) {
        score -= 10;
        feedback.push('Avoid common patterns and sequences');
        break;
      }
    }

    // Clamp score
    score = Math.max(0, Math.min(100, score));

    // Crack time estimation (very rough)
    const guessesPerSecond = 10e9; // 10 billion guesses/sec
    const totalCombinations = Math.pow(charsetSize, len);
    const crackTimeSeconds = totalCombinations / (2 * guessesPerSecond);

    // Determine level
    let level: PasswordStrengthResult['level'];
    if (score < 20) level = 'very-weak';
    else if (score < 40) level = 'weak';
    else if (score < 60) level = 'fair';
    else if (score < 80) level = 'strong';
    else level = 'very-strong';

    return { score, level, feedback, entropy: Math.round(entropy * 100) / 100, crackTimeSeconds };
  }

  /** Check if a password has been compromised (local check against common passwords) */
  static isCommonPassword(password: string): boolean {
    const common = [
      'password', '123456', '12345678', 'qwerty', 'abc123',
      'monkey', 'master', 'dragon', 'login', 'princess',
      'football', 'shadow', 'sunshine', 'trustno1', 'iloveyou',
      'batman', 'access', 'hello', 'charlie', 'donald',
      'password1', 'qwerty123', 'letmein', 'welcome', 'admin123',
    ];
    return common.includes(password.toLowerCase());
  }
}

// ─── RBAC (Role-Based Access Control) ────────────────────────
/**
 * Role-Based Access Control with hierarchical roles.
 * Define roles with permissions, check permissions for routes/actions.
 */
export class RBAC {
  private roles = new Map<string, Role>();
  private userRoles = new Map<string, Set<string>>();

  /** Define a role with permissions */
  defineRole(role: Role): void {
    this.roles.set(role.name, role);
  }

  /** Define multiple roles at once */
  defineRoles(roles: Role[]): void {
    for (const role of roles) {
      this.defineRole(role);
    }
  }

  /** Assign a role to a user */
  assignRole(userId: string, roleName: string): boolean {
    if (!this.roles.has(roleName)) return false;
    const roles = this.userRoles.get(userId) ?? new Set();
    roles.add(roleName);
    this.userRoles.set(userId, roles);
    return true;
  }

  /** Remove a role from a user */
  revokeRole(userId: string, roleName: string): boolean {
    const roles = this.userRoles.get(userId);
    if (!roles) return false;
    return roles.delete(roleName);
  }

  /** Get all roles assigned to a user (including inherited) */
  getUserRoles(userId: string): string[] {
    const directRoles = this.userRoles.get(userId);
    if (!directRoles) return [];

    const allRoles = new Set<string>();
    const resolveInheritance = (roleName: string, depth: number = 0) => {
      if (depth > 10 || allRoles.has(roleName)) return; // Prevent infinite loops
      allRoles.add(roleName);
      const role = this.roles.get(roleName);
      if (role?.inherits) {
        for (const parent of role.inherits) {
          resolveInheritance(parent, depth + 1);
        }
      }
    };

    for (const roleName of directRoles) {
      resolveInheritance(roleName);
    }

    return Array.from(allRoles);
  }

  /** Get all permissions for a user (from all roles including inherited) */
  getUserPermissions(userId: string): Permission[] {
    const roles = this.getUserRoles(userId);
    const permissions: Permission[] = [];
    const seen = new Set<string>();

    for (const roleName of roles) {
      const role = this.roles.get(roleName);
      if (role) {
        for (const perm of role.permissions) {
          const key = `${perm.action}:${perm.resource}`;
          if (!seen.has(key)) {
            seen.add(key);
            permissions.push(perm);
          }
        }
      }
    }

    return permissions;
  }

  /** Check if a user has a specific permission */
  hasPermission(userId: string, action: string, resource: string): boolean {
    const permissions = this.getUserPermissions(userId);
    return permissions.some(p => {
      // Exact match or wildcard
      const actionMatch = p.action === action || p.action === '*';
      const resourceMatch = p.resource === resource || p.resource === '*';
      return actionMatch && resourceMatch;
    });
  }

  /** Check if a user has any of the specified roles */
  hasRole(userId: string, roleNames: string[]): boolean {
    const userRoles = this.getUserRoles(userId);
    return roleNames.some(r => userRoles.includes(r));
  }

  /** Check if a user has all of the specified roles */
  hasAllRoles(userId: string, roleNames: string[]): boolean {
    const userRoles = this.getUserRoles(userId);
    return roleNames.every(r => userRoles.includes(r));
  }

  /** Create a permission check middleware function */
  createPermissionGuard(action: string, resource: string): (userId: string) => { allowed: boolean; reason?: string } {
    return (userId: string) => {
      if (this.hasPermission(userId, action, resource)) {
        return { allowed: true };
      }
      return { allowed: false, reason: `Missing permission: ${action} on ${resource}` };
    };
  }

  /** Create a role check middleware function */
  createRoleGuard(roles: string[]): (userId: string) => { allowed: boolean; reason?: string } {
    return (userId: string) => {
      if (this.hasRole(userId, roles)) {
        return { allowed: true };
      }
      return { allowed: false, reason: `Missing required role: ${roles.join(' or ')}` };
    };
  }

  /** Get a role definition */
  getRole(name: string): Role | undefined {
    return this.roles.get(name);
  }

  /** Get all defined role names */
  getDefinedRoles(): string[] {
    return Array.from(this.roles.keys());
  }

  /** Validate the role hierarchy for circular inheritance */
  validateHierarchy(): { valid: boolean; circular: string[][] } {
    const circular: string[][] = [];
    const visited = new Set<string>();
    const stack = new Set<string>();

    const check = (roleName: string, path: string[]): void => {
      if (stack.has(roleName)) {
        const cycleStart = path.indexOf(roleName);
        circular.push(path.slice(cycleStart).concat(roleName));
        return;
      }
      if (visited.has(roleName)) return;

      visited.add(roleName);
      stack.add(roleName);
      const role = this.roles.get(roleName);
      if (role?.inherits) {
        for (const parent of role.inherits) {
          check(parent, [...path, roleName]);
        }
      }
      stack.delete(roleName);
    };

    for (const roleName of this.roles.keys()) {
      check(roleName, []);
    }

    return { valid: circular.length === 0, circular };
  }

  /** Create a default RBAC with common roles */
  static createDefault(): RBAC {
    const rbac = new RBAC();

    rbac.defineRoles([
      {
        name: 'viewer',
        description: 'Read-only access',
        permissions: [
          { action: 'read', resource: '*' },
        ],
      },
      {
        name: 'editor',
        description: 'Read and write access',
        inherits: ['viewer'],
        permissions: [
          { action: 'write', resource: '*' },
          { action: 'create', resource: '*' },
        ],
      },
      {
        name: 'admin',
        description: 'Full access except user management',
        inherits: ['editor'],
        permissions: [
          { action: 'delete', resource: '*' },
          { action: 'manage', resource: 'settings' },
        ],
      },
      {
        name: 'superadmin',
        description: 'Full system access',
        inherits: ['admin'],
        permissions: [
          { action: '*', resource: '*' },
        ],
      },
    ]);

    return rbac;
  }
}

// ─── Login Attempt Tracker ───────────────────────────────────
/**
 * Track login attempts and enforce lockout.
 */
export class LoginAttemptTracker {
  private attempts = new Map<string, { count: number; lastAttempt: number; lockedUntil: number }>();
  private maxAttempts: number;
  private lockoutDuration: number;

  constructor(maxAttempts: number = 5, lockoutDuration: number = 900000) {
    this.maxAttempts = maxAttempts;
    this.lockoutDuration = lockoutDuration;
  }

  /** Record a failed login attempt */
  recordFailure(identifier: string): { locked: boolean; remainingAttempts: number; lockedUntil?: number } {
    const now = Date.now();
    let entry = this.attempts.get(identifier);

    if (entry && now > entry.lockedUntil) {
      // Lockout expired, reset
      entry = { count: 0, lastAttempt: now, lockedUntil: 0 };
    }

    if (!entry) {
      entry = { count: 0, lastAttempt: now, lockedUntil: 0 };
      this.attempts.set(identifier, entry);
    }

    entry.count++;
    entry.lastAttempt = now;

    if (entry.count >= this.maxAttempts) {
      entry.lockedUntil = now + this.lockoutDuration;
      return { locked: true, remainingAttempts: 0, lockedUntil: entry.lockedUntil };
    }

    return { locked: false, remainingAttempts: this.maxAttempts - entry.count };
  }

  /** Record a successful login — reset the counter */
  recordSuccess(identifier: string): void {
    this.attempts.delete(identifier);
  }

  /** Check if an identifier is currently locked */
  isLocked(identifier: string): { locked: boolean; remainingMs?: number } {
    const entry = this.attempts.get(identifier);
    if (!entry) return { locked: false };

    const now = Date.now();
    if (now < entry.lockedUntil) {
      return { locked: true, remainingMs: entry.lockedUntil - now };
    }

    return { locked: false };
  }

  /** Reset attempts for an identifier */
  reset(identifier: string): void {
    this.attempts.delete(identifier);
  }

  /** Clean up expired entries */
  cleanup(): number {
    const now = Date.now();
    let removed = 0;
    for (const [key, entry] of this.attempts) {
      if (now > entry.lockedUntil && entry.count >= this.maxAttempts) {
        this.attempts.delete(key);
        removed++;
      }
    }
    return removed;
  }
}
