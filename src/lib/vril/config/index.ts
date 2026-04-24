/**
 * Vril.js v2.0.0 — Framework Configuration System
 * Type-safe configuration builder with validation, deep merging,
 * environment-specific configs, secrets management, and config watching.
 */

export const CONFIG_MODULE_VERSION = '2.1.0';

// ─── Core Types ──────────────────────────────────────────────
export type Environment = 'development' | 'staging' | 'production' | 'test';

export interface ConfigValidationResult {
  valid: boolean;
  errors: ConfigValidationError[];
  warnings: ConfigValidationWarning[];
}

export interface ConfigValidationError {
  path: string;
  message: string;
  value?: unknown;
}

export interface ConfigValidationWarning {
  path: string;
  message: string;
  suggestion?: string;
}

// ─── Configuration Schema ────────────────────────────────────
export interface ConfigSchemaField {
  type: 'string' | 'number' | 'boolean' | 'object' | 'array' | 'enum';
  required?: boolean;
  default?: unknown;
  enum?: unknown[];
  min?: number;
  max?: number;
  pattern?: RegExp;
  description?: string;
  env?: string; // Environment variable name
  secret?: boolean; // Mark as secret (will be encrypted)
}

export interface ConfigSchema {
  [key: string]: ConfigSchemaField | ConfigSchema;
}

// ─── Full Configuration ──────────────────────────────────────
export interface SecurityConfig {
  trustedTypes: boolean;
  apiMembrane: boolean;
  blockedAPIs: string[];
  csp: {
    defaultSrc: string[];
    scriptSrc: string[];
    styleSrc: string[];
    fontSrc: string[];
    imgSrc: string[];
    connectSrc: string[];
    frameSrc: string[];
    objectSrc: string[];
    baseUri: string[];
    formAction: string[];
    frameAncestors: string[];
    upgradeInsecureRequests: boolean;
    blockAllMixedContent: boolean;
    reportTo?: string;
  };
  permissionsPolicy: Record<string, string[]>;
  headers: {
    strictTransportSecurity: string;
    xContentTypeOptions: string;
    xFrameOptions: string;
    referrerPolicy: string;
    crossOriginOpenerPolicy: string;
    crossOriginEmbedderPolicy: string;
    crossOriginResourcePolicy: string;
    permissionsPolicy?: string;
    contentSecurityPolicy?: string;
  };
  csrf: {
    enabled: boolean;
    tokenHeader: string;
    cookieName: string;
    sameSite: 'Strict' | 'Lax' | 'None';
    doubleSubmit: boolean;
    tokenRotation: boolean;
  };
}

export interface CryptoConfig {
  defaultAlgorithm: 'aes-256-gcm' | 'x25519-mlkem768';
  kdfIterations: number;
  pqcEnabled: boolean;
  hybridMode: boolean;
  keyRotationDays: number;
}

export interface RouterConfig {
  defaultRateLimit: number;
  defaultMaxBodySize: number;
  strictOriginValidation: boolean;
  botDetection: boolean;
  corsOrigins: string[];
}

export interface BuildConfig {
  cspNonce: boolean;
  sriHashes: boolean;
  securityHeaders: boolean;
  sbom: boolean;
  strictMode: boolean;
}

export interface ServerConfig {
  port: number;
  host: string;
  https: boolean;
  hstsMaxAge: number;
  requestTimeout: number;
  maxRequestSize: number;
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

export interface VrilFullConfig {
  version: string;
  environment: Environment;
  security: SecurityConfig;
  crypto: CryptoConfig;
  router: RouterConfig;
  build: BuildConfig;
  server: ServerConfig;
  auth: AuthConfig;
  signals: {
    enabled: boolean;
  };
  [key: string]: unknown;
}

// ─── Default Configurations ──────────────────────────────────
const DEFAULT_SECURITY: SecurityConfig = {
  trustedTypes: true,
  apiMembrane: true,
  blockedAPIs: ['WebTransport', 'RTCPeerConnection'],
  csp: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    imgSrc: ["'self'", "data:"],
    connectSrc: ["'self'"],
    frameSrc: ["'none'"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"],
    upgradeInsecureRequests: true,
    blockAllMixedContent: true,
  },
  permissionsPolicy: {
    gpu: [], camera: [], microphone: [], usb: [], serial: [],
    bluetooth: [], hid: [], geolocation: [], payment: [],
    'xr-spatial-tracking': [], 'compute-pressure': [],
  },
  headers: {
    strictTransportSecurity: 'max-age=63072000; includeSubDomains; preload',
    xContentTypeOptions: 'nosniff',
    xFrameOptions: 'DENY',
    referrerPolicy: 'strict-origin-when-cross-origin',
    crossOriginOpenerPolicy: 'same-origin',
    crossOriginEmbedderPolicy: 'credentialless',
    crossOriginResourcePolicy: 'same-origin',
  },
  csrf: {
    enabled: true,
    tokenHeader: 'x-vril-csrf',
    cookieName: 'vril-csrf',
    sameSite: 'Strict',
    doubleSubmit: true,
    tokenRotation: true,
  },
};

const DEFAULT_CRYPTO: CryptoConfig = {
  defaultAlgorithm: 'aes-256-gcm',
  kdfIterations: 600000,
  pqcEnabled: true,
  hybridMode: true,
  keyRotationDays: 90,
};

const DEFAULT_ROUTER: RouterConfig = {
  defaultRateLimit: 100,
  defaultMaxBodySize: 1024 * 1024,
  strictOriginValidation: false,
  botDetection: true,
  corsOrigins: [],
};

const DEFAULT_BUILD: BuildConfig = {
  cspNonce: true,
  sriHashes: true,
  securityHeaders: true,
  sbom: false,
  strictMode: true,
};

const DEFAULT_SERVER: ServerConfig = {
  port: 3000,
  host: '0.0.0.0',
  https: false,
  hstsMaxAge: 63072000,
  requestTimeout: 30000,
  maxRequestSize: 10 * 1024 * 1024,
};

const DEFAULT_AUTH: AuthConfig = {
  sessionTTL: 86400000, // 24 hours
  sessionIdleTimeout: 1800000, // 30 minutes
  tokenAlgorithm: 'HMAC-SHA256',
  passwordMinLength: 12,
  passwordRounds: 600000,
  maxLoginAttempts: 5,
  lockoutDuration: 900000, // 15 minutes
};

/** Full default configuration */
export const DEFAULT_FULL_CONFIG: VrilFullConfig = {
  version: '2.1.0',
  environment: 'development',
  security: DEFAULT_SECURITY,
  crypto: DEFAULT_CRYPTO,
  router: DEFAULT_ROUTER,
  build: DEFAULT_BUILD,
  server: DEFAULT_SERVER,
  auth: DEFAULT_AUTH,
  signals: { enabled: true },
};

// ─── Preset Configurations ───────────────────────────────────
/** SPA preset — minimal security for client-rendered apps */
export const SPA_PRESET: Partial<VrilFullConfig> = {
  security: {
    ...DEFAULT_SECURITY,
    csp: {
      ...DEFAULT_SECURITY.csp,
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
    },
  },
  build: { ...DEFAULT_BUILD, sriHashes: false, cspNonce: false },
  server: { ...DEFAULT_SERVER, https: false },
};

/** SSR preset — full security for server-rendered apps */
export const SSR_PRESET: Partial<VrilFullConfig> = {
  security: DEFAULT_SECURITY,
  build: DEFAULT_BUILD,
  server: { ...DEFAULT_SERVER, https: true },
  auth: DEFAULT_AUTH,
};

/** Static preset — security for statically generated sites */
export const STATIC_PRESET: Partial<VrilFullConfig> = {
  security: {
    ...DEFAULT_SECURITY,
    csrf: { ...DEFAULT_SECURITY.csrf, enabled: false },
  },
  build: DEFAULT_BUILD,
  server: { ...DEFAULT_SERVER, https: true },
};

/** API-only preset — security for API servers */
export const API_PRESET: Partial<VrilFullConfig> = {
  security: {
    ...DEFAULT_SECURITY,
    csp: {
      ...DEFAULT_SECURITY.csp,
      scriptSrc: ["'none'"],
      styleSrc: ["'none'"],
      frameSrc: ["'none'"],
    },
  },
  router: {
    ...DEFAULT_ROUTER,
    defaultRateLimit: 60,
    strictOriginValidation: true,
  },
  auth: DEFAULT_AUTH,
  server: { ...DEFAULT_SERVER, https: true, requestTimeout: 10000 },
};

// ─── Config Validator ────────────────────────────────────────
/**
 * Validate configuration values against a schema.
 */
export class ConfigValidator {
  private schema: ConfigSchema;

  constructor(schema: ConfigSchema) {
    this.schema = schema;
  }

  /** Validate a config object against the schema */
  validate(config: Record<string, unknown>): ConfigValidationResult {
    const errors: ConfigValidationError[] = [];
    const warnings: ConfigValidationWarning[] = [];

    this.validateObject(config, this.schema, '', errors, warnings);

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  private validateObject(
    obj: Record<string, unknown>,
    schema: ConfigSchema,
    path: string,
    errors: ConfigValidationError[],
    warnings: ConfigValidationWarning[]
  ): void {
    for (const [key, field] of Object.entries(schema)) {
      const currentPath = path ? `${path}.${key}` : key;
      const value = obj[key];

      // Check if field is a nested schema
      if (this.isSchema(field)) {
        if (value === undefined || value === null) {
          errors.push({ path: currentPath, message: `Missing required config section: ${currentPath}` });
          continue;
        }
        if (typeof value === 'object' && !Array.isArray(value)) {
          this.validateObject(value as Record<string, unknown>, field as ConfigSchema, currentPath, errors, warnings);
        } else {
          errors.push({ path: currentPath, message: `Expected object, got ${typeof value}`, value });
        }
        continue;
      }

      const f = field as ConfigSchemaField;

      // Required check
      if (f.required && (value === undefined || value === null)) {
        errors.push({ path: currentPath, message: `Required field "${currentPath}" is missing` });
        continue;
      }

      // Skip further validation if not provided and has default
      if (value === undefined || value === null) {
        if (f.default !== undefined) {
          // Warning about using default
          warnings.push({ path: currentPath, message: `Using default value for "${currentPath}"`, suggestion: `Set explicitly in config` });
        }
        continue;
      }

      // Type check
      const actualType = Array.isArray(value) ? 'array' : typeof value;
      if (f.type !== actualType) {
        errors.push({ path: currentPath, message: `Expected type "${f.type}", got "${actualType}"`, value });
        continue;
      }

      // Enum check
      if (f.enum && !f.enum.includes(value)) {
        errors.push({ path: currentPath, message: `Value must be one of: ${f.enum.join(', ')}`, value });
      }

      // Number range checks
      if (f.type === 'number') {
        if (f.min !== undefined && (value as number) < f.min) {
          errors.push({ path: currentPath, message: `Value must be at least ${f.min}`, value });
        }
        if (f.max !== undefined && (value as number) > f.max) {
          errors.push({ path: currentPath, message: `Value must be at most ${f.max}`, value });
        }
      }

      // Pattern check for strings
      if (f.type === 'string' && f.pattern && !f.pattern.test(value as string)) {
        errors.push({ path: currentPath, message: `Value does not match pattern ${f.pattern}`, value });
      }

      // Security warnings
      if (f.secret && typeof value === 'string' && value.length < 16) {
        warnings.push({ path: currentPath, message: 'Secret value is too short (minimum 16 characters recommended)', suggestion: 'Use a longer, randomly generated secret' });
      }
    }
  }

  private isSchema(field: ConfigSchemaField | ConfigSchema): boolean {
    return !('type' in field);
  }
}

// ─── Config Merger ───────────────────────────────────────────
export interface MergeConflictResolution {
  strategy: 'source-wins' | 'target-wins' | 'concat-arrays' | 'merge-deep';
  customResolver?: (path: string, targetValue: unknown, sourceValue: unknown) => unknown;
}

/**
 * Deep merge configs with conflict resolution.
 */
export class ConfigMerger {
  private resolution: MergeConflictResolution;

  constructor(resolution: MergeConflictResolution = { strategy: 'source-wins' }) {
    this.resolution = resolution;
  }

  /** Deep merge two config objects */
  merge<T extends Record<string, unknown>>(target: T, source: Partial<T>): T {
    return this.deepMerge(target, source, '') as T;
  }

  private deepMerge(target: unknown, source: unknown, path: string): unknown {
    if (source === null || source === undefined) return target;
    if (target === null || target === undefined) return source;

    if (Array.isArray(source)) {
      if (this.resolution.strategy === 'concat-arrays' && Array.isArray(target)) {
        return [...target, ...source];
      }
      return source;
    }

    if (typeof source === 'object' && typeof target === 'object') {
      const result: Record<string, unknown> = { ...(target as Record<string, unknown>) };
      for (const key of Object.keys(source as Record<string, unknown>)) {
        const currentPath = path ? `${path}.${key}` : key;
        const sourceVal = (source as Record<string, unknown>)[key];
        const targetVal = (target as Record<string, unknown>)[key];

        if (this.resolution.customResolver && sourceVal !== undefined && targetVal !== undefined) {
          result[key] = this.resolution.customResolver(currentPath, targetVal, sourceVal);
        } else if (sourceVal !== undefined && targetVal !== undefined && typeof sourceVal === 'object' && typeof targetVal === 'object' && !Array.isArray(sourceVal)) {
          result[key] = this.deepMerge(targetVal, sourceVal, currentPath);
        } else {
          switch (this.resolution.strategy) {
            case 'target-wins':
              result[key] = targetVal !== undefined ? targetVal : sourceVal;
              break;
            case 'source-wins':
            default:
              result[key] = sourceVal !== undefined ? sourceVal : targetVal;
              break;
          }
        }
      }
      return result;
    }

    return this.resolution.strategy === 'target-wins' ? target : source;
  }

  /** Merge multiple config objects in sequence */
  mergeAll<T extends Record<string, unknown>>(base: T, ...overrides: Partial<T>[]): T {
    let result = base;
    for (const override of overrides) {
      result = this.merge(result, override);
    }
    return result;
  }
}

// ─── Environment Config ──────────────────────────────────────
/**
 * Environment-specific configuration (dev/staging/prod).
 */
export class EnvironmentConfig {
  private configs = new Map<Environment, Partial<VrilFullConfig>>();
  private currentEnv: Environment = 'development';

  /** Set configuration for a specific environment */
  set(env: Environment, config: Partial<VrilFullConfig>): void {
    this.configs.set(env, config);
  }

  /** Set the current environment */
  setEnvironment(env: Environment): void {
    this.currentEnv = env;
  }

  /** Get the current environment */
  getEnvironment(): Environment {
    return this.currentEnv;
  }

  /** Get configuration for the current environment */
  getConfig(): Partial<VrilFullConfig> {
    return this.configs.get(this.currentEnv) ?? {};
  }

  /** Get configuration for a specific environment */
  getConfigFor(env: Environment): Partial<VrilFullConfig> {
    return this.configs.get(env) ?? {};
  }

  /** Resolve the full config by merging base with environment overrides */
  resolve(base: VrilFullConfig): VrilFullConfig {
    const envConfig = this.getConfig();
    const merger = new ConfigMerger({ strategy: 'source-wins' });
    return merger.merge(base, envConfig);
  }

  /** Detect environment from NODE_ENV or process.env */
  static detectEnvironment(): Environment {
    if (typeof process !== 'undefined' && process.env) {
      const env: string = (process.env.NODE_ENV ?? process.env.VRIL_ENV ?? '') as string;
      if (env === 'production' || env === 'prod') return 'production';
      if (env === 'staging' || env === 'stage') return 'staging';
      if (env === 'test' || env === 'testing') return 'test';
    }
    return 'development';
  }

  /** Create environment config with common presets */
  static createWithPresets(): EnvironmentConfig {
    const envConfig = new EnvironmentConfig();

    envConfig.set('development', {
      environment: 'development',
      security: {
        ...DEFAULT_SECURITY,
        csp: {
          ...DEFAULT_SECURITY.csp,
          scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        },
      },
      server: { ...DEFAULT_SERVER, https: false },
      build: { ...DEFAULT_BUILD, strictMode: false },
    });

    envConfig.set('staging', {
      environment: 'staging',
      security: DEFAULT_SECURITY,
      server: { ...DEFAULT_SERVER, https: true },
      build: DEFAULT_BUILD,
    });

    envConfig.set('production', {
      environment: 'production',
      security: DEFAULT_SECURITY,
      crypto: { ...DEFAULT_CRYPTO, keyRotationDays: 30 },
      server: { ...DEFAULT_SERVER, https: true },
      build: DEFAULT_BUILD,
      auth: { ...DEFAULT_AUTH, maxLoginAttempts: 3, lockoutDuration: 1800000 },
    });

    envConfig.set('test', {
      environment: 'test',
      security: {
        ...DEFAULT_SECURITY,
        csrf: { ...DEFAULT_SECURITY.csrf, enabled: false },
      },
      auth: { ...DEFAULT_AUTH, maxLoginAttempts: 100 },
    });

    return envConfig;
  }
}

// ─── Config Secrets ──────────────────────────────────────────
export interface SecretEntry {
  key: string;
  encrypted: string;
  version: number;
}

/**
 * Manage secrets in config with encryption.
 */
export class ConfigSecrets {
  private secrets = new Map<string, SecretEntry>();
  private key: CryptoKey | null = null;
  private version = 1;

  /** Initialize with a master encryption key */
  async initialize(masterKey: string): Promise<void> {
    if (typeof crypto === 'undefined' || !crypto.subtle) return;
    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(masterKey),
      'PBKDF2', false, ['deriveKey']
    );
    this.key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: new TextEncoder().encode('vril-config-secrets'), iterations: 100000, hash: 'SHA-256' },
      keyMaterial, { name: 'AES-GCM', length: 256 },
      false, ['encrypt', 'decrypt']
    );
  }

  /** Set an encrypted secret */
  async setSecret(key: string, value: string): Promise<void> {
    if (!this.key) throw new Error('ConfigSecrets not initialized');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, this.key, new TextEncoder().encode(value)
    );
    const combined = new Uint8Array(iv.length + new Uint8Array(encrypted).length);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    this.secrets.set(key, {
      key,
      encrypted: btoa(String.fromCharCode(...combined)),
      version: this.version,
    });
  }

  /** Get and decrypt a secret */
  async getSecret(key: string): Promise<string | null> {
    const entry = this.secrets.get(key);
    if (!entry || !this.key) return null;

    const combined = Uint8Array.from(atob(entry.encrypted), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const data = combined.slice(12);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv }, this.key, data
    );
    return new TextDecoder().decode(decrypted);
  }

  /** Check if a secret exists */
  hasSecret(key: string): boolean {
    return this.secrets.has(key);
  }

  /** List all secret keys (without decrypting) */
  listSecrets(): string[] {
    return Array.from(this.secrets.keys());
  }

  /** Delete a secret */
  deleteSecret(key: string): boolean {
    return this.secrets.delete(key);
  }

  /** Export secrets as a JSON-safe object (encrypted values only) */
  exportSecrets(): Record<string, SecretEntry> {
    const result: Record<string, SecretEntry> = {};
    for (const [key, entry] of this.secrets) {
      result[key] = { ...entry };
    }
    return result;
  }

  /** Import secrets from a previously exported object */
  importSecrets(data: Record<string, SecretEntry>): void {
    for (const [key, entry] of Object.entries(data)) {
      this.secrets.set(key, entry);
    }
  }
}

// ─── Config Watcher ──────────────────────────────────────────
export type ConfigChangeListener = (key: string, oldValue: unknown, newValue: unknown) => void;

/**
 * Watch for configuration changes (file-based or environment).
 * In edge/serverless environments, this watches environment variables.
 */
export class ConfigWatcher {
  private listeners = new Map<string, ConfigChangeListener[]>();
  private globalListeners: ConfigChangeListener[] = [];
  private currentValues = new Map<string, unknown>();
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private watchingEnv = false;

  /** Register a listener for a specific config key */
  on(key: string, listener: ConfigChangeListener): void {
    const existing = this.listeners.get(key) ?? [];
    existing.push(listener);
    this.listeners.set(key, existing);
  }

  /** Register a listener for any config change */
  onAnyChange(listener: ConfigChangeListener): void {
    this.globalListeners.push(listener);
  }

  /** Remove a listener */
  off(key: string, listener: ConfigChangeListener): void {
    const existing = this.listeners.get(key);
    if (existing) {
      this.listeners.set(key, existing.filter(l => l !== listener));
    }
  }

  /** Start watching environment variables for changes */
  watchEnvironment(keys: string[], intervalMs: number = 5000): void {
    if (this.watchingEnv) return;
    this.watchingEnv = true;

    // Initialize current values
    for (const key of keys) {
      this.currentValues.set(key, this.getEnvValue(key));
    }

    this.intervalId = setInterval(() => {
      for (const key of keys) {
        const oldValue = this.currentValues.get(key);
        const newValue = this.getEnvValue(key);
        if (oldValue !== newValue) {
          this.currentValues.set(key, newValue);
          this.notifyListeners(key, oldValue, newValue);
        }
      }
    }, intervalMs);
  }

  /** Stop watching */
  stopWatching(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    this.watchingEnv = false;
  }

  /** Manually trigger a change notification */
  notifyChange(key: string, oldValue: unknown, newValue: unknown): void {
    this.notifyListeners(key, oldValue, newValue);
  }

  /** Set the current snapshot of config values */
  setSnapshot(values: Record<string, unknown>): void {
    for (const [key, value] of Object.entries(values)) {
      this.currentValues.set(key, value);
    }
  }

  private notifyListeners(key: string, oldValue: unknown, newValue: unknown): void {
    const keyListeners = this.listeners.get(key) ?? [];
    for (const listener of keyListeners) {
      try { listener(key, oldValue, newValue); } catch { /* ignore listener errors */ }
    }
    for (const listener of this.globalListeners) {
      try { listener(key, oldValue, newValue); } catch { /* ignore listener errors */ }
    }
  }

  private getEnvValue(key: string): string | undefined {
    if (typeof process !== 'undefined' && process.env) {
      return process.env[key];
    }
    return undefined;
  }
}

// ─── createConfig Builder ────────────────────────────────────
export interface ConfigBuilderOptions {
  /** Base configuration to extend */
  base?: Partial<VrilFullConfig>;
  /** Environment-specific overrides */
  environment?: EnvironmentConfig;
  /** Schema for validation */
  schema?: ConfigSchema;
  /** Secrets manager */
  secrets?: ConfigSecrets;
  /** Watcher for config changes */
  watcher?: ConfigWatcher;
}

/**
 * Type-safe configuration builder with validation.
 * Creates a validated, merged, and environment-aware configuration.
 */
export function createConfig(options: ConfigBuilderOptions = {}): {
  config: VrilFullConfig;
  validate: () => ConfigValidationResult;
  getSecret: (key: string) => Promise<string | null>;
  watch: (keys: string[]) => ConfigWatcher;
  version: string;
} {
  // Start with defaults
  let config: VrilFullConfig = { ...DEFAULT_FULL_CONFIG };

  // Apply base config
  if (options.base) {
    const merger = new ConfigMerger({ strategy: 'source-wins' });
    config = merger.merge(config, options.base as Partial<VrilFullConfig>);
  }

  // Apply environment overrides
  if (options.environment) {
    config = options.environment.resolve(config);
  }

  return {
    config,

    validate: () => {
      if (options.schema) {
        const validator = new ConfigValidator(options.schema);
        return validator.validate(config as unknown as Record<string, unknown>);
      }
      // Basic built-in validation
      const errors: ConfigValidationError[] = [];
      const warnings: ConfigValidationWarning[] = [];

      if (config.server.port < 1 || config.server.port > 65535) {
        errors.push({ path: 'server.port', message: 'Port must be between 1 and 65535' });
      }
      if (config.crypto.kdfIterations < 100000) {
        warnings.push({ path: 'crypto.kdfIterations', message: 'KDF iterations below 100000 are not recommended', suggestion: 'Use at least 600000 iterations' });
      }
      if (config.auth.passwordMinLength < 8) {
        warnings.push({ path: 'auth.passwordMinLength', message: 'Minimum password length below 8 is not recommended', suggestion: 'Use at least 12 characters' });
      }
      if (config.security.csrf.sameSite === 'None' && !config.server.https) {
        errors.push({ path: 'security.csrf.sameSite', message: 'SameSite=None requires HTTPS' });
      }

      return { valid: errors.length === 0, errors, warnings };
    },

    getSecret: async (key: string) => {
      if (options.secrets) {
        return options.secrets.getSecret(key);
      }
      return null;
    },

    watch: (keys: string[]) => {
      const watcher = options.watcher ?? new ConfigWatcher();
      watcher.watchEnvironment(keys);
      return watcher;
    },

    version: '2.1.0',
  };
}
