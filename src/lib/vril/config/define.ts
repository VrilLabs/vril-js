/**
 * Vril.js v2.1.0 — defineVrilConfig Utility
 * ─────────────────────────────────────────────
 * Type-safe configuration definition with validation, deep merging,
 * environment-specific overrides, and Next.js integration.
 *
 * Usage:
 *   import { defineVrilConfig } from './src/lib/vril/config/define';
 *   export default defineVrilConfig({ ... });
 */

import type { NextConfig } from 'next';

// ─── Version ──────────────────────────────────────────────────
export const VRIL_CONFIG_VERSION = '2.1.0';

// ─── Environment Type ────────────────────────────────────────
export type Environment = 'development' | 'staging' | 'production' | 'test';

// ─── Security Configuration ──────────────────────────────────
export interface VrilSecurityConfig {
  /** Enable Trusted Types enforcement to prevent DOM XSS */
  trustedTypes: boolean;
  /** Install API membrane that blocks dangerous browser APIs */
  apiMembrane: boolean;
  /** Browser APIs to block via the zero-trust membrane */
  blockedAPIs: string[];
  /** Content Security Policy (CSP Level 3) */
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
  /** Permissions Policy (Feature Policy) */
  permissionsPolicy: Record<string, string[]>;
  /** HTTP Security Headers applied to every response */
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
  /** CSRF (Cross-Site Request Forgery) Protection */
  csrf: {
    enabled: boolean;
    tokenHeader: string;
    cookieName: string;
    sameSite: 'Strict' | 'Lax' | 'None';
    doubleSubmit: boolean;
    tokenRotation: boolean;
  };
}

// ─── Cryptography Configuration ──────────────────────────────
export interface VrilCryptoConfig {
  /** Default encryption algorithm */
  defaultAlgorithm: 'aes-256-gcm' | 'x25519-mlkem768';
  /** PBKDF2 iteration count for key derivation (OWASP: 600K+) */
  kdfIterations: number;
  /** Enable post-quantum cryptography support */
  pqcEnabled: boolean;
  /** Enable hybrid mode (classical + PQC combined) */
  hybridMode: boolean;
  /** Automatic key rotation period in days (0 = disabled) */
  keyRotationDays: number;
}

// ─── Router Configuration ────────────────────────────────────
export interface VrilRouterConfig {
  /** Default rate limit (requests per minute per IP) */
  defaultRateLimit: number;
  /** Default maximum request body size in bytes */
  defaultMaxBodySize: number;
  /** Validate Origin header on every request */
  strictOriginValidation: boolean;
  /** Enable bot detection via User-Agent analysis */
  botDetection: boolean;
  /** Allowed CORS origins. Empty = same-origin only */
  corsOrigins: string[];
}

// ─── Build Configuration ─────────────────────────────────────
export interface VrilBuildConfig {
  /** Generate per-request CSP nonces for inline scripts/styles */
  cspNonce: boolean;
  /** Generate Subresource Integrity (SRI) hashes for assets */
  sriHashes: boolean;
  /** Apply security headers during the build process */
  securityHeaders: boolean;
  /** Generate SBOM in CycloneDX format */
  sbom: boolean;
  /** Enable React Strict Mode */
  strictMode: boolean;
}

// ─── Server Configuration ────────────────────────────────────
export interface VrilServerConfig {
  /** Server port */
  port: number;
  /** Server host */
  host: string;
  /** Enable HTTPS */
  https: boolean;
  /** HSTS max-age in seconds */
  hstsMaxAge: number;
  /** Request timeout in milliseconds */
  requestTimeout: number;
  /** Maximum request body size in bytes */
  maxRequestSize: number;
}

// ─── Auth Configuration ──────────────────────────────────────
export interface VrilAuthConfig {
  /** Session time-to-live in milliseconds */
  sessionTTL: number;
  /** Session idle timeout in milliseconds */
  sessionIdleTimeout: number;
  /** Token signing algorithm */
  tokenAlgorithm: string;
  /** Minimum password length */
  passwordMinLength: number;
  /** PBKDF2 iterations for password hashing */
  passwordRounds: number;
  /** Maximum login attempts before lockout */
  maxLoginAttempts: number;
  /** Account lockout duration in milliseconds */
  lockoutDuration: number;
}

// ─── Next.js Integration ─────────────────────────────────────
export interface VrilNextjsConfig {
  /** Enable React Strict Mode */
  reactStrictMode?: boolean;
  /** Don't expose X-Powered-By header */
  poweredByHeader?: boolean;
  /** Custom environment variables available at build time */
  env?: Record<string, string>;
  /** Webpack configuration overrides */
  webpack?: (config: unknown, options: unknown) => unknown;
  /** Image optimization configuration */
  images?: Record<string, unknown>;
  /** Additional Next.js config passthrough */
  [key: string]: unknown;
}

// ─── Full Resolved Configuration ─────────────────────────────
export interface VrilResolvedConfig {
  /** Vril.js configuration version */
  version: string;
  /** Current environment */
  environment: Environment;
  /** Security configuration */
  security: VrilSecurityConfig;
  /** Cryptography configuration */
  crypto: VrilCryptoConfig;
  /** Router configuration */
  router: VrilRouterConfig;
  /** Build configuration */
  build: VrilBuildConfig;
  /** Server configuration */
  server: VrilServerConfig;
  /** Auth configuration */
  auth: VrilAuthConfig;
  /** Signals configuration */
  signals: {
    enabled: boolean;
  };
  /** Next.js integration */
  nextjs: VrilNextjsConfig;
}

// ─── User Configuration (Partial) ────────────────────────────
export interface VrilUserConfig {
  security?: Partial<VrilSecurityConfig>;
  crypto?: Partial<VrilCryptoConfig>;
  router?: Partial<VrilRouterConfig>;
  build?: Partial<VrilBuildConfig>;
  server?: Partial<VrilServerConfig>;
  auth?: Partial<VrilAuthConfig>;
  nextjs?: VrilNextjsConfig;
  /** Environment-specific overrides */
  env?: {
    development?: Partial<VrilUserConfig>;
    staging?: Partial<VrilUserConfig>;
    production?: Partial<VrilUserConfig>;
    test?: Partial<VrilUserConfig>;
  };
}

// ─── Validation Result ───────────────────────────────────────
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

// ─── Default Configurations ──────────────────────────────────
const DEFAULT_SECURITY: VrilSecurityConfig = {
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

const DEFAULT_CRYPTO: VrilCryptoConfig = {
  defaultAlgorithm: 'aes-256-gcm',
  kdfIterations: 600000,
  pqcEnabled: true,
  hybridMode: true,
  keyRotationDays: 90,
};

const DEFAULT_ROUTER: VrilRouterConfig = {
  defaultRateLimit: 100,
  defaultMaxBodySize: 1024 * 1024,
  strictOriginValidation: false,
  botDetection: true,
  corsOrigins: [],
};

const DEFAULT_BUILD: VrilBuildConfig = {
  cspNonce: true,
  sriHashes: true,
  securityHeaders: true,
  sbom: false,
  strictMode: true,
};

const DEFAULT_SERVER: VrilServerConfig = {
  port: 3000,
  host: '0.0.0.0',
  https: false,
  hstsMaxAge: 63072000,
  requestTimeout: 30000,
  maxRequestSize: 10 * 1024 * 1024,
};

const DEFAULT_AUTH: VrilAuthConfig = {
  sessionTTL: 86400000,
  sessionIdleTimeout: 1800000,
  tokenAlgorithm: 'HMAC-SHA256',
  passwordMinLength: 12,
  passwordRounds: 600000,
  maxLoginAttempts: 5,
  lockoutDuration: 900000,
};

// ─── Deep Merge Utility ──────────────────────────────────────
function deepMerge<T extends Record<string, any>>(target: T, source: Partial<T>): T {
  if (!source) return target;
  const result = { ...target };

  for (const key of Object.keys(source) as Array<keyof T>) {
    const sourceVal = source[key];
    const targetVal = target[key];

    if (
      sourceVal !== null &&
      sourceVal !== undefined &&
      typeof sourceVal === 'object' &&
      !Array.isArray(sourceVal) &&
      typeof targetVal === 'object' &&
      targetVal !== null &&
      !Array.isArray(targetVal)
    ) {
      (result as any)[key] = deepMerge(
        targetVal as Record<string, any>,
        sourceVal as Partial<Record<string, any>>
      );
    } else if (sourceVal !== undefined) {
      (result as any)[key] = sourceVal;
    }
  }

  return result;
}

// ─── Environment Detection ───────────────────────────────────
function detectEnvironment(): Environment {
  if (typeof process !== 'undefined' && process.env) {
    const env: string = (process.env.NODE_ENV ?? process.env.VRIL_ENV ?? '') as string;
    if (env === 'production' || env === 'prod') return 'production';
    if (env === 'staging' || env === 'stage') return 'staging';
    if (env === 'test' || env === 'testing') return 'test';
  }
  return 'development';
}

// ─── Validation Logic ────────────────────────────────────────
function validateConfig(config: VrilResolvedConfig): ConfigValidationResult {
  const errors: ConfigValidationError[] = [];
  const warnings: ConfigValidationWarning[] = [];

  // Server validation
  if (config.server.port < 1 || config.server.port > 65535) {
    errors.push({
      path: 'server.port',
      message: `Port must be between 1 and 65535, got ${config.server.port}`,
      value: config.server.port,
    });
  }

  // Crypto validation
  if (config.crypto.kdfIterations < 100000) {
    errors.push({
      path: 'crypto.kdfIterations',
      message: 'KDF iterations below 100,000 are cryptographically insecure',
      value: config.crypto.kdfIterations,
    });
  } else if (config.crypto.kdfIterations < 600000) {
    warnings.push({
      path: 'crypto.kdfIterations',
      message: 'KDF iterations below 600,000 do not meet OWASP 2023 recommendations',
      suggestion: 'Use at least 600,000 iterations for PBKDF2-SHA-512',
    });
  }

  if (config.crypto.keyRotationDays < 0) {
    errors.push({
      path: 'crypto.keyRotationDays',
      message: 'Key rotation days cannot be negative',
      value: config.crypto.keyRotationDays,
    });
  } else if (config.crypto.keyRotationDays > 365) {
    warnings.push({
      path: 'crypto.keyRotationDays',
      message: 'Key rotation period exceeds 365 days',
      suggestion: 'Consider rotating keys more frequently (90 days recommended)',
    });
  }

  // Auth validation
  if (config.auth.passwordMinLength < 8) {
    errors.push({
      path: 'auth.passwordMinLength',
      message: 'Minimum password length below 8 is insecure',
      value: config.auth.passwordMinLength,
    });
  } else if (config.auth.passwordMinLength < 12) {
    warnings.push({
      path: 'auth.passwordMinLength',
      message: 'Minimum password length below 12 is not recommended',
      suggestion: 'Use at least 12 characters per NIST SP 800-63B',
    });
  }

  if (config.auth.maxLoginAttempts < 1) {
    errors.push({
      path: 'auth.maxLoginAttempts',
      message: 'Max login attempts must be at least 1',
      value: config.auth.maxLoginAttempts,
    });
  }

  if (config.auth.lockoutDuration < 60000) {
    warnings.push({
      path: 'auth.lockoutDuration',
      message: 'Lockout duration below 60 seconds may be insufficient',
      suggestion: 'Use at least 15 minutes (900,000 ms)',
    });
  }

  // Security validation
  if (config.security.csrf.sameSite === 'None' && !config.server.https) {
    errors.push({
      path: 'security.csrf.sameSite',
      message: 'SameSite=None requires HTTPS to be enabled',
      value: 'None',
    });
  }

  if (config.security.headers.strictTransportSecurity && !config.server.https) {
    warnings.push({
      path: 'security.headers.strictTransportSecurity',
      message: 'HSTS header has no effect without HTTPS',
      suggestion: 'Enable server.https for HSTS to be effective',
    });
  }

  if (config.security.csp.scriptSrc.includes("'unsafe-eval'") && config.environment === 'production') {
    warnings.push({
      path: 'security.csp.scriptSrc',
      message: "'unsafe-eval' in CSP script-src is a security risk in production",
      suggestion: "Remove 'unsafe-eval' and use CSP nonces instead",
    });
  }

  // Router validation
  if (config.router.defaultRateLimit < 10) {
    warnings.push({
      path: 'router.defaultRateLimit',
      message: 'Rate limit below 10 requests/minute may cause legitimate traffic issues',
      suggestion: 'Use at least 60 requests/minute for most applications',
    });
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

// ─── CSP Header Builder ──────────────────────────────────────
function buildCSPString(csp: VrilSecurityConfig['csp']): string {
  const directives: string[] = [];

  if (csp.defaultSrc.length) directives.push(`default-src ${csp.defaultSrc.join(' ')}`);
  if (csp.scriptSrc.length) directives.push(`script-src ${csp.scriptSrc.join(' ')}`);
  if (csp.styleSrc.length) directives.push(`style-src ${csp.styleSrc.join(' ')}`);
  if (csp.fontSrc.length) directives.push(`font-src ${csp.fontSrc.join(' ')}`);
  if (csp.imgSrc.length) directives.push(`img-src ${csp.imgSrc.join(' ')}`);
  if (csp.connectSrc.length) directives.push(`connect-src ${csp.connectSrc.join(' ')}`);
  if (csp.frameSrc.length) directives.push(`frame-src ${csp.frameSrc.join(' ')}`);
  if (csp.objectSrc.length) directives.push(`object-src ${csp.objectSrc.join(' ')}`);
  if (csp.baseUri.length) directives.push(`base-uri ${csp.baseUri.join(' ')}`);
  if (csp.formAction.length) directives.push(`form-action ${csp.formAction.join(' ')}`);
  if (csp.frameAncestors.length) directives.push(`frame-ancestors ${csp.frameAncestors.join(' ')}`);
  if (csp.upgradeInsecureRequests) directives.push('upgrade-insecure-requests');
  if (csp.blockAllMixedContent) directives.push('block-all-mixed-content');
  if (csp.reportTo) directives.push(`report-to ${csp.reportTo}`);

  return directives.join('; ');
}

// ─── Permissions Policy Builder ──────────────────────────────
function buildPermissionsPolicyString(policy: Record<string, string[]>): string {
  return Object.entries(policy)
    .map(([feature, origins]) => {
      if (origins.length === 0) return `${feature}=()`;
      return `${feature}=(${origins.join(' ')})`;
    })
    .join(', ');
}

// ─── Define Vril Config ──────────────────────────────────────
/**
 * Define a Vril.js configuration with full type safety, validation,
 * and Next.js integration.
 *
 * @param userConfig - Partial configuration object with overrides
 * @returns Resolved configuration with validation, Next.js conversion, and utilities
 *
 * @example
 * ```typescript
 * import { defineVrilConfig } from './src/lib/vril/config/define';
 *
 * export default defineVrilConfig({
 *   security: {
 *     trustedTypes: true,
 *     csp: { defaultSrc: ["'self'"] },
 *   },
 *   crypto: {
 *     kdfIterations: 600000,
 *     pqcEnabled: true,
 *   },
 *   nextjs: {
 *     reactStrictMode: true,
 *   },
 * });
 * ```
 */
export function defineVrilConfig(userConfig: VrilUserConfig = {}): {
  /** Fully resolved and merged configuration */
  config: VrilResolvedConfig;

  /** Validate the configuration and return errors/warnings */
  validate: () => ConfigValidationResult;

  /** Convert Vril config to a Next.js compatible config object */
  toNextConfig: () => NextConfig;

  /** Build the CSP header string from the current configuration */
  buildCSPHeader: () => string;

  /** Build the Permissions-Policy header string */
  buildPermissionsPolicyHeader: () => string;

  /** Build all security headers as a key-value map */
  buildSecurityHeaders: () => Record<string, string>;

  /** Get the Vril.js version */
  getVersion: () => string;

  /** Get the current environment */
  getEnvironment: () => Environment;
} {
  // Detect environment
  const environment = detectEnvironment();

  // Start with defaults
  let resolved: VrilResolvedConfig = {
    version: VRIL_CONFIG_VERSION,
    environment,
    security: { ...DEFAULT_SECURITY },
    crypto: { ...DEFAULT_CRYPTO },
    router: { ...DEFAULT_ROUTER },
    build: { ...DEFAULT_BUILD },
    server: { ...DEFAULT_SERVER },
    auth: { ...DEFAULT_AUTH },
    signals: { enabled: true },
    nextjs: userConfig.nextjs ?? {},
  };

  // Deep merge user config over defaults
  if (userConfig.security) {
    resolved.security = deepMerge(DEFAULT_SECURITY, userConfig.security);
  }
  if (userConfig.crypto) {
    resolved.crypto = { ...DEFAULT_CRYPTO, ...userConfig.crypto };
  }
  if (userConfig.router) {
    resolved.router = { ...DEFAULT_ROUTER, ...userConfig.router };
  }
  if (userConfig.build) {
    resolved.build = { ...DEFAULT_BUILD, ...userConfig.build };
  }
  if (userConfig.server) {
    resolved.server = { ...DEFAULT_SERVER, ...userConfig.server };
  }
  if (userConfig.auth) {
    resolved.auth = { ...DEFAULT_AUTH, ...userConfig.auth };
  }

  // Apply environment-specific overrides
  if (userConfig.env) {
    const envOverride = userConfig.env[environment];
    if (envOverride) {
      if (envOverride.security) {
        resolved.security = deepMerge(resolved.security, envOverride.security);
      }
      if (envOverride.crypto) {
        resolved.crypto = { ...resolved.crypto, ...envOverride.crypto };
      }
      if (envOverride.router) {
        resolved.router = { ...resolved.router, ...envOverride.router };
      }
      if (envOverride.build) {
        resolved.build = { ...resolved.build, ...envOverride.build };
      }
      if (envOverride.server) {
        resolved.server = { ...resolved.server, ...envOverride.server };
      }
      if (envOverride.auth) {
        resolved.auth = { ...resolved.auth, ...envOverride.auth };
      }
      if (envOverride.nextjs) {
        resolved.nextjs = { ...resolved.nextjs, ...envOverride.nextjs };
      }
    }
  }

  return {
    config: resolved,

    validate: () => validateConfig(resolved),

    toNextConfig: (): NextConfig => {
      const nextConfig: Record<string, unknown> = {
        reactStrictMode: resolved.build.strictMode,
        poweredByHeader: false,
      };

      // Apply Next.js-specific settings
      if (resolved.nextjs) {
        for (const [key, value] of Object.entries(resolved.nextjs)) {
          if (key !== 'webpack' && key !== 'images' && key !== 'env') {
            nextConfig[key] = value;
          }
        }
        if (resolved.nextjs.webpack) {
          nextConfig.webpack = resolved.nextjs.webpack;
        }
        if (resolved.nextjs.images) {
          nextConfig.images = resolved.nextjs.images;
        }
        if (resolved.nextjs.env) {
          nextConfig.env = resolved.nextjs.env;
        }
      }

      // Apply security headers via Next.js headers() config
      const securityHeaders = buildAllSecurityHeaders(resolved);
      if (Object.keys(securityHeaders).length > 0) {
        nextConfig.headers = async () => [
          {
            source: '/(.*)',
            headers: Object.entries(securityHeaders).map(([key, value]) => ({
              key,
              value,
            })),
          },
        ];
      }

      return nextConfig as NextConfig;
    },

    buildCSPHeader: () => buildCSPString(resolved.security.csp),

    buildPermissionsPolicyHeader: () => buildPermissionsPolicyString(resolved.security.permissionsPolicy),

    buildSecurityHeaders: () => buildAllSecurityHeaders(resolved),

    getVersion: () => VRIL_CONFIG_VERSION,

    getEnvironment: () => environment,
  };
}

// ─── Security Headers Builder ────────────────────────────────
function buildAllSecurityHeaders(config: VrilResolvedConfig): Record<string, string> {
  const headers: Record<string, string> = {};

  if (config.security.headers.strictTransportSecurity) {
    headers['Strict-Transport-Security'] = config.security.headers.strictTransportSecurity;
  }
  if (config.security.headers.xContentTypeOptions) {
    headers['X-Content-Type-Options'] = config.security.headers.xContentTypeOptions;
  }
  if (config.security.headers.xFrameOptions) {
    headers['X-Frame-Options'] = config.security.headers.xFrameOptions;
  }
  if (config.security.headers.referrerPolicy) {
    headers['Referrer-Policy'] = config.security.headers.referrerPolicy;
  }
  if (config.security.headers.crossOriginOpenerPolicy) {
    headers['Cross-Origin-Opener-Policy'] = config.security.headers.crossOriginOpenerPolicy;
  }
  if (config.security.headers.crossOriginEmbedderPolicy) {
    headers['Cross-Origin-Embedder-Policy'] = config.security.headers.crossOriginEmbedderPolicy;
  }
  if (config.security.headers.crossOriginResourcePolicy) {
    headers['Cross-Origin-Resource-Policy'] = config.security.headers.crossOriginResourcePolicy;
  }

  // CSP header
  headers['Content-Security-Policy'] = buildCSPString(config.security.csp);

  // Permissions-Policy header
  headers['Permissions-Policy'] = buildPermissionsPolicyString(config.security.permissionsPolicy);

  return headers;
}

// ─── Preset Configurations ───────────────────────────────────

/** SPA preset — relaxed security for client-rendered apps */
export const SPA_PRESET = {
  security: {
    csp: {
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
    },
  },
  build: {
    sriHashes: false,
    cspNonce: false,
  },
  server: {
    https: false,
  },
};

/** SSR preset — full security for server-rendered apps */
export const SSR_PRESET = {
  server: {
    https: true,
  },
};

/** Static preset — security for statically generated sites */
export const STATIC_PRESET = {
  security: {
    csrf: {
      enabled: false,
    },
  },
  server: {
    https: true,
  },
};

/** API-only preset — security for API servers */
export const API_PRESET = {
  security: {
    csp: {
      scriptSrc: ["'none'"],
      styleSrc: ["'none'"],
      frameSrc: ["'none'"],
    },
  },
  router: {
    defaultRateLimit: 60,
    strictOriginValidation: true,
  },
  server: {
    https: true,
    requestTimeout: 10000,
  },
};
