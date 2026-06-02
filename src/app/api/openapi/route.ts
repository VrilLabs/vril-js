import { json } from "@/lib/vril/framework";
import { generateOpenAPISpec, type RouteManifestEntry } from "@/lib/vril/openapi";

/**
 * Vril.js documentation surface registry.
 * Maps every documented module, function, and class to its docs section anchor.
 * The command palette docs explorer consumes this to provide navigation to /docs.
 */
const DOCS_SURFACE: RouteManifestEntry[] = [
  // ─── Core ───────────────────────────────────────────────────────
  { routePath: 'createVrilApp()', methods: ['GET'], description: 'Create and configure a Vril.js application instance', tags: ['Core'], docsAnchor: 'core' },
  { routePath: 'detectEnvironment()', methods: ['GET'], description: 'Detect runtime: browser, server, edge, or Node.js', tags: ['Core'], docsAnchor: 'core' },
  { routePath: 'FeatureFlags', methods: ['GET'], description: 'Feature flag system with rollout percentage support', tags: ['Core'], docsAnchor: 'core' },
  { routePath: 'PluginLifecycleRegistry', methods: ['GET'], description: 'Register and invoke plugin lifecycle hooks', tags: ['Core'], docsAnchor: 'core' },
  { routePath: 'PerformanceProfiler', methods: ['GET'], description: 'High-resolution timing for crypto and rendering ops', tags: ['Core'], docsAnchor: 'core' },

  // ─── Config ─────────────────────────────────────────────────────
  { routePath: 'createConfig()', methods: ['GET'], description: 'Type-safe config builder with validation and secrets', tags: ['Config'], docsAnchor: 'config-mod' },
  { routePath: 'ConfigValidator', methods: ['GET'], description: 'Validate config values against a schema definition', tags: ['Config'], docsAnchor: 'config-mod' },
  { routePath: 'EnvironmentConfig', methods: ['GET'], description: 'Dev/staging/prod/test environment-specific overrides', tags: ['Config'], docsAnchor: 'config-mod' },
  { routePath: 'ConfigSecrets', methods: ['GET'], description: 'AES-GCM encrypted secrets with PBKDF2 key derivation', tags: ['Config'], docsAnchor: 'config-mod' },

  // ─── Plugin ─────────────────────────────────────────────────────
  { routePath: 'createPlugin()', methods: ['GET'], description: 'Fluent builder for type-safe plugin creation', tags: ['Plugin'], docsAnchor: 'plugin' },
  { routePath: 'PluginRegistry', methods: ['GET'], description: 'Register, enable, disable, and configure plugins', tags: ['Plugin'], docsAnchor: 'plugin' },
  { routePath: 'PluginLoader', methods: ['GET'], description: 'Load plugins with SHA-256 integrity verification', tags: ['Plugin'], docsAnchor: 'plugin' },

  // ─── Types ──────────────────────────────────────────────────────
  { routePath: 'SecureString', methods: ['GET'], description: 'Branded string that has been security-validated', tags: ['Types'], docsAnchor: 'types' },
  { routePath: 'Encrypted<T>', methods: ['GET'], description: 'Branded type for encrypted data', tags: ['Types'], docsAnchor: 'types' },
  { routePath: 'SecurityLevel', methods: ['GET'], description: 'Enum: none | low | medium | high | critical', tags: ['Types'], docsAnchor: 'types' },

  // ─── Security (parent — has submenu) ────────────────────────────
  { routePath: 'vril/security', methods: ['GET'], description: 'Security module overview — Trusted Types, CSP, API membrane', tags: ['Security'], docsAnchor: 'security', hasSubmenu: true },
  { routePath: 'installTrustedTypes()', methods: ['POST'], description: 'Install Trusted Types policy to prevent DOM XSS', tags: ['Security'], docsAnchor: 'security' },
  { routePath: 'installAPIMembrane()', methods: ['POST'], description: 'Block dangerous browser APIs at runtime', tags: ['Security'], docsAnchor: 'security' },
  { routePath: 'DOMPSanitizer', methods: ['GET'], description: 'Zero-dependency HTML sanitizer', tags: ['Security'], docsAnchor: 'security' },
  { routePath: 'ContentSecurityPolicy', methods: ['GET'], description: 'Fluent CSP builder with nonce and report support', tags: ['Security'], docsAnchor: 'security' },

  // ─── Security > Vault ───────────────────────────────────────────
  { routePath: 'VrilVault', methods: ['GET'], description: 'AES-256-GCM vault with PBKDF2-SHA-512 (600K iterations)', tags: ['Security › Vault'], docsAnchor: 'vault' },
  { routePath: 'VrilVault.encrypt()', methods: ['POST'], description: 'Encrypt text with passphrase, returns versioned bundle', tags: ['Security › Vault'], docsAnchor: 'vault' },
  { routePath: 'VrilVault.decrypt()', methods: ['POST'], description: 'Decrypt bundle with passphrase, verifies integrity', tags: ['Security › Vault'], docsAnchor: 'vault' },

  // ─── Security > PQC ─────────────────────────────────────────────
  { routePath: 'PQCKeyExchange', methods: ['GET'], description: 'Post-quantum key exchange (ML-KEM / Kyber)', tags: ['Security › PQC'], docsAnchor: 'pqc' },
  { routePath: 'PQCSignature', methods: ['POST'], description: 'Post-quantum digital signatures (ML-DSA / SLH-DSA)', tags: ['Security › PQC'], docsAnchor: 'pqc' },

  // ─── Security > Hybrid ──────────────────────────────────────────
  { routePath: 'HybridEncryption', methods: ['POST'], description: 'Classical + PQC hybrid encryption', tags: ['Security › Hybrid'], docsAnchor: 'hybrid' },
  { routePath: 'HybridKeyAgreement', methods: ['POST'], description: 'ECDH + ML-KEM hybrid key agreement', tags: ['Security › Hybrid'], docsAnchor: 'hybrid' },

  // ─── Security > Agility ─────────────────────────────────────────
  { routePath: 'AlgorithmNegotiator', methods: ['GET'], description: 'Negotiate algorithm by security level', tags: ['Security › Agility'], docsAnchor: 'agility' },
  { routePath: 'CryptoAgility', methods: ['GET'], description: 'Algorithm registry with migration support', tags: ['Security › Agility'], docsAnchor: 'agility' },

  // ─── Security > Hardening ───────────────────────────────────────
  { routePath: 'RuntimeHardening', methods: ['POST'], description: 'Freeze prototypes, seal globals, disable eval', tags: ['Security › Hardening'], docsAnchor: 'hardening' },
  { routePath: 'MemoryProtection', methods: ['POST'], description: 'Secure memory with auto-zeroing and freezing', tags: ['Security › Hardening'], docsAnchor: 'hardening' },

  // ─── Security > Audit ───────────────────────────────────────────
  { routePath: 'SecurityAuditor', methods: ['GET'], description: 'Run security audit checks across modules', tags: ['Security › Audit'], docsAnchor: 'audit' },
  { routePath: 'AuditLogger', methods: ['POST'], description: 'Structured audit logging with tamper detection', tags: ['Security › Audit'], docsAnchor: 'audit' },

  // ─── Signals ────────────────────────────────────────────────────
  { routePath: 'signal()', methods: ['POST'], description: 'Create a reactive signal with get/set/peek', tags: ['Data'], docsAnchor: 'signals' },
  { routePath: 'computed()', methods: ['POST'], description: 'Create a derived signal that auto-updates', tags: ['Data'], docsAnchor: 'signals' },
  { routePath: 'effect()', methods: ['POST'], description: 'Run side effects when dependencies change', tags: ['Data'], docsAnchor: 'signals' },
  { routePath: 'batch()', methods: ['POST'], description: 'Batch multiple updates into one notification', tags: ['Data'], docsAnchor: 'signals' },
  { routePath: 'encryptedSignal()', methods: ['POST'], description: 'Signal that encrypts values in memory with AES-256-GCM', tags: ['Data'], docsAnchor: 'signals' },

  // ─── State ──────────────────────────────────────────────────────
  { routePath: 'createStore()', methods: ['POST'], description: 'Create a store with initial state and middleware', tags: ['Data'], docsAnchor: 'state' },
  { routePath: 'VrilStore', methods: ['GET'], description: 'Full state management: get/set/select/dispatch/subscribe', tags: ['Data'], docsAnchor: 'state' },
  { routePath: 'StateEncryption', methods: ['POST'], description: 'Field-level AES-256-GCM encryption for sensitive state', tags: ['Data'], docsAnchor: 'state' },

  // ─── Hooks ──────────────────────────────────────────────────────
  { routePath: 'useSignal()', methods: ['GET'], description: 'Subscribe to a signal in a React component', tags: ['Hooks'], docsAnchor: 'hooks' },
  { routePath: 'useEncryptedState()', methods: ['GET'], description: 'React state that encrypts values with AES-256-GCM', tags: ['Hooks'], docsAnchor: 'hooks' },
  { routePath: 'useCSRFToken()', methods: ['GET'], description: 'Get and manage CSRF tokens for server actions', tags: ['Hooks'], docsAnchor: 'hooks' },
  { routePath: 'useRateLimiter()', methods: ['GET'], description: 'Client-side rate limiting for API calls', tags: ['Hooks'], docsAnchor: 'hooks' },

  // ─── Cache ──────────────────────────────────────────────────────
  { routePath: 'MemoryCache', methods: ['GET'], description: 'LRU cache with TTL, max entries, and memory pressure', tags: ['Data'], docsAnchor: 'cache' },
  { routePath: 'EncryptedCache', methods: ['POST'], description: 'AES-256-GCM encrypted cache for sensitive data', tags: ['Data'], docsAnchor: 'cache' },
  { routePath: 'CacheInvalidator', methods: ['DELETE'], description: 'Tag-based and pattern-based cache invalidation', tags: ['Data'], docsAnchor: 'cache' },

  // ─── Server ─────────────────────────────────────────────────────
  { routePath: 'validateDeserializedPayload()', methods: ['POST'], description: 'Validate RSC payloads: depth, keys, prototype pollution', tags: ['Server'], docsAnchor: 'server' },
  { routePath: 'CSRFGuard', methods: ['POST'], description: 'Generate/validate CSRF tokens with constant-time comparison', tags: ['Server'], docsAnchor: 'server' },
  { routePath: 'RequestSigner', methods: ['POST'], description: 'HMAC-SHA256 request signing with replay prevention', tags: ['Server'], docsAnchor: 'server' },
  { routePath: 'SecurityMiddlewareChain', methods: ['POST'], description: 'Composable security checks with audit logging', tags: ['Server'], docsAnchor: 'server' },

  // ─── Build ──────────────────────────────────────────────────────
  { routePath: 'BuildSecurityChecker', methods: ['GET'], description: '20-point build security audit', tags: ['Build'], docsAnchor: 'build' },
  { routePath: 'SRIHasher', methods: ['POST'], description: 'Multi-algorithm SRI (sha256+sha384+sha512)', tags: ['Build'], docsAnchor: 'build' },
  { routePath: 'SBOMGenerator', methods: ['GET'], description: 'CycloneDX SBOM with vulnerability matching', tags: ['Build'], docsAnchor: 'build' },

  // ─── Router ─────────────────────────────────────────────────────
  { routePath: 'createSecureHandler()', methods: ['POST'], description: 'Create API route handler with built-in security', tags: ['Router'], docsAnchor: 'router' },
  { routePath: 'RouteSecurityRegistry', methods: ['GET'], description: 'Map route patterns to security policies', tags: ['Router'], docsAnchor: 'router' },
  { routePath: 'RouteMiddleware', methods: ['POST'], description: 'Composable: withAuth, withCSRF, withRateLimit, withCORS', tags: ['Router'], docsAnchor: 'router' },
  { routePath: 'NavigationGuard', methods: ['GET'], description: 'Client-side URL validation, tab-nabbing prevention', tags: ['Router'], docsAnchor: 'router' },

  // ─── Auth ───────────────────────────────────────────────────────
  { routePath: 'SessionManager', methods: ['POST'], description: 'Create/validate/rotate/destroy sessions with HMAC tokens', tags: ['Auth'], docsAnchor: 'auth' },
  { routePath: 'TokenHandler', methods: ['POST'], description: 'JWT-like tokens: create, verify, refresh (Web Crypto)', tags: ['Auth'], docsAnchor: 'auth' },
  { routePath: 'PasswordHandler', methods: ['POST'], description: 'PBKDF2-SHA-512 (600K iter) with constant-time verify', tags: ['Auth'], docsAnchor: 'auth' },
  { routePath: 'RBAC', methods: ['GET'], description: 'Hierarchical role-based access control with permission guards', tags: ['Auth'], docsAnchor: 'auth' },

  // ─── API ────────────────────────────────────────────────────────
  { routePath: 'createAPIRoute()', methods: ['POST'], description: 'Builder for API routes with validation, CSRF, rate limiting', tags: ['API'], docsAnchor: 'api' },
  { routePath: 'APISchema', methods: ['GET'], description: 'Zero-dep schema builder: string, number, object, array, enum', tags: ['API'], docsAnchor: 'api' },
  { routePath: 'APIRateLimiter', methods: ['POST'], description: 'Token bucket rate limiting per IP/route', tags: ['API'], docsAnchor: 'api' },

  // ─── SSR ────────────────────────────────────────────────────────
  { routePath: 'createSSRStream()', methods: ['POST'], description: 'Create server-side rendering stream', tags: ['Platform'], docsAnchor: 'ssr' },
  { routePath: 'SSRSecurityGuard', methods: ['POST'], description: 'Validate SSR output for XSS before sending', tags: ['Platform'], docsAnchor: 'ssr' },

  // ─── Streaming ──────────────────────────────────────────────────
  { routePath: 'StreamIntegrityValidator', methods: ['POST'], description: 'HMAC integrity validation for streaming data', tags: ['Platform'], docsAnchor: 'streaming' },
  { routePath: 'RateLimitedStream', methods: ['POST'], description: 'Rate-limited streams to prevent DoS', tags: ['Platform'], docsAnchor: 'streaming' },

  // ─── Edge ───────────────────────────────────────────────────────
  { routePath: 'EdgeRuntime', methods: ['GET'], description: 'Edge runtime detection and utilities', tags: ['Platform'], docsAnchor: 'edge' },
  { routePath: 'EdgeKV', methods: ['GET'], description: 'Edge key-value storage with TTL', tags: ['Platform'], docsAnchor: 'edge' },
  { routePath: 'EdgeSecurity', methods: ['GET'], description: 'Bot detection and IP allowlisting', tags: ['Platform'], docsAnchor: 'edge' },

  // ─── Utils ──────────────────────────────────────────────────────
  { routePath: 'constantTimeEqual()', methods: ['GET'], description: 'Constant-time comparison (prevents timing attacks)', tags: ['Utils'], docsAnchor: 'utils' },
  { routePath: 'secureRandom()', methods: ['GET'], description: 'Cryptographically secure random bytes', tags: ['Utils'], docsAnchor: 'utils' },
  { routePath: 'hashData()', methods: ['POST'], description: 'SHA-256/384/512 hashing via Web Crypto', tags: ['Utils'], docsAnchor: 'utils' },
  { routePath: 'sanitizeHTML()', methods: ['POST'], description: 'Basic HTML sanitizer (strips scripts, event handlers)', tags: ['Utils'], docsAnchor: 'utils' },
];

/**
 * GET /api/openapi
 * Returns the OpenAPI 3.1.0 specification representing the full Vril.js API surface.
 * The command palette docs explorer consumes this endpoint to provide navigation to /docs.
 */
export async function GET(request: Request) {
  // Construct the server URL from request headers
  let serverUrl: string | undefined;
  const proto = request.headers.get('x-forwarded-proto') || 'https';
  const host = request.headers.get('host');
  if (host) {
    serverUrl = `${proto}://${host}`;
  }

  const spec = generateOpenAPISpec(DOCS_SURFACE, {
    title: 'Vril.js API',
    description: 'Full API surface for the Vril.js security-first framework. Each entry links to the corresponding documentation section at /docs.',
    serverUrl,
  });

  return json(spec, {
    headers: {
      'Cache-Control': 'public, max-age=60, stale-while-revalidate=300',
    },
  });
}
