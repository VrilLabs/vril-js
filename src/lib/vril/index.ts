/**
 * Vril.js v2.1.0 — The Security-First React Framework
 * by VRIL LABS
 *
 * Post-quantum cryptography · Zero-trust membrane · Crypto agility
 * ΩSignal reactivity · Secure SSR · Build-time integrity
 * Streaming SSR · Edge Runtime · Plugin Architecture
 */

export const VRIL_VERSION = '2.1.0';

// ─── Core ────────────────────────────────────────────────────
export {
  createVrilApp,
  DEFAULT_VRIL_CONFIG,
  detectEnvironment,
  env,
  type VrilConfig,
  type CSPConfig,
  type SecurityHeadersConfig,
  type PluginLifecycleHook,
  type HookCallback,
  PluginLifecycleRegistry,
  type EnvironmentInfo,
  type FeatureFlagConfig,
  FeatureFlags,
  type AppContextShape,
  AppContext,
  type VersionInfo,
  type MigrationFn,
  type MigrationDescriptor,
  VersionTracker,
  type PerformanceMark,
  type PerformanceReport,
  PerformanceProfiler,
} from './core';

// ─── Security ────────────────────────────────────────────────
export {
  installTrustedTypes,
  setSafeHTML,
  buildCSPHeader,
  buildPermissionsPolicy,
  buildSecurityHeaders,
  installAPIMembrane,
  IntegrityChecker,
  TrustedTypesEnforcer,
  DOMPSanitizer,
  URLValidator,
  ContentSecurityPolicy,
  PermissionsPolicyBuilder,
  SecurityContext,
  type TrustedTypesPolicy,
  type SanitizationConfig,
  type URLValidationResult,
  type SecurityContextState,
} from './security';

export {
  VrilVault,
  SecureMemory,
  type VaultConfig,
  type EncryptionResult,
  type DecryptionResult,
  type BlobEncryptionResult,
  type KeyWrapResult,
  type StrengthAssessment,
} from './security/crypto/vault';

export {
  PQCHandler,
  pqc,
  type PQCKeyPair,
  type KEMResult,
  type SignatureResult,
  type AlgorithmInfo,
  type BenchmarkResult,
  type PQCAlgorithm,
} from './security/crypto/pqc';

export {
  HybridKEM,
  HybridSigner,
  HybridKeyRotation,
  type HybridKEMResult,
  type HybridSignatureResult,
  type KeyRotationPolicy,
  type HybridKeyPair,
  type KeyRotationEvent,
} from './security/crypto/hybrid';

export {
  CryptoAgility,
  AlgorithmRegistry,
  MigrationExecutor,
  AlgorithmHealthMonitor,
  CryptoPolicy,
  AuditLogger,
  type AlgorithmDescriptor,
  type AlgorithmHealth,
  type VulnerabilityEntry,
  type MigrationPlan,
  type MigrationStep,
  type MigrationResult,
  type CryptoPolicyConfig,
  type AuditLogEntry,
  type QuantumMilestone,
} from './security/crypto/agility';

export {
  CrossOriginIsolation,
  FingerprintResistance,
  TimingAttackMitigation,
  ClickjackingProtection,
  XSSShield,
  CookieFortress,
  SecurityHeadersBuilder,
  type HardeningConfig,
  type CookieOptions,
  type SecurityHeaderSet,
} from './security/hardening';

export {
  SecurityAuditor,
  CSPViolationReporter,
  SecurityScoreCalculator,
  VulnerabilityDatabase,
  ComplianceChecker,
  generateSecurityReport,
  type AuditResult,
  type SecurityScore,
  type VulnerabilityFinding,
  type CSPViolationReport,
  type ComplianceStatus,
  type SecurityReport,
} from './security/audit';

// ─── Signals ─────────────────────────────────────────────────
export {
  signal,
  computed,
  effect,
  batch,
  untrack,
  store,
  lazySignal,
  asyncSignal,
  resourceSignal,
  debouncedSignal,
  throttledSignal,
  persistedSignal,
  encryptedSignal,
  signalFromEvent,
  signalFromPromise,
  onSignalCreate,
  onSignalUpdate,
  onEffectRun,
  createSignalGraph,
  ΩSignal,
  type AsyncSignalState,
  type ResourceState,
  type SignalNode,
  type SignalGraph,
} from './signals';

// ─── State ────────────────────────────────────────────────────
export {
  VrilStore,
  createStore,
  StoreRegistry,
  storeRegistry,
  StateEncryption,
  StatePersistence,
  StateValidator,
  loggerMiddleware,
  persistenceMiddleware,
  devtoolsMiddleware,
  encryptionMiddleware,
  type StoreConfig,
  type StoreMiddleware,
  type StateAction,
  type StateTransition,
  type Selector,
  type StateValidatorFn,
  type StoreSubscriber,
} from './state';

// ─── Hooks ────────────────────────────────────────────────────
export {
  useSignal,
  useComputed,
  useAsyncSignal,
  useResource,
  useEncryptedState,
  useSecureStorage,
  useCSRFToken,
  useSecurityHeaders,
  usePermission,
  useRateLimiter,
  useVrilConfig,
  useIsOnline,
  type AsyncState,
  type ResourceOptions,
  type RateLimitConfig as HookRateLimitConfig,
} from './hooks';

// ─── Diagnostics ──────────────────────────────────────────────
export {
  PerformanceMonitor,
  SecurityDiagnostics,
  CryptoProfiler,
  NetworkMonitor,
  BundleAnalyzer,
  MemoryProfiler,
  createDiagnosticReport,
  type PerformanceMetric,
  type SecurityDiagnostic,
  type CryptoProfile,
  type NetworkMetric,
  type BundleInfo,
  type MemorySnapshot,
  type DiagnosticReport,
} from './diagnostics';

// ─── Utils ────────────────────────────────────────────────────
export {
  constantTimeEqual,
  secureRandom,
  secureRandomString,
  hashData,
  encodeBase64,
  decodeBase64,
  encodeBase64Url,
  decodeBase64Url,
  sanitizeHTML,
  validateURL,
  deepClone,
  deepFreeze,
  mergeConfigs,
  debounce,
  throttle,
  retryWithBackoff,
  type RetryOptions,
  type SanitizeConfig,
} from './utils';

// ─── Types ────────────────────────────────────────────────────
export {
  SecurityLevel,
  type VrilRuntime,
  type VrilFeature,
  type SecureString,
  type Encrypted,
  type Hashed,
  type Signed,
  type PQCVerified,
  type AlgorithmIdentifier,
  type AlgorithmCategory,
  type AlgorithmStatus,
  type DataClassification,
  type KeyUsage,
  type KeyType,
  type KeyFormat,
  type CryptoKeyMetadata,
  type CSPDirective,
  type PermissionsPolicyDirective,
  type SignalKind,
  type StoreActionType,
  type HttpMethod,
  type RequestSigningAlgorithm,
  type CSRFTokenSource,
  type DeepPartial,
  type DeepReadonly,
  type Branded,
  type Nominal,
  type Unbrand,
  type RequireKeys,
  type OptionalKeys,
  type Exact,
  type Awaited,
  type DiagnosticSeverity,
  type MetricCategory,
  type HealthStatus,
  type SemVer,
  type MigrationDirection,
  type CompatibilityLevel,
} from './types';

// ─── Router ──────────────────────────────────────────────────
export {
  RouteSecurityRegistry,
  createSecureHandler,
  DEFAULT_ROUTE_SECURITY,
  MUTATION_SECURITY,
  RouteMiddleware,
  RouteGroup,
  RouteScanner,
  NavigationGuard,
  ROUTER_MODULE_VERSION,
  type RouteSecurityPolicy,
  type RouteConfig,
  type CORSConfig,
  type RouteHandler,
  type RouteContext,
  type SessionData,
  type Middleware,
  type RouteSecurityIssue,
  type NavigationPolicy,
  type NavigationValidationResult,
} from './router';

// ─── Server ──────────────────────────────────────────────────
export {
  validateDeserializedPayload,
  CSRFGuard,
  RequestSigner,
  EnvEncryption,
  SupplyChainIntegrity,
  RSCSecurityBoundary,
  ServerTimingSecurity,
  RequestValidator,
  SecurityMiddlewareChain,
  SERVER_MODULE_VERSION,
  DEFAULT_DESERIALIZATION_CONFIG,
  type DeserializationConfig,
  type IntegrityManifest,
  type SBOMEntry,
  type SBOMV23,
  type RSCSecurityConfig,
  type HSMKeyProvider,
  type RequestValidationConfig,
  type RequestValidationResult,
  type SecurityCheckResult,
  type SecurityAuditLog,
} from './server';

// ─── Build ───────────────────────────────────────────────────
export {
  CSPNonceGenerator,
  SRIHasher,
  BuildSecurityChecker,
  generateAuditReport,
  BuildPlugin,
  SBOMGenerator,
  BuildIntegrityVerifier,
  SecurityHeadersPlugin,
  BUILD_MODULE_VERSION,
  type VrilBuildManifest,
  type SecurityAuditResult,
  type BuildPluginConfig,
  type CSPManifestEntry,
  type CycloneDXComponent,
  type CycloneDXDocument,
  type VulnerabilityMatch,
  type BuildIntegrityManifest,
  type IntegrityVerificationResult,
  type SecurityHeadersConfig as BuildSecurityHeadersConfig,
} from './build';

// ─── Config ──────────────────────────────────────────────────
export {
  createConfig,
  ConfigValidator,
  ConfigMerger,
  EnvironmentConfig,
  ConfigSecrets,
  ConfigWatcher,
  CONFIG_MODULE_VERSION,
  DEFAULT_FULL_CONFIG,
  SPA_PRESET,
  SSR_PRESET,
  STATIC_PRESET,
  API_PRESET,
  type Environment,
  type VrilFullConfig,
  type SecurityConfig,
  type CryptoConfig as ConfigCryptoConfig,
  type RouterConfig as ConfigRouterConfig,
  type BuildConfig as ConfigBuildConfig,
  type ServerConfig as ConfigServerConfig,
  type AuthConfig as ConfigAuthConfig,
  type ConfigValidationResult,
  type ConfigValidationError,
  type ConfigValidationWarning,
  type ConfigSchema,
  type ConfigSchemaField,
  type MergeConflictResolution,
  type ConfigChangeListener,
  type ConfigBuilderOptions,
  type SecretEntry,
} from './config';

// ─── Auth ────────────────────────────────────────────────────
export {
  SessionManager,
  TokenHandler,
  PasswordHandler,
  RBAC,
  LoginAttemptTracker,
  AUTH_MODULE_VERSION,
  DEFAULT_AUTH_CONFIG,
  type Session,
  type TokenPayload,
  type Role,
  type Permission,
  type AuthConfig as AuthModuleConfig,
  type PasswordStrengthResult,
} from './auth';

// ─── SSR ─────────────────────────────────────────────────────
export {
  createSSRStream,
  renderToStream,
  SSRSecurityGuard,
  SelectiveHydration,
  SSRManifest,
  type HydrationStrategy,
  type SSRChunk,
  type SSROptions,
  type HydrationDescriptor,
  type SSRManifestEntry,
} from './ssr';

// ─── Streaming ───────────────────────────────────────────────
export {
  createStreamingBoundary,
  StreamIntegrityValidator,
  RateLimitedStream,
  SecureStreamTransformer,
  StreamingCache,
  type StreamingConfig,
  type StreamChunk,
  type CachePolicy as StreamCachePolicy,
} from './streaming';

// ─── Cache ───────────────────────────────────────────────────
export {
  MemoryCache,
  StaleWhileRevalidate,
  EncryptedCache,
  CacheRegistry,
  CacheInvalidator,
  distributedCacheKey,
  type CachePolicy,
  type CacheEntry,
  type CacheStats,
} from './cache';

// ─── API ─────────────────────────────────────────────────────
export {
  APISchema,
  APIErrorHandler,
  APIError,
  APIRateLimiter,
  APIVersioning,
  createAPIRoute,
  type ValidationResult,
  type ValidationError as APIValidationError,
  type APIRequest,
  type APIResponse,
  type APIRouteConfig,
  type RateLimitConfig as APIRateLimitConfig,
} from './api';

// ─── Plugin ──────────────────────────────────────────────────
export {
  PluginRegistry,
  PluginLoader,
  createPlugin,
  type PluginLifecycle,
  type PluginHook,
  type PluginManifest,
  type PluginPermission,
  type VrilPlugin,
  type PluginMiddleware,
  type PluginContext,
  type PluginLogger,
  type PluginCrypto,
} from './plugin';

// ─── Head ────────────────────────────────────────────────────
export {
  HeadManager,
  generateOGTags,
  generateStructuredData,
  SEOOptimizer,
  CSPNonceInjector,
  type HeadTag,
  type SEOConfig,
  type RobotsDirective,
  type OGConfig,
  type OGImage,
  type TwitterConfig,
  type AlternateLanguage,
  type StructuredDataConfig,
} from './head';

// ─── Edge ────────────────────────────────────────────────────
export {
  EdgeRuntime,
  EdgeKV,
  EdgeGeo,
  EdgeSecurity,
  createEdgeHandler,
  type EdgeConfig,
  type GeoData,
  type EdgeEnvironment,
  type EdgeHandlerContext,
} from './edge';

// ─── Components ──────────────────────────────────────────────
export { VrilProvider, useVril } from '@/components/vril-provider';
export { CrystalWindow, useCrystalWindow } from '@/components/crystal-window';
export { VaultDialog } from '@/components/vault-dialog';
export { CommandPalette, type CommandItem } from '@/components/command-palette';
export { VrilModal } from '@/components/modal';
