/**
 * Vril.js v2.0.0 — Core Configuration & Framework Foundation
 * Security-first React framework by VRIL LABS
 *
 * Plugin lifecycle · Environment detection · Feature flags ·
 * App context · Version migration · Performance profiling
 */

// ─── Existing v1 Exports (PRESERVED) ──────────────────────────

export interface CSPConfig {
  defaultSrc?: string[];
  scriptSrc?: string[];
  styleSrc?: string[];
  fontSrc?: string[];
  imgSrc?: string[];
  connectSrc?: string[];
  frameSrc?: string[];
  objectSrc?: string[];
  baseUri?: string[];
  formAction?: string[];
  frameAncestors?: string[];
  upgradeInsecureRequests?: boolean;
  blockAllMixedContent?: boolean;
  reportTo?: string;
}

export interface SecurityHeadersConfig {
  strictTransportSecurity?: string;
  xContentTypeOptions?: string;
  xFrameOptions?: string;
  referrerPolicy?: string;
  crossOriginOpenerPolicy?: string;
  crossOriginEmbedderPolicy?: string;
  crossOriginResourcePolicy?: string;
  permissionsPolicy?: string;
  contentSecurityPolicy?: string;
}

export interface VrilConfig {
  security: {
    trustedTypes: boolean;
    apiMembrane: boolean;
    blockedAPIs: string[];
    csp: CSPConfig;
    permissionsPolicy: Record<string, string[]>;
    headers: SecurityHeadersConfig;
  };
  crypto: {
    defaultAlgorithm: 'aes-256-gcm' | 'x25519-mlkem768';
    kdfIterations: number;
    pqcEnabled: boolean;
    hybridMode: boolean;
  };
  signals: {
    enabled: boolean;
  };
}

export const DEFAULT_VRIL_CONFIG: VrilConfig = {
  security: {
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
  },
  crypto: {
    defaultAlgorithm: 'aes-256-gcm',
    kdfIterations: 600000,
    pqcEnabled: true,
    hybridMode: true,
  },
  signals: {
    enabled: true,
  },
};

export function createVrilApp(config: Partial<VrilConfig> = {}): { config: VrilConfig; version: string } {
  const merged: VrilConfig = {
    ...DEFAULT_VRIL_CONFIG,
    ...config,
    security: { ...DEFAULT_VRIL_CONFIG.security, ...config.security, csp: { ...DEFAULT_VRIL_CONFIG.security.csp, ...config.security?.csp }, headers: { ...DEFAULT_VRIL_CONFIG.security.headers, ...config.security?.headers } },
    crypto: { ...DEFAULT_VRIL_CONFIG.crypto, ...config.crypto },
    signals: { ...DEFAULT_VRIL_CONFIG.signals, ...config.signals },
  };
  return { config: merged, version: '2.1.0' };
}

// ─── Plugin Lifecycle Hooks ───────────────────────────────────

/** Lifecycle stages for plugins and framework internals */
export type PluginLifecycleHook =
  | 'onInit'
  | 'onReady'
  | 'onRequest'
  | 'onResponse'
  | 'onError'
  | 'onBuild'
  | 'onSecurityCheck';

/** A hook callback receiving a generic context and returning void or a modified context */
export type HookCallback<T = Record<string, unknown>> = (ctx: T) => void | T | Promise<void | T>;

/** Registry for lifecycle hooks with ordered execution */
export class PluginLifecycleRegistry {
  private hooks = new Map<PluginLifecycleHook, HookCallback[]>();
  private version = '2.1.0';

  /** Register a callback for a given lifecycle hook */
  on<T = Record<string, unknown>>(hook: PluginLifecycleHook, callback: HookCallback<T>): () => void {
    if (!this.hooks.has(hook)) {
      this.hooks.set(hook, []);
    }
    const list = this.hooks.get(hook)!;
    list.push(callback as HookCallback);
    return () => {
      const idx = list.indexOf(callback as HookCallback);
      if (idx !== -1) list.splice(idx, 1);
    };
  }

  /** Execute all callbacks for a given hook in registration order */
  async emit<T = Record<string, unknown>>(hook: PluginLifecycleHook, ctx: T): Promise<T> {
    const callbacks = this.hooks.get(hook);
    if (!callbacks || callbacks.length === 0) return ctx;
    let result: any = ctx;
    for (const cb of callbacks) {
      const out = await cb(result);
      if (out !== undefined) result = out;
    }
    return result;
  }

  /** Remove all callbacks for a specific hook */
  clear(hook?: PluginLifecycleHook): void {
    if (hook) {
      this.hooks.delete(hook);
    } else {
      this.hooks.clear();
    }
  }

  /** Get the count of registered hooks */
  getHookCount(hook: PluginLifecycleHook): number {
    return this.hooks.get(hook)?.length ?? 0;
  }

  /** Get all registered hook names */
  getRegisteredHooks(): PluginLifecycleHook[] {
    return Array.from(this.hooks.keys());
  }
}

// ─── Environment Detection ────────────────────────────────────

/** Immutable snapshot of the current runtime environment */
export interface EnvironmentInfo {
  isServer: boolean;
  isClient: boolean;
  isEdge: boolean;
  isDev: boolean;
  isProd: boolean;
  isSSR: boolean;
  runtime: 'node' | 'browser' | 'edge' | 'unknown';
  platform: string;
}

/** Detect the current runtime environment */
export function detectEnvironment(): EnvironmentInfo {
  const isServer = typeof window === 'undefined' && typeof globalThis !== 'undefined';
  const isClient = typeof window !== 'undefined';
  const isEdge =
    typeof globalThis !== 'undefined' &&
    typeof (globalThis as any).EdgeRuntime !== 'undefined';
  const isDev =
    (typeof process !== 'undefined' && process.env?.NODE_ENV === 'development') ||
    (typeof import.meta !== 'undefined' && (import.meta as any).env?.DEV === true);
  const isProd = !isDev;
  const isSSR = isServer && !isEdge;

  let runtime: EnvironmentInfo['runtime'] = 'unknown';
  if (isEdge) runtime = 'edge';
  else if (isServer) runtime = 'node';
  else if (isClient) runtime = 'browser';

  let platform = 'unknown';
  if (typeof navigator !== 'undefined') {
    platform = navigator.platform ?? 'unknown';
  } else if (typeof process !== 'undefined') {
    platform = process.platform ?? 'unknown';
  }

  return Object.freeze({
    isServer,
    isClient,
    isEdge,
    isDev,
    isProd,
    isSSR,
    runtime,
    platform,
  });
}

/** Singleton environment snapshot — computed once at import time */
export const env: EnvironmentInfo = detectEnvironment();

// ─── Feature Flags ────────────────────────────────────────────

export interface FeatureFlagConfig {
  name: string;
  enabled: boolean;
  description?: string;
  rolloutPercentage?: number;
  allowedEnvironments?: Array<'development' | 'production' | 'staging'>;
  expiresAt?: number;
}

/** Type-safe feature flag system with rollout and environment gating */
export class FeatureFlags {
  private flags = new Map<string, FeatureFlagConfig>();
  private version = '2.1.0';

  /** Register a feature flag */
  register(flag: FeatureFlagConfig): void {
    this.flags.set(flag.name, { ...flag });
  }

  /** Check if a feature flag is enabled, considering rollout % and environment */
  isEnabled(name: string, userId?: string): boolean {
    const flag = this.flags.get(name);
    if (!flag) return false;

    if (!flag.enabled) return false;

    if (flag.expiresAt && Date.now() > flag.expiresAt) return false;

    if (flag.allowedEnvironments) {
      const currentEnv = env.isDev ? 'development' : env.isProd ? 'production' : 'staging';
      if (!flag.allowedEnvironments.includes(currentEnv)) return false;
    }

    if (flag.rolloutPercentage !== undefined && flag.rolloutPercentage < 100) {
      if (!userId) return false;
      const hash = simpleHash(`${name}:${userId}`);
      return (hash % 100) < flag.rolloutPercentage;
    }

    return true;
  }

  /** Get all registered flags */
  getAll(): FeatureFlagConfig[] {
    return Array.from(this.flags.values());
  }

  /** Update a flag at runtime */
  update(name: string, patch: Partial<FeatureFlagConfig>): boolean {
    const flag = this.flags.get(name);
    if (!flag) return false;
    this.flags.set(name, { ...flag, ...patch });
    return true;
  }

  /** Remove a flag */
  remove(name: string): boolean {
    return this.flags.delete(name);
  }

  /** Reset all flags */
  clear(): void {
    this.flags.clear();
  }
}

/** Simple deterministic hash for rollout evaluation */
function simpleHash(input: string): number {
  let h = 0;
  for (let i = 0; i < input.length; i++) {
    h = ((h << 5) - h + input.charCodeAt(i)) | 0;
  }
  return Math.abs(h);
}

// ─── App Context ──────────────────────────────────────────────

export interface AppContextShape {
  version: string;
  env: EnvironmentInfo;
  config: VrilConfig;
  flags: FeatureFlags;
  lifecycle: PluginLifecycleRegistry;
  startTime: number;
  metadata: Record<string, unknown>;
}

/** Central application context with provider pattern */
export class AppContext {
  private static instance: AppContext | null = null;
  private ctx: AppContextShape;
  private subscribers = new Set<(ctx: AppContextShape) => void>();

  private constructor(config: Partial<VrilConfig> = {}) {
    const app = createVrilApp(config);
    this.ctx = {
      version: '2.1.0',
      env,
      config: app.config,
      flags: new FeatureFlags(),
      lifecycle: new PluginLifecycleRegistry(),
      startTime: Date.now(),
      metadata: {},
    };
  }

  /** Get or create the singleton app context */
  static getInstance(config?: Partial<VrilConfig>): AppContext {
    if (!AppContext.instance) {
      AppContext.instance = new AppContext(config);
    }
    return AppContext.instance;
  }

  /** Reset the singleton (useful for testing) */
  static reset(): void {
    AppContext.instance = null;
  }

  /** Read the current context */
  get(): AppContextShape {
    return this.ctx;
  }

  /** Update context metadata */
  setMetadata(key: string, value: unknown): void {
    this.ctx.metadata[key] = value;
    this.notify();
  }

  /** Subscribe to context changes */
  subscribe(listener: (ctx: AppContextShape) => void): () => void {
    this.subscribers.add(listener);
    return () => this.subscribers.delete(listener);
  }

  /** Get uptime in milliseconds */
  getUptime(): number {
    return Date.now() - this.ctx.startTime;
  }

  private notify(): void {
    const snapshot = this.get();
    for (const sub of this.subscribers) {
      try { sub(snapshot); } catch { /* swallow subscriber errors */ }
    }
  }
}

// ─── Version Tracking & Migration ─────────────────────────────

export interface VersionInfo {
  current: string;
  previous: string | null;
  migrationsApplied: string[];
  firstRun: boolean;
  timestamp: number;
}

export type MigrationFn = (ctx: AppContextShape) => void | Promise<void>;

export interface MigrationDescriptor {
  from: string;
  to: string;
  migrate: MigrationFn;
}

/** Version tracker with migration support */
export class VersionTracker {
  private migrations: MigrationDescriptor[] = [];
  private currentVersion = '2.1.0';
  private storageKey = '__vril_version__';

  /** Register a migration between versions */
  registerMigration(migration: MigrationDescriptor): void {
    this.migrations.push(migration);
  }

  /** Run all pending migrations based on stored version */
  async runMigrations(ctx: AppContextShape): Promise<VersionInfo> {
    const stored = this.getStoredVersion();
    const previous = stored;
    const applied: string[] = [];

    if (stored && stored !== this.currentVersion) {
      const pending = this.getPendingMigrations(stored);
      for (const m of pending) {
        await m.migrate(ctx);
        applied.push(`${m.from}→${m.to}`);
      }
    }

    this.setStoredVersion(this.currentVersion);

    return {
      current: this.currentVersion,
      previous,
      migrationsApplied: applied,
      firstRun: !stored,
      timestamp: Date.now(),
    };
  }

  /** Get current version */
  getVersion(): string {
    return this.currentVersion;
  }

  /** Get stored version from persistent storage */
  private getStoredVersion(): string | null {
    if (typeof localStorage !== 'undefined') {
      return localStorage.getItem(this.storageKey);
    }
    return null;
  }

  /** Persist version to storage */
  private setStoredVersion(version: string): void {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(this.storageKey, version);
    }
  }

  /** Get migrations that need to run from a given version */
  private getPendingMigrations(fromVersion: string): MigrationDescriptor[] {
    const sorted = [...this.migrations].sort((a, b) =>
      compareVersions(a.from, b.from) - compareVersions(b.from, a.from)
    );
    return sorted.filter(m => compareVersions(m.from, fromVersion) >= 0);
  }
}

/** Semantic version comparison: returns negative if a < b */
function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (na !== nb) return na - nb;
  }
  return 0;
}

// ─── Performance Profiling ────────────────────────────────────

export interface PerformanceMark {
  name: string;
  startTime: number;
  duration: number;
  metadata?: Record<string, unknown>;
}

export interface PerformanceReport {
  marks: PerformanceMark[];
  totalDuration: number;
  slowestMark: PerformanceMark | null;
  timestamp: number;
  version: string;
}

/** Lightweight performance profiler using performance.now() */
export class PerformanceProfiler {
  private marks = new Map<string, { start: number; metadata?: Record<string, unknown> }>();
  private completed: PerformanceMark[] = [];
  private version = '2.1.0';

  /** Start a performance mark */
  startMark(name: string, metadata?: Record<string, unknown>): void {
    this.marks.set(name, {
      start: typeof performance !== 'undefined' ? performance.now() : Date.now(),
      metadata,
    });
  }

  /** End a performance mark and record its duration */
  endMark(name: string): PerformanceMark | null {
    const entry = this.marks.get(name);
    if (!entry) return null;

    const end = typeof performance !== 'undefined' ? performance.now() : Date.now();
    const mark: PerformanceMark = {
      name,
      startTime: entry.start,
      duration: end - entry.start,
      metadata: entry.metadata,
    };

    this.marks.delete(name);
    this.completed.push(mark);
    return mark;
  }

  /** Measure a synchronous function execution */
  measure<T>(name: string, fn: () => T, metadata?: Record<string, unknown>): T {
    this.startMark(name, metadata);
    try {
      return fn();
    } finally {
      this.endMark(name);
    }
  }

  /** Measure an async function execution */
  async measureAsync<T>(name: string, fn: () => Promise<T>, metadata?: Record<string, unknown>): Promise<T> {
    this.startMark(name, metadata);
    try {
      return await fn();
    } finally {
      this.endMark(name);
    }
  }

  /** Generate a performance report */
  getReport(): PerformanceReport {
    const sorted = [...this.completed].sort((a, b) => a.startTime - b.startTime);
    const slowest = sorted.length > 0
      ? sorted.reduce((a, b) => (a.duration > b.duration ? a : b))
      : null;
    const totalDuration = sorted.reduce((sum, m) => sum + m.duration, 0);

    return {
      marks: sorted,
      totalDuration,
      slowestMark: slowest,
      timestamp: Date.now(),
      version: this.version,
    };
  }

  /** Clear all recorded marks */
  clear(): void {
    this.marks.clear();
    this.completed = [];
  }

  /** Get count of completed marks */
  getMarkCount(): number {
    return this.completed.length;
  }
}
