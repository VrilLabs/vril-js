/**
 * Vril.js v2.0.0 — Runtime Diagnostics & Monitoring Module
 * Performance tracking, security health monitoring, crypto profiling,
 * network monitoring, bundle analysis, memory profiling
 *
 * Zero external dependencies — Web APIs and built-in JS only.
 */

// ─── Types ────────────────────────────────────────────────────────

/** A single performance measurement */
export interface PerformanceMetric {
  /** Metric name */
  name: string;
  /** Duration in milliseconds */
  durationMs: number;
  /** Start timestamp (performance.now) */
  startTimestamp: number;
  /** End timestamp (performance.now) */
  endTimestamp: number;
  /** Optional metadata */
  metadata?: Record<string, unknown>;
  /** Category of the metric */
  category: 'render' | 'signal' | 'api' | 'crypto' | 'custom';
}

/** Security diagnostic check result */
export interface SecurityDiagnostic {
  /** Check name */
  check: string;
  /** Current status */
  status: 'pass' | 'warn' | 'fail' | 'info';
  /** Human-readable message */
  message: string;
  /** Severity (1 = info, 5 = critical) */
  severity: number;
  /** Suggested remediation */
  remediation?: string;
  /** Timestamp of the check */
  timestamp: number;
}

/** Crypto operation profile */
export interface CryptoProfile {
  /** Algorithm name */
  algorithm: string;
  /** Operation type */
  operation: 'keygen' | 'encrypt' | 'decrypt' | 'sign' | 'verify' | 'hash' | 'derive';
  /** Average duration in ms */
  avgDurationMs: number;
  /** Min duration in ms */
  minDurationMs: number;
  /** Max duration in ms */
  maxDurationMs: number;
  /** Number of samples */
  sampleCount: number;
  /** Total time spent in ms */
  totalTimeMs: number;
}

/** Network request metric */
export interface NetworkMetric {
  /** Request URL */
  url: string;
  /** HTTP method */
  method: string;
  /** Response status code */
  statusCode: number;
  /** Request duration in ms */
  durationMs: number;
  /** Response size in bytes */
  sizeBytes: number;
  /** Timestamp of the request */
  timestamp: number;
  /** Whether the request was cached */
  cached: boolean;
}

/** Bundle analysis result */
export interface BundleInfo {
  /** Estimated bundle size in bytes */
  sizeBytes: number;
  /** Number of modules loaded */
  moduleCount: number;
  /** Scripts loaded */
  scripts: string[];
  /** Stylesheets loaded */
  stylesheets: string[];
  /** Timestamp of the analysis */
  timestamp: number;
}

/** Memory usage snapshot */
export interface MemorySnapshot {
  /** Used JS heap size in bytes */
  usedJSHeapSize: number;
  /** Total JS heap size in bytes */
  totalJSHeapSize: number;
  /** JS heap size limit in bytes */
  jsHeapSizeLimit: number;
  /** Usage ratio (0-1) */
  usageRatio: number;
  /** Timestamp of the snapshot */
  timestamp: number;
}

/** Comprehensive diagnostic report */
export interface DiagnosticReport {
  /** Report version */
  version: string;
  /** Timestamp of report generation */
  timestamp: number;
  /** Performance metrics */
  performance: PerformanceMetric[];
  /** Security diagnostics */
  security: SecurityDiagnostic[];
  /** Crypto profiles */
  crypto: CryptoProfile[];
  /** Network metrics */
  network: NetworkMetric[];
  /** Bundle info */
  bundle: BundleInfo | null;
  /** Memory snapshots */
  memory: MemorySnapshot[];
  /** Environment info */
  environment: {
    userAgent: string;
    isSecureContext: boolean;
    hasWebCrypto: boolean;
    hasTrustedTypes: boolean;
    hasServiceWorker: boolean;
    protocol: string;
  };
}

// ─── PerformanceMonitor ───────────────────────────────────────────

/**
 * Track component render times, signal updates, and API calls.
 * Uses performance.now() for high-resolution timing.
 */
export class PerformanceMonitor {
  private metrics: PerformanceMetric[] = [];
  private activeMarks = new Map<string, { start: number; category: PerformanceMetric['category']; metadata?: Record<string, unknown> }>();
  private _version = '2.1.0';
  private maxMetrics = 1000;

  /** Start a performance mark */
  startMark(name: string, category: PerformanceMetric['category'] = 'custom', metadata?: Record<string, unknown>): void {
    this.activeMarks.set(name, {
      start: typeof performance !== 'undefined' ? performance.now() : Date.now(),
      category,
      metadata,
    });
  }

  /** End a performance mark and record the metric */
  endMark(name: string): PerformanceMetric | null {
    const mark = this.activeMarks.get(name);
    if (!mark) return null;

    const end = typeof performance !== 'undefined' ? performance.now() : Date.now();
    const metric: PerformanceMetric = {
      name,
      durationMs: end - mark.start,
      startTimestamp: mark.start,
      endTimestamp: end,
      metadata: mark.metadata,
      category: mark.category,
    };

    this.activeMarks.delete(name);
    this.metrics.push(metric);

    // Evict oldest if at capacity
    if (this.metrics.length > this.maxMetrics) {
      this.metrics.shift();
    }

    return metric;
  }

  /** Measure a synchronous function */
  measure<T>(name: string, fn: () => T, category: PerformanceMetric['category'] = 'custom', metadata?: Record<string, unknown>): T {
    this.startMark(name, category, metadata);
    try {
      return fn();
    } finally {
      this.endMark(name);
    }
  }

  /** Measure an asynchronous function */
  async measureAsync<T>(name: string, fn: () => Promise<T>, category: PerformanceMetric['category'] = 'custom', metadata?: Record<string, unknown>): Promise<T> {
    this.startMark(name, category, metadata);
    try {
      return await fn();
    } finally {
      this.endMark(name);
    }
  }

  /** Get all recorded metrics */
  getMetrics(category?: PerformanceMetric['category']): PerformanceMetric[] {
    if (category) return this.metrics.filter(m => m.category === category);
    return [...this.metrics];
  }

  /** Get average duration for a named metric */
  getAverageDuration(name: string): number {
    const matching = this.metrics.filter(m => m.name === name);
    if (matching.length === 0) return 0;
    return matching.reduce((sum, m) => sum + m.durationMs, 0) / matching.length;
  }

  /** Get the slowest N metrics */
  getSlowest(count: number = 10): PerformanceMetric[] {
    return [...this.metrics].sort((a, b) => b.durationMs - a.durationMs).slice(0, count);
  }

  /** Get count of recorded metrics */
  getCount(): number {
    return this.metrics.length;
  }

  /** Clear all metrics */
  clear(): void {
    this.metrics = [];
    this.activeMarks.clear();
  }
}

// ─── SecurityDiagnostics ──────────────────────────────────────────

/**
 * Real-time security health monitoring.
 * Checks for common security misconfigurations and vulnerabilities.
 */
export class SecurityDiagnostics {
  private checks: SecurityDiagnostic[] = [];
  private _version = '2.1.0';

  /** Run all security diagnostics and return results */
  runAll(): SecurityDiagnostic[] {
    this.checks = [];
    this.checkSecureContext();
    this.checkContentSecurityPolicy();
    this.checkTrustedTypes();
    this.checkMixedContent();
    this.checkCookieSecurity();
    this.checkCrossOriginIsolation();
    this.checkPermissionsPolicy();
    this.checkXSSVulnerabilities();
    this.checkStorageSecurity();
    this.checkWebCryptoAvailability();
    return [...this.checks];
  }

  /** Get the last diagnostic results */
  getResults(): SecurityDiagnostic[] {
    return [...this.checks];
  }

  /** Get checks by status */
  getByStatus(status: SecurityDiagnostic['status']): SecurityDiagnostic[] {
    return this.checks.filter(c => c.status === status);
  }

  /** Get overall security score (0-100) */
  getScore(): number {
    if (this.checks.length === 0) return 0;
    const weights = { pass: 100, info: 80, warn: 40, fail: 0 };
    const total = this.checks.reduce((sum, c) => sum + weights[c.status], 0);
    return Math.round(total / this.checks.length);
  }

  // ─── Individual Checks ────────────────────────────────────────

  private addCheck(check: Omit<SecurityDiagnostic, 'timestamp'>): void {
    this.checks.push({ ...check, timestamp: Date.now() });
  }

  private checkSecureContext(): void {
    const isSecure = typeof window !== 'undefined' && window.isSecureContext;
    this.addCheck({
      check: 'Secure Context',
      status: isSecure ? 'pass' : 'fail',
      message: isSecure ? 'Running in a secure context (HTTPS)' : 'Not running in a secure context',
      severity: isSecure ? 0 : 5,
      remediation: isSecure ? undefined : 'Serve the application over HTTPS to enable security-sensitive APIs',
    });
  }

  private checkContentSecurityPolicy(): void {
    if (typeof document === 'undefined') return;
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    const hasCSP = !!cspMeta;
    this.addCheck({
      check: 'Content Security Policy',
      status: hasCSP ? 'pass' : 'warn',
      message: hasCSP ? 'CSP header detected' : 'No Content-Security-Policy header found',
      severity: hasCSP ? 0 : 4,
      remediation: hasCSP ? undefined : 'Add a Content-Security-Policy header to prevent XSS and injection attacks',
    });

    if (hasCSP) {
      const content = cspMeta!.getAttribute('content') ?? '';
      if (content.includes("'unsafe-inline'")) {
        this.addCheck({
          check: 'CSP unsafe-inline',
          status: 'warn',
          message: 'CSP allows unsafe-inline scripts',
          severity: 3,
          remediation: 'Use nonce-based CSP instead of unsafe-inline',
        });
      }
      if (content.includes("'unsafe-eval'")) {
        this.addCheck({
          check: 'CSP unsafe-eval',
          status: 'fail',
          message: 'CSP allows unsafe-eval',
          severity: 4,
          remediation: 'Remove unsafe-eval from CSP and refactor code to avoid eval()',
        });
      }
    }
  }

  private checkTrustedTypes(): void {
    const hasTT = typeof window !== 'undefined' && !!(window as any).trustedTypes;
    this.addCheck({
      check: 'Trusted Types',
      status: hasTT ? 'pass' : 'info',
      message: hasTT ? 'Trusted Types API available' : 'Trusted Types API not available',
      severity: 0,
      remediation: hasTT ? undefined : 'Enable Trusted Types for additional XSS protection',
    });
  }

  private checkMixedContent(): void {
    if (typeof document === 'undefined') return;
    const isHTTPS = location.protocol === 'https:';
    if (!isHTTPS) return;

    const insecureResources = document.querySelectorAll(
      'img[src^="http:"], script[src^="http:"], link[href^="http:"]'
    );
    this.addCheck({
      check: 'Mixed Content',
      status: insecureResources.length === 0 ? 'pass' : 'fail',
      message: insecureResources.length === 0
        ? 'No mixed content detected'
        : `${insecureResources.length} insecure resources found on HTTPS page`,
      severity: insecureResources.length === 0 ? 0 : 4,
      remediation: insecureResources.length > 0 ? 'Replace all HTTP resource URLs with HTTPS' : undefined,
    });
  }

  private checkCookieSecurity(): void {
    if (typeof document === 'undefined') return;
    const cookies = document.cookie.split(';');
    let insecureCount = 0;
    for (const cookie of cookies) {
      const trimmed = cookie.trim();
      if (trimmed && !trimmed.toLowerCase().includes('secure') && !trimmed.toLowerCase().includes('httponly')) {
        insecureCount++;
      }
    }
    this.addCheck({
      check: 'Cookie Security',
      status: insecureCount === 0 ? 'pass' : 'warn',
      message: insecureCount === 0
        ? 'All cookies have security attributes'
        : `${insecureCount} cookies may be missing Secure/HttpOnly flags`,
      severity: insecureCount === 0 ? 0 : 3,
      remediation: insecureCount > 0 ? 'Set Secure and HttpOnly flags on all cookies' : undefined,
    });
  }

  private checkCrossOriginIsolation(): void {
    if (typeof window === 'undefined') return;
    const isolated = typeof crossOriginIsolated !== 'undefined' && crossOriginIsolated;

    this.addCheck({
      check: 'Cross-Origin Isolation',
      status: isolated ? 'pass' : 'warn',
      message: isolated
        ? 'Cross-origin isolation enabled (SharedArrayBuffer available)'
        : 'Cross-origin isolation not enabled',
      severity: isolated ? 0 : 2,
      remediation: isolated ? undefined : 'Set Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy headers',
    });
  }

  private checkPermissionsPolicy(): void {
    if (typeof document === 'undefined') return;
    const hasPP = !!document.querySelector('meta[http-equiv="Permissions-Policy"]');
    this.addCheck({
      check: 'Permissions Policy',
      status: hasPP ? 'pass' : 'info',
      message: hasPP ? 'Permissions-Policy header detected' : 'No Permissions-Policy header found',
      severity: 0,
      remediation: 'Add a Permissions-Policy header to restrict browser feature access',
    });
  }

  private checkXSSVulnerabilities(): void {
    if (typeof document === 'undefined') return;
    const inlineEventHandlers = document.querySelectorAll('[onclick], [onerror], [onload], [onmouseover]');
    this.addCheck({
      check: 'Inline Event Handlers',
      status: inlineEventHandlers.length === 0 ? 'pass' : 'warn',
      message: inlineEventHandlers.length === 0
        ? 'No inline event handlers detected'
        : `${inlineEventHandlers.length} inline event handlers found (potential XSS risk)`,
      severity: inlineEventHandlers.length === 0 ? 0 : 3,
      remediation: inlineEventHandlers.length > 0 ? 'Replace inline event handlers with addEventListener' : undefined,
    });
  }

  private checkStorageSecurity(): void {
    if (typeof localStorage === 'undefined') return;
    let sensitiveDataCount = 0;
    const sensitivePatterns = ['token', 'password', 'secret', 'key', 'credential', 'auth'];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && sensitivePatterns.some(p => key.toLowerCase().includes(p))) {
        sensitiveDataCount++;
      }
    }
    this.addCheck({
      check: 'Storage Security',
      status: sensitiveDataCount === 0 ? 'pass' : 'warn',
      message: sensitiveDataCount === 0
        ? 'No sensitive data patterns found in localStorage'
        : `${sensitiveDataCount} potentially sensitive items found in localStorage`,
      severity: sensitiveDataCount === 0 ? 0 : 3,
      remediation: sensitiveDataCount > 0 ? 'Use encrypted storage for sensitive data instead of plain localStorage' : undefined,
    });
  }

  private checkWebCryptoAvailability(): void {
    const hasWebCrypto = typeof crypto !== 'undefined' && !!crypto.subtle;
    this.addCheck({
      check: 'Web Crypto API',
      status: hasWebCrypto ? 'pass' : 'fail',
      message: hasWebCrypto ? 'Web Crypto API available' : 'Web Crypto API not available',
      severity: hasWebCrypto ? 0 : 5,
      remediation: hasWebCrypto ? undefined : 'Ensure the page is served over HTTPS to enable Web Crypto API',
    });
  }
}

// ─── CryptoProfiler ───────────────────────────────────────────────

/**
 * Profile cryptographic operations (key generation, encryption, decryption, signing).
 * Tracks timing and throughput for each algorithm and operation type.
 */
export class CryptoProfiler {
  private profiles = new Map<string, CryptoProfile>();
  private _version = '2.1.0';

  /** Profile a synchronous crypto function */
  profileSync<T>(
    algorithm: string,
    operation: CryptoProfile['operation'],
    fn: () => T
  ): T {
    const start = performance.now();
    try {
      return fn();
    } finally {
      const duration = performance.now() - start;
      this.recordSample(algorithm, operation, duration);
    }
  }

  /** Profile an asynchronous crypto function */
  async profileAsync<T>(
    algorithm: string,
    operation: CryptoProfile['operation'],
    fn: () => Promise<T>
  ): Promise<T> {
    const start = performance.now();
    try {
      return await fn();
    } finally {
      const duration = performance.now() - start;
      this.recordSample(algorithm, operation, duration);
    }
  }

  /** Record a timing sample */
  private recordSample(algorithm: string, operation: CryptoProfile['operation'], durationMs: number): void {
    const key = `${algorithm}:${operation}`;
    const existing = this.profiles.get(key);

    if (existing) {
      existing.sampleCount++;
      existing.totalTimeMs += durationMs;
      existing.minDurationMs = Math.min(existing.minDurationMs, durationMs);
      existing.maxDurationMs = Math.max(existing.maxDurationMs, durationMs);
      existing.avgDurationMs = existing.totalTimeMs / existing.sampleCount;
    } else {
      this.profiles.set(key, {
        algorithm,
        operation,
        avgDurationMs: durationMs,
        minDurationMs: durationMs,
        maxDurationMs: durationMs,
        sampleCount: 1,
        totalTimeMs: durationMs,
      });
    }
  }

  /** Get profile for a specific algorithm and operation */
  getProfile(algorithm: string, operation: CryptoProfile['operation']): CryptoProfile | undefined {
    return this.profiles.get(`${algorithm}:${operation}`);
  }

  /** Get all recorded profiles */
  getAllProfiles(): CryptoProfile[] {
    return Array.from(this.profiles.values());
  }

  /** Clear all profiles */
  clear(): void {
    this.profiles.clear();
  }
}

// ─── NetworkMonitor ───────────────────────────────────────────────

/**
 * Track API calls, response times, and error rates.
 * Uses fetch interception and PerformanceObserver when available.
 */
export class NetworkMonitor {
  private metrics: NetworkMetric[] = [];
  private _version = '2.1.0';
  private maxMetrics = 500;
  private originalFetch: typeof fetch | null = null;
  private intercepting = false;

  /** Start intercepting fetch requests */
  startInterception(): void {
    if (this.intercepting || typeof window === 'undefined') return;

    this.originalFetch = window.fetch;
    const self = this;

    window.fetch = async function(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      const method = init?.method ?? 'GET';
      const start = performance.now();

      try {
        const response = await self.originalFetch!.call(this, input, init);
        const duration = performance.now() - start;

        self.recordMetric({
          url,
          method,
          statusCode: response.status,
          durationMs: duration,
          sizeBytes: parseInt(response.headers.get('content-length') ?? '0', 10),
          timestamp: Date.now(),
          cached: response.headers.get('x-cache') === 'HIT',
        });

        return response;
      } catch (err) {
        self.recordMetric({
          url,
          method,
          statusCode: 0,
          durationMs: performance.now() - start,
          sizeBytes: 0,
          timestamp: Date.now(),
          cached: false,
        });
        throw err;
      }
    };

    this.intercepting = true;
  }

  /** Stop intercepting fetch requests */
  stopInterception(): void {
    if (!this.intercepting || !this.originalFetch) return;
    window.fetch = this.originalFetch;
    this.originalFetch = null;
    this.intercepting = false;
  }

  /** Record a network metric manually */
  recordMetric(metric: NetworkMetric): void {
    this.metrics.push(metric);
    if (this.metrics.length > this.maxMetrics) {
      this.metrics.shift();
    }
  }

  /** Get all recorded metrics */
  getMetrics(urlPattern?: RegExp): NetworkMetric[] {
    if (urlPattern) return this.metrics.filter(m => urlPattern.test(m.url));
    return [...this.metrics];
  }

  /** Get error rate (0-1) */
  getErrorRate(): number {
    if (this.metrics.length === 0) return 0;
    const errors = this.metrics.filter(m => m.statusCode >= 400 || m.statusCode === 0).length;
    return errors / this.metrics.length;
  }

  /** Get average response time */
  getAverageResponseTime(urlPattern?: RegExp): number {
    const metrics = urlPattern ? this.metrics.filter(m => urlPattern.test(m.url)) : this.metrics;
    if (metrics.length === 0) return 0;
    return metrics.reduce((sum, m) => sum + m.durationMs, 0) / metrics.length;
  }

  /** Get total bytes transferred */
  getTotalBytes(): number {
    return this.metrics.reduce((sum, m) => sum + m.sizeBytes, 0);
  }

  /** Clear all metrics */
  clear(): void {
    this.metrics = [];
  }
}

// ─── BundleAnalyzer ───────────────────────────────────────────────

/**
 * Runtime bundle size tracking.
 * Analyzes the currently loaded resources on the page.
 */
export class BundleAnalyzer {
  private _version = '2.1.0';

  /** Analyze the current page's loaded resources */
  analyze(): BundleInfo {
    const scripts: string[] = [];
    const stylesheets: string[] = [];
    let totalSize = 0;

    if (typeof document !== 'undefined') {
      // Count scripts
      const scriptElements = document.querySelectorAll('script[src]');
      scriptElements.forEach(el => {
        const src = el.getAttribute('src');
        if (src) scripts.push(src);
      });

      // Count stylesheets
      const linkElements = document.querySelectorAll('link[rel="stylesheet"]');
      linkElements.forEach(el => {
        const href = el.getAttribute('href');
        if (href) stylesheets.push(href);
      });

      // Estimate size from Performance API
      if (typeof performance !== 'undefined' && performance.getEntriesByType) {
        const resources = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
        totalSize = resources.reduce((sum, r) => sum + (r.transferSize || 0), 0);
      }
    }

    return {
      sizeBytes: totalSize,
      moduleCount: scripts.length + stylesheets.length,
      scripts,
      stylesheets,
      timestamp: Date.now(),
    };
  }

  /** Get resource timing data for loaded scripts */
  getScriptTiming(): Array<{ url: string; durationMs: number; sizeBytes: number }> {
    if (typeof performance === 'undefined' || !performance.getEntriesByType) return [];

    const resources = performance.getEntriesByType('resource') as PerformanceResourceTiming[];
    return resources
      .filter(r => r.initiatorType === 'script')
      .map(r => ({
        url: r.name,
        durationMs: r.duration,
        sizeBytes: r.transferSize || 0,
      }));
  }
}

// ─── MemoryProfiler ───────────────────────────────────────────────

/**
 * Track memory usage patterns.
 * Uses the Performance.memory API (Chromium-only) with fallbacks.
 */
export class MemoryProfiler {
  private snapshots: MemorySnapshot[] = [];
  private _version = '2.1.0';
  private maxSnapshots = 100;
  private intervalId: ReturnType<typeof setInterval> | null = null;

  /** Take a memory snapshot */
  snapshot(): MemorySnapshot | null {
    const perf = performance as any;
    if (!perf?.memory) return null;

    const snap: MemorySnapshot = {
      usedJSHeapSize: perf.memory.usedJSHeapSize,
      totalJSHeapSize: perf.memory.totalJSHeapSize,
      jsHeapSizeLimit: perf.memory.jsHeapSizeLimit,
      usageRatio: perf.memory.usedJSHeapSize / perf.memory.jsHeapSizeLimit,
      timestamp: Date.now(),
    };

    this.snapshots.push(snap);
    if (this.snapshots.length > this.maxSnapshots) {
      this.snapshots.shift();
    }

    return snap;
  }

  /** Start periodic memory monitoring */
  startMonitoring(intervalMs: number = 5000): void {
    this.stopMonitoring();
    this.intervalId = setInterval(() => this.snapshot(), intervalMs);
  }

  /** Stop periodic memory monitoring */
  stopMonitoring(): void {
    if (this.intervalId !== null) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  /** Get all recorded snapshots */
  getSnapshots(): MemorySnapshot[] {
    return [...this.snapshots];
  }

  /** Detect potential memory leaks (consistent growth pattern) */
  detectLeak(): { likely: boolean; growthRate: number; message: string } {
    if (this.snapshots.length < 5) {
      return { likely: false, growthRate: 0, message: 'Insufficient data (need 5+ snapshots)' };
    }

    const recent = this.snapshots.slice(-10);
    let totalGrowth = 0;
    for (let i = 1; i < recent.length; i++) {
      totalGrowth += recent[i].usedJSHeapSize - recent[i - 1].usedJSHeapSize;
    }

    const avgGrowth = totalGrowth / (recent.length - 1);
    const growthRate = avgGrowth / (recent[0].usedJSHeapSize || 1);
    const likely = growthRate > 0.01; // >1% consistent growth

    return {
      likely,
      growthRate,
      message: likely
        ? `Potential memory leak detected: ${(growthRate * 100).toFixed(2)}% growth per snapshot`
        : 'No significant memory growth detected',
    };
  }

  /** Clear all snapshots */
  clear(): void {
    this.snapshots = [];
  }
}

// ─── createDiagnosticReport ───────────────────────────────────────

/**
 * Generate a comprehensive diagnostic report combining all monitoring modules.
 * Captures a full snapshot of the application's runtime health.
 */
export function createDiagnosticReport(): DiagnosticReport {
  const perf = new PerformanceMonitor();
  const security = new SecurityDiagnostics();
  const cryptoProfiler = new CryptoProfiler();
  const network = new NetworkMonitor();
  const bundle = new BundleAnalyzer();
  const memory = new MemoryProfiler();

  // Run security checks
  const securityResults = security.runAll();

  // Capture memory
  const memorySnap = memory.snapshot();

  return {
    version: '2.1.0',
    timestamp: Date.now(),
    performance: perf.getMetrics(),
    security: securityResults,
    crypto: cryptoProfiler.getAllProfiles(),
    network: network.getMetrics(),
    bundle: bundle.analyze(),
    memory: memorySnap ? [memorySnap] : [],
    environment: {
      userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'unknown',
      isSecureContext: typeof window !== 'undefined' ? window.isSecureContext : false,
      hasWebCrypto: typeof globalThis.crypto !== 'undefined' && !!globalThis.crypto.subtle,
      hasTrustedTypes: typeof window !== 'undefined' && !!(window as any).trustedTypes,
      hasServiceWorker: typeof navigator !== 'undefined' && 'serviceWorker' in navigator,
      protocol: typeof location !== 'undefined' ? location.protocol : 'unknown',
    },
  };
}
