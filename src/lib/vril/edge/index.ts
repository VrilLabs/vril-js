/**
 * Vril.js v2.0.0 — Edge Runtime Utilities
 * Edge detection & adaptation · Key-value store · Geolocation ·
 * Edge security · Edge-compatible request handlers
 *
 * Zero external dependencies — Web Crypto API and built-in JS only.
 */

// ─── Types ────────────────────────────────────────────────────

/** Configuration for edge runtime */
export interface EdgeConfig {
  /** Region hint for edge placement */
  region?: string;
  /** Maximum execution time in ms (edge runtimes have limits) */
  maxExecutionTime?: number;
  /** Enable geolocation */
  geoEnabled?: boolean;
  /** Enable bot detection */
  botDetection?: boolean;
  /** Security headers preset */
  securityLevel?: 'strict' | 'moderate' | 'permissive';
  /** IP allowlist for restricted access */
  ipAllowlist?: string[];
  /** IP blocklist */
  ipBlocklist?: string[];
}

/** Geolocation data derived from request headers */
export interface GeoData {
  country?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  postalCode?: string;
  metroCode?: string;
  /** Whether this data is approximate (privacy-safe) */
  approximated: boolean;
}

/** Detected edge environment details */
export interface EdgeEnvironment {
  isEdge: boolean;
  runtime: 'cloudflare' | 'vercel' | 'deno' | 'aws-lambda' | 'generic' | 'unknown';
  region: string;
  supportsWaitUntil: boolean;
  supportsCache: boolean;
  supportsKV: boolean;
  supportsDurableObjects: boolean;
}

// ─── Edge Runtime ─────────────────────────────────────────────

/**
 * Detect and adapt to edge runtime environments.
 * Provides environment-specific optimizations and capability detection.
 */
export class EdgeRuntime {
  private config: EdgeConfig;
  private env: EdgeEnvironment;
  private version = '2.1.0';

  constructor(config: EdgeConfig = {}) {
    this.config = config;
    this.env = this.detectEnvironment();
  }

  /** Detect the current edge runtime environment */
  detectEnvironment(): EdgeEnvironment {
    const globalRef = globalThis as Record<string, unknown>;

    const isEdge =
      typeof globalRef.EdgeRuntime !== 'undefined' ||
      typeof globalRef.caches !== 'undefined' ||
      typeof globalRef.KV !== 'undefined';

    let runtime: EdgeEnvironment['runtime'] = 'unknown';

    if (typeof globalRef.caches !== 'undefined' && typeof globalRef.KV !== 'undefined') {
      runtime = 'cloudflare';
    } else if (typeof globalRef.EdgeRuntime !== 'undefined') {
      runtime = 'vercel';
    } else if (typeof (globalRef as any).Deno !== 'undefined') {
      runtime = 'deno';
    } else if (typeof process !== 'undefined' && process.env?.AWS_LAMBDA_FUNCTION_NAME) {
      runtime = 'aws-lambda';
    } else if (isEdge) {
      runtime = 'generic';
    }

    return {
      isEdge,
      runtime,
      region: this.config.region ?? this.detectRegion(),
      supportsWaitUntil: typeof globalRef.waitUntil === 'function' || typeof ((globalRef as Record<string, unknown>).context as Record<string, unknown> | undefined)?.waitUntil === 'function',
      supportsCache: typeof globalRef.caches !== 'undefined',
      supportsKV: typeof globalRef.KV !== 'undefined' || typeof globalRef.__KV__ !== 'undefined',
      supportsDurableObjects: typeof globalRef.DurableObject !== 'undefined',
    };
  }

  /** Get the detected environment */
  getEnvironment(): EdgeEnvironment {
    return this.env;
  }

  /** Check if a specific capability is available */
  hasCapability(capability: keyof Omit<EdgeEnvironment, 'isEdge' | 'runtime' | 'region'>): boolean {
    return this.env[capability] as boolean;
  }

  /** Attempt to detect the edge region from headers or environment */
  private detectRegion(): string {
    const globalRef = globalThis as unknown as Record<string, string>;
    return globalRef.REGION ?? globalRef.VERCEL_REGION ?? globalRef.CF_REGION ?? 'unknown';
  }
}

// ─── Edge KV ──────────────────────────────────────────────────

/**
 * Key-value store abstraction for edge environments.
 * Falls back to in-memory storage when no native KV is available.
 */
export class EdgeKV<V = unknown> {
  private store = new Map<string, { value: V; expiresAt: number }>();
  private namespace: string;
  private version = '2.1.0';

  constructor(namespace: string = 'default') {
    this.namespace = namespace;
  }

  /** Get a value by key */
  async get(key: string): Promise<V | null> {
    const namespacedKey = this.prefixKey(key);
    const entry = this.store.get(namespacedKey);

    if (!entry) return null;
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.store.delete(namespacedKey);
      return null;
    }

    return entry.value;
  }

  /** Set a value with optional TTL */
  async set(key: string, value: V, ttlMs?: number): Promise<void> {
    const namespacedKey = this.prefixKey(key);
    this.store.set(namespacedKey, {
      value,
      expiresAt: ttlMs ? Date.now() + ttlMs : Infinity,
    });
  }

  /** Delete a key */
  async delete(key: string): Promise<boolean> {
    return this.store.delete(this.prefixKey(key));
  }

  /** List keys matching a prefix */
  async list(prefix?: string): Promise<string[]> {
    const keys: string[] = [];
    const searchPrefix = prefix ? this.prefixKey(prefix) : `${this.namespace}:`;

    for (const key of this.store.keys()) {
      if (key.startsWith(searchPrefix)) {
        keys.push(key.substring(this.namespace.length + 1));
      }
    }
    return keys;
  }

  /** Check if a key exists */
  async has(key: string): Promise<boolean> {
    const namespacedKey = this.prefixKey(key);
    const entry = this.store.get(namespacedKey);
    if (!entry) return false;
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.store.delete(namespacedKey);
      return false;
    }
    return true;
  }

  /** Get the number of entries */
  get size(): number {
    return this.store.size;
  }

  /** Clear all entries in this namespace */
  async clear(): Promise<void> {
    const keysToDelete: string[] = [];
    for (const key of this.store.keys()) {
      if (key.startsWith(`${this.namespace}:`)) {
        keysToDelete.push(key);
      }
    }
    for (const key of keysToDelete) {
      this.store.delete(key);
    }
  }

  private prefixKey(key: string): string {
    return `${this.namespace}:${key}`;
  }
}

// ─── Edge Geo ─────────────────────────────────────────────────

/** Standard headers that carry geolocation data across CDN providers */
const GEO_HEADERS: Record<string, (value: string) => Partial<GeoData>> = {
  'cf-ipcountry': (v) => ({ country: v.toUpperCase() }),
  'x-vercel-ip-country': (v) => ({ country: v.toUpperCase() }),
  'x-vercel-ip-country-region': (v) => ({ region: v }),
  'x-vercel-ip-city': (v) => ({ city: decodeURIComponent(v) }),
  'x-vercel-ip-latitude': (v) => ({ latitude: parseFloat(v) }),
  'x-vercel-ip-longitude': (v) => ({ longitude: parseFloat(v) }),
  'x-vercel-ip-timezone': (v) => ({ timezone: v }),
  'x-geo-country': (v) => ({ country: v.toUpperCase() }),
  'x-geo-region': (v) => ({ region: v }),
  'x-geo-city': (v) => ({ city: decodeURIComponent(v) }),
  'x-geo-lat': (v) => ({ latitude: parseFloat(v) }),
  'x-geo-lon': (v) => ({ longitude: parseFloat(v) }),
  'x-forwarded-for': () => ({}), // Don't expose raw IP
};

/**
 * Extract geolocation from request headers with privacy controls.
 * Supports Cloudflare, Vercel, and generic CDN geo headers.
 */
export class EdgeGeo {
  private privacyMode: 'full' | 'approximate' | 'none';
  private version = '2.1.0';

  constructor(privacyMode: 'full' | 'approximate' | 'none' = 'approximate') {
    this.privacyMode = privacyMode;
  }

  /** Extract geo data from request headers */
  extract(headers: Record<string, string>): GeoData {
    if (this.privacyMode === 'full') {
      return { approximated: true };
    }

    const geo: GeoData = { approximated: this.privacyMode === 'approximate' };

    for (const [headerName, parser] of Object.entries(GEO_HEADERS)) {
      const value = headers[headerName] ?? headers[headerName.toLowerCase()];
      if (value) {
        Object.assign(geo, parser(value));
      }
    }

    // In approximate mode, reduce precision of coordinates
    if (this.privacyMode === 'approximate') {
      if (geo.latitude !== undefined) {
        geo.latitude = Math.round(geo.latitude * 10) / 10; // ~11km precision
      }
      if (geo.longitude !== undefined) {
        geo.longitude = Math.round(geo.longitude * 10) / 10;
      }
      // Remove postal code for privacy
      delete geo.postalCode;
    }

    return geo;
  }

  /** Check if request is from a specific country */
  isFromCountry(headers: Record<string, string>, countryCode: string): boolean {
    const geo = this.extract(headers);
    return geo.country?.toUpperCase() === countryCode.toUpperCase();
  }

  /** Check if request is from an EU country (GDPR check) */
  isFromEU(headers: Record<string, string>): boolean {
    const euCountries = new Set([
      'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR',
      'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL',
      'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE',
    ]);
    const geo = this.extract(headers);
    return geo.country ? euCountries.has(geo.country) : false;
  }
}

// ─── Edge Security ────────────────────────────────────────────

/** Known bot user-agent patterns */
const BOT_PATTERNS: RegExp[] = [
  /bot/i,
  /crawl/i,
  /spider/i,
  /scrape/i,
  /headless/i,
  /curl/i,
  /wget/i,
  /python-requests/i,
  /go-http/i,
  /java\//i,
  /node-fetch/i,
  /axios/i,
  /postman/i,
  /insomnia/i,
];

/**
 * Edge-specific security: headers, bot detection, IP allowlisting.
 * Optimized for fast execution at the edge.
 */
export class EdgeSecurity {
  private config: EdgeConfig;
  private version = '2.1.0';

  constructor(config: EdgeConfig = {}) {
    this.config = config;
  }

  /** Generate security headers based on the configured level */
  getSecurityHeaders(): Record<string, string> {
    const level = this.config.securityLevel ?? 'moderate';

    const strict: Record<string, string> = {
      'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '0',
      'Referrer-Policy': 'no-referrer',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
      'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'",
      'X-Vril-Version': this.version,
    };

    const moderate: Record<string, string> = {
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN',
      'X-XSS-Protection': '0',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'X-Vril-Version': this.version,
    };

    const permissive: Record<string, string> = {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN',
      'X-Vril-Version': this.version,
    };

    switch (level) {
      case 'strict': return strict;
      case 'moderate': return moderate;
      case 'permissive': return permissive;
    }
  }

  /** Detect if the request comes from a bot */
  isBot(userAgent: string): boolean {
    if (!userAgent) return true; // No user-agent = suspicious
    return BOT_PATTERNS.some((pattern) => pattern.test(userAgent));
  }

  /** Check if an IP is allowed based on allowlist/blocklist */
  isIPAllowed(ip: string): boolean {
    if (!ip) return false;

    // Blocklist takes precedence
    if (this.config.ipBlocklist && this.config.ipBlocklist.includes(ip)) {
      return false;
    }

    // If allowlist is defined, only allow listed IPs
    if (this.config.ipAllowlist && this.config.ipAllowlist.length > 0) {
      return this.config.ipAllowlist.includes(ip);
    }

    return true;
  }

  /** Validate a request's basic security properties */
  validateRequest(request: {
    ip?: string;
    userAgent?: string;
    headers?: Record<string, string>;
    method?: string;
  }): { allowed: boolean; reason?: string } {
    // IP check
    if (request.ip && !this.isIPAllowed(request.ip)) {
      return { allowed: false, reason: 'IP blocked' };
    }

    // Bot check (if enabled)
    if (this.config.botDetection && request.userAgent && this.isBot(request.userAgent)) {
      return { allowed: false, reason: 'Bot detected' };
    }

    // Method check
    const allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
    if (request.method && !allowedMethods.includes(request.method.toUpperCase())) {
      return { allowed: false, reason: 'Invalid HTTP method' };
    }

    return { allowed: true };
  }

  /** Rate limit check using a simple in-memory counter (edge-compatible) */
  createRateLimit(options: {
    windowMs: number;
    maxRequests: number;
  }): (key: string) => { allowed: boolean; remaining: number; resetAt: number } {
    const counters = new Map<string, { count: number; resetAt: number }>();

    return (key: string) => {
      const now = Date.now();
      let counter = counters.get(key);

      if (!counter || now > counter.resetAt) {
        counter = { count: 0, resetAt: now + options.windowMs };
        counters.set(key, counter);
      }

      counter.count++;

      if (counter.count > options.maxRequests) {
        return { allowed: false, remaining: 0, resetAt: counter.resetAt };
      }

      return {
        allowed: true,
        remaining: options.maxRequests - counter.count,
        resetAt: counter.resetAt,
      };
    };
  }
}

// ─── Create Edge Handler ──────────────────────────────────────

/**
 * Create an edge-compatible request handler with built-in security.
 * Returns a function compatible with standard Request → Response patterns.
 */
export function createEdgeHandler(
  handler: (request: Request, context: EdgeHandlerContext) => Promise<Response> | Response,
  config?: EdgeConfig
): (request: Request, context?: EdgeHandlerContext) => Promise<Response> {
  const security = new EdgeSecurity(config);
  const geo = new EdgeGeo(config?.geoEnabled === false ? 'full' : 'approximate');
  const kv = new EdgeKV('edge-handler');

  return async (request: Request, context?: EdgeHandlerContext) => {
    const startTime = Date.now();

    try {
      // Extract request metadata
      const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? '';
      const userAgent = request.headers.get('user-agent') ?? '';
      const headersObj: Record<string, string> = {};
      request.headers.forEach((value, key) => {
        headersObj[key] = value;
      });

      // Security validation
      const validation = security.validateRequest({
        ip,
        userAgent,
        headers: headersObj,
        method: request.method,
      });

      if (!validation.allowed) {
        return new Response(
          JSON.stringify({ error: 'Forbidden', reason: validation.reason }),
          {
            status: 403,
            headers: {
              'Content-Type': 'application/json',
              ...security.getSecurityHeaders(),
            },
          }
        );
      }

      // Build context
      const ctx: EdgeHandlerContext = {
        geo: geo.extract(headersObj),
        ip,
        userAgent,
        kv,
        waitUntil: context?.waitUntil ?? ((fn: Promise<unknown>) => { fn.catch(() => {}); }),
        securityHeaders: security.getSecurityHeaders(),
      };

      // Execute handler
      const response = await handler(request, ctx);

      // Inject security headers into response
      const securityHeaders = security.getSecurityHeaders();
      for (const [key, value] of Object.entries(securityHeaders)) {
        response.headers.set(key, value);
      }

      // Add performance timing
      response.headers.set('X-Response-Time', `${Date.now() - startTime}ms`);

      return response;
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: 'Internal Server Error',
          requestId: generateRequestId(),
        }),
        {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            ...security.getSecurityHeaders(),
          },
        }
      );
    }
  };
}

/** Context passed to edge handlers */
export interface EdgeHandlerContext {
  geo: GeoData;
  ip: string;
  userAgent: string;
  kv: EdgeKV;
  waitUntil: (fn: Promise<unknown>) => void;
  securityHeaders: Record<string, string>;
}

// ─── Helpers ──────────────────────────────────────────────────

function generateRequestId(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return `edge_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
}
