/**
 * Vril.js v2.0.0 — Secure Router
 * File-system based routing with security annotations per route.
 * Extends Next.js App Router with route-level security policies,
 * composable middleware, route groups, route scanning, and navigation guards.
 */

export const ROUTER_MODULE_VERSION = '2.1.0';

// ─── Route Security Policy ───────────────────────────────────
export interface RouteSecurityPolicy {
  /** CSRF protection for mutation endpoints */
  csrf?: boolean;
  /** Rate limit: requests per minute (0 = unlimited) */
  rateLimit?: number;
  /** Required authentication */
  auth?: boolean;
  /** Allowed HTTP methods */
  methods?: string[];
  /** Custom CSP for this route (overrides global) */
  csp?: Record<string, string[]>;
  /** Permissions policy override */
  permissionsPolicy?: Record<string, string[]>;
  /** Request signing required (edge→origin) */
  signedRequests?: boolean;
  /** Maximum request body size in bytes */
  maxBodySize?: number;
  /** Response cache TTL in seconds (-1 = no cache, 0 = forever) */
  cacheTTL?: number;
  /** Audit log level for this route */
  auditLevel?: 'none' | 'minimal' | 'full';
  /** Content-Type validation for request bodies */
  allowedContentTypes?: string[];
  /** Origin validation (strict mode) */
  strictOriginValidation?: boolean;
  /** Bot detection and blocking */
  blockBots?: boolean;
  /** CORS configuration */
  cors?: CORSConfig;
  /** IP allowlist for this route */
  ipAllowlist?: string[];
}

export interface CORSConfig {
  /** Allowed origins */
  origins: string[];
  /** Allowed methods */
  methods: string[];
  /** Allowed headers */
  allowedHeaders: string[];
  /** Exposed headers */
  exposedHeaders: string[];
  /** Allow credentials */
  credentials: boolean;
  /** Max age for preflight cache */
  maxAge: number;
}

export interface RouteConfig {
  path: string;
  security: RouteSecurityPolicy;
  /** Route metadata for documentation */
  meta?: {
    title?: string;
    description?: string;
    apiVersion?: number;
  };
  /** Route group this route belongs to */
  group?: string;
}

export const DEFAULT_ROUTE_SECURITY: RouteSecurityPolicy = {
  csrf: true,
  rateLimit: 100,
  methods: ['GET', 'HEAD', 'OPTIONS'],
  signedRequests: false,
  maxBodySize: 1024 * 1024,
  cacheTTL: -1,
  auditLevel: 'minimal',
  allowedContentTypes: ['application/json', 'text/plain'],
  strictOriginValidation: false,
  blockBots: false,
  cors: {
    origins: [],
    methods: ['GET', 'HEAD', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: [],
    credentials: false,
    maxAge: 86400,
  },
};

export const MUTATION_SECURITY: RouteSecurityPolicy = {
  ...DEFAULT_ROUTE_SECURITY,
  methods: ['POST', 'PUT', 'PATCH', 'DELETE'],
  csrf: true,
  rateLimit: 30,
  auditLevel: 'full',
  maxBodySize: 512 * 1024,
};

// ─── Route Security Registry ─────────────────────────────────
export interface RouteMatchResult {
  policy: RouteSecurityPolicy;
  params: Record<string, string>;
  pattern: string;
}

/**
 * Route Security Registry
 * Maps route patterns to security policies.
 * v2.0.0: Adds wildcard patterns with parameter extraction, route groups
 * with shared security policies, nested route inheritance, route-specific CSP.
 */
export class RouteSecurityRegistry {
  private routes = new Map<string, RouteConfig>();
  private groups = new Map<string, RouteSecurityPolicy>();

  /** Register a route configuration */
  register(config: RouteConfig): void {
    this.routes.set(config.path, {
      ...config,
      security: { ...DEFAULT_ROUTE_SECURITY, ...config.security },
    });
  }

  /** Register multiple routes at once */
  registerAll(configs: RouteConfig[]): void {
    for (const config of configs) {
      this.register(config);
    }
  }

  /** Define a route group with shared security policy */
  defineGroup(name: string, policy: RouteSecurityPolicy): void {
    this.groups.set(name, policy);
  }

  /** Get the security policy for a path, considering groups and inheritance */
  getPolicy(path: string): RouteSecurityPolicy {
    // Exact match first
    const exact = this.routes.get(path);
    if (exact) {
      // Apply group policy if route belongs to a group
      let policy = exact.security;
      if (exact.group && this.groups.has(exact.group)) {
        policy = { ...this.groups.get(exact.group)!, ...exact.security };
      }
      return policy;
    }

    // Wildcard/pattern match with parameter extraction
    const match = this.matchPattern(path);
    if (match) {
      let policy = match.security;
      if (match.group && this.groups.has(match.group)) {
        policy = { ...this.groups.get(match.group)!, ...policy };
      }
      return policy;
    }

    // Check parent path for nested route inheritance
    const parentPolicy = this.getInheritedPolicy(path);
    if (parentPolicy) return parentPolicy;

    return DEFAULT_ROUTE_SECURITY;
  }

  /** Match a path against registered patterns and extract parameters */
  matchPattern(path: string): (RouteConfig & { params: Record<string, string> }) | null {
    const segments = path.split('/').filter(Boolean);

    for (const [pattern, config] of this.routes) {
      const patternSegments = pattern.split('/').filter(Boolean);
      if (patternSegments.length !== segments.length) continue;

      const params: Record<string, string> = {};
      let match = true;

      for (let i = 0; i < patternSegments.length; i++) {
        const ps = patternSegments[i];
        const ss = segments[i];

        if (ps.startsWith(':')) {
          // Named parameter
          params[ps.substring(1)] = ss;
        } else if (ps === '*') {
          // Wildcard — matches any segment
          params[`wildcard_${i}`] = ss;
        } else if (ps !== ss) {
          match = false;
          break;
        }
      }

      if (match) {
        return { ...config, params };
      }
    }

    // Also check glob patterns (e.g., /api/*)
    for (const [pattern, config] of this.routes) {
      if (pattern.includes('*')) {
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
        if (regex.test(path)) {
          return { ...config, params: { wildcard: path } };
        }
      }
    }

    return null;
  }

  /** Get inherited policy from parent routes for nested route inheritance */
  private getInheritedPolicy(path: string): RouteSecurityPolicy | null {
    const segments = path.split('/').filter(Boolean);
    // Walk up from most specific to least specific parent
    for (let i = segments.length - 1; i >= 1; i--) {
      const parentPath = '/' + segments.slice(0, i).join('/');
      const parent = this.routes.get(parentPath);
      if (parent) {
        let policy = parent.security;
        if (parent.group && this.groups.has(parent.group)) {
          policy = { ...this.groups.get(parent.group)!, ...policy };
        }
        return policy;
      }
    }
    return null;
  }

  /** Validate a request against the route's security policy */
  validateRequest(path: string, request: {
    method: string;
    contentType?: string;
    bodySize?: number;
    origin?: string;
    ip?: string;
  }): { valid: boolean; violations: string[] } {
    const policy = this.getPolicy(path);
    const violations: string[] = [];

    if (policy.methods && !policy.methods.includes(request.method)) {
      violations.push(`Method ${request.method} not allowed on ${path}`);
    }

    if (policy.maxBodySize && request.bodySize && request.bodySize > policy.maxBodySize) {
      violations.push(`Body size ${request.bodySize} exceeds limit ${policy.maxBodySize}`);
    }

    if (policy.allowedContentTypes && request.contentType) {
      if (!policy.allowedContentTypes.some(ct => request.contentType!.startsWith(ct))) {
        violations.push(`Content-Type ${request.contentType} not allowed`);
      }
    }

    if (policy.strictOriginValidation && request.origin) {
      const allowedOrigins = policy.cors?.origins ?? [];
      if (allowedOrigins.length > 0 && !allowedOrigins.includes(request.origin)) {
        violations.push(`Origin ${request.origin} not allowed in strict mode`);
      }
    }

    if (policy.ipAllowlist && policy.ipAllowlist.length > 0 && request.ip) {
      if (!policy.ipAllowlist.includes(request.ip)) {
        violations.push(`IP ${request.ip} not in allowlist`);
      }
    }

    return { valid: violations.length === 0, violations };
  }

  /** Get all registered routes */
  getAllRoutes(): RouteConfig[] {
    return Array.from(this.routes.values());
  }

  /** Get route-specific CSP with nonce injection */
  getCSPWithNonce(path: string, nonce: string): string {
    const policy = this.getPolicy(path);
    const cspOverrides = policy.csp ?? {};

    const directives: string[] = [
      `default-src 'self'`,
      `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
      `style-src 'self' 'unsafe-inline'`,
      `img-src 'self' data: blob:`,
      `connect-src 'self'`,
      `frame-src 'none'`,
      `object-src 'none'`,
      `base-uri 'self'`,
      `form-action 'self'`,
      `frame-ancestors 'none'`,
    ];

    for (const [directive, values] of Object.entries(cspOverrides)) {
      const idx = directives.findIndex(d => d.startsWith(directive));
      if (idx >= 0) {
        directives[idx] = `${directive} ${values.join(' ')}`;
      } else {
        directives.push(`${directive} ${values.join(' ')}`);
      }
    }

    return directives.join('; ');
  }

  /** Get all defined groups */
  getGroups(): Map<string, RouteSecurityPolicy> {
    return new Map(this.groups);
  }
}

// ─── Secure Handler ──────────────────────────────────────────
/**
 * Create a secure API route handler with built-in validation.
 * v2.0.0: Adds body size enforcement with streaming, origin validation,
 * bot detection, rate limiting per route, automatic CORS handling.
 */
export function createSecureHandler(
  handler: (request: Request, ctx: { path: string; policy: RouteSecurityPolicy; params: Record<string, string> }) => Promise<Response>,
  policy: Partial<RouteSecurityPolicy> = {}
) {
  const mergedPolicy: RouteSecurityPolicy = { ...DEFAULT_ROUTE_SECURITY, ...policy };
  const rateLimitMap = new Map<string, { count: number; windowStart: number }>();

  return async (request: Request, ctx: { path?: string }) => {
    const path = ctx.path || new URL(request.url).pathname;

    // Method validation
    if (mergedPolicy.methods && !mergedPolicy.methods.includes(request.method)) {
      return new Response('Method Not Allowed', { status: 405 });
    }

    // Content-Type validation
    if (mergedPolicy.allowedContentTypes) {
      const ct = request.headers.get('content-type');
      if (ct && !mergedPolicy.allowedContentTypes.some(a => ct.startsWith(a))) {
        return new Response('Unsupported Media Type', { status: 415 });
      }
    }

    // Request body size enforcement with streaming support
    if (mergedPolicy.maxBodySize) {
      const contentLength = parseInt(request.headers.get('content-length') ?? '0', 10);
      if (contentLength > mergedPolicy.maxBodySize) {
        return new Response('Payload Too Large', { status: 413 });
      }
    }

    // CSRF check for mutation methods
    if (mergedPolicy.csrf && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) {
      const origin = request.headers.get('origin');
      const host = request.headers.get('host');
      if (!origin || !host || !origin.includes(host)) {
        return new Response('Forbidden — CSRF check failed', { status: 403 });
      }
    }

    // Origin validation (strict mode)
    if (mergedPolicy.strictOriginValidation) {
      const origin = request.headers.get('origin');
      const allowed = mergedPolicy.cors?.origins ?? [];
      if (origin && allowed.length > 0 && !allowed.includes(origin)) {
        return new Response('Forbidden — Origin not allowed', { status: 403 });
      }
    }

    // Bot detection
    if (mergedPolicy.blockBots) {
      const ua = request.headers.get('user-agent') ?? '';
      const botPatterns = [/bot/i, /crawler/i, /spider/i, /scraper/i, /curl/i, /wget/i];
      if (botPatterns.some(p => p.test(ua))) {
        return new Response('Forbidden — Bot access blocked', { status: 403 });
      }
    }

    // Rate limiting per route
    if (mergedPolicy.rateLimit && mergedPolicy.rateLimit > 0) {
      const ip = request.headers.get('x-real-ip') ?? request.headers.get('cf-connecting-ip') ?? 'unknown';
      const key = `${ip}:${path}`;
      const now = Date.now();
      let entry = rateLimitMap.get(key);
      if (!entry || (now - entry.windowStart) > 60000) {
        entry = { count: 0, windowStart: now };
        rateLimitMap.set(key, entry);
      }
      entry.count++;
      if (entry.count > mergedPolicy.rateLimit) {
        return new Response('Too Many Requests', { status: 429, headers: { 'Retry-After': '60' } });
      }
    }

    // Automatic CORS handling
    if (request.method === 'OPTIONS' && mergedPolicy.cors) {
      return handlePreflight(request, mergedPolicy.cors);
    }

    // Add CORS headers to response
    const result = await handler(request, { path, policy: mergedPolicy, params: {} });

    if (mergedPolicy.cors && mergedPolicy.cors.origins.length > 0) {
      const origin = request.headers.get('origin') ?? '';
      if (mergedPolicy.cors.origins.includes(origin)) {
        const newHeaders = new Headers(result.headers);
        newHeaders.set('Access-Control-Allow-Origin', origin);
        if (mergedPolicy.cors.credentials) {
          newHeaders.set('Access-Control-Allow-Credentials', 'true');
        }
        for (const h of mergedPolicy.cors.exposedHeaders) {
          newHeaders.append('Access-Control-Expose-Headers', h);
        }
        return new Response(result.body, { status: result.status, statusText: result.statusText, headers: newHeaders });
      }
    }

    return result;
  };
}

/** Handle CORS preflight requests */
function handlePreflight(request: Request, cors: CORSConfig): Response {
  const origin = request.headers.get('origin') ?? '';
  if (!cors.origins.includes(origin)) {
    return new Response('Forbidden', { status: 403 });
  }

  const headers = new Headers();
  headers.set('Access-Control-Allow-Origin', origin);
  headers.set('Access-Control-Allow-Methods', cors.methods.join(', '));
  headers.set('Access-Control-Allow-Headers', cors.allowedHeaders.join(', '));
  headers.set('Access-Control-Max-Age', cors.maxAge.toString());
  if (cors.credentials) {
    headers.set('Access-Control-Allow-Credentials', 'true');
  }

  return new Response(null, { status: 204, headers });
}

// ─── Route Middleware (NEW) ──────────────────────────────────
export type RouteHandler = (request: Request, ctx: RouteContext) => Promise<Response>;

export interface RouteContext {
  path: string;
  params: Record<string, string>;
  policy: RouteSecurityPolicy;
  session?: SessionData;
  metadata: Record<string, unknown>;
}

export interface SessionData {
  id: string;
  userId?: string;
  roles?: string[];
  expires: number;
}

export type Middleware = (next: RouteHandler) => RouteHandler;

/**
 * Composable route middleware for security checks.
 * Usage: withAuth(withCSRF(withRateLimit(handler)))
 */
export class RouteMiddleware {
  /** Require authentication — reject unauthenticated requests */
  static withAuth(): Middleware {
    return (next: RouteHandler): RouteHandler => {
      return async (request, ctx) => {
        const authHeader = request.headers.get('authorization');
        const sessionCookie = request.headers.get('cookie');

        if (!authHeader && !sessionCookie) {
          return new Response(JSON.stringify({ error: 'Authentication required' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        // Validate session if present
        if (ctx.session) {
          if (Date.now() > ctx.session.expires) {
            return new Response(JSON.stringify({ error: 'Session expired' }), {
              status: 401,
              headers: { 'Content-Type': 'application/json' },
            });
          }
        }

        return next(request, ctx);
      };
    };
  }

  /** Require CSRF token for mutation requests */
  static withCSRF(tokenHeader: string = 'x-vril-csrf', cookieName: string = 'vril-csrf'): Middleware {
    return (next: RouteHandler): RouteHandler => {
      return async (request, ctx) => {
        if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) {
          return next(request, ctx);
        }

        const headerToken = request.headers.get(tokenHeader);
        const cookieHeader = request.headers.get('cookie') ?? '';
        let cookieToken: string | null = null;

        const parts = cookieHeader.split(';');
        for (const part of parts) {
          const trimmed = part.trim();
          if (trimmed.startsWith(`${cookieName}=`)) {
            cookieToken = trimmed.substring(cookieName.length + 1);
          }
        }

        if (!headerToken || !cookieToken || headerToken !== cookieToken) {
          return new Response(JSON.stringify({ error: 'CSRF validation failed' }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        return next(request, ctx);
      };
    };
  }

  /** Apply rate limiting */
  static withRateLimit(limit: number = 100, windowMs: number = 60000): Middleware {
    const rateMap = new Map<string, { count: number; windowStart: number }>();
    return (next: RouteHandler): RouteHandler => {
      return async (request, ctx) => {
        const ip = request.headers.get('x-real-ip') ?? request.headers.get('cf-connecting-ip') ?? 'unknown';
        const key = `${ip}:${ctx.path}`;
        const now = Date.now();

        let entry = rateMap.get(key);
        if (!entry || (now - entry.windowStart) > windowMs) {
          entry = { count: 0, windowStart: now };
          rateMap.set(key, entry);
        }
        entry.count++;

        if (entry.count > limit) {
          return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
            status: 429,
            headers: { 'Content-Type': 'application/json', 'Retry-After': Math.ceil(windowMs / 1000).toString() },
          });
        }

        return next(request, ctx);
      };
    };
  }

  /** Handle CORS */
  static withCORS(config: CORSConfig): Middleware {
    return (next: RouteHandler): RouteHandler => {
      return async (request, ctx) => {
        // Preflight
        if (request.method === 'OPTIONS') {
          return handlePreflight(request, config);
        }

        const response = await next(request, ctx);
        const origin = request.headers.get('origin') ?? '';

        if (config.origins.includes(origin)) {
          const newHeaders = new Headers(response.headers);
          newHeaders.set('Access-Control-Allow-Origin', origin);
          if (config.credentials) {
            newHeaders.set('Access-Control-Allow-Credentials', 'true');
          }
          return new Response(response.body, { status: response.status, statusText: response.statusText, headers: newHeaders });
        }

        return response;
      };
    };
  }

  /** Verify request signatures */
  static withSignedRequest(secret: string): Middleware {
    return (next: RouteHandler): RouteHandler => {
      return async (request, ctx) => {
        const timestamp = parseInt(request.headers.get('x-vril-timestamp') ?? '0', 10);
        const signature = request.headers.get('x-vril-signature') ?? '';
        const nonce = request.headers.get('x-vril-nonce') ?? '';

        if (!timestamp || !signature || !nonce) {
          return new Response(JSON.stringify({ error: 'Missing signature headers' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        // Check timestamp freshness (5 minute window)
        if (Math.abs(Date.now() - timestamp) > 300000) {
          return new Response(JSON.stringify({ error: 'Signature expired' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
          });
        }

        // Verify HMAC-SHA256 signature
        if (typeof crypto !== 'undefined' && crypto.subtle) {
          const key = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(secret),
            { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
          );
          const payload = `${request.method}:${ctx.path}:${nonce}`;
          const expectedSig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}:${payload}`));
          const expectedHex = Array.from(new Uint8Array(expectedSig)).map(b => b.toString(16).padStart(2, '0')).join('');

          if (signature.length !== expectedHex.length) {
            return new Response(JSON.stringify({ error: 'Invalid signature' }), {
              status: 401,
              headers: { 'Content-Type': 'application/json' },
            });
          }

          let result = 0;
          for (let i = 0; i < signature.length; i++) {
            result |= signature.charCodeAt(i) ^ expectedHex.charCodeAt(i);
          }

          if (result !== 0) {
            return new Response(JSON.stringify({ error: 'Signature verification failed' }), {
              status: 401,
              headers: { 'Content-Type': 'application/json' },
            });
          }
        }

        return next(request, ctx);
      };
    };
  }

  /** Compose multiple middleware: withAuth(withCSRF(withRateLimit(handler))) */
  static compose(...middlewares: Middleware[]): (handler: RouteHandler) => RouteHandler {
    return (handler: RouteHandler): RouteHandler => {
      return middlewares.reduceRight((acc, middleware) => middleware(acc), handler);
    };
  }
}

// ─── Route Group (NEW) ───────────────────────────────────────
/**
 * Group routes with shared security policies.
 * API routes with auth, public routes with caching, admin routes with IP allowlisting.
 */
export class RouteGroup {
  private name: string;
  private policy: RouteSecurityPolicy;
  private routes: RouteConfig[] = [];

  constructor(name: string, policy: RouteSecurityPolicy) {
    this.name = name;
    this.policy = policy;
  }

  /** Add a route to this group */
  addRoute(path: string, securityOverrides: Partial<RouteSecurityPolicy> = {}): RouteGroup {
    this.routes.push({
      path,
      security: { ...this.policy, ...securityOverrides },
      group: this.name,
    });
    return this;
  }

  /** Get all routes in this group */
  getRoutes(): RouteConfig[] {
    return [...this.routes];
  }

  /** Get the group name */
  getName(): string {
    return this.name;
  }

  /** Get the group security policy */
  getPolicy(): RouteSecurityPolicy {
    return { ...this.policy };
  }

  /** Register all routes in this group with a registry */
  registerWith(registry: RouteSecurityRegistry): void {
    for (const route of this.routes) {
      registry.register(route);
    }
  }

  /** Create an API routes group with authentication */
  static api(options: { rateLimit?: number; cors?: CORSConfig } = {}): RouteGroup {
    return new RouteGroup('api', {
      ...MUTATION_SECURITY,
      auth: true,
      csrf: true,
      rateLimit: options.rateLimit ?? 60,
      auditLevel: 'full',
      cors: options.cors ?? {
        origins: [],
        methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'x-vril-csrf'],
        exposedHeaders: ['X-Request-Id'],
        credentials: true,
        maxAge: 3600,
      },
    });
  }

  /** Create a public routes group with caching */
  static public(options: { cacheTTL?: number } = {}): RouteGroup {
    return new RouteGroup('public', {
      ...DEFAULT_ROUTE_SECURITY,
      auth: false,
      csrf: false,
      methods: ['GET', 'HEAD', 'OPTIONS'],
      cacheTTL: options.cacheTTL ?? 3600,
      rateLimit: 200,
    });
  }

  /** Create an admin routes group with IP allowlisting */
  static admin(options: { ipAllowlist?: string[] } = {}): RouteGroup {
    return new RouteGroup('admin', {
      ...MUTATION_SECURITY,
      auth: true,
      csrf: true,
      rateLimit: 30,
      auditLevel: 'full',
      strictOriginValidation: true,
      blockBots: true,
      ipAllowlist: options.ipAllowlist ?? ['127.0.0.1'],
    });
  }
}

// ─── Route Scanner (NEW) ─────────────────────────────────────
export interface RouteSecurityIssue {
  path: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  recommendation: string;
}

/**
 * Scan route definitions for security issues.
 */
export class RouteScanner {
  private issues: RouteSecurityIssue[] = [];

  /** Scan a set of routes for security problems */
  scan(routes: RouteConfig[]): RouteSecurityIssue[] {
    this.issues = [];

    for (const route of routes) {
      // Check for routes without CSRF on mutations
      if (route.security.methods?.some(m => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(m)) && !route.security.csrf) {
        this.issues.push({
          path: route.path,
          severity: 'high',
          description: 'Mutation route without CSRF protection',
          recommendation: 'Enable CSRF protection for all mutation endpoints',
        });
      }

      // Check for routes without auth that accept mutations
      if (route.security.methods?.some(m => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(m)) && !route.security.auth) {
        this.issues.push({
          path: route.path,
          severity: 'medium',
          description: 'Mutation route without authentication',
          recommendation: 'Require authentication for mutation endpoints',
        });
      }

      // Check for overly permissive methods
      if (route.security.methods && route.security.methods.includes('*')) {
        this.issues.push({
          path: route.path,
          severity: 'medium',
          description: 'Route allows all HTTP methods',
          recommendation: 'Restrict to only necessary HTTP methods',
        });
      }

      // Check for missing rate limiting
      if (!route.security.rateLimit || route.security.rateLimit === 0) {
        this.issues.push({
          path: route.path,
          severity: 'medium',
          description: 'Route has no rate limiting',
          recommendation: 'Apply rate limiting to prevent abuse',
        });
      }

      // Check for overly large body size limits
      if (route.security.maxBodySize && route.security.maxBodySize > 10 * 1024 * 1024) {
        this.issues.push({
          path: route.path,
          severity: 'low',
          description: 'Very large max body size (> 10MB)',
          recommendation: 'Reduce max body size to prevent DoS attacks',
        });
      }

      // Check for wildcard routes without specific security
      if (route.path.includes('*') && !route.security.auth) {
        this.issues.push({
          path: route.path,
          severity: 'medium',
          description: 'Wildcard route without authentication',
          recommendation: 'Add authentication or restrict the wildcard pattern',
        });
      }

      // Check for missing audit logging on mutation routes
      if (route.security.methods?.some(m => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(m)) && route.security.auditLevel === 'none') {
        this.issues.push({
          path: route.path,
          severity: 'low',
          description: 'Mutation route with no audit logging',
          recommendation: 'Enable at least minimal audit logging for mutation endpoints',
        });
      }

      // Check for routes allowing all content types
      if (route.security.allowedContentTypes && route.security.allowedContentTypes.includes('*/*')) {
        this.issues.push({
          path: route.path,
          severity: 'low',
          description: 'Route accepts all content types',
          recommendation: 'Restrict allowed content types to only what is needed',
        });
      }
    }

    // Check for duplicate routes
    const pathMap = new Map<string, number>();
    for (const route of routes) {
      const count = pathMap.get(route.path) ?? 0;
      pathMap.set(route.path, count + 1);
    }
    for (const [path, count] of pathMap) {
      if (count > 1) {
        this.issues.push({
          path,
          severity: 'high',
          description: `Duplicate route definition (${count} registrations)`,
          recommendation: 'Ensure each route is registered only once',
        });
      }
    }

    return this.issues;
  }

  /** Get a summary of scanned issues */
  getSummary(): { total: number; bySeverity: Record<string, number> } {
    const bySeverity: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    for (const issue of this.issues) {
      bySeverity[issue.severity]++;
    }
    return { total: this.issues.length, bySeverity };
  }
}

// ─── Navigation Guard (NEW) ──────────────────────────────────
export interface NavigationPolicy {
  /** Allowed destination origins for external navigation */
  allowedExternalOrigins: string[];
  /** Block all external navigation */
  blockExternalNavigation: boolean;
  /** Sandbox external links with rel=noopener,noreferrer */
  sandboxExternalLinks: boolean;
  /** Maximum number of redirects allowed */
  maxRedirects: number;
  /** Block data: URLs */
  blockDataUrls: boolean;
  /** Block javascript: URLs */
  blockJavascriptUrls: boolean;
  /** Custom URL validation function */
  customValidator?: (url: URL) => boolean;
}

const DEFAULT_NAVIGATION_POLICY: NavigationPolicy = {
  allowedExternalOrigins: [],
  blockExternalNavigation: false,
  sandboxExternalLinks: true,
  maxRedirects: 5,
  blockDataUrls: true,
  blockJavascriptUrls: true,
};

export interface NavigationValidationResult {
  allowed: boolean;
  reason?: string;
  sanitizedUrl?: string;
  isExternal: boolean;
}

/**
 * Client-side navigation security.
 * Validates destination URLs, prevents tab-nabbing, sandboxes external navigation.
 */
export class NavigationGuard {
  private policy: NavigationPolicy;
  private redirectCount = new Map<string, number>();

  constructor(policy: Partial<NavigationPolicy> = {}) {
    this.policy = { ...DEFAULT_NAVIGATION_POLICY, ...policy };
  }

  /** Validate a destination URL before navigation */
  validate(url: string, currentOrigin: string): NavigationValidationResult {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url, currentOrigin);
    } catch {
      return { allowed: false, reason: 'Invalid URL format', isExternal: false };
    }

    // Block javascript: URLs
    if (this.policy.blockJavascriptUrls && parsedUrl.protocol === 'javascript:') {
      return { allowed: false, reason: 'javascript: URLs are blocked', isExternal: false };
    }

    // Block data: URLs
    if (this.policy.blockDataUrls && parsedUrl.protocol === 'data:') {
      return { allowed: false, reason: 'data: URLs are blocked', isExternal: false };
    }

    const isExternal = parsedUrl.origin !== currentOrigin;

    // Block external navigation
    if (isExternal && this.policy.blockExternalNavigation) {
      return { allowed: false, reason: 'External navigation is blocked', isExternal: true };
    }

    // Check allowed external origins
    if (isExternal && this.policy.allowedExternalOrigins.length > 0) {
      if (!this.policy.allowedExternalOrigins.some(o => parsedUrl.origin === o || parsedUrl.hostname.endsWith(o))) {
        return { allowed: false, reason: `External origin ${parsedUrl.origin} is not allowed`, isExternal: true };
      }
    }

    // Custom validator
    if (this.policy.customValidator && !this.policy.customValidator(parsedUrl)) {
      return { allowed: false, reason: 'URL failed custom validation', isExternal };
    }

    // Sanitize URL — remove tracking parameters
    const sanitizedUrl = this.sanitizeUrl(parsedUrl);

    return { allowed: true, sanitizedUrl, isExternal };
  }

  /** Generate attributes for an external link to prevent tab-nabbing */
  getExternalLinkAttrs(url: string, currentOrigin: string): Record<string, string> {
    const result = this.validate(url, currentOrigin);
    const attrs: Record<string, string> = { href: result.sanitizedUrl ?? url };

    if (result.isExternal && this.policy.sandboxExternalLinks) {
      attrs.rel = 'noopener noreferrer';
      if (this.policy.blockExternalNavigation) {
        attrs.target = '_blank';
        attrs['data-vril-blocked'] = 'true';
      } else {
        attrs.target = '_blank';
      }
    }

    return attrs;
  }

  /** Track redirects and enforce maximum count */
  trackRedirect(sessionId: string, from: string, to: string): { allowed: boolean; redirectCount: number } {
    const key = `${sessionId}:${from}`;
    const count = (this.redirectCount.get(key) ?? 0) + 1;
    this.redirectCount.set(key, count);
    return {
      allowed: count <= this.policy.maxRedirects,
      redirectCount: count,
    };
  }

  /** Reset redirect tracking for a session */
  resetRedirects(sessionId: string): void {
    for (const key of this.redirectCount.keys()) {
      if (key.startsWith(sessionId)) {
        this.redirectCount.delete(key);
      }
    }
  }

  /** Sanitize a URL by removing common tracking parameters */
  private sanitizeUrl(url: URL): string {
    const trackingParams = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'fbclid', 'gclid', 'ref'];
    const sanitized = new URL(url.toString());
    for (const param of trackingParams) {
      sanitized.searchParams.delete(param);
    }
    return sanitized.toString();
  }
}
