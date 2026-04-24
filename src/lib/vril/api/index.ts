/**
 * Vril.js v2.0.0 — Type-Safe API Route Builder
 * Input validation · CSRF protection · Rate limiting ·
 * Error handling · Route versioning · Zero-dependency schema
 *
 * Zero external dependencies — Web Crypto API and built-in JS only.
 */

// ─── Types ────────────────────────────────────────────────────

/** Validation result returned by schema validators */
export interface ValidationResult<T = unknown> {
  success: boolean;
  data?: T;
  errors?: ValidationError[];
}

/** A single validation error */
export interface ValidationError {
  path: string;
  message: string;
  code: string;
  value?: unknown;
}

/** Enhanced API request with typed body, query, and params */
export interface APIRequest<TBody = unknown, TQuery = unknown, TParams = unknown> {
  body: TBody;
  query: TQuery;
  params: TParams;
  headers: Record<string, string>;
  method: string;
  url: string;
  ip?: string;
  requestId: string;
}

/** Structured API response */
export interface APIResponse<T = unknown> {
  status: number;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: unknown;
  };
  headers: Record<string, string>;
  timestamp: number;
  requestId: string;
  version: string;
}

/** Configuration for an API route */
export interface APIRouteConfig<TBody = unknown, TQuery = unknown, TParams = unknown> {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  validateBody?: (body: unknown) => ValidationResult<TBody>;
  validateQuery?: (query: unknown) => ValidationResult<TQuery>;
  validateParams?: (params: unknown) => ValidationResult<TParams>;
  rateLimit?: RateLimitConfig;
  csrfProtection?: boolean;
  version?: string;
  deprecated?: boolean;
  deprecationMessage?: string;
  securityHeaders?: boolean;
  requireAuth?: boolean;
  handler: (req: APIRequest<TBody, TQuery, TParams>) => Promise<APIResponse> | APIResponse;
}

/** Rate limit configuration */
export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  keyGenerator?: (req: APIRequest) => string;
  skipSuccessfulRequests?: boolean;
}

// ─── APISchema (Zero-Dependency Validation) ───────────────────

/**
 * Zod-like schema builder with zero external dependencies.
 * Provides a fluent API for building validation schemas.
 */
export class APISchema {
  private version = '2.1.0';

  /** Validate a string value */
  static string(options?: { min?: number; max?: number; pattern?: RegExp; email?: boolean }) {
    return (value: unknown): ValidationResult<string> => {
      if (typeof value !== 'string') {
        return { success: false, errors: [{ path: '', message: 'Expected string', code: 'type_error', value }] };
      }
      const errors: ValidationError[] = [];
      if (options?.min && value.length < options.min) {
        errors.push({ path: '', message: `String must be at least ${options.min} characters`, code: 'min_length', value });
      }
      if (options?.max && value.length > options.max) {
        errors.push({ path: '', message: `String must be at most ${options.max} characters`, code: 'max_length', value });
      }
      if (options?.pattern && !options.pattern.test(value)) {
        errors.push({ path: '', message: 'String does not match required pattern', code: 'pattern_mismatch', value });
      }
      if (options?.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
        errors.push({ path: '', message: 'Invalid email format', code: 'invalid_email', value });
      }
      return errors.length > 0 ? { success: false, errors } : { success: true, data: value };
    };
  }

  /** Validate a number value */
  static number(options?: { min?: number; max?: number; integer?: number }) {
    return (value: unknown): ValidationResult<number> => {
      if (typeof value !== 'number' || isNaN(value)) {
        return { success: false, errors: [{ path: '', message: 'Expected number', code: 'type_error', value }] };
      }
      const errors: ValidationError[] = [];
      if (options?.min !== undefined && value < options.min) {
        errors.push({ path: '', message: `Number must be at least ${options.min}`, code: 'min_value', value });
      }
      if (options?.max !== undefined && value > options.max) {
        errors.push({ path: '', message: `Number must be at most ${options.max}`, code: 'max_value', value });
      }
      if (options?.integer && !Number.isInteger(value)) {
        errors.push({ path: '', message: 'Number must be an integer', code: 'not_integer', value });
      }
      return errors.length > 0 ? { success: false, errors } : { success: true, data: value };
    };
  }

  /** Validate a boolean value */
  static boolean() {
    return (value: unknown): ValidationResult<boolean> => {
      if (typeof value !== 'boolean') {
        return { success: false, errors: [{ path: '', message: 'Expected boolean', code: 'type_error', value }] };
      }
      return { success: true, data: value };
    };
  }

  /** Validate an array value */
  static array<T>(itemValidator: (item: unknown) => ValidationResult<T>, options?: { min?: number; max?: number }) {
    return (value: unknown): ValidationResult<T[]> => {
      if (!Array.isArray(value)) {
        return { success: false, errors: [{ path: '', message: 'Expected array', code: 'type_error', value }] };
      }
      const errors: ValidationError[] = [];
      if (options?.min && value.length < options.min) {
        errors.push({ path: '', message: `Array must have at least ${options.min} items`, code: 'min_length', value });
      }
      if (options?.max && value.length > options.max) {
        errors.push({ path: '', message: `Array must have at most ${options.max} items`, code: 'max_length', value });
      }

      const items: T[] = [];
      for (let i = 0; i < value.length; i++) {
        const result = itemValidator(value[i]);
        if (!result.success && result.errors) {
          for (const err of result.errors) {
            errors.push({ ...err, path: `[${i}]${err.path ? '.' + err.path : ''}` });
          }
        } else if (result.data !== undefined) {
          items.push(result.data);
        }
      }

      return errors.length > 0 ? { success: false, errors } : { success: true, data: items };
    };
  }

  /** Validate an object with a defined shape */
  static object<T extends Record<string, (v: unknown) => ValidationResult<any>>>(
    shape: T
  ) {
    return (value: unknown): ValidationResult<{ [K in keyof T]: ReturnType<T[K]> extends ValidationResult<infer V> ? V : never }> => {
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return { success: false, errors: [{ path: '', message: 'Expected object', code: 'type_error', value }] };
      }
      const errors: ValidationError[] = [];
      const result: Record<string, unknown> = {};

      for (const [key, validator] of Object.entries(shape)) {
        const fieldResult = validator((value as Record<string, unknown>)[key]);
        if (!fieldResult.success && fieldResult.errors) {
          for (const err of fieldResult.errors) {
            errors.push({ ...err, path: `${key}${err.path ? '.' + err.path : ''}` });
          }
        } else if (fieldResult.data !== undefined) {
          result[key] = fieldResult.data;
        }
      }

      return errors.length > 0
        ? { success: false, errors }
        : { success: true, data: result as any };
    };
  }

  /** Make a validator optional (allows undefined) */
  static optional<T>(validator: (v: unknown) => ValidationResult<T>) {
    return (value: unknown): ValidationResult<T | undefined> => {
      if (value === undefined || value === null) {
        return { success: true, data: undefined };
      }
      return validator(value) as ValidationResult<T | undefined>;
    };
  }

  /** Create a union of multiple validators */
  static union<T>(...validators: Array<(v: unknown) => ValidationResult<T>>) {
    return (value: unknown): ValidationResult<T> => {
      const allErrors: ValidationError[] = [];
      for (const validator of validators) {
        const result = validator(value);
        if (result.success) return result as ValidationResult<T>;
        if (result.errors) allErrors.push(...result.errors);
      }
      return { success: false, errors: allErrors };
    };
  }

  /** Enum validator — value must be one of the allowed values */
  static enum<T extends string>(...allowed: T[]) {
    return (value: unknown): ValidationResult<T> => {
      if (!allowed.includes(value as T)) {
        return {
          success: false,
          errors: [{ path: '', message: `Value must be one of: ${allowed.join(', ')}`, code: 'enum_mismatch', value }],
        };
      }
      return { success: true, data: value as T };
    };
  }
}

// ─── API Error Handler ────────────────────────────────────────

/**
 * Structured error responses with security-safe messages.
 * Prevents leaking internal details in production.
 */
export class APIErrorHandler {
  private isDev: boolean;
  private version = '2.1.0';

  constructor(isDev?: boolean) {
    this.isDev = isDev ?? (typeof process !== 'undefined' && process.env?.NODE_ENV === 'development');
  }

  /** Convert an error into a structured API response */
  handle(error: unknown, requestId: string): APIResponse {
    if (error instanceof APIError) {
      return {
        status: error.statusCode,
        error: {
          code: error.code,
          message: error.message,
          details: this.isDev ? error.details : undefined,
        },
        headers: this.getSecurityHeaders(),
        timestamp: Date.now(),
        requestId,
        version: this.version,
      };
    }

    if (error instanceof Error) {
      return {
        status: 500,
        error: {
          code: 'INTERNAL_ERROR',
          message: this.isDev ? error.message : 'An internal error occurred',
          details: this.isDev ? { stack: error.stack } : undefined,
        },
        headers: this.getSecurityHeaders(),
        timestamp: Date.now(),
        requestId,
        version: this.version,
      };
    }

    return {
      status: 500,
      error: {
        code: 'UNKNOWN_ERROR',
        message: 'An unknown error occurred',
      },
      headers: this.getSecurityHeaders(),
      timestamp: Date.now(),
      requestId,
      version: this.version,
    };
  }

  /** Create a validation error response */
  validationError(errors: ValidationError[], requestId: string): APIResponse {
    return {
      status: 400,
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Request validation failed',
        details: errors,
      },
      headers: this.getSecurityHeaders(),
      timestamp: Date.now(),
      requestId,
      version: this.version,
    };
  }

  /** Create a rate limit error response */
  rateLimitError(retryAfter: number, requestId: string): APIResponse {
    return {
      status: 429,
      error: {
        code: 'RATE_LIMIT_EXCEEDED',
        message: `Rate limit exceeded. Retry after ${retryAfter} seconds.`,
      },
      headers: {
        ...this.getSecurityHeaders(),
        'Retry-After': String(retryAfter),
      },
      timestamp: Date.now(),
      requestId,
      version: this.version,
    };
  }

  /** Create a CSRF error response */
  csrfError(requestId: string): APIResponse {
    return {
      status: 403,
      error: {
        code: 'CSRF_VALIDATION_FAILED',
        message: 'CSRF token validation failed',
      },
      headers: this.getSecurityHeaders(),
      timestamp: Date.now(),
      requestId,
      version: this.version,
    };
  }

  private getSecurityHeaders(): Record<string, string> {
    return {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Cache-Control': 'no-store',
      'X-Vril-Version': this.version,
    };
  }
}

/** Custom API error class */
export class APIError extends Error {
  constructor(
    public statusCode: number,
    public code: string,
    message: string,
    public details?: unknown
  ) {
    super(message);
    this.name = 'APIError';
  }
}

// ─── API Rate Limiter ─────────────────────────────────────────

interface TokenBucket {
  tokens: number;
  lastRefill: number;
}

/**
 * Token bucket rate limiter per IP/route.
 * Uses in-memory storage with automatic cleanup.
 */
export class APIRateLimiter {
  private buckets = new Map<string, TokenBucket>();
  private config: RateLimitConfig;
  private version = '2.1.0';

  constructor(config: RateLimitConfig) {
    this.config = config;
    // Periodic cleanup of expired buckets
    if (typeof setInterval !== 'undefined') {
      setInterval(() => this.cleanup(), this.config.windowMs);
    }
  }

  /** Check if a request is allowed under the rate limit */
  check(req: APIRequest): { allowed: boolean; remaining: number; retryAfter: number } {
    const key = this.config.keyGenerator
      ? this.config.keyGenerator(req)
      : `${req.ip ?? 'unknown'}:${req.method}:${req.url}`;

    const bucket = this.buckets.get(key) ?? {
      tokens: this.config.maxRequests,
      lastRefill: Date.now(),
    };

    // Refill tokens based on elapsed time
    const elapsed = Date.now() - bucket.lastRefill;
    const refillRate = this.config.maxRequests / this.config.windowMs;
    const refilled = Math.floor(elapsed * refillRate);
    bucket.tokens = Math.min(this.config.maxRequests, bucket.tokens + refilled);
    bucket.lastRefill = Date.now();

    if (bucket.tokens <= 0) {
      const retryAfter = Math.ceil((1 / refillRate) / 1000);
      this.buckets.set(key, bucket);
      return { allowed: false, remaining: 0, retryAfter };
    }

    bucket.tokens--;
    this.buckets.set(key, bucket);
    return { allowed: true, remaining: bucket.tokens, retryAfter: 0 };
  }

  /** Clean up expired buckets */
  private cleanup(): void {
    const cutoff = Date.now() - this.config.windowMs * 2;
    for (const [key, bucket] of this.buckets) {
      if (bucket.lastRefill < cutoff) {
        this.buckets.delete(key);
      }
    }
  }
}

// ─── API Versioning ───────────────────────────────────────────

interface VersionedRoute {
  version: string;
  deprecated: boolean;
  deprecationMessage?: string;
  sunsetDate?: string;
}

/**
 * Route versioning with deprecation warnings.
 * Manages API version lifecycle and communicates changes to consumers.
 */
export class APIVersioning {
  private routes = new Map<string, VersionedRoute[]>();
  private currentVersion = '2.1.0';

  /** Register a versioned route */
  register(path: string, version: VersionedRoute): void {
    const existing = this.routes.get(path) ?? [];
    existing.push(version);
    existing.sort((a, b) => this.compareVersions(b.version, a.version));
    this.routes.set(path, existing);
  }

  /** Get the appropriate version for a request */
  resolve(path: string, requestedVersion?: string): VersionedRoute | null {
    const versions = this.routes.get(path);
    if (!versions || versions.length === 0) return null;

    if (requestedVersion) {
      const match = versions.find((v) => v.version === requestedVersion);
      if (match) return match;
    }

    return versions[0]; // Latest version
  }

  /** Get deprecation headers for a response */
  getDeprecationHeaders(route: VersionedRoute): Record<string, string> {
    const headers: Record<string, string> = {};
    if (route.deprecated) {
      headers['Deprecation'] = 'true';
      if (route.deprecationMessage) {
        headers['Sunset'] = route.sunsetDate ?? '';
        headers['Link'] = `<${route.deprecationMessage}>; rel="deprecation"`;
      }
    }
    return headers;
  }

  /** Compare semantic versions: positive if a > b */
  private compareVersions(a: string, b: string): number {
    const pa = a.split('.').map(Number);
    const pb = b.split('.').map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const na = pa[i] ?? 0;
      const nb = pb[i] ?? 0;
      if (na !== nb) return na - nb;
    }
    return 0;
  }
}

// ─── Create API Route ─────────────────────────────────────────

/**
 * Builder for API routes with input validation, CSRF protection, and rate limiting.
 * Returns a handler function that can be used directly in route definitions.
 */
export function createAPIRoute<TBody = unknown, TQuery = unknown, TParams = unknown>(
  config: APIRouteConfig<TBody, TQuery, TParams>
): (rawRequest: {
  body?: unknown;
  query?: unknown;
  params?: unknown;
  headers?: Record<string, string>;
  method?: string;
  url?: string;
  ip?: string;
}) => Promise<APIResponse> {
  const errorHandler = new APIErrorHandler();
  const rateLimiter = config.rateLimit ? new APIRateLimiter(config.rateLimit) : null;
  const versioning = new APIVersioning();

  if (config.version) {
    versioning.register(config.path, {
      version: config.version,
      deprecated: config.deprecated ?? false,
      deprecationMessage: config.deprecationMessage,
    });
  }

  return async (rawRequest) => {
    const requestId = generateRequestId();
    const timestamp = Date.now();

    try {
      // Build typed request
      const req: APIRequest<TBody, TQuery, TParams> = {
        body: rawRequest.body as TBody,
        query: (rawRequest.query ?? {}) as TQuery,
        params: (rawRequest.params ?? {}) as TParams,
        headers: rawRequest.headers ?? {},
        method: rawRequest.method ?? config.method,
        url: rawRequest.url ?? config.path,
        ip: rawRequest.ip,
        requestId,
      };

      // Method check
      if (req.method !== config.method) {
        return {
          status: 405,
          error: { code: 'METHOD_NOT_ALLOWED', message: `Expected ${config.method}, got ${req.method}` },
          headers: { Allow: config.method },
          timestamp,
          requestId,
          version: '2.1.0',
        };
      }

      // Rate limiting
      if (rateLimiter) {
        const limitResult = rateLimiter.check(req);
        if (!limitResult.allowed) {
          return errorHandler.rateLimitError(limitResult.retryAfter, requestId);
        }
      }

      // CSRF protection for state-changing methods
      if (config.csrfProtection && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
        const csrfToken = req.headers['x-csrf-token'] ?? req.headers['x-xsrf-token'];
        if (!csrfToken) {
          return errorHandler.csrfError(requestId);
        }
      }

      // Body validation
      if (config.validateBody) {
        const result = config.validateBody(rawRequest.body);
        if (!result.success) {
          return errorHandler.validationError(result.errors ?? [], requestId);
        }
        req.body = result.data as TBody;
      }

      // Query validation
      if (config.validateQuery) {
        const result = config.validateQuery(rawRequest.query);
        if (!result.success) {
          return errorHandler.validationError(result.errors ?? [], requestId);
        }
        req.query = result.data as TQuery;
      }

      // Params validation
      if (config.validateParams) {
        const result = config.validateParams(rawRequest.params);
        if (!result.success) {
          return errorHandler.validationError(result.errors ?? [], requestId);
        }
        req.params = result.data as TParams;
      }

      // Execute handler
      const response = await config.handler(req);

      // Add deprecation headers if needed
      if (config.deprecated) {
        response.headers = {
          ...response.headers,
          Deprecation: 'true',
          ...(config.deprecationMessage ? { 'X-Deprecation-Notice': config.deprecationMessage } : {}),
        };
      }

      // Add security headers
      if (config.securityHeaders !== false) {
        response.headers = {
          ...response.headers,
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'Cache-Control': 'no-store',
        };
      }

      return response;
    } catch (error) {
      return errorHandler.handle(error, requestId);
    }
  };
}

// ─── Helpers ──────────────────────────────────────────────────

/** Generate a unique request ID using crypto */
function generateRequestId(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  // Fallback: timestamp + random
  return `req_${Date.now()}_${Math.random().toString(36).substring(2, 10)}`;
}
