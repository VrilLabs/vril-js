/**
 * Vril.js v2.0.0 — Zero-Dependency Utility Functions
 * Crypto utilities, encoding, sanitization, validation, and helpers
 *
 * constantTimeEqual · secureRandom · secureRandomString · hashData
 * encodeBase64 · decodeBase64 · encodeBase64Url · decodeBase64Url
 * sanitizeHTML · validateURL · deepClone · deepFreeze
 * mergeConfigs · debounce · throttle · retryWithBackoff
 *
 * Zero external dependencies — Web Crypto API and built-in JS only.
 */

// ─── Types ────────────────────────────────────────────────────────

/** Options for retryWithBackoff */
export interface RetryOptions {
  /** Maximum number of retry attempts */
  maxRetries: number;
  /** Initial delay in ms before first retry */
  initialDelayMs: number;
  /** Multiplier for exponential backoff */
  backoffMultiplier: number;
  /** Maximum delay in ms between retries */
  maxDelayMs: number;
  /** Jitter factor (0-1) to add randomness to delay */
  jitterFactor: number;
}

/** Configuration for HTML sanitization */
export interface SanitizeConfig {
  /** Strip all script tags */
  stripScripts?: boolean;
  /** Strip event handler attributes (onclick, onerror, etc.) */
  stripEventHandlers?: boolean;
  /** Strip javascript: URLs */
  stripJavascriptUrls?: boolean;
  /** Strip iframe tags */
  stripIframes?: boolean;
  /** Strip object/embed tags */
  stripObjectEmbed?: boolean;
  /** Strip style tags */
  stripStyles?: boolean;
  /** Allowed tags (if set, only these tags are kept) */
  allowedTags?: string[];
  /** Custom patterns to strip */
  customPatterns?: RegExp[];
}

/** Default retry options */
const DEFAULT_RETRY_OPTIONS: RetryOptions = {
  maxRetries: 3,
  initialDelayMs: 1000,
  backoffMultiplier: 2,
  maxDelayMs: 30000,
  jitterFactor: 0.1,
};

// ─── Cryptographic Utilities ──────────────────────────────────────

/**
 * Constant-time string/buffer comparison to prevent timing attacks.
 * Compares all bytes regardless of where the first difference occurs.
 */
export function constantTimeEqual(a: string | Uint8Array, b: string | Uint8Array): boolean {
  const aBytes = typeof a === 'string' ? new TextEncoder().encode(a) : a;
  const bBytes = typeof b === 'string' ? new TextEncoder().encode(b) : b;

  if (aBytes.length !== bBytes.length) return false;

  let result = 0;
  for (let i = 0; i < aBytes.length; i++) {
    result |= aBytes[i] ^ bBytes[i];
  }
  return result === 0;
}

/**
 * Generate cryptographically secure random bytes.
 * Uses crypto.getRandomValues for CSPRNG.
 */
export function secureRandom(bytes: number): Uint8Array {
  if (bytes <= 0) throw new Error('[VRIL] secureRandom: bytes must be positive');
  return crypto.getRandomValues(new Uint8Array(bytes));
}

/**
 * Generate a cryptographically secure random string.
 * Default charset is URL-safe alphanumeric characters.
 */
export function secureRandomString(
  length: number,
  charset: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
): string {
  if (length <= 0) throw new Error('[VRIL] secureRandomString: length must be positive');

  const randomBytes = secureRandom(length);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[randomBytes[i] % charset.length];
  }
  return result;
}

/**
 * Hash data using SHA-256, SHA-384, or SHA-512 via Web Crypto API.
 * Returns a hex-encoded hash string.
 */
export async function hashData(
  data: string | Uint8Array,
  algorithm: 'SHA-256' | 'SHA-384' | 'SHA-512' = 'SHA-256'
): Promise<string> {
  const encoded = typeof data === 'string' ? new TextEncoder().encode(data) : (data as Uint8Array);
  const hashBuffer = await crypto.subtle.digest(algorithm, encoded as BufferSource);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// ─── Base64 Encoding ──────────────────────────────────────────────

/**
 * Encode an ArrayBuffer or Uint8Array to a standard Base64 string.
 */
export function encodeBase64(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Decode a standard Base64 string to a Uint8Array.
 */
export function decodeBase64(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encode an ArrayBuffer or Uint8Array to a URL-safe Base64 string.
 * Replaces '+' with '-', '/' with '_', and strips padding '='.
 */
export function encodeBase64Url(data: ArrayBuffer | Uint8Array): string {
  return encodeBase64(data)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decode a URL-safe Base64 string to a Uint8Array.
 * Restores '+' and '/' characters and adds padding.
 */
export function decodeBase64Url(str: string): Uint8Array {
  let padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = padded.length % 4;
  if (padding === 2) padded += '==';
  else if (padding === 3) padded += '=';
  return decodeBase64(padded);
}

// ─── HTML Sanitization ────────────────────────────────────────────

/**
 * Basic HTML sanitizer that strips dangerous elements and attributes.
 * Not a full sanitizer — use DOMPurify for complex use cases.
 */
export function sanitizeHTML(html: string, config: SanitizeConfig = {}): string {
  const {
    stripScripts = true,
    stripEventHandlers = true,
    stripJavascriptUrls = true,
    stripIframes = true,
    stripObjectEmbed = true,
    stripStyles = false,
    allowedTags,
    customPatterns = [],
  } = config;

  let sanitized = html;

  // Strip script tags
  if (stripScripts) {
    sanitized = sanitized.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '');
    sanitized = sanitized.replace(/<script\b[^>]*\/?>/gi, '');
  }

  // Strip iframe tags
  if (stripIframes) {
    sanitized = sanitized.replace(/<iframe\b[^>]*>[\s\S]*?<\/iframe>/gi, '');
    sanitized = sanitized.replace(/<iframe\b[^>]*\/?>/gi, '');
  }

  // Strip object/embed tags
  if (stripObjectEmbed) {
    sanitized = sanitized.replace(/<object\b[^>]*>[\s\S]*?<\/object>/gi, '');
    sanitized = sanitized.replace(/<embed\b[^>]*>/gi, '');
  }

  // Strip style tags
  if (stripStyles) {
    sanitized = sanitized.replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, '');
  }

  // Strip event handler attributes
  if (stripEventHandlers) {
    sanitized = sanitized.replace(/\s+on\w+\s*=\s*["'][^"']*["']/gi, '');
    sanitized = sanitized.replace(/\s+on\w+\s*=\s*\S+/gi, '');
  }

  // Strip javascript: URLs
  if (stripJavascriptUrls) {
    sanitized = sanitized.replace(/href\s*=\s*["']javascript:[^"']*["']/gi, 'href="#"');
    sanitized = sanitized.replace(/src\s*=\s*["']javascript:[^"']*["']/gi, '');
    sanitized = sanitized.replace(/action\s*=\s*["']javascript:[^"']*["']/gi, '');
  }

  // Filter to allowed tags only
  if (allowedTags && allowedTags.length > 0) {
    const tagPattern = new RegExp(`<(?!\/?(${allowedTags.join('|')})[\\s>])[^>]+>`, 'gi');
    sanitized = sanitized.replace(tagPattern, '');
  }

  // Custom patterns
  for (const pattern of customPatterns) {
    sanitized = sanitized.replace(pattern, '');
  }

  return sanitized;
}

// ─── URL Validation ───────────────────────────────────────────────

/**
 * Validate a URL string and check its protocol against allowed protocols.
 * Prevents javascript:, data:, and vbscript: XSS vectors by default.
 */
export function validateURL(
  url: string,
  allowedProtocols: string[] = ['https:', 'http:']
): { valid: boolean; protocol: string | null; reason?: string } {
  if (!url || typeof url !== 'string') {
    return { valid: false, protocol: null, reason: 'URL is empty or not a string' };
  }

  // Trim whitespace
  const trimmed = url.trim();

  // Check for protocol-relative URLs
  if (trimmed.startsWith('//')) {
    return { valid: true, protocol: 'relative', reason: 'Protocol-relative URL' };
  }

  try {
    const parsed = new URL(trimmed, typeof location !== 'undefined' ? location.href : undefined);
    const protocol = parsed.protocol.toLowerCase();

    if (!allowedProtocols.includes(protocol)) {
      return {
        valid: false,
        protocol,
        reason: `Protocol "${protocol}" not in allowed list: [${allowedProtocols.join(', ')}]`,
      };
    }

    // Additional XSS checks
    const lowerUrl = trimmed.toLowerCase();
    const dangerousPatterns = ['javascript:', 'data:text/html', 'vbscript:'];
    for (const pattern of dangerousPatterns) {
      if (lowerUrl.includes(pattern)) {
        return { valid: false, protocol, reason: `Dangerous URL pattern detected: ${pattern}` };
      }
    }

    return { valid: true, protocol };
  } catch (e) {
    return { valid: false, protocol: null, reason: `Invalid URL: ${(e as Error).message}` };
  }
}

// ─── Object Utilities ─────────────────────────────────────────────

/**
 * Deep clone an object using structuredClone with fallback.
 * Handles ArrayBuffers, TypedArrays, and Date objects correctly.
 */
export function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') return obj;

  // Use structuredClone if available (handles ArrayBuffers, Dates, etc.)
  if (typeof structuredClone === 'function') {
    try {
      return structuredClone(obj);
    } catch {
      // Fall through to manual clone
    }
  }

  // Manual deep clone fallback
  if (obj instanceof ArrayBuffer) {
    return obj.slice(0) as unknown as T;
  }

  if (ArrayBuffer.isView(obj)) {
    const view = obj as unknown as ArrayBufferView;
    return new (view.constructor as any)(view.buffer.slice(0), view.byteOffset, (view as any).length) as unknown as T;
  }

  if (obj instanceof Date) {
    return new Date(obj.getTime()) as unknown as T;
  }

  if (obj instanceof Map) {
    const clone = new Map() as Map<any, any>;
    for (const [key, value] of (obj as Map<any, any>)) {
      clone.set(deepClone(key), deepClone(value));
    }
    return clone as unknown as T;
  }

  if (obj instanceof Set) {
    const clone = new Set() as Set<any>;
    for (const value of (obj as Set<any>)) {
      clone.add(deepClone(value));
    }
    return clone as unknown as T;
  }

  if (Array.isArray(obj)) {
    return obj.map(item => deepClone(item)) as unknown as T;
  }

  const clone: Record<string, unknown> = {};
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    clone[key] = deepClone((obj as Record<string, unknown>)[key]);
  }
  return clone as T;
}

/**
 * Deep freeze an object, making it recursively immutable.
 * Applies Object.freeze to all nested objects and arrays.
 */
export function deepFreeze<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') return obj;

  // Get all properties including non-enumerable
  const propNames = Object.getOwnPropertyNames(obj);

  for (const name of propNames) {
    const value = (obj as Record<string, unknown>)[name];
    if (value && typeof value === 'object') {
      deepFreeze(value);
    }
  }

  return Object.freeze(obj);
}

/**
 * Deep merge two objects with type safety.
 * Override values take precedence; arrays are replaced, not concatenated.
 */
export function mergeConfigs<T extends Record<string, unknown>>(
  base: T,
  override: Partial<T>
): T {
  const result = { ...base } as Record<string, unknown>;

  for (const key of Object.keys(override as Record<string, unknown>)) {
    const baseVal = result[key];
    const overVal = (override as Record<string, unknown>)[key];

    if (
      baseVal && overVal &&
      typeof baseVal === 'object' && typeof overVal === 'object' &&
      !Array.isArray(baseVal) && !Array.isArray(overVal) &&
      !(baseVal instanceof Date) && !(overVal instanceof Date) &&
      !(baseVal instanceof Map) && !(overVal instanceof Map) &&
      !(baseVal instanceof Set) && !(overVal instanceof Set) &&
      !(ArrayBuffer.isView(baseVal)) && !(ArrayBuffer.isView(overVal))
    ) {
      result[key] = mergeConfigs(
        baseVal as Record<string, unknown>,
        overVal as Record<string, unknown>
      );
    } else if (overVal !== undefined) {
      result[key] = overVal;
    }
  }

  return result as T;
}

// ─── Function Utilities ───────────────────────────────────────────

/**
 * Debounce a function — delays invocation until `ms` milliseconds
 * have elapsed since the last call.
 */
export function debounce<T extends (...args: any[]) => any>(
  fn: T,
  ms: number
): (...args: Parameters<T>) => void {
  let timer: ReturnType<typeof setTimeout> | undefined;

  return function (this: any, ...args: Parameters<T>) {
    if (timer !== undefined) clearTimeout(timer);
    timer = setTimeout(() => {
      fn.apply(this, args);
      timer = undefined;
    }, ms);
  };
}

/**
 * Throttle a function — limits invocation to at most once per `ms` milliseconds.
 * Calls the function with the latest arguments on the trailing edge.
 */
export function throttle<T extends (...args: any[]) => any>(
  fn: T,
  ms: number
): (...args: Parameters<T>) => void {
  let lastCall = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let lastArgs: Parameters<T> | undefined;

  return function (this: any, ...args: Parameters<T>) {
    const now = Date.now();
    lastArgs = args;

    if (now - lastCall >= ms) {
      lastCall = now;
      fn.apply(this, args);
    } else if (timer === undefined) {
      timer = setTimeout(() => {
        lastCall = Date.now();
        timer = undefined;
        if (lastArgs) fn.apply(this, lastArgs);
      }, ms - (now - lastCall));
    }
  };
}

/**
 * Retry a function with exponential backoff.
 * Waits increasingly longer between each retry attempt.
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  options: Partial<RetryOptions> = {}
): Promise<T> {
  const opts = { ...DEFAULT_RETRY_OPTIONS, ...options };
  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= opts.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));

      if (attempt === opts.maxRetries) break;

      // Calculate delay with exponential backoff
      const baseDelay = opts.initialDelayMs * Math.pow(opts.backoffMultiplier, attempt);
      const jitter = baseDelay * opts.jitterFactor * Math.random();
      const delay = Math.min(baseDelay + jitter, opts.maxDelayMs);

      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  throw lastError ?? new Error('[VRIL] retryWithBackoff: all retries exhausted');
}
