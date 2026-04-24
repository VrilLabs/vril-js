/**
 * Vril.js v2.0.0 — Streaming Utilities for React Server Components
 * Secure streaming boundaries · HMAC integrity · Rate limiting ·
 * Content sanitization · Streaming cache
 *
 * Zero external dependencies — Web Streams API and Web Crypto API only.
 */

// ─── Types ────────────────────────────────────────────────────

/** Configuration for streaming behavior */
export interface StreamingConfig {
  /** HMAC secret key for chunk integrity validation */
  hmacSecret?: string;
  /** Maximum bytes per second per stream (rate limiting) */
  maxBytesPerSecond?: number;
  /** Maximum chunk size in bytes */
  maxChunkSize?: number;
  /** Maximum total stream size in bytes */
  maxTotalSize?: number;
  /** Patterns to strip from streaming content */
  sanitizePatterns?: RegExp[];
  /** Cache policy for streaming responses */
  cachePolicy?: CachePolicy;
  /** Enable integrity validation */
  integrityCheck?: boolean;
}

/** A chunk in the streaming pipeline */
export interface StreamChunk {
  id: string;
  data: string;
  sequence: number;
  hash?: string;
  timestamp: number;
  isFinal?: boolean;
}

/** Cache policy for streaming responses */
export interface CachePolicy {
  /** Time-to-live in milliseconds */
  ttl: number;
  /** Stale-while-revalidate window in milliseconds */
  staleWhileRevalidate?: number;
  /** Maximum number of cached entries */
  maxEntries?: number;
  /** Vary-by headers for cache key generation */
  varyBy?: string[];
}

/** Default streaming configuration */
const DEFAULT_STREAMING_CONFIG: StreamingConfig = {
  maxBytesPerSecond: 1024 * 1024, // 1 MB/s
  maxChunkSize: 64 * 1024,        // 64 KB
  maxTotalSize: 10 * 1024 * 1024, // 10 MB
  integrityCheck: true,
  cachePolicy: {
    ttl: 60000,
    staleWhileRevalidate: 30000,
    maxEntries: 100,
  },
};

// ─── Streaming Boundary ───────────────────────────────────────

const SECURITY_FALLBACK = '<div aria-busy="true" role="status">Loading secure content…</div>';

/**
 * Creates a Suspense-like streaming boundary with security-aware fallback.
 * Prevents rendering of untrusted content while the stream is loading.
 */
export function createStreamingBoundary(
  boundaryId: string,
  config?: Partial<StreamingConfig>
): {
  wrap: (content: string) => string;
  getFallback: () => string;
  resolve: (content: string) => string;
  reject: (error: Error) => string;
} {
  const cfg = { ...DEFAULT_STREAMING_CONFIG, ...config };
  const marker = `vril-stream-${boundaryId}`;

  return {
    /** Wrap content in a streaming boundary container */
    wrap(content: string): string {
      return `<!--${marker}:start-->${content}<!--${marker}:end-->`;
    },

    /** Get the security-safe fallback for unresolved boundaries */
    getFallback(): string {
      return `<!--${marker}:fallback-->${SECURITY_FALLBACK}<!--${marker}:end-->`;
    },

    /** Resolve the boundary with validated content */
    resolve(content: string): string {
      const sanitized = new SecureStreamTransformer(cfg).transform(content);
      return `<!--${marker}:resolved-->${sanitized}<!--${marker}:end-->`;
    },

    /** Reject the boundary with an error (sanitized message) */
    reject(error: Error): string {
      const safeMsg = escapeHtml(error.message).substring(0, 200);
      return `<!--${marker}:error--><div role="alert">Content unavailable: ${safeMsg}</div><!--${marker}:end-->`;
    },
  };
}

// ─── Stream Integrity Validator ───────────────────────────────

/**
 * Validates streaming chunks haven't been tampered with using HMAC-SHA256.
 * Uses the Web Crypto API for all cryptographic operations.
 */
export class StreamIntegrityValidator {
  private secret: string;
  private version = '2.1.0';

  constructor(secret: string) {
    this.secret = secret;
  }

  /** Compute an HMAC-SHA256 tag for a chunk */
  async computeHash(data: string, sequence: number): Promise<string> {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(this.secret);
    const message = encoder.encode(`${sequence}:${data}`);

    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, message);
    return Array.from(new Uint8Array(signature))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /** Validate a chunk's integrity against its stored hash */
  async validate(chunk: StreamChunk): Promise<boolean> {
    if (!chunk.hash) return false;
    const computed = await this.computeHash(chunk.data, chunk.sequence);
    return constantTimeEqual(computed, chunk.hash);
  }

  /** Sign a chunk by computing and attaching its hash */
  async sign(chunk: Omit<StreamChunk, 'hash'>): Promise<StreamChunk> {
    const hash = await this.computeHash(chunk.data, chunk.sequence);
    return { ...chunk, hash };
  }

  /** Validate an entire sequence of chunks */
  async validateSequence(chunks: StreamChunk[]): Promise<{
    valid: boolean;
    invalidChunks: number[];
  }> {
    const invalidChunks: number[] = [];

    for (let i = 0; i < chunks.length; i++) {
      const chunk = chunks[i];
      // Verify sequence order
      if (chunk.sequence !== i) {
        invalidChunks.push(i);
        continue;
      }
      // Verify hash
      const valid = await this.validate(chunk);
      if (!valid) {
        invalidChunks.push(i);
      }
    }

    return {
      valid: invalidChunks.length === 0,
      invalidChunks,
    };
  }
}

// ─── Rate-Limited Stream ──────────────────────────────────────

/**
 * Wraps streams with rate limiting to prevent DoS attacks.
 * Enforces bytes-per-second and total size limits.
 */
export class RateLimitedStream {
  private config: StreamingConfig;
  private bytesSent = 0;
  private startTime = 0;
  private version = '2.1.0';

  constructor(config?: Partial<StreamingConfig>) {
    this.config = { ...DEFAULT_STREAMING_CONFIG, ...config };
  }

  /** Check if a chunk can be sent without exceeding rate limits */
  canSend(chunkSize: number): { allowed: boolean; reason?: string } {
    // Total size check
    if (
      this.config.maxTotalSize &&
      this.bytesSent + chunkSize > this.config.maxTotalSize
    ) {
      return {
        allowed: false,
        reason: `Total size limit exceeded: ${this.bytesSent + chunkSize} > ${this.config.maxTotalSize}`,
      };
    }

    // Per-chunk size check
    if (this.config.maxChunkSize && chunkSize > this.config.maxChunkSize) {
      return {
        allowed: false,
        reason: `Chunk size exceeds limit: ${chunkSize} > ${this.config.maxChunkSize}`,
      };
    }

    // Rate check
    if (this.config.maxBytesPerSecond && this.startTime > 0) {
      const elapsed = (Date.now() - this.startTime) / 1000;
      const currentRate = this.bytesSent / elapsed;
      if (currentRate > this.config.maxBytesPerSecond) {
        return {
          allowed: false,
          reason: `Rate limit exceeded: ${Math.round(currentRate)} B/s > ${this.config.maxBytesPerSecond} B/s`,
        };
      }
    }

    return { allowed: true };
  }

  /** Record that bytes have been sent */
  recordSent(bytes: number): void {
    if (this.startTime === 0) this.startTime = Date.now();
    this.bytesSent += bytes;
  }

  /** Create a rate-limited TransformStream */
  createTransformStream(): TransformStream<string, string> {
    const self = this;
    return new TransformStream({
      transform(chunk, controller) {
        const size = new TextEncoder().encode(chunk).length;
        const check = self.canSend(size);
        if (check.allowed) {
          self.recordSent(size);
          controller.enqueue(chunk);
        } else {
          controller.error(new Error(`[VRIL Stream] ${check.reason}`));
        }
      },
    });
  }

  /** Get current statistics */
  getStats(): { bytesSent: number; elapsedMs: number; bytesPerSecond: number } {
    const elapsed = this.startTime > 0 ? Date.now() - this.startTime : 0;
    return {
      bytesSent: this.bytesSent,
      elapsedMs: elapsed,
      bytesPerSecond: elapsed > 0 ? (this.bytesSent / elapsed) * 1000 : 0,
    };
  }

  /** Reset the rate limiter */
  reset(): void {
    this.bytesSent = 0;
    this.startTime = 0;
  }
}

// ─── Secure Stream Transformer ────────────────────────────────

/** Default patterns stripped from streaming content */
const DEFAULT_SANITIZE_PATTERNS: RegExp[] = [
  /<script\b[^>]*>[\s\S]*?<\/script>/gi,
  /javascript\s*:/gi,
  /on(error|load|click|mouseover|focus|blur|submit|change|keydown)\s*=\s*["'][^"']*["']/gi,
  /<iframe\b[^>]*>[\s\S]*?<\/iframe>/gi,
  /<object\b[^>]*>[\s\S]*?<\/object>/gi,
  /<embed\b[^>]*>/gi,
  /expression\s*\(/gi,
  /vbscript\s*:/gi,
  /data\s*:\s*text\/html/gi,
  /\\u003[cC]/g,
  /\\x3[cC]/g,
];

/**
 * Sanitizes streaming content by stripping dangerous patterns.
 * Can be used as a TransformStream or standalone transformer.
 */
export class SecureStreamTransformer {
  private patterns: RegExp[];
  private version = '2.1.0';

  constructor(config?: Partial<StreamingConfig>) {
    this.patterns =
      config?.sanitizePatterns ?? DEFAULT_SANITIZE_PATTERNS;
  }

  /** Transform (sanitize) a string in-place */
  transform(content: string): string {
    let sanitized = content;
    for (const pattern of this.patterns) {
      sanitized = sanitized.replace(pattern, '');
    }
    return sanitized;
  }

  /** Create a TransformStream for use in a pipeline */
  createTransformStream(): TransformStream<string, string> {
    const self = this;
    return new TransformStream({
      transform(chunk, controller) {
        controller.enqueue(self.transform(chunk));
      },
    });
  }

  /** Add a custom sanitization pattern */
  addPattern(pattern: RegExp): void {
    this.patterns.push(pattern);
  }

  /** Remove a sanitization pattern */
  removePattern(pattern: RegExp): void {
    const idx = this.patterns.indexOf(pattern);
    if (idx !== -1) this.patterns.splice(idx, 1);
  }
}

// ─── Streaming Cache ──────────────────────────────────────────

interface CachedStream {
  chunks: StreamChunk[];
  cachedAt: number;
  accessedAt: number;
  etag: string;
  policy: CachePolicy;
}

/**
 * Cache streaming responses with stale-while-revalidate support.
 * In-memory cache with TTL and size limits.
 */
export class StreamingCache {
  private cache = new Map<string, CachedStream>();
  private config: CachePolicy;
  private version = '2.1.0';

  constructor(policy?: CachePolicy) {
    this.config = policy ?? DEFAULT_STREAMING_CONFIG.cachePolicy!;
  }

  /** Store a complete stream response in cache */
  set(key: string, chunks: StreamChunk[], policy?: CachePolicy): void {
    const effectivePolicy = policy ?? this.config;

    // Evict if at capacity
    if (this.config.maxEntries && this.cache.size >= this.config.maxEntries) {
      this.evictOldest();
    }

    const combined = chunks.map((c) => c.data).join('');
    this.cache.set(key, {
      chunks,
      cachedAt: Date.now(),
      accessedAt: Date.now(),
      etag: simpleHash(combined),
      policy: effectivePolicy,
    });
  }

  /** Retrieve cached stream if still fresh */
  get(key: string): StreamChunk[] | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    const age = Date.now() - entry.cachedAt;
    const swrWindow = entry.policy.staleWhileRevalidate ?? 0;
    const totalLifetime = entry.policy.ttl + swrWindow;

    if (age > totalLifetime) {
      this.cache.delete(key);
      return null;
    }

    entry.accessedAt = Date.now();
    return entry.chunks;
  }

  /** Check if a cached response is stale (but within SWR window) */
  isStale(key: string): boolean {
    const entry = this.cache.get(key);
    if (!entry) return false;
    return Date.now() - entry.cachedAt > entry.policy.ttl;
  }

  /** Check if a cached response should be revalidated in the background */
  shouldRevalidate(key: string): boolean {
    return this.isStale(key) && this.get(key) !== null;
  }

  /** Get the ETag for a cached response */
  getETag(key: string): string | null {
    return this.cache.get(key)?.etag ?? null;
  }

  /** Invalidate a specific cache key */
  invalidate(key: string): boolean {
    return this.cache.delete(key);
  }

  /** Invalidate all cache entries matching a pattern */
  invalidatePattern(pattern: RegExp): number {
    let count = 0;
    for (const key of this.cache.keys()) {
      if (pattern.test(key)) {
        this.cache.delete(key);
        count++;
      }
    }
    return count;
  }

  /** Clear the entire cache */
  clear(): void {
    this.cache.clear();
  }

  /** Get cache statistics */
  getStats(): { size: number; hitRate: number; entries: number } {
    return {
      size: this.cache.size,
      hitRate: 0, // Would need hit/miss tracking for real implementation
      entries: this.cache.size,
    };
  }

  /** Evict the oldest entry */
  private evictOldest(): void {
    let oldest: string | null = null;
    let oldestTime = Infinity;
    for (const [key, entry] of this.cache) {
      if (entry.accessedAt < oldestTime) {
        oldest = key;
        oldestTime = entry.accessedAt;
      }
    }
    if (oldest) this.cache.delete(oldest);
  }
}

// ─── Helpers ──────────────────────────────────────────────────

/** Constant-time string comparison to prevent timing attacks */
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/** Simple non-cryptographic hash for ETags */
function simpleHash(input: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return ('00000000' + (h >>> 0).toString(16)).slice(-8);
}

/** Escape HTML special characters */
function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}
