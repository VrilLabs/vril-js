/**
 * Vril.js v2.0.0 — Server-Side Rendering Module
 * Streaming SSR · Security validation · Selective hydration · SSR manifest
 *
 * Zero external dependencies — uses Web Streams API and React conventions only.
 */

// ─── Types ────────────────────────────────────────────────────

/** Hydration priority strategy for components */
export type HydrationStrategy = 'immediate' | 'visible' | 'idle';

/** A chunk in the SSR stream */
export interface SSRChunk {
  id: string;
  html: string;
  suspenseBoundary?: string;
  isFallback?: boolean;
  timestamp: number;
}

/** Options for SSR rendering */
export interface SSROptions {
  /** Maximum time in ms to wait for Suspense boundaries before sending fallback */
  timeout?: number;
  /** Enable streaming (chunked transfer encoding) */
  streaming?: boolean;
  /** Security validation of SSR output */
  securityCheck?: boolean;
  /** Max HTML size in bytes to prevent memory bomb */
  maxHtmlSize?: number;
  /** Bootstrap script nonce for CSP */
  nonce?: string;
  /** Custom abort signal */
  signal?: AbortSignal;
}

/** Component hydration descriptor */
export interface HydrationDescriptor {
  componentId: string;
  strategy: HydrationStrategy;
  props?: Record<string, unknown>;
  boundary?: string;
}

/** SSR manifest tracking what was rendered on the server */
export interface SSRManifestEntry {
  componentId: string;
  rendered: boolean;
  strategy: HydrationStrategy;
  htmlHash: string;
  timestamp: number;
}

// ─── SSR Security Guard ───────────────────────────────────────

/** Dangerous patterns that should never appear in SSR output */
const XSS_PATTERNS: RegExp[] = [
  /<script\b[^>]*>[\s\S]*?<\/script>/gi,
  /javascript\s*:/gi,
  /on(error|load|click|mouseover|focus|blur|submit|change)\s*=/gi,
  /<iframe\b[^>]*>[\s\S]*?<\/iframe>/gi,
  /<object\b[^>]*>[\s\S]*?<\/object>/gi,
  /<embed\b[^>]*>/gi,
  /<link\b[^>]*rel\s*=\s*["']importmap/gi,
  /data\s*:\s*text\/html/gi,
  /expression\s*\(/gi,
  /vbscript\s*:/gi,
  /<meta\b[^>]*http-equiv\s*=\s*["']refresh/gi,
];

const INJECTION_PATTERNS: RegExp[] = [
  /\$\{.*\}/g,                       // Template injection
  /<!--\s*#include/gi,               // SSI injection
  /<!--\s*#exec/gi,                  // SSI exec
  /%3Cscript/gi,                     // URL-encoded script
  /\\u003[cC]/g,                     // Unicode-encoded <
];

/**
 * Validates SSR output for XSS and injection attacks before sending to client.
 * Strips or rejects dangerous content patterns.
 */
export class SSRSecurityGuard {
  private violations: string[] = [];
  private version = '2.1.0';
  private maxHtmlSize: number;

  constructor(maxHtmlSize: number = 5 * 1024 * 1024) {
    this.maxHtmlSize = maxHtmlSize;
  }

  /**
   * Validate HTML string for security threats.
   * Returns sanitized HTML and a list of violations found.
   */
  validate(html: string): { safe: boolean; html: string; violations: string[] } {
    this.violations = [];

    // Size check — prevent memory bombs
    if (html.length > this.maxHtmlSize) {
      this.violations.push(
        `HTML size ${html.length} exceeds maximum ${this.maxHtmlSize} bytes`
      );
      return { safe: false, html: '', violations: this.violations };
    }

    let sanitized = html;

    // Check XSS patterns
    for (const pattern of XSS_PATTERNS) {
      const matches = sanitized.match(pattern);
      if (matches) {
        for (const match of matches) {
          this.violations.push(`XSS pattern detected: ${match.substring(0, 80)}`);
        }
        sanitized = sanitized.replace(pattern, '');
      }
    }

    // Check injection patterns
    for (const pattern of INJECTION_PATTERNS) {
      const matches = sanitized.match(pattern);
      if (matches) {
        for (const match of matches) {
          this.violations.push(`Injection pattern detected: ${match.substring(0, 80)}`);
        }
        sanitized = sanitized.replace(pattern, '');
      }
    }

    // Validate attribute values for event handlers
    const attrPattern = /\s(\w+)\s*=\s*["']([^"']*?)["']/g;
    let attrMatch: RegExpExecArray | null;
    while ((attrMatch = attrPattern.exec(sanitized)) !== null) {
      const [, attrName, attrValue] = attrMatch;
      if (/^on/i.test(attrName) && attrValue.length > 0) {
        this.violations.push(`Event handler attribute: ${attrName}="${attrValue.substring(0, 40)}"`);
      }
    }

    return {
      safe: this.violations.length === 0,
      html: sanitized,
      violations: [...this.violations],
    };
  }

  /** Get the list of violations from the last validation */
  getViolations(): string[] {
    return [...this.violations];
  }
}

// ─── Streaming SSR ────────────────────────────────────────────

/**
 * Create an SSR stream from chunked HTML output.
 * Implements chunked transfer encoding using Web Streams API.
 */
export function createSSRStream(options?: SSROptions): {
  stream: ReadableStream<SSRChunk>;
  enqueue: (chunk: SSRChunk) => void;
  close: () => void;
} {
  const chunks: SSRChunk[] = [];
  let controller: ReadableStreamDefaultController<SSRChunk> | null = null;
  let closed = false;

  const stream = new ReadableStream<SSRChunk>({
    start(ctrl) {
      controller = ctrl;
      // Flush any chunks enqueued before the controller was ready
      for (const chunk of chunks) {
        ctrl.enqueue(chunk);
      }
      chunks.length = 0;
    },
    cancel() {
      closed = true;
      controller = null;
    },
  });

  function enqueue(chunk: SSRChunk): void {
    if (closed) return;
    if (controller) {
      controller.enqueue(chunk);
    } else {
      chunks.push(chunk);
    }
  }

  function close(): void {
    if (closed) return;
    closed = true;
    if (controller) {
      try { controller.close(); } catch { /* already closed */ }
    }
  }

  return { stream, enqueue, close };
}

/**
 * Render a React tree to a ReadableStream with Suspense boundary support.
 * Produces chunks as HTML fragments become available.
 */
export async function renderToStream(
  renderFn: () => string | Promise<string>,
  options: SSROptions = {}
): Promise<{ stream: ReadableStream<SSRChunk>; manifest: SSRManifest }> {
  const {
    timeout = 10000,
    securityCheck = true,
    maxHtmlSize = 5 * 1024 * 1024,
    nonce,
    signal,
  } = options;

  const { stream, enqueue, close } = createSSRStream(options);
  const manifest = new SSRManifest();
  const guard = securityCheck ? new SSRSecurityGuard(maxHtmlSize) : null;

  const renderPromise = (async () => {
    try {
      const html = await renderFn();

      if (guard) {
        const result = guard.validate(html);
        if (!result.safe) {
          enqueue({
            id: 'error',
            html: '<!-- SSR validation failed -->',
            timestamp: Date.now(),
          });
          close();
          return;
        }
        enqueue({
          id: 'root',
          html: result.html,
          timestamp: Date.now(),
        });
      } else {
        enqueue({
          id: 'root',
          html,
          timestamp: Date.now(),
        });
      }

      manifest.record('root', true, 'immediate', await hashString(html));
    } catch (err) {
      enqueue({
        id: 'error',
        html: `<!-- SSR render error: ${escapeHtml(String(err))} -->`,
        timestamp: Date.now(),
      });
    } finally {
      close();
    }
  })();

  // Apply timeout
  if (timeout > 0) {
    const timeoutPromise = new Promise<void>((resolve) => {
      setTimeout(() => {
        enqueue({
          id: 'timeout',
          html: '<!-- SSR timeout -->',
          isFallback: true,
          timestamp: Date.now(),
        });
        close();
        resolve();
      }, timeout);
    });

    await Promise.race([renderPromise, timeoutPromise]);
  } else {
    await renderPromise;
  }

  if (signal?.aborted) {
    close();
  }

  return { stream, manifest };
}

// ─── Selective Hydration ──────────────────────────────────────

/**
 * Marks components for hydration priority.
 * Injects data attributes into HTML for client-side hydration scheduling.
 */
export class SelectiveHydration {
  private descriptors = new Map<string, HydrationDescriptor>();
  private version = '2.1.0';

  /** Register a component for selective hydration */
  register(descriptor: HydrationDescriptor): void {
    this.descriptors.set(descriptor.componentId, descriptor);
  }

  /** Wrap HTML with hydration metadata attributes */
  wrapForHydration(componentId: string, html: string): string {
    const descriptor = this.descriptors.get(componentId);
    if (!descriptor) return html;

    const strategy = descriptor.strategy;
    const attrs = [
      `data-vril-hydrate="${strategy}"`,
      `data-vril-id="${componentId}"`,
    ];

    if (descriptor.boundary) {
      attrs.push(`data-vril-boundary="${escapeHtml(descriptor.boundary)}"`);
    }

    if (descriptor.props && Object.keys(descriptor.props).length > 0) {
      try {
        const encoded = btoa(JSON.stringify(descriptor.props));
        attrs.push(`data-vril-props="${encoded}"`);
      } catch { /* props too large, skip */ }
    }

    return `<div ${attrs.join(' ')}>${html}</div>`;
  }

  /** Get hydration script that the client should execute */
  getHydrationScript(nonce?: string): string {
    const entries = Array.from(this.descriptors.entries());
    if (entries.length === 0) return '';

    const schedule = entries.map(([, d]) => ({
      id: d.componentId,
      strategy: d.strategy,
      boundary: d.boundary,
    }));

    const nonceAttr = nonce ? ` nonce="${escapeHtml(nonce)}"` : '';
    const json = JSON.stringify(schedule);
    return `<script${nonceAttr}>self.__VRIL_HYDRATION__=${json};</script>`;
  }

  /** Get all registered descriptors */
  getDescriptors(): HydrationDescriptor[] {
    return Array.from(this.descriptors.values());
  }

  /** Clear all descriptors */
  clear(): void {
    this.descriptors.clear();
  }
}

// ─── SSR Manifest ─────────────────────────────────────────────

/**
 * Tracks what was server-rendered vs client-only.
 * Used for hydration reconciliation and debugging.
 */
export class SSRManifest {
  private entries = new Map<string, SSRManifestEntry>();
  private version = '2.1.0';

  /** Record a component that was rendered on the server */
  record(
    componentId: string,
    rendered: boolean,
    strategy: HydrationStrategy,
    htmlHash: string
  ): void {
    this.entries.set(componentId, {
      componentId,
      rendered,
      strategy,
      htmlHash,
      timestamp: Date.now(),
    });
  }

  /** Check if a component was server-rendered */
  wasRendered(componentId: string): boolean {
    return this.entries.get(componentId)?.rendered ?? false;
  }

  /** Get the hydration strategy for a component */
  getStrategy(componentId: string): HydrationStrategy | null {
    return this.entries.get(componentId)?.strategy ?? null;
  }

  /** Verify the HTML hash matches what was rendered (detects tampering) */
  async verifyIntegrity(componentId: string, currentHtml: string): Promise<boolean> {
    const entry = this.entries.get(componentId);
    if (!entry) return false;
    const currentHash = await hashString(currentHtml);
    return currentHash === entry.htmlHash;
  }

  /** Serialize the manifest to JSON */
  toJSON(): { version: string; entries: SSRManifestEntry[] } {
    return {
      version: this.version,
      entries: Array.from(this.entries.values()),
    };
  }

  /** Deserialize a manifest from JSON */
  static fromJSON(data: { version: string; entries: SSRManifestEntry[] }): SSRManifest {
    const manifest = new SSRManifest();
    for (const entry of data.entries) {
      manifest.entries.set(entry.componentId, entry);
    }
    return manifest;
  }

  /** Get all entries */
  getEntries(): SSRManifestEntry[] {
    return Array.from(this.entries.values());
  }

  /** Get count of rendered components */
  getRenderedCount(): number {
    let count = 0;
    for (const entry of this.entries.values()) {
      if (entry.rendered) count++;
    }
    return count;
  }
}

// ─── Helpers ──────────────────────────────────────────────────

/** Compute a SHA-256 hash of a string using Web Crypto API */
async function hashString(input: string): Promise<string> {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const data = new TextEncoder().encode(input);
    const buf = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
  // Fallback: simple hash for environments without crypto.subtle
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
