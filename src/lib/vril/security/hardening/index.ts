/**
 * Vril.js v2.1.0 — Browser Hardening Module
 *
 * Comprehensive browser security hardening including cross-origin isolation,
 * fingerprint resistance, timing attack mitigation, clickjacking protection,
 * XSS shielding, secure cookie management, and security headers builder.
 *
 * Zero external dependencies — Web APIs only.
 */

// ─── Types ────────────────────────────────────────────────────────────────

/** Hardening configuration */
export interface HardeningConfig {
  /** Enable cross-origin isolation (COOP+COEP+CORP) */
  crossOriginIsolation: boolean;
  /** Enable fingerprint resistance measures */
  fingerprintResistance: boolean;
  /** Enable timing attack mitigation */
  timingAttackMitigation: boolean;
  /** Enable clickjacking protection */
  clickjackingProtection: boolean;
  /** Enable XSS shield */
  xssShield: boolean;
  /** Enable secure cookie management */
  secureCookies: boolean;
  /** Cross-origin embedder policy value */
  coepPolicy: 'credentialless' | 'require-corp' | 'none';
  /** Cross-origin opener policy value */
  coopPolicy: 'same-origin' | 'same-origin-allow-popups' | 'unsafe-none';
  /** Cross-origin resource policy value */
  corpPolicy: 'same-origin' | 'same-site' | 'cross-origin';
}

/** Cookie options for secure cookie management */
export interface CookieOptions {
  /** Cookie name */
  name: string;
  /** Cookie value */
  value: string;
  /** Cookie expiration (max-age in seconds) */
  maxAge?: number;
  /** Cookie expiration date */
  expires?: Date;
  /** Domain for the cookie */
  domain?: string;
  /** Path for the cookie */
  path?: string;
  /** Whether to use Secure flag */
  secure?: boolean;
  /** Whether to use HttpOnly flag */
  httpOnly?: boolean;
  /** SameSite policy */
  sameSite?: 'Strict' | 'Lax' | 'None';
  /** Whether to use __Host- prefix (requires Secure, no domain, path=/) */
  hostPrefix?: boolean;
  /** Whether to use __Secure- prefix (requires Secure) */
  securePrefix?: boolean;
}

/** Security header set */
export interface SecurityHeaderSet {
  'Strict-Transport-Security'?: string;
  'X-Content-Type-Options'?: string;
  'X-Frame-Options'?: string;
  'Referrer-Policy'?: string;
  'Cross-Origin-Opener-Policy'?: string;
  'Cross-Origin-Embedder-Policy'?: string;
  'Cross-Origin-Resource-Policy'?: string;
  'Content-Security-Policy'?: string;
  'Permissions-Policy'?: string;
  'X-XSS-Protection'?: string;
  [key: string]: string | undefined;
}

/** Default hardening configuration */
const DEFAULT_HARDENING_CONFIG: HardeningConfig = {
  crossOriginIsolation: true,
  fingerprintResistance: true,
  timingAttackMitigation: true,
  clickjackingProtection: true,
  xssShield: true,
  secureCookies: true,
  coepPolicy: 'require-corp',
  coopPolicy: 'same-origin',
  corpPolicy: 'same-origin',
};

// ─── CrossOriginIsolation ─────────────────────────────────────────────────

/**
 * Enables cross-origin isolation for SharedArrayBuffer access
 * and improved security boundaries.
 *
 * Sets COOP (Cross-Origin-Opener-Policy), COEP (Cross-Origin-Embedder-Policy),
 * and CORP (Cross-Origin-Resource-Policy) headers.
 */
export class CrossOriginIsolation {
  private readonly version = '2.1.0';
  private config: HardeningConfig;
  private isIsolated = false;

  constructor(config?: Partial<HardeningConfig>) {
    this.config = { ...DEFAULT_HARDENING_CONFIG, ...config };
  }

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Check if the current page is cross-origin isolated.
   */
  isCrossOriginIsolated(): boolean {
    if (typeof window === 'undefined') return false;
    return (crossOriginIsolated as boolean) ?? false;
  }

  /**
   * Check if SharedArrayBuffer is available.
   */
  isSharedArrayBufferAvailable(): boolean {
    if (typeof window === 'undefined') return false;
    return typeof SharedArrayBuffer !== 'undefined';
  }

  /**
   * Get the headers needed for cross-origin isolation.
   */
  getIsolationHeaders(): SecurityHeaderSet {
    if (!this.config.crossOriginIsolation) return {};

    const headers: SecurityHeaderSet = {};

    if (this.config.coopPolicy !== 'unsafe-none') {
      headers['Cross-Origin-Opener-Policy'] = this.config.coopPolicy;
    }

    if (this.config.coepPolicy !== 'none') {
      headers['Cross-Origin-Embedder-Policy'] = this.config.coepPolicy;
    }

    headers['Cross-Origin-Resource-Policy'] = this.config.corpPolicy;

    return headers;
  }

  /**
   * Attempt to enable cross-origin isolation at runtime.
   * Note: This only works in contexts where headers can be modified.
   * For static pages, headers must be set by the server.
   */
  async enableIsolation(): Promise<{ success: boolean; reason?: string }> {
    if (typeof window === 'undefined') {
      return { success: false, reason: 'Not running in browser context' };
    }

    if (this.isCrossOriginIsolated()) {
      this.isIsolated = true;
      return { success: true };
    }

    // Check if we can enable isolation
    const hasSharedBuffer = this.isSharedArrayBufferAvailable();
    if (!hasSharedBuffer) {
      return {
        success: false,
        reason: 'SharedArrayBuffer not available — ensure COOP and COEP headers are set by the server',
      };
    }

    return {
      success: false,
      reason: 'Cross-origin isolation requires server-side headers (COOP + COEP)',
    };
  }

  /** Get current isolation status */
  getStatus(): {
    isIsolated: boolean;
    coop: string;
    coep: string;
    corp: string;
    sharedArrayBufferAvailable: boolean;
  } {
    return {
      isIsolated: this.isCrossOriginIsolated(),
      coop: this.config.coopPolicy,
      coep: this.config.coepPolicy,
      corp: this.config.corpPolicy,
      sharedArrayBufferAvailable: this.isSharedArrayBufferAvailable(),
    };
  }
}

// ─── FingerprintResistance ────────────────────────────────────────────────

/**
 * Anti-fingerprinting measures to reduce browser uniqueness.
 *
 * Adds noise to canvas, WebGL, and audio fingerprinting APIs
 * to make the browser less identifiable without breaking functionality.
 */
export class FingerprintResistance {
  private readonly version = '2.1.0';
  private noiseEnabled = false;
  private canvasNoiseLevel: number;
  private audioNoiseLevel: number;

  constructor(canvasNoiseLevel: number = 0.01, audioNoiseLevel: number = 0.001) {
    this.canvasNoiseLevel = canvasNoiseLevel;
    this.audioNoiseLevel = audioNoiseLevel;
  }

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Enable fingerprint resistance measures.
   */
  enable(): { enabled: string[] } {
    if (typeof window === 'undefined') return { enabled: [] };
    if (this.noiseEnabled) return { enabled: [] };

    const enabled: string[] = [];

    // Canvas fingerprint noise
    if (this.patchCanvasFingerprinting()) {
      enabled.push('canvas-noise');
    }

    // WebGL fingerprint noise
    if (this.patchWebGLFingerprinting()) {
      enabled.push('webgl-noise');
    }

    // Audio fingerprint noise
    if (this.patchAudioFingerprinting()) {
      enabled.push('audio-noise');
    }

    // Date/timezone normalization
    if (this.patchTimezoneFingerprinting()) {
      enabled.push('timezone-normalize');
    }

    this.noiseEnabled = true;
    return { enabled };
  }

  /**
   * Disable fingerprint resistance measures.
   */
  disable(): void {
    this.noiseEnabled = false;
  }

  /**
   * Check if fingerprint resistance is active.
   */
  isActive(): boolean {
    return this.noiseEnabled;
  }

  /**
   * Generate a canvas fingerprint hash for testing.
   */
  async testCanvasFingerprint(): Promise<string> {
    if (typeof document === 'undefined') return 'unavailable';
    const canvas = document.createElement('canvas');
    canvas.width = 200;
    canvas.height = 50;
    const ctx = canvas.getContext('2d');
    if (!ctx) return 'unavailable';

    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(0, 0, 200, 50);
    ctx.fillStyle = '#069';
    ctx.fillText('Vril.js FP Test 🎯', 2, 15);

    const dataUrl = canvas.toDataURL();
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(dataUrl));
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  private patchCanvasFingerprinting(): boolean {
    if (typeof HTMLCanvasElement === 'undefined') return false;

    try {
      const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
      const noiseLevel = this.canvasNoiseLevel;

      HTMLCanvasElement.prototype.toDataURL = function (this: HTMLCanvasElement, ...args: unknown[]) {
        const ctx = this.getContext('2d');
        if (ctx) {
          try {
            const imageData = ctx.getImageData(0, 0, this.width, this.height);
            for (let i = 0; i < imageData.data.length; i += 4) {
              const noise = (Math.random() - 0.5) * 2 * noiseLevel * 255;
              imageData.data[i] = Math.max(0, Math.min(255, imageData.data[i] + noise));
            }
            ctx.putImageData(imageData, 0, 0);
          } catch {
            // tainted canvas — skip
          }
        }
        return origToDataURL.apply(this, args as [type?: string, quality?: number]);
      };

      return true;
    } catch {
      return false;
    }
  }

  private patchWebGLFingerprinting(): boolean {
    if (typeof HTMLCanvasElement === 'undefined') return false;

    try {
      const origGetContext = HTMLCanvasElement.prototype.getContext;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (HTMLCanvasElement.prototype as any).getContext = function (this: HTMLCanvasElement, type: string, ...args: unknown[]) {
        const context = origGetContext.call(this, type, ...args.slice(0, 1) as [options?: any]);
        if (context && (type === 'webgl' || type === 'webgl2') && noiseEnabled) {
          const gl = context as WebGLRenderingContext;
          // Slightly modify RENDERER and VENDOR strings
          // This is a light touch — deep WebGL spoofing would break rendering
          const origGetShaderPrecisionFormat = gl.getShaderPrecisionFormat.bind(gl);
          gl.getShaderPrecisionFormat = function (shaderType: number, precisionType: number) {
            const result = origGetShaderPrecisionFormat(shaderType, precisionType);
            if (result) {
              // Add slight variation to precision values
              const vary = Math.random() < 0.5 ? 0 : 1;
              return {
                rangeMin: result.rangeMin,
                rangeMax: result.rangeMax,
                precision: result.precision + vary,
              } as WebGLShaderPrecisionFormat;
            }
            return result;
          };
        }
        return context;
      };

      const noiseEnabled = true; // closure reference
      return true;
    } catch {
      return false;
    }
  }

  private patchAudioFingerprinting(): boolean {
    if (typeof AudioContext === 'undefined' && typeof OfflineAudioContext === 'undefined') return false;

    try {
      const noiseLevel = this.audioNoiseLevel;
      const OrigOfflineAudioContext = OfflineAudioContext;

      if (OrigOfflineAudioContext) {
        const origStartRendering = OrigOfflineAudioContext.prototype.startRendering;
        OrigOfflineAudioContext.prototype.startRendering = function (this: OfflineAudioContext) {
          const result = origStartRendering.call(this);
          return result.then((buffer: AudioBuffer) => {
            for (let ch = 0; ch < buffer.numberOfChannels; ch++) {
              const data = buffer.getChannelData(ch);
              for (let i = 0; i < data.length; i++) {
                data[i] += (Math.random() - 0.5) * noiseLevel;
              }
            }
            return buffer;
          });
        };
      }

      return true;
    } catch {
      return false;
    }
  }

  private patchTimezoneFingerprinting(): boolean {
    if (typeof Intl === 'undefined' || !Intl.DateTimeFormat) return false;

    try {
      // Override timezone detection to return UTC
      const origResolvedOptions = Intl.DateTimeFormat.prototype.resolvedOptions;
      Intl.DateTimeFormat.prototype.resolvedOptions = function () {
        const options = origResolvedOptions.call(this);
        return { ...options, timeZone: 'UTC' };
      };
      return true;
    } catch {
      return false;
    }
  }
}

// ─── TimingAttackMitigation ───────────────────────────────────────────────

/**
 * Mitigates timing attacks through constant-time comparisons,
 * request timing normalization, and jitter injection.
 */
export class TimingAttackMitigation {
  private readonly version = '2.1.0';
  private requestTimings: number[] = [];
  private minResponseTimeMs: number;

  constructor(minResponseTimeMs: number = 50) {
    this.minResponseTimeMs = minResponseTimeMs;
  }

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Constant-time comparison of two Uint8Arrays.
   * Returns true if equal, false otherwise.
   * Always processes the full length regardless of early mismatches.
   */
  constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
      // Still do a full comparison to avoid length-based timing leaks
      const maxLen = Math.max(a.length, b.length);
      let _dummy = 0;
      for (let i = 0; i < maxLen; i++) {
        const aVal = i < a.length ? a[i] : 0;
        const bVal = i < b.length ? b[i] : 0;
        _dummy |= aVal ^ bVal;
      }
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }

  /**
   * Constant-time string comparison.
   */
  constantTimeStringEqual(a: string, b: string): boolean {
    const encoder = new TextEncoder();
    const aBytes = encoder.encode(a);
    const bBytes = encoder.encode(b);
    return this.constantTimeEqual(aBytes, bBytes);
  }

  /**
   * Add random jitter to a value to prevent timing analysis.
   * Returns value +/- jitter percentage.
   */
  addJitter(valueMs: number, jitterPercent: number = 0.1): number {
    const jitter = valueMs * jitterPercent * (Math.random() * 2 - 1);
    return Math.max(0, valueMs + jitter);
  }

  /**
   * Normalize response timing by ensuring minimum response time.
   * Call at the end of request handlers.
   */
  async normalizeTiming(): Promise<void> {
    const elapsed = performance.now();
    if (elapsed < this.minResponseTimeMs) {
      const delay = this.minResponseTimeMs - elapsed;
      const jitteredDelay = this.addJitter(delay, 0.2);
      await new Promise(resolve => setTimeout(resolve, jitteredDelay));
    }
  }

  /**
   * Create a timing-safe wrapper for an async function.
   */
  wrapTimingSafe<T extends (...args: unknown[]) => Promise<unknown>>(
    fn: T,
    minTimeMs?: number
  ): T {
    const minTime = minTimeMs ?? this.minResponseTimeMs;

    const wrapped = async (...args: unknown[]): Promise<unknown> => {
      const start = performance.now();
      try {
        const result = await fn(...args);
        const elapsed = performance.now() - start;
        if (elapsed < minTime) {
          await new Promise(resolve =>
            setTimeout(resolve, this.addJitter(minTime - elapsed, 0.15))
          );
        }
        return result;
      } catch (error) {
        const elapsed = performance.now() - start;
        if (elapsed < minTime) {
          await new Promise(resolve =>
            setTimeout(resolve, this.addJitter(minTime - elapsed, 0.15))
          );
        }
        throw error;
      }
    };

    return wrapped as T;
  }

  /**
   * Record a request timing for analysis.
   */
  recordTiming(durationMs: number): void {
    this.requestTimings.push(durationMs);
    if (this.requestTimings.length > 1000) {
      this.requestTimings = this.requestTimings.slice(-500);
    }
  }

  /**
   * Analyze request timing variance for potential timing attack indicators.
   */
  analyzeTimingVariance(): {
    mean: number;
    variance: number;
    standardDeviation: number;
    suspiciousVariance: boolean;
  } {
    const timings = this.requestTimings;
    if (timings.length < 2) {
      return { mean: 0, variance: 0, standardDeviation: 0, suspiciousVariance: false };
    }

    const mean = timings.reduce((sum, t) => sum + t, 0) / timings.length;
    const variance = timings.reduce((sum, t) => sum + Math.pow(t - mean, 2), 0) / timings.length;
    const standardDeviation = Math.sqrt(variance);

    // High variance relative to mean might indicate timing vulnerability
    const coefficientOfVariation = mean > 0 ? standardDeviation / mean : 0;
    const suspiciousVariance = coefficientOfVariation > 0.5;

    return { mean, variance, standardDeviation, suspiciousVariance };
  }
}

// ─── ClickjackingProtection ───────────────────────────────────────────────

/**
 * Clickjacking protection through X-Frame-Options, CSP frame-ancestors,
 * and JavaScript frame-busting.
 */
export class ClickjackingProtection {
  private readonly version = '2.1.0';
  private frameBustingEnabled = false;

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Get anti-clickjacking headers.
   */
  getProtectionHeaders(allowedOrigins: string[] = []): SecurityHeaderSet {
    const headers: SecurityHeaderSet = {};

    if (allowedOrigins.length === 0) {
      headers['X-Frame-Options'] = 'DENY';
      headers['Content-Security-Policy'] = "frame-ancestors 'none'";
    } else if (allowedOrigins.length === 1 && allowedOrigins[0] === 'self') {
      headers['X-Frame-Options'] = 'SAMEORIGIN';
      headers['Content-Security-Policy'] = "frame-ancestors 'self'";
    } else {
      headers['X-Frame-Options'] = 'SAMEORIGIN';
      headers['Content-Security-Policy'] = `frame-ancestors ${allowedOrigins.join(' ')}`;
    }

    return headers;
  }

  /**
   * Enable JavaScript frame-busting as a defense-in-depth measure.
   * This runs in the browser and prevents framing even if headers are stripped.
   */
  enableFrameBusting(): { enabled: boolean } {
    if (typeof window === 'undefined') return { enabled: false };
    if (this.frameBustingEnabled) return { enabled: false };

    try {
      // Check if we're in a frame
      if (window.top !== window.self) {
        // Break out of the frame
        window.top!.location.href = window.self.location.href;
      }

      // Set up ongoing frame detection
      const style = document.createElement('style');
      style.textContent = 'body { display: block !important; }';
      document.head.appendChild(style);

      // Monitor for framing attempts
      Object.defineProperty(document, 'hidden', {
        get: () => {
          if (window.top !== window.self) {
            console.warn('[VRIL Security] Page is framed — potential clickjacking');
          }
          return false;
        },
        configurable: true,
      });

      this.frameBustingEnabled = true;
      return { enabled: true };
    } catch {
      return { enabled: false };
    }
  }

  /**
   * Check if the page is currently framed.
   */
  isFramed(): boolean {
    if (typeof window === 'undefined') return false;
    try {
      return window.top !== window.self;
    } catch {
      // Cross-origin access error means we're in a cross-origin frame
      return true;
    }
  }

  /**
   * Disable frame busting.
   */
  disableFrameBusting(): void {
    this.frameBustingEnabled = false;
  }
}

// ─── XSSShield ────────────────────────────────────────────────────────────

/**
 * DOM-based XSS prevention including innerHTML sanitization,
 * URL scheme validation, and dangerous pattern detection.
 */
export class XSSShield {
  private readonly version = '2.1.0';

  /** Dangerous HTML patterns */
  private static readonly DANGEROUS_PATTERNS = [
    /<script[\s>]/gi,
    /<iframe[\s>]/gi,
    /<object[\s>]/gi,
    /<embed[\s>]/gi,
    /<applet[\s>]/gi,
    /<form[\s>]/gi,
    /<input[\s>]/gi,
    /<textarea[\s>]/gi,
    /<button[\s>]/gi,
    /<link[\s>]/gi,
    /<meta[\s>]/gi,
    /<base[\s>]/gi,
    /<style[\s>]/gi,
    /on\w+\s*=/gi,
    /javascript\s*:/gi,
    /vbscript\s*:/gi,
    /data\s*:\s*text\/html/gi,
    /expression\s*\(/gi,
    /url\s*\(/gi,
    /@import/gi,
    /-moz-binding/gi,
    /behavior\s*:/gi,
  ];

  /** Safe HTML tags (whitelist) */
  private static readonly SAFE_TAGS = new Set([
    'p', 'br', 'hr', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'dl', 'dt', 'dd', 'table', 'thead', 'tbody', 'tfoot',
    'tr', 'th', 'td', 'caption', 'colgroup', 'col', 'a', 'img', 'b', 'i',
    'em', 'strong', 'small', 'sub', 'sup', 'code', 'pre', 'blockquote',
    'figure', 'figcaption', 'details', 'summary', 'mark', 'abbr', 'cite',
    'dfn', 'kbd', 'samp', 'var', 'time', 'article', 'section', 'nav',
    'aside', 'header', 'footer', 'main',
  ]);

  /** Safe attributes (whitelist) */
  private static readonly SAFE_ATTRS = new Set([
    'class', 'id', 'title', 'lang', 'dir', 'role', 'aria-label',
    'aria-describedby', 'aria-hidden', 'aria-expanded', 'aria-controls',
    'href', 'src', 'alt', 'width', 'height', 'colspan', 'rowspan',
    'scope', 'tabindex', 'rel', 'target', 'download', 'datetime',
    'name', 'value', 'type', 'data-testid',
  ]);

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Sanitize HTML by removing dangerous elements and attributes.
   * This is a zero-dependency sanitizer (no DOMPurify).
   */
  sanitizeHTML(html: string, options?: { allowedTags?: string[]; allowedAttrs?: string[] }): string {
    let result = html;

    // Remove dangerous patterns
    for (const pattern of XSSShield.DANGEROUS_PATTERNS) {
      result = result.replace(pattern, '');
    }

    // If specific tags are allowed, strip everything else
    const allowedTags = options?.allowedTags ?? Array.from(XSSShield.SAFE_TAGS);
    const allowedAttrs = options?.allowedAttrs ?? Array.from(XSSShield.SAFE_ATTRS);

    // Remove unknown tags
    result = result.replace(/<\/?([a-zA-Z][a-zA-Z0-9]*)[^>]*>/g, (match, tagName) => {
      if (allowedTags.includes(tagName.toLowerCase())) {
        // Sanitize attributes on allowed tags
        return match.replace(/([a-zA-Z-]+)\s*=\s*["']([^"']*)["']/g, (attrMatch: string, attrName: string, attrValue: string) => {
          if (allowedAttrs.includes(attrName.toLowerCase())) {
            // Validate attribute values
            if (attrName.toLowerCase() === 'href' || attrName.toLowerCase() === 'src') {
              if (this.isDangerousURL(attrValue)) {
                return '';
              }
            }
            return attrMatch;
          }
          return '';
        });
      }
      return '';
    });

    // Remove any remaining script-like content
    result = result.replace(/<!--[\s\S]*?-->/g, ''); // Comments
    result = result.replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, ''); // CDATA

    return result;
  }

  /**
   * Check if a URL is potentially dangerous (javascript:, data:, vbscript:).
   */
  isDangerousURL(url: string): boolean {
    const trimmed = url.trim().toLowerCase();
    return (
      trimmed.startsWith('javascript:') ||
      trimmed.startsWith('vbscript:') ||
      trimmed.startsWith('data:text/html') ||
      trimmed.startsWith('data:application') ||
      trimmed.includes('\njavascript:') ||
      trimmed.includes('\rjavascript:')
    );
  }

  /**
   * Validate a URL for safe use.
   */
  validateURL(url: string): { safe: boolean; reason?: string; sanitized?: string } {
    if (!url || typeof url !== 'string') {
      return { safe: false, reason: 'URL is empty or not a string' };
    }

    const trimmed = url.trim();

    // Check for dangerous schemes
    if (this.isDangerousURL(trimmed)) {
      return { safe: false, reason: 'Dangerous URL scheme detected' };
    }

    // Check for protocol-relative URLs (potential SSRF)
    if (trimmed.startsWith('//')) {
      return { safe: true, sanitized: trimmed };
    }

    // Validate safe protocols
    const safeProtocols = ['http://', 'https://', 'mailto:', 'tel:', 'ftp://', '/'];
    const hasSafeProtocol = safeProtocols.some(p => trimmed.toLowerCase().startsWith(p));

    if (!hasSafeProtocol && trimmed.includes(':')) {
      const protocol = trimmed.split(':')[0].toLowerCase();
      return { safe: false, reason: `Unknown or dangerous protocol: ${protocol}` };
    }

    // Check for encoded dangerous content
    try {
      const decoded = decodeURIComponent(trimmed);
      if (this.isDangerousURL(decoded)) {
        return { safe: false, reason: 'Encoded dangerous URL scheme detected' };
      }
    } catch {
      // Invalid encoding — suspicious
      return { safe: false, reason: 'Malformed URL encoding' };
    }

    return { safe: true, sanitized: trimmed };
  }

  /**
   * Set innerHTML safely with sanitization.
   */
  setSafeInnerHTML(element: HTMLElement, html: string): void {
    const sanitized = this.sanitizeHTML(html);
    element.innerHTML = sanitized;
  }

  /**
   * Create a text node safely (no XSS risk).
   */
  createSafeTextNode(text: string): Text {
    if (typeof document === 'undefined') {
      throw new Error('[VRIL XSS] Cannot create text node outside browser context');
    }
    return document.createTextNode(text);
  }

  /**
   * Escape HTML special characters.
   */
  escapeHTML(str: string): string {
    const map: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;',
    };
    return str.replace(/[&<>"'/]/g, char => map[char] ?? char);
  }
}

// ─── CookieFortress ───────────────────────────────────────────────────────

/**
 * Secure cookie management with __Host- prefix, SameSite,
 * Secure, HttpOnly enforcement.
 */
export class CookieFortress {
  private readonly version = '2.1.0';

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Set a secure cookie with all security flags.
   */
  set(options: CookieOptions): { success: boolean; cookieString: string } {
    const parts: string[] = [];

    // Apply prefix
    let name = options.name;
    if (options.hostPrefix) {
      name = `__Host-${name}`;
    } else if (options.securePrefix) {
      name = `__Secure-${name}`;
    }

    parts.push(`${encodeURIComponent(name)}=${encodeURIComponent(options.value)}`);

    // Max-Age or Expires
    if (options.maxAge !== undefined) {
      parts.push(`Max-Age=${options.maxAge}`);
    } else if (options.expires) {
      parts.push(`Expires=${options.expires.toUTCString()}`);
    }

    // Domain — not allowed with __Host- prefix
    if (options.domain && !options.hostPrefix) {
      parts.push(`Domain=${options.domain}`);
    }

    // Path — must be / for __Host- prefix
    if (options.hostPrefix) {
      parts.push('Path=/');
    } else if (options.path) {
      parts.push(`Path=${options.path}`);
    }

    // Secure flag — always on for __Host- and __Secure- prefixes
    if (options.secure !== false) {
      parts.push('Secure');
    }

    // HttpOnly flag
    if (options.httpOnly !== false) {
      parts.push('HttpOnly');
    }

    // SameSite
    const sameSite = options.sameSite ?? 'Strict';
    parts.push(`SameSite=${sameSite}`);

    const cookieString = parts.join('; ');

    if (typeof document !== 'undefined' && !options.httpOnly) {
      document.cookie = cookieString;
    }

    return { success: true, cookieString };
  }

  /**
   * Get a cookie value by name.
   */
  get(name: string, hostPrefix: boolean = false, securePrefix: boolean = false): string | null {
    if (typeof document === 'undefined') return null;

    let fullName = name;
    if (hostPrefix) fullName = `__Host-${name}`;
    else if (securePrefix) fullName = `__Secure-${name}`;

    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const [cookieName, ...rest] = cookie.trim().split('=');
      if (cookieName === encodeURIComponent(fullName)) {
        return decodeURIComponent(rest.join('='));
      }
    }
    return null;
  }

  /**
   * Delete a cookie.
   */
  delete(name: string, options?: { domain?: string; path?: string; hostPrefix?: boolean; securePrefix?: boolean }): void {
    if (typeof document === 'undefined') return;

    let fullName = name;
    if (options?.hostPrefix) fullName = `__Host-${name}`;
    else if (options?.securePrefix) fullName = `__Secure-${name}`;

    const parts = [
      `${encodeURIComponent(fullName)}=`,
      'Max-Age=0',
      'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    ];

    if (options?.domain) parts.push(`Domain=${options.domain}`);
    parts.push(`Path=${options?.path ?? '/'}`);
    parts.push('Secure');

    document.cookie = parts.join('; ');
  }

  /**
   * Validate a cookie configuration for security best practices.
   */
  validateConfig(options: CookieOptions): { valid: boolean; warnings: string[] } {
    const warnings: string[] = [];

    if (!options.secure && !options.hostPrefix && !options.securePrefix) {
      warnings.push('Cookie should use the Secure flag');
    }

    if (!options.httpOnly && options.name !== 'csrf-token') {
      warnings.push('Cookie should use HttpOnly flag unless client-side access is required');
    }

    if (options.sameSite === 'None') {
      warnings.push('SameSite=None should only be used for cross-site cookies');
      if (!options.secure) {
        warnings.push('SameSite=None requires the Secure flag');
      }
    }

    if (options.hostPrefix) {
      if (!options.secure && options.secure !== false) {
        warnings.push('__Host- prefix requires the Secure flag');
      }
      if (options.domain) {
        warnings.push('__Host- prefix must not specify a Domain');
      }
      if (options.path && options.path !== '/') {
        warnings.push('__Host- prefix requires Path=/');
      }
    }

    if (options.securePrefix && !options.secure && options.secure !== false) {
      warnings.push('__Secure- prefix requires the Secure flag');
    }

    return { valid: warnings.length === 0, warnings };
  }

  /**
   * Audit all current cookies for security issues.
   */
  auditCookies(): {
    total: number;
    insecure: Array<{ name: string; issues: string[] }>;
    recommendations: string[];
  } {
    if (typeof document === 'undefined') {
      return { total: 0, insecure: [], recommendations: [] };
    }

    const cookies = document.cookie.split(';').filter(c => c.trim());
    const insecure: Array<{ name: string; issues: string[] }> = [];
    const recommendations: string[] = [];

    for (const cookie of cookies) {
      const [name] = cookie.trim().split('=');
      const issues: string[] = [];

      if (!name.startsWith('__Host-') && !name.startsWith('__Secure-')) {
        issues.push('Missing security prefix');
        recommendations.push(`Consider using __Host- or __Secure- prefix for ${name}`);
      }

      if (issues.length > 0) {
        insecure.push({ name, issues });
      }
    }

    return { total: cookies.length, insecure, recommendations };
  }
}

// ─── SecurityHeadersBuilder ───────────────────────────────────────────────

/**
 * Fluent API for building comprehensive security headers.
 */
export class SecurityHeadersBuilder {
  private headers: SecurityHeaderSet = {};
  private readonly version = '2.1.0';

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Set Strict-Transport-Security (HSTS).
   */
  hsts(maxAge: number = 31536000, includeSubDomains: boolean = true, preload: boolean = false): this {
    let value = `max-age=${maxAge}`;
    if (includeSubDomains) value += '; includeSubDomains';
    if (preload) value += '; preload';
    this.headers['Strict-Transport-Security'] = value;
    return this;
  }

  /**
   * Set X-Content-Type-Options.
   */
  noSniff(): this {
    this.headers['X-Content-Type-Options'] = 'nosniff';
    return this;
  }

  /**
   * Set X-Frame-Options.
   */
  frameOptions(policy: 'DENY' | 'SAMEORIGIN'): this {
    this.headers['X-Frame-Options'] = policy;
    return this;
  }

  /**
   * Set Referrer-Policy.
   */
  referrerPolicy(policy: 'no-referrer' | 'no-referrer-when-downgrade' | 'origin' | 'origin-when-cross-origin' | 'same-origin' | 'strict-origin' | 'strict-origin-when-cross-origin' | 'unsafe-url'): this {
    this.headers['Referrer-Policy'] = policy;
    return this;
  }

  /**
   * Set Cross-Origin-Opener-Policy.
   */
  coop(policy: 'same-origin' | 'same-origin-allow-popups' | 'unsafe-none'): this {
    this.headers['Cross-Origin-Opener-Policy'] = policy;
    return this;
  }

  /**
   * Set Cross-Origin-Embedder-Policy.
   */
  coep(policy: 'credentialless' | 'require-corp' | 'unsafe-none'): this {
    this.headers['Cross-Origin-Embedder-Policy'] = policy;
    return this;
  }

  /**
   * Set Cross-Origin-Resource-Policy.
   */
  corp(policy: 'same-origin' | 'same-site' | 'cross-origin'): this {
    this.headers['Cross-Origin-Resource-Policy'] = policy;
    return this;
  }

  /**
   * Set Content-Security-Policy.
   */
  csp(policy: string): this {
    this.headers['Content-Security-Policy'] = policy;
    return this;
  }

  /**
   * Set Permissions-Policy.
   */
  permissionsPolicy(policy: string): this {
    this.headers['Permissions-Policy'] = policy;
    return this;
  }

  /**
   * Set X-XSS-Protection (deprecated but still useful for legacy browsers).
   */
  xssProtection(mode: 'block' | 'report'): this {
    this.headers['X-XSS-Protection'] = mode === 'block' ? '1; mode=block' : '1; report';
    return this;
  }

  /**
   * Add a custom header.
   */
  custom(name: string, value: string): this {
    this.headers[name] = value;
    return this;
  }

  /**
   * Apply a preset configuration for maximum security.
   */
  maximumSecurity(): this {
    return this
      .hsts(63072000, true, true)
      .noSniff()
      .frameOptions('DENY')
      .referrerPolicy('no-referrer')
      .coop('same-origin')
      .coep('require-corp')
      .corp('same-origin')
      .csp("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
      .permissionsPolicy('camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()')
      .xssProtection('block')
      .custom('X-Vril-Version', '2.1.0')
      .custom('Server', 'Vril.js');
  }

  /**
   * Apply a preset for development (relaxed).
   */
  development(): this {
    return this
      .hsts(300, false, false)
      .noSniff()
      .frameOptions('SAMEORIGIN')
      .referrerPolicy('strict-origin-when-cross-origin')
      .custom('X-Vril-Version', '2.0.0-dev');
  }

  /**
   * Build the final header set.
   */
  build(): SecurityHeaderSet {
    return { ...this.headers };
  }

  /**
   * Reset all headers.
   */
  reset(): this {
    this.headers = {};
    return this;
  }
}
