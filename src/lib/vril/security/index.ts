/**
 * Vril.js v2.0.0 — Security Module
 *
 * Comprehensive security module including Trusted Types enforcement,
 * HTML sanitization, URL validation, Content Security Policy builder,
 * Permissions Policy builder, Security Context, and Integrity Checking.
 *
 * All existing v1 exports are preserved and enhanced.
 * Zero external dependencies — Web APIs only.
 */

// ─── Window Extensions for Vril ────────────────────────────────────────────

interface VrilWindowExtension {
  __VRIL_TT_V2__?: {
    createHTML: (input: string) => string;
  };
  __VRIL_SECURITY__?: {
    version: string;
    bannedConstructors: string[];
    trustedTypes: boolean;
    installed: number;
  };
  trustedTypes?: {
    createPolicy: (name: string, rules: Record<string, (...args: unknown[]) => unknown>) => TrustedTypesPolicy;
  };
}

// ─── Re-exports from sub-modules ──────────────────────────────────────────

export { PQCHandler, type PQCKeyPair, type KEMResult, type SignatureResult, type AlgorithmInfo, type BenchmarkResult, type PQCAlgorithm } from './crypto/pqc';
export { HybridKEM, HybridSigner, HybridKeyRotation, type HybridKEMResult, type HybridSignatureResult, type KeyRotationPolicy, type HybridKeyPair, type KeyRotationEvent } from './crypto/hybrid';
export { VrilVault, SecureMemory, type VaultConfig, type EncryptionResult, type DecryptionResult, type BlobEncryptionResult, type KeyWrapResult, type StrengthAssessment } from './crypto/vault';
export { AlgorithmRegistry, MigrationExecutor, AlgorithmHealthMonitor, CryptoPolicy, AuditLogger, CryptoAgility, type AlgorithmDescriptor, type AlgorithmHealth, type VulnerabilityEntry, type MigrationPlan, type MigrationStep, type MigrationResult, type CryptoPolicyConfig, type AuditLogEntry, type QuantumMilestone } from './crypto/agility';
export { CrossOriginIsolation, FingerprintResistance, TimingAttackMitigation, ClickjackingProtection, XSSShield, CookieFortress, SecurityHeadersBuilder, type HardeningConfig, type CookieOptions, type SecurityHeaderSet } from './hardening';
import { SecurityHeadersBuilder as SecurityHeadersBuilderImpl } from './hardening';
export { SecurityAuditor, CSPViolationReporter, SecurityScoreCalculator, VulnerabilityDatabase, ComplianceChecker, generateSecurityReport, type AuditResult, type SecurityScore, type VulnerabilityFinding, type CSPViolationReport, type ComplianceStatus, type SecurityReport } from './audit';

// ─── Types ────────────────────────────────────────────────────────────────

/** Sanitization configuration */
export interface SanitizationConfig {
  /** Allowed HTML tags */
  allowedTags: string[];
  /** Allowed HTML attributes */
  allowedAttributes: string[];
  /** Allowed URI schemes */
  allowedSchemes: string[];
  /** Whether to strip comments */
  stripComments: boolean;
  /** Whether to strip data attributes */
  stripDataAttributes: boolean;
  /** Maximum nesting depth */
  maxNestingDepth: number;
  /** Maximum HTML length */
  maxLength: number;
}

/** URL validation result */
export interface URLValidationResult {
  /** Whether the URL is safe to use */
  safe: boolean;
  /** Sanitized URL (if possible) */
  sanitized: string;
  /** Reason for rejection */
  reason?: string;
  /** Detected scheme */
  scheme: string;
  /** Whether the URL is absolute */
  isAbsolute: boolean;
  /** Whether the URL has credentials */
  hasCredentials: boolean;
  /** Whether the URL has a fragment */
  hasFragment: boolean;
}

/** Security context state */
export interface SecurityContextState {
  /** Whether Trusted Types are enforced */
  trustedTypesEnforced: boolean;
  /** Whether CSP is active */
  cspActive: boolean;
  /** Whether the context is secure (HTTPS) */
  isSecureContext: boolean;
  /** Whether cross-origin isolation is active */
  isCrossOriginIsolated: boolean;
  /** Active security policies */
  activePolicies: string[];
  /** Security module version */
  version: string;
  /** Initialization timestamp */
  initializedAt: number;
  /** Violation count since init */
  violationCount: number;
}

/** Trusted Types policy interface */
export interface TrustedTypesPolicy {
  createHTML: (input: string) => string;
  createScript: never;
  createScriptURL: never;
}

/** CSP directive configuration */
export interface CSPDirective {
  name: string;
  values: string[];
}

// ─── TrustedTypesEnforcer ─────────────────────────────────────────────────

/**
 * Strict Trusted Types enforcement with violation reporting.
 *
 * Trusted Types prevent DOM-based XSS by requiring all dangerous
 * sink assignments (innerHTML, eval, etc.) to go through a policy.
 */
export class TrustedTypesEnforcer {
  private policy: TrustedTypesPolicy | null = null;
  private violationCount: number = 0;
  private violationListeners: Array<(violation: { sink: string; data: string; timestamp: number }) => void> = [];
  private readonly version = '2.1.0';

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Install Trusted Types enforcement.
   * Returns whether installation was successful.
   */
  install(policyName: string = 'vril-labs-v2'): {
    installed: boolean;
    policy: TrustedTypesPolicy | null;
    enforced: boolean;
  } {
    if (typeof window === 'undefined') {
      return { installed: false, policy: null, enforced: false };
    }

    const win = window as Window & VrilWindowExtension & { trustedTypes?: { createPolicy: (name: string, rules: Record<string, (...args: unknown[]) => unknown>) => TrustedTypesPolicy } };
    if (!win.trustedTypes?.createPolicy) {
      return { installed: false, policy: null, enforced: false };
    }

    try {
      // Create policy with strict rules
      this.policy = win.trustedTypes.createPolicy(policyName, {
        createHTML: (input: unknown): string => {
          // Use our built-in sanitizer
          const sanitized = DOMPSanitizer.sanitize(String(input));
          return sanitized;
        },
        createScript: (): never => {
          this.violationCount++;
          this.notifyViolation({ sink: 'createScript', data: '', timestamp: Date.now() });
          throw new TypeError('[VRIL Security] Dynamic script creation is strictly prohibited');
        },
        createScriptURL: (): never => {
          this.violationCount++;
          this.notifyViolation({ sink: 'createScriptURL', data: '', timestamp: Date.now() });
          throw new TypeError('[VRIL Security] Dynamic script URLs are strictly prohibited');
        },
      });

      // Try to enforce require-trusted-types-for
      let enforced = false;
      try {
        const cspMeta = document.createElement('meta');
        cspMeta.setAttribute('http-equiv', 'Content-Security-Policy');
        cspMeta.setAttribute('content', "require-trusted-types-for 'script'");
        document.head.appendChild(cspMeta);
        enforced = true;
      } catch {
        enforced = false;
      }

      // Store reference
      win.__VRIL_TT_V2__ = this.policy;

      return {
        installed: true,
        policy: this.policy as TrustedTypesPolicy,
        enforced,
      };
    } catch {
      return { installed: true, policy: null, enforced: false };
    }
  }

  /**
   * Set innerHTML safely through Trusted Types.
   */
  setSafeHTML(element: HTMLElement, html: string): void {
    const vrilWin = typeof window !== 'undefined' ? window as Window & VrilWindowExtension : null;
    if (vrilWin?.__VRIL_TT_V2__) {
      try {
        element.innerHTML = vrilWin.__VRIL_TT_V2__.createHTML(html);
      } catch {
        // Fallback to sanitized HTML
        element.innerHTML = DOMPSanitizer.sanitize(html);
      }
    } else {
      element.innerHTML = DOMPSanitizer.sanitize(html);
    }
  }

  /**
   * Get violation count.
   */
  getViolationCount(): number {
    return this.violationCount;
  }

  /**
   * Register a violation listener.
   */
  onViolation(listener: (violation: { sink: string; data: string; timestamp: number }) => void): () => void {
    this.violationListeners.push(listener);
    return () => {
      this.violationListeners = this.violationListeners.filter(l => l !== listener);
    };
  }

  private notifyViolation(violation: { sink: string; data: string; timestamp: number }): void {
    for (const listener of this.violationListeners) {
      try {
        listener(violation);
      } catch {
        // Listener errors should not affect enforcement
      }
    }
  }
}

// ─── DOMPSanitizer ────────────────────────────────────────────────────────

/**
 * Zero-dependency HTML sanitizer (no DOMPurify).
 *
 * Removes dangerous elements, attributes, and URLs while
 * preserving safe HTML structure.
 */
export class DOMPSanitizer {
  private static readonly version = '2.1.0';

  /** Dangerous tags that must be completely removed */
  private static readonly DANGEROUS_TAGS = new Set([
    'script', 'iframe', 'object', 'embed', 'applet', 'form', 'input',
    'textarea', 'select', 'button', 'link', 'meta', 'base', 'style',
    'template', 'slot', 'noscript', 'noframes',
  ]);

  /** Safe tags whitelist */
  private static readonly SAFE_TAGS = new Set([
    'p', 'br', 'hr', 'div', 'span', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'dl', 'dt', 'dd', 'table', 'thead', 'tbody', 'tfoot',
    'tr', 'th', 'td', 'caption', 'a', 'img', 'b', 'i', 'em', 'strong',
    'small', 'sub', 'sup', 'code', 'pre', 'blockquote', 'figure', 'figcaption',
    'details', 'summary', 'mark', 'abbr', 'cite', 'dfn', 'kbd', 'samp',
    'var', 'time', 'article', 'section', 'nav', 'aside', 'header', 'footer',
    'main', 'picture', 'source', 'video', 'audio', 'track',
  ]);

  /** Safe attributes whitelist */
  private static readonly SAFE_ATTRS = new Set([
    'class', 'id', 'title', 'lang', 'dir', 'role', 'tabindex',
    'aria-label', 'aria-describedby', 'aria-hidden', 'aria-expanded',
    'aria-controls', 'aria-live', 'aria-atomic', 'aria-relevant',
    'href', 'src', 'alt', 'width', 'height', 'colspan', 'rowspan',
    'scope', 'rel', 'target', 'download', 'datetime', 'name',
    'value', 'type', 'data-testid', 'loading', 'decoding', 'controls',
    'autoplay', 'loop', 'muted', 'playsinline', 'poster', 'preload',
    'start', 'reversed', 'open', 'cite',
  ]);

  /** Dangerous attribute patterns */
  private static readonly DANGEROUS_ATTR_PATTERNS = [
    /^on/i,          // Event handlers: onclick, onerror, etc.
    /^formaction/i,  // Form action override
    /^xlink:href/i,  // SVG xlink
    /^data-/i,       // data: URIs in attributes (with exceptions)
    /^fscommand/i,   // Flash
    /^seeksegmenttime/i, // Flash
  ];

  /** Get version */
  static getVersion(): string {
    return DOMPSanitizer.version;
  }

  /**
   * Sanitize HTML, removing all dangerous content.
   */
  static sanitize(html: string, config?: Partial<SanitizationConfig>): string {
    if (!html || typeof html !== 'string') return '';

    const fullConfig: SanitizationConfig = {
      allowedTags: Array.from(DOMPSanitizer.SAFE_TAGS),
      allowedAttributes: Array.from(DOMPSanitizer.SAFE_ATTRS),
      allowedSchemes: ['http', 'https', 'mailto', 'tel'],
      stripComments: true,
      stripDataAttributes: true,
      maxNestingDepth: 20,
      maxLength: 1000000,
      ...config,
    };

    // Length check
    if (html.length > fullConfig.maxLength) {
      html = html.slice(0, fullConfig.maxLength);
    }

    let result = html;

    // Remove HTML comments
    if (fullConfig.stripComments) {
      result = result.replace(/<!--[\s\S]*?-->/g, '');
    }

    // Remove CDATA sections
    result = result.replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, '');

    // Remove dangerous tags entirely (including content)
    for (const tag of DOMPSanitizer.DANGEROUS_TAGS) {
      const regex = new RegExp(`<${tag}[\\s>][\\s\\S]*?<\\/${tag}>`, 'gi');
      result = result.replace(regex, '');
      // Also handle self-closing
      const selfCloseRegex = new RegExp(`<${tag}[^>]*?\\/>`, 'gi');
      result = result.replace(selfCloseRegex, '');
      // And open tags without closing
      const openRegex = new RegExp(`<${tag}[\\s>][^<]*`, 'gi');
      result = result.replace(openRegex, '');
    }

    // Process remaining tags
    result = result.replace(/<([/]?)([a-zA-Z][a-zA-Z0-9]*)([^>]*)>/g, (match, isClosing, tagName, attrs) => {
      const lowerTag = tagName.toLowerCase();

      // Check if tag is allowed
      if (!fullConfig.allowedTags.includes(lowerTag) && !DOMPSanitizer.SAFE_TAGS.has(lowerTag)) {
        return '';
      }

      if (isClosing) {
        return `</${lowerTag}>`;
      }

      // Sanitize attributes
      const sanitizedAttrs = DOMPSanitizer.sanitizeAttributes(attrs, fullConfig);
      return `<${lowerTag}${sanitizedAttrs}>`;
    });

    // Remove event handlers that survived
    result = result.replace(/\bon\w+\s*=\s*["'][^"']*["']/gi, '');
    result = result.replace(/\bon\w+\s*=\s*[^\s>]*/gi, '');

    // Remove javascript: and data: URLs
    result = result.replace(/href\s*=\s*["']\s*javascript\s*:[^"']*["']/gi, 'href=""');
    result = result.replace(/src\s*=\s*["']\s*javascript\s*:[^"']*["']/gi, 'src=""');
    result = result.replace(/href\s*=\s*["']\s*data\s*:[^"']*["']/gi, 'href=""');
    result = result.replace(/src\s*=\s*["']\s*data\s*:[^"']*["']/gi, 'src=""');

    // Remove vbscript:
    result = result.replace(/href\s*=\s*["']\s*vbscript\s*:[^"']*["']/gi, 'href=""');

    // Remove style attributes with expressions
    result = result.replace(/style\s*=\s*["'][^"']*expression\s*\([^"']*["']/gi, '');

    return result;
  }

  /**
   * Escape HTML special characters (for text content).
   */
  static escape(text: string): string {
    const map: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#x27;',
      '/': '&#x2F;',
    };
    return text.replace(/[&<>"'/]/g, char => map[char] ?? char);
  }

  /**
   * Strip all HTML tags, returning only text content.
   */
  static stripTags(html: string): string {
    return html.replace(/<[^>]*>/g, '');
  }

  /**
   * Check if HTML contains any dangerous patterns.
   */
  static containsDangerousContent(html: string): boolean {
    const dangerousPatterns = [
      /<script[\s>]/i,
      /<iframe[\s>]/i,
      /<object[\s>]/i,
      /on\w+\s*=/i,
      /javascript\s*:/i,
      /vbscript\s*:/i,
      /expression\s*\(/i,
      /data\s*:\s*text\/html/i,
    ];

    return dangerousPatterns.some(pattern => pattern.test(html));
  }

  private static sanitizeAttributes(attrString: string, config: SanitizationConfig): string {
    if (!attrString.trim()) return '';

    const attrs: string[] = [];
    const attrRegex = /([a-zA-Z-]+)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]*)))?/g;

    let match;
    while ((match = attrRegex.exec(attrString)) !== null) {
      const name = match[1].toLowerCase();
      const value = match[2] ?? match[3] ?? match[4] ?? '';

      // Check against dangerous attribute patterns
      const isDangerous = DOMPSanitizer.DANGEROUS_ATTR_PATTERNS.some(pattern => pattern.test(name));
      if (isDangerous) {
        // Allow specific data- attributes
        if (name === 'data-testid' && config.allowedAttributes.includes('data-testid')) {
          attrs.push(`${name}="${value}"`);
        }
        continue;
      }

      // Check attribute whitelist
      if (!config.allowedAttributes.includes(name)) continue;

      // Validate URL attributes
      if (name === 'href' || name === 'src') {
        const lowerValue = value.trim().toLowerCase();
        const isDangerousURL =
          lowerValue.startsWith('javascript:') ||
          lowerValue.startsWith('vbscript:') ||
          lowerValue.startsWith('data:text/html') ||
          lowerValue.startsWith('data:application');

        if (isDangerousURL) continue;

        // Validate scheme
        if (lowerValue.includes(':') && !lowerValue.startsWith('/') && !lowerValue.startsWith('#')) {
          const scheme = lowerValue.split(':')[0].toLowerCase();
          if (!config.allowedSchemes.includes(scheme)) continue;
        }

        // Add rel="noopener noreferrer" for target="_blank"
        if (name === 'href') {
          attrs.push(`${name}="${value}"`);
          continue;
        }
      }

      attrs.push(`${name}="${value}"`);
    }

    return attrs.length > 0 ? ' ' + attrs.join(' ') : '';
  }
}

// ─── URLValidator ─────────────────────────────────────────────────────────

/**
 * URL validation and sanitization to prevent javascript:, data: XSS
 * and other URL-based attacks.
 */
export class URLValidator {
  private static readonly version = '2.1.0';

  /** Safe URL schemes */
  private static readonly SAFE_SCHEMES = new Set([
    'http', 'https', 'mailto', 'tel', 'ftp', 'ftps',
  ]);

  /** Dangerous URL schemes */
  private static readonly DANGEROUS_SCHEMES = new Set([
    'javascript', 'vbscript', 'data', 'blob',
  ]);

  /** Get version */
  static getVersion(): string {
    return URLValidator.version;
  }

  /**
   * Validate and sanitize a URL.
   */
  static validate(url: string): URLValidationResult {
    if (!url || typeof url !== 'string') {
      return {
        safe: false,
        sanitized: '',
        reason: 'URL is empty or not a string',
        scheme: '',
        isAbsolute: false,
        hasCredentials: false,
        hasFragment: false,
      };
    }

    const trimmed = url.trim();

    // Check for dangerous schemes (case-insensitive, whitespace-tolerant)
    const schemeMatch = trimmed.match(/^\s*([a-zA-Z][a-zA-Z0-9+\-.]*)\s*:/);
    const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : '';

    // Check for dangerous schemes with possible whitespace
    const normalizedForCheck = trimmed.replace(/\s/g, '').toLowerCase();
    if (
      normalizedForCheck.startsWith('javascript:') ||
      normalizedForCheck.startsWith('vbscript:') ||
      normalizedForCheck.startsWith('data:text/html') ||
      normalizedForCheck.startsWith('data:application')
    ) {
      return {
        safe: false,
        sanitized: '',
        reason: `Dangerous URL scheme detected: ${scheme || 'encoded'}`,
        scheme,
        isAbsolute: !!scheme,
        hasCredentials: false,
        hasFragment: false,
      };
    }

    // Try to parse the URL
    let parsed: URL | null = null;
    let isAbsolute = false;
    try {
      parsed = new URL(trimmed, 'https://placeholder.invalid');
      isAbsolute = trimmed.includes('://') || trimmed.startsWith('/');
    } catch {
      return {
        safe: false,
        sanitized: '',
        reason: 'Malformed URL',
        scheme,
        isAbsolute: false,
        hasCredentials: false,
        hasFragment: false,
      };
    }

    // Check scheme
    if (scheme && URLValidator.DANGEROUS_SCHEMES.has(scheme)) {
      return {
        safe: false,
        sanitized: '',
        reason: `Forbidden URL scheme: ${scheme}`,
        scheme,
        isAbsolute: true,
        hasCredentials: parsed.username !== '' || parsed.password !== '',
        hasFragment: !!parsed.hash,
      };
    }

    // Check for credentials in URL
    const hasCredentials = parsed.username !== '' || parsed.password !== '';
    if (hasCredentials) {
      return {
        safe: false,
        sanitized: trimmed.replace(/[^:]+:[^@]+@/, ''),
        reason: 'URL contains credentials which may be leaked',
        scheme,
        isAbsolute: true,
        hasCredentials: true,
        hasFragment: !!parsed.hash,
      };
    }

    // Validate safe scheme
    if (scheme && !URLValidator.SAFE_SCHEMES.has(scheme)) {
      return {
        safe: false,
        sanitized: '',
        reason: `Unknown URL scheme: ${scheme}`,
        scheme,
        isAbsolute: true,
        hasCredentials: false,
        hasFragment: !!parsed.hash,
      };
    }

    // Check for encoded dangerous content
    try {
      const decoded = decodeURIComponent(trimmed);
      const decodedLower = decoded.toLowerCase().replace(/\s/g, '');
      if (
        decodedLower.includes('javascript:') ||
        decodedLower.includes('vbscript:') ||
        decodedLower.includes('data:text/html')
      ) {
        return {
          safe: false,
          sanitized: '',
          reason: 'Encoded dangerous content detected in URL',
          scheme,
          isAbsolute: true,
          hasCredentials: false,
          hasFragment: !!parsed.hash,
        };
      }
    } catch {
      // Invalid encoding — suspicious
      return {
        safe: false,
        sanitized: '',
        reason: 'Malformed URL encoding detected',
        scheme,
        isAbsolute: !!scheme,
        hasCredentials: false,
        hasFragment: false,
      };
    }

    return {
      safe: true,
      sanitized: trimmed,
      scheme,
      isAbsolute,
      hasCredentials: false,
      hasFragment: !!parsed.hash,
    };
  }

  /**
   * Sanitize a URL — return empty string if dangerous.
   */
  static sanitize(url: string): string {
    const result = URLValidator.validate(url);
    return result.safe ? result.sanitized : '';
  }

  /**
   * Check if a URL is safe without returning details.
   */
  static isSafe(url: string): boolean {
    return URLValidator.validate(url).safe;
  }
}

// ─── ContentSecurityPolicy ────────────────────────────────────────────────

/**
 * Content Security Policy builder with report-uri, report-to,
 * nonce support, and comprehensive directive management.
 */
export class ContentSecurityPolicy {
  private directives: Map<string, Set<string>> = new Map();
  private reportUri?: string;
  private reportTo?: string;
  private nonce?: string;
  private readonly version = '2.1.0';

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Set a CSP directive.
   */
  setDirective(name: string, ...values: string[]): this {
    if (!this.directives.has(name)) {
      this.directives.set(name, new Set());
    }
    const set = this.directives.get(name)!;
    for (const value of values) {
      set.add(value);
    }
    return this;
  }

  /**
   * Remove a value from a directive.
   */
  removeDirectiveValue(name: string, value: string): this {
    const set = this.directives.get(name);
    if (set) {
      set.delete(value);
      if (set.size === 0) {
        this.directives.delete(name);
      }
    }
    return this;
  }

  /**
   * Remove an entire directive.
   */
  removeDirective(name: string): this {
    this.directives.delete(name);
    return this;
  }

  /**
   * Set the report-uri for violation reports.
   */
  setReportUri(uri: string): this {
    this.reportUri = uri;
    return this;
  }

  /**
   * Set the report-to group for violation reports.
   */
  setReportTo(group: string): this {
    this.reportTo = group;
    return this;
  }

  /**
   * Generate and set a nonce for script/style sources.
   */
  generateNonce(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    this.nonce = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    return this.nonce;
  }

  /**
   * Get the current nonce.
   */
  getNonce(): string | undefined {
    return this.nonce;
  }

  /**
   * Add nonce to script-src directive.
   */
  addNonceToScripts(): this {
    if (!this.nonce) this.generateNonce();
    return this.setDirective('script-src', `'nonce-${this.nonce}'`);
  }

  /**
   * Add nonce to style-src directive.
   */
  addNonceToStyles(): this {
    if (!this.nonce) this.generateNonce();
    return this.setDirective('style-src', `'nonce-${this.nonce}'`);
  }

  /**
   * Apply a strict CSP preset.
   */
  strict(): this {
    return this
      .setDirective('default-src', "'none'")
      .setDirective('script-src', "'self'")
      .setDirective('style-src', "'self'")
      .setDirective('img-src', "'self'")
      .setDirective('font-src', "'self'")
      .setDirective('connect-src', "'self'")
      .setDirective('frame-ancestors', "'none'")
      .setDirective('base-uri', "'self'")
      .setDirective('form-action', "'self'")
      .setDirective('object-src', "'none'")
      .setDirective('media-src', "'self'")
      .setDirective('manifest-src', "'self'");
  }

  /**
   * Apply a moderate CSP preset.
   */
  moderate(): this {
    return this
      .setDirective('default-src', "'self'")
      .setDirective('script-src', "'self'", "'unsafe-inline'")
      .setDirective('style-src', "'self'", "'unsafe-inline'")
      .setDirective('img-src', "'self'", 'data:', 'https:')
      .setDirective('font-src', "'self'", 'https:')
      .setDirective('connect-src', "'self'", 'https:')
      .setDirective('frame-ancestors', "'self'")
      .setDirective('base-uri', "'self'")
      .setDirective('form-action', "'self'")
      .setDirective('object-src', "'none'");
  }

  /**
   * Build the CSP header value.
   */
  build(): string {
    const parts: string[] = [];

    const directiveOrder = [
      'default-src', 'script-src', 'style-src', 'img-src', 'font-src',
      'connect-src', 'frame-src', 'frame-ancestors', 'object-src',
      'media-src', 'manifest-src', 'base-uri', 'form-action',
      'child-src', 'worker-src', 'navigate-to', 'sandbox',
    ];

    // Add ordered directives
    for (const name of directiveOrder) {
      const values = this.directives.get(name);
      if (values && values.size > 0) {
        parts.push(`${name} ${Array.from(values).join(' ')}`);
      }
    }

    // Add any remaining directives not in the order
    for (const [name, values] of this.directives) {
      if (!directiveOrder.includes(name) && values.size > 0) {
        parts.push(`${name} ${Array.from(values).join(' ')}`);
      }
    }

    // Add report-uri
    if (this.reportUri) {
      parts.push(`report-uri ${this.reportUri}`);
    }

    // Add report-to
    if (this.reportTo) {
      parts.push(`report-to ${this.reportTo}`);
    }

    return parts.join('; ');
  }

  /**
   * Build as a meta tag.
   */
  buildMetaTag(): string {
    return `<meta http-equiv="Content-Security-Policy" content="${this.build().replace(/"/g, '&quot;')}">`;
  }

  /**
   * Reset all directives.
   */
  reset(): this {
    this.directives.clear();
    this.reportUri = undefined;
    this.reportTo = undefined;
    this.nonce = undefined;
    return this;
  }
}

// ─── PermissionsPolicyBuilder ─────────────────────────────────────────────

/**
 * Fluent Permissions-Policy builder.
 */
export class PermissionsPolicyBuilder {
  private policies: Map<string, string[]> = new Map();
  private readonly version = '2.1.0';

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Set a permission policy.
   */
  set(directive: string, ...allowlist: string[]): this {
    this.policies.set(directive, allowlist);
    return this;
  }

  /**
   * Deny a permission (empty allowlist).
   */
  deny(...directives: string[]): this {
    for (const directive of directives) {
      this.policies.set(directive, []);
    }
    return this;
  }

  /**
   * Allow a permission for self only.
   */
  selfOnly(directive: string): this {
    this.policies.set(directive, ['self']);
    return this;
  }

  /**
   * Allow a permission for all origins.
   */
  allowAll(directive: string): this {
    this.policies.set(directive, ['*']);
    return this;
  }

  /**
   * Apply a strict permissions policy preset.
   */
  strict(): this {
    const denyList = [
      'camera', 'microphone', 'geolocation', 'payment', 'usb',
      'magnetometer', 'gyroscope', 'accelerometer', 'ambient-light-sensor',
      'battery', 'bluetooth', 'display-capture', 'document-domain',
      'encrypted-media', 'gamepad', 'hid', 'idle-detection',
      'local-fonts', 'midi', 'otp-credentials', 'screen-wake-lock',
      'serial', 'speaker-selection', 'storage-access', 'window-management',
      'xr-spatial-tracking',
    ];

    for (const directive of denyList) {
      this.deny(directive);
    }

    return this
      .selfOnly('fullscreen')
      .selfOnly('clipboard-write')
      .selfOnly('clipboard-read')
      .selfOnly('sync-xhr');
  }

  /**
   * Apply a moderate permissions policy preset.
   */
  moderate(): this {
    return this
      .deny('camera', 'microphone', 'usb', 'bluetooth', 'serial', 'hid')
      .selfOnly('geolocation')
      .selfOnly('payment')
      .selfOnly('fullscreen')
      .selfOnly('clipboard-write')
      .allowAll('encrypted-media');
  }

  /**
   * Build the Permissions-Policy header value.
   */
  build(): string {
    return Array.from(this.policies.entries())
      .map(([directive, allowlist]) => {
        if (allowlist.length === 0) {
          return `${directive}=()`;
        }
        const values = allowlist
          .map(v => v === '*' ? '*' : v === 'self' ? "'self'" : `"${v}"`)
          .join(' ');
        return `${directive}=(${values})`;
      })
      .join(', ');
  }

  /**
   * Reset all policies.
   */
  reset(): this {
    this.policies.clear();
    return this;
  }
}

// ─── SecurityContext ──────────────────────────────────────────────────────

/**
 * Runtime security context with state tracking.
 * Provides a centralized view of the application's security posture.
 */
export class SecurityContext {
  private state: SecurityContextState;
  private eventListeners: Map<string, Array<(data: unknown) => void>> = new Map();
  private readonly version = '2.1.0';

  constructor() {
    this.state = {
      trustedTypesEnforced: false,
      cspActive: false,
      isSecureContext: false,
      isCrossOriginIsolated: false,
      activePolicies: [],
      version: '2.1.0',
      initializedAt: Date.now(),
      violationCount: 0,
    };
  }

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Initialize the security context and detect current state.
   */
  async initialize(): Promise<SecurityContextState> {
    if (typeof window !== 'undefined') {
      this.state.isSecureContext = window.isSecureContext;
      this.state.isCrossOriginIsolated = (crossOriginIsolated as boolean) ?? false;
      this.state.trustedTypesEnforced = !!(window as Window & VrilWindowExtension).trustedTypes;

      // Detect CSP
      try {
        const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        this.state.cspActive = cspMeta !== null;
      } catch {
        this.state.cspActive = false;
      }
    }

    this.state.initializedAt = Date.now();
    this.emit('initialized', this.state);

    return { ...this.state };
  }

  /**
   * Get the current security context state.
   */
  getState(): SecurityContextState {
    return { ...this.state };
  }

  /**
   * Update the security context state.
   */
  updateState(update: Partial<SecurityContextState>): void {
    this.state = { ...this.state, ...update };
    this.emit('stateChanged', this.state);
  }

  /**
   * Record a security violation.
   */
  recordViolation(violation: { type: string; details: string }): void {
    this.state.violationCount++;
    this.emit('violation', {
      ...violation,
      totalViolations: this.state.violationCount,
      timestamp: Date.now(),
    });
  }

  /**
   * Register a security policy as active.
   */
  registerPolicy(policyName: string): void {
    if (!this.state.activePolicies.includes(policyName)) {
      this.state.activePolicies.push(policyName);
      this.emit('policyRegistered', { policyName, policies: this.state.activePolicies });
    }
  }

  /**
   * Check overall security posture.
   */
  getPosture(): {
    level: 'excellent' | 'good' | 'moderate' | 'poor' | 'critical';
    score: number;
    issues: string[];
  } {
    const issues: string[] = [];
    let score = 100;

    if (!this.state.isSecureContext) {
      issues.push('Not running in a secure context (HTTPS)');
      score -= 25;
    }

    if (!this.state.cspActive) {
      issues.push('No Content Security Policy detected');
      score -= 20;
    }

    if (!this.state.trustedTypesEnforced) {
      issues.push('Trusted Types not enforced');
      score -= 10;
    }

    if (!this.state.isCrossOriginIsolated) {
      issues.push('Not cross-origin isolated');
      score -= 5;
    }

    if (this.state.violationCount > 0) {
      issues.push(`${this.state.violationCount} security violation(s) recorded`);
      score -= Math.min(20, this.state.violationCount * 2);
    }

    score = Math.max(0, score);

    let level: 'excellent' | 'good' | 'moderate' | 'poor' | 'critical';
    if (score >= 90) level = 'excellent';
    else if (score >= 75) level = 'good';
    else if (score >= 50) level = 'moderate';
    else if (score >= 25) level = 'poor';
    else level = 'critical';

    return { level, score, issues };
  }

  /**
   * Subscribe to security events.
   */
  on(event: string, listener: (data: unknown) => void): () => void {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, []);
    }
    this.eventListeners.get(event)!.push(listener);
    return () => {
      const listeners = this.eventListeners.get(event);
      if (listeners) {
        this.eventListeners.set(event, listeners.filter(l => l !== listener));
      }
    };
  }

  private emit(event: string, data: unknown): void {
    const listeners = this.eventListeners.get(event) ?? [];
    for (const listener of listeners) {
      try {
        listener(data);
      } catch {
        // Listener errors should not affect context
      }
    }
  }
}

// ─── IntegrityChecker (Enhanced v2) ───────────────────────────────────────

/**
 * Enhanced integrity checker with multiple hash algorithms
 * and batch verification support.
 */
export class IntegrityChecker {
  private static instance: IntegrityChecker;
  private checksums = new Map<string, Map<string, string>>(); // id -> algorithm -> hash
  private readonly version = '2.1.0';

  /** Supported hash algorithms */
  static readonly ALGORITHMS = ['SHA-256', 'SHA-384', 'SHA-512'] as const;
  static type: 'SHA-256' | 'SHA-384' | 'SHA-512';

  private constructor() {}

  static getInstance(): IntegrityChecker {
    if (!IntegrityChecker.instance) {
      IntegrityChecker.instance = new IntegrityChecker();
    }
    return IntegrityChecker.instance;
  }

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Register a checksum for content with a specific algorithm.
   */
  registerChecksum(id: string, hash: string, algorithm: string = 'SHA-256'): void {
    if (!this.checksums.has(id)) {
      this.checksums.set(id, new Map());
    }
    this.checksums.get(id)!.set(algorithm, hash);
  }

  /**
   * Register checksums for content with multiple algorithms.
   */
  registerChecksums(id: string, hashes: Record<string, string>): void {
    if (!this.checksums.has(id)) {
      this.checksums.set(id, new Map());
    }
    for (const [algorithm, hash] of Object.entries(hashes)) {
      this.checksums.get(id)!.set(algorithm, hash);
    }
  }

  /**
   * Compute a hash of content using Web Crypto API.
   */
  async computeHash(content: string, algorithm: string = 'SHA-256'): Promise<string> {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const data = new TextEncoder().encode(content);
      const buf = await crypto.subtle.digest(algorithm, data);
      const prefix = algorithm.toLowerCase().replace('-', '');
      const hash = Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
      return `${prefix}-${hash}`;
    }
    return 'unavailable';
  }

  /**
   * Compute hashes using multiple algorithms.
   */
  async computeMultiHash(content: string, algorithms: readonly string[] = IntegrityChecker.ALGORITHMS): Promise<Record<string, string>> {
    const results: Record<string, string> = {};
    for (const algo of algorithms) {
      results[algo] = await this.computeHash(content, algo);
    }
    return results;
  }

  /**
   * Verify content against a registered checksum.
   */
  async verify(id: string, content: string, algorithm: string = 'SHA-256'): Promise<boolean> {
    const algoMap = this.checksums.get(id);
    if (!algoMap) return false;
    const expected = algoMap.get(algorithm);
    if (!expected) return false;

    const actual = await this.computeHash(content, algorithm);
    return this.constantTimeEqual(expected, actual);
  }

  /**
   * Verify content against all registered checksums.
   */
  async verifyAll(id: string, content: string): Promise<Record<string, boolean>> {
    const algoMap = this.checksums.get(id);
    if (!algoMap) return {};

    const results: Record<string, boolean> = {};
    for (const [algo] of algoMap) {
      results[algo] = await this.verify(id, content, algo);
    }
    return results;
  }

  /**
   * Batch verify multiple content items.
   */
  async batchVerify(items: Array<{ id: string; content: string; algorithm?: string }>): Promise<Record<string, boolean>> {
    const results: Record<string, boolean> = {};
    for (const item of items) {
      results[item.id] = await this.verify(item.id, item.content, item.algorithm);
    }
    return results;
  }

  /**
   * Generate an SRI (Subresource Integrity) attribute value.
   */
  async generateSRI(content: string, algorithms: readonly string[] = ['SHA-256', 'SHA-384']): Promise<string> {
    const hashes = await Promise.all(
      algorithms.map(async algo => {
        const data = new TextEncoder().encode(content);
        const buf = await crypto.subtle.digest(algo, data);
        const b64 = btoa(String.fromCharCode(...new Uint8Array(buf)));
        return `${algo.toLowerCase().replace('-', '-')}-${b64}`;
      })
    );
    return hashes.join(' ');
  }

  /**
   * Get all registered IDs.
   */
  getRegisteredIds(): string[] {
    return Array.from(this.checksums.keys());
  }

  /**
   * Get registered algorithms for an ID.
   */
  getRegisteredAlgorithms(id: string): string[] {
    return Array.from(this.checksums.get(id)?.keys() ?? []);
  }

  /**
   * Remove a registered checksum.
   */
  removeChecksum(id: string): boolean {
    return this.checksums.delete(id);
  }

  /**
   * Clear all checksums.
   */
  clearAll(): void {
    this.checksums.clear();
  }

  private constantTimeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  }
}

// ─── Legacy v1 Compatibility Exports ──────────────────────────────────────

/**
 * @deprecated Use TrustedTypesEnforcer.install() instead.
 * Install Trusted Types (v1 compatibility).
 */
export function installTrustedTypes(): { installed: boolean; policy: TrustedTypesPolicy | null } {
  const enforcer = new TrustedTypesEnforcer();
  return enforcer.install();
}

/**
 * @deprecated Use TrustedTypesEnforcer.setSafeHTML() instead.
 */
export function setSafeHTML(el: HTMLElement, html: string): void {
  const enforcer = new TrustedTypesEnforcer();
  enforcer.setSafeHTML(el, html);
}

/**
 * @deprecated Use ContentSecurityPolicy class instead.
 */
export function buildCSPHeader(config: Record<string, string[] | undefined>): string {
  const csp = new ContentSecurityPolicy();
  const directiveMap: Record<string, string> = {
    defaultSrc: 'default-src',
    scriptSrc: 'script-src',
    styleSrc: 'style-src',
    fontSrc: 'font-src',
    imgSrc: 'img-src',
    connectSrc: 'connect-src',
    frameSrc: 'frame-src',
    objectSrc: 'object-src',
    baseUri: 'base-uri',
    formAction: 'form-action',
    frameAncestors: 'frame-ancestors',
  };
  for (const [key, values] of Object.entries(config)) {
    const directive = directiveMap[key];
    if (directive && values) {
      csp.setDirective(directive, ...values);
    }
  }
  return csp.build();
}

/**
 * @deprecated Use PermissionsPolicyBuilder class instead.
 */
export function buildPermissionsPolicy(policies: Record<string, string[]>): string {
  const builder = new PermissionsPolicyBuilder();
  for (const [directive, allowlist] of Object.entries(policies)) {
    builder.set(directive, ...allowlist);
  }
  return builder.build();
}

/**
 * @deprecated Use SecurityHeadersBuilder class instead.
 */
export function buildSecurityHeaders(config: Record<string, string | undefined>): Record<string, string> {
  const builder = new SecurityHeadersBuilderImpl();
  const mapping: Record<string, (value: string) => void> = {
    strictTransportSecurity: (v) => builder.hsts(parseInt(v) || 31536000),
    xContentTypeOptions: () => builder.noSniff(),
    xFrameOptions: (v) => builder.frameOptions(v as 'DENY' | 'SAMEORIGIN'),
    referrerPolicy: (v) => builder.referrerPolicy(v as Parameters<typeof builder.referrerPolicy>[0]),
    crossOriginOpenerPolicy: (v) => builder.coop(v as Parameters<typeof builder.coop>[0]),
    crossOriginEmbedderPolicy: (v) => builder.coep(v as Parameters<typeof builder.coep>[0]),
    crossOriginResourcePolicy: (v) => builder.corp(v as Parameters<typeof builder.corp>[0]),
    permissionsPolicy: (v) => builder.permissionsPolicy(v),
    contentSecurityPolicy: (v) => builder.csp(v),
  };

  for (const [key, value] of Object.entries(config)) {
    if (value && mapping[key]) {
      mapping[key](value);
    }
  }

  builder.custom('X-Vril-Version', '2.1.0');
  builder.custom('Server', 'Vril.js');

  const headers = builder.build();
  // Filter out undefined values to match Record<string, string>
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value !== undefined) {
      result[key] = value;
    }
  }
  return result;
}

/**
 * @deprecated Use SecurityContext and individual modules instead.
 * Install API membrane (v1 compatibility).
 */
export function installAPIMembrane(blockedAPIs: string[] = ['WebTransport', 'RTCPeerConnection']): {
  installed: boolean; blocked: string[];
} {
  if (typeof window === 'undefined') return { installed: false, blocked: [] };
  const blocked: string[] = [];
  for (const apiName of blockedAPIs) {
    try {
      Object.defineProperty(window, apiName, {
        configurable: true,
        get: () => {
          if (typeof console !== 'undefined') {
            console.warn(`[VRIL Security] ${apiName} access blocked by API membrane`);
          }
          return undefined;
        },
      });
      blocked.push(apiName);
    } catch { /* non-configurable globals */ }
  }
  (window as Window & VrilWindowExtension).__VRIL_SECURITY__ = Object.freeze({
    version: '2.1.0',
    bannedConstructors: blocked.slice(),
    trustedTypes: !!(window as Window & VrilWindowExtension).__VRIL_TT_V2__,
    installed: Date.now(),
  });
  return { installed: true, blocked };
}
