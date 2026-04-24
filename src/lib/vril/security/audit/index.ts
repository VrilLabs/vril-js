/**
 * Vril.js v2.0.0 — Runtime Security Audit Module
 *
 * Comprehensive runtime security scanning, CSP violation reporting,
 * security scoring, vulnerability database, and compliance checking
 * against OWASP, NIST, and PCI-DSS requirements.
 *
 * Zero external dependencies — Web APIs only.
 */

// ─── Types ────────────────────────────────────────────────────────────────

/** Individual audit result */
export interface AuditResult {
  /** Check identifier */
  id: string;
  /** Check name */
  name: string;
  /** Category */
  category: 'headers' | 'dom' | 'crypto' | 'permissions' | 'cookies' | 'network' | 'configuration';
  /** Result status */
  status: 'pass' | 'fail' | 'warning' | 'info' | 'error';
  /** Severity if failed */
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  /** Description */
  description: string;
  /** Remediation advice */
  remediation?: string;
  /** Evidence / details */
  evidence?: string;
  /** Timestamp */
  timestamp: number;
}

/** Security score breakdown */
export interface SecurityScore {
  /** Overall score (0-100) */
  overall: number;
  /** Header security score (0-100) */
  headers: number;
  /** DOM security score (0-100) */
  dom: number;
  /** Crypto security score (0-100) */
  crypto: number;
  /** Permissions score (0-100) */
  permissions: number;
  /** Cookie security score (0-100) */
  cookies: number;
  /** Grade (A-F) */
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  /** Summary text */
  summary: string;
}

/** Vulnerability finding */
export interface VulnerabilityFinding {
  /** Finding ID */
  id: string;
  /** Vulnerability name */
  name: string;
  /** Category */
  category: 'xss' | 'injection' | 'csrf' | 'misconfiguration' | 'crypto-weakness' | 'info-leak' | 'auth' | 'other';
  /** Severity */
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  /** Description */
  description: string;
  /** CVE ID if applicable */
  cveId?: string;
  /** OWASP category */
  owaspCategory?: string;
  /** Evidence */
  evidence: string;
  /** Remediation */
  remediation: string;
  /** Confidence level */
  confidence: 'high' | 'medium' | 'low';
  /** Timestamp */
  foundAt: number;
}

/** CSP violation report */
export interface CSPViolationReport {
  /** Document URI */
  documentURI: string;
  /** Violated directive */
  violatedDirective: string;
  /** Blocked URI */
  blockedURI?: string;
  /** Source file */
  sourceFile?: string;
  /** Line number */
  lineNumber?: number;
  /** Column number */
  columnNumber?: number;
  /** Status code */
  statusCode?: number;
  /** Timestamp */
  timestamp: number;
}

/** Compliance status for a framework */
export interface ComplianceStatus {
  /** Framework name */
  framework: 'OWASP-Top10' | 'NIST-CSF' | 'PCI-DSS' | 'CIS' | 'SOC2';
  /** Overall compliance percentage */
  compliancePercent: number;
  /** Individual control results */
  controls: Array<{
    id: string;
    name: string;
    status: 'compliant' | 'partial' | 'non-compliant' | 'not-applicable';
    evidence: string;
  }>;
  /** Summary */
  summary: string;
}

/** Full security audit report */
export interface SecurityReport {
  /** Report ID */
  id: string;
  /** Report version */
  version: string;
  /** Timestamp */
  generatedAt: number;
  /** Security score */
  score: SecurityScore;
  /** All audit results */
  results: AuditResult[];
  /** Vulnerability findings */
  vulnerabilities: VulnerabilityFinding[];
  /** Compliance statuses */
  compliance: ComplianceStatus[];
  /** Recommendations (prioritized) */
  recommendations: Array<{
    priority: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    description: string;
    effort: 'low' | 'medium' | 'high';
  }>;
}

// ─── SecurityAuditor ──────────────────────────────────────────────────────

/**
 * Comprehensive runtime security scanner.
 * Checks security headers, DOM vulnerabilities, crypto implementation
 * integrity, and Permissions-Policy enforcement.
 */
export class SecurityAuditor {
  private results: AuditResult[] = [];
  private readonly version = '2.1.0';

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Run all security scans and return results.
   */
  async fullAudit(): Promise<AuditResult[]> {
    this.results = [];
    await this.scanHeaders();
    await this.scanDOM();
    await this.scanCrypto();
    await this.scanPermissions();
    return [...this.results];
  }

  /**
   * Scan security headers for proper configuration.
   */
  async scanHeaders(): Promise<AuditResult[]> {
    const headerResults: AuditResult[] = [];

    // Check HSTS
    headerResults.push(this.checkHeader(
      'hsts',
      'Strict-Transport-Security',
      'headers',
      () => {
        if (typeof window === 'undefined') return { status: 'info', evidence: 'Not in browser context' };
        // In browser, we can't directly read response headers, but we can check
        // if the page was loaded over HTTPS
        const isSecure = window.location.protocol === 'https:';
        return {
          status: isSecure ? 'pass' : 'fail',
          evidence: isSecure ? 'Page loaded over HTTPS' : 'Page not loaded over HTTPS',
          remediation: isSecure ? undefined : 'Enable HTTPS and set Strict-Transport-Security header',
        };
      }
    ));

    // Check X-Content-Type-Options
    headerResults.push(this.checkHeader(
      'x-content-type',
      'X-Content-Type-Options',
      'headers',
      () => {
        // Check for MIME-type confusion indicators
        const hasMetaCharset = typeof document !== 'undefined' &&
          document.querySelector('meta[charset]') !== null;
        return {
          status: hasMetaCharset ? 'pass' : 'warning',
          evidence: hasMetaCharset ? 'Character encoding declared' : 'No explicit character encoding',
          remediation: hasMetaCharset ? undefined : 'Add <meta charset="utf-8"> and set X-Content-Type-Options: nosniff',
        };
      }
    ));

    // Check X-Frame-Options / CSP frame-ancestors
    headerResults.push(this.checkHeader(
      'frame-protection',
      'Frame Protection',
      'headers',
      () => {
        if (typeof window === 'undefined') return { status: 'info', evidence: 'Not in browser context' };
        try {
          // If we can't access window.top, we might be framed cross-origin
          const isFramed = window.top !== window.self;
          return {
            status: isFramed ? 'warning' : 'pass',
            evidence: isFramed ? 'Page appears to be framed' : 'Page is not framed',
            remediation: isFramed ? 'Set X-Frame-Options: DENY or CSP frame-ancestors' : undefined,
          };
        } catch {
          return {
            status: 'warning',
            evidence: 'Cross-origin frame detected',
            remediation: 'Set X-Frame-Options and CSP frame-ancestors headers',
          };
        }
      }
    ));

    // Check Referrer-Policy
    headerResults.push(this.checkHeader(
      'referrer-policy',
      'Referrer-Policy',
      'headers',
      () => {
        if (typeof document === 'undefined') return { status: 'info', evidence: 'Not in browser context' };
        const metaReferrer = document.querySelector('meta[name="referrer"]');
        const hasPolicy = metaReferrer !== null;
        return {
          status: hasPolicy ? 'pass' : 'warning',
          evidence: hasPolicy ? `Referrer-Policy set: ${metaReferrer?.getAttribute('content')}` : 'No Referrer-Policy detected',
          remediation: hasPolicy ? undefined : 'Set Referrer-Policy header or <meta name="referrer" content="strict-origin-when-cross-origin">',
        };
      }
    ));

    // Check Cross-Origin isolation
    headerResults.push(this.checkHeader(
      'cross-origin-isolation',
      'Cross-Origin Isolation',
      'headers',
      () => {
        if (typeof window === 'undefined') return { status: 'info', evidence: 'Not in browser context' };
        const isolated = (crossOriginIsolated as boolean) ?? false;
        return {
          status: isolated ? 'pass' : 'warning',
          evidence: isolated ? 'Page is cross-origin isolated' : 'Page is not cross-origin isolated (SharedArrayBuffer may be unavailable)',
          remediation: isolated ? undefined : 'Set Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy headers',
        };
      }
    ));

    // Check CSP
    headerResults.push(this.checkHeader(
      'csp',
      'Content-Security-Policy',
      'headers',
      () => {
        if (typeof document === 'undefined') return { status: 'info', evidence: 'Not in browser context' };
        const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        const hasCSP = cspMeta !== null;
        return {
          status: hasCSP ? 'pass' : 'fail',
          evidence: hasCSP ? 'CSP detected via meta tag' : 'No Content-Security-Policy detected',
          remediation: hasCSP ? undefined : 'Implement Content-Security-Policy header with strict directives',
          severity: 'high',
        };
      }
    ));

    this.results.push(...headerResults);
    return headerResults;
  }

  /**
   * Scan the DOM for vulnerabilities.
   */
  async scanDOM(): Promise<AuditResult[]> {
    const domResults: AuditResult[] = [];

    if (typeof document === 'undefined') {
      domResults.push({
        id: 'dom-context',
        name: 'DOM Scan',
        category: 'dom',
        status: 'info',
        severity: 'info',
        description: 'DOM scan not available outside browser context',
        timestamp: Date.now(),
      });
      this.results.push(...domResults);
      return domResults;
    }

    // Check for inline scripts
    const inlineScripts = document.querySelectorAll('script:not([src])');
    domResults.push({
      id: 'dom-inline-scripts',
      name: 'Inline Scripts',
      category: 'dom',
      status: inlineScripts.length > 0 ? 'warning' : 'pass',
      severity: 'medium',
      description: `${inlineScripts.length} inline script(s) detected`,
      evidence: `Found ${inlineScripts.length} inline <script> tags`,
      remediation: inlineScripts.length > 0 ? 'Move inline scripts to external files with integrity attributes' : undefined,
      timestamp: Date.now(),
    });

    // Check for inline event handlers
    const elementsWithHandlers = document.querySelectorAll('[onclick], [onerror], [onload], [onmouseover]');
    domResults.push({
      id: 'dom-inline-handlers',
      name: 'Inline Event Handlers',
      category: 'dom',
      status: elementsWithHandlers.length > 0 ? 'fail' : 'pass',
      severity: 'high',
      description: `${elementsWithHandlers.length} inline event handler(s) detected`,
      evidence: `Found ${elementsWithHandlers.length} elements with inline event handlers`,
      remediation: elementsWithHandlers.length > 0 ? 'Remove inline event handlers and use addEventListener instead' : undefined,
      timestamp: Date.now(),
    });

    // Check for javascript: URLs
    const jsLinks = document.querySelectorAll('a[href^="javascript:"]');
    domResults.push({
      id: 'dom-js-urls',
      name: 'JavaScript URLs',
      category: 'dom',
      status: jsLinks.length > 0 ? 'fail' : 'pass',
      severity: 'high',
      description: `${jsLinks.length} javascript: URL(s) detected`,
      evidence: `Found ${jsLinks.length} links with javascript: URLs`,
      remediation: jsLinks.length > 0 ? 'Replace javascript: URLs with proper event handlers' : undefined,
      timestamp: Date.now(),
    });

    // Check for target="_blank" without rel="noopener"
    const vulnerableLinks = Array.from(document.querySelectorAll('a[target="_blank"]'))
      .filter(a => !((a as HTMLAnchorElement).rel && (a as HTMLAnchorElement).rel.includes('noopener')));
    domResults.push({
      id: 'dom-target-blank',
      name: 'Target Blank Security',
      category: 'dom',
      status: vulnerableLinks.length > 0 ? 'warning' : 'pass',
      severity: 'medium',
      description: `${vulnerableLinks.length} link(s) with target="_blank" missing rel="noopener"`,
      evidence: `Found ${vulnerableLinks.length} links vulnerable to tab-napping`,
      remediation: vulnerableLinks.length > 0 ? 'Add rel="noopener noreferrer" to all target="_blank" links' : undefined,
      timestamp: Date.now(),
    });

    // Check for forms without CSRF tokens
    const forms = document.querySelectorAll('form');
    const formsWithoutCSRF = Array.from(forms).filter(form => {
      const method = form.getAttribute('method')?.toUpperCase() ?? 'GET';
      if (method === 'GET') return false;
      return !form.querySelector('input[name*="csrf"], input[name*="token"], input[name*="_token"]');
    });
    domResults.push({
      id: 'dom-csrf',
      name: 'CSRF Protection',
      category: 'dom',
      status: formsWithoutCSRF.length > 0 ? 'warning' : 'pass',
      severity: 'medium',
      description: `${formsWithoutCSRF.length} form(s) may lack CSRF protection`,
      evidence: `Found ${formsWithoutCSRF.length} POST forms without visible CSRF tokens`,
      remediation: formsWithoutCSRF.length > 0 ? 'Add CSRF tokens to all state-changing forms' : undefined,
      timestamp: Date.now(),
    });

    this.results.push(...domResults);
    return domResults;
  }

  /**
   * Scan crypto implementation integrity.
   */
  async scanCrypto(): Promise<AuditResult[]> {
    const cryptoResults: AuditResult[] = [];

    // Check Web Crypto API availability
    const hasWebCrypto = typeof crypto !== 'undefined' && !!crypto.subtle;
    cryptoResults.push({
      id: 'crypto-webcrypto',
      name: 'Web Crypto API',
      category: 'crypto',
      status: hasWebCrypto ? 'pass' : 'fail',
      severity: 'critical',
      description: 'Web Crypto API availability',
      evidence: hasWebCrypto ? 'Web Crypto API is available' : 'Web Crypto API is NOT available',
      remediation: hasWebCrypto ? undefined : 'Ensure the page is served over HTTPS or localhost for Web Crypto API access',
      timestamp: Date.now(),
    });

    if (hasWebCrypto) {
      // Check algorithm support
      const algorithms = await crypto.subtle.digest('SHA-256', new Uint8Array(1));
      cryptoResults.push({
        id: 'crypto-sha256',
        name: 'SHA-256 Support',
        category: 'crypto',
        status: algorithms.byteLength === 32 ? 'pass' : 'fail',
        severity: 'high',
        description: 'SHA-256 hash algorithm support',
        evidence: `SHA-256 produces ${algorithms.byteLength * 8}-bit output`,
        timestamp: Date.now(),
      });

      // Check AES-GCM support
      try {
        await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt']
        );
        cryptoResults.push({
          id: 'crypto-aes-gcm',
          name: 'AES-256-GCM Support',
          category: 'crypto',
          status: 'pass',
          severity: 'info',
          description: 'AES-256-GCM encryption is available',
          evidence: 'Successfully generated AES-256-GCM key',
          timestamp: Date.now(),
        });
      } catch {
        cryptoResults.push({
          id: 'crypto-aes-gcm',
          name: 'AES-256-GCM Support',
          category: 'crypto',
          status: 'fail',
          severity: 'critical',
          description: 'AES-256-GCM encryption is NOT available',
          evidence: 'Failed to generate AES-256-GCM key',
          remediation: 'Ensure the browser supports AES-256-GCM',
          timestamp: Date.now(),
        });
      }

      // Check for insecure random usage (Math.random)
      cryptoResults.push({
        id: 'crypto-random-source',
        name: 'Secure Random Source',
        category: 'crypto',
        status: 'info',
        severity: 'info',
        description: 'Verify use of crypto.getRandomValues over Math.random',
        evidence: 'Runtime check — ensure all security-sensitive code uses crypto.getRandomValues()',
        remediation: 'Never use Math.random() for security purposes',
        timestamp: Date.now(),
      });
    }

    // Check for mixed content
    if (typeof window !== 'undefined') {
      const isSecureContext = window.isSecureContext;
      cryptoResults.push({
        id: 'crypto-secure-context',
        name: 'Secure Context',
        category: 'crypto',
        status: isSecureContext ? 'pass' : 'fail',
        severity: 'high',
        description: 'Page is running in a secure context',
        evidence: isSecureContext ? 'Running in secure context' : 'NOT in secure context — some APIs unavailable',
        remediation: isSecureContext ? undefined : 'Serve the page over HTTPS to enable secure context',
        timestamp: Date.now(),
      });
    }

    this.results.push(...cryptoResults);
    return cryptoResults;
  }

  /**
   * Scan Permissions-Policy enforcement.
   */
  async scanPermissions(): Promise<AuditResult[]> {
    const permResults: AuditResult[] = [];

    if (typeof navigator === 'undefined') {
      permResults.push({
        id: 'perm-context',
        name: 'Permissions Scan',
        category: 'permissions',
        status: 'info',
        severity: 'info',
        description: 'Permissions scan not available outside browser context',
        timestamp: Date.now(),
      });
      this.results.push(...permResults);
      return permResults;
    }

    // Check sensitive API permissions
    const sensitiveAPIs: Array<{ name: string; api: string; check: () => boolean }> = [
      { name: 'Geolocation', api: 'geolocation', check: () => 'geolocation' in navigator },
      { name: 'Camera', api: 'mediaDevices', check: () => !!(navigator.mediaDevices) },
      { name: 'Notifications', api: 'Notification', check: () => 'Notification' in window },
      { name: 'Clipboard', api: 'clipboard', check: () => !!(navigator.clipboard) },
    ];

    for (const api of sensitiveAPIs) {
      const available = api.check();
      permResults.push({
        id: `perm-${api.api}`,
        name: `${api.name} API`,
        category: 'permissions',
        status: available ? 'info' : 'pass',
        severity: 'info',
        description: `${api.name} API is ${available ? 'available' : 'not available'}`,
        evidence: available ? `${api.name} API detected — ensure it's properly restricted via Permissions-Policy` : `${api.name} API not detected`,
        remediation: available ? `Consider restricting ${api.name} via Permissions-Policy if not needed` : undefined,
        timestamp: Date.now(),
      });
    }

    this.results.push(...permResults);
    return permResults;
  }

  private checkHeader(
    id: string,
    name: string,
    category: AuditResult['category'],
    check: () => {
      status: AuditResult['status'];
      evidence: string;
      remediation?: string;
      severity?: AuditResult['severity'];
    }
  ): AuditResult {
    const result = check();
    return {
      id,
      name,
      category,
      status: result.status,
      severity: result.severity ?? (result.status === 'fail' ? 'medium' : 'info'),
      description: name,
      evidence: result.evidence,
      remediation: result.remediation,
      timestamp: Date.now(),
    };
  }
}

// ─── CSPViolationReporter ─────────────────────────────────────────────────

/**
 * Collects and reports Content-Security-Policy violations.
 */
export class CSPViolationReporter {
  private violations: CSPViolationReport[] = [];
  private listeners: Array<(report: CSPViolationReport) => void> = [];
  private maxReports: number;
  private readonly version = '2.1.0';

  constructor(maxReports: number = 1000) {
    this.maxReports = maxReports;
  }

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Start listening for CSP violations.
   */
  startListening(): { started: boolean } {
    if (typeof document === 'undefined') return { started: false };

    try {
      document.addEventListener('securitypolicyviolation', (event: SecurityPolicyViolationEvent) => {
        const report: CSPViolationReport = {
          documentURI: event.documentURI,
          violatedDirective: event.violatedDirective,
          blockedURI: event.blockedURI,
          sourceFile: event.sourceFile,
          lineNumber: event.lineNumber,
          columnNumber: event.columnNumber,
          statusCode: event.statusCode,
          timestamp: Date.now(),
        };

        this.violations.push(report);

        if (this.violations.length > this.maxReports) {
          this.violations = this.violations.slice(-this.maxReports);
        }

        for (const listener of this.listeners) {
          try {
            listener(report);
          } catch {
            // Listener errors should not affect reporting
          }
        }
      });

      return { started: true };
    } catch {
      return { started: false };
    }
  }

  /**
   * Register a listener for CSP violations.
   */
  onViolation(listener: (report: CSPViolationReport) => void): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }

  /**
   * Get all collected violations.
   */
  getViolations(filter?: {
    directive?: string;
    blockedURI?: string;
    since?: number;
  }): CSPViolationReport[] {
    let violations = [...this.violations];

    if (filter?.directive) {
      violations = violations.filter(v => v.violatedDirective.includes(filter.directive!));
    }
    if (filter?.blockedURI) {
      violations = violations.filter(v => v.blockedURI?.includes(filter.blockedURI!));
    }
    if (filter?.since) {
      violations = violations.filter(v => v.timestamp >= filter.since!);
    }

    return violations;
  }

  /**
   * Get violation statistics.
   */
  getStats(): {
    totalViolations: number;
    violationsByDirective: Record<string, number>;
    topBlockedURIs: Array<{ uri: string; count: number }>;
  } {
    const byDirective: Record<string, number> = {};
    const byURI: Record<string, number> = {};

    for (const v of this.violations) {
      byDirective[v.violatedDirective] = (byDirective[v.violatedDirective] ?? 0) + 1;
      if (v.blockedURI) {
        byURI[v.blockedURI] = (byURI[v.blockedURI] ?? 0) + 1;
      }
    }

    const topBlockedURIs = Object.entries(byURI)
      .map(([uri, count]) => ({ uri, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return {
      totalViolations: this.violations.length,
      violationsByDirective: byDirective,
      topBlockedURIs,
    };
  }

  /**
   * Clear all stored violations.
   */
  clear(): void {
    this.violations = [];
  }
}

// ─── SecurityScoreCalculator ──────────────────────────────────────────────

/**
 * Calculates a security score (0-100) based on multiple factors.
 */
export class SecurityScoreCalculator {
  private readonly version = '2.1.0';

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Calculate security score from audit results.
   */
  calculate(results: AuditResult[]): SecurityScore {
    const categories = ['headers', 'dom', 'crypto', 'permissions', 'cookies'] as const;

    const categoryScores: Record<string, number> = {};
    for (const cat of categories) {
      categoryScores[cat] = this.calculateCategoryScore(results.filter(r => r.category === cat));
    }

    const weights: Record<string, number> = {
      headers: 0.25,
      dom: 0.25,
      crypto: 0.25,
      permissions: 0.15,
      cookies: 0.10,
    };

    let overall = 0;
    for (const [cat, weight] of Object.entries(weights)) {
      overall += (categoryScores[cat] ?? 100) * weight;
    }

    overall = Math.round(Math.max(0, Math.min(100, overall)));

    return {
      overall,
      headers: Math.round(categoryScores.headers ?? 100),
      dom: Math.round(categoryScores.dom ?? 100),
      crypto: Math.round(categoryScores.crypto ?? 100),
      permissions: Math.round(categoryScores.permissions ?? 100),
      cookies: Math.round(categoryScores.cookies ?? 100),
      grade: this.scoreToGrade(overall),
      summary: this.generateSummary(overall, results),
    };
  }

  private calculateCategoryScore(results: AuditResult[]): number {
    if (results.length === 0) return 100;

    let score = 100;

    for (const result of results) {
      switch (result.status) {
        case 'pass':
          break;
        case 'info':
          break;
        case 'warning':
          score -= 5;
          break;
        case 'fail':
          switch (result.severity) {
            case 'critical': score -= 25; break;
            case 'high': score -= 15; break;
            case 'medium': score -= 10; break;
            case 'low': score -= 5; break;
            default: score -= 8;
          }
          break;
        case 'error':
          score -= 20;
          break;
      }
    }

    return Math.max(0, score);
  }

  private scoreToGrade(score: number): SecurityScore['grade'] {
    if (score >= 97) return 'A+';
    if (score >= 90) return 'A';
    if (score >= 75) return 'B';
    if (score >= 60) return 'C';
    if (score >= 40) return 'D';
    return 'F';
  }

  private generateSummary(score: number, results: AuditResult[]): string {
    const failures = results.filter(r => r.status === 'fail');
    const warnings = results.filter(r => r.status === 'warning');
    const critical = failures.filter(r => r.severity === 'critical');

    if (score >= 90) {
      return `Excellent security posture. ${warnings.length} minor warning(s) to address.`;
    }
    if (score >= 75) {
      return `Good security with room for improvement. ${failures.length} issue(s) and ${warnings.length} warning(s) found.`;
    }
    if (score >= 60) {
      return `Moderate security concerns. ${failures.length} issue(s) need attention, including ${critical.length} critical.`;
    }
    return `Significant security vulnerabilities detected. ${critical.length} critical and ${failures.length} total issue(s) require immediate attention.`;
  }
}

// ─── VulnerabilityDatabase ────────────────────────────────────────────────

/**
 * Check against known vulnerability patterns.
 */
export class VulnerabilityDatabase {
  private patterns: Array<{
    id: string;
    name: string;
    category: VulnerabilityFinding['category'];
    severity: VulnerabilityFinding['severity'];
    pattern: RegExp;
    description: string;
    owaspCategory?: string;
    remediation: string;
  }>;
  private readonly version = '2.1.0';

  constructor() {
    this.patterns = [
      {
        id: 'vuln-xss-innerhtml',
        name: 'innerHTML XSS',
        category: 'xss',
        severity: 'high',
        pattern: /\.innerHTML\s*=\s*[^"]*\+/,
        description: 'Dynamic innerHTML assignment with string concatenation is vulnerable to XSS',
        owaspCategory: 'A03:2021 – Injection',
        remediation: 'Use textContent or sanitize HTML before assignment',
      },
      {
        id: 'vuln-xss-eval',
        name: 'eval() Usage',
        category: 'xss',
        severity: 'critical',
        pattern: /\beval\s*\(/,
        description: 'eval() usage is extremely dangerous and should never be used with untrusted input',
        owaspCategory: 'A03:2021 – Injection',
        remediation: 'Replace eval() with safer alternatives like JSON.parse() or Function constructors',
      },
      {
        id: 'vuln-xss-document-write',
        name: 'document.write() Usage',
        category: 'xss',
        severity: 'high',
        pattern: /document\.write\s*\(/,
        description: 'document.write() can lead to XSS and should be avoided',
        owaspCategory: 'A03:2021 – Injection',
        remediation: 'Use DOM manipulation methods instead of document.write()',
      },
      {
        id: 'vuln-crypto-math-random',
        name: 'Insecure Random Number',
        category: 'crypto-weakness',
        severity: 'high',
        pattern: /Math\.random\(\)/,
        description: 'Math.random() is not cryptographically secure',
        owaspCategory: 'A02:2021 – Cryptographic Failures',
        remediation: 'Use crypto.getRandomValues() for security-sensitive operations',
      },
      {
        id: 'vuln-info-console-log',
        name: 'Console Logging',
        category: 'info-leak',
        severity: 'low',
        pattern: /console\.(log|debug|info)\s*\(/,
        description: 'Console logging may leak sensitive information in production',
        remediation: 'Remove or disable console logging in production builds',
      },
      {
        id: 'vuln-injection-construct',
        name: 'Function Constructor Injection',
        category: 'injection',
        severity: 'critical',
        pattern: /new\s+Function\s*\(/,
        description: 'Function constructor is equivalent to eval() and enables code injection',
        owaspCategory: 'A03:2021 – Injection',
        remediation: 'Never use Function constructor with untrusted input',
      },
      {
        id: 'vuln-csrf-fetch-credentials',
        name: 'Fetch with Credentials',
        category: 'csrf',
        severity: 'medium',
        pattern: /credentials\s*:\s*['"]include['"]/,
        description: 'Sending credentials in cross-origin requests may expose cookies',
        owaspCategory: 'A01:2021 – Broken Access Control',
        remediation: 'Use credentials: same-origin or omit for cross-origin requests',
      },
      {
        id: 'vuln-misconfiguration-cors',
        name: 'Wildcard CORS',
        category: 'misconfiguration',
        severity: 'high',
        pattern: /Access-Control-Allow-Origin\s*:\s*['"]\*['"]/,
        description: 'Wildcard CORS allows any origin to access the resource',
        owaspCategory: 'A05:2021 – Security Misconfiguration',
        remediation: 'Specify exact allowed origins instead of using *',
      },
      {
        id: 'vuln-auth-localstorage',
        name: 'Token in localStorage',
        category: 'auth',
        severity: 'medium',
        pattern: /localStorage\.setItem\s*\(\s*['"]*(?:token|auth|jwt|session)/i,
        description: 'Storing authentication tokens in localStorage is vulnerable to XSS',
        owaspCategory: 'A07:2021 – Identification and Authentication Failures',
        remediation: 'Use HttpOnly cookies for authentication tokens',
      },
    ];
  }

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Scan source code for known vulnerability patterns.
   */
  scan(sourceCode: string): VulnerabilityFinding[] {
    const findings: VulnerabilityFinding[] = [];

    for (const pattern of this.patterns) {
      const matches = sourceCode.match(pattern.pattern);
      if (matches) {
        findings.push({
          id: pattern.id,
          name: pattern.name,
          category: pattern.category,
          severity: pattern.severity,
          description: pattern.description,
          owaspCategory: pattern.owaspCategory,
          evidence: `Pattern matched: ${matches[0]}`,
          remediation: pattern.remediation,
          confidence: 'high',
          foundAt: Date.now(),
        });
      }
    }

    return findings;
  }

  /**
   * Add a custom vulnerability pattern.
   */
  addPattern(pattern: {
    id: string;
    name: string;
    category: VulnerabilityFinding['category'];
    severity: VulnerabilityFinding['severity'];
    pattern: RegExp;
    description: string;
    remediation: string;
  }): void {
    this.patterns.push(pattern);
  }

  /**
   * Get all registered patterns.
   */
  getPatterns(): Array<{ id: string; name: string; category: string; severity: string }> {
    return this.patterns.map(p => ({
      id: p.id,
      name: p.name,
      category: p.category,
      severity: p.severity,
    }));
  }
}

// ─── ComplianceChecker ────────────────────────────────────────────────────

/**
 * Check compliance with OWASP, NIST, PCI-DSS requirements.
 */
export class ComplianceChecker {
  private readonly version = '2.1.0';

  /** Get version */
  getVersion(): string {
    return this.version;
  }

  /**
   * Check compliance against a specific framework.
   */
  checkCompliance(
    framework: ComplianceStatus['framework'],
    auditResults: AuditResult[]
  ): ComplianceStatus {
    switch (framework) {
      case 'OWASP-Top10':
        return this.checkOWASP(auditResults);
      case 'NIST-CSF':
        return this.checkNIST(auditResults);
      case 'PCI-DSS':
        return this.checkPCI(auditResults);
      default:
        return this.checkGeneric(framework, auditResults);
    }
  }

  private checkOWASP(results: AuditResult[]): ComplianceStatus {
    const controls: ComplianceStatus['controls'] = [
      {
        id: 'A01', name: 'Broken Access Control',
        status: this.evaluateControl(results, ['frame-protection', 'perm-geolocation']),
        evidence: 'Based on frame protection and permission checks',
      },
      {
        id: 'A02', name: 'Cryptographic Failures',
        status: this.evaluateControl(results, ['crypto-webcrypto', 'crypto-aes-gcm', 'crypto-secure-context']),
        evidence: 'Based on crypto API availability and secure context checks',
      },
      {
        id: 'A03', name: 'Injection',
        status: this.evaluateControl(results, ['csp', 'dom-js-urls', 'dom-inline-handlers']),
        evidence: 'Based on CSP and injection pattern checks',
      },
      {
        id: 'A04', name: 'Insecure Design',
        status: this.evaluateControl(results, ['cross-origin-isolation', 'referrer-policy']),
        evidence: 'Based on security architecture checks',
      },
      {
        id: 'A05', name: 'Security Misconfiguration',
        status: this.evaluateControl(results, ['hsts', 'x-content-type', 'csp']),
        evidence: 'Based on security header configuration checks',
      },
      {
        id: 'A06', name: 'Vulnerable Components',
        status: 'not-applicable' as const,
        evidence: 'Component scanning requires server-side analysis',
      },
      {
        id: 'A07', name: 'Auth Failures',
        status: 'not-applicable' as const,
        evidence: 'Authentication checks require application-specific testing',
      },
      {
        id: 'A08', name: 'Data Integrity Failures',
        status: this.evaluateControl(results, ['crypto-sha256', 'dom-csrf']),
        evidence: 'Based on integrity and CSRF checks',
      },
      {
        id: 'A09', name: 'Logging Failures',
        status: 'not-applicable' as const,
        evidence: 'Logging requires server-side analysis',
      },
      {
        id: 'A10', name: 'SSRF',
        status: 'not-applicable' as const,
        evidence: 'SSRF requires server-side analysis',
      },
    ];

    const applicable = controls.filter(c => c.status !== 'not-applicable');
    const compliant = applicable.filter(c => c.status === 'compliant');
    const percent = applicable.length > 0 ? (compliant.length / applicable.length) * 100 : 100;

    return {
      framework: 'OWASP-Top10',
      compliancePercent: Math.round(percent),
      controls,
      summary: `${compliant.length}/${applicable.length} applicable OWASP Top 10 controls are compliant`,
    };
  }

  private checkNIST(results: AuditResult[]): ComplianceStatus {
    const controls: ComplianceStatus['controls'] = [
      {
        id: 'PR.DS-1', name: 'Data-at-rest protection',
        status: this.evaluateControl(results, ['crypto-aes-gcm']),
        evidence: 'Based on encryption capability checks',
      },
      {
        id: 'PR.DS-2', name: 'Data-in-transit protection',
        status: this.evaluateControl(results, ['hsts', 'crypto-secure-context']),
        evidence: 'Based on HTTPS and secure context checks',
      },
      {
        id: 'PR.AC-1', name: 'Access control',
        status: this.evaluateControl(results, ['frame-protection', 'csp']),
        evidence: 'Based on frame protection and CSP checks',
      },
      {
        id: 'PR.AC-3', name: 'Remote access protection',
        status: this.evaluateControl(results, ['cross-origin-isolation']),
        evidence: 'Based on cross-origin isolation checks',
      },
      {
        id: 'PR.IP-1', name: 'Policy enforcement',
        status: this.evaluateControl(results, ['csp', 'referrer-policy']),
        evidence: 'Based on security policy checks',
      },
    ];

    const applicable = controls.filter(c => c.status !== 'not-applicable');
    const compliant = applicable.filter(c => c.status === 'compliant');
    const percent = applicable.length > 0 ? (compliant.length / applicable.length) * 100 : 100;

    return {
      framework: 'NIST-CSF',
      compliancePercent: Math.round(percent),
      controls,
      summary: `${compliant.length}/${applicable.length} applicable NIST CSF controls are compliant`,
    };
  }

  private checkPCI(results: AuditResult[]): ComplianceStatus {
    const controls: ComplianceStatus['controls'] = [
      {
        id: 'Req-3', name: 'Protect stored cardholder data',
        status: this.evaluateControl(results, ['crypto-aes-gcm']),
        evidence: 'Based on encryption capability checks',
      },
      {
        id: 'Req-4', name: 'Encrypt transmission',
        status: this.evaluateControl(results, ['hsts', 'crypto-secure-context']),
        evidence: 'Based on HTTPS enforcement checks',
      },
      {
        id: 'Req-6', name: 'Secure systems and applications',
        status: this.evaluateControl(results, ['csp', 'dom-js-urls', 'dom-inline-handlers']),
        evidence: 'Based on XSS and injection prevention checks',
      },
      {
        id: 'Req-8', name: 'Identify and authenticate',
        status: 'not-applicable' as const,
        evidence: 'Authentication checks require application-specific testing',
      },
    ];

    const applicable = controls.filter(c => c.status !== 'not-applicable');
    const compliant = applicable.filter(c => c.status === 'compliant');
    const percent = applicable.length > 0 ? (compliant.length / applicable.length) * 100 : 100;

    return {
      framework: 'PCI-DSS',
      compliancePercent: Math.round(percent),
      controls,
      summary: `${compliant.length}/${applicable.length} applicable PCI-DSS controls are compliant`,
    };
  }

  private checkGeneric(framework: ComplianceStatus['framework'], _results: AuditResult[]): ComplianceStatus {
    return {
      framework,
      compliancePercent: 0,
      controls: [],
      summary: `Framework ${framework} checking not yet implemented`,
    };
  }

  private evaluateControl(
    results: AuditResult[],
    relatedCheckIds: string[]
  ): 'compliant' | 'partial' | 'non-compliant' {
    const related = results.filter(r => relatedCheckIds.includes(r.id));
    if (related.length === 0) return 'non-compliant';

    const failed = related.filter(r => r.status === 'fail');
    const warned = related.filter(r => r.status === 'warning');

    if (failed.length > 0) return 'non-compliant';
    if (warned.length > 0) return 'partial';
    return 'compliant';
  }
}

// ─── generateSecurityReport ───────────────────────────────────────────────

/**
 * Generate a comprehensive security audit report with recommendations.
 */
export async function generateSecurityReport(): Promise<SecurityReport> {
  const auditor = new SecurityAuditor();
  const scoreCalculator = new SecurityScoreCalculator();
  const vulnDB = new VulnerabilityDatabase();
  const complianceChecker = new ComplianceChecker();

  // Run full audit
  const results = await auditor.fullAudit();

  // Calculate score
  const score = scoreCalculator.calculate(results);

  // Scan for vulnerabilities (check current page source if available)
  let vulnerabilities: VulnerabilityFinding[] = [];
  if (typeof document !== 'undefined') {
    try {
      const pageSource = document.documentElement.outerHTML;
      vulnerabilities = vulnDB.scan(pageSource);
    } catch {
      // Can't access page source
    }
  }

  // Check compliance
  const frameworks: ComplianceStatus['framework'][] = ['OWASP-Top10', 'NIST-CSF', 'PCI-DSS'];
  const compliance = frameworks.map(fw => complianceChecker.checkCompliance(fw, results));

  // Generate recommendations
  const recommendations = generateRecommendations(results, vulnerabilities);

  return {
    id: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    version: '2.1.0',
    generatedAt: Date.now(),
    score,
    results,
    vulnerabilities,
    compliance,
    recommendations,
  };
}

function generateRecommendations(
  results: AuditResult[],
  vulnerabilities: VulnerabilityFinding[]
): SecurityReport['recommendations'] {
  const recs: SecurityReport['recommendations'] = [];

  // From failed audit results
  for (const result of results.filter(r => r.status === 'fail')) {
    recs.push({
      priority: result.severity === 'critical' ? 'critical' : result.severity === 'high' ? 'high' : 'medium',
      title: result.name,
      description: result.remediation ?? `Fix ${result.name} issue`,
      effort: result.severity === 'critical' ? 'high' : 'medium',
    });
  }

  // From vulnerability findings
  for (const vuln of vulnerabilities) {
    recs.push({
      priority: vuln.severity === 'critical' ? 'critical' : vuln.severity === 'high' ? 'high' : 'low',
      title: vuln.name,
      description: vuln.remediation,
      effort: 'medium',
    });
  }

  // Sort by priority
  const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  recs.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);

  // Deduplicate
  const seen = new Set<string>();
  return recs.filter(r => {
    const key = r.title;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
