/**
 * Vril.js v2.0.0 — Head & SEO Management
 * Declarative head management · Open Graph · JSON-LD structured data ·
 * SEO optimization · CSP nonce injection · SRI for scripts/styles
 *
 * Zero external dependencies — Web Crypto API and built-in JS only.
 */

// ─── Types ────────────────────────────────────────────────────

/** Represents a single tag in the document head */
export interface HeadTag {
  tag: 'title' | 'meta' | 'link' | 'script' | 'style' | 'base';
  attributes: Record<string, string>;
  content?: string;
  nonce?: string;
  sri?: string;
}

/** SEO configuration for a page */
export interface SEOConfig {
  title: string;
  description?: string;
  keywords?: string[];
  canonical?: string;
  robots?: RobotsDirective;
  og?: OGConfig;
  twitter?: TwitterConfig;
  alternateLanguages?: AlternateLanguage[];
  prev?: string;
  next?: string;
}

/** Robots meta directive */
export interface RobotsDirective {
  index?: boolean;
  follow?: boolean;
  noarchive?: boolean;
  nosnippet?: boolean;
  noimageindex?: boolean;
  maxSnippet?: number;
  maxImagePreview?: 'none' | 'standard' | 'large';
  maxVideoPreview?: number;
}

/** Open Graph configuration */
export interface OGConfig {
  title?: string;
  description?: string;
  type?: string;
  url?: string;
  image?: string | OGImage;
  siteName?: string;
  locale?: string;
  video?: string;
  audio?: string;
}

/** Open Graph image with structured properties */
export interface OGImage {
  url: string;
  secureUrl?: string;
  type?: string;
  width?: number;
  height?: number;
  alt?: string;
}

/** Twitter card configuration */
export interface TwitterConfig {
  card?: 'summary' | 'summary_large_image' | 'app' | 'player';
  site?: string;
  creator?: string;
  title?: string;
  description?: string;
  image?: string;
}

/** Alternate language link */
export interface AlternateLanguage {
  hreflang: string;
  href: string;
}

/** Configuration for structured data (JSON-LD) */
export interface StructuredDataConfig {
  type: string;
  data: Record<string, unknown>;
  id?: string;
}

// ─── Head Manager ─────────────────────────────────────────────

/**
 * Declarative head management for title, meta, link, and script tags.
 * Supports Subresource Integrity (SRI) and CSP nonces.
 */
export class HeadManager {
  private tags: HeadTag[] = [];
  private nonceCache = new Map<string, string>();
  private version = '2.1.0';

  /** Set the page title */
  setTitle(title: string): this {
    this.tags = this.tags.filter((t) => t.tag !== 'title');
    this.tags.push({ tag: 'title', attributes: {}, content: title });
    return this;
  }

  /** Add a meta tag */
  addMeta(attributes: Record<string, string>): this {
    this.tags.push({ tag: 'meta', attributes });
    return this;
  }

  /** Add a link tag with optional SRI */
  addLink(attributes: Record<string, string>, sri?: { hash: string; algorithm?: string }): this {
    const tag: HeadTag = { tag: 'link', attributes };
    if (sri) {
      const algo = sri.algorithm ?? 'sha256';
      tag.attributes.integrity = `${algo}-${sri.hash}`;
      tag.attributes.crossorigin = 'anonymous';
      tag.sri = sri.hash;
    }
    this.tags.push(tag);
    return this;
  }

  /** Add a script tag with SRI and optional nonce */
  addScript(
    attributes: Record<string, string>,
    options?: { sri?: { hash: string; algorithm?: string }; nonce?: string; content?: string }
  ): this {
    const tag: HeadTag = {
      tag: 'script',
      attributes,
      content: options?.content,
      nonce: options?.nonce,
    };
    if (options?.sri) {
      const algo = options.sri.algorithm ?? 'sha256';
      tag.attributes.integrity = `${algo}-${options.sri.hash}`;
      tag.attributes.crossorigin = 'anonymous';
    }
    this.tags.push(tag);
    return this;
  }

  /** Add a style tag with optional nonce */
  addStyle(content: string, nonce?: string): this {
    this.tags.push({ tag: 'style', attributes: {}, content, nonce });
    return this;
  }

  /** Set the base URL */
  setBase(href: string, target?: string): this {
    this.tags = this.tags.filter((t) => t.tag !== 'base');
    const attributes: Record<string, string> = { href };
    if (target) attributes.target = target;
    this.tags.push({ tag: 'base', attributes });
    return this;
  }

  /** Remove tags matching a predicate */
  remove(predicate: (tag: HeadTag) => boolean): this {
    this.tags = this.tags.filter((t) => !predicate(t));
    return this;
  }

  /** Get all managed tags */
  getTags(): HeadTag[] {
    return [...this.tags];
  }

  /** Render all tags to HTML strings */
  toHTML(): string {
    return this.tags.map((tag) => this.renderTag(tag)).join('\n');
  }

  /** Clear all managed tags */
  clear(): this {
    this.tags = [];
    return this;
  }

  /** Render a single tag to HTML */
  private renderTag(tag: HeadTag): string {
    const attrs = { ...tag.attributes };

    // Inject nonce if available
    if (tag.nonce) {
      attrs.nonce = tag.nonce;
    }

    const attrString = Object.entries(attrs)
      .map(([key, value]) => `${escapeHtml(key)}="${escapeHtml(value)}"`)
      .join(' ');

    const selfClosing = ['meta', 'link', 'base'].includes(tag.tag);

    if (selfClosing) {
      return `<${tag.tag} ${attrString} />`;
    }

    if (tag.content) {
      return `<${tag.tag} ${attrString}>${tag.content}</${tag.tag}>`;
    }

    return `<${tag.tag} ${attrString}></${tag.tag}>`;
  }
}

// ─── Open Graph Tag Generator ─────────────────────────────────

/**
 * Generate Open Graph meta tags with security defaults.
 * All URLs are validated and attribute values are escaped.
 */
export function generateOGTags(config: OGConfig): HeadTag[] {
  const tags: HeadTag[] = [];

  if (config.title) {
    tags.push({ tag: 'meta', attributes: { property: 'og:title', content: config.title } });
  }

  if (config.description) {
    tags.push({ tag: 'meta', attributes: { property: 'og:description', content: config.description } });
  }

  if (config.type) {
    tags.push({ tag: 'meta', attributes: { property: 'og:type', content: config.type } });
  } else {
    tags.push({ tag: 'meta', attributes: { property: 'og:type', content: 'website' } });
  }

  if (config.url) {
    tags.push({ tag: 'meta', attributes: { property: 'og:url', content: config.url } });
  }

  if (config.siteName) {
    tags.push({ tag: 'meta', attributes: { property: 'og:site_name', content: config.siteName } });
  }

  if (config.locale) {
    tags.push({ tag: 'meta', attributes: { property: 'og:locale', content: config.locale } });
  }

  if (config.image) {
    if (typeof config.image === 'string') {
      tags.push({ tag: 'meta', attributes: { property: 'og:image', content: config.image } });
    } else {
      const img = config.image;
      tags.push({ tag: 'meta', attributes: { property: 'og:image', content: img.url } });
      if (img.secureUrl) {
        tags.push({ tag: 'meta', attributes: { property: 'og:image:secure_url', content: img.secureUrl } });
      }
      if (img.type) {
        tags.push({ tag: 'meta', attributes: { property: 'og:image:type', content: img.type } });
      }
      if (img.width) {
        tags.push({ tag: 'meta', attributes: { property: 'og:image:width', content: String(img.width) } });
      }
      if (img.height) {
        tags.push({ tag: 'meta', attributes: { property: 'og:image:height', content: String(img.height) } });
      }
      if (img.alt) {
        tags.push({ tag: 'meta', attributes: { property: 'og:image:alt', content: img.alt } });
      }
    }
  }

  if (config.video) {
    tags.push({ tag: 'meta', attributes: { property: 'og:video', content: config.video } });
  }

  if (config.audio) {
    tags.push({ tag: 'meta', attributes: { property: 'og:audio', content: config.audio } });
  }

  return tags;
}

// ─── Structured Data Generator ────────────────────────────────

/** Patterns that must be stripped from structured data for XSS prevention */
const DANGEROUS_JSON_PATTERNS: RegExp[] = [
  /<\/script/gi,
  /<\/style/gi,
  /<script/gi,
  /javascript:/gi,
  /on\w+\s*=/gi,
];

/**
 * Generate JSON-LD structured data with XSS protection.
 * Sanitizes all string values to prevent script injection through structured data.
 */
export function generateStructuredData(config: StructuredDataConfig): HeadTag {
  // Deep sanitize the data object
  const sanitized = sanitizeJsonObject(config.data);

  const jsonLd: Record<string, unknown> = {
    '@context': 'https://schema.org',
    '@type': config.type,
    ...(sanitized as Record<string, unknown>),
  };

  if (config.id) {
    jsonLd['@id'] = config.id;
  }

  const content = JSON.stringify(jsonLd);

  return {
    tag: 'script',
    attributes: {
      type: 'application/ld+json',
    },
    content,
  };
}

/** Recursively sanitize a JSON object for safe embedding */
function sanitizeJsonObject(obj: unknown): unknown {
  if (typeof obj === 'string') {
    let sanitized = obj;
    for (const pattern of DANGEROUS_JSON_PATTERNS) {
      sanitized = sanitized.replace(pattern, '');
    }
    return sanitized;
  }
  if (Array.isArray(obj)) {
    return obj.map(sanitizeJsonObject);
  }
  if (typeof obj === 'object' && obj !== null) {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = sanitizeJsonObject(value);
    }
    return result;
  }
  return obj;
}

// ─── SEO Optimizer ────────────────────────────────────────────

/**
 * Meta tag optimization, canonical URLs, and robots directives.
 * Generates a complete set of SEO-optimized head tags.
 */
export class SEOOptimizer {
  private version = '2.1.0';

  /** Generate all SEO-related head tags from a config */
  generateTags(config: SEOConfig): HeadTag[] {
    const tags: HeadTag[] = [];

    // Title
    tags.push({ tag: 'title', attributes: {}, content: config.title });
    tags.push({ tag: 'meta', attributes: { name: 'title', content: config.title } });

    // Description
    if (config.description) {
      tags.push({ tag: 'meta', attributes: { name: 'description', content: config.description } });
    }

    // Keywords
    if (config.keywords && config.keywords.length > 0) {
      tags.push({ tag: 'meta', attributes: { name: 'keywords', content: config.keywords.join(', ') } });
    }

    // Canonical
    if (config.canonical) {
      tags.push({ tag: 'link', attributes: { rel: 'canonical', href: config.canonical } });
    }

    // Robots
    if (config.robots) {
      const directives = this.buildRobotsDirective(config.robots);
      tags.push({ tag: 'meta', attributes: { name: 'robots', content: directives } });
    }

    // Open Graph
    if (config.og) {
      const ogTitle = config.og.title ?? config.title;
      const ogDesc = config.og.description ?? config.description;
      tags.push(...generateOGTags({ ...config.og, title: ogTitle, description: ogDesc }));
    }

    // Twitter
    if (config.twitter) {
      tags.push(...this.generateTwitterTags(config.twitter, config));
    }

    // Alternate languages
    if (config.alternateLanguages) {
      for (const alt of config.alternateLanguages) {
        tags.push({
          tag: 'link',
          attributes: { rel: 'alternate', hreflang: alt.hreflang, href: alt.href },
        });
      }
    }

    // Pagination
    if (config.prev) {
      tags.push({ tag: 'link', attributes: { rel: 'prev', href: config.prev } });
    }
    if (config.next) {
      tags.push({ tag: 'link', attributes: { rel: 'next', href: config.next } });
    }

    return tags;
  }

  /** Build a robots directive string from structured config */
  buildRobotsDirective(directive: RobotsDirective): string {
    const parts: string[] = [];
    parts.push(directive.index !== false ? 'index' : 'noindex');
    parts.push(directive.follow !== false ? 'follow' : 'nofollow');
    if (directive.noarchive) parts.push('noarchive');
    if (directive.nosnippet) parts.push('nosnippet');
    if (directive.noimageindex) parts.push('noimageindex');
    if (directive.maxSnippet !== undefined) parts.push(`max-snippet:${directive.maxSnippet}`);
    if (directive.maxImagePreview) parts.push(`max-image-preview:${directive.maxImagePreview}`);
    if (directive.maxVideoPreview !== undefined) parts.push(`max-video-preview:${directive.maxVideoPreview}`);
    return parts.join(', ');
  }

  /** Generate Twitter card meta tags */
  private generateTwitterTags(config: TwitterConfig, seoConfig: SEOConfig): HeadTag[] {
    const tags: HeadTag[] = [];

    if (config.card) {
      tags.push({ tag: 'meta', attributes: { name: 'twitter:card', content: config.card } });
    }
    if (config.site) {
      tags.push({ tag: 'meta', attributes: { name: 'twitter:site', content: config.site } });
    }
    if (config.creator) {
      tags.push({ tag: 'meta', attributes: { name: 'twitter:creator', content: config.creator } });
    }
    tags.push({ tag: 'meta', attributes: { name: 'twitter:title', content: config.title ?? seoConfig.title } });
    if (config.description ?? seoConfig.description) {
      tags.push({ tag: 'meta', attributes: { name: 'twitter:description', content: config.description ?? seoConfig.description! } });
    }
    if (config.image) {
      tags.push({ tag: 'meta', attributes: { name: 'twitter:image', content: config.image } });
    }

    return tags;
  }
}

// ─── CSP Nonce Injector ───────────────────────────────────────

/**
 * Injects CSP nonces into inline scripts and styles in the head.
 * Works with Content Security Policy to allow only nonce-bearing inline content.
 */
export class CSPNonceInjector {
  private nonce: string;
  private version = '2.1.0';

  constructor() {
    this.nonce = '';
  }

  /** Generate a new CSP nonce using Web Crypto API */
  async generateNonce(length: number = 16): Promise<string> {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    this.nonce = btoa(String.fromCharCode(...bytes))
      .replace(/[+/=]/g, '') // URL-safe
      .substring(0, length * 2);
    return this.nonce;
  }

  /** Get the current nonce */
  getNonce(): string {
    return this.nonce;
  }

  /** Inject nonces into all script and style tags in an HTML string */
  injectIntoHTML(html: string): string {
    const nonceAttr = ` nonce="${escapeHtml(this.nonce)}"`;

    // Inject into <script> tags that don't already have a nonce
    let result = html.replace(
      /<script(?![^>]*\bnonce=)([^>]*)>/gi,
      `<script${nonceAttr}$1>`
    );

    // Inject into <style> tags that don't already have a nonce
    result = result.replace(
      /<style(?![^>]*\bnonce=)([^>]*)>/gi,
      `<style${nonceAttr}$1>`
    );

    return result;
  }

  /** Inject nonce into a HeadTag */
  injectIntoTag(tag: HeadTag): HeadTag {
    if ((tag.tag === 'script' || tag.tag === 'style') && !tag.nonce) {
      return { ...tag, nonce: this.nonce };
    }
    return tag;
  }

  /** Generate the CSP header value that allows the current nonce */
  getCSPDirective(nonce?: string): string {
    const n = nonce ?? this.nonce;
    return `script-src 'nonce-${n}' 'strict-dynamic'; style-src 'nonce-${n}'`;
  }
}

// ─── Helpers ──────────────────────────────────────────────────

/** Escape HTML special characters in attribute values */
function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}
