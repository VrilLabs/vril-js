/**
 * Vril.js v2.1.0 — Configuration File
 * ────────────────────────────────────
 * This is the user-facing configuration file for Vril.js.
 * Similar to next.config.ts for Next.js, this file controls
 * every aspect of the Vril.js framework behavior.
 *
 * Edit this file to customize security, cryptography, routing,
 * server, build, auth, and Next.js integration settings.
 */

import { defineVrilConfig } from './src/lib/vril/config/define';

export default defineVrilConfig({
  // ─── Security ────────────────────────────────────────────────
  // Zero-trust security membrane: Trusted Types, API blocking,
  // CSP, Permissions Policy, security headers, and CSRF protection.
  security: {
    // Enforce Trusted Types policy to prevent DOM XSS.
    // Blocks innerHTML, outerHTML, document.write, etc. unless
    // they go through a trusted types policy.
    trustedTypes: true,

    // Install the API membrane that blocks dangerous browser APIs
    // listed in blockedAPIs. Runs at document-start before any
    // application code can access those APIs.
    apiMembrane: true,

    // Browser APIs to block via the zero-trust membrane.
    // WebTransport: prevents arbitrary TCP/UDP connections.
    // RTCPeerConnection: prevents WebRTC IP leaks.
    blockedAPIs: ['WebTransport', 'RTCPeerConnection'],

    // Content Security Policy (CSP Level 3)
    // Controls which resources the browser is allowed to load.
    csp: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: true,
      blockAllMixedContent: true,
      reportTo: undefined,  // Set to your CSP reporting endpoint
    },

    // Permissions Policy (Feature Policy)
    // Controls which browser features and APIs the page can use.
    // Empty arrays = feature is denied for all origins.
    permissionsPolicy: {
      gpu: [],              // Deny GPU access by default
      camera: [],           // Deny camera access
      microphone: [],       // Deny microphone access
      usb: [],              // Deny WebUSB
      serial: [],           // Deny Web Serial API
      bluetooth: [],        // Deny Web Bluetooth
      hid: [],              // Deny Human Interface Device
      geolocation: [],      // Deny geolocation
      payment: [],          // Deny Payment Request API
      'xr-spatial-tracking': [],   // Deny WebXR
      'compute-pressure': [],      // Deny Compute Pressure API
    },

    // HTTP Security Headers
    // These are applied to every response from the server.
    headers: {
      strictTransportSecurity: 'max-age=63072000; includeSubDomains; preload',
      xContentTypeOptions: 'nosniff',
      xFrameOptions: 'DENY',
      referrerPolicy: 'strict-origin-when-cross-origin',
      crossOriginOpenerPolicy: 'same-origin',
      crossOriginEmbedderPolicy: 'credentialless',
      crossOriginResourcePolicy: 'same-origin',
    },

    // CSRF (Cross-Site Request Forgery) Protection
    csrf: {
      enabled: true,           // Enable double-submit CSRF tokens
      tokenHeader: 'x-vril-csrf',  // Header name for CSRF token
      cookieName: 'vril-csrf',     // Cookie name for CSRF token
      sameSite: 'Strict',          // Cookie SameSite attribute
      doubleSubmit: true,           // Use double-submit pattern
      tokenRotation: true,          // Rotate token after each request
    },
  },

  // ─── Cryptography ────────────────────────────────────────────
  // Post-quantum cryptography, hybrid key exchange, crypto agility.
  // All operations use the Web Crypto API — zero dependencies.
  crypto: {
    // Default encryption algorithm.
    // 'aes-256-gcm' — Symmetric encryption for vault/storage.
    // 'x25519-mlkem768' — Hybrid KEM for key exchange.
    defaultAlgorithm: 'aes-256-gcm',

    // PBKDF2 iteration count for key derivation.
    // OWASP 2023 recommends 600,000+ iterations for PBKDF2-SHA-512.
    // Lower values are insecure; higher values impact performance.
    kdfIterations: 600000,

    // Enable post-quantum cryptography support.
    // When true, ML-KEM-768/1024 and ML-DSA-65/87 are available.
    pqcEnabled: true,

    // Enable hybrid mode (classical + PQC combined).
    // When true, key exchange and signatures combine classical
    // algorithms (X25519, ECDSA-P256) with PQC algorithms
    // (ML-KEM-768, ML-DSA-65) for defense in depth.
    hybridMode: true,

    // Automatic key rotation period in days.
    // After this period, keys are marked for rotation.
    // Set to 0 to disable automatic rotation.
    keyRotationDays: 90,
  },

  // ─── Router ──────────────────────────────────────────────────
  // Secure routing with rate limiting, CORS, bot detection.
  router: {
    // Default rate limit (requests per minute per IP).
    defaultRateLimit: 100,

    // Default maximum request body size in bytes.
    defaultMaxBodySize: 1024 * 1024,  // 1 MB

    // Validate Origin header on every request.
    strictOriginValidation: false,

    // Enable bot detection via User-Agent analysis.
    botDetection: true,

    // Allowed CORS origins. Empty = same-origin only.
    // Example: ['https://example.com', 'https://app.example.com']
    corsOrigins: [] as string[],
  },

  // ─── Server ──────────────────────────────────────────────────
  // Server configuration: port, host, HTTPS, timeouts.
  server: {
    port: 3000,
    host: '0.0.0.0',

    // Enable HTTPS (required for HSTS, COOP/COEP, etc.)
    https: false,

    // HSTS max-age in seconds (only effective with HTTPS).
    // 63072000 = 2 years (recommended for preload lists).
    hstsMaxAge: 63072000,

    // Request timeout in milliseconds.
    requestTimeout: 30000,

    // Maximum request body size in bytes.
    maxRequestSize: 10 * 1024 * 1024,  // 10 MB
  },

  // ─── Build ───────────────────────────────────────────────────
  // Build-time security: CSP nonces, SRI hashes, SBOM, auditing.
  build: {
    // Generate per-request CSP nonces for inline scripts/styles.
    // Replaces 'unsafe-inline' with nonce-based allowlisting.
    cspNonce: true,

    // Generate Subresource Integrity (SRI) hashes for all assets.
    // Uses sha256, sha384, sha512 — triple hash for maximum security.
    sriHashes: true,

    // Apply security headers during the build process.
    securityHeaders: true,

    // Generate a Software Bill of Materials (SBOM) in CycloneDX format.
    // Useful for supply chain security audits.
    sbom: false,

    // Enable React Strict Mode for additional runtime checks.
    strictMode: true,
  },

  // ─── Auth ────────────────────────────────────────────────────
  // Authentication primitives: sessions, tokens, passwords, RBAC.
  auth: {
    // Session time-to-live in milliseconds.
    sessionTTL: 86400000,       // 24 hours

    // Session idle timeout in milliseconds.
    sessionIdleTimeout: 1800000, // 30 minutes

    // Token signing algorithm.
    tokenAlgorithm: 'HMAC-SHA256',

    // Minimum password length (OWASP recommends 12+).
    passwordMinLength: 12,

    // PBKDF2 iterations for password hashing.
    passwordRounds: 600000,

    // Maximum login attempts before lockout.
    maxLoginAttempts: 5,

    // Account lockout duration in milliseconds.
    lockoutDuration: 900000,    // 15 minutes
  },

  // ─── Next.js Integration ─────────────────────────────────────
  // Pass through any Next.js configuration options here.
  // These are forwarded directly to Next.js when using toNextConfig().
  nextjs: {
    reactStrictMode: true,
    poweredByHeader: false,     // Don't expose X-Powered-By header
  },
});
