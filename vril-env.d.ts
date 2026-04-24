/// <reference types="next" />
/// <reference types="next/image-types/global" />

// NOTE: This file should not be edited manually.
// See https://nextjs.org/docs/app/building-your-application/configuring/typescript for more information.

// ─── Vril.js Environment Variables ─────────────────────────────────────────
// Extend the NodeJS ProcessEnv interface to provide strict types for all
// environment variables used by Vril.js. Add new variables here as needed.
declare namespace NodeJS {
  interface ProcessEnv {
    // ── Runtime ────────────────────────────────────────────────────────────
    readonly NODE_ENV: "development" | "test" | "production";
    /** The public URL of the deployed application (e.g. https://vril.js.org) */
    readonly NEXT_PUBLIC_APP_URL?: string;

    // ── Cryptography / Secrets ─────────────────────────────────────────────
    /** Master secret used for HMAC token signing (min 32 bytes, base64-encoded) */
    readonly VRIL_SECRET_KEY?: string;
    /** Secret used for CSRF double-submit token generation */
    readonly VRIL_CSRF_SECRET?: string;
    /** Secret used for session encryption and signing */
    readonly VRIL_SESSION_SECRET?: string;
    /** AES-256-GCM encryption key for the secure vault (base64-encoded) */
    readonly VRIL_ENCRYPTION_KEY?: string;
    /** PBKDF2 / Argon2 salt for key derivation functions (base64-encoded) */
    readonly VRIL_KDF_SALT?: string;

    // ── Authentication ─────────────────────────────────────────────────────
    /** JWT issuer identifier */
    readonly VRIL_JWT_ISSUER?: string;
    /** JWT audience identifier */
    readonly VRIL_JWT_AUDIENCE?: string;

    // ── Database / Storage ─────────────────────────────────────────────────
    /** Database connection string (if applicable) */
    readonly DATABASE_URL?: string;

    // ── Observability / Reporting ──────────────────────────────────────────
    /** Endpoint for CSP violation reports */
    readonly VRIL_CSP_REPORT_URL?: string;
    /** Endpoint for security audit event ingestion */
    readonly VRIL_AUDIT_ENDPOINT?: string;
  }
}

// ─── Vril.js Global Augmentations ───────────────────────────────────────────
declare global {
  /**
   * Set by the Vril.js security proxy on every request.
   * Contains the resolved Vril configuration for the current request context.
   */
  interface Window {
    /** Vril.js version string injected by the runtime */
    readonly __VRIL_VERSION__?: string;
  }
}

export {};
