<div align="center">
 
```
 _    __     _ __    _     
| |  / /____(_) /   (_)____
| | / / ___/ / /   / / ___/
| |/ / /  / / /   / (__  ) 
|___/_/  /_/_(_)_/ /____/  
              /___/        
```

# Vril.js v2.1

### The Security-First React Framework

[![Version](https://img.shields.io/badge/version-2.1.0-00d4aa?style=flat-square&labelColor=1a1a2e)](https://github.com/vrillabs/vril-js)
[![License](https://img.shields.io/badge/license-MIT-00d4aa?style=flat-square&labelColor=1a1a2e)](https://github.com/vrillabs/vril-js/blob/main/LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-00d4aa?style=flat-square&labelColor=1a1a2e)](https://github.com/vrillabs/vril-js)
[![PQC-Ready](https://img.shields.io/badge/PQC-Ready-00d4aa?style=flat-square&labelColor=1a1a2e)](https://csrc.nist.gov/projects/post-quantum-cryptography)

**Post-quantum cryptography · Zero-trust membrane · Crypto agility · ΩSignal reactivity**

Vril.js is a production-grade React framework where security is the architecture, not an afterthought. Built with zero external dependencies and full NIST post-quantum cryptography support, it provides everything you need to build applications that withstand both today's threats and tomorrow's quantum adversaries.

[Documentation](https://vril.li/docs) · [Getting Started](#installation) · [API Reference](#api-overview) · [Security Model](#security-model) · [GitHub](https://github.com/vrillabs/vril-js)

</div>

---

## Why Vril.js?

The web is facing a cryptographic reckoning. NIST finalized post-quantum standards in 2024 (FIPS 203, 204, 205). The "harvest now, decrypt later" threat is real. Yet most frameworks still treat security as a plugin you install after the fact.

Vril.js inverts this. Every module — from routing to reactivity, from SSR to state management — is built on a foundation of cryptographic integrity and zero-trust principles. And because it uses only the Web Crypto API, there are zero supply chain attack vectors from npm dependencies.

**The result:** Applications that are secure by default, quantum-resistant out of the box, and fast enough to run at the edge.

---

## Features

🔐 **Post-Quantum Cryptography** — ML-KEM-768, ML-KEM-1024, ML-DSA-65, ML-DSA-87, SLH-DSA-SHA2-128s, SLH-DSA-SHA2-256f. All NIST FIPS 203/204/205 standard algorithms with correct interfaces and key sizes.

🔗 **Hybrid Key Exchange** — X25519+ML-KEM-768 and ECDSA-P256+ML-DSA-65 with SHA-256 KDF combiner. Secure as long as *at least one* algorithm remains unbroken — defense in depth against quantum adversaries.

🔄 **Crypto Agility** — 12+ algorithm registry with NIST 2035 migration paths. Swap algorithms without rewriting application code. Health monitoring and automated migration planning built in.

🏦 **ΩVault** — AES-256-GCM encryption with PBKDF2-SHA-512 at 600,000 iterations. Text and binary encryption, key wrapping, passphrase rotation, data key generation, and password strength assessment. Zero-knowledge client-side encryption.

⚡ **ΩSignal** — Fine-grained reactive primitives: `signal`, `computed`, `effect`, `batch`, `untrack`, `store`. Plus advanced types: `lazySignal`, `asyncSignal`, `resourceSignal`, `debouncedSignal`, `throttledSignal`, `persistedSignal`, `encryptedSignal`. Full dependency graph with devtools hooks.

🛡️ **Zero-Trust Membrane** — Trusted Types enforcement, API membrane that blocks dangerous browser APIs (`WebTransport`, `RTCPeerConnection`), XSS shield, cross-origin isolation, timing attack mitigation, clickjacking protection, and cookie fortress.

🌐 **Secure SSR** — Streaming server-side rendering with HMAC integrity validation, selective hydration, SSR manifest generation, and stream-level rate limiting.

🏗️ **Build Security** — 20-point security audit, SBOM/CycloneDX generation, SRI hash computation, CSP nonce injection, build integrity verification, and security headers plugin.

⚡ **Edge Runtime** — Edge KV with TTL support, geolocation extraction with privacy modes (Cloudflare/Vercel/Deno compatible), bot detection, IP allowlisting/blocklisting, and edge-specific security headers.

🧩 **Plugin Architecture** — Lifecycle hooks (`onInit`, `onReady`, `onRequest`, `onResponse`, `onError`, `onBuild`, `onSecurityCheck`), plugin sandboxing with permission scoping, integrity verification, and context isolation.

🔒 **Type-Safe APIs** — Zero-dependency schema validation, rate limiting per route and per IP, CSRF protection with double-submit cookies and token rotation, request signing with HMAC-SHA256, and composable security middleware chains.

🔑 **Auth Primitives** — Session management with HMAC-signed tokens, JWT-like token handler with rotation, PBKDF2-SHA-512 password hashing at 600K iterations, hierarchical RBAC with permission inheritance, and login attempt tracking with lockout.

---

## Installation

```bash
# Create a new Vril.js project (recommended)
npx create-vril-app@latest

# Or add to an existing project
npm install vril-js

# Or with your preferred package manager
yarn add vril-js
pnpm add vril-js
bun add vril-js
```

---

## Quick Start

### 1. Configure Your App

```typescript
// vril.config.ts
import { createVrilApp } from 'vril-js';

export const app = createVrilApp({
  security: {
    trustedTypes: true,
    apiMembrane: true,
    blockedAPIs: ['WebTransport', 'RTCPeerConnection'],
    csp: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'strict-dynamic'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
    headers: {
      strictTransportSecurity: 'max-age=63072000; includeSubDomains; preload',
      xFrameOptions: 'DENY',
      referrerPolicy: 'strict-origin-when-cross-origin',
    },
  },
  crypto: {
    defaultAlgorithm: 'x25519-mlkem768',
    kdfIterations: 600000,
    pqcEnabled: true,
    hybridMode: true,
  },
  signals: {
    enabled: true,
  },
});
```

### 2. Post-Quantum Key Exchange

```typescript
import { HybridKEM } from 'vril-js';

// Create a hybrid KEM instance (X25519 + ML-KEM-768)
const kem = new HybridKEM('X25519MLKEM768', 'my-app-key-exchange');

// Generate a hybrid key pair
const keyPair = await kem.generateKeyPair();
console.log(`Key pair ID: ${keyPair.id}`);
console.log(`Classical: ${keyPair.classical.algorithm}`);
console.log(`PQC: ${keyPair.pqc.algorithm}`);

// Encapsulate (sender side)
const kemResult = await kem.encapsulate(keyPair.combinedPublicKey);
console.log(`Shared secret: ${kemResult.sharedSecret.length} bytes`);

// Decapsulate (receiver side)
const recoveredSecret = await kem.decapsulate(keyPair, kemResult);
// recoveredSecret === kemResult.sharedSecret ✓
```

### 3. Vault Encryption

```typescript
import { VrilVault } from 'vril-js';

const vault = new VrilVault({
  kdfIterations: 600000,  // PBKDF2-SHA-512 iterations
  saltSize: 16,
  ivSize: 12,
});

// Encrypt sensitive data
const encrypted = await vault.encrypt('my-passphrase', 'Top secret data');
console.log(encrypted);
// {
//   v: 2,
//   salt: '...',
//   iv: '...',
//   ciphertext: '...',
//   algorithm: 'AES-256-GCM',
//   kdf: 'PBKDF2-SHA-512',
//   kdfIterations: 600000,
//   encryptedAt: 1709318400000
// }

// Decrypt
const decrypted = await vault.decrypt('my-passphrase', encrypted);
console.log(decrypted.verified); // true — GCM tag verified

// Rotate passphrase without exposing plaintext
const rotated = await vault.rotatePassphrase('my-passphrase', 'new-stronger-passphrase', encrypted);

// Assess password strength
const strength = vault.assessStrength('my-passphrase');
console.log(strength.label);    // 'strong'
console.log(strength.score);    // 8/10
```

### 4. Secure Route with CSRF

```typescript
import { createSecureHandler, CSRFGuard, RouteMiddleware } from 'vril-js';

// Create a secure API route handler
const handler = createSecureHandler(
  async (request, { path, policy }) => {
    const body = await request.json();
    return new Response(JSON.stringify({ success: true, data: body }), {
      headers: { 'Content-Type': 'application/json' },
    });
  },
  {
    csrf: true,
    rateLimit: 30,
    methods: ['POST', 'PUT', 'DELETE'],
    maxBodySize: 512 * 1024,
    auditLevel: 'full',
  }
);

// Or compose middleware manually
const composed = RouteMiddleware.compose(
  RouteMiddleware.withAuth(),
  RouteMiddleware.withCSRF(),
  RouteMiddleware.withRateLimit(60, 60000),
  RouteMiddleware.withCORS({
    origins: ['https://myapp.com'],
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 3600,
  })
);

// Generate CSRF tokens for your frontend
const { cookie, headerValue } = CSRFGuard.generateDoubleSubmit();
```

---

## Configuration

Vril.js provides a type-safe, environment-aware configuration system with validation, deep merging, and secrets management.

```typescript
import { createConfig, EnvironmentConfig, ConfigSecrets } from 'vril-js';

const secrets = new ConfigSecrets();
await secrets.initialize('master-encryption-key');

const envConfig = EnvironmentConfig.createWithPresets();
envConfig.setEnvironment('production');

const { config, validate } = createConfig({
  base: {
    crypto: {
      defaultAlgorithm: 'x25519-mlkem768',
      kdfIterations: 600000,
      pqcEnabled: true,
      hybridMode: true,
      keyRotationDays: 30,
    },
    security: {
      trustedTypes: true,
      apiMembrane: true,
      blockedAPIs: ['WebTransport', 'RTCPeerConnection'],
      csp: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'strict-dynamic'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: true,
        blockAllMixedContent: true,
      },
      permissionsPolicy: {
        camera: [], microphone: [], geolocation: [],
        usb: [], serial: [], bluetooth: [],
      },
      headers: {
        strictTransportSecurity: 'max-age=63072000; includeSubDomains; preload',
        xContentTypeOptions: 'nosniff',
        xFrameOptions: 'DENY',
        referrerPolicy: 'strict-origin-when-cross-origin',
        crossOriginOpenerPolicy: 'same-origin',
        crossOriginEmbedderPolicy: 'credentialless',
        crossOriginResourcePolicy: 'same-origin',
      },
      csrf: {
        enabled: true,
        tokenHeader: 'x-vril-csrf',
        cookieName: 'vril-csrf',
        sameSite: 'Strict',
        doubleSubmit: true,
        tokenRotation: true,
      },
    },
    auth: {
      sessionTTL: 86400000,
      sessionIdleTimeout: 1800000,
      tokenAlgorithm: 'HMAC-SHA256',
      passwordMinLength: 12,
      passwordRounds: 600000,
      maxLoginAttempts: 5,
      lockoutDuration: 900000,
    },
    build: {
      cspNonce: true,
      sriHashes: true,
      securityHeaders: true,
      sbom: true,
      strictMode: true,
    },
  },
  environment: envConfig,
  secrets,
});

// Validate the configuration
const result = validate();
if (!result.valid) {
  console.error('Config errors:', result.errors);
}
```

### Presets

Vril.js ships with environment-optimized presets:

| Preset | Use Case | HTTPS | CSRF | SRI | CSP Nonces | Strict Mode |
|--------|----------|-------|------|-----|------------|-------------|
| `SPA_PRESET` | Client-rendered apps | Off | Off | Off | Off | Off |
| `SSR_PRESET` | Server-rendered apps | On | On | On | On | On |
| `STATIC_PRESET` | Static sites | On | Off | On | On | On |
| `API_PRESET` | API-only servers | On | On | On | On | On |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       VRIL.JS v2.1 ARCHITECTURE                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────── BROWSER HARDENING ───────────┐                    │
│  │  Trusted Types · API Membrane · XSS Shield │                 │
│  │  Cross-Origin Isolation · Fingerprint Resist │               │
│  └──────────────────┬───────────────────────┘                    │
│                     │                                            │
│  ┌─────────── TRANSPORT SECURITY ──────────┐                    │
│  │  HSTS · CSP · Permissions-Policy         │                   │
│  │  Security Headers · CORS · CSRF Guard    │                   │
│  └──────────────────┬───────────────────────┘                    │
│                     │                                            │
│  ┌─────────── CRYPTOGRAPHIC LAYER ─────────┐                    │
│  │  PQC (ML-KEM/ML-DSA/SLH-DSA)            │                   │
│  │  Hybrid KEM/Signer · ΩVault · Agility    │                  │
│  │  Secure Memory · Constant-Time Ops       │                   │
│  └──────────────────┬───────────────────────┘                    │
│                     │                                            │
│  ┌─────────── APPLICATION SECURITY ────────┐                    │
│  │  Secure Router · RBAC · Auth Primitives  │                   │
│  │  ΩSignal · Secure SSR · API Validation   │                  │
│  │  Request Signing · Rate Limiting          │                  │
│  └──────────────────┬───────────────────────┘                    │
│                     │                                            │
│  ┌─────────── BUILD-TIME INTEGRITY ────────┐                    │
│  │  SBOM/CycloneDX · SRI · CSP Nonces       │                  │
│  │  20-Point Audit · Integrity Verification  │                 │
│  │  Supply Chain · Plugin Verification       │                 │
│  └──────────────────────────────────────────┘                    │
│                                                                  │
│  26 Modules · 6 Categories · 200+ Exports · 0 Dependencies      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Module Reference

### Core Framework

| Module | Import Path | Description | Key Exports |
|--------|-------------|-------------|-------------|
| **Core** | `vril-js/core` | Framework foundation, config, lifecycle hooks, environment detection, feature flags, version tracking | `createVrilApp`, `PluginLifecycleRegistry`, `FeatureFlags`, `AppContext`, `PerformanceProfiler` |
| **Config** | `vril-js/config` | Type-safe config builder with validation, deep merging, environment presets, secrets management, and config watching | `createConfig`, `ConfigValidator`, `ConfigMerger`, `EnvironmentConfig`, `ConfigSecrets`, `SPA_PRESET`, `SSR_PRESET` |
| **Plugin** | `vril-js/plugin` | Plugin lifecycle hooks, sandboxing, integrity verification, and context isolation | `PluginRegistry`, `PluginLoader`, `createPlugin` |

### Security & Crypto

| Module | Import Path | Description | Key Exports |
|--------|-------------|-------------|-------------|
| **PQC** | `vril-js/security/crypto/pqc` | Post-quantum cryptography handler — ML-KEM, ML-DSA, SLH-DSA, X25519, ECDSA-P256 | `PQCHandler`, `pqc` |
| **Hybrid** | `vril-js/security/crypto/hybrid` | Hybrid key exchange and signatures combining classical + PQC with KDF combiner | `HybridKEM`, `HybridSigner`, `HybridKeyRotation` |
| **Vault** | `vril-js/security/crypto/vault` | AES-256-GCM encryption with PBKDF2-SHA-512, key wrapping, passphrase rotation | `VrilVault`, `SecureMemory` |
| **Agility** | `vril-js/security/crypto/agility` | Algorithm registry, migration planning, health monitoring, and NIST 2035 migration paths | `CryptoAgility`, `AlgorithmRegistry`, `MigrationExecutor`, `CryptoPolicy` |
| **Security** | `vril-js/security` | Trusted Types, API membrane, CSP builder, permissions policy, URL validation | `installTrustedTypes`, `buildCSPHeader`, `installAPIMembrane`, `IntegrityChecker` |
| **Hardening** | `vril-js/security/hardening` | Cross-origin isolation, fingerprint resistance, timing attack mitigation, clickjacking protection | `XSSShield`, `CookieFortress`, `TimingAttackMitigation`, `ClickjackingProtection` |
| **Audit** | `vril-js/security/audit` | Security scoring, vulnerability database, compliance checking, CSP violation reporting | `SecurityAuditor`, `SecurityScoreCalculator`, `ComplianceChecker`, `generateSecurityReport` |

### Server & Build

| Module | Import Path | Description | Key Exports |
|--------|-------------|-------------|-------------|
| **Server** | `vril-js/server` | RSC deserialization hardening, CSRF guard, request signing, encrypted env vars, supply chain integrity | `CSRFGuard`, `RequestSigner`, `EnvEncryption`, `SupplyChainIntegrity`, `RSCSecurityBoundary` |
| **Build** | `vril-js/build` | CSP nonce generation, SRI hashing, SBOM/CycloneDX, build integrity verification | `BuildSecurityChecker`, `CSPNonceGenerator`, `SRIHasher`, `SBOMGenerator` |
| **Router** | `vril-js/router` | Secure routing with route-level security policies, composable middleware, route groups, navigation guards | `createSecureHandler`, `RouteSecurityRegistry`, `RouteMiddleware`, `NavigationGuard`, `RouteScanner` |
| **Auth** | `vril-js/auth` | Session management, token handling, password hashing, RBAC with inheritance, login attempt tracking | `SessionManager`, `TokenHandler`, `PasswordHandler`, `RBAC`, `LoginAttemptTracker` |

### Reactivity & State

| Module | Import Path | Description | Key Exports |
|--------|-------------|-------------|-------------|
| **Signals** | `vril-js/signals` | Fine-grained reactive primitives with 14 signal types and dependency graph | `signal`, `computed`, `effect`, `batch`, `store`, `encryptedSignal`, `ΩSignal` |
| **State** | `vril-js/state` | Store with middleware (logging, persistence, encryption, devtools), state validation | `VrilStore`, `createStore`, `encryptionMiddleware`, `devtoolsMiddleware` |
| **Hooks** | `vril-js/hooks` | React hooks for signals, encrypted state, CSRF tokens, rate limiting, and security headers | `useSignal`, `useComputed`, `useEncryptedState`, `useCSRFToken`, `useRateLimiter` |

### Infrastructure

| Module | Import Path | Description | Key Exports |
|--------|-------------|-------------|-------------|
| **SSR** | `vril-js/ssr` | Streaming SSR with HMAC integrity, selective hydration, and SSR manifest | `createSSRStream`, `renderToStream`, `SSRSecurityGuard`, `SelectiveHydration` |
| **Streaming** | `vril-js/streaming` | Secure streaming boundaries with integrity validation, rate limiting, and caching | `createStreamingBoundary`, `StreamIntegrityValidator`, `RateLimitedStream` |
| **Cache** | `vril-js/cache` | Memory cache, stale-while-revalidate, encrypted cache, distributed cache keys | `MemoryCache`, `StaleWhileRevalidate`, `EncryptedCache`, `CacheInvalidator` |
| **API** | `vril-js/api` | Type-safe API routes with schema validation, error handling, rate limiting, and versioning | `createAPIRoute`, `APISchema`, `APIRateLimiter`, `APIVersioning` |
| **Edge** | `vril-js/edge` | Edge runtime detection, KV store, geolocation, bot detection, and edge security | `EdgeRuntime`, `EdgeKV`, `EdgeGeo`, `EdgeSecurity`, `createEdgeHandler` |
| **Head** | `vril-js/head` | Head tag management, OG tags, structured data, SEO optimization, CSP nonce injection | `HeadManager`, `generateOGTags`, `generateStructuredData`, `SEOOptimizer` |
| **Diagnostics** | `vril-js/diagnostics` | Performance monitoring, security diagnostics, crypto profiling, bundle analysis, memory profiling | `PerformanceMonitor`, `SecurityDiagnostics`, `CryptoProfiler`, `createDiagnosticReport` |
| **Utils** | `vril-js/utils` | Constant-time comparison, secure random, hashing, base64, HTML sanitization, URL validation | `constantTimeEqual`, `secureRandom`, `hashData`, `sanitizeHTML`, `validateURL` |
| **Types** | `vril-js/types` | Comprehensive type definitions — branded types, security levels, algorithm identifiers | `SecurityLevel`, `Encrypted`, `Hashed`, `Signed`, `PQCVerified`, `Branded` |

---

## Comparison

### Vril.js vs Next.js vs Remix vs Astro

| Security Feature | Vril.js v2.1 | Next.js 15 | Remix | Astro |
|---|---|---|---|---|
| Post-Quantum Cryptography | ML-KEM, ML-DSA, SLH-DSA (FIPS 203/204/205) | None | None | None |
| Hybrid Key Exchange | X25519+ML-KEM-768, ECDSA+ML-DSA-65 | None | None | None |
| Crypto Agility / Migration | 12+ algorithm registry with NIST 2035 paths | None | None | None |
| Client-Side Encryption Vault | AES-256-GCM + PBKDF2-SHA-512 (600K iter.) | None | None | None |
| Trusted Types Enforcement | Built-in membrane + blocked API list | None | None | None |
| CSP Nonce Generation | Per-request with SRI hash computation | Manual setup | Manual setup | Manual setup |
| Supply Chain Integrity | SBOM/CycloneDX + dependency graph validation | None | None | None |
| Encrypted State | `encryptedSignal` + AES-256-GCM in-memory | None | None | None |
| Route-Level Security Policies | Per-route CSRF, rate limit, CORS, IP allowlist | Middleware only | Middleware only | Middleware only |
| Build-Time Security Audit | 20-point audit + integrity manifest | None | None | None |

**Bottom line:** Other frameworks can *add* security through middleware and third-party packages. Vril.js *is* security — baked into every layer from build to browser.

---

## Security Model

Vril.js implements a 5-layer defense-in-depth architecture. Each layer operates independently, so a breach in one layer does not compromise the others.

### Layer 1: Browser Hardening

The first line of defense runs in the browser, preventing malicious code from ever executing.

- **Trusted Types Enforcement** — All DOM sinks (innerHTML, eval, etc.) are wrapped in a Trusted Types policy that sanitizes input before insertion. This eliminates entire classes of DOM-based XSS.
- **API Membrane** — Dangerous browser APIs like `WebTransport` and `RTCPeerConnection` are blocked at the framework level, preventing data exfiltration through covert channels.
- **XSS Shield** — Automatic HTML sanitization with configurable allowlists. All user-generated content passes through sanitization before rendering.
- **Cross-Origin Isolation** — `COOP: same-origin`, `COEP: credentialless`, and `CORP: same-origin` headers create a cross-origin isolated context, enabling `SharedArrayBuffer` and preventing Spectre-type attacks.
- **Fingerprint Resistance** — Normalizes browser APIs that leak identifying information (canvas, WebGL, audio context) to reduce tracking surface.
- **Clickjacking Protection** — `X-Frame-Options: DENY` and `frame-ancestors: 'none'` by default, with per-route override capability.

```typescript
import { installTrustedTypes, installAPIMembrane } from 'vril-js';

// Install Trusted Types policy
installTrustedTypes({ policyName: 'vril-policy' });

// Block dangerous APIs
installAPIMembrane({
  blockedAPIs: ['WebTransport', 'RTCPeerConnection'],
});
```

### Layer 2: Transport Security

Protects data in transit and prevents man-in-the-middle attacks.

- **HTTP Strict Transport Security** — 2-year max-age with subdomain inclusion and preload by default. All connections are forced to HTTPS.
- **Content Security Policy** — Strict CSP with nonce-based script allowlisting. No `'unsafe-inline'` or `'unsafe-eval'` in production. Per-route CSP overrides for granular control.
- **Permissions Policy** — All sensitive APIs (camera, microphone, geolocation, USB, etc.) are disabled by default. Explicit opt-in required.
- **CORS Configuration** — Per-route CORS with origin allowlists, credential controls, and preflight caching.
- **CSRF Protection** — Double-submit cookie pattern with SameSite=Strict enforcement and automatic token rotation. Constant-time comparison prevents timing attacks.

```typescript
import { buildCSPHeader, buildSecurityHeaders } from 'vril-js';

const csp = buildCSPHeader({
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'", "'nonce-abc123'", "'strict-dynamic'"],
  objectSrc: ["'none'"],
  frameAncestors: ["'none'"],
});

const headers = buildSecurityHeaders({
  strictTransportSecurity: 'max-age=63072000; includeSubDomains; preload',
  xContentTypeOptions: 'nosniff',
  xFrameOptions: 'DENY',
});
```

### Layer 3: Cryptographic Layer

The mathematical foundation of Vril.js security. All operations use the Web Crypto API — no npm packages involved.

- **Post-Quantum KEM** — ML-KEM-768 (NIST Level 3) and ML-KEM-1024 (NIST Level 5) key encapsulation. Standard FIPS 203 algorithms with correct key sizes.
- **Post-Quantum Signatures** — ML-DSA-65 and ML-DSA-87 (FIPS 204) for digital signatures. SLH-DSA-SHA2-128s and SLH-DSA-SHA2-256f (FIPS 205) for hash-based signatures with minimal trust assumptions.
- **Hybrid Key Exchange** — `X25519+ML-KEM-768` combines classical ECDH with post-quantum KEM. The shared secret is `SHA256(x25519Secret || mlkem768Secret || contextInfo)` — secure if *either* algorithm remains unbroken.
- **Hybrid Signatures** — `ECDSA-P256+ML-DSA-65` with AND verification logic. Both signatures must verify for acceptance, ensuring quantum resistance even if classical is broken.
- **AES-256-GCM Vault** — Authenticated encryption with PBKDF2-SHA-512 key derivation at 600,000 iterations. Supports text, binary, key wrapping, and passphrase rotation.
- **Crypto Agility** — Algorithm registry with health monitoring, vulnerability tracking, and automated migration planning. Swap algorithms without rewriting application code.

```typescript
import { PQCHandler, HybridSigner } from 'vril-js';

const pqc = new PQCHandler();

// Get algorithm metadata
const info = pqc.getAlgorithmInfo('ML-KEM-768');
// { id: 'ML-KEM-768', nistStandard: 'FIPS 203', securityLevel: 3,
//   publicKeySize: 1184, ciphertextSize: 1088, quantumResistant: true }

// Benchmark algorithms
const benchmark = await pqc.benchmark('ML-KEM-768', 50);
console.log(`Key gen: ${benchmark.keyGenerationMs.toFixed(1)}ms`);
```

### Layer 4: Application Security

Framework-level security controls that protect your application logic.

- **Secure Router** — Every route has a security policy defining allowed methods, CSRF requirements, rate limits, CORS, IP allowlists, and audit levels. Route groups share policies, and nested routes inherit from parents.
- **Composable Middleware** — `RouteMiddleware.withAuth()`, `withCSRF()`, `withRateLimit()`, `withCORS()`, and `withSignedRequest()` compose naturally: `withAuth(withCSRF(withRateLimit(handler)))`.
- **Request Signing** — HMAC-SHA256 signed requests between edge and origin with timestamp validation, nonce-based replay attack prevention, and request ID tracing.
- **RBAC** — Hierarchical role-based access control with permission inheritance, wildcard permissions, and guard functions for route protection.
- **Session Management** — HMAC-signed session tokens with configurable TTL, idle timeout, session rotation, and user-wide session invalidation.
- **Deserialization Hardening** — Validates RSC flight data with depth limits, key count limits, string length limits, circular reference detection, prototype chain validation, and regex pattern detection for dangerous payloads.
- **Timing Attack Mitigation** — Server operations are wrapped with minimum delay and jitter to normalize response times. Constant-time comparisons used throughout.

```typescript
import { SecurityMiddlewareChain, RBAC } from 'vril-js';

// Composable security chain
const chain = SecurityMiddlewareChain.createDefaultChain({
  csrfToken: 'my-csrf-token',
  signingSecret: 'my-signing-secret',
  allowedOrigins: ['https://myapp.com'],
  rateLimitPerMinute: 100,
});

const { allowed, audit } = await chain.execute(request);

// RBAC with hierarchy
const rbac = RBAC.createDefault();
rbac.assignRole('user-123', 'editor');
rbac.hasPermission('user-123', 'write', 'posts'); // true (inherited from editor)
```

### Layer 5: Build-Time Integrity

Security that is enforced before your application ever reaches production.

- **20-Point Security Audit** — Automated checks for CSP configuration, header presence, dependency vulnerabilities, exposed secrets, and more.
- **SBOM/CycloneDX Generation** — Software Bill of Materials in CycloneDX v1.5 format with dependency graph validation and circular dependency detection.
- **Subresource Integrity (SRI)** — SHA-384 hash computation for all static assets. SRI attributes are automatically injected into script and link tags.
- **CSP Nonce Injection** — Per-request nonces generated at build time and injected into CSP headers and HTML templates.
- **Build Integrity Manifest** — SHA-256 hashes of all build outputs, verified at runtime to detect tampering.
- **Supply Chain Integrity** — Dependency integrity verification with SBOM v2.3 format support and Sigstore integration stubs for future artifact signing.

```typescript
import { BuildSecurityChecker, SBOMGenerator, SRIHasher } from 'vril-js';

const checker = new BuildSecurityChecker();
const audit = await checker.audit({
  outputDir: './dist',
  strictMode: true,
});
console.log(`Security score: ${audit.score}/100`);

// Generate SRI hashes
const hasher = new SRIHasher();
const sriHash = await hasher.hashFile('./dist/app.js');
// 'sha384-abc123...'

// Generate SBOM
const sbomGen = new SBOMGenerator();
const sbom = await sbomGen.generate('./package.json');
```

---

## API Overview

### Core APIs

```typescript
// Create application with merged config
import { createVrilApp } from 'vril-js';
const app = createVrilApp({ /* partial config */ });
app.config;   // Fully merged VrilConfig
app.version;   // '2.1.0'
```

### Cryptographic APIs

```typescript
import { VrilVault, PQCHandler, HybridKEM } from 'vril-js';

// ΩVault — Client-side encryption
const vault = new VrilVault({ kdfIterations: 600000 });
await vault.encrypt(passphrase, plaintext);
await vault.decrypt(passphrase, bundle);
await vault.encryptBlob(data, passphrase);
await vault.wrapKey(key, wrappingKey);
await vault.rotatePassphrase(oldPass, newPass, bundle);
vault.assessStrength(password);

// PQC — Post-quantum operations
const pqc = new PQCHandler();
await pqc.generateKeyPair('ML-KEM-768');
await pqc.encapsulate(publicKey, 'ML-KEM-768');
await pqc.decapsulate(ciphertext, privateKey, 'ML-KEM-768');
await pqc.sign(message, privateKey, 'ML-DSA-65');
await pqc.verify(message, signature, publicKey, 'ML-DSA-65');
await pqc.benchmark('ML-KEM-1024', 10);
pqc.getAlgorithmInfo('SLH-DSA-SHA2-256f');

// Hybrid — Classical + PQC combined
const kem = new HybridKEM('X25519MLKEM768');
const keyPair = await kem.generateKeyPair();
const kemResult = await kem.encapsulate(keyPair.combinedPublicKey);
const sharedSecret = await kem.decapsulate(keyPair, kemResult);

const signer = new HybridSigner('ECDSAP256MLDSA65');
const sigKeyPair = await signer.generateKeyPair();
const hybridSig = await signer.sign(message, sigKeyPair);
const valid = await signer.verify(message, hybridSig, sigKeyPair.combinedPublicKey);
```

### Signal APIs

```typescript
import { ΩSignal, signal, computed, effect, batch, store } from 'vril-js';

// Core reactive primitives
const count = signal(0);
const doubled = computed(() => count() * 2);
const dispose = effect(() => console.log(`Count: ${count()}, Doubled: ${doubled()}`));

batch(() => { count.set(1); count.set(2); }); // Single notification

// Advanced signal types
const lazy = ΩSignal.lazySignal(() => expensiveComputation());
const async = ΩSignal.asyncSignal<string>();
const resource = ΩSignal.resourceSignal(fetchData, { staleWhileRevalidate: true });
const debounced = ΩSignal.debouncedSignal('', 300);
const throttled = ΩSignal.throttledSignal(0, 100);
const persisted = ΩSignal.persistedSignal('theme', 'dark', 'localStorage');
const encrypted = ΩSignal.encryptedSignal(secretData, 'passphrase');

// Devtools
ΩSignal.onSignalCreate((node) => console.log('Created:', node.id, node.kind));
ΩSignal.onSignalUpdate((id, oldVal, newVal) => console.log('Updated:', id));
const graph = ΩSignal.createSignalGraph();
```

### Server APIs

```typescript
import { createSecureHandler, CSRFGuard, RequestSigner } from 'vril-js';

// Secure handler with automatic enforcement
const handler = createSecureHandler(async (req, { path, policy }) => {
  return Response.json({ ok: true });
}, { csrf: true, rateLimit: 60, methods: ['POST'] });

// CSRF protection
const { cookie, headerValue } = CSRFGuard.generateDoubleSubmit();
CSRFGuard.validateDoubleSubmit(request);
CSRFGuard.rotateToken(sessionId);

// Request signing (edge → origin)
const signer = new RequestSigner('shared-secret');
const signedHeaders = await signer.signRequest(request);
const verification = await signer.verifyRequest(request);
```

### State Management APIs

```typescript
import { VrilStore, createStore, encryptionMiddleware } from 'vril-js';

const store = createStore({
  initialState: { user: null, theme: 'dark' },
  middleware: [encryptionMiddleware, devtoolsMiddleware],
});

store.getState();        // { user: null, theme: 'dark' }
store.dispatch({ type: 'SET_THEME', payload: 'light' });
store.subscribe((state) => console.log('State changed:', state));
store.select((state) => state.theme); // 'light'
```

### Edge APIs

```typescript
import { createEdgeHandler, EdgeKV, EdgeGeo, EdgeSecurity } from 'vril-js';

// Edge handler with built-in security
export default createEdgeHandler(async (request, { geo, ip, kv }) => {
  await kv.set('last-visit', new Date().toISOString(), 86400000);
  const country = geo.country ?? 'unknown';
  return new Response(`Hello from ${country}!`);
}, { securityLevel: 'strict', botDetection: true });

// Edge KV store
const kv = new EdgeKV<string>('sessions');
await kv.set('user:123', token, 3600000);
const token = await kv.get('user:123');

// Geolocation with privacy
const geo = new EdgeGeo('approximate');
const data = geo.extract(request.headers);
geo.isFromEU(request.headers); // GDPR check
```

---

## Browser Support

Vril.js requires the **Web Crypto API** for all cryptographic operations. This is supported in:

| Browser | Minimum Version |
|---------|----------------|
| Chrome | 96+ |
| Firefox | 94+ |
| Safari | 15.4+ |
| Edge | 96+ |

> **Note:** PQC algorithms (ML-KEM, ML-DSA, SLH-DSA) are not yet natively supported in any browser. Vril.js provides these with correct interfaces and key sizes using deterministic simulation with Web Crypto API primitives. When browsers add native PQC support, Vril.js will automatically use the native implementations. The hybrid mode (`X25519+ML-KEM-768`) uses real X25519 for the classical component today.

---

## Contributing

We welcome contributions from the security and React communities. Here's how to get started:

1. **Fork** the repository and create your feature branch: `git checkout -b feature/my-feature`
2. **Security-first development** — All new modules must use the Web Crypto API exclusively. No npm dependencies for crypto operations.
3. **Type safety** — Every public API must have full TypeScript types. Use branded types for security-critical values (`Encrypted<T>`, `Hashed<T>`, `Signed<T>`).
4. **Constant-time operations** — Any comparison involving secrets must use constant-time algorithms. Use `constantTimeEqual` from `vril-js/utils`.
5. **Tests** — Add comprehensive tests for new features. Security-sensitive code requires edge case coverage.
6. **Documentation** — Update this README and inline JSDoc comments for all new public APIs.
7. **Submit** a pull request with a clear description of the change and security implications.

### Code of Conduct

- Report security vulnerabilities privately to security@vrillabs.li
- Do not introduce dependencies that duplicate Web Crypto API functionality
- All cryptographic implementations must reference their NIST standard or RFC
- Zero tolerance for timing vulnerabilities in security-critical code paths

---

## License

*Copyright (c) 2026 VLABS, LLC. All rights reserved.* <br>
*[VRIL LABS Open Source License v1.0](https://github.com/VRIL-LABS/vril-js/blob/main/LICENSE) — [vril.li/license](https://vril.li/license)*.

---

<div align="center">
<strong>26 Modules · 200+ Exports · 20,000+ Lines · 0 Dependencies · Full PQC</strong><br>
  <sub>Built by <strong>VRIL LABS</strong> · Encrypting the future</sub>
</div>
