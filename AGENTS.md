# AGENTS.md — Vril.js AI Coding Agent Guide

> Universal instruction file for all AI coding agents (GitHub Copilot, Claude, Gemini, Codex, Cursor, etc.) working on the `vril-js` repository. This is the single source of truth — keep it current.

---

## Project Overview

**Vril.js** (`@vrillabs/vril-js`) is a security-first React framework with a built-in Vril runtime. It provides:

- Post-quantum cryptography (ML-KEM-768/1024, ML-DSA-65/87, SLH-DSA) via bundled zero-dependency FIPS 203/204/205 implementations
- Zero-trust security membrane (Trusted Types, API blocking, CSP Level 3, Permissions Policy)
- Hybrid key exchange (X25519+ML-KEM-768) and hybrid signing (ECDSA-P256+ML-DSA-65)
- Crypto agility with 12+ algorithm registry and NIST 2035 migration paths
- ΩSignal fine-grained reactive primitives (14 signal types)
- Secure SSR, streaming, edge runtime, plugin architecture
- 26 modules · 200+ exports · 0 runtime npm dependencies for the security/PQC core

**Stack:** Vril Runtime · React 19 · TypeScript 5 · Tailwind CSS v4 · ESLint 9  
**npm:** `@vrillabs/vril-js` — https://www.npmjs.com/package/@vrillabs/vril-js  
**Deployed at:** https://vril-js.vercel.app

> **Important:** This project uses the built-in **Vril runtime** (not Next.js). Never add `next/` imports.

---

## Essential Commands

```bash
npm install          # Install dependencies (node_modules not in git)
npm run dev          # Development server (http://localhost:3000)
npm run build        # Production build
npm run start        # Start production server
npm run lint         # ESLint 9 flat config
npx tsc --noEmit    # TypeScript type-check (0 errors expected)
```

**Pre-merge checklist:** `npm install && npx tsc --noEmit && npm run lint && npm run build` must all pass with zero errors.

---

## Repository Structure

```
vril-js/
├── src/
│   ├── app/               # Vril runtime pages, layout, and API handlers
│   │   ├── api/           # API route handlers (route.ts files)
│   │   ├── docs/          # Documentation page (/docs)
│   │   ├── globals.css    # Global styles (Tailwind v4 + design tokens)
│   │   ├── layout.tsx     # Root layout with font definitions
│   │   └── page.tsx       # Landing page (/)
│   ├── components/        # Shared React components
│   ├── hooks/             # Custom React hooks
│   ├── lib/
│   │   ├── utils.ts       # cn() utility helper
│   │   └── vril/          # Core Vril.js library (all 26 modules)
│   │       ├── api/       # Type-safe API routes, schema validation, rate limiting
│   │       ├── auth/      # Session, token, password hashing, RBAC
│   │       ├── build/     # CSP nonces, SRI hashes, SBOM, build integrity
│   │       ├── cache/     # Memory cache, stale-while-revalidate, encrypted cache
│   │       ├── config/    # defineVrilConfig, createConfig, environment presets
│   │       ├── core/      # App lifecycle, feature flags, performance profiler
│   │       ├── diagnostics/ # Performance, security diagnostics, crypto profiler
│   │       ├── edge/      # Edge KV, geolocation, bot detection, edge security
│   │       ├── framework/ # Built-in Vril runtime CLI (dev/build/start)
│   │       ├── head/      # Head/meta management, OG tags, SEO, CSP nonce inject
│   │       ├── hooks/     # React hooks for signals, auth, CSRF, security headers
│   │       ├── openapi/   # OpenAPI spec generation from route manifests
│   │       ├── plugin/    # Plugin registry, lifecycle hooks, sandboxing
│   │       ├── router/    # Secure routing, composable middleware, route groups
│   │       ├── security/  # Trusted Types, CSP, hardening, audit, PQC/crypto
│   │       ├── server/    # CSRF guard, request signing, RSC deserialization hardening
│   │       ├── signals/   # ΩSignal reactive primitives (14 signal types)
│   │       ├── ssr/       # Streaming SSR, selective hydration, SSR manifest
│   │       ├── state/     # VrilStore, middleware (logging, persistence, encryption)
│   │       ├── streaming/ # Secure streaming boundaries, integrity, rate limiting
│   │       ├── types/     # Shared TypeScript types (branded, security levels)
│   │       ├── utils/     # Constant-time ops, secure random, base64, URL validation
│   │       ├── index.ts   # Root barrel export (single entry point for all modules)
│   │       └── version.ts # VRIL_VERSION constant
│   └── proxy.ts           # Vril security proxy (security headers on every response)
├── public/                # Static assets
├── vril.config.ts         # User-facing Vril.js configuration
├── vril-env.d.ts          # Env variable + global type declarations
├── eslint.config.mjs      # ESLint 9 flat config
├── postcss.config.mjs     # PostCSS (Tailwind CSS v4)
├── tsconfig.json          # TypeScript configuration
└── vercel.json            # Vercel deployment configuration
```

---

## Key Files

| File | Purpose |
|------|---------|
| `vril.config.ts` | User-facing framework config (security, crypto, router, server, auth, build) |
| `src/proxy.ts` | Vril security proxy — injects HSTS, CSP, CORP, COOP, COEP, Permissions-Policy, Referrer-Policy |
| `src/lib/vril/index.ts` | Root barrel — single source of all public exports |
| `src/lib/vril/framework/cli.mjs` | Built-in Vril runtime CLI (runs dev/build/start) |
| `src/app/page.tsx` | Landing/showcase page served at `/` |
| `src/app/docs/page.tsx` | Full documentation page served at `/docs` |
| `vril-env.d.ts` | TypeScript declarations for env vars and global augmentations |

---

## Code Conventions

### TypeScript
- **Strict mode** is enabled — avoid `any`; use `unknown` with type guards instead
- Use `type` imports for type-only references: `import { type Foo } from './foo'`
- Prefer `interface` for extendable object shapes, `type` for unions/intersections
- All public functions and exports must have explicit return types

### Imports and Path Aliases
- Path alias `@/*` maps to `src/*` — use `import { cn } from '@/lib/utils'`
- Within this repo, import Vril modules via `@/lib/vril/...` (direct submodule paths)
- Route handlers use `import { json } from '@/lib/vril/framework'`
- Do **not** use relative `../../../` paths when `@/` aliases work

### React / Vril Runtime
- Mark client components with `'use client'` at the top of the file; server components are the default
- Route handlers live at `src/app/api/<name>/route.ts` and export `GET`, `POST`, etc.
- The `src/proxy.ts` `proxy` function runs before all route handling — edit with care
- **Never add `next/` imports** — this project uses the built-in Vril runtime, not Next.js

### File Naming
- React components: `kebab-case.tsx`
- Utility modules: `kebab-case.ts`
- Route handlers: `route.ts` inside `src/app/api/...`

### Styling
- Use **Tailwind CSS v4** utility classes throughout
- Design tokens are defined in `src/app/globals.css` under `@theme inline`
- Custom color names: `olo-teal`, `ionic-blue`, `void-indigo`, `cerulean-arc`, `arctic-mist`, `deep-void`, `ghost-haze`
- Use the `cn()` utility from `@/lib/utils` for conditional class merging

---

## Security Rules (Non-Negotiable)

- **Never add `'unsafe-eval'`** to any CSP directive
- **Never use `node:crypto`** or third-party crypto libraries — all crypto must go through `src/lib/vril/security/` using the Web Crypto API
- **`trustedTypes: true`** in `vril.config.ts` must not be disabled
- **`apiMembrane: true`** in `vril.config.ts` must not be disabled
- New API routes must validate request origins and enforce CSRF protection
- Comparisons involving secrets must use `constantTimeEqual` from `@/lib/vril/utils`
- New environment secrets must be declared in `vril-env.d.ts` under `NodeJS.ProcessEnv`; prefix with `VRIL_`
- PQC operations use the bundled `nativePQCProvider` by default — do not replace with unverified providers
- Do not introduce npm dependencies that duplicate Web Crypto API functionality

---

## Module Reference

| Module | Subpath (within repo) | Key Exports |
|--------|-----------------------|-------------|
| **Core** | `@/lib/vril/core` | `createVrilApp`, `PluginLifecycleRegistry`, `FeatureFlags`, `AppContext`, `PerformanceProfiler` |
| **Config** | `@/lib/vril/config` | `createConfig`, `defineVrilConfig`, `ConfigValidator`, `EnvironmentConfig`, `ConfigSecrets`, `SPA_PRESET`, `SSR_PRESET`, `STATIC_PRESET`, `API_PRESET` |
| **Plugin** | `@/lib/vril/plugin` | `PluginRegistry`, `PluginLoader`, `createPlugin` |
| **PQC** | `@/lib/vril/security/crypto/pqc` | `PQCHandler`, `nativePQCProvider`, `pqc` |
| **Hybrid** | `@/lib/vril/security/crypto/hybrid` | `HybridKEM`, `HybridSigner`, `HybridKeyRotation` |
| **Active Surface PQC** | `@/lib/vril/security/crypto/active-surface-pqc` | `ActiveSurfacePQC` |
| **Vault** | `@/lib/vril/security/crypto/vault` | `VrilVault`, `SecureMemory` |
| **Agility** | `@/lib/vril/security/crypto/agility` | `CryptoAgility`, `AlgorithmRegistry`, `MigrationExecutor`, `CryptoPolicy` |
| **Security** | `@/lib/vril/security` | `installTrustedTypes`, `buildCSPHeader`, `installAPIMembrane`, `IntegrityChecker` |
| **Hardening** | `@/lib/vril/security/hardening` | `XSSShield`, `CookieFortress`, `TimingAttackMitigation`, `ClickjackingProtection`, `CrossOriginIsolation` |
| **Audit** | `@/lib/vril/security/audit` | `SecurityAuditor`, `SecurityScoreCalculator`, `ComplianceChecker`, `generateSecurityReport` |
| **Server** | `@/lib/vril/server` | `CSRFGuard`, `RequestSigner`, `EnvEncryption`, `SupplyChainIntegrity`, `RSCSecurityBoundary`, `SecurityMiddlewareChain` |
| **Build** | `@/lib/vril/build` | `BuildSecurityChecker`, `CSPNonceGenerator`, `SRIHasher`, `SBOMGenerator`, `BuildIntegrityVerifier` |
| **Router** | `@/lib/vril/router` | `createSecureHandler`, `RouteSecurityRegistry`, `RouteMiddleware`, `NavigationGuard`, `RouteScanner` |
| **Auth** | `@/lib/vril/auth` | `SessionManager`, `TokenHandler`, `PasswordHandler`, `RBAC`, `LoginAttemptTracker` |
| **Signals** | `@/lib/vril/signals` | `signal`, `computed`, `effect`, `batch`, `store`, `encryptedSignal`, `ΩSignal` (14 signal types total) |
| **State** | `@/lib/vril/state` | `VrilStore`, `createStore`, `encryptionMiddleware`, `devtoolsMiddleware`, `persistenceMiddleware` |
| **Hooks** | `@/lib/vril/hooks` | `useSignal`, `useComputed`, `useEncryptedState`, `useCSRFToken`, `useRateLimiter`, `useVrilConfig` |
| **SSR** | `@/lib/vril/ssr` | `createSSRStream`, `renderToStream`, `SSRSecurityGuard`, `SelectiveHydration`, `SSRManifest` |
| **Streaming** | `@/lib/vril/streaming` | `createStreamingBoundary`, `StreamIntegrityValidator`, `RateLimitedStream`, `SecureStreamTransformer` |
| **Cache** | `@/lib/vril/cache` | `MemoryCache`, `StaleWhileRevalidate`, `EncryptedCache`, `CacheInvalidator`, `distributedCacheKey` |
| **API** | `@/lib/vril/api` | `createAPIRoute`, `APISchema`, `APIRateLimiter`, `APIVersioning`, `APIErrorHandler`, `APIError` |
| **Edge** | `@/lib/vril/edge` | `EdgeRuntime`, `EdgeKV`, `EdgeGeo`, `EdgeSecurity`, `createEdgeHandler` |
| **Head** | `@/lib/vril/head` | `HeadManager`, `generateOGTags`, `generateStructuredData`, `SEOOptimizer`, `CSPNonceInjector` |
| **Diagnostics** | `@/lib/vril/diagnostics` | `PerformanceMonitor`, `SecurityDiagnostics`, `CryptoProfiler`, `BundleAnalyzer`, `createDiagnosticReport` |
| **Utils** | `@/lib/vril/utils` | `constantTimeEqual`, `secureRandom`, `hashData`, `sanitizeHTML`, `validateURL`, `encodeBase64`, `deepFreeze` |
| **Types** | `@/lib/vril/types` | `SecurityLevel`, `Encrypted`, `Hashed`, `Signed`, `PQCVerified`, `Branded`, `Nominal` |
| **OpenAPI** | `@/lib/vril/openapi` | `generateOpenAPISpec`, `discoverRoutesFromManifest` |
| **Framework** | `@/lib/vril/framework` | `json`, `VrilRouteContext`, `VrilRouteHandler` (Vril runtime internals) |

---

## Environment Variables

- Declare all new environment variables in `vril-env.d.ts` under the `NodeJS.ProcessEnv` interface
- Prefix Vril-specific secrets with `VRIL_`
- Never commit `.env` files — use `.env.local` locally and Vercel Environment Variables in production
- The built-in runtime reads `PORT` and `HOST` for server binding

---

## Testing

No test runner is currently configured. When adding tests, use **Vitest** (compatible with Vril runtime and TypeScript 5). Place test files alongside source files as `*.test.ts` / `*.test.tsx`.

---

## Pull Request Guidelines

- Keep PRs focused and small
- Run `npx tsc --noEmit && npm run lint && npm run build` before submitting
- Security-sensitive changes require an explicit justification comment
- Do not lower TypeScript strictness or disable ESLint rules without justification
- Do not introduce npm dependencies for cryptographic operations
- Update inline JSDoc for any changed public APIs

---

## What Agents Must Never Do

- Add `'unsafe-eval'` or `'unsafe-inline'` to any CSP directive
- Use `next/` imports — use Vril runtime equivalents instead
- Introduce third-party crypto dependencies (`bcrypt`, `noble-*`, `tweetnacl`, etc.)
- Disable `trustedTypes`, `apiMembrane`, or CSRF protection in `vril.config.ts`
- Use `node:crypto` — Web Crypto API + bundled PQC only
- Commit secrets or `.env` files
- Weaken TypeScript strict settings in `tsconfig.json`
- Create helper scripts or workarounds in the repo root instead of using standard tooling

