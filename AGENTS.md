# AGENTS.md — Vril.js Coding Agent Guide

> This file provides instructions and conventions for AI coding agents (GitHub Copilot, etc.) working on the `vril-js` repository.

---

## Project Overview

**Vril.js** is a security-first React framework built on top of Next.js. It provides:

- Post-quantum cryptography (ML-KEM-768, ML-DSA-65) via the Web Crypto API
- Zero-trust security membrane (Trusted Types, API blocking, CSP Level 3)
- Hybrid key exchange and crypto agility (NIST 2035 migration path)
- 22 security modules, 200+ exports, zero runtime dependencies

**Stack:** Next.js 16 · React 19 · TypeScript 5 · Tailwind CSS v4 · ESLint 9

---

## Repository Structure

```
vril-js/
├── src/
│   ├── app/               # Next.js App Router pages and layouts
│   │   ├── api/           # API route handlers
│   │   ├── docs/          # Documentation page
│   │   ├── globals.css    # Global styles (Tailwind v4 + design tokens)
│   │   ├── layout.tsx     # Root layout with font definitions
│   │   └── page.tsx       # Landing page / showcase
│   ├── components/        # Shared React components
│   ├── hooks/             # Custom React hooks
│   ├── lib/
│   │   ├── utils.ts       # Utility functions (cn, etc.)
│   │   └── vril/          # Core Vril.js library modules
│   │       ├── api/       # API utilities
│   │       ├── auth/      # Authentication primitives
│   │       ├── build/     # Build-time helpers
│   │       ├── cache/     # Caching layer
│   │       ├── config/    # Configuration (defineVrilConfig)
│   │       ├── security/  # Security modules (crypto, hardening, audit)
│   │       ├── router/    # Secure routing
│   │       ├── server/    # Server utilities
│   │       ├── state/     # Reactive state management
│   │       └── types/     # Shared TypeScript types
│   └── proxy.ts           # Next.js security proxy (runs on all routes)
├── public/                # Static assets
├── vril.config.ts         # User-facing Vril.js configuration
├── eslint.config.mjs      # ESLint 9 flat config
├── postcss.config.mjs     # PostCSS (Tailwind CSS v4)
├── tsconfig.json          # TypeScript configuration
├── vril-env.d.ts          # Environment variable and global type declarations
└── vercel.json            # Vercel deployment configuration
```

---

## Essential Commands

```bash
# Install dependencies
npm install

# Start the development server
npm run dev

# Build for production
npm run build

# Start the production server
npm run start

# Lint the codebase
npm run lint
```

---

## Code Conventions

### TypeScript
- **Strict mode** is enabled — avoid `any` unless absolutely necessary (use `unknown` with type guards instead)
- Use `type` imports for type-only references: `import { type Foo } from './foo'`
- Prefer `interface` for object shapes that may be extended, `type` for unions/intersections
- All public functions and exports must have explicit return types

### React / Next.js
- Use the **App Router** exclusively (`src/app/`); the Pages Router is not used
- Mark client components with `'use client'` at the top of the file; server components are the default
- The `src/proxy.ts` file is the Next.js middleware equivalent — edit with care as it applies security headers globally

### Security (Critical)
- **Never weaken security defaults** in `vril.config.ts` without a documented reason
- All cryptographic operations must use the **Web Crypto API** — do not introduce `node:crypto` or third-party crypto libraries
- CSP directives must not include `'unsafe-eval'`
- Trusted Types enforcement (`trustedTypes: true`) must remain enabled
- New API routes must validate request origins and enforce CSRF protection

### Styling
- Use **Tailwind CSS v4** utility classes throughout
- Design tokens are defined in `src/app/globals.css` under `@theme inline`
- Custom color names: `olo-teal`, `ionic-blue`, `void-indigo`, `cerulean-arc`, `arctic-mist`, `deep-void`, `ghost-haze`
- Use the `cn()` utility from `src/lib/utils.ts` for conditional class merging

### File Naming
- React components: `kebab-case.tsx`
- Utility modules: `kebab-case.ts`
- Route handlers: `route.ts` inside `app/api/...`

---

## Environment Variables

Declare all new environment variables in `vril-env.d.ts` under the `NodeJS.ProcessEnv` interface before using them. Prefix Vril-specific secrets with `VRIL_`. Never commit `.env` files — use `.env.local` locally and Vercel Environment Variables in production.

---

## Testing

Currently there is no test runner configured. When adding tests, use **Vitest** (compatible with Next.js and TypeScript 5) placed alongside source files as `*.test.ts` / `*.test.tsx`.

---

## Pull Request Guidelines

- Keep PRs focused and small
- Update `CHANGELOG.md` (if it exists) for user-facing changes
- Do not lower TypeScript strictness or disable ESLint rules without justification
- Security-sensitive changes require an explicit justification comment
