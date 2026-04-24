# CLAUDE.md — Vril.js Claude AI Guide

> This file contains instructions and project context for Claude when working on the `vril-js` repository.

---

## Quick Reference

```bash
npm run dev      # Start dev server on http://localhost:3000
npm run build    # Production build
npm run lint     # ESLint 9 flat config
npm install      # Install dependencies
```

TypeScript check (no emit):
```bash
npx tsc --noEmit
```

---

## Project Summary

Vril.js is a security-first React framework built on **Next.js 16** with:
- Post-quantum cryptography (ML-KEM-768, ML-DSA-65) — zero dependencies, Web Crypto API only
- Zero-trust security membrane: Trusted Types, API membrane, CSP Level 3, Permissions Policy
- Hybrid key exchange and crypto agility for NIST 2035 migration
- 22 modules, 200+ exports

**Key files:**
| File | Purpose |
|------|---------|
| `vril.config.ts` | User-facing framework config (security, crypto, router, server, auth) |
| `src/proxy.ts` | Next.js proxy — applies security headers to every response |
| `src/lib/vril/` | Core library — all 22 Vril.js modules live here |
| `src/app/page.tsx` | Landing/showcase page (served at `/`) |
| `src/app/docs/page.tsx` | Full documentation page (served at `/docs`) |
| `vril-env.d.ts` | TypeScript declarations for env vars and global augmentations |

---

## Architecture

```
Request → src/proxy.ts (security headers + CSRF block)
        → Next.js App Router
        → src/app/layout.tsx (root layout, fonts)
        → src/app/page.tsx  OR  src/app/docs/page.tsx
        → src/components/*  (shared UI)
        → src/lib/vril/*    (Vril.js library)
```

The `src/proxy.ts` file exports a `proxy` function (equivalent to Next.js middleware) that runs before every request and injects HSTS, CSP, CORP, COOP, COEP, Permissions-Policy, and Referrer-Policy headers.

---

## Conventions

### Strict Security Rules
- **Never add `'unsafe-eval'`** to CSP
- All crypto must go through `src/lib/vril/security/` — Web Crypto API only, no third-party crypto
- `trustedTypes: true` in `vril.config.ts` must not be disabled
- New environment secrets must be declared in `vril-env.d.ts`

### TypeScript
- Strict mode enabled — `any` is a warning, `unknown` with type guards is preferred
- Type-only imports: `import { type Foo } from './foo'`
- All public exports have explicit return types

### Imports
- Path alias `@/*` maps to `src/*`
- Example: `import { cn } from '@/lib/utils'`

### Styling
- Tailwind CSS v4 with `@tailwindcss/postcss`
- Design tokens in `src/app/globals.css` (`@theme inline`)
- `cn()` helper from `src/lib/utils.ts` for conditional classes

### Component Pattern
```tsx
// Server component (default)
export default function MyPage() { ... }

// Client component
'use client';
export default function MyComponent() { ... }
```

---

## Common Tasks

### Add a new API route
Create `src/app/api/<route-name>/route.ts`:
```ts
import { NextResponse } from 'next/server';
export async function GET() {
  return NextResponse.json({ ... });
}
```

### Add environment variable
1. Add to `vril-env.d.ts` under `NodeJS.ProcessEnv`
2. Set in `.env.local` for local dev
3. Set in Vercel Dashboard > Settings > Environment Variables for production

### Update Vril.js config
Edit `vril.config.ts` — all options are documented inline. Use `defineVrilConfig()` wrapper.

---

## Deployment

The app is deployed on **Vercel**. See `vercel.json` for configuration. Deployments are triggered automatically on push to `main`.

For local production preview:
```bash
npm run build && npm run start
```
