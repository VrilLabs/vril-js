'use client';

import { useState, useCallback, type ReactNode } from 'react';
import Link from 'next/link';

// ─── Types ──────────────────────────────────────────────────────
interface DocSection {
  id: string;
  label: string;
  category?: string;
}

const SECTIONS: DocSection[] = [
  { id: 'intro', label: 'Introduction', category: 'Getting Started' },
  { id: 'install', label: 'Installation', category: 'Getting Started' },
  { id: 'config', label: 'Configuration', category: 'Getting Started' },
  { id: 'quickstart', label: 'Quick Start', category: 'Getting Started' },
  { id: 'core', label: 'vril/core', category: 'Core' },
  { id: 'config-mod', label: 'vril/config', category: 'Core' },
  { id: 'plugin', label: 'vril/plugin', category: 'Core' },
  { id: 'types', label: 'vril/types', category: 'Core' },
  { id: 'security', label: 'vril/security', category: 'Security' },
  { id: 'vault', label: 'vril/security/crypto/vault', category: 'Security' },
  { id: 'pqc', label: 'vril/security/crypto/pqc', category: 'Security' },
  { id: 'hybrid', label: 'vril/security/crypto/hybrid', category: 'Security' },
  { id: 'agility', label: 'vril/security/crypto/agility', category: 'Security' },
  { id: 'hardening', label: 'vril/security/hardening', category: 'Security' },
  { id: 'audit', label: 'vril/security/audit', category: 'Security' },
  { id: 'signals', label: 'vril/signals', category: 'Data' },
  { id: 'state', label: 'vril/state', category: 'Data' },
  { id: 'hooks', label: 'vril/hooks', category: 'Data' },
  { id: 'cache', label: 'vril/cache', category: 'Data' },
  { id: 'server', label: 'vril/server', category: 'Server & Build' },
  { id: 'build', label: 'vril/build', category: 'Server & Build' },
  { id: 'router', label: 'vril/router', category: 'Server & Build' },
  { id: 'auth', label: 'vril/auth', category: 'Server & Build' },
  { id: 'api', label: 'vril/api', category: 'Server & Build' },
  { id: 'ssr', label: 'vril/ssr', category: 'Platform' },
  { id: 'streaming', label: 'vril/streaming', category: 'Platform' },
  { id: 'edge', label: 'vril/edge', category: 'Platform' },
  { id: 'head', label: 'vril/head', category: 'Platform' },
  { id: 'diagnostics', label: 'vril/diagnostics', category: 'Platform' },
  { id: 'utils', label: 'vril/utils', category: 'Platform' },
];

// ─── Code Block Component ───────────────────────────────────────
function Code({ children, lang = 'ts' }: { children: string; lang?: string }) {
  return (
    <div className="relative rounded-xl overflow-hidden my-4">
      <div className="flex items-center justify-between px-4 py-2 bg-[#111520] border-b border-white/6">
        <span className="font-mono text-[10px] tracking-[0.14em] uppercase text-white/25">{lang}</span>
      </div>
      <pre className="px-5 py-4 bg-[#0a0c10] overflow-x-auto text-sm leading-relaxed font-mono text-[#c8d0e0]">
        {children}
      </pre>
    </div>
  );
}

// ─── Export Table Component ──────────────────────────────────────
function ExportTable({ rows }: { rows: [string, string, string][] }) {
  return (
    <div className="overflow-x-auto my-4 rounded-xl border border-white/8">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-[#111520] border-b border-white/8">
            <th className="text-left px-4 py-2.5 font-mono text-[10px] tracking-[0.14em] uppercase text-[#00FFC8]">Export</th>
            <th className="text-left px-4 py-2.5 font-mono text-[10px] tracking-[0.14em] uppercase text-[#00FFC8]">Type</th>
            <th className="text-left px-4 py-2.5 font-mono text-[10px] tracking-[0.14em] uppercase text-[#00FFC8]">Description</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([name, type, desc], i) => (
            <tr key={name} className={`border-b border-white/4 ${i % 2 ? 'bg-white/[0.02]' : ''}`}>
              <td className="px-4 py-2 font-mono text-[#00FFC8] text-xs">{name}</td>
              <td className="px-4 py-2 font-mono text-[#f5a623] text-xs">{type}</td>
              <td className="px-4 py-2 text-white/60">{desc}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Section Component ──────────────────────────────────────────
function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section id={id} className="scroll-mt-24 pb-12 mb-12 border-b border-white/6 last:border-0">
      <h2 className="text-2xl font-bold text-white mb-2 font-[family-name:var(--font-display)]">{title}</h2>
      {children}
    </section>
  );
}

// ─── Security Note Component ────────────────────────────────────
function SecurityNote({ children }: { children: ReactNode }) {
  return (
    <div className="flex gap-3 p-4 my-4 rounded-xl bg-[#f5a623]/8 border border-[#f5a623]/20">
      <span className="text-[#f5a623] text-lg flex-shrink-0">⚠</span>
      <div className="text-sm text-white/70 leading-relaxed">{children}</div>
    </div>
  );
}

// ─── Main Documentation Page ────────────────────────────────────
export default function DocsPage() {
  const [activeSection, setActiveSection] = useState('intro');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const scrollTo = useCallback((id: string) => {
    setActiveSection(id);
    setSidebarOpen(false);
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  // Group sections by category
  const categories: Record<string, DocSection[]> = {};
  for (const s of SECTIONS) {
    const cat = s.category ?? 'Other';
    if (!categories[cat]) categories[cat] = [];
    categories[cat].push(s);
  }

  return (
    <div className="min-h-screen bg-[#080a0e] text-[#e8edf5]">
      {/* Top Nav */}
      <header className="sticky top-0 z-50 bg-[#080a0e]/90 backdrop-blur-xl border-b border-white/6">
        <div className="max-w-[1440px] mx-auto flex items-center justify-between px-4 lg:px-6 h-14">
          <div className="flex items-center gap-4">
            <button onClick={() => setSidebarOpen(!sidebarOpen)} className="lg:hidden w-9 h-9 flex items-center justify-center rounded-lg border border-white/10 text-white/50 hover:text-white">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 12h18M3 6h18M3 18h18"/></svg>
            </button>
            <Link href="/" className="font-[family-name:var(--font-display)] font-bold text-lg gradient-text">Vril.js</Link>
            <span className="font-mono text-[10px] tracking-[0.14em] uppercase px-2 py-0.5 rounded-full border border-[#00FFC8]/30 text-[#00FFC8] bg-[#00FFC8]/7">Docs</span>
            <span className="font-mono text-xs text-white/20">v2.1.0</span>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/" className="text-sm text-white/40 hover:text-[#00FFC8] transition-colors">← Home</Link>
          </div>
        </div>
      </header>

      <div className="max-w-[1440px] mx-auto flex">
        {/* Sidebar */}
        <aside className={`fixed lg:sticky top-14 left-0 z-40 lg:z-0 w-72 lg:w-64 h-[calc(100dvh-3.5rem)] overflow-y-auto bg-[#080a0e] lg:bg-transparent border-r border-white/6 lg:border-0 transition-transform lg:translate-x-0 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
          <nav className="py-6 px-4">
            {Object.entries(categories).map(([cat, sections]) => (
              <div key={cat} className="mb-6">
                <div className="font-mono text-[10px] tracking-[0.14em] uppercase text-white/20 mb-2 px-3">{cat}</div>
                {sections.map(s => (
                  <button
                    key={s.id}
                    onClick={() => scrollTo(s.id)}
                    className={`w-full text-left px-3 py-1.5 rounded-lg text-sm transition-colors mb-0.5 ${
                      activeSection === s.id
                        ? 'bg-[#00FFC8]/10 text-[#00FFC8] font-medium'
                        : 'text-white/45 hover:text-white/70 hover:bg-white/4'
                    }`}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            ))}
          </nav>
        </aside>

        {/* Backdrop for mobile */}
        {sidebarOpen && (
          <div className="fixed inset-0 z-30 bg-black/50 lg:hidden" onClick={() => setSidebarOpen(false)} />
        )}

        {/* Main Content */}
        <main className="flex-1 min-w-0 px-4 lg:px-8 py-8 max-w-4xl">
          {/* Introduction */}
          <Section id="intro" title="Introduction">
            <p className="text-white/60 leading-relaxed mb-4">
              Vril.js is the security-first React framework by VRIL LABS. It provides post-quantum cryptography,
              zero-trust security membranes, and crypto agility built into every layer of the React framework —
              with zero external dependencies. Every cryptographic operation uses the Web Crypto API natively
              available in modern browsers, ensuring maximum performance and minimum attack surface.
            </p>
            <p className="text-white/60 leading-relaxed mb-4">
              With 26 framework modules, 200+ exports, and full post-quantum support (ML-KEM-768, ML-DSA-65,
              SLH-DSA), Vril.js is designed for applications where security is not optional — it is foundational.
              The framework implements a 5-layer security architecture spanning browser hardening, transport
              security, cryptographic operations, application-level protections, and build-time integrity verification.
            </p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 my-6">
              {[
                ['26', 'Modules'],
                ['200+', 'Exports'],
                ['0', 'Dependencies'],
                ['Full', 'PQC'],
              ].map(([val, label]) => (
                <div key={label} className="text-center p-3 rounded-xl bg-white/[0.03] border border-white/6">
                  <div className="text-xl font-bold gradient-text font-[family-name:var(--font-display)]">{val}</div>
                  <div className="font-mono text-[10px] tracking-[0.14em] uppercase text-white/30 mt-1">{label}</div>
                </div>
              ))}
            </div>
          </Section>

          {/* Installation */}
          <Section id="install" title="Installation">
            <p className="text-white/60 leading-relaxed mb-4">
              Create a new Vril.js project with the official CLI, or add Vril.js to an existing Next.js project.
            </p>
            <Code>{`# Create a new project
npx create-vril-app@latest my-app
cd my-app
npm run dev

# Or add to existing project
npm install vril-js

# Verify installation
npx vril doctor`}</Code>
            <p className="text-white/40 text-sm mt-3">
              Requires Node.js 18.17+, React 19+, and a browser with Web Crypto API support (Chrome 96+, Firefox 94+, Safari 15.4+).
            </p>
          </Section>

          {/* Configuration */}
          <Section id="config" title="Configuration (vril.config.ts)">
            <p className="text-white/60 leading-relaxed mb-4">
              Vril.js uses a <code className="text-[#00FFC8] bg-[#00FFC8]/8 px-1.5 py-0.5 rounded text-sm">vril.config.ts</code> file
              at the project root, similar to Next.js&apos;s <code className="text-white/50 bg-white/5 px-1.5 py-0.5 rounded text-sm">next.config.ts</code>.
              This file controls all framework behavior including security policies, cryptography settings, routing,
              build security, and authentication.
            </p>
            <Code>{`import { defineVrilConfig } from './src/lib/vril/config/define';

export default defineVrilConfig({
  security: {
    trustedTypes: true,
    apiMembrane: true,
    csp: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      objectSrc: ["'none'"],
    },
    csrf: {
      enabled: true,
      tokenHeader: 'x-vril-csrf',
      sameSite: 'Strict',
    },
  },
  crypto: {
    defaultAlgorithm: 'aes-256-gcm',
    kdfIterations: 600000,    // OWASP: 600K+
    pqcEnabled: true,
    hybridMode: true,
    keyRotationDays: 90,
  },
  build: {
    cspNonce: true,
    sriHashes: true,
    sbom: true,
  },
  auth: {
    sessionTTL: 86400000,
    passwordMinLength: 12,
  },
});`}</Code>
          </Section>

          {/* Quick Start */}
          <Section id="quickstart" title="Quick Start">
            <Code>{`import { createVrilApp, VrilVault, PQCHandler, signal } from '@/lib/vril';

// 1. Create your secure app
const app = createVrilApp({
  security: { trustedTypes: true, apiMembrane: true },
  crypto: { pqcEnabled: true, hybridMode: true },
});

// 2. Encrypt sensitive data with ΩVault
const vault = new VrilVault(600000);
const encrypted = await vault.encrypt('passphrase', 'sensitive data');
const decrypted = await vault.decrypt('passphrase', encrypted);

// 3. Post-quantum key exchange
const pqc = new PQCHandler();
const hybridKey = await pqc.generateHybridKeyPair();

// 4. Reactive state with ΩSignal
const count = signal(0);
const doubled = computed(() => count() * 2);
effect(() => console.log(\`Count: \${count()}, Doubled: \${doubled()}\`));
count.set(1);`}</Code>
          </Section>

          {/* ─── Core Modules ─────────────────────────────────────── */}
          <Section id="core" title="vril/core">
            <p className="text-white/60 leading-relaxed mb-4">
              The core module provides framework initialization, environment detection, feature flags,
              plugin lifecycle management, and performance profiling. It is the entry point for configuring
              and bootstrapping a Vril.js application.
            </p>
            <ExportTable rows={[
              ['createVrilApp()', 'function', 'Create and configure a Vril.js application instance'],
              ['DEFAULT_VRIL_CONFIG', 'const', 'Default security-first configuration object'],
              ['detectEnvironment()', 'function', 'Detect runtime: browser, server, edge, or Node.js'],
              ['env', 'const', 'Pre-computed environment info (isServer, isClient, isEdge, isDev)'],
              ['FeatureFlags', 'class', 'Feature flag system with rollout percentage support'],
              ['PluginLifecycleRegistry', 'class', 'Register and invoke plugin lifecycle hooks'],
              ['AppContext', 'class', 'Singleton application context shared across modules'],
              ['VersionTracker', 'class', 'Framework version tracking with migration support'],
              ['PerformanceProfiler', 'class', 'High-resolution timing for crypto and rendering ops'],
            ]} />
            <Code>{`import { createVrilApp, env, FeatureFlags } from '@/lib/vril/core';

const app = createVrilApp({
  security: { trustedTypes: true, apiMembrane: true },
  crypto: { pqcEnabled: true, hybridMode: true },
});

// Environment detection
console.log(env.isServer, env.isClient, env.isEdge);

// Feature flags with gradual rollout
const flags = new FeatureFlags();
flags.register('pqc-v2', { enabled: true, rollout: 25 }); // 25% rollout
if (flags.isEnabled('pqc-v2')) { /* use new PQC API */ }`}</Code>
          </Section>

          <Section id="config-mod" title="vril/config">
            <p className="text-white/60 leading-relaxed mb-4">
              The config module provides type-safe configuration with validation, deep merging, environment-specific
              overrides, encrypted secrets management, and runtime config watching. It powers the vril.config.ts file.
            </p>
            <ExportTable rows={[
              ['createConfig()', 'function', 'Type-safe config builder with validation and secrets'],
              ['ConfigValidator', 'class', 'Validate config values against a schema definition'],
              ['ConfigMerger', 'class', 'Deep merge with 4 conflict resolution strategies'],
              ['EnvironmentConfig', 'class', 'Dev/staging/prod/test environment-specific overrides'],
              ['ConfigSecrets', 'class', 'AES-GCM encrypted secrets with PBKDF2 key derivation'],
              ['ConfigWatcher', 'class', 'Watch environment variables for runtime config changes'],
            ]} />
            <Code>{`import { createConfig, EnvironmentConfig } from '@/lib/vril/config';

const envConfig = EnvironmentConfig.createWithPresets();
const { config, validate } = createConfig({
  base: { crypto: { kdfIterations: 600000 } },
  environment: envConfig,
});

const result = validate();
if (!result.valid) {
  console.error('Config errors:', result.errors);
}`}</Code>
          </Section>

          <Section id="plugin" title="vril/plugin">
            <p className="text-white/60 leading-relaxed mb-4">
              Plugin architecture with lifecycle hooks, dependency resolution, sandboxed loading, and
              integrity verification. Plugins can extend any part of the framework without modifying core code.
            </p>
            <ExportTable rows={[
              ['createPlugin()', 'function', 'Fluent builder for type-safe plugin creation'],
              ['PluginRegistry', 'class', 'Register, enable, disable, and configure plugins'],
              ['PluginLoader', 'class', 'Load plugins with SHA-256 integrity verification'],
              ['PluginContext', 'interface', 'Shared context between plugins with crypto utilities'],
            ]} />
            <Code>{`import { createPlugin, PluginRegistry } from '@/lib/vril/plugin';

const auditPlugin = createPlugin('security-audit')
  .onInit((ctx) => { ctx.log('Audit plugin initialized'); })
  .onRequest((ctx) => { ctx.log('Request intercepted'); })
  .build();

const registry = new PluginRegistry();
registry.register(auditPlugin);
registry.initializeAll();`}</Code>
          </Section>

          <Section id="types" title="vril/types">
            <p className="text-white/60 leading-relaxed mb-4">
              Central type definitions including branded security types that provide compile-time guarantees.
              SecureString, Encrypted&lt;T&gt;, Hashed&lt;T&gt;, and Signed&lt;T&gt; prevent accidental misuse
              of sensitive data at the type level.
            </p>
            <ExportTable rows={[
              ['SecurityLevel', 'enum', 'none | low | medium | high | critical'],
              ['SecureString', 'type', 'Branded string that has been security-validated'],
              ['Encrypted&lt;T&gt;', 'type', 'Branded type for encrypted data — cannot be used as plaintext'],
              ['Hashed&lt;T&gt;', 'type', 'Branded type for hashed data'],
              ['Signed&lt;T&gt;', 'type', 'Branded type for cryptographically signed data'],
              ['AlgorithmIdentifier', 'type', 'Union of all 23 supported algorithm identifiers'],
            ]} />
            <Code>{`import type { SecureString, Encrypted, SecurityLevel } from '@/lib/vril/types';

// Branded types prevent accidental misuse at compile time
function processSecure(input: SecureString) { /* ... */ }
// processSecure('plain'); // TypeScript error!
// processSecure(validate('plain') as SecureString); // OK

// Encrypted<T> cannot be accidentally treated as plaintext
function decrypt<T>(data: Encrypted<T>): T { /* ... */ }`}</Code>
          </Section>

          {/* ─── Security Modules ──────────────────────────────────── */}
          <Section id="security" title="vril/security">
            <p className="text-white/60 leading-relaxed mb-4">
              The security module provides Trusted Types enforcement, HTML sanitization, URL validation,
              Content Security Policy building, Permissions-Policy construction, and the zero-trust API membrane.
              It forms the outermost defense layer of Vril.js.
            </p>
            <ExportTable rows={[
              ['installTrustedTypes()', 'function', 'Install Trusted Types policy to prevent DOM XSS'],
              ['installAPIMembrane()', 'function', 'Block dangerous browser APIs at runtime'],
              ['DOMPSanitizer', 'class', 'Zero-dependency HTML sanitizer (no DOMPurify needed)'],
              ['URLValidator', 'class', 'Validate URLs to prevent javascript:/data: XSS attacks'],
              ['ContentSecurityPolicy', 'class', 'Fluent CSP builder with nonce and report support'],
              ['PermissionsPolicyBuilder', 'class', 'Fluent Permissions-Policy builder'],
              ['SecurityContext', 'class', 'Runtime security context with state tracking'],
              ['IntegrityChecker', 'class', 'SHA-256 integrity verification for DOM elements'],
            ]} />
            <Code>{`import { installTrustedTypes, installAPIMembrane, DOMPSanitizer } from '@/lib/vril/security';

// Install zero-trust membrane
installTrustedTypes();
installAPIMembrane(['WebTransport', 'RTCPeerConnection']);

// Sanitize untrusted HTML
const sanitizer = new DOMPSanitizer();
const safe = sanitizer.sanitize(untrustedHTML);

// Validate URLs
const validator = new URLValidator();
const result = validator.validate(userUrl, { allowedProtocols: ['https:'] });`}</Code>
            <SecurityNote>Trusted Types must be installed before any DOM manipulation. Call installTrustedTypes() at the top of your application entry point.</SecurityNote>
          </Section>

          <Section id="vault" title="vril/security/crypto/vault">
            <p className="text-white/60 leading-relaxed mb-4">
              The ΩVault provides zero-knowledge client-side encryption using AES-256-GCM with PBKDF2-SHA-512
              key derivation at 600,000 iterations. It supports text and binary encryption, key wrapping,
              passphrase rotation, and secure memory operations.
            </p>
            <ExportTable rows={[
              ['VrilVault', 'class', 'AES-256-GCM vault with PBKDF2-SHA-512 (600K iterations)'],
              ['encrypt()', 'method', 'Encrypt text with passphrase, returns versioned bundle'],
              ['decrypt()', 'method', 'Decrypt bundle with passphrase, verifies integrity'],
              ['encryptBlob()', 'method', 'Encrypt binary data (ArrayBuffer)'],
              ['wrapKey()', 'method', 'AES-KW key wrapping for secure key storage'],
              ['rotatePassphrase()', 'method', 'Re-encrypt bundle with new passphrase'],
              ['assessStrength()', 'method', 'Password strength scoring (0-6 scale)'],
              ['SecureMemory', 'class', 'Best-effort zeroization of sensitive data in memory'],
            ]} />
            <Code>{`import { VrilVault } from '@/lib/vril/security/crypto/vault';

const vault = new VrilVault(600000);

// Encrypt sensitive data
const encrypted = await vault.encrypt('my-passphrase', 'sensitive data');
// encrypted = { v: 2, salt, iv, ciphertext, algorithm: 'AES-256-GCM', kdf: 'PBKDF2-SHA-512', kdfIterations: 600000 }

// Decrypt
const decrypted = await vault.decrypt('my-passphrase', encrypted);
// decrypted = { plaintext: 'sensitive data', algorithm: 'AES-256-GCM', verified: true }

// Check passphrase strength
const strength = vault.assessStrength('my-passphrase');
// strength = { score: 4, max: 6, label: 'moderate' }`}</Code>
            <SecurityNote>
              Never store passphrases in localStorage or cookies. Use the SecureMemory class to zero out
              passphrase variables after use. KDF iterations below 600,000 do not meet OWASP 2023 recommendations.
            </SecurityNote>
          </Section>

          <Section id="pqc" title="vril/security/crypto/pqc">
            <p className="text-white/60 leading-relaxed mb-4">
              Post-quantum cryptography handler supporting ML-KEM-768, ML-KEM-1024, ML-DSA-65, ML-DSA-87,
              SLH-DSA-SHA2-128s, and SLH-DSA-SHA2-256f. All algorithms follow FIPS 203/204 standards.
              Where browser support is not yet available, the module simulates PQC operations with real
              classical fallbacks (ECDH-P256, ECDSA-P256).
            </p>
            <ExportTable rows={[
              ['PQCHandler', 'class', 'Post-quantum key encapsulation and digital signatures'],
              ['generateKeyPair()', 'method', 'Generate PQC key pairs for KEM or signatures'],
              ['encapsulate()', 'method', 'KEM encapsulation (generate shared secret + ciphertext)'],
              ['decapsulate()', 'method', 'KEM decapsulation (recover shared secret)'],
              ['sign()', 'method', 'Create digital signature (ECDSA-P256 real, ML-DSA simulated)'],
              ['verify()', 'method', 'Verify digital signature'],
              ['benchmark()', 'method', 'Performance benchmark for key gen/encap/decap cycles'],
              ['isSupported()', 'method', 'Check if a PQC algorithm is available'],
            ]} />
            <Code>{`import { PQCHandler } from '@/lib/vril/security/crypto/pqc';

const pqc = new PQCHandler();

// Check algorithm support
pqc.isSupported('ML-KEM-768'); // true
pqc.isSupported('ML-DSA-65');  // true

// Generate hybrid key pair
const keyPair = await pqc.generateKeyPair('X25519-ML-KEM-768');

// Key encapsulation
const result = await pqc.hybridKeyExchange(peerPublicKey);

// Get algorithm info
const info = pqc.getAlgorithmInfo('ML-KEM-768');
// info = { name: 'ML-KEM-768', standard: 'FIPS 203', securityLevel: 3, ... }`}</Code>
            <SecurityNote>
              PQC algorithms not yet natively supported in browsers are simulated. The hybrid approach
              (X25519+ML-KEM-768) ensures classical security is always maintained. When browsers add native
              PQC support, Vril.js will automatically use the real implementations.
            </SecurityNote>
          </Section>

          <Section id="hybrid" title="vril/security/crypto/hybrid">
            <p className="text-white/60 leading-relaxed mb-4">
              Hybrid cryptography combines classical algorithms with post-quantum algorithms, providing
              defense in depth. The shared secret is derived by combining both classical and PQC components
              through a SHA-256 KDF combiner: combined = SHA-256(classicalSecret || pqcSecret || contextInfo).
            </p>
            <ExportTable rows={[
              ['HybridKEM', 'class', 'Hybrid key encapsulation (X25519+ML-KEM-768)'],
              ['HybridSigner', 'class', 'Hybrid digital signatures (ECDSA-P256+ML-DSA-65)'],
              ['HybridKeyRotation', 'class', 'Key rotation with overlap periods for zero-downtime migration'],
              ['encapsulate()', 'method', 'Perform both classical and PQC KEM, combine secrets'],
              ['verify()', 'method', 'Verify both signatures (AND logic — both must pass)'],
            ]} />
            <Code>{`import { HybridKEM, HybridSigner } from '@/lib/vril/security/crypto/hybrid';

// Hybrid key exchange
const kem = new HybridKEM();
const result = await kem.encapsulate();
// result.classicalAlgorithm = 'X25519'
// result.pqcAlgorithm = 'ML-KEM-768'
// result.combinedSecret = SHA-256(X25519_secret || ML-KEM_secret || ctx)

// Hybrid signing
const signer = new HybridSigner();
const signature = await signer.sign(message, keyPair);
const valid = await signer.verify(message, signature, publicKey);
// Both ECDSA-P256 AND ML-DSA-65 must verify`}</Code>
          </Section>

          <Section id="agility" title="vril/security/crypto/agility">
            <p className="text-white/60 leading-relaxed mb-4">
              Crypto agility framework with a 12+ algorithm registry, migration executor, health monitoring,
              organizational crypto policies, and audit logging. Includes NIST 2035 quantum timeline
              milestones for proactive algorithm migration planning.
            </p>
            <ExportTable rows={[
              ['AlgorithmRegistry', 'class', 'Versioned registry of 12+ algorithms with status tracking'],
              ['MigrationExecutor', 'class', 'Execute algorithm migrations with re-encryption/re-signing'],
              ['AlgorithmHealthMonitor', 'class', 'Track NIST announcements and vulnerability reports'],
              ['CryptoPolicy', 'class', 'Define org-wide policies: min key sizes, required/forbidden algos'],
              ['AuditLogger', 'class', 'Log all crypto operations for compliance (SOC 2, FIPS)'],
              ['CryptoAgility', 'class', 'High-level API combining registry, policy, and health'],
            ]} />
            <Code>{`import { CryptoAgility } from '@/lib/vril/security/crypto/agility';

const agility = new CryptoAgility();

// Check system status
const status = agility.getStatus();
// { totalAlgorithms: 12, activeAlgorithms: 8, migrationsPending: 2 }

// Select best algorithm by type
const bestKEM = agility.selectAlgorithm('kem'); // X25519+ML-KEM-768

// Plan migration
const registry = agility.getRegistry();
const plan = registry.migrate('x25519', 'ml-kem-768');
// plan = { success: true, message: 'Migrated from X25519 to ML-KEM-768' }`}</Code>
          </Section>

          <Section id="hardening" title="vril/security/hardening">
            <p className="text-white/60 leading-relaxed mb-4">
              Browser hardening module with cross-origin isolation, fingerprint resistance, timing attack
              mitigation, clickjacking protection, XSS shielding, and secure cookie management.
            </p>
            <ExportTable rows={[
              ['CrossOriginIsolation', 'class', 'Enable COOP+COEP+CORP for SharedArrayBuffer access'],
              ['FingerprintResistance', 'class', 'Anti-fingerprinting: canvas, WebGL, audio noise'],
              ['TimingAttackMitigation', 'class', 'Constant-time comparisons, request timing normalization'],
              ['ClickjackingProtection', 'class', 'X-Frame-Options, CSP frame-ancestors, framing policies'],
              ['XSSShield', 'class', 'DOM-based XSS prevention, innerHTML sanitization'],
              ['CookieFortress', 'class', 'Secure cookies: __Host- prefix, SameSite, Secure, HttpOnly'],
              ['SecurityHeadersBuilder', 'class', 'Fluent API for building comprehensive security headers'],
            ]} />
            <Code>{`import { XSSShield, CookieFortress, CrossOriginIsolation } from '@/lib/vril/security/hardening';

// XSS protection
const shield = new XSSShield();
const safe = shield.sanitize(untrustedHTML);

// Secure cookies
const cookies = new CookieFortress();
cookies.set('session', token, { sameSite: 'Strict', httpOnly: true, secure: true });

// Cross-origin isolation for SharedArrayBuffer
const isolation = new CrossOriginIsolation();
isolation.enable();`}</Code>
          </Section>

          <Section id="audit" title="vril/security/audit">
            <p className="text-white/60 leading-relaxed mb-4">
              Runtime security auditing with comprehensive scanners, CSP violation reporting, security
              scoring, vulnerability databases, and compliance checking against OWASP, NIST, and PCI-DSS.
            </p>
            <ExportTable rows={[
              ['SecurityAuditor', 'class', 'Comprehensive runtime security scanner (headers, DOM, crypto, permissions)'],
              ['CSPViolationReporter', 'class', 'Collect and report Content Security Policy violations'],
              ['SecurityScoreCalculator', 'class', 'Calculate security score (0-100) based on multiple factors'],
              ['VulnerabilityDatabase', 'class', 'Check against known vulnerability patterns'],
              ['ComplianceChecker', 'class', 'Check compliance with OWASP/NIST/PCI-DSS requirements'],
              ['generateSecurityReport()', 'function', 'Generate full security audit report with recommendations'],
            ]} />
            <Code>{`import { SecurityAuditor, generateSecurityReport } from '@/lib/vril/security/audit';

const auditor = new SecurityAuditor();
const headerResults = auditor.scanHeaders();
const domResults = auditor.scanDOM();
const cryptoResults = auditor.scanCrypto();

// Full audit report
const report = await generateSecurityReport();
console.log(report.score); // 0-100
console.log(report.findings); // VulnerabilityFinding[]
console.log(report.compliance); // ComplianceStatus`}</Code>
          </Section>

          {/* ─── Data & Reactivity ─────────────────────────────────── */}
          <Section id="signals" title="vril/signals">
            <p className="text-white/60 leading-relaxed mb-4">
              ΩSignal provides fine-grained reactive primitives: signal, computed, effect, batch, untrack, and store.
              Enhanced with lazy, async, resource, debounced, throttled, persisted, and encrypted signal variants.
              Includes devtools hooks and dependency graph tracking for debugging.
            </p>
            <ExportTable rows={[
              ['signal()', 'function', 'Create a reactive signal with get/set/peek'],
              ['computed()', 'function', 'Create a derived signal that auto-updates'],
              ['effect()', 'function', 'Run side effects when dependencies change'],
              ['batch()', 'function', 'Batch multiple updates into one notification'],
              ['store()', 'function', 'Create a proxy-based reactive object store'],
              ['encryptedSignal()', 'function', 'Signal that encrypts values in memory with AES-256-GCM'],
              ['resourceSignal()', 'function', 'Fetch-like signal with SWR pattern'],
              ['createSignalGraph()', 'function', 'Track signal dependencies for debugging'],
            ]} />
            <Code>{`import { signal, computed, effect, batch, encryptedSignal } from '@/lib/vril/signals';

const name = signal('World');
const greeting = computed(() => \`Hello, \${name()}!\`);

effect(() => console.log(greeting())); // "Hello, World!"
name.set('Vril');                      // "Hello, Vril!"

// Batch updates
batch(() => {
  name.set('Alice');
  // ... other updates
  // Only one notification after batch completes
});

// Encrypted signal (AES-256-GCM in memory)
const secret = encryptedSignal('sensitive-value', 'encryption-key');`}</Code>
          </Section>

          <Section id="state" title="vril/state">
            <p className="text-white/60 leading-relaxed mb-4">
              VrilStore provides full state management built on signals, with middleware pipeline, memoized
              selectors, time-travel debugging, field-level encryption, and persistence.
            </p>
            <ExportTable rows={[
              ['createStore()', 'function', 'Create a store with initial state and middleware'],
              ['VrilStore', 'class', 'Full state management: get/set/select/dispatch/subscribe'],
              ['StateEncryption', 'class', 'Field-level AES-256-GCM encryption for sensitive state'],
              ['StatePersistence', 'class', 'Persist state to storage with optional encryption'],
              ['loggerMiddleware', 'const', 'Log all state transitions for debugging'],
              ['encryptionMiddleware', 'const', 'Auto-encrypt sensitive fields on state change'],
            ]} />
            <Code>{`import { createStore, loggerMiddleware, encryptionMiddleware } from '@/lib/vril/state';

const store = createStore(
  { count: 0, user: null },
  { middleware: [loggerMiddleware, encryptionMiddleware(['user'])] }
);

store.setState({ count: 1 });
const count = store.select((s) => s.count);

// Subscribe to changes
store.subscribe((state, prev) => {
  console.log('State changed:', state);
});`}</Code>
          </Section>

          <Section id="hooks" title="vril/hooks">
            <p className="text-white/60 leading-relaxed mb-4">
              React hooks that integrate Vril.js framework features into components. Includes signal
              subscriptions, encrypted state, secure storage, CSRF tokens, and permission checks.
            </p>
            <ExportTable rows={[
              ['useSignal()', 'hook', 'Subscribe to a signal in a React component'],
              ['useComputed()', 'hook', 'Computed value that auto-updates in React'],
              ['useEncryptedState()', 'hook', 'React state that encrypts values with AES-256-GCM'],
              ['useSecureStorage()', 'hook', 'localStorage with encryption and serialization'],
              ['useCSRFToken()', 'hook', 'Get and manage CSRF tokens for server actions'],
              ['useRateLimiter()', 'hook', 'Client-side rate limiting for API calls'],
              ['usePermission()', 'hook', 'Check browser Permissions Policy for features'],
            ]} />
            <Code>{`import { useSignal, useEncryptedState, useCSRFToken } from '@/lib/vril/hooks';

function SecureForm() {
  const count = useSignal(signal(0));
  const [secret, setSecret] = useEncryptedState('field-key', 'initial');
  const csrfToken = useCSRFToken();

  return (
    <form>
      <input type="hidden" name="csrf" value={csrfToken} />
      <input value={secret} onChange={(e) => setSecret(e.target.value)} />
      <button type="button" onClick={() => count.set(c => c + 1)}>{count}</button>
    </form>
  );
}`}</Code>
          </Section>

          <Section id="cache" title="vril/cache">
            <p className="text-white/60 leading-relaxed mb-4">
              Multi-tier intelligent caching with LRU memory cache, stale-while-revalidate, AES-256-GCM
              encrypted cache layer, cache registry, and tag-based invalidation.
            </p>
            <ExportTable rows={[
              ['MemoryCache', 'class', 'LRU cache with TTL, max entries, and memory pressure'],
              ['StaleWhileRevalidate', 'class', 'SWR pattern with background refresh'],
              ['EncryptedCache', 'class', 'AES-256-GCM encrypted cache for sensitive data'],
              ['CacheRegistry', 'class', 'Manage multiple named caches with different policies'],
              ['CacheInvalidator', 'class', 'Tag-based and pattern-based cache invalidation'],
              ['distributedCacheKey()', 'function', 'Collision-free cache keys with namespace isolation'],
            ]} />
            <Code>{`import { MemoryCache, EncryptedCache } from '@/lib/vril/cache';

const cache = new MemoryCache<string>({ maxSize: 1000, ttl: 60000 });
await cache.set('user:1', JSON.stringify(user));
const user = await cache.get('user:1');

// Encrypted cache for sensitive data
const encCache = new EncryptedCache({ passphrase: 'vault-key' });
await encCache.set('api-key', 'sk_live_abc123');
const key = await encCache.get('api-key');`}</Code>
          </Section>

          {/* ─── Server & Build ─────────────────────────────────────── */}
          <Section id="server" title="vril/server">
            <p className="text-white/60 leading-relaxed mb-4">
              Server security utilities including RSC deserialization hardening (CVE-2025-55182 prevention),
              CSRF guard with double-submit pattern, edge request signing with HMAC-SHA256, encrypted
              environment variables, and supply chain integrity verification.
            </p>
            <ExportTable rows={[
              ['validateDeserializedPayload()', 'function', 'Validate RSC payloads: depth, keys, prototype pollution'],
              ['CSRFGuard', 'class', 'Generate/validate CSRF tokens with constant-time comparison'],
              ['RequestSigner', 'class', 'HMAC-SHA256 request signing with replay prevention'],
              ['EnvEncryption', 'class', 'Encrypt environment variables for edge runtime'],
              ['SupplyChainIntegrity', 'class', 'SBOM v2.3 integrity verification'],
              ['RSCSecurityBoundary', 'class', 'RSC flight data validation, action signing, rate limiting'],
              ['SecurityMiddlewareChain', 'class', 'Composable security checks with audit logging'],
            ]} />
            <Code>{`import { CSRFGuard, RequestSigner, validateDeserializedPayload } from '@/lib/vril/server';

// CSRF protection
const token = CSRFGuard.generateToken();
const isValid = CSRFGuard.validateToken(request, expectedToken);

// Request signing (edge → origin)
const signer = new RequestSigner(process.env.SIGNING_SECRET);
const signature = await signer.sign(payload, Date.now());

// Validate deserialized RSC data
const result = validateDeserializedPayload(data, { maxDepth: 16 });
if (!result.valid) throw new Error(result.reason);`}</Code>
          </Section>

          <Section id="build" title="vril/build">
            <p className="text-white/60 leading-relaxed mb-4">
              Build-time security with 20-point security audit, CSP nonce generation, multi-algorithm SRI,
              SBOM generation in CycloneDX format, build integrity verification, and platform-specific
              security headers output.
            </p>
            <ExportTable rows={[
              ['CSPNonceGenerator', 'class', 'Per-request CSP nonces with strict-dynamic support'],
              ['SRIHasher', 'class', 'Multi-algorithm SRI (sha256+sha384+sha512)'],
              ['BuildSecurityChecker', 'class', '20-point build security audit'],
              ['BuildPlugin', 'class', 'Build plugin for CSP manifest, SRI injection, security transforms'],
              ['SBOMGenerator', 'class', 'CycloneDX SBOM with vulnerability matching'],
              ['SecurityHeadersPlugin', 'class', 'Auto-generate headers for Vercel/Netlify/Cloudflare/Nginx'],
            ]} />
            <Code>{`import { BuildSecurityChecker, SRIHasher } from '@/lib/vril/build';

// Run 20-point security audit
const checker = new BuildSecurityChecker();
checker.pass('csp-nonce');
checker.pass('sri-hashes');
checker.pass('hsts-preload');
const status = checker.getStatus();
// { total: 20, passed: 3, failed: [...17 items] }

// Generate SRI attribute
const sri = await SRIHasher.compute(scriptContent, 'sha384');
// "sha384-..."`}</Code>
          </Section>

          <Section id="router" title="vril/router">
            <p className="text-white/60 leading-relaxed mb-4">
              Secure router with per-route CSRF, rate limits, method restrictions, CORS handling, and
              composable middleware. Includes route groups, security scanning, and client-side navigation
              guards to prevent tab-nabbing and URL injection.
            </p>
            <ExportTable rows={[
              ['RouteSecurityRegistry', 'class', 'Map route patterns to security policies'],
              ['createSecureHandler()', 'function', 'Create API route handler with built-in security'],
              ['RouteMiddleware', 'class', 'Composable: withAuth, withCSRF, withRateLimit, withCORS'],
              ['RouteGroup', 'class', 'Group routes with shared security: api(), public(), admin()'],
              ['NavigationGuard', 'class', 'Client-side URL validation, tab-nabbing prevention'],
              ['RouteScanner', 'class', 'Scan route definitions for security issues'],
            ]} />
            <Code>{`import { RouteSecurityRegistry, createSecureHandler, RouteMiddleware } from '@/lib/vril/router';

const registry = new RouteSecurityRegistry();
registry.register({ path: '/api/*', security: { csrf: true, rateLimit: 60 } });

// Composable middleware
const handler = RouteMiddleware.compose(
  RouteMiddleware.withAuth,
  RouteMiddleware.withCSRF,
  RouteMiddleware.withRateLimit({ max: 100 }),
)(async (req) => Response.json({ ok: true }));`}</Code>
          </Section>

          <Section id="auth" title="vril/auth">
            <p className="text-white/60 leading-relaxed mb-4">
              Authentication building blocks: session management with HMAC-SHA256 tokens, JWT-like token
              handling using Web Crypto, PBKDF2-SHA-512 password hashing, and hierarchical RBAC with
              role inheritance.
            </p>
            <ExportTable rows={[
              ['SessionManager', 'class', 'Create/validate/rotate/destroy sessions with HMAC tokens'],
              ['TokenHandler', 'class', 'JWT-like tokens: create, verify, refresh (Web Crypto)'],
              ['PasswordHandler', 'class', 'PBKDF2-SHA-512 (600K iter) with constant-time verify'],
              ['RBAC', 'class', 'Hierarchical role-based access control with permission guards'],
              ['LoginAttemptTracker', 'class', 'Failed login tracking with progressive lockout'],
            ]} />
            <Code>{`import { SessionManager, RBAC, PasswordHandler } from '@/lib/vril/auth';

// Sessions
const sessions = new SessionManager({ ttl: 86400000 });
const session = sessions.create({ userId: '123' });

// RBAC
const rbac = new RBAC();
rbac.defineRole('admin', ['read', 'write', 'delete']);
rbac.defineRole('user', ['read']);
const canDelete = rbac.checkPermission('admin', 'delete'); // true

// Passwords
const passwords = new PasswordHandler();
const hash = await passwords.hash('user-password');
const valid = await passwords.verify('user-password', hash);`}</Code>
          </Section>

          <Section id="api" title="vril/api">
            <p className="text-white/60 leading-relaxed mb-4">
              Type-safe API route builder with zero-dependency schema validation (no Zod needed),
              structured error handling, token-bucket rate limiting, and route versioning with
              deprecation warnings.
            </p>
            <ExportTable rows={[
              ['createAPIRoute()', 'function', 'Builder for API routes with validation, CSRF, rate limiting'],
              ['APISchema', 'class', 'Zero-dep schema builder: string, number, object, array, enum'],
              ['APIErrorHandler', 'class', 'Structured error responses (safe in prod, verbose in dev)'],
              ['APIRateLimiter', 'class', 'Token bucket rate limiting per IP/route'],
              ['APIVersioning', 'class', 'Route versioning with deprecation warnings'],
            ]} />
            <Code>{`import { createAPIRoute, APISchema } from '@/lib/vril/api';

const schema = APISchema.object({
  name: APISchema.string().min(1).max(100),
  email: APISchema.string().pattern(/^[^@]+@[^@]+$/),
});

const handler = createAPIRoute({
  validate: schema,
  rateLimit: { max: 100, window: 60000 },
  csrf: true,
}, async (req) => {
  return Response.json({ user: req.body });
});`}</Code>
          </Section>

          {/* ─── Platform Modules ───────────────────────────────────── */}
          <Section id="ssr" title="vril/ssr">
            <p className="text-white/60 leading-relaxed mb-4">
              Server-side rendering with streaming support, security guard that validates SSR output for
              XSS and injection attacks before sending, and selective hydration with three strategies:
              immediate, visible, and idle.
            </p>
            <Code>{`import { createSSRStream, SSRSecurityGuard, SelectiveHydration } from '@/lib/vril/ssr';

const guard = new SSRSecurityGuard();
const clean = guard.sanitize(ssrOutput);

const hydration = new SelectiveHydration();
hydration.mark('hero', 'immediate');
hydration.mark('comments', 'visible');
hydration.mark('analytics', 'idle');`}</Code>
          </Section>

          <Section id="streaming" title="vril/streaming">
            <p className="text-white/60 leading-relaxed mb-4">
              Streaming utilities for React Server Components with HMAC integrity validation, rate-limited
              streams to prevent DoS, secure content transformers, and streaming cache with stale-while-revalidate.
            </p>
            <Code>{`import { StreamIntegrityValidator, RateLimitedStream } from '@/lib/vril/streaming';

const validator = new StreamIntegrityValidator('hmac-secret');
validator.addChunk(chunk);
const isValid = validator.verify(finalChunk, expectedHash);

const limited = new RateLimitedStream({ bytesPerSecond: 1024 * 1024 });`}</Code>
          </Section>

          <Section id="edge" title="vril/edge">
            <p className="text-white/60 leading-relaxed mb-4">
              Edge runtime detection, key-value storage, geolocation with privacy controls, and
              edge-specific security including bot detection and IP allowlisting.
            </p>
            <Code>{`import { EdgeRuntime, EdgeKV, EdgeSecurity } from '@/lib/vril/edge';

const runtime = new EdgeRuntime();
if (runtime.isEdge()) { /* edge-specific code */ }

const kv = new EdgeKV<string>({ namespace: 'sessions', ttl: 3600 });
await kv.set('user:1', JSON.stringify(session));

const edgeSec = new EdgeSecurity({ preset: 'strict' });
const isBot = edgeSec.detectBot(userAgent);`}</Code>
          </Section>

          <Section id="head" title="vril/head">
            <p className="text-white/60 leading-relaxed mb-4">
              Head/SEO management with SRI-enforced script tags, Open Graph tag generation, JSON-LD
              structured data with XSS protection, and CSP nonce injection for inline scripts.
            </p>
            <Code>{`import { HeadManager, generateOGTags, CSPNonceInjector } from '@/lib/vril/head';

const head = new HeadManager();
head.addTitle('My App');
head.addMeta({ name: 'description', content: 'Secure app' });

const ogTags = generateOGTags({ title: 'My App', url: 'https://app.com' });
const nonce = CSPNonceInjector.generate();`}</Code>
          </Section>

          <Section id="diagnostics" title="vril/diagnostics">
            <p className="text-white/60 leading-relaxed mb-4">
              Runtime diagnostics and monitoring: performance profiling with high-resolution timing,
              security health monitoring, crypto operation profiling, network request tracking, and
              memory leak detection.
            </p>
            <Code>{`import { PerformanceMonitor, SecurityDiagnostics } from '@/lib/vril/diagnostics';

const perf = new PerformanceMonitor();
perf.start('encryption');
await vault.encrypt(key, data);
perf.end('encryption');
// encryption: 42ms

const diag = new SecurityDiagnostics();
const health = diag.checkAll();`}</Code>
          </Section>

          <Section id="utils" title="vril/utils">
            <p className="text-white/60 leading-relaxed mb-4">
              Zero-dependency utility functions for security operations: constant-time comparison,
              secure random generation, SHA hashing, Base64 encoding, HTML sanitization, URL validation,
              deep clone/freeze/merge, debounce/throttle, and exponential backoff retry.
            </p>
            <ExportTable rows={[
              ['constantTimeEqual()', 'function', 'Constant-time string/buffer comparison (prevents timing attacks)'],
              ['secureRandom()', 'function', 'Cryptographically secure random bytes'],
              ['secureRandomString()', 'function', 'Secure random string (configurable charset)'],
              ['hashData()', 'function', 'SHA-256/384/512 hashing via Web Crypto'],
              ['sanitizeHTML()', 'function', 'Basic HTML sanitizer (strips scripts, event handlers)'],
              ['validateURL()', 'function', 'URL validation with protocol allowlisting'],
            ]} />
            <Code>{`import { constantTimeEqual, secureRandomString, hashData } from '@/lib/vril/utils';

// Constant-time comparison (prevents timing attacks)
const match = constantTimeEqual(userToken, expectedToken);

// Secure random string
const apiKey = secureRandomString(32, 'alphanumeric');

// SHA-256 hashing
const hash = await hashData('input-data', 'SHA-256');`}</Code>
          </Section>
        </main>
      </div>
    </div>
  );
}
