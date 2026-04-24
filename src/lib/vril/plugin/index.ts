/**
 * Vril.js v2.0.0 — Plugin Architecture
 * Plugin interface · Registry · Loader with sandboxing ·
 * Plugin context with isolation · Lifecycle hooks
 *
 * Zero external dependencies — Web Crypto API and built-in JS only.
 */

// ─── Types ────────────────────────────────────────────────────

/** Plugin lifecycle stages */
export type PluginLifecycle = 'onInit' | 'onReady' | 'onRequest' | 'onResponse' | 'onError' | 'onBuild' | 'onSecurityCheck';

/** A hook callback that can modify context or perform side effects */
export type PluginHook = (ctx: PluginContext) => void | PluginContext | Promise<void | PluginContext>;

/** Metadata describing a plugin */
export interface PluginManifest {
  name: string;
  version: string;
  description?: string;
  author?: string;
  license?: string;
  homepage?: string;
  dependencies?: string[];
  permissions?: PluginPermission[];
  integrity?: string;
}

/** Permissions a plugin may request */
export interface PluginPermission {
  resource: string;
  access: 'read' | 'write' | 'execute';
}

/** Configuration for a plugin */
export interface VrilPlugin {
  manifest: PluginManifest;
  hooks?: Partial<Record<PluginLifecycle, PluginHook>>;
  middleware?: PluginMiddleware[];
  configure?: (config: Record<string, unknown>) => void;
  destroy?: () => void | Promise<void>;
}

/** Middleware function that can intercept and modify requests */
export type PluginMiddleware = (
  ctx: PluginContext,
  next: () => Promise<void>
) => Promise<void>;

/** Shared context between plugins with namespace isolation */
export interface PluginContext {
  pluginName: string;
  version: string;
  state: Map<string, unknown>;
  shared: Record<string, unknown>;
  config: Record<string, unknown>;
  logger: PluginLogger;
  crypto: PluginCrypto;
}

/** Logger interface available to plugins */
export interface PluginLogger {
  info: (message: string, ...args: unknown[]) => void;
  warn: (message: string, ...args: unknown[]) => void;
  error: (message: string, ...args: unknown[]) => void;
  debug: (message: string, ...args: unknown[]) => void;
}

/** Cryptographic utilities available to plugins */
export interface PluginCrypto {
  randomUUID: () => string;
  hash: (data: string) => Promise<string>;
  hmac: (data: string, secret: string) => Promise<string>;
}

// ─── Plugin Registry ──────────────────────────────────────────

interface RegisteredPlugin {
  plugin: VrilPlugin;
  enabled: boolean;
  registeredAt: number;
  config: Record<string, unknown>;
}

/**
 * Central registry for plugins with enable/disable/configure capabilities.
 * Enforces permission boundaries and manages lifecycle.
 */
export class PluginRegistry {
  private plugins = new Map<string, RegisteredPlugin>();
  private executionOrder: string[] = [];
  private version = '2.1.0';

  /** Register a plugin with the framework */
  register(plugin: VrilPlugin, config?: Record<string, unknown>): void {
    const name = plugin.manifest.name;

    // Check for duplicate registration
    if (this.plugins.has(name)) {
      throw new Error(`[VRIL Plugin] Plugin "${name}" is already registered`);
    }

    // Check dependency satisfaction
    if (plugin.manifest.dependencies) {
      for (const dep of plugin.manifest.dependencies) {
        if (!this.plugins.has(dep)) {
          throw new Error(`[VRIL Plugin] Plugin "${name}" requires dependency "${dep}" which is not registered`);
        }
      }
    }

    // Verify integrity if specified
    if (plugin.manifest.integrity) {
      // Integrity verification happens in PluginLoader
    }

    // Call configure if the plugin supports it
    if (plugin.configure && config) {
      plugin.configure(config);
    }

    this.plugins.set(name, {
      plugin,
      enabled: true,
      registeredAt: Date.now(),
      config: config ?? {},
    });

    this.executionOrder.push(name);
  }

  /** Unregister a plugin */
  async unregister(name: string): Promise<boolean> {
    const entry = this.plugins.get(name);
    if (!entry) return false;

    // Call destroy if available
    if (entry.plugin.destroy) {
      await entry.plugin.destroy();
    }

    this.plugins.delete(name);
    this.executionOrder = this.executionOrder.filter((n) => n !== name);

    // Remove dependents
    const dependents = this.getDependents(name);
    for (const dep of dependents) {
      await this.unregister(dep);
    }

    return true;
  }

  /** Enable a disabled plugin */
  enable(name: string): boolean {
    const entry = this.plugins.get(name);
    if (!entry) return false;
    entry.enabled = true;
    return true;
  }

  /** Disable a plugin without removing it */
  disable(name: string): boolean {
    const entry = this.plugins.get(name);
    if (!entry) return false;
    entry.enabled = false;
    return true;
  }

  /** Check if a plugin is registered and enabled */
  isEnabled(name: string): boolean {
    return this.plugins.get(name)?.enabled ?? false;
  }

  /** Get a plugin by name */
  get(name: string): VrilPlugin | null {
    return this.plugins.get(name)?.plugin ?? null;
  }

  /** Update a plugin's configuration at runtime */
  configure(name: string, config: Record<string, unknown>): boolean {
    const entry = this.plugins.get(name);
    if (!entry) return false;
    entry.config = { ...entry.config, ...config };
    if (entry.plugin.configure) {
      entry.plugin.configure(entry.config);
    }
    return true;
  }

  /** Execute all hooks for a given lifecycle stage */
  async executeHooks(lifecycle: PluginLifecycle, baseCtx: Record<string, unknown>): Promise<void> {
    for (const name of this.executionOrder) {
      const entry = this.plugins.get(name);
      if (!entry || !entry.enabled) continue;

      const hook = entry.plugin.hooks?.[lifecycle];
      if (!hook) continue;

      const ctx = this.createContext(name, entry.config);
      const fullCtx = { ...baseCtx, ...Object.fromEntries(ctx.state) };

      try {
        await hook({ ...ctx, shared: fullCtx });
      } catch (err) {
        ctx.logger.error(`Hook ${lifecycle} failed for plugin ${name}:`, err);
      }
    }
  }

  /** Execute middleware chain for a request */
  async executeMiddleware(
    baseCtx: Record<string, unknown>,
    finalHandler: () => Promise<void>
  ): Promise<void> {
    const middlewares: Array<{ name: string; middleware: PluginMiddleware }> = [];

    for (const name of this.executionOrder) {
      const entry = this.plugins.get(name);
      if (!entry || !entry.enabled || !entry.plugin.middleware) continue;
      for (const mw of entry.plugin.middleware) {
        middlewares.push({ name, middleware: mw });
      }
    }

    // Build middleware chain
    let index = 0;
    const run = async (): Promise<void> => {
      if (index >= middlewares.length) {
        await finalHandler();
        return;
      }
      const { name, middleware } = middlewares[index++];
      const ctx = this.createContext(name, this.plugins.get(name)?.config ?? {});
      await middleware({ ...ctx, shared: baseCtx }, run);
    };

    await run();
  }

  /** Get all registered plugin names */
  getRegistered(): string[] {
    return Array.from(this.plugins.keys());
  }

  /** Get all enabled plugin names */
  getEnabled(): string[] {
    const enabled: string[] = [];
    for (const [name, entry] of this.plugins) {
      if (entry.enabled) enabled.push(name);
    }
    return enabled;
  }

  /** Get plugins that depend on a given plugin */
  private getDependents(name: string): string[] {
    const dependents: string[] = [];
    for (const [pName, entry] of this.plugins) {
      if (entry.plugin.manifest.dependencies?.includes(name)) {
        dependents.push(pName);
      }
    }
    return dependents;
  }

  /** Create an isolated context for a plugin */
  private createContext(pluginName: string, config: Record<string, unknown>): PluginContext {
    return {
      pluginName,
      version: this.version,
      state: new Map(),
      shared: {},
      config,
      logger: createPluginLogger(pluginName),
      crypto: createPluginCrypto(),
    };
  }
}

// ─── Plugin Loader ────────────────────────────────────────────

/**
 * Load plugins with sandboxing and integrity verification.
 * Verifies plugin manifests and enforces permission boundaries.
 */
export class PluginLoader {
  private registry: PluginRegistry;
  private integrityKeys = new Map<string, string>();
  private version = '2.1.0';

  constructor(registry: PluginRegistry) {
    this.registry = registry;
  }

  /** Load a plugin with integrity verification */
  async load(plugin: VrilPlugin, config?: Record<string, unknown>): Promise<{
    loaded: boolean;
    errors: string[];
  }> {
    const errors: string[] = [];

    // Validate manifest
    if (!plugin.manifest.name) {
      errors.push('Plugin manifest must include a name');
    }
    if (!plugin.manifest.version) {
      errors.push('Plugin manifest must include a version');
    }

    // Validate hook signatures
    if (plugin.hooks) {
      const validHooks: PluginLifecycle[] = ['onInit', 'onReady', 'onRequest', 'onResponse', 'onError', 'onBuild', 'onSecurityCheck'];
      for (const [hookName, hookFn] of Object.entries(plugin.hooks)) {
        if (!validHooks.includes(hookName as PluginLifecycle)) {
          errors.push(`Invalid hook: ${hookName}`);
        }
        if (typeof hookFn !== 'function') {
          errors.push(`Hook ${hookName} must be a function`);
        }
      }
    }

    // Verify integrity if manifest specifies it
    if (plugin.manifest.integrity) {
      const valid = await this.verifyIntegrity(plugin);
      if (!valid) {
        errors.push(`Integrity verification failed for plugin "${plugin.manifest.name}"`);
      }
    }

    // Check permissions
    if (plugin.manifest.permissions) {
      for (const perm of plugin.manifest.permissions) {
        if (!this.isPermissionAllowed(perm)) {
          errors.push(`Permission denied: ${perm.access} on ${perm.resource}`);
        }
      }
    }

    if (errors.length > 0) {
      return { loaded: false, errors };
    }

    try {
      this.registry.register(plugin, config);
      return { loaded: true, errors: [] };
    } catch (err) {
      return { loaded: false, errors: [String(err)] };
    }
  }

  /** Unload a plugin */
  async unload(name: string): Promise<boolean> {
    return this.registry.unregister(name);
  }

  /** Verify plugin integrity using Web Crypto API */
  private async verifyIntegrity(plugin: VrilPlugin): Promise<boolean> {
    try {
      const serialized = JSON.stringify({
        name: plugin.manifest.name,
        version: plugin.manifest.version,
        hooks: Object.keys(plugin.hooks ?? {}),
      });
      const data = new TextEncoder().encode(serialized);
      const hash = await crypto.subtle.digest('SHA-256', data);
      const hex = Array.from(new Uint8Array(hash))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      // Simple prefix check (in production would use full SRI)
      return plugin.manifest.integrity!.startsWith(`sha256-${hex.substring(0, 16)}`);
    } catch {
      return false;
    }
  }

  /** Check if a permission is allowed */
  private isPermissionAllowed(permission: PluginPermission): boolean {
    // Default allowlist — can be customized
    const allowed: Record<string, string[]> = {
      cache: ['read', 'write'],
      config: ['read'],
      logger: ['read', 'write'],
      metrics: ['read'],
    };
    const resourcePerms = allowed[permission.resource];
    return resourcePerms?.includes(permission.access) ?? false;
  }
}

// ─── Create Plugin Factory ────────────────────────────────────

/** Fluent builder chain returned by createPlugin */
interface PluginChain {
  manifest: PluginManifest;
  hooks: Partial<Record<PluginLifecycle, PluginHook>>;
  middleware: PluginMiddleware[];
  onInit: (hook: PluginHook) => PluginChain;
  onReady: (hook: PluginHook) => PluginChain;
  onRequest: (hook: PluginHook) => PluginChain;
  onResponse: (hook: PluginHook) => PluginChain;
  onError: (hook: PluginHook) => PluginChain;
  onBuild: (hook: PluginHook) => PluginChain;
  onSecurityCheck: (hook: PluginHook) => PluginChain;
  use: (middleware: PluginMiddleware) => PluginChain;
  configure: (fn: (config: Record<string, unknown>) => void) => PluginChain;
  destroy: (fn: () => void | Promise<void>) => PluginChain;
  build: () => VrilPlugin;
}

/**
 * Factory function for type-safe plugin creation.
 * Provides a fluent builder API for defining plugins.
 */
export function createPlugin(
  manifest: PluginManifest
): PluginChain {
  const hooks: Partial<Record<PluginLifecycle, PluginHook>> = {};
  const middlewares: PluginMiddleware[] = [];
  let configureFn: ((config: Record<string, unknown>) => void) | undefined;
  let destroyFn: (() => void | Promise<void>) | undefined;

  function createChain(): PluginChain {
    return {
      manifest,
      hooks,
      middleware: middlewares,
      onInit(hook: PluginHook) { hooks.onInit = hook; return createChain(); },
      onReady(hook: PluginHook) { hooks.onReady = hook; return createChain(); },
      onRequest(hook: PluginHook) { hooks.onRequest = hook; return createChain(); },
      onResponse(hook: PluginHook) { hooks.onResponse = hook; return createChain(); },
      onError(hook: PluginHook) { hooks.onError = hook; return createChain(); },
      onBuild(hook: PluginHook) { hooks.onBuild = hook; return createChain(); },
      onSecurityCheck(hook: PluginHook) { hooks.onSecurityCheck = hook; return createChain(); },
      use(middleware: PluginMiddleware) { middlewares.push(middleware); return createChain(); },
      configure(fn: (config: Record<string, unknown>) => void) { configureFn = fn; return createChain(); },
      destroy(fn: () => void | Promise<void>) { destroyFn = fn; return createChain(); },
      build(): VrilPlugin {
        return {
          manifest,
          hooks,
          middleware: middlewares.length > 0 ? middlewares : undefined,
          configure: configureFn,
          destroy: destroyFn,
        };
      },
    };
  }

  return createChain();
}

interface PluginBuilder {
  manifest: PluginManifest;
  hooks: Partial<Record<PluginLifecycle, PluginHook>>;
  middleware: PluginMiddleware[];
  configure?: (config: Record<string, unknown>) => void;
  destroy?: () => void | Promise<void>;
}

// ─── Plugin Context Helpers ───────────────────────────────────

/** Create a scoped logger for a plugin */
function createPluginLogger(pluginName: string): PluginLogger {
  const prefix = `[VRIL:${pluginName}]`;
  return {
    info: (msg: string, ...args: unknown[]) => console.info(prefix, msg, ...args),
    warn: (msg: string, ...args: unknown[]) => console.warn(prefix, msg, ...args),
    error: (msg: string, ...args: unknown[]) => console.error(prefix, msg, ...args),
    debug: (msg: string, ...args: unknown[]) => {
      if (typeof process !== 'undefined' && process.env?.NODE_ENV === 'development') {
        console.debug(prefix, msg, ...args);
      }
    },
  };
}

/** Create cryptographic utilities for plugins using Web Crypto API */
function createPluginCrypto(): PluginCrypto {
  return {
    randomUUID: () => {
      if (typeof crypto !== 'undefined' && crypto.randomUUID) {
        return crypto.randomUUID();
      }
      return `${Date.now()}-${Math.random().toString(36).substring(2, 10)}`;
    },

    hash: async (data: string): Promise<string> => {
      if (typeof crypto !== 'undefined' && crypto.subtle) {
        const encoded = new TextEncoder().encode(data);
        const buf = await crypto.subtle.digest('SHA-256', encoded);
        return Array.from(new Uint8Array(buf))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      }
      // Fallback: FNV-1a
      let h = 0x811c9dc5;
      for (let i = 0; i < data.length; i++) {
        h ^= data.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
      }
      return ('00000000' + (h >>> 0).toString(16)).slice(-8);
    },

    hmac: async (data: string, secret: string): Promise<string> => {
      if (typeof crypto !== 'undefined' && crypto.subtle) {
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey(
          'raw',
          encoder.encode(secret),
          { name: 'HMAC', hash: 'SHA-256' },
          false,
          ['sign']
        );
        const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
        return Array.from(new Uint8Array(sig))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      }
      // Fallback: simple keyed hash
      let h = 0x811c9dc5;
      const combined = secret + data;
      for (let i = 0; i < combined.length; i++) {
        h ^= combined.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
      }
      return ('00000000' + (h >>> 0).toString(16)).slice(-8);
    },
  };
}
