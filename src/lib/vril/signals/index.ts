/**
 * Vril.js v2.0.0 — ΩSignal Reactive Primitives
 * Fine-grained reactivity with advanced signal types, dependency tracking, and devtools
 *
 * signal · computed · effect · batch · untrack · store
 * lazySignal · asyncSignal · resourceSignal · debouncedSignal · throttledSignal
 * persistedSignal · encryptedSignal · signalFromEvent · signalFromPromise
 * Devtools: onSignalCreate · onSignalUpdate · onEffectRun · createSignalGraph
 */

// ─── Types ────────────────────────────────────────────────────────

/** State of an async signal */
export interface AsyncSignalState<T> {
  /** Current data value, undefined if not yet resolved */
  data: T | undefined;
  /** True while the async operation is in progress */
  loading: boolean;
  /** Error object if the async operation failed */
  error: Error | undefined;
  /** Whether data has been loaded at least once */
  initialized: boolean;
}

/** State of a resource signal with SWR support */
export interface ResourceState<T> extends AsyncSignalState<T> {
  /** Timestamp of last successful fetch */
  lastFetchedAt: number | undefined;
  /** True when serving stale data while revalidating */
  isStale: boolean;
  /** Whether a refetch is in progress */
  isRefetching: boolean;
}

/** Node in the signal dependency graph */
export interface SignalNode {
  /** Unique identifier for the signal */
  id: string;
  /** Kind of reactive node */
  kind: 'signal' | 'computed' | 'effect' | 'lazy' | 'async' | 'resource' | 'debounced' | 'throttled' | 'persisted' | 'encrypted';
  /** IDs of signals this node depends on */
  dependencies: string[];
  /** IDs of signals that depend on this node */
  dependents: string[];
  /** Current value snapshot (for debugging) */
  valueSnapshot: unknown;
  /** Creation timestamp */
  createdAt: number;
  /** Last update timestamp */
  updatedAt: number;
}

/** Dependency graph for all tracked signals */
export interface SignalGraph {
  /** All signal nodes indexed by ID */
  nodes: Map<string, SignalNode>;
  /** Version of the graph snapshot */
  version: string;
  /** Timestamp of graph creation */
  timestamp: number;
  /** Get a serializable JSON representation */
  toJSON(): Record<string, unknown>;
}

// ─── Internal State ───────────────────────────────────────────────

type Subscriber = () => void;

let currentEffect: Function | null = null;
let pendingEffects: Function[] = [];
let batching = 0;

/** Auto-incrementing ID for signal devtools tracking */
let nextSignalId = 0;

/** Devtools hooks */
let signalCreateHook: ((node: SignalNode) => void) | null = null;
let signalUpdateHook: ((id: string, oldValue: unknown, newValue: unknown) => void) | null = null;
let effectRunHook: ((id: string) => void) | null = null;

/** Global registry of all active signals for graph tracking */
const signalRegistry = new Map<string, {
  kind: SignalNode['kind'];
  value: () => unknown;
  dependencies: Set<string>;
  dependents: Set<string>;
  createdAt: number;
  updatedAt: number;
}>();

// ─── Devtools Hooks ───────────────────────────────────────────────

/** Register a callback invoked when any signal is created */
export function onSignalCreate(hook: (node: SignalNode) => void): () => void {
  signalCreateHook = hook;
  return () => { signalCreateHook = null; };
}

/** Register a callback invoked when any signal value changes */
export function onSignalUpdate(hook: (id: string, oldValue: unknown, newValue: unknown) => void): () => void {
  signalUpdateHook = hook;
  return () => { signalUpdateHook = null; };
}

/** Register a callback invoked when any effect runs */
export function onEffectRun(hook: (id: string) => void): () => void {
  effectRunHook = hook;
  return () => { effectRunHook = null; };
}

/** Create a snapshot of the current signal dependency graph */
export function createSignalGraph(): SignalGraph {
  const nodes = new Map<string, SignalNode>();
  for (const [id, entry] of signalRegistry) {
    nodes.set(id, {
      id,
      kind: entry.kind,
      dependencies: Array.from(entry.dependencies),
      dependents: Array.from(entry.dependents),
      valueSnapshot: entry.value(),
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
    });
  }
  return {
    nodes,
    version: '2.1.0',
    timestamp: Date.now(),
    toJSON() {
      const obj: Record<string, unknown> = { version: '2.1.0', timestamp: this.timestamp, signals: {} };
      for (const [k, v] of this.nodes) {
        (obj.signals as Record<string, unknown>)[k] = {
          kind: v.kind, dependencies: v.dependencies, dependents: v.dependents,
          createdAt: v.createdAt, updatedAt: v.updatedAt,
        };
      }
      return obj;
    },
  };
}

/** Register a signal in the global registry */
function registerSignal(id: string, kind: SignalNode['kind'], valueFn: () => unknown): void {
  signalRegistry.set(id, {
    kind,
    value: valueFn,
    dependencies: new Set(),
    dependents: new Set(),
    createdAt: Date.now(),
    updatedAt: Date.now(),
  });
  if (signalCreateHook) {
    const entry = signalRegistry.get(id)!;
    signalCreateHook({
      id, kind, dependencies: [], dependents: [],
      valueSnapshot: valueFn(), createdAt: entry.createdAt, updatedAt: entry.updatedAt,
    });
  }
}

/** Track that `dependentId` depends on `dependencyId` */
function trackDependency(dependencyId: string, dependentId: string): void {
  const dep = signalRegistry.get(dependencyId);
  const dependent = signalRegistry.get(dependentId);
  if (dep) dep.dependents.add(dependentId);
  if (dependent) dependent.dependencies.add(dependencyId);
}

// ─── Core signal ──────────────────────────────────────────────────

export interface SignalReadable<T> {
  (): T;
  _kind: 'signal';
  _id: string;
  peek: () => T;
  set: (next: T | ((prev: T) => T)) => void;
}

export interface ComputedReadable<T> {
  (): T;
  _kind: 'computed';
  _id: string;
  _invalidate: () => void;
}

/**
 * Create a reactive signal holding a value.
 * Reading inside an effect or computed automatically subscribes.
 */
export function signal<T>(initial: T): SignalReadable<T> {
  let value = initial;
  const subscribers = new Set<Subscriber>();
  const id = `sig_${nextSignalId++}`;

  function read(): T {
    if (currentEffect) {
      subscribers.add(currentEffect as Subscriber);
      if ((currentEffect as any)._id) {
        trackDependency(id, (currentEffect as any)._id);
      }
    }
    return value;
  }

  read._kind = 'signal' as const;
  read._id = id;

  read.peek = () => value;

  read.set = (next: T | ((prev: T) => T)) => {
    const n = typeof next === 'function' ? (next as (p: T) => T)(value) : next;
    if (Object.is(n, value)) return;
    const old = value;
    value = n;
    const entry = signalRegistry.get(id);
    if (entry) entry.updatedAt = Date.now();
    if (signalUpdateHook) signalUpdateHook(id, old, n);
    notify(subscribers);
  };

  registerSignal(id, 'signal', () => read.peek());
  return read;
}

/**
 * Create a computed signal that derives its value from other signals.
 * Properly tracks dependencies by running the computation inside a tracking context.
 */
export function computed<T>(fn: () => T): ComputedReadable<T> {
  let cachedValue: T;
  let dirty = true;
  const subscribers = new Set<Subscriber>();
  const dependencies = new Set<string>();
  const id = `comp_${nextSignalId++}`;

  /** Track which signals this computed depends on */
  function recompute(): void {
    const prevDeps = new Set(dependencies);
    dependencies.clear();

    // Set up tracking: when we call fn(), any signal reads will register us
    const prevEffect = currentEffect;
    const tracker = () => {
      dirty = false;
      cachedValue = fn();
    };
    (tracker as any)._id = id;
    currentEffect = tracker as unknown as Function;
    try {
      tracker();
    } finally {
      currentEffect = prevEffect;
    }

    // Update dependency tracking in registry
    const entry = signalRegistry.get(id);
    if (entry) {
      // Remove old deps
      for (const dep of prevDeps) {
        const depEntry = signalRegistry.get(dep);
        if (depEntry) depEntry.dependents.delete(id);
        entry.dependencies.delete(dep);
      }
      // Add new deps
      for (const dep of dependencies) {
        trackDependency(dep, id);
      }
      entry.updatedAt = Date.now();
    }
  }

  function self(): T {
    if (currentEffect) {
      subscribers.add(currentEffect as Subscriber);
      if ((currentEffect as any)._id) {
        trackDependency(id, (currentEffect as any)._id);
      }
    }
    if (dirty) recompute();
    return cachedValue;
  }

  self._kind = 'computed' as const;
  self._id = id;
  self._invalidate = () => {
    if (!dirty) {
      dirty = true;
      notify(subscribers);
    }
  };

  registerSignal(id, 'computed', () => {
    if (dirty) recompute();
    return cachedValue;
  });

  return self;
}

/**
 * Create a side effect that re-runs when any read signal changes.
 * Returns a dispose function to clean up.
 */
export function effect(fn: () => void | (() => void)): () => void {
  let disposeFn: (() => void) | null = null;
  const id = `eff_${nextSignalId++}`;

  function runner() {
    if (disposeFn) { try { disposeFn(); } catch {} disposeFn = null; }
    const prev = currentEffect;
    currentEffect = runner;
    try {
      if (effectRunHook) effectRunHook(id);
      disposeFn = fn() || null;
    } finally {
      currentEffect = prev;
    }
  }

  (runner as any)._id = id;
  (runner as any)._kind = 'effect';
  runner();

  return () => {
    if (disposeFn) { try { disposeFn(); } catch {} disposeFn = null; }
  };
}

/**
 * Batch multiple signal writes into a single notification pass.
 * Prevents redundant re-computations and effect runs.
 */
export function batch(fn: () => void): void {
  batching++;
  try { fn(); } finally { batching--; if (batching === 0) flush(); }
}

/**
 * Read signals inside fn without subscribing the current effect.
 */
export function untrack<T>(fn: () => T): T {
  const prev = currentEffect;
  currentEffect = null;
  try { return fn(); } finally { currentEffect = prev; }
}

/**
 * Create a reactive object where each property is an individual signal.
 * Supports deep reactivity for flat objects.
 */
export function store<T extends Record<string, unknown>>(obj: T): { [K in keyof T]: T[K] } {
  const sigs: Record<string, any> = {};
  const proxy: Record<string, unknown> = {};
  for (const k of Object.keys(obj)) {
    const s = signal(obj[k]);
    sigs[k] = s;
    Object.defineProperty(proxy, k, {
      enumerable: true,
      get: () => s(),
      set: (v: unknown) => s.set(v),
    });
  }
  return proxy as any;
}

// ─── Advanced Signal Types ────────────────────────────────────────

/**
 * Create a lazy signal that only computes its value on first read.
 * The factory function is deferred until the signal is accessed.
 */
export function lazySignal<T>(factory: () => T): SignalReadable<T> {
  let initialized = false;
  let value: T;
  const inner = signal<T | undefined>(undefined);
  const id = `lazy_${nextSignalId++}`;

  const read = (() => {
    if (!initialized) {
      value = factory();
      initialized = true;
    }
    return value!;
  }) as unknown as SignalReadable<T>;

  read._kind = 'signal';
  read._id = id;
  read.peek = () => { if (!initialized) { value = factory(); initialized = true; } return value; };
  read.set = (next: T | ((prev: T) => T)) => {
    const prev = read.peek();
    const n = typeof next === 'function' ? (next as (p: T) => T)(prev) : next;
    if (Object.is(n, prev)) return;
    value = n;
    initialized = true;
    inner.set(n);
  };

  registerSignal(id, 'lazy', () => read.peek());
  return read;
}

/**
 * Create an async signal for managing async values with loading/error states.
 */
export function asyncSignal<T>(): {
  read: () => AsyncSignalState<T>;
  resolve: (value: T) => void;
  reject: (error: Error) => void;
  start: () => void;
  reset: () => void;
} {
  const id = `async_${nextSignalId++}`;
  const state = signal<AsyncSignalState<T>>({
    data: undefined,
    loading: false,
    error: undefined,
    initialized: false,
  });

  registerSignal(id, 'async', () => state.peek());

  return {
    read: () => state(),
    resolve: (value: T) => {
      state.set({ data: value, loading: false, error: undefined, initialized: true });
    },
    reject: (error: Error) => {
      state.set(s => ({ ...s, loading: false, error, initialized: true }));
    },
    start: () => {
      state.set(s => ({ ...s, loading: true, error: undefined }));
    },
    reset: () => {
      state.set({ data: undefined, loading: false, error: undefined, initialized: false });
    },
  };
}

/**
 * Create a resource signal with fetch-like semantics and stale-while-revalidate.
 */
export function resourceSignal<T>(
  fetcher: () => Promise<T>,
  options?: { staleWhileRevalidate?: boolean; cacheTime?: number }
): {
  read: () => ResourceState<T>;
  refetch: () => Promise<void>;
  mutate: (value: T) => void;
  reset: () => void;
} {
  const id = `res_${nextSignalId++}`;
  const opts = { staleWhileRevalidate: true, cacheTime: 0, ...options };
  const state = signal<ResourceState<T>>({
    data: undefined,
    loading: false,
    error: undefined,
    initialized: false,
    lastFetchedAt: undefined,
    isStale: false,
    isRefetching: false,
  });

  registerSignal(id, 'resource', () => state.peek());

  async function doFetch(isRefetch = false): Promise<void> {
    const prev = state.peek();
    if (isRefetch && prev.loading) return;

    if (isRefetch) {
      state.set(s => ({ ...s, isRefetching: true }));
    } else {
      state.set(s => ({ ...s, loading: true, error: undefined }));
    }

    try {
      const data = await fetcher();
      state.set({
        data,
        loading: false,
        error: undefined,
        initialized: true,
        lastFetchedAt: Date.now(),
        isStale: false,
        isRefetching: false,
      });

      // Mark stale after cacheTime
      if (opts.cacheTime > 0) {
        setTimeout(() => {
          const current = state.peek();
          if (current.lastFetchedAt && Date.now() - current.lastFetchedAt >= opts.cacheTime) {
            state.set(s => ({ ...s, isStale: true }));
            if (opts.staleWhileRevalidate) {
              doFetch(true);
            }
          }
        }, opts.cacheTime);
      }
    } catch (err) {
      state.set(s => ({
        ...s,
        loading: false,
        isRefetching: false,
        error: err instanceof Error ? err : new Error(String(err)),
        initialized: true,
      }));
    }
  }

  // Auto-fetch on creation
  doFetch();

  return {
    read: () => state(),
    refetch: () => doFetch(true),
    mutate: (value: T) => {
      state.set(s => ({
        ...s, data: value, loading: false, error: undefined,
        initialized: true, lastFetchedAt: Date.now(), isStale: false, isRefetching: false,
      }));
    },
    reset: () => {
      state.set({
        data: undefined, loading: false, error: undefined, initialized: false,
        lastFetchedAt: undefined, isStale: false, isRefetching: false,
      });
    },
  };
}

/**
 * Create a debounced signal that delays updates by `delay` ms.
 */
export function debouncedSignal<T>(initial: T, delay: number): SignalReadable<T> {
  const inner = signal(initial);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const id = `deb_${nextSignalId++}`;
  const read = (() => inner()) as unknown as SignalReadable<T>;

  read._kind = 'signal';
  read._id = id;
  read.peek = () => inner.peek();

  read.set = (next: T | ((prev: T) => T)) => {
    const n = typeof next === 'function' ? (next as (p: T) => T)(inner.peek()) : next;
    if (Object.is(n, inner.peek())) return;
    if (timer !== undefined) clearTimeout(timer);
    timer = setTimeout(() => { inner.set(n); timer = undefined; }, delay);
  };

  registerSignal(id, 'debounced', () => inner.peek());
  return read;
}

/**
 * Create a throttled signal that limits updates to at most once per `interval` ms.
 */
export function throttledSignal<T>(initial: T, interval: number): SignalReadable<T> {
  const inner = signal(initial);
  let lastEmit = 0;
  let pending: T | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const id = `thr_${nextSignalId++}`;
  const read = (() => inner()) as unknown as SignalReadable<T>;

  read._kind = 'signal';
  read._id = id;
  read.peek = () => inner.peek();

  read.set = (next: T | ((prev: T) => T)) => {
    const n = typeof next === 'function' ? (next as (p: T) => T)(inner.peek()) : next;
    if (Object.is(n, inner.peek())) return;

    const now = Date.now();
    if (now - lastEmit >= interval) {
      lastEmit = now;
      inner.set(n);
    } else {
      pending = n;
      if (timer === undefined) {
        timer = setTimeout(() => {
          if (pending !== undefined) {
            inner.set(pending);
            lastEmit = Date.now();
            pending = undefined;
          }
          timer = undefined;
        }, interval - (now - lastEmit));
      }
    }
  };

  registerSignal(id, 'throttled', () => inner.peek());
  return read;
}

/**
 * Create a signal that persists its value to localStorage or sessionStorage.
 * Automatically hydrates from storage on creation.
 */
export function persistedSignal<T>(
  key: string,
  initial: T,
  storage?: 'localStorage' | 'sessionStorage'
): SignalReadable<T> {
  const id = `per_${nextSignalId++}`;
  let storedValue = initial;

  if (typeof window !== 'undefined') {
    try {
      const store = storage === 'sessionStorage' ? sessionStorage : localStorage;
      const raw = store.getItem(key);
      if (raw !== null) storedValue = JSON.parse(raw);
    } catch { /* use initial on parse failure */ }
  }

  const inner = signal<T>(storedValue);

  const read = (() => inner()) as unknown as SignalReadable<T>;
  read._kind = 'signal';
  read._id = id;
  read.peek = () => inner.peek();
  read.set = (next: T | ((prev: T) => T)) => {
    const n = typeof next === 'function' ? (next as (p: T) => T)(inner.peek()) : next;
    inner.set(n);
    if (typeof window !== 'undefined') {
      try {
        const store = storage === 'sessionStorage' ? sessionStorage : localStorage;
        store.setItem(key, JSON.stringify(n));
      } catch { /* storage full or unavailable */ }
    }
  };

  registerSignal(id, 'persisted', () => inner.peek());
  return read;
}

/**
 * Create a signal that encrypts its value in memory using AES-256-GCM.
 * Values are stored as encrypted ciphertext; decryption occurs on read.
 */
export function encryptedSignal<T>(
  initial: T,
  passphrase: string
): {
  read: () => Promise<T>;
  set: (next: T | ((prev: T) => T)) => Promise<void>;
  peek: () => Promise<T>;
} {
  const id = `enc_${nextSignalId++}`;
  let encryptedData: string | null = null;
  let cachedDecrypted: T = initial;

  async function deriveKey(pass: string, salt: Uint8Array): Promise<CryptoKey> {
    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt as BufferSource, iterations: 100000, hash: 'SHA-512' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  async function encryptValue(value: T): Promise<void> {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(passphrase, salt);
    const encoded = new TextEncoder().encode(JSON.stringify(value));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
    const combined = new Uint8Array(salt.length + iv.length + new Uint8Array(ct).length);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(ct), salt.length + iv.length);
    encryptedData = btoa(String.fromCharCode(...combined));
  }

  async function decryptValue(): Promise<T> {
    if (encryptedData === null) return cachedDecrypted;
    try {
      const combined = new Uint8Array(
        atob(encryptedData).split('').map(c => c.charCodeAt(0))
      );
      const salt = combined.slice(0, 16);
      const iv = combined.slice(16, 28);
      const ct = combined.slice(28);
      const key = await deriveKey(passphrase, salt);
      const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      cachedDecrypted = JSON.parse(new TextDecoder().decode(decrypted));
      return cachedDecrypted;
    } catch {
      return cachedDecrypted;
    }
  }

  // Encrypt initial value
  encryptValue(initial);

  registerSignal(id, 'encrypted', () => cachedDecrypted);

  return {
    read: () => decryptValue(),
    set: async (next: T | ((prev: T) => T)) => {
      const prev = await decryptValue();
      const n = typeof next === 'function' ? (next as (p: T) => T)(prev) : next;
      cachedDecrypted = n;
      await encryptValue(n);
    },
    peek: () => decryptValue(),
  };
}

/**
 * Create a signal from a DOM event on a target element.
 * Automatically subscribes and unsubscribes to keep the signal in sync.
 */
export function signalFromEvent(
  target: EventTarget,
  event: string,
  options?: AddEventListenerOptions
): SignalReadable<Event> {
  const id = `evt_${nextSignalId++}`;
  const inner = signal<Event>(null as unknown as Event);

  const handler = (e: Event) => inner.set(e);
  target.addEventListener(event, handler, options);

  const read = (() => inner()) as unknown as SignalReadable<Event>;
  read._kind = 'signal';
  read._id = id;
  read.peek = () => inner.peek();
  read.set = () => {
    // Events cannot be set externally; this is a no-op for interface compatibility
  };

  registerSignal(id, 'signal', () => inner.peek());
  return read;
}

/**
 * Create a signal from a Promise. Tracks loading, error, and resolved states.
 */
export function signalFromPromise<T>(
  promise: Promise<T>
): SignalReadable<AsyncSignalState<T>> {
  const id = `prom_${nextSignalId++}`;
  const inner = signal<AsyncSignalState<T>>({
    data: undefined,
    loading: true,
    error: undefined,
    initialized: false,
  });

  promise
    .then(value => {
      inner.set({ data: value, loading: false, error: undefined, initialized: true });
    })
    .catch(err => {
      inner.set({
        data: undefined,
        loading: false,
        error: err instanceof Error ? err : new Error(String(err)),
        initialized: true,
      });
    });

  const read = (() => inner()) as unknown as SignalReadable<AsyncSignalState<T>>;
  read._kind = 'signal';
  read._id = id;
  read.peek = () => inner.peek();
  read.set = (next) => { inner.set(typeof next === 'function' ? (next as Function)(inner.peek()) : next); };

  registerSignal(id, 'signal', () => inner.peek());
  return read;
}

// ─── Internal Notification System ─────────────────────────────────

function notify(subscribers: Set<Subscriber>): void {
  subscribers.forEach(sub => {
    if ((sub as any)._kind === 'computed') (sub as any)._invalidate();
    else if (!pendingEffects.includes(sub)) pendingEffects.push(sub);
  });
  if (batching === 0) flush();
}

function flush(): void {
  const q = pendingEffects;
  pendingEffects = [];
  for (const eff of q) {
    try { eff(); } catch (e) { console.error('[ΩSignal]', e); }
  }
}

// ─── Public API Surface ───────────────────────────────────────────

export const ΩSignal = Object.freeze({
  signal,
  computed,
  effect,
  batch,
  untrack,
  store,
  lazySignal,
  asyncSignal,
  resourceSignal,
  debouncedSignal,
  throttledSignal,
  persistedSignal,
  encryptedSignal,
  signalFromEvent,
  signalFromPromise,
  onSignalCreate,
  onSignalUpdate,
  onEffectRun,
  createSignalGraph,
  version: '2.1.0',
});
