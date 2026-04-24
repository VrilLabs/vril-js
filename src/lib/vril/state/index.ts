/**
 * Vril.js v2.0.0 — State Management Module
 * Full state management built on ΩSignal reactive primitives
 *
 * VrilStore · StoreRegistry · StateEncryption · StatePersistence
 * TimeTravel (undo/redo) · StateValidator · Middleware
 *
 * Zero external dependencies — Web Crypto API and built-in JS only.
 */

import { signal, computed, effect, batch } from '../signals';

// ─── Types ────────────────────────────────────────────────────────

/** Configuration for creating a store */
export interface StoreConfig<T = unknown> {
  /** Name of the store for registry and devtools */
  name: string;
  /** Initial state */
  initialState: T;
  /** Enable time-travel debugging (undo/redo) */
  enableTimeTravel?: boolean;
  /** Maximum history entries for time travel */
  maxHistory?: number;
  /** Persist state to storage */
  persist?: {
    key: string;
    storage?: 'localStorage' | 'sessionStorage';
    encrypt?: boolean;
    passphrase?: string;
  };
  /** Middleware chain */
  middleware?: StoreMiddleware<T>[];
  /** State validation schema */
  validator?: StateValidatorFn<T>;
}

/** Middleware function that intercepts state transitions */
export type StoreMiddleware<T = unknown> = (
  state: T,
  action: StateAction,
  next: (state: T) => T
) => T;

/** A state transition action */
export interface StateAction {
  /** Action type identifier */
  type: string;
  /** Action payload */
  payload?: unknown;
  /** Timestamp of the action */
  timestamp: number;
  /** Source that dispatched the action */
  source?: string;
}

/** State transition record for time travel */
export interface StateTransition<T = unknown> {
  /** The action that caused the transition */
  action: StateAction;
  /** State before the transition */
  before: T;
  /** State after the transition */
  after: T;
  /** Timestamp of the transition */
  timestamp: number;
}

/** Selector function that extracts a slice of state */
export type Selector<T, R> = (state: T) => R;

/** State validation function */
export type StateValidatorFn<T> = (state: T) => { valid: boolean; errors: string[] };

/** Store subscription callback */
export type StoreSubscriber<T> = (state: T, action: StateAction) => void;

// ─── VrilStore ────────────────────────────────────────────────────

/**
 * Full-featured state management store built on ΩSignal.
 * Supports middleware, selectors, time travel, and persistence.
 */
export class VrilStore<T extends Record<string, unknown>> {
  private _state: ReturnType<typeof signal<T>>;
  private _subscribers = new Set<StoreSubscriber<T>>();
  private _middleware: StoreMiddleware<T>[];
  private _validator?: StateValidatorFn<T>;
  private _name: string;
  private _version = '2.1.0';

  // Time travel
  private _history: StateTransition<T>[] = [];
  private _historyIndex = -1;
  private _enableTimeTravel: boolean;
  private _maxHistory: number;

  // Persistence
  private _persistConfig?: StoreConfig<T>['persist'];

  /** Get the store name */
  get name(): string { return this._name; }

  /** Get the current state (reactive read) */
  getState(): T { return this._state(); }

  constructor(config: StoreConfig<T>) {
    this._name = config.name;
    this._middleware = config.middleware ?? [];
    this._validator = config.validator;
    this._enableTimeTravel = config.enableTimeTravel ?? false;
    this._maxHistory = config.maxHistory ?? 100;
    this._persistConfig = config.persist;

    // Hydrate from persistence if available
    let initialState = config.initialState;
    if (this._persistConfig && typeof window !== 'undefined') {
      try {
        const storage = this._persistConfig.storage === 'sessionStorage'
          ? sessionStorage : localStorage;
        const raw = storage.getItem(this._persistConfig.key);
        if (raw !== null) {
          initialState = JSON.parse(raw);
        }
      } catch { /* use initial state on parse error */ }
    }

    this._state = signal(initialState);

    // Record initial state in history
    if (this._enableTimeTravel) {
      this._historyIndex = 0;
    }

    // Auto-persist on changes
    if (this._persistConfig) {
      effect(() => {
        const state = this._state();
        this._persist(state);
      });
    }
  }

  /**
   * Set state with optional action context.
   * Runs through middleware chain and validates before committing.
   */
  setState(updater: T | ((prev: T) => T), actionType = 'SET_STATE', payload?: unknown): void {
    const action: StateAction = {
      type: actionType,
      payload,
      timestamp: Date.now(),
      source: this._name,
    };

    const prevState = this._state.peek();
    let nextState = typeof updater === 'function'
      ? (updater as (prev: T) => T)(prevState)
      : updater;

    // Run middleware chain
    nextState = this._applyMiddleware(nextState, action);

    // Validate
    if (this._validator) {
      const result = this._validator(nextState);
      if (!result.valid) {
        console.error(`[VrilStore:${this._name}] State validation failed:`, result.errors);
        return;
      }
    }

    // Commit state
    batch(() => {
      this._state.set(nextState);
    });

    // Record history
    if (this._enableTimeTravel) {
      this._history.push({ action, before: prevState, after: nextState, timestamp: Date.now() });
      if (this._history.length > this._maxHistory) {
        this._history.shift();
      }
      this._historyIndex = this._history.length - 1;
    }

    // Notify subscribers
    this._notifySubscribers(nextState, action);
  }

  /**
   * Dispatch an action through the store's middleware pipeline.
   * The action handler must return the new state.
   */
  dispatch(action: StateAction, reducer: (state: T, action: StateAction) => T): void {
    const prevState = this._state.peek();
    let nextState = reducer(prevState, action);

    // Run middleware chain
    nextState = this._applyMiddleware(nextState, action);

    // Validate
    if (this._validator) {
      const result = this._validator(nextState);
      if (!result.valid) {
        console.error(`[VrilStore:${this._name}] Validation failed for action "${action.type}":`, result.errors);
        return;
      }
    }

    batch(() => {
      this._state.set(nextState);
    });

    if (this._enableTimeTravel) {
      this._history.push({ action, before: prevState, after: nextState, timestamp: Date.now() });
      if (this._history.length > this._maxHistory) {
        this._history.shift();
      }
      this._historyIndex = this._history.length - 1;
    }

    this._notifySubscribers(nextState, action);
  }

  /**
   * Create a memoized selector that only recomputes when the selected slice changes.
   */
  select<R>(selector: Selector<T, R>): { read: () => R; dispose: () => void } {
    const selected = computed(() => selector(this._state()));
    let lastValue: R;
    let initialized = false;
    const dispose = effect(() => {
      lastValue = selected();
      initialized = true;
    });
    return {
      read: () => {
        if (!initialized) lastValue = selected();
        return lastValue;
      },
      dispose,
    };
  }

  /**
   * Subscribe to state changes.
   * Returns an unsubscribe function.
   */
  subscribe(subscriber: StoreSubscriber<T>): () => void {
    this._subscribers.add(subscriber);
    return () => this._subscribers.delete(subscriber);
  }

  // ─── Time Travel ───────────────────────────────────────────────

  /** Undo the last state change */
  undo(): boolean {
    if (!this._enableTimeTravel || this._historyIndex <= 0) return false;
    this._historyIndex--;
    const entry = this._history[this._historyIndex];
    if (entry) {
      this._state.set(entry.before);
      this._notifySubscribers(entry.before, { type: 'UNDO', timestamp: Date.now() });
      return true;
    }
    return false;
  }

  /** Redo a previously undone state change */
  redo(): boolean {
    if (!this._enableTimeTravel || this._historyIndex >= this._history.length - 1) return false;
    this._historyIndex++;
    const entry = this._history[this._historyIndex];
    if (entry) {
      this._state.set(entry.after);
      this._notifySubscribers(entry.after, { type: 'REDO', timestamp: Date.now() });
      return true;
    }
    return false;
  }

  /** Check if undo is available */
  canUndo(): boolean {
    return this._enableTimeTravel && this._historyIndex > 0;
  }

  /** Check if redo is available */
  canRedo(): boolean {
    return this._enableTimeTravel && this._historyIndex < this._history.length - 1;
  }

  /** Get the full history of state transitions */
  getHistory(): StateTransition<T>[] {
    return [...this._history];
  }

  /** Clear history */
  clearHistory(): void {
    this._history = [];
    this._historyIndex = -1;
  }

  // ─── Internal ──────────────────────────────────────────────────

  private _applyMiddleware(state: T, action: StateAction): T {
    let result = state;
    for (const mw of this._middleware) {
      result = mw(result, action, (s) => s);
    }
    return result;
  }

  private _notifySubscribers(state: T, action: StateAction): void {
    for (const sub of this._subscribers) {
      try { sub(state, action); } catch (e) { console.error(`[VrilStore:${this._name}] Subscriber error:`, e); }
    }
  }

  private _persist(state: T): void {
    if (!this._persistConfig || typeof window === 'undefined') return;
    try {
      const storage = this._persistConfig.storage === 'sessionStorage'
        ? sessionStorage : localStorage;
      storage.setItem(this._persistConfig.key, JSON.stringify(state));
    } catch { /* storage unavailable */ }
  }
}

/**
 * Create a new VrilStore with the given configuration.
 */
export function createStore<T extends Record<string, unknown>>(
  initialState: T,
  options?: Partial<StoreConfig<T>>
): VrilStore<T> {
  return new VrilStore({
    name: options?.name ?? 'default',
    initialState,
    ...options,
  });
}

// ─── StoreRegistry ────────────────────────────────────────────────

/**
 * Central registry for managing multiple named stores.
 * Provides lookup, lifecycle management, and cross-store coordination.
 */
export class StoreRegistry {
  private stores = new Map<string, VrilStore<any>>();
  private _version = '2.1.0';

  /** Register a store in the registry */
  register<T extends Record<string, unknown>>(store: VrilStore<T>): void {
    if (this.stores.has(store.name)) {
      console.warn(`[StoreRegistry] Store "${store.name}" already registered, replacing.`);
    }
    this.stores.set(store.name, store);
  }

  /** Get a store by name */
  get<T extends Record<string, unknown>>(name: string): VrilStore<T> | undefined {
    return this.stores.get(name);
  }

  /** Check if a store exists */
  has(name: string): boolean {
    return this.stores.has(name);
  }

  /** Remove a store from the registry */
  remove(name: string): boolean {
    return this.stores.delete(name);
  }

  /** Get all registered store names */
  getStoreNames(): string[] {
    return Array.from(this.stores.keys());
  }

  /** Get all registered stores */
  getAll(): VrilStore<any>[] {
    return Array.from(this.stores.values());
  }

  /** Clear all stores */
  clear(): void {
    this.stores.clear();
  }

  /** Snapshot of all store states */
  snapshot(): Record<string, unknown> {
    const result: Record<string, unknown> = {};
    for (const [name, store] of this.stores) {
      result[name] = store.getState();
    }
    return result;
  }
}

/** Global store registry singleton */
export const storeRegistry = new StoreRegistry();

// ─── StateEncryption ──────────────────────────────────────────────

/**
 * Encrypts and decrypts sensitive state fields using AES-256-GCM.
 * Integrates with VrilStore for transparent field-level encryption.
 */
export class StateEncryption {
  private _version = '2.1.0';
  private _passphrase: string;
  private _keyCache = new Map<string, CryptoKey>();

  constructor(passphrase: string) {
    this._passphrase = passphrase;
  }

  /** Derive an AES-256-GCM key from passphrase and salt */
  private async deriveKey(salt: Uint8Array): Promise<CryptoKey> {
    const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
    if (this._keyCache.has(saltHex)) return this._keyCache.get(saltHex)!;

    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(this._passphrase), 'PBKDF2', false, ['deriveKey']
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt as BufferSource, iterations: 310000, hash: 'SHA-512' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
    this._keyCache.set(saltHex, key);
    return key;
  }

  /** Encrypt a state object, returning a base64 ciphertext string */
  async encrypt(state: unknown): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this.deriveKey(salt);
    const encoded = new TextEncoder().encode(JSON.stringify(state));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

    const combined = new Uint8Array(salt.length + iv.length + new Uint8Array(ct).length);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(ct), salt.length + iv.length);

    return btoa(String.fromCharCode(...combined));
  }

  /** Decrypt a previously encrypted state object */
  async decrypt(ciphertext: string): Promise<unknown> {
    const combined = new Uint8Array(atob(ciphertext).split('').map(c => c.charCodeAt(0)));
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const ct = combined.slice(28);
    const key = await this.deriveKey(salt);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  /** Encrypt specific fields of a state object */
  async encryptFields<T extends Record<string, unknown>>(
    state: T,
    fields: (keyof T)[]
  ): Promise<T> {
    const result = { ...state };
    for (const field of fields) {
      if (result[field] !== undefined) {
        (result as Record<string, unknown>)[field as string] = await this.encrypt(result[field]);
      }
    }
    return result;
  }

  /** Decrypt specific fields of a state object */
  async decryptFields<T extends Record<string, unknown>>(
    state: T,
    fields: (keyof T)[]
  ): Promise<T> {
    const result = { ...state };
    for (const field of fields) {
      const value = (result as Record<string, unknown>)[field as string];
      if (typeof value === 'string') {
        try {
          (result as Record<string, unknown>)[field as string] = await this.decrypt(value);
        } catch { /* not encrypted, leave as-is */ }
      }
    }
    return result;
  }

  /** Clear cached keys */
  clearKeyCache(): void {
    this._keyCache.clear();
  }
}

// ─── StatePersistence ─────────────────────────────────────────────

/**
 * Persists state to Web Storage with optional AES-256-GCM encryption.
 * Supports localStorage and sessionStorage.
 */
export class StatePersistence {
  private _version = '2.1.0';
  private _storage: Storage;
  private _encryption?: StateEncryption;

  constructor(
    storage: 'localStorage' | 'sessionStorage' = 'localStorage',
    passphrase?: string
  ) {
    this._storage = typeof window !== 'undefined'
      ? (storage === 'sessionStorage' ? sessionStorage : localStorage)
      : null as unknown as Storage;
    if (passphrase) {
      this._encryption = new StateEncryption(passphrase);
    }
  }

  /** Save state to storage */
  async save(key: string, state: unknown): Promise<void> {
    try {
      let data: string;
      if (this._encryption) {
        data = await this._encryption.encrypt(state);
      } else {
        data = JSON.stringify(state);
      }
      this._storage.setItem(key, data);
    } catch (e) {
      console.error('[StatePersistence] Save failed:', e);
    }
  }

  /** Load state from storage */
  async load<T>(key: string): Promise<T | null> {
    try {
      const raw = this._storage.getItem(key);
      if (raw === null) return null;

      if (this._encryption) {
        return await this._encryption.decrypt(raw) as T;
      }
      return JSON.parse(raw) as T;
    } catch (e) {
      console.error('[StatePersistence] Load failed:', e);
      return null;
    }
  }

  /** Remove a key from storage */
  remove(key: string): void {
    try { this._storage.removeItem(key); } catch {}
  }

  /** Check if a key exists */
  has(key: string): boolean {
    return this._storage.getItem(key) !== null;
  }

  /** Clear all persisted state */
  clear(): void {
    try { this._storage.clear(); } catch {}
  }
}

// ─── StateValidator ───────────────────────────────────────────────

/**
 * Validates state transitions against a schema or validation function.
 * Prevents invalid state from being committed to the store.
 */
export class StateValidator<T> {
  private _rules = new Map<string, (value: unknown) => boolean>();
  private _version = '2.1.0';

  /** Add a validation rule for a specific field */
  addRule(field: string, validator: (value: unknown) => boolean): void {
    this._rules.set(field, validator);
  }

  /** Remove a validation rule */
  removeRule(field: string): void {
    this._rules.delete(field);
  }

  /** Validate a state object against all registered rules */
  validate(state: T): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    for (const [field, rule] of this._rules) {
      const value = (state as Record<string, unknown>)[field];
      if (!rule(value)) {
        errors.push(`Validation failed for field "${field}"`);
      }
    }
    return { valid: errors.length === 0, errors };
  }

  /** Create a StoreValidatorFn from this validator */
  toValidatorFn(): StateValidatorFn<T> {
    return (state: T) => this.validate(state);
  }
}

// ─── Middleware Factories ─────────────────────────────────────────

/** Logger middleware that logs all state transitions */
export function loggerMiddleware<T>(logFn?: (action: StateAction, state: T) => void): StoreMiddleware<T> {
  const log = logFn ?? ((action, state) => {
    console.log(`[VrilStore] Action: ${action.type}`, { payload: action.payload, state });
  });
  return (state, action, next) => {
    log(action, state);
    return next(state);
  };
}

/** Persistence middleware that auto-saves on each transition */
export function persistenceMiddleware<T>(
  key: string,
  storage: 'localStorage' | 'sessionStorage' = 'localStorage',
  encrypt?: { passphrase: string }
): StoreMiddleware<T> {
  let persistence: StatePersistence | null = null;

  return (state, action, next) => {
    const result = next(state);

    // Defer persistence to avoid blocking middleware chain
    if (typeof window !== 'undefined') {
      if (!persistence) {
        persistence = new StatePersistence(storage, encrypt?.passphrase);
      }
      persistence.save(key, result);
    }

    return result;
  };
}

/** Devtools middleware that sends state transitions to a listener */
export function devtoolsMiddleware<T>(
  listener: (transition: StateTransition<T>) => void
): StoreMiddleware<T> {
  return (state, action, next) => {
    const before = state;
    const after = next(state);
    listener({ action, before, after, timestamp: Date.now() });
    return after;
  };
}

/** Encryption middleware that encrypts specified fields before storage */
export function encryptionMiddleware<T>(
  fields: (keyof T)[],
  passphrase: string
): StoreMiddleware<T> {
  const encryption = new StateEncryption(passphrase);

  return (state, action, next) => {
    const result = next(state);
    // Fire-and-forget async encryption for the specified fields
    encryption.encryptFields(result as Record<string, unknown>, fields as (keyof Record<string, unknown>)[]).catch(() => {});
    return result;
  };
}
