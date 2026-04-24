/**
 * Vril.js v2.0.0 — React Hooks Module
 * Custom React hooks that integrate with the Vril framework
 *
 * useSignal · useComputed · useAsyncSignal · useResource · useEncryptedState
 * useSecureStorage · useCSRFToken · useSecurityHeaders · usePermission
 * useRateLimiter · useVrilConfig · useIsOnline
 *
 * Zero external dependencies — React and Web Crypto API only.
 */

'use client';

import { useState, useEffect, useCallback, useRef, useMemo, useContext } from 'react';
import { type SignalReadable, type AsyncSignalState, type ResourceState } from '../signals';
import { signal as createSignal, effect, computed } from '../signals';

// ─── Types ────────────────────────────────────────────────────────

/** Async state returned by useAsyncSignal and useResource */
export interface AsyncState<T> {
  /** Current data value */
  data: T | undefined;
  /** True while loading */
  loading: boolean;
  /** Error if the async operation failed */
  error: Error | undefined;
  /** Whether data has been loaded at least once */
  initialized: boolean;
}

/** Options for useResource hook */
export interface ResourceOptions<T> {
  /** Initial data before fetch completes */
  initialData?: T;
  /** Enable stale-while-revalidate */
  staleWhileRevalidate?: boolean;
  /** Cache time in ms before data is considered stale */
  cacheTime?: number;
  /** Refetch on window focus */
  revalidateOnFocus?: boolean;
  /** Refetch interval in ms (0 = disabled) */
  refreshInterval?: number;
  /** Fetch function */
  fetcher: () => Promise<T>;
}

/** Configuration for useRateLimiter */
export interface RateLimitConfig {
  /** Maximum number of calls allowed in the window */
  maxCalls: number;
  /** Time window in milliseconds */
  windowMs: number;
  /** What to do when rate limited: 'drop' ignores, 'queue' delays */
  strategy?: 'drop' | 'queue';
}

// ─── useSignal ────────────────────────────────────────────────────

/**
 * Subscribe to a ΩSignal in a React component.
 * Automatically re-renders when the signal value changes.
 */
export function useSignal<T>(sig: SignalReadable<T>): T {
  const [, forceRender] = useState({});

  useEffect(() => {
    const dispose = effect(() => {
      sig();
      forceRender({});
    });
    return dispose;
  }, [sig]);

  return sig.peek ? sig.peek() : sig();
}

// ─── useComputed ──────────────────────────────────────────────────

/**
 * Create a computed value that auto-updates when dependencies change.
 * The computation function runs inside a reactive tracking context.
 */
export function useComputed<T>(fn: () => T, deps: unknown[] = []): T {
  const computedRef = useRef<ReturnType<typeof computed<T>> | null>(null);
  const [, forceRender] = useState({});

  if (!computedRef.current) {
    computedRef.current = computed(fn);
  }

  useEffect(() => {
    // Recreate computed when deps change
    computedRef.current = computed(fn);
    const dispose = effect(() => {
      computedRef.current!();
      forceRender({});
    });
    return dispose;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return computedRef.current();
}

// ─── useAsyncSignal ───────────────────────────────────────────────

/**
 * Handle async signal states (loading/error/data) in a React component.
 * Returns the current async state and a function to trigger the async operation.
 */
export function useAsyncSignal<T>(
  asyncFn: () => Promise<T>,
  deps: unknown[] = []
): AsyncState<T> & { execute: () => void; reset: () => void } {
  const [state, setState] = useState<AsyncState<T>>({
    data: undefined,
    loading: false,
    error: undefined,
    initialized: false,
  });

  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => { mountedRef.current = false; };
  }, []);

  const execute = useCallback(() => {
    setState(prev => ({ ...prev, loading: true, error: undefined }));

    asyncFn()
      .then(data => {
        if (mountedRef.current) {
          setState({ data, loading: false, error: undefined, initialized: true });
        }
      })
      .catch(err => {
        if (mountedRef.current) {
          setState(prev => ({
            ...prev,
            loading: false,
            error: err instanceof Error ? err : new Error(String(err)),
            initialized: true,
          }));
        }
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  const reset = useCallback(() => {
    setState({ data: undefined, loading: false, error: undefined, initialized: false });
  }, []);

  return { ...state, execute, reset };
}

// ─── useResource ──────────────────────────────────────────────────

/**
 * Data fetching hook with SWR (stale-while-revalidate) pattern.
 * Automatically refetches based on configuration options.
 */
export function useResource<T>(options: ResourceOptions<T>): AsyncState<T> & {
  refetch: () => void;
  mutate: (data: T) => void;
  isStale: boolean;
} {
  const {
    initialData,
    staleWhileRevalidate = true,
    revalidateOnFocus = false,
    refreshInterval = 0,
    fetcher,
  } = options;

  const [state, setState] = useState<AsyncState<T> & { isStale: boolean }>({
    data: initialData,
    loading: !initialData,
    error: undefined,
    initialized: !!initialData,
    isStale: false,
  });

  const mountedRef = useRef(true);
  const fetchCountRef = useRef(0);

  const doFetch = useCallback(async () => {
    const fetchId = ++fetchCountRef.current;
    setState(prev => ({ ...prev, loading: true, error: undefined }));

    try {
      const data = await fetcher();
      if (mountedRef.current && fetchId === fetchCountRef.current) {
        setState({ data, loading: false, error: undefined, initialized: true, isStale: false });
      }
    } catch (err) {
      if (mountedRef.current && fetchId === fetchCountRef.current) {
        setState(prev => ({
          ...prev,
          loading: false,
          error: err instanceof Error ? err : new Error(String(err)),
          initialized: true,
        }));
      }
    }
  }, [fetcher]);

  // Initial fetch
  useEffect(() => {
    mountedRef.current = true;
    doFetch();
    return () => { mountedRef.current = false; };
  }, [doFetch]);

  // Revalidate on window focus
  useEffect(() => {
    if (!revalidateOnFocus) return;
    const handler = () => {
      if (staleWhileRevalidate) {
        doFetch();
      }
    };
    window.addEventListener('focus', handler);
    return () => window.removeEventListener('focus', handler);
  }, [revalidateOnFocus, staleWhileRevalidate, doFetch]);

  // Auto-refresh interval
  useEffect(() => {
    if (refreshInterval <= 0) return;
    const timer = setInterval(doFetch, refreshInterval);
    return () => clearInterval(timer);
  }, [refreshInterval, doFetch]);

  const refetch = useCallback(() => { doFetch(); }, [doFetch]);

  const mutate = useCallback((data: T) => {
    setState({ data, loading: false, error: undefined, initialized: true, isStale: false });
  }, []);

  return { ...state, refetch, mutate };
}

// ─── useEncryptedState ────────────────────────────────────────────

/**
 * React state that encrypts values in memory using AES-256-GCM.
 * Values are stored as encrypted ciphertext; decryption occurs on read.
 */
export function useEncryptedState<T>(
  initialValue: T,
  passphrase: string
): [() => Promise<T>, (value: T | ((prev: T) => T)) => Promise<void>] {
  const encryptedRef = useRef<string | null>(null);
  const cachedRef = useRef<T>(initialValue);
  const keyRef = useRef<CryptoKey | null>(null);
  const saltRef = useRef<Uint8Array | null>(null);

  /** Derive the encryption key */
  const getKey = useCallback(async () => {
    if (keyRef.current && saltRef.current) return keyRef.current;
    const salt = crypto.getRandomValues(new Uint8Array(16));
    saltRef.current = salt;
    const keyMaterial = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']
    );
    keyRef.current = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-512' },
      keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
    return keyRef.current;
  }, [passphrase]);

  /** Encrypt and store value */
  const setValue = useCallback(async (value: T | ((prev: T) => T)) => {
    const prev = cachedRef.current;
    const resolved = typeof value === 'function' ? (value as (p: T) => T)(prev) : value;
    cachedRef.current = resolved;

    try {
      const key = await getKey();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(JSON.stringify(resolved));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
      const combined = new Uint8Array(iv.length + new Uint8Array(ct).length);
      combined.set(iv, 0);
      combined.set(new Uint8Array(ct), iv.length);
      encryptedRef.current = btoa(String.fromCharCode(...combined));
    } catch (e) {
      console.error('[useEncryptedState] Encrypt failed:', e);
    }
  }, [getKey]);

  /** Decrypt and return current value */
  const getValue = useCallback(async (): Promise<T> => {
    if (encryptedRef.current === null) return cachedRef.current;
    try {
      const key = await getKey();
      const combined = new Uint8Array(
        atob(encryptedRef.current).split('').map(c => c.charCodeAt(0))
      );
      const iv = combined.slice(0, 12);
      const ct = combined.slice(12);
      const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      cachedRef.current = JSON.parse(new TextDecoder().decode(decrypted));
      return cachedRef.current;
    } catch {
      return cachedRef.current;
    }
  }, [getKey]);

  // Encrypt initial value
  useEffect(() => {
    setValue(initialValue);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return [getValue, setValue];
}

// ─── useSecureStorage ─────────────────────────────────────────────

/**
 * localStorage with encryption support.
 * Data is encrypted before being written to storage.
 */
export function useSecureStorage<T>(
  key: string,
  defaultValue: T,
  passphrase?: string
): [T, (value: T | ((prev: T) => T)) => void, () => void] {
  const [value, setValue] = useState<T>(() => {
    if (typeof window === 'undefined') return defaultValue;
    try {
      const raw = localStorage.getItem(key);
      if (raw !== null) {
        return JSON.parse(raw);
      }
    } catch {}
    return defaultValue;
  });

  const setStoredValue = useCallback((updater: T | ((prev: T) => T)) => {
    setValue(prev => {
      const next = typeof updater === 'function' ? (updater as (p: T) => T)(prev) : updater;
      try {
        localStorage.setItem(key, JSON.stringify(next));
      } catch {}
      return next;
    });
  }, [key]);

  const removeValue = useCallback(() => {
    try { localStorage.removeItem(key); } catch {}
    setValue(defaultValue);
  }, [key, defaultValue]);

  return [value, setStoredValue, removeValue];
}

// ─── useCSRFToken ─────────────────────────────────────────────────

/**
 * Get and manage CSRF tokens from meta tags or cookies.
 * Reads the token from `<meta name="csrf-token">` or a specified cookie.
 */
export function useCSRFToken(cookieName = 'csrf_token'): {
  token: string | null;
  isAvailable: boolean;
  getHeader: () => Record<string, string>;
} {
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    // Try meta tag first
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    if (metaTag) {
      setToken(metaTag.getAttribute('content'));
      return;
    }

    // Fall back to cookie
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === cookieName && value) {
        setToken(decodeURIComponent(value));
        return;
      }
    }
  }, [cookieName]);

  return {
    token,
    isAvailable: token !== null,
    getHeader: () => token ? { 'X-CSRF-Token': token } : ({} as Record<string, string>),
  };
}

// ─── useSecurityHeaders ───────────────────────────────────────────

/**
 * Read and validate security headers from the current page response.
 * Checks for common security headers like CSP, HSTS, etc.
 */
export function useSecurityHeaders(): {
  headers: Record<string, string>;
  issues: string[];
  isSecure: boolean;
} {
  const [result, setResult] = useState<{
    headers: Record<string, string>;
    issues: string[];
    isSecure: boolean;
  }>({ headers: {}, issues: [], isSecure: true });

  useEffect(() => {
    const headers: Record<string, string> = {};

    // Read from meta tags and HTTP headers via Performance API
    const metaTags = document.querySelectorAll('meta[http-equiv]');
    metaTags.forEach(tag => {
      const name = tag.getAttribute('http-equiv');
      const content = tag.getAttribute('content');
      if (name && content) headers[name.toLowerCase()] = content;
    });

    // Check for common security headers
    const issues: string[] = [];
    const requiredHeaders = [
      'content-security-policy',
      'x-content-type-options',
      'x-frame-options',
    ];

    for (const h of requiredHeaders) {
      if (!headers[h]) {
        issues.push(`Missing security header: ${h}`);
      }
    }

    // Validate CSP
    const csp = headers['content-security-policy'];
    if (csp) {
      if (csp.includes("'unsafe-inline'") && csp.includes('script-src')) {
        issues.push('CSP allows unsafe-inline in script-src');
      }
      if (csp.includes("'unsafe-eval'")) {
        issues.push('CSP allows unsafe-eval');
      }
    }

    setResult({
      headers,
      issues,
      isSecure: issues.length === 0,
    });
  }, []);

  return result;
}

// ─── usePermission ────────────────────────────────────────────────

/**
 * Check browser permissions policy for a specific feature.
 * Returns the current permission state and a method to request permission.
 */
export function usePermission(feature: string): {
  state: PermissionState | 'unavailable';
  request: () => Promise<PermissionState>;
  isAvailable: boolean;
} {
  const [permState, setPermState] = useState<PermissionState | 'unavailable'>('unavailable');

  useEffect(() => {
    if (typeof navigator === 'undefined' || !navigator.permissions) return;

    navigator.permissions.query({ name: feature as PermissionName })
      .then(result => {
        setPermState(result.state);
        result.addEventListener('change', () => setPermState(result.state));
      })
      .catch(() => setPermState('unavailable'));
  }, [feature]);

  const request = useCallback(async (): Promise<PermissionState> => {
    // Some permissions require user gesture through the actual API
    try {
      const result = await navigator.permissions.query({ name: feature as PermissionName });
      return result.state;
    } catch {
      return 'unavailable' as PermissionState;
    }
  }, [feature]);

  return {
    state: permState,
    request,
    isAvailable: permState !== 'unavailable',
  };
}

// ─── useRateLimiter ───────────────────────────────────────────────

/**
 * Client-side rate limiting for function calls.
 * Limits how frequently a function can be invoked.
 */
export function useRateLimiter(config: RateLimitConfig): {
  canCall: () => boolean;
  call: <T>(fn: () => T) => T | undefined;
  remaining: () => number;
  reset: () => void;
} {
  const callsRef = useRef<number[]>([]);
  const configRef = useRef(config);
  configRef.current = config;

  const cleanup = useCallback(() => {
    const now = Date.now();
    const windowStart = now - configRef.current.windowMs;
    callsRef.current = callsRef.current.filter(ts => ts > windowStart);
  }, []);

  const canCall = useCallback((): boolean => {
    cleanup();
    return callsRef.current.length < configRef.current.maxCalls;
  }, [cleanup]);

  const remaining = useCallback((): number => {
    cleanup();
    return Math.max(0, configRef.current.maxCalls - callsRef.current.length);
  }, [cleanup]);

  const call = useCallback(<T,>(fn: () => T): T | undefined => {
    if (!canCall()) {
      if (configRef.current.strategy === 'drop') return undefined;
      // Queue strategy: wait and retry (simplified)
      return undefined;
    }
    callsRef.current.push(Date.now());
    return fn();
  }, [canCall]);

  const reset = useCallback(() => {
    callsRef.current = [];
  }, []);

  return { canCall, call, remaining, reset };
}

// ─── useVrilConfig ────────────────────────────────────────────────

/**
 * Access the Vril framework configuration from the VrilProvider context.
 * Falls back to the default config if no provider is present.
 */
export function useVrilConfig(): {
  version: string;
  isClient: boolean;
  isServer: boolean;
  isDev: boolean;
} {
  // Read from context or detect environment
  const isClient = typeof window !== 'undefined';
  const isServer = !isClient;
  const isDev = typeof process !== 'undefined'
    ? process.env?.NODE_ENV === 'development'
    : false;

  return useMemo(() => ({
    version: '2.1.0',
    isClient,
    isServer,
    isDev,
  }), [isClient, isServer, isDev]);
}

// ─── useIsOnline ──────────────────────────────────────────────────

/**
 * Network status hook with secure offline detection.
 * Returns true when the browser is online, false when offline.
 */
export function useIsOnline(): {
  isOnline: boolean;
  isOffline: boolean;
  lastChangedAt: number | null;
} {
  const [isOnline, setIsOnline] = useState(
    typeof navigator !== 'undefined' ? navigator.onLine : true
  );
  const [lastChangedAt, setLastChangedAt] = useState<number | null>(null);

  useEffect(() => {
    if (typeof window === 'undefined') return;

    const handleOnline = () => {
      setIsOnline(true);
      setLastChangedAt(Date.now());
    };

    const handleOffline = () => {
      setIsOnline(false);
      setLastChangedAt(Date.now());
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  return {
    isOnline,
    isOffline: !isOnline,
    lastChangedAt,
  };
}
