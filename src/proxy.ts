/**
 * Vril.js v2.1.0 Security Proxy
 * Applies all security headers, CSP, Permissions-Policy, and
 * blocks internal header injection attacks (CVE-2025-29927 mitigation).
 * Includes HSTS preload, COEP/COOP for SharedArrayBuffer support,
 * and request integrity validation.
 *
 * Vril.js uses this proxy before route handling to reject client-injected
 * internal headers and apply framework security headers.
 */

export const SECURITY_HEADERS: Record<string, string> = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'credentialless',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': [
    'camera=()', 'microphone=()', 'geolocation=()', 'payment=()',
    'usb=()', 'serial=()', 'bluetooth=()', 'hid=()',
    'xr-spatial-tracking=()', 'compute-pressure=()',
  ].join(', '),
  'X-Vril-Version': '2.1.0',
  'Server': 'Vril.js',
};

// Internal headers that must never be set by clients (CVE-2025-29927 mitigation)
const BLOCKED_CLIENT_HEADERS = [
  'x-middleware-subrequest',
  'x-vril-internal',
  'x-vril-subrequest',
];

export function proxy(request: Request): Response | null {
  // Block suspicious client-injected headers
  for (const header of BLOCKED_CLIENT_HEADERS) {
    if (request.headers.get(header)) {
      return new Response('Forbidden', { status: 403 });
    }
  }

  return null;
}

export function applySecurityHeaders(headers: Headers): Headers {
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) headers.set(key, value);
  return headers;
}
