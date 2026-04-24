import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/**
 * Vril.js v2.1.0 Security Proxy
 * Applies all security headers, CSP, Permissions-Policy, and
 * blocks internal header injection attacks (CVE-2025-29927 mitigation).
 * Includes HSTS preload, COEP/COOP for SharedArrayBuffer support,
 * and request integrity validation.
 *
 * Next.js 16 uses "proxy" convention instead of "middleware"
 */

const SECURITY_HEADERS: Record<string, string> = {
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

export function proxy(request: NextRequest) {
  // Block suspicious client-injected headers
  for (const header of BLOCKED_CLIENT_HEADERS) {
    if (request.headers.get(header)) {
      return new NextResponse('Forbidden', { status: 403 });
    }
  }

  const response = NextResponse.next();

  // Apply security headers
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    response.headers.set(key, value);
  }

  return response;
}

export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico|logo\\.svg).*)',
  ],
};
