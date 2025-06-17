import { NextResponse, type NextRequest } from 'next/server';

/**
 * Middleware to apply Content Security Policy (CSP) headers
 * Runs in all environments including development mode
 */
export function middleware(request: NextRequest) {
  // Generate a unique nonce for each request to enhance CSP security
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');

  const isDev = process.env.NODE_ENV === 'development';

  // Different CSP directives for development vs production
  const styleDev = `'self' 'unsafe-inline'`;
  const styleProd = `'self' 'nonce-${nonce}'`;

  const scriptDev = `'self' 'unsafe-inline' 'unsafe-eval'`;
  const scriptProd = `'self' 'nonce-${nonce}' 'strict-dynamic'`;

  // Comprehensive CSP header with environment-specific settings
  const cspHeader = `
      default-src 'self';
      connect-src 'self' blob:;
      script-src ${isDev ? scriptDev : scriptProd};
      style-src ${isDev ? styleDev : styleProd};
      img-src    'self' data: blob:;
      font-src   'self';
      object-src 'none';
      base-uri   'self';
      form-action 'self';
      frame-ancestors 'none';
      upgrade-insecure-requests;
      worker-src 'self' blob:;
      manifest-src 'self';
      media-src 'self' blob:;
      frame-src 'self';
  `;
  // Replace newline characters and spaces
  const contentSecurityPolicyHeaderValue = cspHeader
    .replace(/\s{2,}/g, ' ')
    .trim();

  // Pass nonce to the application for use in script/style tags
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);

  requestHeaders.set(
    'Content-Security-Policy',
    contentSecurityPolicyHeaderValue,
  );

  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });
  response.headers.set(
    'Content-Security-Policy',
    contentSecurityPolicyHeaderValue,
  );

  return response;
}

/**
 * Apply middleware only to non-static paths
 * Exclude API routes, static files, images, favicon, and image generation routes
 * Also exclude prefetch requests
 */
export const config = {
  matcher: [
    {
      source:
        '/((?!api|_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml|opengraph-image|twitter-image|icon|apple-icon).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};
