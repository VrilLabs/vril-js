import { renderToString } from 'react-dom/server';
import LandingPage from './page';
import DocsPage from './docs/page';
import { metadata } from './layout';

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function metaTag(name: string, content: string | undefined): string {
  return content ? `<meta name="${escapeHtml(name)}" content="${escapeHtml(content)}">` : '';
}

function propertyTag(property: string, content: string | undefined): string {
  return content ? `<meta property="${escapeHtml(property)}" content="${escapeHtml(content)}">` : '';
}

function renderHead(): string {
  const title = metadata.title ?? 'Vril.js';
  const description = metadata.description ?? '';
  const keywords = metadata.keywords?.join(', ');
  return [
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>${escapeHtml(title)}</title>`,
    metaTag('description', description),
    metaTag('keywords', keywords),
    propertyTag('og:title', metadata.openGraph?.title ?? title),
    propertyTag('og:description', metadata.openGraph?.description ?? description),
    propertyTag('og:type', metadata.openGraph?.type),
    metaTag('twitter:card', metadata.twitter?.card),
    metaTag('twitter:title', metadata.twitter?.title ?? title),
    metaTag('twitter:description', metadata.twitter?.description ?? description),
    '<link rel="stylesheet" href="/assets/globals.css">',
    '<script type="module" src="/assets/app.js" defer></script>',
  ].filter(Boolean).join('');
}

function resolvePage(pathname: string) {
  if (pathname === '/docs' || pathname.startsWith('/docs/')) return <DocsPage />;
  return <LandingPage />;
}

export function renderRoute(pathname: string): string {
  const appHtml = renderToString(resolvePage(pathname));
  return `<!doctype html><html lang="en"><head>${renderHead()}</head><body class="antialiased bg-background text-foreground"><div id="vril-root">${appHtml}</div></body></html>`;
}

