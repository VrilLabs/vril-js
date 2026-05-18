import { hydrateRoot } from 'react-dom/client';
import LandingPage from './page';
import DocsPage from './docs/page';

function resolvePage(pathname: string) {
  if (pathname === '/docs' || pathname.startsWith('/docs/')) return <DocsPage />;
  return <LandingPage />;
}

const root = document.getElementById('vril-root');
if (root) {
  hydrateRoot(root, resolvePage(window.location.pathname));
}

