#!/usr/bin/env node
import { build as esbuild } from 'esbuild';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { extname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = process.cwd();
const outDir = resolve(root, '.vril/output');
const assetsDir = join(outDir, 'assets');
const serverBundle = resolve(root, '.vril/server.mjs');
const apiBundle = resolve(root, '.vril/api.mjs');

const aliasPlugin = {
  name: 'vril-alias',
  setup(build) {
    build.onResolve({ filter: /^@\// }, async args => {
      const basePath = resolve(root, 'src', args.path.slice(2));
      return { path: await resolveModulePath(basePath) };
    });
  },
};

const ignoreCssPlugin = {
  name: 'vril-ignore-css-imports',
  setup(build) {
    build.onLoad({ filter: /\.css$/ }, () => ({ contents: '', loader: 'js' }));
  },
};

async function resolveModulePath(basePath) {
  const candidates = [
    basePath,
    `${basePath}.ts`,
    `${basePath}.tsx`,
    `${basePath}.js`,
    `${basePath}.jsx`,
    join(basePath, 'index.ts'),
    join(basePath, 'index.tsx'),
    join(basePath, 'index.js'),
    join(basePath, 'index.jsx'),
  ];
  for (const candidate of candidates) {
    if (await isFile(candidate)) return candidate;
  }
  return basePath;
}

async function isFile(path) {
  try {
    return (await stat(path)).isFile();
  } catch {
    return false;
  }
}

const securityHeaders = {
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

const mimeTypes = {
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
};

async function bundle() {
  await rm(resolve(root, '.vril'), { recursive: true, force: true });
  await mkdir(assetsDir, { recursive: true });

  await esbuild({
    entryPoints: [resolve(root, 'src/app/vril-client.tsx')],
    outfile: join(assetsDir, 'app.js'),
    bundle: true,
    minify: process.env.NODE_ENV === 'production',
    sourcemap: process.env.NODE_ENV !== 'production',
    platform: 'browser',
    format: 'esm',
    jsx: 'automatic',
    plugins: [aliasPlugin, ignoreCssPlugin],
    define: { 'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV ?? 'production') },
  });

  await esbuild({
    entryPoints: [resolve(root, 'src/app/vril-server.tsx')],
    outfile: serverBundle,
    bundle: true,
    platform: 'node',
    format: 'esm',
    // Keep React/Node packages external so Node can load their native CJS/ESM entry points.
    packages: 'external',
    jsx: 'automatic',
    plugins: [aliasPlugin, ignoreCssPlugin],
    define: { 'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV ?? 'production') },
  });

  await esbuild({
    entryPoints: [resolve(root, 'src/app/api/route.ts')],
    outfile: apiBundle,
    bundle: true,
    platform: 'node',
    format: 'esm',
    plugins: [aliasPlugin, ignoreCssPlugin],
    define: { 'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV ?? 'production') },
  });

  const tailwind = spawnSync(
    process.platform === 'win32' ? 'npx.cmd' : 'npx',
    ['@tailwindcss/cli', '-i', resolve(root, 'src/app/globals.css'), '-o', join(assetsDir, 'globals.css'), '--minify'],
    { cwd: root, stdio: 'inherit' },
  );
  if (tailwind.status !== 0) {
    throw new Error('Vril CSS build failed');
  }

  const { renderRoute } = await import(`${pathToFileURL(serverBundle).href}?t=${Date.now()}`);
  await writeStaticRoute('/', renderRoute('/'));
  await writeStaticRoute('/docs', renderRoute('/docs'));
}

async function writeStaticRoute(route, html) {
  const dir = route === '/' ? outDir : join(outDir, route.replace(/^\/+/, ''));
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'index.html'), html);
}

async function serve() {
  const { GET } = await import(`${pathToFileURL(apiBundle).href}?t=${Date.now()}`).catch(() => ({ GET: null }));
  const port = Number(process.env.PORT ?? 3000);
  const host = process.env.HOST ?? '0.0.0.0';

  const server = createServer(async (req, res) => {
    try {
      for (const [key, value] of Object.entries(securityHeaders)) res.setHeader(key, value);
      if (req.headers['x-middleware-subrequest'] || req.headers['x-vril-internal'] || req.headers['x-vril-subrequest']) {
        res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' }).end('Forbidden');
        return;
      }

      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
      if (url.pathname === '/api' && typeof GET === 'function') {
        const response = await GET(new Request(url));
        res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
        res.end(Buffer.from(await response.arrayBuffer()));
        return;
      }

      const filePath = resolveStaticPath(url.pathname);
      const fileStat = await stat(filePath).catch(() => null);
      if (!fileStat?.isFile()) {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' }).end('Not Found');
        return;
      }
      res.writeHead(200, { 'content-type': mimeTypes[extname(filePath)] ?? 'application/octet-stream' });
      createReadStream(filePath).pipe(res);
    } catch (error) {
      res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' }).end(error instanceof Error ? error.message : 'Internal Error');
    }
  });

  server.listen(port, host, () => {
    console.log(`Vril.js server listening on http://${host}:${port}`);
  });
}

function resolveStaticPath(pathname) {
  const normalized = decodeURIComponent(pathname).replace(/^\/+/, '');
  if (!normalized || normalized === 'index.html') return join(outDir, 'index.html');
  if (normalized === 'docs') return join(outDir, 'docs/index.html');
  return join(outDir, normalized);
}

const command = process.argv[2] ?? 'build';
if (command === 'build') {
  await bundle();
} else if (command === 'start') {
  await serve();
} else if (command === 'dev') {
  process.env.NODE_ENV = process.env.NODE_ENV ?? 'development';
  await bundle();
  await serve();
} else {
  console.error(`Unknown Vril command: ${command}`);
  process.exit(1);
}
