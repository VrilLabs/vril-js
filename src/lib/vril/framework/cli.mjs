#!/usr/bin/env node
import { build as esbuild } from 'esbuild';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { cp, mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { extname, isAbsolute, join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const root = process.cwd();
const outDir = resolve(root, '.vril/output');
const assetsDir = join(outDir, 'assets');
const serverBundle = resolve(root, '.vril/server.mjs');
const apiDir = resolve(root, '.vril/api');
const apiRoutesManifest = resolve(root, '.vril/api-routes.json');
const runtimeConfigBundle = resolve(root, '.vril/runtime-config.mjs');
const vercelOutputDir = resolve(root, '.vercel/output');
const vercelStaticDir = join(vercelOutputDir, 'static');
const vercelFunctionDir = join(vercelOutputDir, 'functions/api.func');
const defaultCSP = "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content";
const developmentCSP = "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self' http://localhost:* http://127.0.0.1:* ws://localhost:* ws://127.0.0.1:*; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content";

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
  'X-Vril-Version': '2.2.0',
  'Content-Security-Policy': defaultCSP,
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
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf',
};

async function bundle() {
  await rm(resolve(root, '.vril'), { recursive: true, force: true });
  await rm(vercelOutputDir, { recursive: true, force: true });
  await mkdir(assetsDir, { recursive: true });
  await mkdir(apiDir, { recursive: true });
  const runtimeConfig = await loadRuntimeConfig();

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
    // Server-side dependencies stay external so Node can load native CJS/ESM entry points.
    packages: 'external',
    jsx: 'automatic',
    plugins: [aliasPlugin, ignoreCssPlugin],
    define: { 'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV ?? 'production') },
  });

  const apiRoutes = await buildApiRoutes();

  const tailwind = spawnSync(
    process.platform === 'win32' ? 'npx.cmd' : 'npx',
    ['@tailwindcss/cli', '-i', resolve(root, 'src/app/globals.css'), '-o', join(assetsDir, 'globals.css'), '--minify'],
    { cwd: root, stdio: 'inherit' },
  );
  if (tailwind.status !== 0) {
    throw new Error('Vril CSS build failed');
  }

  // Copy contents of public directory into build output
  const publicDir = resolve(root, 'public');
  if (await stat(publicDir).then(s => s.isDirectory()).catch(() => false)) {
    for (const entry of await readdir(publicDir)) {
      await cp(join(publicDir, entry), join(outDir, entry), { recursive: true });
    }
  }

  const { renderRoute } = await import(`${pathToFileURL(serverBundle).href}?t=${Date.now()}`);
  await writeStaticRoute('/', renderRoute('/'));
  await writeStaticRoute('/docs', renderRoute('/docs'));
  await writeVercelOutput(apiRoutes, runtimeConfig);
}

async function loadRuntimeConfig() {
  const fallback = {
    headers: securityHeaders,
    poweredByHeader: false,
    server: { port: 3000, host: '0.0.0.0' },
  };
  const configPath = resolve(root, 'vril.config.ts');
  if (!(await isFile(configPath))) return fallback;
  await mkdir(resolve(root, '.vril'), { recursive: true });
  await esbuild({
    entryPoints: [configPath],
    outfile: runtimeConfigBundle,
    bundle: true,
    platform: 'node',
    format: 'esm',
    packages: 'external',
    plugins: [aliasPlugin, ignoreCssPlugin],
  });
  const module = await import(`${pathToFileURL(runtimeConfigBundle).href}?t=${Date.now()}`);
  const config = module.default;
  const resolved = typeof config?.toVrilRuntimeConfig === 'function'
    ? config.toVrilRuntimeConfig()
    : {};
  return {
    ...fallback,
    ...resolved,
    headers: { ...fallback.headers, ...(resolved.headers ?? {}) },
    server: { ...fallback.server, ...(resolved.server ?? {}) },
  };
}

async function buildApiRoutes() {
  const sources = await discoverApiRouteFiles(resolve(root, 'src/app/api'));
  const routes = sources.map((source, index) => ({
    source,
    routePath: apiRoutePathFromFile(source),
    bundlePath: join(apiDir, `route-${index}.mjs`),
    bundleName: `route-${index}.mjs`,
  }));

  for (const route of routes) {
    await esbuild({
      entryPoints: [route.source],
      outfile: route.bundlePath,
      bundle: true,
      platform: 'node',
      format: 'esm',
      packages: 'external',
      plugins: [aliasPlugin, ignoreCssPlugin],
      define: { 'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV ?? 'production') },
    });
  }

  await writeFile(apiRoutesManifest, JSON.stringify(routes.map(({ routePath, bundlePath, bundleName }) => ({ routePath, bundlePath, bundleName })), null, 2));
  return routes;
}

async function discoverApiRouteFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
  const files = [];
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...await discoverApiRouteFiles(fullPath));
    } else if (entry.isFile() && entry.name === 'route.ts') {
      files.push(fullPath);
    }
  }
  return files.sort();
}

function apiRoutePathFromFile(filePath) {
  const apiRoot = resolve(root, 'src/app/api');
  const segment = relative(apiRoot, filePath).replaceAll('\\', '/').replace(/(^|\/)route\.ts$/, '').replace(/\/$/, '');
  return normalizeRoutePath(`/api/${segment}`);
}

function normalizeRoutePath(pathname) {
  const normalized = pathname.replace(/[/]+$/, '');
  return normalized || '/';
}

async function writeStaticRoute(route, html) {
  const dir = route === '/' ? outDir : join(outDir, route.replace(/^\/+/, ''));
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'index.html'), html);
}

async function writeVercelOutput(apiRoutes, runtimeConfig) {
  await mkdir(vercelStaticDir, { recursive: true });
  await cp(outDir, vercelStaticDir, { recursive: true });
  await mkdir(join(vercelFunctionDir, 'routes'), { recursive: true });
  for (const route of apiRoutes) {
    await cp(route.bundlePath, join(vercelFunctionDir, 'routes', route.bundleName));
  }
  await writeFile(join(vercelFunctionDir, 'package.json'), JSON.stringify({ type: 'module' }, null, 2));
  await writeFile(join(vercelFunctionDir, '.vc-config.json'), JSON.stringify({
    runtime: 'nodejs20.x',
    handler: 'index.mjs',
    launcherType: 'Nodejs',
  }, null, 2));
  await writeFile(join(vercelFunctionDir, 'index.mjs'), generateVercelFunction(apiRoutes, runtimeConfig));
  await writeFile(join(vercelOutputDir, 'config.json'), JSON.stringify({
    version: 3,
    routes: [
      { src: '/api(?:/.*)?', dest: '/api' },
      { handle: 'filesystem' },
    ],
  }, null, 2));
}

function generateVercelFunction(apiRoutes, runtimeConfig) {
  const manifest = apiRoutes.map(route => ({
    routePath: route.routePath,
    bundleName: route.bundleName,
  }));
  const headers = buildRuntimeHeaders(runtimeConfig);
  return `const routeDefinitions = ${JSON.stringify(manifest, null, 2)};
const securityHeaders = ${JSON.stringify(headers, null, 2)};
const routes = await Promise.all(routeDefinitions.map(async route => ({
  ...route,
  module: await import(\`./routes/\${route.bundleName}\`),
})));

export default async function handler(req, res) {
  for (const [key, value] of Object.entries(securityHeaders)) res.setHeader(key, value);
  const url = new URL(req.url ?? '/', \`https://\${req.headers.host ?? 'localhost'}\`);
  const route = routes.find(candidate => candidate.routePath === normalizeRoutePath(url.pathname));
  const method = (req.method ?? 'GET').toUpperCase();
  const fn = route?.module?.[method];
  if (typeof fn !== 'function') {
    res.statusCode = route ? 405 : 404;
    res.end(route ? 'Method Not Allowed' : 'Not Found');
    return;
  }
  const request = createRequest(req, url);
  const response = await fn(request, { request, params: {} });
  res.statusCode = response.status;
  response.headers.forEach((value, key) => res.setHeader(key, value));
  res.end(Buffer.from(await response.arrayBuffer()));
}

function normalizeRoutePath(pathname) {
  const normalized = pathname.replace(/[/]+$/, '');
  return normalized || '/';
}

function createRequest(req, url) {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) headers.set(key, value.join(', '));
    else if (typeof value === 'string') headers.set(key, value);
  }
  const init = { method: req.method, headers };
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    init.body = req;
    init.duplex = 'half';
  }
  return new Request(url, init);
}
`;
}

async function serve() {
  const runtimeConfig = await loadRuntimeConfig();
  const apiRoutes = await loadApiRoutes();
  const port = Number(process.env.PORT ?? runtimeConfig.server?.port ?? 3000);
  const host = process.env.HOST ?? runtimeConfig.server?.host ?? '0.0.0.0';
  const headers = buildRuntimeHeaders(runtimeConfig);

  const server = createServer(async (req, res) => {
    try {
      for (const [key, value] of Object.entries(headers)) res.setHeader(key, value);
      if (req.headers['x-middleware-subrequest'] || req.headers['x-vril-internal'] || req.headers['x-vril-subrequest']) {
        res.writeHead(403, { 'content-type': 'text/plain; charset=utf-8' }).end('Forbidden');
        return;
      }

      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
      if (url.pathname.startsWith('/api')) {
        const route = apiRoutes.find(candidate => candidate.routePath === normalizeRoutePath(url.pathname));
        const handler = route?.module?.[(req.method ?? 'GET').toUpperCase()];
        if (typeof handler !== 'function') {
          res.writeHead(route ? 405 : 404, { 'content-type': 'text/plain; charset=utf-8' }).end(route ? 'Method Not Allowed' : 'Not Found');
          return;
        }
        const request = createWebRequest(req, url);
        const response = await handler(request, { request, params: {} });
        res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
        res.end(Buffer.from(await response.arrayBuffer()));
        return;
      }

      const filePath = resolveStaticPath(url.pathname);
      if (!filePath) {
        res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' }).end('Bad Request');
        return;
      }
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

async function loadApiRoutes() {
  const routes = JSON.parse(await readFile(apiRoutesManifest, 'utf8').catch(() => '[]'));
  return Promise.all(routes.map(async route => ({
    ...route,
    module: await import(`${pathToFileURL(route.bundlePath).href}?t=${Date.now()}`),
  })));
}

function buildRuntimeHeaders(runtimeConfig) {
  const headers = { ...securityHeaders, ...(runtimeConfig.headers ?? {}) };
  if (process.env.NODE_ENV === 'development') headers['Content-Security-Policy'] = developmentCSP;
  headers['X-Vril-Version'] = '2.2.0';
  if (runtimeConfig.poweredByHeader) headers['X-Powered-By'] = 'Vril.js';
  return headers;
}

function createWebRequest(req, url) {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) headers.set(key, value.join(', '));
    else if (typeof value === 'string') headers.set(key, value);
  }
  const init = { method: req.method, headers };
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    init.body = req;
    init.duplex = 'half';
  }
  return new Request(url, init);
}

function resolveStaticPath(pathname) {
  let normalized;
  try {
    normalized = decodeURIComponent(pathname).replace(/^\/+/, '');
  } catch {
    return null;
  }
  if (!normalized || normalized === 'index.html') normalized = 'index.html';
  else if (normalized === 'docs') normalized = 'docs/index.html';

  const filePath = resolve(outDir, normalized);
  const pathWithinOutput = relative(outDir, filePath);
  if (pathWithinOutput === '' || pathWithinOutput.startsWith('..') || isAbsolute(pathWithinOutput)) {
    return null;
  }
  return filePath;
}

// ─── Doctor Command ─────────────────────────────────────────────────────────

async function doctor() {
  const packageJsonPath = resolve(root, 'package.json');
  const pkg = JSON.parse(await readFile(packageJsonPath, 'utf8'));
  const configPath = resolve(root, 'vril.config.ts');
  const hasConfig = await isFile(configPath);

  let vrilConfig = null;
  if (hasConfig) {
    await mkdir(resolve(root, '.vril'), { recursive: true });
    await esbuild({
      entryPoints: [configPath],
      outfile: runtimeConfigBundle,
      bundle: true,
      platform: 'node',
      format: 'esm',
      packages: 'external',
      plugins: [aliasPlugin, ignoreCssPlugin],
    });
    const module = await import(`${pathToFileURL(runtimeConfigBundle).href}?t=${Date.now()}`);
    const configObj = module.default;
    // Access the full resolved config object
    vrilConfig = configObj?.config ?? null;
  }

  console.log('');
  console.log('\u2592\u2592 Vril.js Doctor v2.2.0');
  console.log('\u2500'.repeat(50));
  console.log('');

  // ─── 20-Point Security Audit ────────────────────────────────────────────
  const checks = [];

  // 1. HTTPS / HSTS configuration
  checks.push({
    name: 'HSTS configured',
    pass: !!(vrilConfig?.security?.headers?.strictTransportSecurity || securityHeaders['Strict-Transport-Security']),
  });

  // 2. X-Content-Type-Options
  checks.push({
    name: 'X-Content-Type-Options: nosniff',
    pass: (vrilConfig?.security?.headers?.xContentTypeOptions ?? securityHeaders['X-Content-Type-Options']) === 'nosniff',
  });

  // 3. X-Frame-Options
  checks.push({
    name: 'X-Frame-Options set',
    pass: !!(vrilConfig?.security?.headers?.xFrameOptions || securityHeaders['X-Frame-Options']),
  });

  // 4. Referrer-Policy
  checks.push({
    name: 'Referrer-Policy configured',
    pass: !!(vrilConfig?.security?.headers?.referrerPolicy || securityHeaders['Referrer-Policy']),
  });

  // 5. Cross-Origin-Opener-Policy
  checks.push({
    name: 'Cross-Origin-Opener-Policy set',
    pass: !!(vrilConfig?.security?.headers?.crossOriginOpenerPolicy || securityHeaders['Cross-Origin-Opener-Policy']),
  });

  // 6. Cross-Origin-Embedder-Policy
  checks.push({
    name: 'Cross-Origin-Embedder-Policy set',
    pass: !!(vrilConfig?.security?.headers?.crossOriginEmbedderPolicy || securityHeaders['Cross-Origin-Embedder-Policy']),
  });

  // 7. Content-Security-Policy
  checks.push({
    name: 'Content-Security-Policy defined',
    pass: !!(vrilConfig?.security?.csp || securityHeaders['Content-Security-Policy']),
  });

  // 8. Permissions-Policy
  checks.push({
    name: 'Permissions-Policy configured',
    pass: !!(vrilConfig?.security?.permissionsPolicy || securityHeaders['Permissions-Policy']),
  });

  // 9. No unsafe-inline in CSP script-src
  const cspString = securityHeaders['Content-Security-Policy'] ?? '';
  const scriptSrc = vrilConfig?.security?.csp?.scriptSrc ?? [];
  checks.push({
    name: 'No unsafe-inline in script-src',
    pass: !cspString.includes("'unsafe-inline'") && !scriptSrc.includes("'unsafe-inline'"),
  });

  // 10. No unsafe-eval in CSP
  checks.push({
    name: 'No unsafe-eval in CSP',
    pass: !cspString.includes("'unsafe-eval'") && !(vrilConfig?.security?.csp?.scriptSrc ?? []).includes("'unsafe-eval'"),
  });

  // 11. frame-ancestors restriction
  checks.push({
    name: 'CSP frame-ancestors restricted',
    pass: cspString.includes('frame-ancestors') || (vrilConfig?.security?.csp?.frameAncestors ?? []).length > 0,
  });

  // 12. Trusted Types enabled
  checks.push({
    name: 'Trusted Types enforcement',
    pass: vrilConfig?.security?.trustedTypes === true,
  });

  // 13. API membrane active
  checks.push({
    name: 'API membrane configured',
    pass: vrilConfig?.security?.apiMembrane === true,
  });

  // 14. CSRF protection enabled
  checks.push({
    name: 'CSRF protection enabled',
    pass: vrilConfig?.security?.csrf?.enabled === true,
  });

  // 15. SRI hashes configured
  checks.push({
    name: 'Subresource Integrity (SRI)',
    pass: vrilConfig?.build?.sriHashes === true,
  });

  // 16. No known vulnerable dependencies (check for lockfile existence)
  const lockfilePath = resolve(root, 'package-lock.json');
  const hasLockfile = await isFile(lockfilePath);
  checks.push({
    name: 'Lockfile present',
    pass: hasLockfile,
  });

  // 17. No .env file committed (check for .env in project root)
  const envFilePath = resolve(root, '.env');
  const hasEnvFile = await isFile(envFilePath);
  checks.push({
    name: 'No .env file exposed',
    pass: !hasEnvFile,
  });

  // 18. Strict TypeScript (check tsconfig.json for strict mode)
  const tsconfigPath = resolve(root, 'tsconfig.json');
  let tsStrict = false;
  try {
    const raw = await readFile(tsconfigPath, 'utf8');
    // tsconfig.json is JSONC – strip comments and trailing commas before parsing
    const stripped = raw
      .replace(/\/\/[^\n]*/g, '')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/,(\s*[}\]])/g, '$1');
    const tsconfig = JSON.parse(stripped);
    tsStrict = tsconfig?.compilerOptions?.strict === true;
  } catch { /* no tsconfig or invalid */ }
  checks.push({
    name: 'TypeScript strict mode',
    pass: tsStrict,
  });

  // 19. X-Powered-By header disabled
  checks.push({
    name: 'X-Powered-By disabled',
    pass: vrilConfig?.framework?.poweredByHeader === false || vrilConfig?.poweredByHeader === false,
  });

  // 20. upgrade-insecure-requests in CSP
  checks.push({
    name: 'upgrade-insecure-requests in CSP',
    pass: cspString.includes('upgrade-insecure-requests') || vrilConfig?.security?.csp?.upgradeInsecureRequests === true,
  });

  const passed = checks.filter(c => c.pass).length;
  const total = checks.length;

  for (const check of checks) {
    const icon = check.pass ? '\u2713' : '\u2717';
    const color = check.pass ? '\x1b[32m' : '\x1b[31m';
    console.log(`  ${color}${icon}\x1b[0m ${check.name}`);
  }

  console.log('');
  console.log(`\u25B8 Security audit: ${passed}/${total} checks passed`);

  // ─── SBOM Generation (CycloneDX) ───────────────────────────────────────
  const allDeps = {
    ...(pkg.dependencies ?? {}),
    ...(pkg.devDependencies ?? {}),
  };
  const components = Object.entries(allDeps).map(([name, version]) => {
    const ver = String(version).replace(/^[\^~>=<]*/g, '');
    const purl = `pkg:npm/${name.startsWith('@') ? '%40' + name.slice(1) : name}@${ver}`;
    return {
      'bom-ref': purl,
      type: 'library',
      name,
      version: ver,
      purl,
      scope: pkg.dependencies?.[name] ? 'required' : 'optional',
    };
  });

  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${generateUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'VrilLabs', name: 'vril-doctor', version: '2.2.0' }],
      component: {
        type: 'application',
        name: pkg.name ?? 'vril-app',
        version: pkg.version ?? '0.0.0',
      },
    },
    components,
    dependencies: components.map(c => ({ ref: c.purl, dependsOn: [] })),
  };

  const sbomPath = resolve(root, 'sbom.cyclonedx.json');
  await writeFile(sbomPath, JSON.stringify(sbom, null, 2));
  console.log(`\u25B8 SBOM generated: sbom.cyclonedx.json`);
  console.log('');

  if (passed < total) {
    console.log(`\x1b[33m\u26A0 ${total - passed} check(s) did not pass. Review recommendations above.\x1b[0m`);
    console.log('');
  }
}

function generateUUID() {
  const bytes = new Uint8Array(16);
  // Use crypto.getRandomValues if available, otherwise fall back
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
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
} else if (command === 'doctor') {
  await doctor();
} else {
  console.error(`Unknown Vril command: ${command}`);
  process.exit(1);
}
