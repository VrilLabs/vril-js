import { json } from "@/lib/vril/framework";
import { generateOpenAPISpec, type RouteManifestEntry } from "@/lib/vril/openapi";

/**
 * GET /api/openapi
 * Returns the auto-generated OpenAPI 3.1.0 specification for all Vril.js API routes.
 * The command palette docs explorer consumes this endpoint.
 */
export async function GET(request: Request) {
  // Discover routes — in production these come from the built manifest.
  // For the framework itself, we define the known API surface here.
  const routes: RouteManifestEntry[] = [
    {
      routePath: '/api',
      methods: ['GET'],
      description: 'Health check / root API endpoint',
      tags: ['General'],
      responses: {
        '200': { description: 'API is operational', content: { 'application/json': { schema: { type: 'object', properties: { message: { type: 'string', example: 'Hello, world!' } } } } } },
      },
    },
    {
      routePath: '/api/openapi',
      methods: ['GET'],
      description: 'Auto-generated OpenAPI specification',
      tags: ['Documentation'],
      responses: {
        '200': { description: 'OpenAPI 3.1.0 JSON document', content: { 'application/json': { schema: { type: 'object' } } } },
      },
    },
  ];

  // Construct the server URL from request headers
  let serverUrl: string | undefined;
  const proto = request.headers.get('x-forwarded-proto') || 'https';
  const host = request.headers.get('host');
  if (host) {
    serverUrl = `${proto}://${host}`;
  }

  const spec = generateOpenAPISpec(routes, {
    title: 'Vril.js API',
    description: 'OpenAPI specification for the Vril.js security-first framework API. This is a curated list of the framework showcase endpoints.',
    serverUrl,
  });

  return json(spec, {
    headers: {
      'Cache-Control': 'public, max-age=60, stale-while-revalidate=300',
    },
  });
}
