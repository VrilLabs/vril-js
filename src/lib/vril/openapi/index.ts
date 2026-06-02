/**
 * Vril.js — OpenAPI Specification Generator
 * Automatically discovers API routes and generates an OpenAPI 3.1.0 spec.
 * Used by the command palette docs explorer and served at /api/openapi.
 */

import { VRIL_VERSION } from '../version';

export interface OpenAPIInfo {
  title: string;
  version: string;
  description?: string;
}

export interface OpenAPIPathItem {
  summary?: string;
  description?: string;
  get?: OpenAPIOperation;
  post?: OpenAPIOperation;
  put?: OpenAPIOperation;
  patch?: OpenAPIOperation;
  delete?: OpenAPIOperation;
}

export interface OpenAPIOperation {
  operationId?: string;
  summary?: string;
  description?: string;
  tags?: string[];
  parameters?: OpenAPIParameter[];
  requestBody?: OpenAPIRequestBody;
  responses: Record<string, OpenAPIResponse>;
}

export interface OpenAPIParameter {
  name: string;
  in: 'query' | 'header' | 'path' | 'cookie';
  description?: string;
  required?: boolean;
  schema?: OpenAPISchema;
}

export interface OpenAPIRequestBody {
  description?: string;
  required?: boolean;
  content: Record<string, { schema: OpenAPISchema }>;
}

export interface OpenAPIResponse {
  description: string;
  content?: Record<string, { schema: OpenAPISchema }>;
}

export interface OpenAPISchema {
  type?: string;
  properties?: Record<string, OpenAPISchema>;
  items?: OpenAPISchema;
  required?: string[];
  description?: string;
  example?: unknown;
}

export interface OpenAPISpec {
  openapi: string;
  info: OpenAPIInfo;
  servers?: Array<{ url: string; description?: string }>;
  paths: Record<string, OpenAPIPathItem>;
  components?: {
    schemas?: Record<string, OpenAPISchema>;
    securitySchemes?: Record<string, unknown>;
  };
  tags?: Array<{ name: string; description?: string }>;
}

export interface RouteManifestEntry {
  routePath: string;
  methods?: string[];
  description?: string;
  tags?: string[];
  parameters?: OpenAPIParameter[];
  requestBody?: OpenAPIRequestBody;
  responses?: Record<string, OpenAPIResponse>;
}

/**
 * Generate an OpenAPI 3.1.0 specification from discovered route manifest entries.
 */
export function generateOpenAPISpec(
  routes: RouteManifestEntry[],
  options: {
    title?: string;
    version?: string;
    description?: string;
    serverUrl?: string;
  } = {}
): OpenAPISpec {
  const {
    title = 'Vril.js API',
    version = VRIL_VERSION,
    description = 'Auto-generated OpenAPI specification for Vril.js API routes.',
    serverUrl,
  } = options;

  const paths: Record<string, OpenAPIPathItem> = {};

  for (const route of routes) {
    const methods = route.methods ?? ['GET'];
    const pathItem: OpenAPIPathItem = {};

    for (const method of methods) {
      const methodUpper = method.toUpperCase();
      const operation: OpenAPIOperation = {
        operationId: `${method.toLowerCase()}_${route.routePath.replace(/[^a-zA-Z0-9]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '')}`,
        summary: route.description ?? `${method} ${route.routePath}`,
        tags: route.tags ?? [deriveTag(route.routePath)],
        parameters: route.parameters,
        requestBody: methodUpper !== 'GET' && methodUpper !== 'DELETE' ? route.requestBody : undefined,
        responses: route.responses ?? {
          '200': { description: 'Successful response', content: { 'application/json': { schema: { type: 'object' } } } },
          '400': { description: 'Bad request' },
          '401': { description: 'Unauthorized' },
          '404': { description: 'Not found' },
          '500': { description: 'Internal server error' },
        },
      };

      const key = method.toLowerCase() as keyof OpenAPIPathItem;
      (pathItem as Record<string, OpenAPIOperation>)[key] = operation;
    }

    paths[route.routePath] = pathItem;
  }

  const spec: OpenAPISpec = {
    openapi: '3.1.0',
    info: { title, version, description },
    paths,
    components: {
      securitySchemes: {
        csrfToken: {
          type: 'apiKey',
          in: 'header',
          name: 'x-vril-csrf',
          description: 'CSRF double-submit token',
        },
      },
    },
    tags: deriveTagList(routes),
  };

  if (serverUrl) {
    spec.servers = [{ url: serverUrl, description: 'API Server' }];
  }

  return spec;
}

function deriveTag(routePath: string): string {
  const segments = routePath.replace(/^\/api\/?/, '').split('/').filter(Boolean);
  if (segments.length === 0) return 'General';
  return segments[0].charAt(0).toUpperCase() + segments[0].slice(1);
}

function deriveTagList(routes: RouteManifestEntry[]): Array<{ name: string; description?: string }> {
  const tags = new Set<string>();
  for (const route of routes) {
    if (route.tags) {
      route.tags.forEach(t => tags.add(t));
    } else {
      tags.add(deriveTag(route.routePath));
    }
  }
  return Array.from(tags).sort().map(name => ({ name }));
}

/**
 * Discover routes from the built api-routes.json manifest.
 * Maps manifest entries to RouteManifestEntry objects with standard HTTP methods.
 */
export function discoverRoutesFromManifest(
  manifest: Array<{ routePath: string; bundleName?: string }>
): RouteManifestEntry[] {
  return manifest.map(entry => ({
    routePath: entry.routePath,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  }));
}
