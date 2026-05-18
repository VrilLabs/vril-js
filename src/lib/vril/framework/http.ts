export interface VrilRouteContext {
  params?: Record<string, string>;
  request: Request;
}

export type VrilRouteHandler = (request: Request, context: VrilRouteContext) => Response | Promise<Response>;

export function json(data: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  if (!headers.has('content-type')) headers.set('content-type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(data), { ...init, headers });
}

