// The MCP endpoint: Streamable HTTP, stateless. initialize, ping, tools/list, tools/call; answers are JSON (no SSE
// stream); notifications get 202; batches of up to 20 messages; bodies up to 64 KB.
//
// Who sees which tool is decided here and only here (toolsFor), from the tool's access rule and whether the
// connection was allowed to write. Every call is recorded in tool_calls: who, which tool, outcome, time taken.
// Never arguments or results: they can hold anything the person typed.
import { PROTOCOLS, SERVER, instructions } from './config.ts';
import type { Env } from './env.ts';
import type { User } from './identity.ts';
import { TOOLS } from './tools/index.ts';
import { ToolError, type Tool, type ToolContext } from './tools/types.ts';
import { CORS, json, q } from './util.ts';

const MAX_BODY = 64 * 1024;
const MAX_BATCH = 20;

/** The tools this caller may see. A signed-in connection without the write scope never sees write tools. */
export function toolsFor(user: User | null, scopes: Set<string>): Tool[] {
  return TOOLS.filter((t) => {
    if (t.write && user && !scopes.has('write')) return false;
    if (t.access === 'public') return true;
    if (!user) return false;
    if (t.access === 'signed_in') return true;
    return typeof t.access === 'function' && t.access(user);
  });
}

const listed = (t: Tool) => ({ name: t.name, title: t.title, description: t.description, inputSchema: t.inputSchema, annotations: t.annotations });
const rpcError = (id: unknown, code: number, message: string) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });

/** Why a tool the caller asked for isn't theirs to use, in words the assistant can pass on. */
function refusal(c: ToolContext, t: Tool): string {
  if (!c.user) return `${t.name} needs you to sign in: connect to ${c.url.origin}/mcp instead of /public.`;
  if (t.write && !c.scopes.has('write')) return `${t.name} changes things, and this connection is read-only. Reconnect and allow actions to use it.`;
  return `${t.name} isn’t available to your account.`;
}

async function call(c: ToolContext, t: Tool, args: Record<string, unknown>) {
  const started = Date.now();
  let data: unknown;
  let error: string | null = null;
  try {
    data = await t.run(c, args);
  } catch (e) {
    error = e instanceof ToolError ? e.message : 'Something went wrong running this tool. Try again shortly.';
    if (!(e instanceof ToolError)) console.error(JSON.stringify({ msg: 'tool error', tool: t.name, err: String((e as Error)?.stack || e) }));
  }
  const log = q(c.env, 'INSERT INTO tool_calls (grant_id, user_id, tool, ok, error, ms) VALUES (?, ?, ?, ?, ?, ?)',
    c.grant?.id ?? null, c.user?.id ?? null, t.name, error ? 0 : 1, error ? error.slice(0, 200) : null, Date.now() - started).run()
    .catch((e) => console.error(JSON.stringify({ msg: 'audit write failed', tool: t.name, err: String(e) })));
  c.ctx.waitUntil(log);
  if (error) return { content: [{ type: 'text', text: error }], isError: true };
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }], structuredContent: data };
}

type Message = { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: Record<string, any> };

async function handle(c: ToolContext, msg: Message) {
  if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return rpcError(msg?.id, -32600, 'Invalid Request');
  if (!('id' in msg)) return null; // notifications (initialized, cancelled): nothing to answer
  const { id, method } = msg;
  const params = msg.params && typeof msg.params === 'object' ? msg.params : {};
  switch (method) {
    case 'initialize': {
      const asked = params.protocolVersion;
      return { jsonrpc: '2.0', id, result: {
        protocolVersion: PROTOCOLS.includes(asked) ? asked : PROTOCOLS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER,
        instructions: instructions(c.user ? c.user.name : null),
      } };
    }
    case 'ping': return { jsonrpc: '2.0', id, result: {} };
    case 'tools/list': return { jsonrpc: '2.0', id, result: { tools: toolsFor(c.user, c.scopes).map(listed) } };
    case 'tools/call': {
      const t = TOOLS.find((x) => x.name === params.name);
      if (!t) return rpcError(id, -32602, `Unknown tool: ${String(params.name).slice(0, 60)}`);
      if (!toolsFor(c.user, c.scopes).includes(t)) return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: refusal(c, t) }], isError: true } };
      const args = params.arguments && typeof params.arguments === 'object' && !Array.isArray(params.arguments) ? params.arguments : {};
      return { jsonrpc: '2.0', id, result: await call(c, t, args) };
    }
    case 'resources/list': return { jsonrpc: '2.0', id, result: { resources: [] } };
    case 'prompts/list': return { jsonrpc: '2.0', id, result: { prompts: [] } };
    default: return rpcError(id, -32601, `Method not found: ${method.slice(0, 60)}`);
  }
}

/** One POST to /public or /mcp, already authenticated (or anonymous). */
export async function rpc(request: Request, env: Env, ctx: ExecutionContext, url: URL, user: User | null, scopes: Set<string>, grant: ToolContext['grant']) {
  if (request.method !== 'POST') return new Response('This MCP endpoint answers POST requests only (no event stream).', { status: 405, headers: { allow: 'POST, OPTIONS', ...CORS } });
  const text = await request.text();
  if (text.length > MAX_BODY) return json(rpcError(null, -32600, 'Request too large'), 413);
  let body: unknown;
  try { body = JSON.parse(text); } catch { return json(rpcError(null, -32700, 'Parse error'), 400); }
  const c: ToolContext = { env, ctx, request, url, user, scopes, grant };
  if (Array.isArray(body)) {
    if (!body.length || body.length > MAX_BATCH) return json(rpcError(null, -32600, 'Invalid Request'), 400);
    const out = [];
    for (const m of body) { const r = await handle(c, m); if (r) out.push(r); }
    return out.length ? json(out) : new Response(null, { status: 202, headers: CORS });
  }
  const out = await handle(c, body as Message);
  return out ? json(out) : new Response(null, { status: 202, headers: CORS });
}
