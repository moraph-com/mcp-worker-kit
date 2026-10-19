// The MCP endpoint: Streamable HTTP, stateless. initialize, ping, tools/list, tools/call; answers are JSON (no SSE
// stream); notifications and client responses get 202; bodies up to 64 KB.
//
// Protocol version: the MCP-Protocol-Version header names it on every request after initialize; an unknown one gets
// 400, and none means 2025-03-26 (as the spec says). JSON-RPC batches (up to 20 messages) are accepted only for
// versions before 2025-06-18, which removed them.
//
// Who sees which tool is decided here and only here (toolsFor), from the tool's access rule and whether the
// connection was allowed to write. Every call is recorded in tool_calls: who, which tool, outcome, time taken.
// Never arguments or results: they can hold anything the person typed.
import { PROTOCOLS, SERVER, instructions } from './config.ts';
import type { Env } from './env.ts';
import type { User } from './identity.ts';
import { TOOLS } from './tools/index.ts';
import { ToolError, type Tool, type ToolContext } from './tools/types.ts';
import { check } from './tools/validate.ts';
import { CORS, json, q, readBody } from './util.ts';

const MAX_BODY = 64 * 1024;
const MAX_BATCH = 20;
const DEFAULT_PROTOCOL = '2025-03-26';
const BATCHES_REMOVED = '2025-06-18';

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

/** One tool_calls row: refusals and bad arguments too, since denied attempts are what a reviewer looks for. */
function audit(c: ToolContext, tool: string, error: string | null, started: number) {
  c.ctx.waitUntil(q(c.env, 'INSERT INTO tool_calls (grant_id, user_id, tool, ok, error, ms) VALUES (?, ?, ?, ?, ?, ?)',
    c.grant?.id ?? null, c.user?.id ?? null, tool.slice(0, 64), error ? 0 : 1, error ? error.slice(0, 200) : null, Date.now() - started).run()
    .catch((e) => console.error(JSON.stringify({ msg: 'audit write failed', tool, err: String(e) }))));
}
const toolError = (text: string) => ({ content: [{ type: 'text', text }], isError: true });
const isPlainObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

async function call(c: ToolContext, t: Tool, args: Record<string, unknown>) {
  const started = Date.now();
  // Bad arguments come back as a tool error, not a protocol error, so the assistant can see what to fix (MCP 2025-11-25).
  let error = check(args, t.inputSchema);
  let data: unknown;
  if (!error) {
    try {
      data = await t.run(c, args);
    } catch (e) {
      error = e instanceof ToolError ? e.message : 'Something went wrong running this tool. Try again shortly.';
      if (!(e instanceof ToolError)) console.error(JSON.stringify({ msg: 'tool error', tool: t.name, err: String((e as Error)?.stack || e) }));
    }
  }
  audit(c, t.name, error, started);
  if (error) return toolError(error);
  // structuredContent must be a JSON object; anything else goes out as text only.
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }], ...(isPlainObject(data) ? { structuredContent: data } : {}) };
}

type Message = { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: Record<string, any>; result?: unknown; error?: unknown };

async function handle(c: ToolContext, msg: Message) {
  if (isPlainObject(msg) && msg.jsonrpc === '2.0' && msg.method === undefined && 'id' in msg && ('result' in msg || 'error' in msg)) return null; // a response from the client: nothing to answer
  if (!isPlainObject(msg) || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return rpcError(isPlainObject(msg) ? msg.id : null, -32600, 'Invalid Request');
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
      if (!toolsFor(c.user, c.scopes).includes(t)) {
        const why = refusal(c, t);
        audit(c, t.name, why, Date.now());
        return { jsonrpc: '2.0', id, result: toolError(why) };
      }
      if (params.arguments !== undefined && !isPlainObject(params.arguments)) return rpcError(id, -32602, 'arguments must be an object.');
      return { jsonrpc: '2.0', id, result: await call(c, t, params.arguments ?? {}) };
    }
    case 'resources/list': return { jsonrpc: '2.0', id, result: { resources: [] } };
    case 'prompts/list': return { jsonrpc: '2.0', id, result: { prompts: [] } };
    default: return rpcError(id, -32601, `Method not found: ${method.slice(0, 60)}`);
  }
}

/** One POST to /public or /mcp, already authenticated (or anonymous). */
export async function rpc(request: Request, env: Env, ctx: ExecutionContext, url: URL, user: User | null, scopes: Set<string>, grant: ToolContext['grant']) {
  if (request.method !== 'POST') return new Response('This MCP endpoint answers POST requests only (no event stream).', { status: 405, headers: { allow: 'POST, OPTIONS', ...CORS } });
  const version = request.headers.get('mcp-protocol-version');
  if (version !== null && !PROTOCOLS.includes(version)) {
    return json(rpcError(null, -32600, `Unsupported MCP-Protocol-Version ${version.slice(0, 40)}; this server supports ${PROTOCOLS.join(', ')}.`), 400);
  }
  const text = await readBody(request, MAX_BODY);
  if (text === null) return json(rpcError(null, -32600, 'Request too large'), 413);
  let body: unknown;
  try { body = JSON.parse(text); } catch { return json(rpcError(null, -32700, 'Parse error'), 400); }
  const c: ToolContext = { env, ctx, request, url, user, scopes, grant };
  if (Array.isArray(body)) {
    if ((version ?? DEFAULT_PROTOCOL) >= BATCHES_REMOVED) return json(rpcError(null, -32600, `JSON-RPC batches aren't part of MCP ${version}. Send one message per request.`), 400);
    if (!body.length || body.length > MAX_BATCH) return json(rpcError(null, -32600, 'Invalid Request'), 400);
    const out = [];
    for (const m of body) { const r = await handle(c, m); if (r) out.push(r); }
    return out.length ? json(out) : new Response(null, { status: 202, headers: CORS });
  }
  const out = await handle(c, body as Message);
  return out ? json(out) : new Response(null, { status: 202, headers: CORS });
}
