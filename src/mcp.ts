/**
 * @file The MCP endpoint: JSON-RPC 2.0 over Streamable HTTP, stateless, answering in JSON.
 *
 * `index.ts` routes `/public` (anonymous) and `/mcp` (after `oauth.authenticate`) here. This file decides what each
 * caller may see and do, runs tools, and writes the audit trail.
 *
 * ## Transport (MCP 2025-11-25, basic/transports)
 *
 * - **POST only.** GET gets 405, because there is no server-to-client event stream. DELETE gets 405 as well, because
 *   there are no sessions to end. Both are answers the spec allows.
 * - **Answers are `application/json`**, never SSE. Notifications and client responses get `202 Accepted` with no
 *   body.
 * - **`Origin` is checked** against DNS rebinding ({@link originAllowed}). An `Origin` that isn't allowed gets 403.
 * - **`MCP-Protocol-Version`** must name a version in `PROTOCOLS`, otherwise the answer is 400. When the header is
 *   missing, 2025-03-26 is assumed, as the spec says.
 * - **Batches** (up to {@link MAX_BATCH} messages) are accepted only for versions before 2025-06-18, which removed
 *   them from the protocol.
 * - **Bodies** must be `application/json` and at most {@link MAX_BODY} bytes, and the size is counted while reading.
 *
 * ## Authorization of tools
 *
 * {@link toolsFor} is the **only** place that decides which tools a caller may use. `tools/list` shows exactly that
 * list, and `tools/call` re-checks against it, so a hidden tool can't be called by guessing its name.
 *
 * ## Audit trail
 *
 * Every `tools/call` writes one `tool_calls` row: who, which tool, whether it worked, how long it took, and for a
 * failure, the message. That includes refusals, because denied attempts are what a reviewer looks for. The row never
 * holds arguments or results, which can contain anything the person typed. That's why schema failures are recorded
 * with a fixed message instead of the validator's text, which can quote the caller's argument names.
 */
import { PROTOCOLS, SERVER, instructions } from './config.ts';
import type { Env } from './env.ts';
import type { User } from './identity.ts';
import type { Grant } from './oauth.ts';
import { TOOLS } from './tools/index.ts';
import { ToolError, type Tool, type ToolContext } from './tools/types.ts';
import { check } from './tools/validate.ts';
import { CORS, isJson, json, q, readBody } from './util.ts';

/** Largest request body accepted. Tool arguments are small, and anything bigger is a mistake or an attack. */
const MAX_BODY = 64 * 1024;
/** Most messages in one batch. Each one can be a tool call, so this caps the work one request can cause. */
const MAX_BATCH = 20;
/** Assumed when `MCP-Protocol-Version` is absent (MCP 2025-11-25 transports, "Protocol Version Header"). */
const DEFAULT_PROTOCOL = '2025-03-26';
/** The first version without JSON-RPC batching (MCP 2025-06-18 changelog). */
const BATCHES_REMOVED = '2025-06-18';
/** What the audit row says for a schema failure. The validator's own message can quote the caller's input. */
const AUDIT_BAD_ARGUMENTS = 'Arguments didn’t match the tool’s inputSchema.';

/** Standard JSON-RPC 2.0 error codes (JSON-RPC 2.0 §5.1). */
const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;

/**
 * The tools this caller may see and call.
 *
 * @param user - The signed-in person, or null on `/public`.
 * @param scopes - The connection's granted scopes. Empty on `/public`.
 * @returns Tools whose `access` rule admits the caller. On a signed-in connection without the `write` scope, write
 *   tools are left out. (A write tool with `access: 'public'` stays on `/public`, where nobody has scopes. Use that
 *   only for something like a contact form.)
 */
export function toolsFor(user: User | null, scopes: Set<string>): Tool[] {
  return TOOLS.filter((t) => {
    if (t.write && user && !scopes.has('write')) return false;
    if (t.access === 'public') return true;
    if (!user) return false;
    if (t.access === 'signed_in') return true;
    return typeof t.access === 'function' && t.access(user);
  });
}

/**
 * Whether the request's `Origin` may use the MCP endpoints.
 *
 * MCP 2025-11-25 transports, "Security Warning": servers "MUST validate the Origin header on all incoming
 * connections to prevent DNS rebinding attacks", and must answer 403 when it is present and invalid. The rule here:
 *
 * - **No `Origin` header:** allowed. Assistants call from their own servers or from native apps, not from a web page.
 *   DNS rebinding needs a browser, and a browser always sends `Origin` on these requests.
 * - **This server's own origin:** allowed.
 * - **Anything else:** allowed only if listed in `ALLOWED_ORIGINS`, or if that setting is `*`.
 *
 * `*` is a reasonable choice for a public deployment. These endpoints use no cookies, so a page that a visitor's
 * browser happens to load can only do what any anonymous caller could already do (`/public`), or what a bearer token
 * the page already holds allows (`/mcp`).
 */
export function originAllowed(request: Request, env: Env, url: URL): boolean {
  const origin = request.headers.get('origin');
  if (origin === null || origin === url.origin) return true;
  const allowed = String(env.ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return allowed.includes('*') || allowed.includes(origin);
}

/** The definition `tools/list` shows for a tool. `run` and `access` stay on the server. */
const listed = (t: Tool) => ({
  name: t.name,
  title: t.title,
  description: t.description,
  inputSchema: t.inputSchema,
  annotations: t.annotations,
});
type Id = string | number | null;
const rpcError = (id: Id, code: number, message: string) => ({ jsonrpc: '2.0', id, error: { code, message } });
const result = (id: Id, value: unknown) => ({ jsonrpc: '2.0', id, result: value });

/** Why a tool the caller asked for isn't theirs to use, in words the assistant can pass on. */
function refusal(c: ToolContext, t: Tool): string {
  if (!c.user) return `${t.name} needs you to sign in: connect to ${c.url.origin}/mcp instead of /public.`;
  if (t.write && !c.scopes.has('write'))
    return `${t.name} changes things, and this connection is read-only. Reconnect and allow actions to use it.`;
  return `${t.name} isn’t available to your account.`;
}

/**
 * Records one tool call in `tool_calls`, without slowing down the answer.
 *
 * The write is handed to `waitUntil`, so the response doesn't wait for D1. If the write fails, the failure is logged
 * rather than thrown: a logging failure must not change what the assistant receives.
 *
 * @param error - The message to record, or null for success. **Never pass arguments, results or text the caller
 *   chose.**
 */
function audit(c: ToolContext, tool: string, error: string | null, started: number): void {
  c.ctx.waitUntil(
    q(
      c.env,
      'INSERT INTO tool_calls (grant_id, user_id, tool, ok, error, ms) VALUES (?, ?, ?, ?, ?, ?)',
      c.grant?.id ?? null,
      c.user?.id ?? null,
      tool.slice(0, 64),
      error ? 0 : 1,
      error ? error.slice(0, 200) : null,
      Date.now() - started,
    )
      .run()
      .catch((e: unknown) => console.error(JSON.stringify({ msg: 'audit write failed', tool, err: String(e) }))),
  );
}
const toolError = (text: string) => ({ content: [{ type: 'text', text }], isError: true });
const isPlainObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/** Runs a tool the caller may use, and returns the `tools/call` result. */
async function call(c: ToolContext, t: Tool, args: Record<string, unknown>) {
  const started = Date.now();
  // Bad arguments come back as a tool result with isError, not as a protocol error, so the assistant sees what to fix
  // and can try again (MCP 2025-11-25 server/tools, "Error Handling").
  const invalid = check(args, t.inputSchema);
  if (invalid) {
    audit(c, t.name, AUDIT_BAD_ARGUMENTS, started);
    return toolError(invalid);
  }
  let data: unknown;
  try {
    data = await t.run(c, args);
  } catch (e) {
    // Only a ToolError's message reaches the assistant. Anything else could carry SQL, stack traces or internal
    // names, so the assistant gets a generic message and the details go to the Worker's logs.
    const message = e instanceof ToolError ? e.message : 'Something went wrong running this tool. Try again shortly.';
    if (!(e instanceof ToolError))
      console.error(JSON.stringify({ msg: 'tool error', tool: t.name, err: String((e as Error)?.stack || e) }));
    audit(c, t.name, message, started);
    return toolError(message);
  }
  audit(c, t.name, null, started);
  // structuredContent must be a JSON object (MCP 2025-06-18+). Any other value goes out as text only. The text copy is
  // kept for clients that predate structuredContent ("SHOULD also return the serialized JSON in a TextContent block").
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
    ...(isPlainObject(data) ? { structuredContent: data } : {}),
  };
}

/**
 * Answers one JSON-RPC message.
 *
 * @param inBatch - The message arrived inside a batch, where `initialize` isn't allowed (MCP 2025-03-26 lifecycle).
 * @returns The response object, or null when nothing should be sent back: for a notification, or for a response
 *   from the client to a server request.
 */
async function handle(c: ToolContext, msg: unknown, inBatch: boolean): Promise<object | null> {
  if (!isPlainObject(msg)) return rpcError(null, INVALID_REQUEST, 'Invalid Request');
  // A response from the client (to a request this server never sends): accept it and say nothing (202).
  if (msg.jsonrpc === '2.0' && msg.method === undefined && 'id' in msg && ('result' in msg || 'error' in msg))
    return null;
  // MCP narrows JSON-RPC ids: "MUST be a string or integer" and "MUST NOT be null" (MCP basic, "Requests"). An object
  // id echoed back would be malformed JSON-RPC, so it's refused with id null, as JSON-RPC 2.0 §5 says to do when the id
  // can't be read.
  const hasId = 'id' in msg;
  const idOk = typeof msg.id === 'string' || (typeof msg.id === 'number' && Number.isInteger(msg.id));
  if (msg.jsonrpc !== '2.0' || typeof msg.method !== 'string' || (hasId && !idOk))
    return rpcError(idOk ? (msg.id as Id) : null, INVALID_REQUEST, 'Invalid Request');
  if (!hasId) return null; // a notification (initialized, cancelled, …): nothing to answer
  const id = msg.id as string | number;
  const method = msg.method;
  if (msg.params !== undefined && !isPlainObject(msg.params))
    return rpcError(id, INVALID_PARAMS, 'params must be an object.');
  const params = msg.params ?? {};

  switch (method) {
    case 'initialize': {
      if (inBatch) return rpcError(id, INVALID_REQUEST, 'initialize can’t be part of a batch.');
      const asked = params.protocolVersion;
      return result(id, {
        protocolVersion: typeof asked === 'string' && PROTOCOLS.includes(asked) ? asked : PROTOCOLS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER,
        instructions: instructions(c.user ? c.user.name : null),
      });
    }
    case 'ping':
      return result(id, {});
    case 'tools/list':
      return result(id, { tools: toolsFor(c.user, c.scopes).map(listed) });
    case 'tools/call': {
      const t = TOOLS.find((x) => x.name === params.name);
      if (!t) return rpcError(id, INVALID_PARAMS, `Unknown tool: ${String(params.name).slice(0, 60)}`);
      // Same list as tools/list: knowing a hidden tool's name doesn't get you anywhere.
      if (!toolsFor(c.user, c.scopes).includes(t)) {
        const why = refusal(c, t);
        audit(c, t.name, why, Date.now());
        return result(id, toolError(why));
      }
      if (params.arguments !== undefined && !isPlainObject(params.arguments))
        return rpcError(id, INVALID_PARAMS, 'arguments must be an object.');
      return result(id, await call(c, t, params.arguments ?? {}));
    }
    // Not declared in capabilities, so clients shouldn't ask. Empty answers are friendlier than an error if they do.
    case 'resources/list':
      return result(id, { resources: [] });
    case 'prompts/list':
      return result(id, { prompts: [] });
    default:
      return rpcError(id, METHOD_NOT_FOUND, `Method not found: ${method.slice(0, 60)}`);
  }
}

const accepted = () => new Response(null, { status: 202, headers: CORS });

/**
 * Handles one HTTP request to `/public` or `/mcp`, after `index.ts` has checked the `Origin` and, for `/mcp`,
 * authenticated the caller.
 *
 * @param caller - The authenticated connection, or null on `/public`.
 */
export async function rpc(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  url: URL,
  caller: { user: User; scopes: Set<string>; grant: Grant } | null,
): Promise<Response> {
  if (request.method !== 'POST')
    return new Response('This MCP endpoint answers POST requests only (no event stream).', {
      status: 405,
      headers: { allow: 'POST, OPTIONS', ...CORS },
    });
  const version = request.headers.get('mcp-protocol-version');
  if (version !== null && !PROTOCOLS.includes(version)) {
    return json(
      rpcError(
        null,
        INVALID_REQUEST,
        `Unsupported MCP-Protocol-Version ${version.slice(0, 40)}; this server supports ${PROTOCOLS.join(', ')}.`,
      ),
      400,
    );
  }
  if (!isJson(request))
    return json(rpcError(null, INVALID_REQUEST, 'Send JSON-RPC as Content-Type: application/json.'), 415);
  const text = await readBody(request, MAX_BODY);
  if (text === null) return json(rpcError(null, INVALID_REQUEST, 'Request too large'), 413);
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return json(rpcError(null, PARSE_ERROR, 'Parse error'), 400);
  }
  const c: ToolContext = {
    env,
    ctx,
    request,
    url,
    user: caller?.user ?? null,
    scopes: caller?.scopes ?? new Set(),
    grant: caller?.grant ?? null,
  };
  if (Array.isArray(body)) {
    if ((version ?? DEFAULT_PROTOCOL) >= BATCHES_REMOVED)
      return json(
        rpcError(
          null,
          INVALID_REQUEST,
          `JSON-RPC batches aren't part of MCP ${version}. Send one message per request.`,
        ),
        400,
      );
    if (!body.length || body.length > MAX_BATCH) return json(rpcError(null, INVALID_REQUEST, 'Invalid Request'), 400);
    const out = [];
    // One at a time, in order: a batch is a convenience, not a way to run 20 tools in parallel against D1.
    for (const m of body) {
      const r = await handle(c, m, true);
      if (r) out.push(r);
    }
    return out.length ? json(out) : accepted();
  }
  const out = await handle(c, body, false);
  return out ? json(out) : accepted();
}
