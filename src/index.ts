// mcp-worker-kit: a remote MCP server on Cloudflare Workers, so AI assistants (Claude, ChatGPT, Cursor and others)
// can work from your data as the person using them, and only as far as that person may go.
//
//   POST /public       anyone, no sign-in: the public tools only
//   POST /mcp          OAuth bearer token (oauth.ts): public tools plus what the person's account may see and do
//   GET  /             what this is and how to connect
//   /.well-known/oauth-protected-resource, /.well-known/oauth-authorization-server, /oauth/*   OAuth 2.1 (oauth.ts)
//   /dev/login, /dev/logout    development sign-in, localhost only (identity.ts)
//   cron               daily clean-up of expired OAuth rows and old tool-call records
import type { Env } from './env.ts';
import { providerFor } from './identity.ts';
import { rpc } from './mcp.ts';
import * as oauth from './oauth.ts';
import { TOOLS } from './tools/index.ts';
import { SERVER } from './config.ts';
import { CORS, esc, json, page } from './util.ts';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const p = url.pathname;
    const idp = providerFor(env);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { ...CORS, 'access-control-max-age': '86400' } });
    if (p === '/robots.txt') return new Response('User-agent: *\nAllow: /$\nDisallow: /\n', { headers: { 'content-type': 'text/plain; charset=utf-8' } });
    if (p === '/.well-known/oauth-protected-resource' || p === '/.well-known/oauth-protected-resource/mcp') return oauth.protectedResource(url);
    if (p === '/.well-known/oauth-authorization-server' || p === '/.well-known/oauth-authorization-server/mcp') return oauth.authServer(url);
    if (p === '/oauth/register') return oauth.register(request, env);
    if (p === '/oauth/authorize') return oauth.authorize(request, env, url);
    if (p === '/oauth/continue') return oauth.continueAuth(request, env, url, idp);
    if (p === '/oauth/token') return oauth.token(request, env);
    if (p === '/oauth/revoke') return oauth.revoke(request, env);
    const own = idp.routes && (await idp.routes(request, env, url));
    if (own) return own;
    if (p === '/public') return rpc(request, env, ctx, url, null, new Set(), null);
    if (p === '/mcp') {
      if (request.method !== 'POST') return rpc(request, env, ctx, url, null, new Set(), null);
      const auth = await oauth.authenticate(request, env, idp);
      if ('error' in auth) return oauth.unauthorized(url, auth.error === 'missing' ? 'Sign in to connect.' : 'Your connection has expired or was revoked. Connect again.');
      return rpc(request, env, ctx, url, auth.user, auth.scopes, auth.grant);
    }
    if (p === '/' && request.method === 'GET') return infoPage(url);
    return json({ error: 'Not found. MCP endpoints: /mcp (sign in) and /public.' }, 404);
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(oauth.daily(env));
  },
} satisfies ExportedHandler<Env>;

function infoPage(url: URL) {
  const o = url.origin;
  const who = (t: (typeof TOOLS)[number]) => (t.access === 'public' ? 'Anyone' : t.access === 'signed_in' ? 'Signed in' : 'Some accounts');
  const rows = TOOLS.map((t) => `<tr><td><code>${esc(t.name)}</code></td><td>${esc(who(t))}${t.write ? ', with actions allowed' : ''}</td><td>${esc(t.description)}</td></tr>`).join('');
  return page(SERVER.title, `<h1>${esc(SERVER.title)}</h1>
<p>A <a href="https://modelcontextprotocol.io">Model Context Protocol</a> server. Connect Claude, ChatGPT, Cursor or any assistant that supports remote MCP servers.</p>
<h2>Connect</h2>
<p><strong>Signed in:</strong> add a remote MCP server (custom connector) with the address <code>${esc(o)}/mcp</code>. Your assistant opens a sign-in page and you choose what it may do. Claude Code: <code>claude mcp add --transport http ${esc(SERVER.name)} ${esc(o)}/mcp</code></p>
<p><strong>Public tools only:</strong> <code>${esc(o)}/public</code></p>
<h2>Tools</h2><table><thead><tr><th>Tool</th><th>Who</th><th>What</th></tr></thead><tbody>${rows}</tbody></table>
<h2>Safety</h2><ul><li>Sign-in uses your existing account. Nothing here asks for a password.</li>
<li>Assistants read, and, only if you allow it, take everyday actions. Approvals, access changes and payments stay on the service’s own site.</li>
<li>Every tool call is recorded (never its contents). End a connection at any time from your assistant.</li></ul>`)
    .then((r) => { r.headers.set('cache-control', 'public, max-age=600'); return r; });
}
