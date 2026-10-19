/**
 * @file mcp-worker-kit: a remote MCP server on Cloudflare Workers. AI assistants (Claude, ChatGPT, Cursor and others)
 * work from your data as the person using them, and only as far as that person may go.
 *
 * This file is the Worker's entry point. It routes requests and applies the checks every route shares (CORS
 * preflight, the optional rate limiter, the MCP `Origin` check). The work itself happens elsewhere:
 *
 * | Route                              | Who may call                         | Handled in    |
 * | ---------------------------------- | ------------------------------------ | ------------- |
 * | `POST /public`                     | anyone                               | `mcp.ts`      |
 * | `POST /mcp`                        | OAuth bearer token                   | `mcp.ts`      |
 * | `/.well-known/oauth-*`, `/oauth/*` | anyone (it's how you sign in)        | `oauth.ts`    |
 * | `/dev/login`, `/dev/logout`        | localhost only                       | `identity.ts` |
 * | `GET /`                            | anyone: what this is, how to connect | `infoPage`    |
 * | cron (daily)                       | Cloudflare                           | `oauth.daily` |
 */
import type { Env } from './env.ts';
import { providerFor } from './identity.ts';
import { originAllowed, rpc } from './mcp.ts';
import * as oauth from './oauth.ts';
import { TOOLS } from './tools/index.ts';
import { SERVER } from './config.ts';
import { CORS, esc, json, network, page } from './util.ts';

/** Routes that take no credentials, so the optional rate limiter applies to them. */
const ANONYMOUS = new Set(['/public', '/oauth/register', '/oauth/authorize', '/oauth/token', '/oauth/revoke']);

/**
 * Asks the optional Workers Rate Limiting binding whether this network may make another anonymous request.
 *
 * The key is the network (an IPv4 address or an IPv6 /64), not the raw address, for the reason given at
 * `util.network`. Without the binding, this always says yes. The D1-backed limits on registration and authorization
 * (`oauth.ts`) apply either way.
 */
async function withinRateLimit(request: Request, env: Env): Promise<boolean> {
  if (!env.RATE_LIMITER) return true;
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  return (await env.RATE_LIMITER.limit({ key: network(ip) })).success;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const p = url.pathname;
    const idp = providerFor(env);
    // CORS preflight for every path, answered before anything else. Preflights carry no credentials and change
    // nothing, so answering them early is safe.
    if (request.method === 'OPTIONS')
      return new Response(null, { status: 204, headers: { ...CORS, 'access-control-max-age': '86400' } });
    if (ANONYMOUS.has(p) && !(await withinRateLimit(request, env)))
      return json({ error: 'rate_limited', error_description: 'Too many requests. Try again in a minute.' }, 429, {
        'retry-after': '60',
      });

    if (p === '/robots.txt')
      return new Response('User-agent: *\nAllow: /$\nDisallow: /\n', {
        headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
    // `/.well-known/oauth-protected-resource/mcp` is RFC 9728 §3.1's path-inserted location for the /mcp resource.
    // The issuer here has no path, so RFC 8414 only needs the plain authorization-server URL. Some clients derive a
    // /mcp form from the MCP URL anyway, so that answers too.
    if (p === '/.well-known/oauth-protected-resource' || p === '/.well-known/oauth-protected-resource/mcp')
      return oauth.protectedResource(url);
    if (p === '/.well-known/oauth-authorization-server' || p === '/.well-known/oauth-authorization-server/mcp')
      return oauth.authServer(url);
    if (p === '/oauth/register') return oauth.register(request, env);
    if (p === '/oauth/authorize') return oauth.authorize(request, env, url);
    if (p === '/oauth/continue') return oauth.continueAuth(request, env, url, idp);
    if (p === '/oauth/token') return oauth.token(request, env, idp);
    if (p === '/oauth/revoke') return oauth.revoke(request, env);
    const own = idp.routes && (await idp.routes(request, env, url));
    if (own) return own;

    if (p === '/public' || p === '/mcp') {
      // Checked before authentication, so a page on a disallowed origin learns nothing, not even whether a token is good.
      if (!originAllowed(request, env, url))
        return json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Origin not allowed.' } }, 403);
      // Non-POST methods get their 405 from rpc() without needing a token: there is nothing to protect in "no".
      if (p === '/public' || request.method !== 'POST') return rpc(request, env, ctx, url, null);
      const auth = await oauth.authenticate(request, env, idp, url);
      if ('error' in auth)
        return auth.error === 'missing'
          ? oauth.unauthorized(url, 'Sign in to connect.')
          : oauth.unauthorized(url, 'Your connection has expired or was revoked. Connect again.', true);
      return rpc(request, env, ctx, url, auth);
    }
    if (p === '/' && request.method === 'GET') return infoPage(url);
    return json({ error: 'Not found. MCP endpoints: /mcp (sign in) and /public.' }, 404);
  },

  /**
   * The daily clean-up (`triggers.crons` in wrangler.jsonc). This awaits `daily()` rather than handing it to
   * `waitUntil`, so a failure marks the cron run as failed in the dashboard instead of disappearing.
   */
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    await oauth.daily(env);
  },
} satisfies ExportedHandler<Env>;

/**
 * `GET /`: what this server is, how to connect, and which tools exist.
 *
 * Every tool is listed, including those only some accounts can use. That's deliberate: knowing a tool exists gives
 * nobody access to it (`toolsFor` decides), and people deserve to know what an assistant connected here could do.
 */
function infoPage(url: URL): Promise<Response> {
  const o = url.origin;
  const who = (t: (typeof TOOLS)[number]) =>
    t.access === 'public' ? 'Anyone' : t.access === 'signed_in' ? 'Signed in' : 'Some accounts';
  const rows = TOOLS.map(
    (t) =>
      `<tr><td><code>${esc(t.name)}</code></td><td>${esc(who(t))}${t.write ? ', with actions allowed' : ''}</td><td>${esc(t.description)}</td></tr>`,
  ).join('');
  return page(
    SERVER.title,
    `<h1>${esc(SERVER.title)}</h1>
<p>A <a href="https://modelcontextprotocol.io">Model Context Protocol</a> server. Connect Claude, ChatGPT, Cursor or any assistant that supports remote MCP servers.</p>
<h2>Connect</h2>
<p><strong>Signed in:</strong> add a remote MCP server (custom connector) with the address <code>${esc(o)}/mcp</code>. Your assistant opens a sign-in page and you choose what it may do. Claude Code: <code>claude mcp add --transport http ${esc(SERVER.name)} ${esc(o)}/mcp</code></p>
<p><strong>Public tools only:</strong> <code>${esc(o)}/public</code></p>
<h2>Tools</h2><table><thead><tr><th>Tool</th><th>Who</th><th>What</th></tr></thead><tbody>${rows}</tbody></table>
<h2>Safety</h2><ul><li>Sign-in uses your existing account. Nothing here asks for a password.</li>
<li>Assistants read, and, only if you allow it, take everyday actions. Approvals, access changes and payments stay on the service’s own site.</li>
<li>Every tool call is recorded (never its contents). End a connection at any time from your assistant.</li></ul>`,
  ).then((r) => {
    // The page is the same for everyone, so unlike the other HTML pages it may be cached.
    r.headers.set('cache-control', 'public, max-age=600');
    return r;
  });
}
