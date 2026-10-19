/**
 * @file The OAuth 2.1 authorization server for `/mcp`, and the resource-server check that every `/mcp` request goes
 * through ({@link authenticate}).
 *
 * The MCP authorization spec (2025-11-25) asks servers to implement OAuth 2.1 (draft-ietf-oauth-v2-1-13) with the
 * following pieces, and this file implements each of them:
 *
 * | Endpoint                                  | Spec                                                         |
 * | ----------------------------------------- | ------------------------------------------------------------ |
 * | `/.well-known/oauth-protected-resource`   | Protected Resource Metadata, RFC 9728                        |
 * | `/.well-known/oauth-authorization-server` | Authorization Server Metadata, RFC 8414                      |
 * | `POST /oauth/register`                    | Dynamic Client Registration, RFC 7591                        |
 * | `GET /oauth/authorize`                    | Authorization code + PKCE S256 (RFC 7636), RFC 8707 resource |
 * | `GET/POST /oauth/continue`                | Sign-in (`identity.ts`) and the consent screen               |
 * | `POST /oauth/token`                       | Code exchange and refresh-token rotation                     |
 * | `POST /oauth/revoke`                      | Token revocation, RFC 7009                                   |
 *
 * ## Data model
 *
 * A **grant** (`oauth_grants`) is one connection: one person approving one assistant, with the scopes they chose.
 * Codes and tokens all point at a grant, so revoking the grant ends every token at once. A grant is *live* while it
 * has an unused, unexpired refresh token ({@link liveConnections}).
 *
 * ## Design decisions
 *
 * - **Opaque tokens, stored hashed.** Tokens are 256-bit random values with a recognisable prefix (`mcpat_`,
 *   `mcprt_`) that secret scanners can match. Only their SHA-256 is stored, so a database leak doesn't hand out
 *   working tokens. Opaque tokens also mean every request checks revocation, which a self-contained JWT can't do.
 * - **Single use, enforced atomically.** A code or refresh token is consumed with
 *   `UPDATE … SET used_at = now WHERE used_at IS NULL`, and the request only proceeds if the update changed a row. Two
 *   racing requests with the same value can't both win. The loser is treated as reuse, which revokes the whole grant
 *   (RFC 6749 §4.1.2, RFC 9700 §4.14.2: a replayed code or refresh token means one of them has leaked). There is
 *   deliberately no grace period. A client whose refresh response was lost has to connect again, and in exchange a
 *   thief can never quietly win the race.
 * - **Audience-bound tokens.** Every token records the resource (RFC 8707) it was issued for, `<origin>/mcp`, and
 *   `authenticate` only accepts it at that resource. A token issued on your custom domain doesn't work on the
 *   Worker's `workers.dev` address (MCP authorization, "Token Audience Binding and Validation").
 * - **Connections end.** Refresh tokens rotate (OAuth 2.1 §4.3.1) and expire, and a grant lasts at most
 *   `GRANT_MAX_DAYS` however often it's refreshed. After that, the person signs in through the identity provider
 *   again.
 * - **No automatic redirects to unvetted sites.** Registration is open, so a redirect URI only proves that someone
 *   registered it. Errors found before the person has seen the consent screen are shown on a page with a link,
 *   instead of an automatic redirect (RFC 9700 §4.11.2, MCP authorization "Open Redirection").
 * - **The consent step is tied to one browser.** `/oauth/authorize` stores the request server-side and binds it to
 *   an `HttpOnly` `__Host-` cookie. A link to `/oauth/continue` is useless in any other browser, which defeats
 *   consent CSRF and login-fixation tricks (RFC 9700 §4.7).
 */
import {
  ACCESS_SECONDS,
  AUDIT_DAYS,
  CODE_SECONDS,
  GRANT_MAX_DAYS,
  REFRESH_DAYS,
  REGISTRATIONS_PER_HOUR,
  REQUEST_MINUTES,
  REQUESTS_PER_NETWORK,
  SCOPES,
  SERVER,
  UNUSED_CLIENT_DAYS,
} from './config.ts';
import type { Env } from './env.ts';
import { resolveUser, type IdentityProvider, type User } from './identity.ts';
import {
  all,
  b64url,
  clean,
  esc,
  fromSqlTime,
  isJson,
  json,
  networkKey,
  one,
  page,
  parseCookies,
  q,
  randomId,
  readBody,
  readUrlEncoded,
  sameOrigin,
  sha256,
  sqlTime,
} from './util.ts';

/** Every scope the server knows, in the order the metadata lists them. */
export const SCOPE_LIST = Object.keys(SCOPES);
/** Binds an authorization request to the browser that started it. `__Host-` means Secure, Path=/ and no Domain. */
const REQ_COOKIE = '__Host-kit_oauthreq';
const ACCESS_PREFIX = 'mcpat_';
const REFRESH_PREFIX = 'mcprt_';
const HEX64 = /^[0-9a-f]{64}$/;
/** OAuth request bodies are a few hundred bytes. 16 KB leaves room for long client metadata and nothing more. */
const MAX_FORM = 16 * 1024;
const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

/** An OAuth error response (RFC 6749 §5.2). `json()` already adds `Cache-Control: no-store`, and `Pragma` is for HTTP/1.0 caches. */
const oauthError = (error: string, description: string, status = 400, extra: Record<string, string> = {}) =>
  json({ error, error_description: description }, status, { pragma: 'no-cache', ...extra });
const methodNotAllowed = (allow: string) =>
  oauthError('invalid_request', `Use ${allow}.`, 405, { allow: `${allow}, OPTIONS` });

/** `value` without its token prefix if it is exactly prefix + 64 hex characters, otherwise null. */
const unprefix = (value: string | null, prefix: string): string | null =>
  value && value.startsWith(prefix) && HEX64.test(value.slice(prefix.length)) ? value.slice(prefix.length) : null;

// ---------------------------------------------------------------- metadata

/** The canonical URI of this MCP server (MCP authorization, "Canonical Server URI"): the resource every token is for. */
export const resourceUrl = (url: URL): string => `${url.origin}/mcp`;

/** Normalises a resource indicator for comparison: lowercase scheme and host, no trailing slash. Null if invalid. */
const canonicalResource = (r: string): string | null => {
  try {
    const u = new URL(r);
    // RFC 8707 §2: the resource "MUST NOT include a fragment component" and "SHOULD NOT include a query component".
    if (u.hash || u.search) return null;
    return `${u.origin}${u.pathname.replace(/\/+$/, '')}`;
  } catch {
    return null;
  }
};

/**
 * Whether a `resource` parameter (RFC 8707) names `expected` or its origin. An absent parameter is accepted, because
 * older clients don't send one. The token is then bound to `expected` anyway.
 */
const okResource = (resource: string | null, expected: string): boolean => {
  if (!resource) return true;
  const r = canonicalResource(resource);
  return r === expected || r === new URL(expected).origin;
};

/** `GET /.well-known/oauth-protected-resource[/mcp]` (RFC 9728 §3). It names this server as the authorization server. */
export function protectedResource(url: URL): Response {
  return json(
    {
      resource: resourceUrl(url),
      authorization_servers: [url.origin],
      scopes_supported: SCOPE_LIST,
      bearer_methods_supported: ['header'],
      resource_name: SERVER.title,
      resource_documentation: `${url.origin}/`,
    },
    200,
    { 'cache-control': 'public, max-age=3600' },
  );
}

/**
 * `GET /.well-known/oauth-authorization-server` (RFC 8414 §3).
 *
 * `code_challenge_methods_supported: ["S256"]` matters: MCP clients must refuse to continue without it (MCP
 * authorization, "Authorization Code Protection"). `authorization_response_iss_parameter_supported` announces the
 * `iss` parameter that defends against mix-up attacks (RFC 9207).
 */
export function authServer(url: URL): Response {
  const o = url.origin;
  return json(
    {
      issuer: o,
      authorization_endpoint: `${o}/oauth/authorize`,
      token_endpoint: `${o}/oauth/token`,
      registration_endpoint: `${o}/oauth/register`,
      revocation_endpoint: `${o}/oauth/revoke`,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
      revocation_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
      scopes_supported: SCOPE_LIST,
      service_documentation: `${o}/`,
      authorization_response_iss_parameter_supported: true,
    },
    200,
    { 'cache-control': 'public, max-age=3600' },
  );
}

/**
 * The 401 for `/mcp` without a usable token.
 *
 * `WWW-Authenticate` carries `resource_metadata`, which is how an MCP client discovers where to sign in (RFC 9728
 * §5.1, MCP authorization "Protected Resource Metadata Discovery"). It also carries `scope`, the scopes to ask for
 * (RFC 6750 §3). When a token was sent but isn't valid, `error="invalid_token"` tells the client to refresh or
 * reconnect. When no token was sent, there is no error code, as RFC 6750 §3.1 asks.
 */
export function unauthorized(url: URL, description: string, invalidToken = false): Response {
  return json({ jsonrpc: '2.0', id: null, error: { code: -32001, message: description } }, 401, {
    'www-authenticate': `Bearer realm="mcp"${invalidToken ? ', error="invalid_token"' : ''}, resource_metadata="${url.origin}/.well-known/oauth-protected-resource", scope="${SCOPE_LIST.join(' ')}"`,
  });
}

// ---------------------------------------------------------------- registration

const isLoopback = (u: URL) => u.protocol === 'http:' && LOOPBACK_HOSTS.includes(u.hostname);

/**
 * Whether a redirect URI may be registered.
 *
 * - `https:` anywhere.
 * - `http:` only on loopback, for native apps that listen locally (RFC 8252 §7.3). The MCP spec allows no other
 *   plain `http:` (MCP authorization, "Communication Security").
 * - Private-use schemes such as `cursor://` or `com.example.app:/cb` for desktop apps (RFC 8252 §7.1). Schemes a
 *   browser would *execute* rather than hand to an app (`javascript:`, `data:`, `vbscript:`, `blob:`, `file:`) are
 *   refused.
 * - Never a fragment (RFC 6749 §3.1.2).
 */
export function okRedirect(u: string): boolean {
  try {
    const x = new URL(u);
    if (x.hash) return false;
    if (x.protocol === 'https:') return true;
    if (x.protocol === 'http:') return isLoopback(x);
    return (
      /^[a-z][a-z0-9+.-]{2,}:$/.test(x.protocol) &&
      !['javascript:', 'data:', 'file:', 'vbscript:', 'blob:'].includes(x.protocol)
    );
  } catch {
    return false;
  }
}

/**
 * Whether a redirect URI from an authorization request matches a registered one.
 *
 * The match is exact, as OAuth 2.1 and RFC 9700 §2.1 require: no prefixes and no wildcards. The one exception is
 * the **port** of a loopback `http:` URI, because native apps listen on whatever port is free when they start
 * (RFC 8252 §7.3, which OAuth 2.1 adopts). Host, path and query must still match exactly. `localhost` and
 * `127.0.0.1` are different hosts here, on purpose.
 */
export function redirectMatches(registered: string, asked: string): boolean {
  if (registered === asked) return true;
  try {
    const r = new URL(registered),
      a = new URL(asked);
    return (
      isLoopback(r) &&
      isLoopback(a) &&
      r.hostname === a.hostname &&
      r.pathname === a.pathname &&
      r.search === a.search &&
      !a.hash
    );
  } catch {
    return false;
  }
}

interface Client {
  id: string;
  name: string;
  redirect_uris: string;
  secret_hash: string | null;
}
/** A registered client by id, or null. The format is checked first, so junk never reaches the database. */
const clientBy = (env: Env, id: string | null): Promise<Client | null> =>
  id && /^client_[0-9a-f]{32}$/.test(id)
    ? one<Client>(env, 'SELECT id, name, redirect_uris, secret_hash FROM oauth_clients WHERE id = ?', id)
    : Promise.resolve(null);

const AUTH_METHODS = ['none', 'client_secret_post', 'client_secret_basic'];
const GRANT_TYPES = ['authorization_code', 'refresh_token'];

/**
 * `POST /oauth/register`: dynamic client registration (RFC 7591).
 *
 * Open to anyone, because that's how MCP clients with no prior relationship connect. The defences that make this
 * safe are: redirect URIs are validated ({@link okRedirect}), registrations are limited per network
 * (`REGISTRATIONS_PER_HOUR`), clients that never connect are removed by {@link daily}, and the consent screen shows
 * where the person will be sent. Public clients (`none`) get no secret and rely on PKCE. Confidential clients get a
 * secret that is shown once and stored only as a hash.
 */
export async function register(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') return methodNotAllowed('POST');
  const text = await readBody(request, MAX_FORM);
  if (text === null) return oauthError('invalid_client_metadata', 'Client metadata must be under 16 KB.', 413);
  let m: unknown;
  try {
    m = JSON.parse(text);
  } catch {
    return oauthError('invalid_client_metadata', 'The body must be JSON.');
  }
  if (!m || typeof m !== 'object' || Array.isArray(m))
    return oauthError('invalid_client_metadata', 'The body must be a JSON object.');
  const meta = m as Record<string, unknown>;
  const uris: unknown[] = Array.isArray(meta.redirect_uris) ? meta.redirect_uris : [];
  if (
    !uris.length ||
    uris.length > 10 ||
    !uris.every((u): u is string => typeof u === 'string' && u.length <= 500 && okRedirect(u))
  ) {
    return oauthError(
      'invalid_redirect_uri',
      'redirect_uris must be 1 to 10 https URLs, loopback http URLs or app schemes, without fragments.',
    );
  }
  const method = meta.token_endpoint_auth_method ?? 'none';
  if (typeof method !== 'string' || !AUTH_METHODS.includes(method))
    return oauthError(
      'invalid_client_metadata',
      'token_endpoint_auth_method must be none, client_secret_post or client_secret_basic.',
    );
  if (
    meta.grant_types !== undefined &&
    !(
      Array.isArray(meta.grant_types) && meta.grant_types.every((g) => typeof g === 'string' && GRANT_TYPES.includes(g))
    )
  ) {
    return oauthError('invalid_client_metadata', 'Only authorization_code and refresh_token grants are supported.');
  }
  const net = await networkKey(request, env);
  // Count, then insert: two simultaneous requests can both pass the count. The limit is a brake on floods, not an
  // exact quota, so a few extra rows under a burst are an acceptable price for avoiding a transaction.
  const recent = await one<{ n: number }>(
    env,
    'SELECT COUNT(*) AS n FROM oauth_clients WHERE network_hash = ? AND created_at > ?',
    net,
    sqlTime(Date.now() - 3600e3),
  );
  if ((recent?.n ?? 0) >= REGISTRATIONS_PER_HOUR)
    return oauthError('invalid_request', 'Too many registrations from this network. Try again later.', 429);
  const id = `client_${randomId(16)}`;
  const secret = method === 'none' ? null : randomId(32);
  const name = clean(meta.client_name, 100) || 'AI assistant';
  const uri =
    typeof meta.client_uri === 'string' && meta.client_uri.length <= 300 && /^https:\/\//.test(meta.client_uri)
      ? meta.client_uri
      : null;
  await q(
    env,
    'INSERT INTO oauth_clients (id, name, redirect_uris, secret_hash, uri, network_hash) VALUES (?, ?, ?, ?, ?, ?)',
    id,
    name,
    JSON.stringify(uris),
    secret ? await sha256(secret) : null,
    uri,
    net,
  ).run();
  // RFC 7591 §3.2.1: the response echoes the metadata as registered, including any values the server changed.
  return json(
    {
      client_id: id,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: name,
      ...(uri ? { client_uri: uri } : {}),
      redirect_uris: uris,
      grant_types: GRANT_TYPES,
      response_types: ['code'],
      token_endpoint_auth_method: method,
      ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
    },
    201,
  );
}

// ---------------------------------------------------------------- authorize, sign-in, consent
const errorPage = (msg: string, status = 400) =>
  page(
    'Can’t connect',
    `<h1>This connection can’t go ahead</h1><p>${esc(msg)}</p><p>Go back to your assistant and try connecting again.</p>`,
    status,
  );

/** `redirectUri` with the authorization response parameters added (RFC 6749 §4.1.2). Null values are left out. */
const withParams = (redirectUri: string, params: Record<string, string | null | undefined>): string => {
  const u = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) if (v != null) u.searchParams.set(k, v);
  return u.toString();
};
/** A 302 to the client. Used only after the person has seen, on the consent screen, where they'll be sent. */
const back = (redirectUri: string, params: Record<string, string | null | undefined>) =>
  new Response(null, {
    status: 302,
    headers: { location: withParams(redirectUri, params), 'cache-control': 'no-store' },
  });

/** What the person sees as the destination: the host for web and loopback URIs, the scheme for app URIs. */
const destination = (redirectUri: string): string => {
  try {
    const u = new URL(redirectUri);
    return u.host || u.protocol;
  } catch {
    return '';
  }
};

/**
 * An authorization error, shown on a page instead of being redirected automatically.
 *
 * RFC 6749 §4.1.2.1 says to redirect errors back to the client. RFC 9700 §4.11.2 then points out that, with open
 * registration, anyone can register a phishing page as a redirect URI and send a deliberately broken request to
 * bounce people there from your trusted domain. So the person is told what went wrong and gets a link carrying the
 * standard error parameters. They decide whether to follow it ("MAY inform the user and rely on the user to make the
 * correct decision").
 */
const errorBack = (redirectUri: string, params: Record<string, string | null | undefined>, status = 400) =>
  page(
    'Can’t connect',
    `<h1>This connection can’t go ahead</h1><p>${esc(params.error_description)}</p>
<p><a href="${esc(withParams(redirectUri, params))}">Return to ${esc(destination(redirectUri))}</a></p>
<p class="small">Only follow this link if you were connecting an assistant just now.</p>`,
    status,
  );

/** The `form-action` source that lets the consent form's redirect reach the assistant (see `page()` in util.ts). */
const formTarget = (redirectUri: string): string => {
  try {
    const u = new URL(redirectUri);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.origin : u.protocol;
  } catch {
    return '';
  }
};

/** An authorization request waiting for sign-in and consent, as stored in `oauth_requests.params`. */
interface Pending {
  redirect_uri: string;
  state: string | null;
  code_challenge: string;
  scopes: string[];
  resource: string;
}

/**
 * `GET /oauth/authorize`: validates the authorization request, stores it, binds it to this browser and sends the
 * person on to `/oauth/continue`.
 *
 * The validation order matters. Until the client and redirect URI are known to be good, nothing may be sent to the
 * redirect URI (RFC 6749 §4.1.2.1), so those failures get a plain error page. Problems with the remaining parameters
 * get {@link errorBack}.
 */
export async function authorize(request: Request, env: Env, url: URL): Promise<Response> {
  const sp = url.searchParams;
  const client = await clientBy(env, sp.get('client_id'));
  if (!client) return errorPage('The assistant isn’t registered with this server (unknown client_id).');
  const redirectUri = sp.get('redirect_uri') || '';
  const uris = JSON.parse(client.redirect_uris) as string[];
  // redirect_uri may be left out only when exactly one is registered (RFC 6749 §3.1.2.3).
  if (!uris.some((u) => redirectMatches(u, redirectUri)) && !(uris.length === 1 && !redirectUri))
    return errorPage('The assistant asked to return to an address it didn’t register.');
  const ru = redirectUri || uris[0];
  const state = sp.get('state');
  const fail = (error: string, description: string) =>
    errorBack(ru, { error, error_description: description, state, iss: url.origin });
  if (sp.get('response_type') !== 'code') return fail('unsupported_response_type', 'response_type must be code.');
  const challenge = sp.get('code_challenge') || '';
  // OAuth 2.1 makes PKCE mandatory, and S256 is the only method worth supporting: "plain" sends the verifier in the
  // front channel, where it can be intercepted (RFC 7636 §4.2, RFC 9700 §2.1.1). A SHA-256 in base64url is 43 characters.
  if (sp.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(challenge))
    return fail('invalid_request', 'PKCE with code_challenge_method=S256 is required.');
  // Unknown scopes are dropped rather than refused (RFC 6749 §3.3 lets the server grant fewer). read is always included.
  const asked = (sp.get('scope') || SCOPE_LIST.join(' ')).split(/\s+/).filter(Boolean);
  const scopes = SCOPE_LIST.filter((s) => s === 'read' || asked.includes(s));
  if (!okResource(sp.get('resource'), resourceUrl(url)))
    return fail('invalid_target', `resource must be ${resourceUrl(url)}.`);
  if (state && state.length > 2000) return fail('invalid_request', 'state is too long.');

  const net = await networkKey(request, env);
  const started = await one<{ n: number }>(
    env,
    'SELECT COUNT(*) AS n FROM oauth_requests WHERE network_hash = ? AND created_at > ?',
    net,
    sqlTime(Date.now() - REQUEST_MINUTES * 60e3),
  );
  if ((started?.n ?? 0) >= REQUESTS_PER_NETWORK)
    return errorPage('Too many connection attempts from your network. Wait a few minutes and try again.', 429);

  // Reuse this browser's binding if it already has one, so two connections started side by side in the same browser
  // don't cancel each other out. The value is only ever compared by hash, and a __Host- cookie can't be planted by a
  // subdomain, so reusing it gives an attacker nothing.
  const existing = parseCookies(request)[REQ_COOKIE];
  const browser = existing && /^[0-9a-f]{48}$/.test(existing) ? existing : randomId(24);
  const id = randomId(16);
  const pending: Pending = { redirect_uri: ru, state, code_challenge: challenge, scopes, resource: resourceUrl(url) };
  await q(
    env,
    'INSERT INTO oauth_requests (id, browser_hash, client_id, params, network_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
    id,
    await sha256(browser),
    client.id,
    JSON.stringify(pending),
    net,
    sqlTime(Date.now() + REQUEST_MINUTES * 60e3),
  ).run();
  return new Response(null, {
    status: 302,
    headers: {
      location: `/oauth/continue?req=${id}`,
      'cache-control': 'no-store',
      // SameSite=Lax rather than Strict: the person arrives here by a top-level navigation from the assistant's site,
      // and may return to /oauth/continue from an identity provider's site. Lax still keeps the cookie off
      // cross-site POSTs.
      'set-cookie': `${REQ_COOKIE}=${browser}; Path=/; Max-Age=${REQUEST_MINUTES * 60}; HttpOnly; Secure; SameSite=Lax`,
    },
  });
}

/** The authorization request `id`, if this browser started it and it hasn't expired, otherwise null. */
async function ownRequest(request: Request, env: Env, id: string | null) {
  if (!id || !/^[0-9a-f]{32}$/.test(id)) return null;
  const cookie = parseCookies(request)[REQ_COOKIE];
  if (!cookie) return null;
  const r = await one<{ id: string; browser_hash: string; client_id: string; params: string }>(
    env,
    'SELECT id, browser_hash, client_id, params FROM oauth_requests WHERE id = ? AND expires_at > ?',
    id,
    sqlTime(Date.now()),
  );
  return r && r.browser_hash === (await sha256(cookie)) ? r : null;
}

/**
 * `GET|POST /oauth/continue?req=…`: sign in through the identity provider, then approve or deny.
 *
 * GET shows the consent screen. POST records the decision. Both re-check the person through the identity provider and
 * the `users` table, so whoever is signed in *when the button is pressed* is the one who approves. The POST is
 * protected against CSRF three ways: the request id is unguessable, it must belong to this browser's `__Host-`
 * cookie (which is SameSite=Lax, so it isn't sent on cross-site POSTs), and `Origin` must be this site
 * ({@link sameOrigin}). The page itself can't be framed (`page()`), which rules out clickjacking.
 */
export async function continueAuth(request: Request, env: Env, url: URL, idp: IdentityProvider): Promise<Response> {
  const id = url.searchParams.get('req');
  const r = await ownRequest(request, env, id);
  if (!r) return errorPage('This connection request has expired or was started in another browser.');
  const client = await clientBy(env, r.client_id);
  if (!client)
    return errorPage('The assistant’s registration has been removed. Go back to your assistant and connect again.');
  const p = JSON.parse(r.params) as Pending;
  const next = `/oauth/continue?req=${r.id}`;
  const user = await idp.currentUser(request, env, url);
  if (!user) {
    const login = idp.loginUrl(next, url);
    if (login) return new Response(null, { status: 302, headers: { location: login, 'cache-control': 'no-store' } });
    return errorPage(
      idp.name === 'none'
        ? 'Sign-in isn’t set up on this server yet, so only its public tools are available (at /public).'
        : 'You aren’t signed in. If this server uses Cloudflare Access, its administrator needs to protect /oauth/continue with it.',
      401,
    );
  }
  // The users table has the last word even over a provider that still vouches for the person (Access can't be told
  // that someone was disabled here).
  if (await one(env, 'SELECT 1 FROM users WHERE id = ? AND disabled_at IS NOT NULL', user.id))
    return errorPage('Your account can’t connect assistants to this server.', 403);

  if (request.method === 'POST') {
    if (!sameOrigin(request)) return errorPage('This approval didn’t come from this page.', 403);
    const f = await readUrlEncoded(request, MAX_FORM);
    if (!f) return errorPage('That form was too large.', 413);
    // Single use: the request is gone whatever the decision, so a replayed POST finds nothing.
    await q(env, 'DELETE FROM oauth_requests WHERE id = ?', r.id).run();
    if (f.get('decision') !== 'approve')
      return back(p.redirect_uri, {
        error: 'access_denied',
        error_description: 'The person declined.',
        state: p.state,
        iss: url.origin,
      });
    // write is granted only if it was both asked for and ticked. The scope list is never taken from the form itself.
    const scopes = p.scopes.filter((s) => s === 'read' || (s === 'write' && f.get('write') === '1'));
    const grant = randomId(16);
    const code = randomId(32);
    await env.DB.batch([
      q(
        env,
        `INSERT INTO users (id, name, email, roles) VALUES (?, ?, ?, ?)
              ON CONFLICT(id) DO UPDATE SET name = excluded.name, email = excluded.email, roles = excluded.roles, updated_at = datetime('now')`,
        user.id,
        user.name,
        user.email || null,
        JSON.stringify(user.roles || []),
      ),
      q(
        env,
        'INSERT INTO oauth_grants (id, client_id, user_id, scopes) VALUES (?, ?, ?, ?)',
        grant,
        client.id,
        user.id,
        scopes.join(' '),
      ),
      q(
        env,
        'INSERT INTO oauth_codes (code_hash, grant_id, client_id, redirect_uri, code_challenge, resource, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        await sha256(code),
        grant,
        client.id,
        p.redirect_uri,
        p.code_challenge,
        p.resource,
        sqlTime(Date.now() + CODE_SECONDS * 1000),
      ),
    ]);
    // iss: RFC 9207, so a client talking to several authorization servers can tell which one answered (mix-up defence).
    return back(p.redirect_uri, { code, state: p.state, iss: url.origin });
  }

  const dest = new URL(p.redirect_uri);
  // Any program on the person's computer can listen on a loopback port or claim an app scheme, so these redirect
  // URIs prove nothing about who the client is (MCP authorization, "Localhost Redirect URI Risks").
  const local = isLoopback(dest) || (dest.protocol !== 'https:' && dest.protocol !== 'http:');
  const lower = (s: string) => s.charAt(0).toLowerCase() + s.slice(1);
  return page(
    'Approve',
    `<p class="small">${esc(SERVER.title)}</p><h1>Allow ${esc(client.name)} to use your account?</h1>
<p>Signed in as <strong>${esc(user.name)}</strong>${user.email && user.email !== user.name ? ` (${esc(user.email)})` : ''}.</p>
${local ? `<p class="warn">This assistant runs on your own computer (it returns to <strong>${esc(destination(p.redirect_uri))}</strong>). Only continue if you started connecting it yourself just now.</p>` : ''}
<form method="post" action="${esc(next)}">
<p><strong>It will be able to:</strong></p><ul><li>${esc(SCOPES.read)}</li></ul>
${p.scopes.includes('write') ? `<p><label><input type="checkbox" name="write" value="1"> Also allow it to ${esc(lower(SCOPES.write))}</label></p>` : ''}
<p class="small">It acts as you, within your current permissions, and every tool call is recorded. After you choose, you return to <strong>${esc(destination(p.redirect_uri))}</strong>. You can disconnect it at any time from your assistant, or by asking it to revoke the connection.</p>
<p><button type="submit" name="decision" value="approve">Allow</button> <button class="ghost" type="submit" name="decision" value="deny">Deny</button></p></form>`,
    200,
    [formTarget(p.redirect_uri)],
  );
}

// ---------------------------------------------------------------- tokens
type Form = { get(k: string): string | null };

/** form-urlencoded decoding of one Basic credential (RFC 6749 §2.3.1: "+" is a space, then percent-decoding). */
const formDecode = (s: string) => decodeURIComponent(s.replace(/\+/g, ' '));

/**
 * Authenticates the client at the token or revocation endpoint (RFC 6749 §2.3.1).
 *
 * Public clients (no secret) identify themselves with `client_id` alone, and PKCE and refresh rotation do the
 * protecting. Confidential clients must present their secret, with HTTP Basic or in the form.
 *
 * @returns The client, and whether HTTP Basic was attempted (a failed Basic attempt must get `WWW-Authenticate`,
 *   RFC 6749 §5.2). `client` is null if authentication failed.
 */
async function clientAuth(request: Request, env: Env, f: Form): Promise<{ client: Client | null; basic: boolean }> {
  let id = f.get('client_id');
  let secret = f.get('client_secret');
  const h = request.headers.get('authorization') || '';
  const basic = /^basic /i.test(h);
  if (basic) {
    try {
      const decoded = atob(h.slice(6).trim());
      const i = decoded.indexOf(':');
      if (i < 0) return { client: null, basic };
      // Split at the first colon only: the secret may contain colons, the id may not (RFC 7617 §2).
      id = formDecode(decoded.slice(0, i));
      secret = formDecode(decoded.slice(i + 1));
    } catch {
      return { client: null, basic };
    }
  }
  const c = await clientBy(env, id);
  if (!c) return { client: null, basic };
  if (c.secret_hash && (!secret || (await sha256(secret)) !== c.secret_hash)) return { client: null, basic };
  return { client: c, basic };
}

/** One connection: a person's approval of one assistant. */
export interface Grant {
  id: string;
  client_id: string;
  user_id: string;
  /** Space-separated, e.g. `"read write"`. */
  scopes: string;
  /** When the person approved it (`sqlTime` format). The grant's hard end is counted from here. */
  created_at: string;
}

/** When a grant ends however often it's refreshed (`GRANT_MAX_DAYS` after approval), in epoch ms. */
const grantEnds = (g: Grant) => fromSqlTime(g.created_at) + GRANT_MAX_DAYS * 864e5;

/**
 * Issues a new access/refresh token pair for a grant, bound to `resource`. Neither token outlives the grant.
 *
 * The response follows RFC 6749 §5.1, including `Cache-Control: no-store`.
 */
async function issue(env: Env, grant: Grant, clientId: string, resource: string): Promise<Response> {
  const access = randomId(32),
    refresh = randomId(32);
  const ends = grantEnds(grant);
  const accessUntil = Math.min(Date.now() + ACCESS_SECONDS * 1000, ends);
  const insert = (kind: 'access' | 'refresh', hash: string, until: number) =>
    q(
      env,
      'INSERT INTO oauth_tokens (token_hash, kind, grant_id, client_id, resource, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
      hash,
      kind,
      grant.id,
      clientId,
      resource,
      sqlTime(until),
    );
  await env.DB.batch([
    insert('access', await sha256(access), accessUntil),
    insert('refresh', await sha256(refresh), Math.min(Date.now() + REFRESH_DAYS * 864e5, ends)),
  ]);
  return json(
    {
      access_token: `${ACCESS_PREFIX}${access}`,
      token_type: 'Bearer',
      expires_in: Math.max(1, Math.round((accessUntil - Date.now()) / 1000)),
      refresh_token: `${REFRESH_PREFIX}${refresh}`,
      scope: grant.scopes,
    },
    200,
    { pragma: 'no-cache' },
  );
}

/**
 * The parameters of a token or revocation request, from a body of at most 16 KB.
 *
 * RFC 6749 specifies `application/x-www-form-urlencoded`. JSON is accepted as well, because some MCP clients send it
 * and refusing them helps nobody.
 */
async function readForm(request: Request): Promise<Form | null> {
  const text = await readBody(request, MAX_FORM);
  if (text === null) return null;
  if (isJson(request)) {
    let j: unknown;
    try {
      j = JSON.parse(text);
    } catch {
      return null;
    }
    if (!j || typeof j !== 'object' || Array.isArray(j)) return null;
    const m = new Map(
      Object.entries(j as Record<string, unknown>).filter((e): e is [string, string] => typeof e[1] === 'string'),
    );
    return { get: (k) => m.get(k) ?? null };
  }
  return new URLSearchParams(text);
}

/**
 * Marks a code or refresh token as used, atomically.
 *
 * @returns False if another request already used it. That counts as reuse even when it was only a race, because a
 *   legitimate client never sends the same value twice.
 */
const claim = async (env: Env, table: 'oauth_codes' | 'oauth_tokens', hash: string): Promise<boolean> =>
  ((
    await q(
      env,
      `UPDATE ${table} SET used_at = datetime('now') WHERE ${table === 'oauth_codes' ? 'code_hash' : 'token_hash'} = ? AND used_at IS NULL`,
      hash,
    ).run()
  ).meta.changes ?? 0) > 0;

/**
 * `POST /oauth/token`: exchanges an authorization code for tokens, or rotates a refresh token.
 *
 * **authorization_code** (OAuth 2.1 §4.1.3): the code must belong to this client and be unused and unexpired. If
 * `redirect_uri` is sent, it must be the one from the authorization request. The PKCE verifier must hash to the
 * stored challenge (RFC 7636 §4.6). A code presented twice revokes the grant and every token issued from it
 * (RFC 6749 §4.1.2).
 *
 * **refresh_token** (OAuth 2.1 §4.3): the token must belong to this client, be unused and unexpired, and its grant
 * must be live and within `GRANT_MAX_DAYS`. It's consumed and replaced (rotation), and the grant's old access
 * tokens are deleted. Presenting a used refresh token revokes the grant (RFC 9700 §4.14.2).
 *
 * In both cases, the person must still be allowed to connect ({@link resolveUser}) before anything is issued.
 */
export async function token(request: Request, env: Env, idp: IdentityProvider): Promise<Response> {
  if (request.method !== 'POST') return methodNotAllowed('POST');
  const f = await readForm(request);
  if (!f) return oauthError('invalid_request', 'Send application/x-www-form-urlencoded parameters, under 16 KB.');
  const { client, basic } = await clientAuth(request, env, f);
  if (!client)
    return oauthError(
      'invalid_client',
      'Unknown client, or wrong client secret.',
      401,
      basic ? { 'www-authenticate': 'Basic realm="oauth"' } : {},
    );
  const type = f.get('grant_type');

  if (type === 'authorization_code') {
    const code = f.get('code') || '';
    const row = HEX64.test(code)
      ? await one<{
          code_hash: string;
          grant_id: string;
          client_id: string;
          redirect_uri: string;
          code_challenge: string;
          resource: string;
          expires_at: string;
          used_at: string | null;
        }>(env, 'SELECT * FROM oauth_codes WHERE code_hash = ?', await sha256(code))
      : null;
    if (!row || row.client_id !== client.id) return oauthError('invalid_grant', 'Unknown authorization code.');
    if (!okResource(f.get('resource'), row.resource))
      return oauthError('invalid_target', `resource must be ${row.resource}.`);
    // Claimed before any other check, so a code can never be tried twice, not even with a different verifier.
    if (row.used_at || !(await claim(env, 'oauth_codes', row.code_hash))) {
      await revokeGrant(env, row.grant_id, 'code_reuse');
      return oauthError('invalid_grant', 'This code was already used; the connection has been ended for safety.');
    }
    if (row.expires_at <= sqlTime(Date.now()))
      return oauthError('invalid_grant', 'The authorization code has expired.');
    const sentRedirect = f.get('redirect_uri');
    if (sentRedirect && sentRedirect !== row.redirect_uri)
      return oauthError('invalid_grant', 'redirect_uri doesn’t match the authorization request.');
    const verifier = f.get('code_verifier') || '';
    // RFC 7636 §4.1: 43 to 128 characters from the unreserved set.
    if (
      !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) ||
      b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))) !== row.code_challenge
    ) {
      return oauthError('invalid_grant', 'PKCE verification failed.');
    }
    const grant = await one<Grant>(env, 'SELECT * FROM oauth_grants WHERE id = ? AND revoked_at IS NULL', row.grant_id);
    if (!grant) return oauthError('invalid_grant', 'This connection was revoked.');
    if (!(await resolveUser(grant.user_id, env, idp)))
      return oauthError('invalid_grant', 'This account can no longer connect assistants.');
    return issue(env, grant, client.id, row.resource);
  }

  if (type === 'refresh_token') {
    const raw = unprefix(f.get('refresh_token'), REFRESH_PREFIX);
    const row = raw
      ? await one<{
          token_hash: string;
          grant_id: string;
          client_id: string;
          resource: string;
          expires_at: string;
          used_at: string | null;
        }>(env, "SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = 'refresh'", await sha256(raw))
      : null;
    if (!row || row.client_id !== client.id) return oauthError('invalid_grant', 'Unknown refresh token.');
    if (!okResource(f.get('resource'), row.resource))
      return oauthError('invalid_target', `resource must be ${row.resource}.`);
    const reuse = async () => {
      await revokeGrant(env, row.grant_id, 'refresh_reuse');
      return oauthError(
        'invalid_grant',
        'This refresh token was already used; the connection has been ended for safety. Connect again.',
      );
    };
    if (row.used_at) return reuse();
    if (row.expires_at <= sqlTime(Date.now()))
      return oauthError('invalid_grant', 'The refresh token has expired. Connect again.');
    const grant = await one<Grant>(env, 'SELECT * FROM oauth_grants WHERE id = ? AND revoked_at IS NULL', row.grant_id);
    if (!grant) return oauthError('invalid_grant', 'This connection was revoked.');
    if (grantEnds(grant) <= Date.now())
      return oauthError('invalid_grant', 'This connection has reached its time limit. Connect again.');
    if (!(await resolveUser(grant.user_id, env, idp)))
      return oauthError('invalid_grant', 'This account can no longer connect assistants.');
    // Rotation: the used refresh token is kept (marked used, not deleted), so that a second use is recognised as
    // theft rather than as an unknown token.
    if (!(await claim(env, 'oauth_tokens', row.token_hash))) return reuse();
    await q(env, "DELETE FROM oauth_tokens WHERE grant_id = ? AND kind = 'access'", grant.id).run();
    return issue(env, grant, client.id, row.resource);
  }
  return oauthError('unsupported_grant_type', 'grant_type must be authorization_code or refresh_token.');
}

/**
 * Ends a connection: marks the grant revoked, deletes its access tokens and marks its refresh tokens used, all in one
 * transaction. Marking refresh tokens rather than deleting them means a later attempt to use one is still
 * recognised (and refused) as reuse.
 *
 * Tokens issued by a request racing with this one are harmless, because {@link authenticate} and the refresh flow
 * both check `revoked_at` on every use.
 *
 * @param by - Why, for the record (`client`, `code_reuse`, `refresh_reuse`, `user:<id>`).
 */
export async function revokeGrant(env: Env, grantId: string, by: string): Promise<void> {
  await env.DB.batch([
    q(
      env,
      "UPDATE oauth_grants SET revoked_at = datetime('now'), revoked_by = ? WHERE id = ? AND revoked_at IS NULL",
      by.slice(0, 80),
      grantId,
    ),
    q(env, "DELETE FROM oauth_tokens WHERE grant_id = ? AND kind = 'access'", grantId),
    q(
      env,
      "UPDATE oauth_tokens SET used_at = COALESCE(used_at, datetime('now')) WHERE grant_id = ? AND kind = 'refresh'",
      grantId,
    ),
  ]);
}

/**
 * `POST /oauth/revoke` (RFC 7009). Revoking either token ends the whole connection, which RFC 7009 §2.1 allows.
 *
 * The answer is 200 for any authenticated client, whether or not the token was known or was theirs (RFC 7009 §2.2).
 * That way the endpoint can't be used to find out which tokens exist.
 */
export async function revoke(request: Request, env: Env): Promise<Response> {
  if (request.method !== 'POST') return methodNotAllowed('POST');
  const f = await readForm(request);
  const { client, basic } = f ? await clientAuth(request, env, f) : { client: null, basic: false };
  if (!f || !client)
    return oauthError(
      'invalid_client',
      'Unknown client.',
      401,
      basic ? { 'www-authenticate': 'Basic realm="oauth"' } : {},
    );
  const t = f.get('token');
  const raw = unprefix(t, ACCESS_PREFIX) ?? unprefix(t, REFRESH_PREFIX);
  if (raw) {
    const row = await one<{ grant_id: string; client_id: string }>(
      env,
      'SELECT grant_id, client_id FROM oauth_tokens WHERE token_hash = ?',
      await sha256(raw),
    );
    if (row && row.client_id === client.id) await revokeGrant(env, row.grant_id, 'client');
  }
  return json({});
}

// ---------------------------------------------------------------- who is calling

/** An authenticated `/mcp` caller. */
export interface Caller {
  grant: Grant;
  scopes: Set<string>;
  user: User;
}

/**
 * The person behind a `/mcp` request's bearer token, re-checked now.
 *
 * Checks that the token is a live access token, that it was issued **for this server's resource** (audience binding,
 * MCP authorization "Token Handling"), that its grant hasn't been revoked or passed `GRANT_MAX_DAYS`, and that the
 * person may still connect ({@link resolveUser}), with their current roles. Disabling someone stops all their
 * assistants on the next request.
 *
 * Only the `Authorization` header is accepted: tokens in the query string are refused (MCP authorization, "Token
 * Requirements"). The scheme name is case-insensitive (RFC 7235 §2.1).
 *
 * @returns The caller, or `{ error: 'missing' }` (no `Authorization` header) / `{ error: 'invalid_token' }`.
 */
export async function authenticate(
  request: Request,
  env: Env,
  idp: IdentityProvider,
  url: URL,
): Promise<Caller | { error: 'missing' | 'invalid_token' }> {
  const h = request.headers.get('authorization');
  if (!h) return { error: 'missing' };
  const m = /^(\S+) +(\S+)$/.exec(h.trim());
  const raw = m && m[1].toLowerCase() === 'bearer' ? unprefix(m[2], ACCESS_PREFIX) : null;
  if (!raw) return { error: 'invalid_token' };
  const row = await one<Grant & { expires_at: string; last_used_at: string | null }>(
    env,
    `SELECT t.expires_at, g.* FROM oauth_tokens t JOIN oauth_grants g ON g.id = t.grant_id
     WHERE t.token_hash = ? AND t.kind = 'access' AND t.resource = ? AND g.revoked_at IS NULL`,
    await sha256(raw),
    resourceUrl(url),
  );
  if (!row || row.expires_at <= sqlTime(Date.now()) || grantEnds(row) <= Date.now()) return { error: 'invalid_token' };
  const user = await resolveUser(row.user_id, env, idp);
  if (!user) return { error: 'invalid_token' };
  // Write last_used_at at most every five minutes, so a busy assistant doesn't turn every read into a D1 write.
  if (!row.last_used_at || row.last_used_at < sqlTime(Date.now() - 300e3))
    await q(env, "UPDATE oauth_grants SET last_used_at = datetime('now') WHERE id = ?", row.id).run();
  const grant: Grant = {
    id: row.id,
    client_id: row.client_id,
    user_id: row.user_id,
    scopes: row.scopes,
    created_at: row.created_at,
  };
  return { grant, scopes: new Set(grant.scopes.split(' ')), user };
}

/** A person's connection as `my_connections` shows it. */
export interface Connection {
  id: string;
  name: string;
  scopes: string;
  created_at: string;
  last_used_at: string | null;
}

/**
 * A person's live connections, newest first.
 *
 * "Live" means not revoked and holding an unused, unexpired refresh token. Refresh tokens never outlive their grant,
 * so this also leaves out grants past `GRANT_MAX_DAYS`, and grants whose code was never exchanged (the client gave
 * up, or PKCE failed).
 */
export const liveConnections = (env: Env, userId: string): Promise<Connection[]> =>
  all<Connection>(
    env,
    `SELECT g.id, c.name, g.scopes, g.created_at, g.last_used_at
     FROM oauth_grants g JOIN oauth_clients c ON c.id = g.client_id
     WHERE g.user_id = ? AND g.revoked_at IS NULL AND EXISTS (
       SELECT 1 FROM oauth_tokens t
       WHERE t.grant_id = g.id AND t.kind = 'refresh' AND t.used_at IS NULL AND t.expires_at > ?)
     ORDER BY g.created_at DESC`,
    userId,
    sqlTime(Date.now()),
  );

/**
 * The daily clean-up (cron, `wrangler.jsonc`). Every table that anonymous requests can write to is bounded by it.
 *
 * - Expired authorization requests, tokens and dev sessions.
 * - Codes a day after they expire. Keeping them that long means a late replay is still recognised as reuse.
 * - Tool-call records and grants older than `AUDIT_DAYS`. Grants end within `GRANT_MAX_DAYS`, and they're kept this
 *   long only so that audit rows can still be traced to a connection.
 * - Registered clients older than `UNUSED_CLIENT_DAYS` with no grants and no pending requests. Registration is open,
 *   so without this they would pile up.
 *
 * The statements run in order in one batch, so clients whose last grant is deleted here go in the same run.
 */
export async function daily(env: Env): Promise<void> {
  const now = sqlTime(Date.now());
  const auditCutoff = sqlTime(Date.now() - AUDIT_DAYS * 864e5);
  await env.DB.batch([
    q(env, 'DELETE FROM oauth_requests WHERE expires_at < ?', now),
    q(env, 'DELETE FROM oauth_codes WHERE expires_at < ?', sqlTime(Date.now() - 864e5)),
    q(env, 'DELETE FROM oauth_tokens WHERE expires_at < ?', now),
    q(env, 'DELETE FROM dev_sessions WHERE expires_at < ?', now),
    q(env, 'DELETE FROM tool_calls WHERE created_at < ?', auditCutoff),
    q(env, 'DELETE FROM oauth_grants WHERE created_at < ?', auditCutoff),
    q(
      env,
      `DELETE FROM oauth_clients WHERE created_at < ?
         AND NOT EXISTS (SELECT 1 FROM oauth_grants g WHERE g.client_id = oauth_clients.id)
         AND NOT EXISTS (SELECT 1 FROM oauth_requests r WHERE r.client_id = oauth_clients.id)`,
      sqlTime(Date.now() - UNUSED_CLIENT_DAYS * 864e5),
    ),
  ]);
}
