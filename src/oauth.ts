// OAuth 2.1 for the /mcp endpoint, as the MCP authorization spec asks: protected resource metadata (RFC 9728),
// authorization server metadata (RFC 8414), dynamic client registration (RFC 7591), authorization code with PKCE
// S256 only, rotating refresh tokens and revocation (RFC 7009).
//
//   /.well-known/oauth-protected-resource     where to sign in, for the /mcp resource
//   /.well-known/oauth-authorization-server   the endpoints below
//   POST /oauth/register     an assistant registers itself (redirect URIs checked, rate-limited per network)
//   GET  /oauth/authorize    checks the request, remembers it for this browser, sends the person to /oauth/continue
//   GET  /oauth/continue     sign in (identity.ts), then the consent screen; POST approves or denies
//   POST /oauth/token        code → tokens (PKCE checked); refresh → new pair (the old one stops working)
//   POST /oauth/revoke       either token ends the whole connection
//
// A grant is what the person approved; revoking it ends every token. Reusing a code or a refresh token revokes the
// grant, because it means one of them leaked. Every secret is stored as its SHA-256 only.
import { ACCESS_SECONDS, CODE_SECONDS, REFRESH_DAYS, REGISTRATIONS_PER_HOUR, REQUEST_MINUTES, SCOPES, SERVER, AUDIT_DAYS } from './config.ts';
import type { Env } from './env.ts';
import type { IdentityProvider, User } from './identity.ts';
import { CORS, b64url, clean, esc, ipHash, json, one, page, parseCookies, q, randomId, sameOrigin, sha256, sqlTime } from './util.ts';

export const SCOPE_LIST = Object.keys(SCOPES);
const REQ_COOKIE = '__Host-kit_oauthreq';
const ACCESS_PREFIX = 'mcpat_';
const REFRESH_PREFIX = 'mcprt_';
const HEX64 = /^[0-9a-f]{64}$/;

const oauthError = (error: string, description: string, status = 400) => json({ error, error_description: description }, status, { pragma: 'no-cache' });
const preflight = () => new Response(null, { status: 204, headers: { ...CORS, 'access-control-max-age': '86400' } });

// ---------------------------------------------------------------- metadata
export const resourceUrl = (url: URL) => `${url.origin}/mcp`;

export function protectedResource(url: URL) {
  return json({ resource: resourceUrl(url), authorization_servers: [url.origin], scopes_supported: SCOPE_LIST, bearer_methods_supported: ['header'],
    resource_name: SERVER.title, resource_documentation: `${url.origin}/` }, 200, { 'cache-control': 'public, max-age=3600' });
}

export function authServer(url: URL) {
  const o = url.origin;
  return json({
    issuer: o, authorization_endpoint: `${o}/oauth/authorize`, token_endpoint: `${o}/oauth/token`, registration_endpoint: `${o}/oauth/register`,
    revocation_endpoint: `${o}/oauth/revoke`, response_types_supported: ['code'], response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'], code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    revocation_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    scopes_supported: SCOPE_LIST, service_documentation: `${o}/`, authorization_response_iss_parameter_supported: true,
  }, 200, { 'cache-control': 'public, max-age=3600' });
}

/** 401 for /mcp without a valid token: WWW-Authenticate points the assistant at the metadata, which starts OAuth. */
export function unauthorized(url: URL, description: string) {
  return json({ jsonrpc: '2.0', id: null, error: { code: -32001, message: description } }, 401, {
    'www-authenticate': `Bearer realm="mcp", resource_metadata="${url.origin}/.well-known/oauth-protected-resource", scope="${SCOPE_LIST.join(' ')}"`,
  });
}

// ---------------------------------------------------------------- registration
/** https anywhere; http only on loopback (native apps); custom schemes for desktop apps; never fragments. */
export function okRedirect(u: string): boolean {
  try {
    const x = new URL(u);
    if (x.hash) return false;
    if (x.protocol === 'https:') return true;
    if (x.protocol === 'http:') return ['localhost', '127.0.0.1', '[::1]'].includes(x.hostname);
    return /^[a-z][a-z0-9+.-]{2,}:$/.test(x.protocol) && !['javascript:', 'data:', 'file:', 'vbscript:', 'blob:'].includes(x.protocol);
  } catch {
    return false;
  }
}

interface Client { id: string; name: string; redirect_uris: string; secret_hash: string | null }
const clientBy = (env: Env, id: unknown) => (/^client_[0-9a-f]{32}$/.test(String(id || '')) ? one<Client>(env, 'SELECT * FROM oauth_clients WHERE id = ?', id) : Promise.resolve(null));

export async function register(request: Request, env: Env) {
  if (request.method === 'OPTIONS') return preflight();
  if (request.method !== 'POST') return oauthError('invalid_request', 'POST client metadata as JSON.', 405);
  let m: Record<string, unknown>;
  try { m = JSON.parse((await request.text()).slice(0, 16000)); } catch { return oauthError('invalid_client_metadata', 'The body must be JSON.'); }
  if (!m || typeof m !== 'object') return oauthError('invalid_client_metadata', 'The body must be a JSON object.');
  const uris = Array.isArray(m.redirect_uris) ? m.redirect_uris.map(String) : [];
  if (!uris.length || uris.length > 10 || !uris.every((u) => u.length <= 500 && okRedirect(u))) {
    return oauthError('invalid_redirect_uri', 'redirect_uris must be 1 to 10 https URLs, loopback http URLs or app schemes, without fragments.');
  }
  const method = String(m.token_endpoint_auth_method || 'none');
  if (!['none', 'client_secret_post', 'client_secret_basic'].includes(method)) return oauthError('invalid_client_metadata', 'token_endpoint_auth_method must be none, client_secret_post or client_secret_basic.');
  if (m.grant_types && !(Array.isArray(m.grant_types) && m.grant_types.every((g) => ['authorization_code', 'refresh_token'].includes(g)))) {
    return oauthError('invalid_client_metadata', 'Only authorization_code and refresh_token grants are supported.');
  }
  const hash = await ipHash(request, env);
  const recent = await one<{ n: number }>(env, 'SELECT COUNT(*) AS n FROM oauth_clients WHERE ip_hash = ? AND created_at > ?', hash, sqlTime(Date.now() - 3600e3));
  if ((recent?.n || 0) >= REGISTRATIONS_PER_HOUR) return oauthError('invalid_request', 'Too many registrations from this network. Try again later.', 429);
  const id = `client_${randomId(16)}`;
  const secret = method === 'none' ? null : randomId(32);
  const name = clean(m.client_name, 100) || 'AI assistant';
  const uri = typeof m.client_uri === 'string' && okRedirect(m.client_uri) ? m.client_uri.slice(0, 300) : null;
  await q(env, 'INSERT INTO oauth_clients (id, name, redirect_uris, secret_hash, uri, ip_hash) VALUES (?, ?, ?, ?, ?, ?)',
    id, name, JSON.stringify(uris), secret ? await sha256(secret) : null, uri, hash).run();
  return json({ client_id: id, client_id_issued_at: Math.floor(Date.now() / 1000), client_name: name, redirect_uris: uris, grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'], token_endpoint_auth_method: method, ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}) }, 201);
}

// ---------------------------------------------------------------- authorize, sign-in, consent
const errorPage = (msg: string, status = 400) => page('Can’t connect', `<h1>This connection can’t go ahead</h1><p>${esc(msg)}</p><p>Go back to your assistant and try connecting again.</p>`, status);
const back = (redirectUri: string, params: Record<string, string | null | undefined>) => {
  const u = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) if (v != null) u.searchParams.set(k, v);
  return new Response(null, { status: 302, headers: { location: u.toString(), 'cache-control': 'no-store' } });
};
/** The form-action source that lets the consent form's redirect reach the assistant. */
const formTarget = (redirectUri: string) => { try { const u = new URL(redirectUri); return u.protocol === 'https:' || u.protocol === 'http:' ? u.origin : u.protocol; } catch { return ''; } };

interface Pending { redirect_uri: string; state: string | null; code_challenge: string; scopes: string[]; resource: string }

/** GET /oauth/authorize */
export async function authorize(request: Request, env: Env, url: URL) {
  const sp = url.searchParams;
  const client = await clientBy(env, sp.get('client_id'));
  if (!client) return errorPage('The assistant isn’t registered with this server (unknown client_id).');
  const redirectUri = sp.get('redirect_uri') || '';
  const uris: string[] = JSON.parse(client.redirect_uris);
  if (!uris.includes(redirectUri) && !(uris.length === 1 && !redirectUri)) return errorPage('The assistant asked to return to an address it didn’t register.');
  const ru = redirectUri || uris[0];
  const state = sp.get('state');
  const fail = (error: string, description: string) => back(ru, { error, error_description: description, state, iss: url.origin });
  if (sp.get('response_type') !== 'code') return fail('unsupported_response_type', 'response_type must be code.');
  const challenge = sp.get('code_challenge') || '';
  if (sp.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43,128}$/.test(challenge)) return fail('invalid_request', 'PKCE with code_challenge_method=S256 is required.');
  const asked = String(sp.get('scope') || SCOPE_LIST.join(' ')).split(/\s+/).filter(Boolean);
  const scopes = asked.filter((s) => SCOPES[s]);
  if (!scopes.includes('read')) scopes.unshift('read');
  // RFC 8707: a token is only for this server's /mcp.
  const resource = sp.get('resource');
  const target = resource ? resource.replace(/\/$/, '') : resourceUrl(url);
  if (target !== resourceUrl(url) && target !== url.origin) return fail('invalid_target', `resource must be ${resourceUrl(url)}.`);
  const browser = randomId(24);
  const id = randomId(16);
  const pending: Pending = { redirect_uri: ru, state, code_challenge: challenge, scopes, resource: resourceUrl(url) };
  await q(env, 'INSERT INTO oauth_requests (id, browser_hash, client_id, params, expires_at) VALUES (?, ?, ?, ?, ?)',
    id, await sha256(browser), client.id, JSON.stringify(pending), sqlTime(Date.now() + REQUEST_MINUTES * 60e3)).run();
  return new Response(null, { status: 302, headers: {
    location: `/oauth/continue?req=${id}`, 'cache-control': 'no-store',
    'set-cookie': `${REQ_COOKIE}=${browser}; Path=/; Max-Age=${REQUEST_MINUTES * 60}; HttpOnly; Secure; SameSite=Lax`,
  } });
}

/** The authorization request this browser started, or null: a link to /oauth/continue is useless in another browser. */
async function ownRequest(request: Request, env: Env, id: string | null) {
  if (!/^[0-9a-f]{32}$/.test(id || '')) return null;
  const cookie = parseCookies(request)[REQ_COOKIE];
  if (!cookie) return null;
  const r = await one<{ id: string; browser_hash: string; client_id: string; params: string }>(env, 'SELECT * FROM oauth_requests WHERE id = ? AND expires_at > ?', id, sqlTime(Date.now()));
  return r && r.browser_hash === (await sha256(cookie)) ? r : null;
}

/** GET|POST /oauth/continue?req= : sign in through the identity provider, then approve or deny. */
export async function continueAuth(request: Request, env: Env, url: URL, idp: IdentityProvider) {
  const id = url.searchParams.get('req');
  const r = await ownRequest(request, env, id);
  if (!r) return errorPage('This connection request has expired or was started in another browser.');
  const client = (await clientBy(env, r.client_id))!;
  const p: Pending = JSON.parse(r.params);
  const next = `/oauth/continue?req=${id}`;
  const user = await idp.currentUser(request, env, url);
  if (!user) {
    const login = idp.loginUrl(next, url);
    if (login) return new Response(null, { status: 302, headers: { location: login, 'cache-control': 'no-store' } });
    return errorPage(idp.name === 'none'
      ? 'Sign-in isn’t set up on this server yet, so only its public tools are available (at /public).'
      : 'You aren’t signed in. If this server uses Cloudflare Access, its administrator needs to protect /oauth/continue with it.', 401);
  }
  if (request.method === 'POST') {
    if (!sameOrigin(request)) return errorPage('This approval didn’t come from this page.', 403);
    const f = await request.formData();
    await q(env, 'DELETE FROM oauth_requests WHERE id = ?', r.id).run();
    if (f.get('decision') !== 'approve') return back(p.redirect_uri, { error: 'access_denied', error_description: 'The person declined.', state: p.state, iss: url.origin });
    const scopes = p.scopes.filter((s) => s === 'read' || (s === 'write' && f.get('write') === '1'));
    const grant = randomId(16);
    const code = randomId(32);
    await env.DB.batch([
      q(env, `INSERT INTO users (id, name, email, roles) VALUES (?, ?, ?, ?)
              ON CONFLICT(id) DO UPDATE SET name = excluded.name, email = excluded.email, roles = excluded.roles, updated_at = datetime('now')`,
        user.id, user.name, user.email || null, JSON.stringify(user.roles || [])),
      q(env, 'INSERT INTO oauth_grants (id, client_id, user_id, scopes) VALUES (?, ?, ?, ?)', grant, client.id, user.id, scopes.join(' ')),
      q(env, 'INSERT INTO oauth_codes (code_hash, grant_id, client_id, redirect_uri, code_challenge, resource, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
        await sha256(code), grant, client.id, p.redirect_uri, p.code_challenge, p.resource, sqlTime(Date.now() + CODE_SECONDS * 1000)),
    ]);
    const res = back(p.redirect_uri, { code, state: p.state, iss: url.origin });
    res.headers.append('set-cookie', `${REQ_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
    return res;
  }
  const host = (() => { try { return new URL(p.redirect_uri).host || new URL(p.redirect_uri).protocol; } catch { return ''; } })();
  const lower = (s: string) => s.charAt(0).toLowerCase() + s.slice(1);
  return page('Approve', `<p class="small">${esc(SERVER.title)}</p><h1>Allow ${esc(client.name)} to use your account?</h1>
<p>Signed in as <strong>${esc(user.name)}</strong>${user.email && user.email !== user.name ? ` (${esc(user.email)})` : ''}.</p>
<form method="post" action="${esc(next)}">
<p><strong>It will be able to:</strong></p><ul><li>${esc(SCOPES.read)}</li></ul>
${p.scopes.includes('write') ? `<p><label><input type="checkbox" name="write" value="1"> Also allow it to ${esc(lower(SCOPES.write))}</label></p>` : ''}
<p class="small">It acts as you, within your current permissions, and every tool call is recorded. After you choose, you return to ${esc(host)}. You can disconnect it at any time from your assistant, or by asking it to revoke the connection.</p>
<p><button type="submit" name="decision" value="approve">Allow</button> <button class="ghost" type="submit" name="decision" value="deny">Deny</button></p></form>`, 200, [formTarget(p.redirect_uri)]);
}

// ---------------------------------------------------------------- tokens
type Form = { get(k: string): File | string | null };

async function clientAuth(request: Request, env: Env, f: Form) {
  let id = f.get('client_id') as string | null;
  let secret = f.get('client_secret') as string | null;
  const h = request.headers.get('authorization') || '';
  if (h.startsWith('Basic ')) {
    try { const [a, b] = atob(h.slice(6)).split(':'); id = decodeURIComponent(a); secret = decodeURIComponent(b || ''); } catch { return null; }
  }
  const c = await clientBy(env, id);
  if (!c) return null;
  if (c.secret_hash && (!secret || (await sha256(secret)) !== c.secret_hash)) return null;
  return c;
}

interface Grant { id: string; client_id: string; user_id: string; scopes: string }

async function issue(env: Env, grant: Grant, clientId: string) {
  const access = randomId(32), refresh = randomId(32);
  await env.DB.batch([
    q(env, "INSERT INTO oauth_tokens (token_hash, kind, grant_id, client_id, expires_at) VALUES (?, 'access', ?, ?, ?)", await sha256(access), grant.id, clientId, sqlTime(Date.now() + ACCESS_SECONDS * 1000)),
    q(env, "INSERT INTO oauth_tokens (token_hash, kind, grant_id, client_id, expires_at) VALUES (?, 'refresh', ?, ?, ?)", await sha256(refresh), grant.id, clientId, sqlTime(Date.now() + REFRESH_DAYS * 864e5)),
  ]);
  return json({ access_token: `${ACCESS_PREFIX}${access}`, token_type: 'Bearer', expires_in: ACCESS_SECONDS, refresh_token: `${REFRESH_PREFIX}${refresh}`, scope: grant.scopes }, 200, { pragma: 'no-cache' });
}

async function readForm(request: Request): Promise<Form | null> {
  const ct = request.headers.get('content-type') || '';
  if (ct.includes('application/json')) {
    const j = await request.json().catch(() => null);
    if (!j || typeof j !== 'object') return null;
    const m = new Map(Object.entries(j).map(([k, v]) => [k, String(v)]));
    return { get: (k) => m.get(k) ?? null };
  }
  return request.formData().catch(() => null);
}

/** POST /oauth/token */
export async function token(request: Request, env: Env) {
  if (request.method === 'OPTIONS') return preflight();
  if (request.method !== 'POST') return oauthError('invalid_request', 'POST form-encoded parameters.', 405);
  const f = await readForm(request);
  if (!f) return oauthError('invalid_request', 'Send application/x-www-form-urlencoded parameters.');
  const client = await clientAuth(request, env, f);
  if (!client) return oauthError('invalid_client', 'Unknown client, or wrong client secret.', 401);
  const type = f.get('grant_type');
  if (type === 'authorization_code') {
    const code = String(f.get('code') || '');
    const row = HEX64.test(code) ? await one<{ code_hash: string; grant_id: string; client_id: string; redirect_uri: string; code_challenge: string; expires_at: string; used_at: string | null }>(env, 'SELECT * FROM oauth_codes WHERE code_hash = ?', await sha256(code)) : null;
    if (!row || row.client_id !== client.id) return oauthError('invalid_grant', 'Unknown authorization code.');
    if (row.used_at) { await revokeGrant(env, row.grant_id, 'code_reuse'); return oauthError('invalid_grant', 'This code was already used; the connection has been ended for safety.'); }
    await q(env, "UPDATE oauth_codes SET used_at = datetime('now') WHERE code_hash = ?", row.code_hash).run();
    if (row.expires_at <= sqlTime(Date.now())) return oauthError('invalid_grant', 'The authorization code has expired.');
    if (String(f.get('redirect_uri') || row.redirect_uri) !== row.redirect_uri) return oauthError('invalid_grant', 'redirect_uri doesn’t match the authorization request.');
    const verifier = String(f.get('code_verifier') || '');
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier) || b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))) !== row.code_challenge) {
      return oauthError('invalid_grant', 'PKCE verification failed.');
    }
    const grant = await one<Grant>(env, 'SELECT * FROM oauth_grants WHERE id = ? AND revoked_at IS NULL', row.grant_id);
    if (!grant) return oauthError('invalid_grant', 'This connection was revoked.');
    return issue(env, grant, client.id);
  }
  if (type === 'refresh_token') {
    const raw = String(f.get('refresh_token') || '').replace(REFRESH_PREFIX, '');
    const row = HEX64.test(raw) ? await one<{ token_hash: string; grant_id: string; client_id: string; expires_at: string; used_at: string | null }>(env, "SELECT * FROM oauth_tokens WHERE token_hash = ? AND kind = 'refresh'", await sha256(raw)) : null;
    if (!row || row.client_id !== client.id) return oauthError('invalid_grant', 'Unknown refresh token.');
    if (row.used_at) { await revokeGrant(env, row.grant_id, 'refresh_reuse'); return oauthError('invalid_grant', 'This refresh token was already used; the connection has been ended for safety. Connect again.'); }
    if (row.expires_at <= sqlTime(Date.now())) return oauthError('invalid_grant', 'The refresh token has expired. Connect again.');
    const grant = await one<Grant>(env, 'SELECT * FROM oauth_grants WHERE id = ? AND revoked_at IS NULL', row.grant_id);
    if (!grant) return oauthError('invalid_grant', 'This connection was revoked.');
    // Rotation: the used refresh token is kept (marked) so a second use is recognised as theft, not just unknown.
    await q(env, "UPDATE oauth_tokens SET used_at = datetime('now') WHERE token_hash = ?", row.token_hash).run();
    await q(env, "DELETE FROM oauth_tokens WHERE grant_id = ? AND kind = 'access'", grant.id).run();
    return issue(env, grant, client.id);
  }
  return oauthError('unsupported_grant_type', 'grant_type must be authorization_code or refresh_token.');
}

/** End a connection: the grant is marked revoked and every token it issued stops working. */
export async function revokeGrant(env: Env, grantId: string, by: string) {
  await env.DB.batch([
    q(env, "UPDATE oauth_grants SET revoked_at = datetime('now'), revoked_by = ? WHERE id = ? AND revoked_at IS NULL", by.slice(0, 80), grantId),
    q(env, "DELETE FROM oauth_tokens WHERE grant_id = ? AND kind = 'access'", grantId),
    q(env, "UPDATE oauth_tokens SET used_at = COALESCE(used_at, datetime('now')) WHERE grant_id = ? AND kind = 'refresh'", grantId),
  ]);
}

/** POST /oauth/revoke: revoking either token ends the whole connection. Always 200 for a known client, as RFC 7009 asks. */
export async function revoke(request: Request, env: Env) {
  if (request.method === 'OPTIONS') return preflight();
  if (request.method !== 'POST') return oauthError('invalid_request', 'POST form-encoded parameters.', 405);
  const f = await readForm(request);
  const client = f && (await clientAuth(request, env, f));
  if (!f || !client) return oauthError('invalid_client', 'Unknown client.', 401);
  const raw = String(f.get('token') || '').replace(ACCESS_PREFIX, '').replace(REFRESH_PREFIX, '');
  if (HEX64.test(raw)) {
    const row = await one<{ grant_id: string; client_id: string }>(env, 'SELECT grant_id, client_id FROM oauth_tokens WHERE token_hash = ?', await sha256(raw));
    if (row && row.client_id === client.id) await revokeGrant(env, row.grant_id, 'client');
  }
  return json({});
}

// ---------------------------------------------------------------- who is calling
export interface Caller { grant: Grant; scopes: Set<string>; user: User }

/**
 * The person behind a bearer token, re-checked now: the token must be live, the grant not revoked, and the person
 * still enabled (or still known to the identity provider, if it re-checks). Disabling someone stops them at once.
 */
export async function authenticate(request: Request, env: Env, idp: IdentityProvider): Promise<Caller | { error: 'missing' | 'invalid_token' }> {
  const h = request.headers.get('authorization') || '';
  const m = h.match(new RegExp(`^Bearer\\s+${ACCESS_PREFIX}([0-9a-f]{64})$`));
  if (!m) return { error: h ? 'invalid_token' : 'missing' };
  const row = await one<Grant & { expires_at: string; last_used_at: string | null }>(env,
    `SELECT t.expires_at, g.* FROM oauth_tokens t JOIN oauth_grants g ON g.id = t.grant_id
     WHERE t.token_hash = ? AND t.kind = 'access' AND g.revoked_at IS NULL`, await sha256(m[1]));
  if (!row || row.expires_at <= sqlTime(Date.now())) return { error: 'invalid_token' };
  let user: User | null;
  if (idp.lookupUser) user = await idp.lookupUser(row.user_id, env);
  else {
    const u = await one<{ id: string; name: string; email: string | null; roles: string }>(env, 'SELECT * FROM users WHERE id = ? AND disabled_at IS NULL', row.user_id);
    user = u ? { id: u.id, name: u.name, email: u.email, roles: JSON.parse(u.roles) } : null;
  }
  if (!user) return { error: 'invalid_token' };
  if (!row.last_used_at || row.last_used_at < sqlTime(Date.now() - 300e3)) await q(env, "UPDATE oauth_grants SET last_used_at = datetime('now') WHERE id = ?", row.id).run();
  const grant: Grant = { id: row.id, client_id: row.client_id, user_id: row.user_id, scopes: row.scopes };
  return { grant, scopes: new Set(grant.scopes.split(' ')), user };
}

/** Daily (cron): drop expired requests, codes, tokens and sessions, and tool-call records past AUDIT_DAYS. */
export async function daily(env: Env) {
  const now = sqlTime(Date.now());
  const dayAgo = sqlTime(Date.now() - 864e5);
  await env.DB.batch([
    q(env, 'DELETE FROM oauth_requests WHERE expires_at < ?', now),
    q(env, 'DELETE FROM oauth_codes WHERE expires_at < ?', dayAgo),
    q(env, 'DELETE FROM oauth_tokens WHERE expires_at < ?', now),
    q(env, 'DELETE FROM dev_sessions WHERE expires_at < ?', now),
    q(env, 'DELETE FROM tool_calls WHERE created_at < ?', sqlTime(Date.now() - AUDIT_DAYS * 864e5)),
  ]);
}
