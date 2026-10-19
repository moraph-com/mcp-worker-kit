// Who is approving a connection. The OAuth server never checks a password: it asks an identity provider who the
// person in this browser is, and the provider uses whatever sign-in you already have.
//
//   accessProvider   Cloudflare Access in front of /oauth/continue: verifies the Cf-Access-Jwt-Assertion JWT
//                    (RS256, keys from the team's JWKS, audience, issuer, expiry). Production-ready. Roles come from
//                    ADMIN_EMAILS as it is now, on every call; someone removed from Access keeps no connection longer
//                    than GRANT_MAX_DAYS (config.ts), since only signing in again asks Access.
//   devProvider      name-only sign-in for `wrangler dev`: on only when DEV_LOGIN=1 AND the host is localhost.
//   noProvider       nothing configured: /public works; connecting to /mcp explains what to set up.
//
// To use your own (Auth0, Okta, Clerk, your app's session cookie), implement IdentityProvider and return it from
// providerFor(). README "Plugging in your sign-in".
import type { Env } from './env.ts';
import { b64urlDecode, clean, esc, one, page, parseCookies, q, randomId, safeNext, sameOrigin, sha256, sqlTime } from './util.ts';

export interface User {
  /** Stable and provider-scoped, e.g. "access:<sub>". Grants and audit records point at it. */
  id: string;
  name: string;
  email?: string | null;
  roles: string[];
}

export interface IdentityProvider {
  name: string;
  /** The person signed in in this browser, or null. Called on the consent screen. */
  currentUser(request: Request, env: Env, url: URL): Promise<User | null>;
  /** Where to send someone who isn't signed in (return to `next` afterwards), or null if this provider can't. */
  loginUrl(next: string, url: URL): string | null;
  /** Routes the provider serves itself (a login form, a callback), or null. */
  routes?(request: Request, env: Env, url: URL): Promise<Response | null>;
  /**
   * Optional: re-check a person on every tool call (still employed, still allowed). Return null to end their
   * connections. Without it, the users table decides (users.disabled_at).
   */
  lookupUser?(id: string, env: Env): Promise<User | null>;
}

export function providerFor(env: Env): IdentityProvider {
  if (env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD) return accessProvider;
  if (env.DEV_LOGIN === '1') return devProvider;
  return noProvider;
}

export const noProvider: IdentityProvider = {
  name: 'none',
  currentUser: async () => null,
  loginUrl: () => null,
};

// ---------------------------------------------------------------- Cloudflare Access
type Jwk = JsonWebKey & { kid?: string };
let jwksCache: { domain: string; at: number; keys: Jwk[] } | null = null;
const JWKS_SECONDS = 600;
/** An unknown kid refetches the keys (Access rotates them), but no more often than this, whatever tokens arrive. */
const JWKS_REFETCH_SECONDS = 30;
const SKEW_SECONDS = 60;

async function accessKeys(domain: string, kid: string): Promise<Jwk | null> {
  const age = jwksCache && jwksCache.domain === domain ? Date.now() - jwksCache.at : Infinity;
  if (age >= JWKS_SECONDS * 1000 || (!jwksCache!.keys.some((k) => k.kid === kid) && age >= JWKS_REFETCH_SECONDS * 1000)) {
    const res = await fetch(`https://${domain}/cdn-cgi/access/certs`);
    if (!res.ok) throw new Error(`Access JWKS: HTTP ${res.status}`);
    const body = (await res.json()) as { keys?: Jwk[] };
    jwksCache = { domain, at: Date.now(), keys: body.keys || [] };
  }
  return jwksCache!.keys.find((k) => k.kid === kid) || null;
}
/** For tests: forget the cached keys. */
export const resetAccessKeys = () => { jwksCache = null; };

/** The verified claims of a Cloudflare Access JWT, or null. */
export async function verifyAccessJwt(token: string, env: Env, now = Date.now()): Promise<Record<string, unknown> | null> {
  const domain = String(env.ACCESS_TEAM_DOMAIN || '').replace(/^https:\/\//, '').replace(/\/+$/, '');
  const parts = token.split('.');
  if (!domain || !env.ACCESS_AUD || parts.length !== 3) return null;
  try {
    const header = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0])));
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') return null;
    const jwk = await accessKeys(domain, header.kid);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlDecode(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
    if (!ok) return null;
    const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])));
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    const t = Math.floor(now / 1000);
    if (!aud.includes(env.ACCESS_AUD)) return null;
    if (claims.iss !== `https://${domain}`) return null;
    if (typeof claims.exp !== 'number' || claims.exp < t - SKEW_SECONDS) return null;
    if (typeof claims.nbf === 'number' && claims.nbf > t + SKEW_SECONDS) return null;
    if (typeof claims.sub !== 'string' || !claims.sub) return null;
    return claims;
  } catch {
    return null;
  }
}

const accessRoles = (email: string | null | undefined, env: Env) => {
  const admins = String(env.ADMIN_EMAILS || '').toLowerCase().split(',').map((s) => s.trim()).filter(Boolean);
  return email && admins.includes(email.toLowerCase()) ? ['admin'] : [];
};

export const accessProvider: IdentityProvider = {
  name: 'cloudflare-access',
  async currentUser(request, env) {
    const token = request.headers.get('cf-access-jwt-assertion') || parseCookies(request).CF_Authorization;
    if (!token) return null;
    const c = await verifyAccessJwt(token, env);
    if (!c) return null;
    const email = typeof c.email === 'string' ? c.email.toLowerCase() : null;
    return { id: `access:${c.sub}`, name: email || String(c.sub), email, roles: accessRoles(email, env) };
  },
  // Every tool call: the person must not be disabled here, and their roles follow ADMIN_EMAILS as it is now, not as
  // it was when they connected.
  async lookupUser(id, env) {
    const u = await one<{ id: string; name: string; email: string | null }>(env, 'SELECT id, name, email FROM users WHERE id = ? AND disabled_at IS NULL', id);
    return u ? { id: u.id, name: u.name, email: u.email, roles: accessRoles(u.email, env) } : null;
  },
  // Access protects /oauth/continue itself, so a request that reaches the Worker without a token means Access isn't
  // set up on that path. There's nowhere useful to send the person.
  loginUrl: () => null,
};

// ---------------------------------------------------------------- development sign-in
const DEV_COOKIE = '__Host-kit_dev';
const DEV_HOURS = 12;
const devOn = (env: Env, url: URL) => env.DEV_LOGIN === '1' && ['localhost', '127.0.0.1'].includes(url.hostname);

export const devProvider: IdentityProvider = {
  name: 'dev',
  async currentUser(request, env, url) {
    if (!devOn(env, url)) return null;
    const token = parseCookies(request)[DEV_COOKIE];
    if (!token || !/^[0-9a-f]{64}$/.test(token)) return null;
    const row = await one<{ id: string; name: string; email: string | null; roles: string }>(env,
      `SELECT u.id, u.name, u.email, u.roles FROM dev_sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled_at IS NULL`, await sha256(token), sqlTime(Date.now()));
    return row ? { id: row.id, name: row.name, email: row.email, roles: JSON.parse(row.roles) } : null;
  },
  loginUrl: (next) => `/dev/login?next=${encodeURIComponent(next)}`,
  async routes(request, env, url) {
    if (url.pathname !== '/dev/login' && url.pathname !== '/dev/logout') return null;
    if (!devOn(env, url)) return new Response('Not found', { status: 404 });
    const next = safeNext(url.searchParams.get('next'));
    if (url.pathname === '/dev/logout') {
      return new Response(null, { status: 302, headers: { location: '/', 'set-cookie': `${DEV_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax` } });
    }
    if (request.method === 'POST') {
      if (!sameOrigin(request)) return page('Sign in', '<h1>That sign-in didn’t come from this page</h1>', 403);
      const f = await request.formData();
      const name = clean(f.get('name'), 60);
      if (!name) return page('Sign in', `<h1>Enter a name</h1><p><a href="/dev/login?next=${esc(encodeURIComponent(next))}">Back</a></p>`, 400);
      const id = `dev:${name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
      const roles = f.get('admin') === '1' ? ['admin'] : [];
      const token = randomId(32);
      await env.DB.batch([
        q(env, `INSERT INTO users (id, name, roles) VALUES (?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET name = excluded.name, roles = excluded.roles, updated_at = datetime('now')`, id, name, JSON.stringify(roles)),
        q(env, 'INSERT INTO dev_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)', await sha256(token), id, sqlTime(Date.now() + DEV_HOURS * 3600e3)),
      ]);
      return new Response(null, { status: 302, headers: { location: next, 'set-cookie': `${DEV_COOKIE}=${token}; Path=/; Max-Age=${DEV_HOURS * 3600}; HttpOnly; Secure; SameSite=Lax`, 'cache-control': 'no-store' } });
    }
    return page('Sign in (development)', `<h1>Development sign-in</h1>
<p class="small">This form exists only on localhost with <code>DEV_LOGIN=1</code>. It asks for a name and nothing else, so never turn it on anywhere real.</p>
<form method="post" action="/dev/login?next=${esc(encodeURIComponent(next))}">
<p><label>Name <input type="text" name="name" required maxlength="60" autofocus></label></p>
<p><label><input type="checkbox" name="admin" value="1"> Give this person the admin role</label></p>
<p><button type="submit">Sign in</button></p></form>`);
  },
};
