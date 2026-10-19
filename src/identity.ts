/**
 * @file Who is approving a connection.
 *
 * The OAuth server (`oauth.ts`) never checks a password. It asks an {@link IdentityProvider} who is signed in in this
 * browser, and the provider uses whatever sign-in the organisation already has, with its two-step verification and
 * its rules. This keeps the kit out of the business of storing credentials, and it means removing someone from the
 * real directory also stops them here (immediately if the provider implements `lookupUser`, otherwise within
 * `GRANT_MAX_DAYS`).
 *
 * Three providers ship with the kit:
 *
 * - {@link accessProvider}: Cloudflare Access in front of `/oauth/continue`. It verifies the
 *   `Cf-Access-Jwt-Assertion` JWT: RS256 only, the key chosen by `kid` from the team's JWKS, then audience, issuer,
 *   expiry and not-before. This is the production choice.
 * - {@link devProvider}: a name-only sign-in for `wrangler dev`. It is on only when `DEV_LOGIN=1` **and** the
 *   hostname is `localhost` or `127.0.0.1`, so a stray setting in production does nothing.
 * - {@link noProvider}: nothing is configured. `/public` works, and connecting to `/mcp` explains what to set up.
 *
 * To use your own sign-in (Auth0, Okta, Clerk, your app's session cookie), implement `IdentityProvider` and return it
 * from {@link providerFor}. The README section "Plugging in your sign-in" shows how.
 */
import type { Env } from './env.ts';
import {
  b64urlDecode,
  clean,
  esc,
  one,
  page,
  parseCookies,
  q,
  randomId,
  readUrlEncoded,
  safeNext,
  sameOrigin,
  sha256,
  sqlTime,
} from './util.ts';

/** A signed-in person, as the identity provider describes them. */
export interface User {
  /**
   * A stable, provider-scoped identifier such as `access:<sub>` or `dev:<name>`. Grants and audit records point at it.
   * Prefix it with the provider's name, so two providers can never give two different people the same id.
   */
  id: string;
  /** A display name, shown on the consent screen and sent to the assistant in `instructions`. */
  name: string;
  email?: string | null;
  /** Roles that tools' `access` rules can test, e.g. `admin`. */
  roles: string[];
}

/** A sign-in source. Return it from {@link providerFor} to put it in use. */
export interface IdentityProvider {
  /** A short name for logs and error pages. `'none'` is reserved for {@link noProvider}. */
  name: string;
  /**
   * The person signed in in this browser, or null. Called on the consent screen, both when it is shown (GET) and when
   * it is answered (POST), so the decision is always made by whoever is signed in at that moment.
   */
  currentUser(request: Request, env: Env, url: URL): Promise<User | null>;
  /**
   * Where to send someone who isn't signed in, or null if this provider has no sign-in page of its own.
   *
   * @param next - A path on this site to return to afterwards. It is already safe to use as a redirect target.
   */
  loginUrl(next: string, url: URL): string | null;
  /** Routes the provider serves itself (a login form, a callback), or null to let routing continue. */
  routes?(request: Request, env: Env, url: URL): Promise<Response | null>;
  /**
   * Optional: re-check a person on every tool call and every token refresh (still employed? still allowed?). Return
   * null to end all of their connections at once. Without it, the `users` table decides, through `users.disabled_at`.
   */
  lookupUser?(id: string, env: Env): Promise<User | null>;
}

/**
 * Picks the identity provider from the environment. When both are configured, Access wins over the development
 * sign-in, so a leftover `DEV_LOGIN=1` can't take over from a real setup.
 */
export function providerFor(env: Env): IdentityProvider {
  if (env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD) return accessProvider;
  if (env.DEV_LOGIN === '1') return devProvider;
  return noProvider;
}

/** No sign-in configured: nobody can approve a connection, so only `/public` is useful. */
export const noProvider: IdentityProvider = {
  name: 'none',
  currentUser: async () => null,
  loginUrl: () => null,
};

/** Parses a `users.roles` value (a JSON array of strings). Anything else counts as no roles. */
const parseRoles = (raw: string): string[] => {
  try {
    const v: unknown = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((r): r is string => typeof r === 'string') : [];
  } catch {
    return [];
  }
};

/**
 * The person behind a grant as they are **now**, or null if they may no longer use it.
 *
 * Called on every authenticated MCP request and before every token is issued. A provider's `lookupUser`, if it has
 * one, has the final say. Otherwise the `users` table does, and setting `disabled_at` there stops someone's
 * assistants on their next request.
 */
export async function resolveUser(id: string, env: Env, idp: IdentityProvider): Promise<User | null> {
  if (idp.lookupUser) return idp.lookupUser(id, env);
  const u = await one<{ id: string; name: string; email: string | null; roles: string }>(
    env,
    'SELECT id, name, email, roles FROM users WHERE id = ? AND disabled_at IS NULL',
    id,
  );
  return u ? { id: u.id, name: u.name, email: u.email, roles: parseRoles(u.roles) } : null;
}

// ---------------------------------------------------------------- Cloudflare Access
type Jwk = JsonWebKey & { kid?: string };
/** The team's signing keys, cached per isolate. `at` is the time of the last successful fetch. */
let jwksCache: { domain: string; at: number; keys: Jwk[] } | null = null;
/** The time of the last fetch attempt, successful or not. Used to throttle refetches. */
let jwksTried = 0;
/** How long fetched keys are trusted before they are fetched again. */
const JWKS_SECONDS = 600;
/**
 * The shortest time between fetches when a token names an unknown `kid` or the last fetch failed. Access rotates its
 * keys, so an unknown `kid` is worth one refetch. Without this throttle, though, a stream of tokens with random `kid`s,
 * or an Access outage, would turn every sign-in attempt into an outbound request.
 */
const JWKS_REFETCH_SECONDS = 30;
/** How long to wait for the JWKS before giving up. A hung fetch would otherwise hold the sign-in request open. */
const JWKS_TIMEOUT_MS = 5000;
/** Allowed clock difference between Access and this Worker when checking `exp` and `nbf` (RFC 7519 §4.1.4). */
const SKEW_SECONDS = 60;

/**
 * The JWK with this `kid` from the team's JWKS (`https://<team>/cdn-cgi/access/certs`), fetching or refetching as the
 * cache and throttle allow.
 *
 * @throws If the fetch fails and there are no cached keys to fall back on. `verifyAccessJwt` catches this.
 */
async function accessKey(domain: string, kid: string): Promise<Jwk | null> {
  const now = Date.now();
  const cached = jwksCache && jwksCache.domain === domain ? jwksCache : null;
  const stale = !cached || now - cached.at >= JWKS_SECONDS * 1000;
  const unknownKid = !!cached && !cached.keys.some((k) => k.kid === kid);
  if ((stale || unknownKid) && now - jwksTried >= JWKS_REFETCH_SECONDS * 1000) {
    jwksTried = now;
    try {
      const res = await fetch(`https://${domain}/cdn-cgi/access/certs`, {
        signal: AbortSignal.timeout(JWKS_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`Access JWKS: HTTP ${res.status}`);
      const body = await res.json<{ keys?: Jwk[] }>();
      jwksCache = { domain, at: Date.now(), keys: Array.isArray(body.keys) ? body.keys : [] };
    } catch (e) {
      // Keep using stale keys through a short outage rather than locking everyone out. Keys are only replaced by a
      // successful fetch, so a failure can't remove a key that has been revoked.
      if (!cached) throw e;
      console.error(JSON.stringify({ msg: 'Access JWKS refetch failed; using cached keys', err: String(e) }));
    }
  }
  return (jwksCache?.domain === domain ? jwksCache.keys : []).find((k) => k.kid === kid) ?? null;
}

/** For tests: forget the cached keys and the refetch throttle. */
export const resetAccessKeys = (): void => {
  jwksCache = null;
  jwksTried = 0;
};

const decodeJson = (part: string): unknown => JSON.parse(new TextDecoder().decode(b64urlDecode(part)));
const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/**
 * Verifies a Cloudflare Access JWT and returns its claims, or null if it isn't valid for this application.
 *
 * Checks, in order:
 *
 * 1. **The algorithm is pinned to RS256.** `alg` comes from the token and the attacker controls the token, so the
 *    verifier never lets it choose: `none`, and HS256 signed with the public key (algorithm confusion, RFC 8725
 *    §2.1 and §3.1), are both refused.
 * 2. **The key** is chosen by `kid` from the team's JWKS and imported as an RS256 key, whatever the JWK itself says.
 * 3. **The signature** over `header.payload` is verified before any claim is trusted.
 * 4. **The claims:** `aud` contains `ACCESS_AUD` (this Access application, not another app of the same team), `iss`
 *    is the team domain, `exp` hasn't passed and `nbf` has (both with {@link SKEW_SECONDS} of leeway), and `sub` is
 *    present.
 *
 * Never throws. Every failure, including network errors fetching the keys, is a null.
 *
 * @param now - Milliseconds since the epoch. Overridable for tests.
 */
export async function verifyAccessJwt(
  token: string,
  env: Env,
  now = Date.now(),
): Promise<Record<string, unknown> | null> {
  const domain = String(env.ACCESS_TEAM_DOMAIN || '')
    .replace(/^https:\/\//, '')
    .replace(/\/+$/, '');
  const parts = token.split('.');
  if (!domain || !env.ACCESS_AUD || parts.length !== 3) return null;
  try {
    const header = decodeJson(parts[0]);
    if (!isRecord(header) || header.alg !== 'RS256' || typeof header.kid !== 'string') return null;
    const jwk = await accessKey(domain, header.kid);
    if (!jwk || jwk.kty !== 'RSA') return null;
    const key = await crypto.subtle.importKey(
      'jwk',
      { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    const ok = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      b64urlDecode(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
    if (!ok) return null;
    const claims = decodeJson(parts[1]);
    if (!isRecord(claims)) return null;
    const aud: unknown[] = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
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

/** Roles under Access: `admin` if the email is in `ADMIN_EMAILS` (case-insensitive), otherwise none. */
const accessRoles = (email: string | null | undefined, env: Env): string[] => {
  const admins = String(env.ADMIN_EMAILS || '')
    .toLowerCase()
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return email && admins.includes(email.toLowerCase()) ? ['admin'] : [];
};

/**
 * Cloudflare Access. Put an Access application in front of `/oauth/continue` (and only that path: the OAuth and MCP
 * endpoints are called by assistants, which can't pass an Access login).
 */
export const accessProvider: IdentityProvider = {
  name: 'cloudflare-access',
  async currentUser(request, env) {
    // Access adds the header on every request it lets through. The cookie is the fallback for a request that reaches
    // the Worker by another route on the same host.
    const token = request.headers.get('cf-access-jwt-assertion') || parseCookies(request).CF_Authorization;
    if (!token) return null;
    const c = await verifyAccessJwt(token, env);
    if (!c) return null;
    const sub = c.sub as string; // verifyAccessJwt guarantees a non-empty string
    const email = typeof c.email === 'string' ? c.email.toLowerCase() : null;
    return { id: `access:${sub}`, name: email || sub, email, roles: accessRoles(email, env) };
  },
  // On every tool call and refresh: the person must not be disabled in the users table, and their roles follow
  // ADMIN_EMAILS as it is now, not as it was when they connected. Access itself can't be asked here: it only vouches
  // for a browser that is passing through it, so GRANT_MAX_DAYS bounds how long a removal from Access goes unnoticed.
  async lookupUser(id, env) {
    const u = await one<{ id: string; name: string; email: string | null }>(
      env,
      'SELECT id, name, email FROM users WHERE id = ? AND disabled_at IS NULL',
      id,
    );
    return u ? { id: u.id, name: u.name, email: u.email, roles: accessRoles(u.email, env) } : null;
  },
  // Access protects /oauth/continue itself, so a request that reaches the Worker there without a token means Access
  // isn't set up on that path. There is nowhere useful to send the person, and the error page says what's missing.
  loginUrl: () => null,
};

// ---------------------------------------------------------------- development sign-in
/** `__Host-`: Secure, Path=/ and no Domain, so another subdomain can't plant or read it (RFC 6265bis §4.1.3.2). */
const DEV_COOKIE = '__Host-kit_dev';
const DEV_HOURS = 12;
const MAX_FORM = 4 * 1024;
const devOn = (env: Env, url: URL) => env.DEV_LOGIN === '1' && ['localhost', '127.0.0.1'].includes(url.hostname);
const clearDevCookie = `${DEV_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;

/**
 * Name-only sign-in for local development. Anyone can claim any name, including the `admin` role, so it exists only
 * on localhost. Sessions are stored hashed in `dev_sessions` (`users.disabled_at` still applies), which keeps the
 * code path the same as a real provider's.
 */
export const devProvider: IdentityProvider = {
  name: 'dev',
  async currentUser(request, env, url) {
    if (!devOn(env, url)) return null;
    const token = parseCookies(request)[DEV_COOKIE];
    if (!token || !/^[0-9a-f]{64}$/.test(token)) return null;
    const row = await one<{ id: string; name: string; email: string | null; roles: string }>(
      env,
      `SELECT u.id, u.name, u.email, u.roles FROM dev_sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled_at IS NULL`,
      await sha256(token),
      sqlTime(Date.now()),
    );
    return row ? { id: row.id, name: row.name, email: row.email, roles: parseRoles(row.roles) } : null;
  },
  loginUrl: (next) => `/dev/login?next=${encodeURIComponent(next)}`,
  async routes(request, env, url) {
    if (url.pathname !== '/dev/login' && url.pathname !== '/dev/logout') return null;
    // A 404 rather than a 403 off localhost: a production host shouldn't even reveal that the route exists.
    if (!devOn(env, url)) return new Response('Not found', { status: 404 });
    const next = safeNext(url.searchParams.get('next'));
    if (url.pathname === '/dev/logout') {
      // End the session on the server too. Clearing the cookie alone would leave a token that still works.
      const token = parseCookies(request)[DEV_COOKIE];
      if (token) await q(env, 'DELETE FROM dev_sessions WHERE token_hash = ?', await sha256(token)).run();
      return new Response(null, { status: 302, headers: { location: '/', 'set-cookie': clearDevCookie } });
    }
    if (request.method === 'POST') {
      if (!sameOrigin(request)) return page('Sign in', '<h1>That sign-in didn’t come from this page</h1>', 403);
      const f = await readUrlEncoded(request, MAX_FORM);
      if (!f) return page('Sign in', '<h1>That form was too large</h1>', 413);
      const name = clean(f.get('name'), 60);
      if (!name)
        return page(
          'Sign in',
          `<h1>Enter a name</h1><p><a href="/dev/login?next=${esc(encodeURIComponent(next))}">Back</a></p>`,
          400,
        );
      const id = `dev:${name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
      const roles = f.get('admin') === '1' ? ['admin'] : [];
      const token = randomId(32);
      await env.DB.batch([
        q(
          env,
          `INSERT INTO users (id, name, roles) VALUES (?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET name = excluded.name, roles = excluded.roles, updated_at = datetime('now')`,
          id,
          name,
          JSON.stringify(roles),
        ),
        q(
          env,
          'INSERT INTO dev_sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)',
          await sha256(token),
          id,
          sqlTime(Date.now() + DEV_HOURS * 3600e3),
        ),
      ]);
      return new Response(null, {
        status: 302,
        headers: {
          location: next,
          'set-cookie': `${DEV_COOKIE}=${token}; Path=/; Max-Age=${DEV_HOURS * 3600}; HttpOnly; Secure; SameSite=Lax`,
          'cache-control': 'no-store',
        },
      });
    }
    return page(
      'Sign in (development)',
      `<h1>Development sign-in</h1>
<p class="small">This form exists only on localhost with <code>DEV_LOGIN=1</code>. It asks for a name and nothing else, so never turn it on anywhere real.</p>
<form method="post" action="/dev/login?next=${esc(encodeURIComponent(next))}">
<p><label>Name <input type="text" name="name" required maxlength="60" autofocus></label></p>
<p><label><input type="checkbox" name="admin" value="1"> Give this person the admin role</label></p>
<p><button type="submit">Sign in</button></p></form>`,
    );
  },
};
