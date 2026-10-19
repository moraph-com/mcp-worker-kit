/**
 * @file The OAuth 2.1 authorization server (`src/oauth.ts`): metadata, registration, the authorization-code flow with
 * PKCE, consent, refresh rotation and reuse detection, revocation, audience binding, lifetimes, races and clean-up.
 * Each security rule has a test showing what is now refused.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import worker from '../src/index.ts';
import type { IdentityProvider } from '../src/identity.ts';
import { continueAuth } from '../src/oauth.ts';
import {
  ORIGIN,
  REDIRECT,
  authorizeFlow,
  connect,
  exchange,
  form,
  mcp,
  pkce,
  registerClient,
  setup,
} from './helpers.ts';

describe('metadata', () => {
  it('describes the protected resource (RFC 9728)', async () => {
    const k = setup();
    const res = await k.call('/.well-known/oauth-protected-resource');
    const m = (await res.json()) as any;
    assert.equal(m.resource, `${ORIGIN}/mcp`);
    assert.deepEqual(m.authorization_servers, [ORIGIN]);
    assert.deepEqual(m.scopes_supported, ['read', 'write']);
  });

  it('describes the authorization server (RFC 8414): PKCE S256 only', async () => {
    const k = setup();
    const m = (await (await k.call('/.well-known/oauth-authorization-server')).json()) as any;
    assert.equal(m.issuer, ORIGIN);
    assert.equal(m.token_endpoint, `${ORIGIN}/oauth/token`);
    assert.equal(m.registration_endpoint, `${ORIGIN}/oauth/register`);
    assert.deepEqual(m.code_challenge_methods_supported, ['S256']);
    assert.deepEqual(m.grant_types_supported, ['authorization_code', 'refresh_token']);
  });

  it('answers /mcp without a token with 401 pointing at the metadata', async () => {
    const k = setup();
    const r = await mcp(k, '/mcp', 'tools/list');
    assert.equal(r.status, 401);
    assert.match(
      r.headers.get('www-authenticate')!,
      /resource_metadata="http:\/\/localhost:8787\/\.well-known\/oauth-protected-resource"/,
    );
  });
});

describe('dynamic client registration', () => {
  const bad = ['http://evil.example/cb', 'https://ok.example/cb#frag', 'javascript:alert(1)', 'not a url'];
  for (const uri of bad) {
    it(`refuses redirect URI ${uri}`, async () => {
      const k = setup();
      const res = await k.call('/oauth/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ redirect_uris: [uri] }),
      });
      assert.equal(res.status, 400);
      assert.equal(((await res.json()) as any).error, 'invalid_redirect_uri');
    });
  }

  it('accepts https, loopback http and app schemes', async () => {
    const k = setup();
    const c = await registerClient(k, {
      redirect_uris: [
        'https://a.example/cb',
        'http://127.0.0.1:33418/cb',
        'cursor://anysphere.cursor-retrieval/oauth/callback',
      ],
    });
    assert.match(c.client_id, /^client_[0-9a-f]{32}$/);
    assert.equal(c.client_secret, undefined);
  });

  it('issues a secret to confidential clients and stores only its hash', async () => {
    const k = setup();
    const c = await registerClient(k, { token_endpoint_auth_method: 'client_secret_post' });
    assert.ok(c.client_secret);
    const [row] = k.rows('SELECT secret_hash FROM oauth_clients');
    assert.notEqual(row.secret_hash, c.client_secret);
    assert.match(String(row.secret_hash), /^[0-9a-f]{64}$/);
  });

  it('rate-limits registrations per network', async () => {
    const k = setup();
    for (let i = 0; i < 30; i++) await registerClient(k);
    const res = await k.call('/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [REDIRECT] }),
    });
    assert.equal(res.status, 429);
  });
});

describe('authorization code with PKCE', () => {
  it('completes the full flow and stores only hashes', async () => {
    const k = setup();
    const t = await connect(k, { write: true });
    assert.match(t.access_token, /^mcpat_[0-9a-f]{64}$/);
    assert.match(t.refresh_token, /^mcprt_[0-9a-f]{64}$/);
    assert.equal(t.scope, 'read write');
    const stored = JSON.stringify(k.rows('SELECT * FROM oauth_tokens'));
    assert.ok(!stored.includes(t.access_token.slice(6)));
    assert.ok(!stored.includes(t.refresh_token.slice(6)));
    assert.equal((await mcp(k, '/mcp', 'ping', {}, t.access_token)).status, 200);
  });

  it('grants read only when the person leaves actions unticked', async () => {
    const k = setup();
    const t = await connect(k, { write: false });
    assert.equal(t.scope, 'read');
  });

  it('requires PKCE S256 on authorize', async () => {
    const k = setup();
    const c = await registerClient(k);
    const qs = new URLSearchParams({
      response_type: 'code',
      client_id: c.client_id,
      redirect_uri: REDIRECT,
      code_challenge: 'x'.repeat(43),
      code_challenge_method: 'plain',
    });
    const res = await k.call(`/oauth/authorize?${qs}`);
    assert.equal(res.status, 400);
    assert.match(await res.text(), /error=invalid_request/);
  });

  // RFC 6749 §4.1.2.1: with a bad redirect URI, nothing may be sent there, not even an error.
  it('refuses an unregistered redirect URI without redirecting there', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { challenge } = await pkce();
    const qs = new URLSearchParams({
      response_type: 'code',
      client_id: c.client_id,
      redirect_uri: 'https://evil.example/cb',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    const res = await k.call(`/oauth/authorize?${qs}`);
    assert.equal(res.status, 400);
    assert.equal(res.headers.get('location'), null);
  });

  it('refuses a token for another resource (RFC 8707)', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { challenge } = await pkce();
    const qs = new URLSearchParams({
      response_type: 'code',
      client_id: c.client_id,
      redirect_uri: REDIRECT,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      resource: 'https://other.example/mcp',
    });
    const res = await k.call(`/oauth/authorize?${qs}`);
    assert.equal(res.headers.get('location'), null);
    assert.match(await res.text(), /error=invalid_target/);
  });

  it('rejects the wrong code verifier', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { challenge } = await pkce();
    const code = (await authorizeFlow(k, c.client_id, challenge)).get('code')!;
    const other = await pkce();
    const res = await exchange(k, c.client_id, code, other.verifier);
    assert.equal(res.status, 400);
    assert.equal(((await res.json()) as any).error_description, 'PKCE verification failed.');
  });

  // RFC 6749 §4.1.2: a replayed code means it leaked, so every token issued from it is revoked too.
  it('revokes the grant when a code is used twice', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { verifier, challenge } = await pkce();
    const code = (await authorizeFlow(k, c.client_id, challenge)).get('code')!;
    const first = (await (await exchange(k, c.client_id, code, verifier)).json()) as any;
    assert.equal((await mcp(k, '/mcp', 'ping', {}, first.access_token)).status, 200);
    const again = await exchange(k, c.client_id, code, verifier);
    assert.equal(again.status, 400);
    assert.equal(
      (await mcp(k, '/mcp', 'ping', {}, first.access_token)).status,
      401,
      'tokens from the first exchange stop working',
    );
    assert.equal(k.rows('SELECT revoked_by FROM oauth_grants')[0].revoked_by, 'code_reuse');
  });

  it('rejects an expired code', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { verifier, challenge } = await pkce();
    const code = (await authorizeFlow(k, c.client_id, challenge)).get('code')!;
    k.db.sqlite.exec("UPDATE oauth_codes SET expires_at = '2000-01-01 00:00:00'");
    const res = await exchange(k, c.client_id, code, verifier);
    assert.equal(((await res.json()) as any).error_description, 'The authorization code has expired.');
  });

  it('sends access_denied back when the person declines', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { challenge } = await pkce();
    const back = await authorizeFlow(k, c.client_id, challenge, { decision: 'deny' });
    assert.equal(back.get('error'), 'access_denied');
    assert.equal(k.rows('SELECT * FROM oauth_grants').length, 0);
  });

  it('refuses a consent POST from another origin', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { challenge } = await pkce();
    const qs = new URLSearchParams({
      response_type: 'code',
      client_id: c.client_id,
      redirect_uri: REDIRECT,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    const a = await k.call(`/oauth/authorize?${qs}`);
    const reqCookie = a.headers.getSetCookie()[0].split(';')[0];
    const login = await k.call('/dev/login', {
      ...form({ name: 'Alice' }),
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: ORIGIN },
    });
    const cookie = `${reqCookie}; ${login.headers.getSetCookie()[0].split(';')[0]}`;
    const res = await k.call(a.headers.get('location')!, {
      ...form({ decision: 'approve' }),
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://evil.example', cookie },
    });
    assert.equal(res.status, 403);
  });

  it('serves the consent screen with a strict content security policy', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { challenge } = await pkce();
    const qs = new URLSearchParams({
      response_type: 'code',
      client_id: c.client_id,
      redirect_uri: REDIRECT,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    const a = await k.call(`/oauth/authorize?${qs}`);
    const login = await k.call('/dev/login', {
      ...form({ name: 'Alice' }),
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: ORIGIN },
    });
    const cookie = `${a.headers.getSetCookie()[0].split(';')[0]}; ${login.headers.getSetCookie()[0].split(';')[0]}`;
    const res = await k.call(a.headers.get('location')!, { headers: { cookie } });
    const csp = res.headers.get('content-security-policy')!;
    assert.match(csp, /default-src 'none'/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.match(csp, /form-action 'self' https:\/\/assistant\.example/);
    assert.ok(!csp.includes('unsafe-inline'));
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.equal(res.headers.get('cache-control'), 'no-store');
  });

  // Consent CSRF: a link to /oauth/continue sent to someone else must not let them approve the attacker's request.
  it('only continues in the browser that started the request', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { challenge } = await pkce();
    const qs = new URLSearchParams({
      response_type: 'code',
      client_id: c.client_id,
      redirect_uri: REDIRECT,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    const a = await k.call(`/oauth/authorize?${qs}`);
    const res = await k.call(a.headers.get('location')!);
    assert.equal(res.status, 400);
  });
});

describe('refresh tokens', () => {
  const refresh = (k: ReturnType<typeof setup>, clientId: string, token: string) =>
    k.call('/oauth/token', form({ grant_type: 'refresh_token', client_id: clientId, refresh_token: token }));

  it('rotates: a refresh gives a new pair and the old access token stops', async () => {
    const k = setup();
    const t = await connect(k);
    const res = await refresh(k, t.clientId, t.refresh_token);
    assert.equal(res.status, 200);
    const n = (await res.json()) as any;
    assert.notEqual(n.refresh_token, t.refresh_token);
    assert.equal((await mcp(k, '/mcp', 'ping', {}, n.access_token)).status, 200);
    assert.equal((await mcp(k, '/mcp', 'ping', {}, t.access_token)).status, 401);
  });

  // RFC 9700 §4.14.2: either the client or a thief holds a used token; ending the grant stops whichever is the thief.
  it('treats reuse of a rotated refresh token as theft and ends the connection', async () => {
    const k = setup();
    const t = await connect(k);
    const n = (await (await refresh(k, t.clientId, t.refresh_token)).json()) as any;
    const reuse = await refresh(k, t.clientId, t.refresh_token);
    assert.equal(reuse.status, 400);
    assert.equal((await mcp(k, '/mcp', 'ping', {}, n.access_token)).status, 401);
    assert.equal((await refresh(k, t.clientId, n.refresh_token)).status, 400);
    assert.equal(k.rows('SELECT revoked_by FROM oauth_grants')[0].revoked_by, 'refresh_reuse');
  });

  it("refuses another client's refresh token", async () => {
    const k = setup();
    const t = await connect(k);
    const other = await registerClient(k);
    assert.equal((await refresh(k, other.client_id, t.refresh_token)).status, 400);
  });
});

describe('revocation (RFC 7009)', () => {
  it('ends the whole connection from either token', async () => {
    const k = setup();
    const t = await connect(k);
    const res = await k.call('/oauth/revoke', form({ client_id: t.clientId, token: t.refresh_token }));
    assert.equal(res.status, 200);
    assert.equal((await mcp(k, '/mcp', 'ping', {}, t.access_token)).status, 401);
  });

  it('answers 200 for an unknown token', async () => {
    const k = setup();
    const t = await connect(k);
    const res = await k.call('/oauth/revoke', form({ client_id: t.clientId, token: `mcpat_${'0'.repeat(64)}` }));
    assert.equal(res.status, 200);
  });

  it('stops a disabled person at once', async () => {
    const k = setup();
    const t = await connect(k);
    k.db.sqlite.exec("UPDATE users SET disabled_at = datetime('now')");
    assert.equal((await mcp(k, '/mcp', 'ping', {}, t.access_token)).status, 401);
  });
});

describe('daily clean-up', () => {
  it('removes expired rows and old audit records', async () => {
    const k = setup();
    await connect(k);
    k.db.sqlite.exec("UPDATE oauth_tokens SET expires_at = '2000-01-01 00:00:00'");
    k.db.sqlite.exec("INSERT INTO tool_calls (tool, ok, ms, created_at) VALUES ('old', 1, 1, '2000-01-01 00:00:00')");
    await worker.scheduled({} as ScheduledController, k.env);
    assert.equal(k.rows('SELECT * FROM oauth_tokens').length, 0);
    assert.equal(k.rows("SELECT * FROM tool_calls WHERE tool = 'old'").length, 0);
  });
});

describe('races and lifetimes', () => {
  const refresh = (k: ReturnType<typeof setup>, clientId: string, token: string) =>
    k.call('/oauth/token', form({ grant_type: 'refresh_token', client_id: clientId, refresh_token: token }));

  // With simulated D1 latency both requests read the token as unused; only the conditional UPDATE can tell them apart.
  it('lets only one of two concurrent refreshes win, and ends the connection', async () => {
    const k = setup(undefined, { latency: true });
    const t = await connect(k);
    const both = await Promise.all([refresh(k, t.clientId, t.refresh_token), refresh(k, t.clientId, t.refresh_token)]);
    assert.deepEqual(both.map((r) => r.status).sort(), [200, 400]);
    const winner = (await both.find((r) => r.status === 200)!.json()) as any;
    assert.equal((await mcp(k, '/mcp', 'ping', {}, winner.access_token)).status, 401, 'the race counts as reuse');
    assert.equal(k.rows('SELECT revoked_by FROM oauth_grants')[0].revoked_by, 'refresh_reuse');
  });

  it('lets only one of two concurrent code exchanges win', async () => {
    const k = setup(undefined, { latency: true });
    const c = await registerClient(k);
    const { verifier, challenge } = await pkce();
    const code = (await authorizeFlow(k, c.client_id, challenge)).get('code')!;
    const both = await Promise.all([
      exchange(k, c.client_id, code, verifier),
      exchange(k, c.client_id, code, verifier),
    ]);
    const ok = both.filter((r) => r.status === 200);
    assert.ok(ok.length <= 1);
    for (const r of ok)
      assert.equal((await mcp(k, '/mcp', 'ping', {}, ((await r.json()) as any).access_token)).status, 401);
  });

  it('ends a connection at GRANT_MAX_DAYS however often it is refreshed', async () => {
    const k = setup();
    const t = await connect(k);
    k.db.sqlite.exec("UPDATE oauth_grants SET created_at = datetime('now', '-31 days')");
    assert.equal((await mcp(k, '/mcp', 'ping', {}, t.access_token)).status, 401);
    const res = await refresh(k, t.clientId, t.refresh_token);
    assert.equal(res.status, 400);
    assert.match(((await res.json()) as any).error_description, /time limit/);
  });

  // Ten minutes before the grant's end, a refresh must not hand out a full hour.
  it("never issues a token that outlives the grant's limit", async () => {
    const k = setup();
    const t = await connect(k);
    k.db.sqlite.exec("UPDATE oauth_grants SET created_at = datetime('now', '-30 days', '+10 minutes')");
    const n = (await (await refresh(k, t.clientId, t.refresh_token)).json()) as any;
    assert.ok(n.expires_in <= 600, `access token lasts ${n.expires_in}s`);
    const [{ latest }] = k.rows(
      "SELECT MAX(expires_at) AS latest FROM oauth_tokens WHERE kind = 'refresh' AND used_at IS NULL",
    );
    assert.ok(String(latest) <= String(k.rows("SELECT datetime(created_at, '+30 days') AS e FROM oauth_grants")[0].e));
  });
});

describe('spec details', () => {
  it('accepts a loopback redirect on any port (RFC 8252), but not another path or host', async () => {
    const k = setup();
    const c = await registerClient(k, { redirect_uris: ['http://127.0.0.1/callback'] });
    const { challenge } = await pkce();
    const go = (redirect_uri: string) =>
      k.call(
        `/oauth/authorize?${new URLSearchParams({ response_type: 'code', client_id: c.client_id, redirect_uri, code_challenge: challenge, code_challenge_method: 'S256' })}`,
      );
    assert.equal((await go('http://127.0.0.1:49152/callback')).status, 302);
    assert.equal((await go('http://127.0.0.1:49152/other')).status, 400);
    assert.equal((await go('http://localhost:49152/callback')).status, 400);
  });

  it('refuses a token request for another resource (RFC 8707)', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { verifier, challenge } = await pkce();
    const code = (await authorizeFlow(k, c.client_id, challenge)).get('code')!;
    const res = await k.call(
      '/oauth/token',
      form({
        grant_type: 'authorization_code',
        client_id: c.client_id,
        code,
        code_verifier: verifier,
        resource: 'https://other.example/mcp',
      }),
    );
    assert.equal(((await res.json()) as any).error, 'invalid_target');
  });

  it('says error="invalid_token" when a token was sent but is no good', async () => {
    const k = setup();
    const r = await mcp(k, '/mcp', 'ping', {}, `mcpat_${'0'.repeat(64)}`);
    assert.equal(r.status, 401);
    assert.match(r.headers.get('www-authenticate')!, /error="invalid_token"/);
    assert.doesNotMatch((await mcp(k, '/mcp', 'ping')).headers.get('www-authenticate')!, /error=/);
  });

  it('refuses oversized registration and token bodies without reading them whole', async () => {
    const k = setup();
    const big = JSON.stringify({ redirect_uris: [REDIRECT], client_name: 'x'.repeat(20000) });
    assert.equal(
      (await k.call('/oauth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: big }))
        .status,
      413,
    );
    const t = await k.call('/oauth/token', form({ grant_type: 'refresh_token', pad: 'x'.repeat(20000) }));
    assert.equal(t.status, 400);
  });

  // Access can't be told that someone was disabled here, so the users table must be able to overrule it.
  it('refuses consent for a disabled person, whatever the identity provider says', async () => {
    const k = setup();
    await connect(k, { name: 'Alice' });
    k.db.sqlite.exec("UPDATE users SET disabled_at = datetime('now')");
    const c = await registerClient(k);
    const { challenge } = await pkce();
    const a = await k.call(
      `/oauth/authorize?${new URLSearchParams({ response_type: 'code', client_id: c.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256' })}`,
    );
    // A provider (like Access) that still vouches for the person: the users table has the last word.
    const idp: IdentityProvider = {
      name: 'test',
      currentUser: async () => ({ id: 'dev:alice', name: 'Alice', roles: [] }),
      loginUrl: () => null,
    };
    const url = new URL(a.headers.get('location')!, ORIGIN);
    const res = await continueAuth(
      new Request(url, { headers: { cookie: a.headers.getSetCookie()[0].split(';')[0] } }),
      k.env,
      url,
      idp,
    );
    assert.equal(res.status, 403);
  });

  // decodeURIComponent throws on a broken escape; another app's cookie must not break sign-in here.
  it('survives a malformed cookie from another app on the same host', async () => {
    const k = setup();
    const res = await k.call(`/oauth/continue?req=${'a'.repeat(32)}`, { headers: { cookie: 'other=%E0%A4%A' } });
    assert.equal(res.status, 400);
  });
});

describe('client clean-up', () => {
  it('removes old clients that never connected, and keeps the rest', async () => {
    const k = setup();
    const used = await connect(k);
    const unused = await registerClient(k);
    const fresh = await registerClient(k);
    k.db.sqlite.exec(
      `UPDATE oauth_clients SET created_at = '2000-01-01 00:00:00' WHERE id IN ('${used.clientId}', '${unused.client_id}')`,
    );
    await worker.scheduled({} as ScheduledController, k.env);
    assert.deepEqual(
      k
        .rows('SELECT id FROM oauth_clients ORDER BY id')
        .map((r) => r.id)
        .sort(),
      [used.clientId, fresh.client_id].sort(),
    );
  });
});

/** The query string of an authorization request for `clientId`, with any parameter overridden. */
const authorizeQuery = (clientId: string, challenge: string, extra: Record<string, string> = {}) =>
  new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  });

describe('no open redirects (RFC 9700 §4.11.2)', () => {
  // Anyone can register a phishing page as a redirect URI. A broken request must not bounce people there unseen.
  it('shows authorization errors on a page with a link instead of redirecting', async () => {
    const k = setup();
    const c = await registerClient(k, { redirect_uris: ['https://phish.example/login'] });
    const res = await k.call(`/oauth/authorize?client_id=${c.client_id}&response_type=token&state=s1`);
    assert.equal(res.status, 400);
    assert.equal(res.headers.get('location'), null);
    const html = await res.text();
    assert.match(html, /Return to phish\.example/);
    assert.match(html, /href="https:\/\/phish\.example\/login\?error=unsupported_response_type&amp;[^"]*state=s1/);
  });
});

describe('token audience (RFC 8707)', () => {
  // The same Worker answers on several hostnames (custom domain, workers.dev). A token is for one of them only.
  it('refuses an access token at a resource it was not issued for', async () => {
    const k = setup();
    const t = await connect(k);
    const ping = (base: string) =>
      k.call(`${base}/mcp`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${t.access_token}` },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' }),
      });
    assert.equal((await ping(ORIGIN)).status, 200);
    assert.equal((await ping('http://127.0.0.1:8787')).status, 401);
  });

  it('carries the audience through refresh and checks a resource sent with it', async () => {
    const k = setup();
    const t = await connect(k);
    const other = await k.call(
      '/oauth/token',
      form({
        grant_type: 'refresh_token',
        client_id: t.clientId,
        refresh_token: t.refresh_token,
        resource: 'https://x.example/mcp',
      }),
    );
    assert.equal(((await other.json()) as any).error, 'invalid_target');
    const ok = await k.call(
      '/oauth/token',
      form({
        grant_type: 'refresh_token',
        client_id: t.clientId,
        refresh_token: t.refresh_token,
        resource: 'HTTP://LOCALHOST:8787/mcp/',
      }),
    );
    assert.equal(ok.status, 200, 'scheme and host compare case-insensitively, a trailing slash is ignored');
    assert.deepEqual(k.rows('SELECT DISTINCT resource FROM oauth_tokens'), [{ resource: `${ORIGIN}/mcp` }]);
  });
});

describe('token endpoint details', () => {
  const refresh = (k: ReturnType<typeof setup>, clientId: string, token: string) =>
    k.call('/oauth/token', form({ grant_type: 'refresh_token', client_id: clientId, refresh_token: token }));

  it('refuses to refresh for a person who has been disabled', async () => {
    const k = setup();
    const t = await connect(k);
    k.db.sqlite.exec("UPDATE users SET disabled_at = datetime('now')");
    const res = await refresh(k, t.clientId, t.refresh_token);
    assert.equal(res.status, 400);
    assert.equal(
      k.rows("SELECT * FROM oauth_tokens WHERE used_at IS NULL AND kind = 'refresh'").length,
      1,
      'nothing new issued',
    );
  });

  it('accepts tokens only with their exact prefix', async () => {
    const k = setup();
    const t = await connect(k);
    assert.equal((await refresh(k, t.clientId, t.refresh_token.slice(6))).status, 400);
    assert.equal((await refresh(k, t.clientId, `x${t.refresh_token}`)).status, 400);
    assert.equal((await refresh(k, t.clientId, t.refresh_token)).status, 200);
  });

  it('authenticates confidential clients with HTTP Basic, and says so when it fails (RFC 6749 §5.2)', async () => {
    const k = setup();
    const c = await registerClient(k, { token_endpoint_auth_method: 'client_secret_basic' });
    const basic = (secret: string) => `Basic ${btoa(`${c.client_id}:${secret}`)}`;
    const bad = await k.call('/oauth/token', {
      ...form({ grant_type: 'refresh_token', refresh_token: 'x' }),
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic('wrong') },
    });
    assert.equal(bad.status, 401);
    assert.match(bad.headers.get('www-authenticate')!, /^Basic/);
    const good = await k.call('/oauth/token', {
      ...form({ grant_type: 'refresh_token', refresh_token: 'x' }),
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic(c.client_secret!) },
    });
    assert.equal(((await good.json()) as any).error, 'invalid_grant', 'client accepted; the token is what is wrong');
  });

  it('answers other methods with 405 and an Allow header', async () => {
    const k = setup();
    const res = await k.call('/oauth/token');
    assert.equal(res.status, 405);
    assert.equal(res.headers.get('allow'), 'POST, OPTIONS');
  });
});

describe('authorization requests', () => {
  // Starting a second connection in the same browser used to replace the first one's cookie.
  it('lets two authorizations started in the same browser both continue', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { challenge } = await pkce();
    const a1 = await k.call(`/oauth/authorize?${authorizeQuery(c.client_id, challenge)}`);
    const cookie = a1.headers.getSetCookie()[0].split(';')[0];
    const a2 = await k.call(`/oauth/authorize?${authorizeQuery(c.client_id, challenge)}`, { headers: { cookie } });
    assert.equal(a2.headers.getSetCookie()[0].split(';')[0], cookie, 'the binding is reused');
    const login = await k.call('/dev/login', {
      ...form({ name: 'Alice' }),
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: ORIGIN },
    });
    const both = `${cookie}; ${login.headers.getSetCookie()[0].split(';')[0]}`;
    for (const a of [a1, a2])
      assert.equal((await k.call(a.headers.get('location')!, { headers: { cookie: both } })).status, 200);
  });

  // /oauth/authorize takes no credentials and writes a row; one script must not be able to write rows forever.
  it('limits pending authorization requests per network', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { challenge } = await pkce();
    k.db.sqlite.exec(
      `INSERT INTO oauth_requests (id, browser_hash, client_id, params, network_hash, expires_at)
       SELECT hex(randomblob(16)), 'x', '${c.client_id}', '{}', (SELECT network_hash FROM oauth_clients), datetime('now', '+15 minutes')
       FROM (WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 60) SELECT i FROM n)`,
    );
    const res = await k.call(`/oauth/authorize?${authorizeQuery(c.client_id, challenge)}`);
    assert.equal(res.status, 429);
  });

  it('refuses an oversized consent form without reading it whole', async () => {
    const k = setup();
    const c = await registerClient(k);
    const a = await k.call(`/oauth/authorize?${authorizeQuery(c.client_id, (await pkce()).challenge)}`);
    const login = await k.call('/dev/login', {
      ...form({ name: 'Alice' }),
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: ORIGIN },
    });
    const cookie = `${a.headers.getSetCookie()[0].split(';')[0]}; ${login.headers.getSetCookie()[0].split(';')[0]}`;
    const res = await k.call(a.headers.get('location')!, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: ORIGIN, cookie },
      body: `decision=approve&pad=${'x'.repeat(20000)}`,
    });
    assert.equal(res.status, 413);
    assert.equal(k.rows('SELECT * FROM oauth_grants').length, 0);
  });

  // Any local program can claim a loopback port, so the consent screen says where the code is going.
  it('warns on the consent screen when the assistant returns to this computer', async () => {
    const k = setup();
    const c = await registerClient(k, { redirect_uris: ['http://127.0.0.1/cb'] });
    const a = await k.call(
      `/oauth/authorize?${authorizeQuery(c.client_id, (await pkce()).challenge, { redirect_uri: 'http://127.0.0.1:5555/cb' })}`,
    );
    const login = await k.call('/dev/login', {
      ...form({ name: 'Alice' }),
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: ORIGIN },
    });
    const cookie = `${a.headers.getSetCookie()[0].split(';')[0]}; ${login.headers.getSetCookie()[0].split(';')[0]}`;
    const html = await (await k.call(a.headers.get('location')!, { headers: { cookie } })).text();
    assert.match(html, /runs on your own computer \(it returns to <strong>127\.0\.0\.1:5555<\/strong>\)/);
  });
});

describe('registration details', () => {
  // A single IPv6 /64 holds 2^64 addresses; counting per address would make the limit meaningless.
  it('counts IPv6 registrations per /64', async () => {
    const k = setup();
    const reg = (ip: string) =>
      k.call('/oauth/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'cf-connecting-ip': ip },
        body: JSON.stringify({ redirect_uris: [REDIRECT] }),
      });
    for (let i = 1; i <= 30; i++) assert.equal((await reg(`2001:db8:aa:bb::${i.toString(16)}`)).status, 201);
    assert.equal((await reg('2001:db8:aa:bb:ffff::1')).status, 429);
    assert.equal((await reg('2001:db8:aa:cc::1')).status, 201, 'another /64 is another network');
  });

  it('ignores metadata of the wrong type and echoes client_uri', async () => {
    const k = setup();
    const c = (await registerClient(k, {
      client_name: { evil: true },
      client_uri: 'https://assistant.example',
    })) as any;
    assert.equal(c.client_name, 'AI assistant');
    assert.equal(c.client_uri, 'https://assistant.example');
  });
});

describe('grant clean-up', () => {
  // Grants used to be kept forever; they are now kept as long as the audit records that point at them.
  it('deletes grants older than the audit period, and then their clients', async () => {
    const k = setup();
    const t = await connect(k);
    k.db.sqlite.exec("UPDATE oauth_grants SET created_at = '2000-01-01 00:00:00'");
    k.db.sqlite.exec("UPDATE oauth_clients SET created_at = '2000-01-01 00:00:00'");
    await worker.scheduled({} as ScheduledController, k.env);
    assert.equal(k.rows('SELECT * FROM oauth_grants').length, 0);
    assert.equal(k.rows('SELECT * FROM oauth_clients WHERE id = ?', t.clientId).length, 0);
  });
});
