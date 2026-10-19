import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { IdentityProvider } from '../src/identity.ts';
import { continueAuth } from '../src/oauth.ts';
import { ORIGIN, REDIRECT, authorizeFlow, connect, exchange, form, mcp, pkce, registerClient, setup } from './helpers.ts';

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
    assert.match(r.headers.get('www-authenticate')!, /resource_metadata="http:\/\/localhost:8787\/\.well-known\/oauth-protected-resource"/);
  });
});

describe('dynamic client registration', () => {
  const bad = ['http://evil.example/cb', 'https://ok.example/cb#frag', 'javascript:alert(1)', 'not a url'];
  for (const uri of bad) {
    it(`refuses redirect URI ${uri}`, async () => {
      const k = setup();
      const res = await k.call('/oauth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: [uri] }) });
      assert.equal(res.status, 400);
      assert.equal(((await res.json()) as any).error, 'invalid_redirect_uri');
    });
  }

  it('accepts https, loopback http and app schemes', async () => {
    const k = setup();
    const c = await registerClient(k, { redirect_uris: ['https://a.example/cb', 'http://127.0.0.1:33418/cb', 'cursor://anysphere.cursor-retrieval/oauth/callback'] });
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
    const res = await k.call('/oauth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ redirect_uris: [REDIRECT] }) });
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
    const qs = new URLSearchParams({ response_type: 'code', client_id: c.client_id, redirect_uri: REDIRECT, code_challenge: 'x'.repeat(43), code_challenge_method: 'plain' });
    const res = await k.call(`/oauth/authorize?${qs}`);
    assert.equal(res.status, 302);
    assert.equal(new URL(res.headers.get('location')!).searchParams.get('error'), 'invalid_request');
  });

  it('refuses an unregistered redirect URI without redirecting there', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { challenge } = await pkce();
    const qs = new URLSearchParams({ response_type: 'code', client_id: c.client_id, redirect_uri: 'https://evil.example/cb', code_challenge: challenge, code_challenge_method: 'S256' });
    const res = await k.call(`/oauth/authorize?${qs}`);
    assert.equal(res.status, 400);
    assert.equal(res.headers.get('location'), null);
  });

  it('refuses a token for another resource (RFC 8707)', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { challenge } = await pkce();
    const qs = new URLSearchParams({ response_type: 'code', client_id: c.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256', resource: 'https://other.example/mcp' });
    const res = await k.call(`/oauth/authorize?${qs}`);
    assert.equal(new URL(res.headers.get('location')!).searchParams.get('error'), 'invalid_target');
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

  it('revokes the grant when a code is used twice', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { verifier, challenge } = await pkce();
    const code = (await authorizeFlow(k, c.client_id, challenge)).get('code')!;
    const first = (await (await exchange(k, c.client_id, code, verifier)).json()) as any;
    assert.equal((await mcp(k, '/mcp', 'ping', {}, first.access_token)).status, 200);
    const again = await exchange(k, c.client_id, code, verifier);
    assert.equal(again.status, 400);
    assert.equal((await mcp(k, '/mcp', 'ping', {}, first.access_token)).status, 401, 'tokens from the first exchange stop working');
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
    const qs = new URLSearchParams({ response_type: 'code', client_id: c.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256' });
    const a = await k.call(`/oauth/authorize?${qs}`);
    const reqCookie = a.headers.getSetCookie()[0].split(';')[0];
    const login = await k.call('/dev/login', { ...form({ name: 'Alice' }), headers: { 'content-type': 'application/x-www-form-urlencoded', origin: ORIGIN } });
    const cookie = `${reqCookie}; ${login.headers.getSetCookie()[0].split(';')[0]}`;
    const res = await k.call(a.headers.get('location')!, { ...form({ decision: 'approve' }), headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://evil.example', cookie } });
    assert.equal(res.status, 403);
  });

  it('serves the consent screen with a strict content security policy', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { challenge } = await pkce();
    const qs = new URLSearchParams({ response_type: 'code', client_id: c.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256' });
    const a = await k.call(`/oauth/authorize?${qs}`);
    const login = await k.call('/dev/login', { ...form({ name: 'Alice' }), headers: { 'content-type': 'application/x-www-form-urlencoded', origin: ORIGIN } });
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

  it('only continues in the browser that started the request', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { challenge } = await pkce();
    const qs = new URLSearchParams({ response_type: 'code', client_id: c.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256' });
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
    const { default: worker } = await import('../src/index.ts');
    const waits: Promise<unknown>[] = [];
    await worker.scheduled({} as ScheduledController, k.env, { waitUntil: (p: Promise<unknown>) => waits.push(p) } as unknown as ExecutionContext);
    await Promise.all(waits);
    assert.equal(k.rows('SELECT * FROM oauth_tokens').length, 0);
    assert.equal(k.rows("SELECT * FROM tool_calls WHERE tool = 'old'").length, 0);
  });
});

describe('races and lifetimes', () => {
  const refresh = (k: ReturnType<typeof setup>, clientId: string, token: string) =>
    k.call('/oauth/token', form({ grant_type: 'refresh_token', client_id: clientId, refresh_token: token }));

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
    const both = await Promise.all([exchange(k, c.client_id, code, verifier), exchange(k, c.client_id, code, verifier)]);
    const ok = both.filter((r) => r.status === 200);
    assert.ok(ok.length <= 1);
    for (const r of ok) assert.equal((await mcp(k, '/mcp', 'ping', {}, ((await r.json()) as any).access_token)).status, 401);
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

  it("never issues a token that outlives the grant's limit", async () => {
    const k = setup();
    const t = await connect(k);
    k.db.sqlite.exec("UPDATE oauth_grants SET created_at = datetime('now', '-30 days', '+10 minutes')");
    const n = (await (await refresh(k, t.clientId, t.refresh_token)).json()) as any;
    assert.ok(n.expires_in <= 600, `access token lasts ${n.expires_in}s`);
    const [{ latest }] = k.rows("SELECT MAX(expires_at) AS latest FROM oauth_tokens WHERE kind = 'refresh' AND used_at IS NULL");
    assert.ok(String(latest) <= String(k.rows("SELECT datetime(created_at, '+30 days') AS e FROM oauth_grants")[0].e));
  });
});

describe('spec details', () => {
  it('accepts a loopback redirect on any port (RFC 8252), but not another path or host', async () => {
    const k = setup();
    const c = await registerClient(k, { redirect_uris: ['http://127.0.0.1/callback'] });
    const { challenge } = await pkce();
    const go = (redirect_uri: string) => k.call(`/oauth/authorize?${new URLSearchParams({ response_type: 'code', client_id: c.client_id, redirect_uri, code_challenge: challenge, code_challenge_method: 'S256' })}`);
    assert.equal((await go('http://127.0.0.1:49152/callback')).status, 302);
    assert.equal((await go('http://127.0.0.1:49152/other')).status, 400);
    assert.equal((await go('http://localhost:49152/callback')).status, 400);
  });

  it('refuses a token request for another resource (RFC 8707)', async () => {
    const k = setup();
    const c = await registerClient(k);
    const { verifier, challenge } = await pkce();
    const code = (await authorizeFlow(k, c.client_id, challenge)).get('code')!;
    const res = await k.call('/oauth/token', form({ grant_type: 'authorization_code', client_id: c.client_id, code, code_verifier: verifier, resource: 'https://other.example/mcp' }));
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
    assert.equal((await k.call('/oauth/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: big })).status, 413);
    const t = await k.call('/oauth/token', form({ grant_type: 'refresh_token', pad: 'x'.repeat(20000) }));
    assert.equal(t.status, 400);
  });

  it('refuses consent for a disabled person, whatever the identity provider says', async () => {
    const k = setup();
    await connect(k, { name: 'Alice' });
    k.db.sqlite.exec("UPDATE users SET disabled_at = datetime('now')");
    const c = await registerClient(k);
    const { challenge } = await pkce();
    const a = await k.call(`/oauth/authorize?${new URLSearchParams({ response_type: 'code', client_id: c.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256' })}`);
    // A provider (like Access) that still vouches for the person: the users table has the last word.
    const idp: IdentityProvider = { name: 'test', currentUser: async () => ({ id: 'dev:alice', name: 'Alice', roles: [] }), loginUrl: () => null };
    const url = new URL(a.headers.get('location')!, ORIGIN);
    const res = await continueAuth(new Request(url, { headers: { cookie: a.headers.getSetCookie()[0].split(';')[0] } }), k.env, url, idp);
    assert.equal(res.status, 403);
  });

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
    k.db.sqlite.exec(`UPDATE oauth_clients SET created_at = '2000-01-01 00:00:00' WHERE id IN ('${used.clientId}', '${unused.client_id}')`);
    const { default: worker } = await import('../src/index.ts');
    const waits: Promise<unknown>[] = [];
    await worker.scheduled({} as ScheduledController, k.env, { waitUntil: (p: Promise<unknown>) => waits.push(p) } as unknown as ExecutionContext);
    await Promise.all(waits);
    assert.deepEqual(k.rows('SELECT id FROM oauth_clients ORDER BY id').map((r) => r.id).sort(), [used.clientId, fresh.client_id].sort());
  });
});
