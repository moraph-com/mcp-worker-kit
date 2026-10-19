/**
 * @file Sign-in providers (`src/identity.ts`): Cloudflare Access JWT verification against a local key pair and a fake
 * JWKS endpoint, the localhost-only development sign-in, and the behaviour with no provider configured.
 */
import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import worker from '../src/index.ts';
import type { Env } from '../src/env.ts';
import { accessProvider, resetAccessKeys, verifyAccessJwt } from '../src/identity.ts';
import { b64url } from '../src/util.ts';
import { createD1 } from './d1.ts';
import { REDIRECT, pkce, registerClient, setup } from './helpers.ts';

const TEAM = 'example.cloudflareaccess.com';
const AUD = 'aud-tag-123';
const env = { ACCESS_TEAM_DOMAIN: TEAM, ACCESS_AUD: AUD, ADMIN_EMAILS: 'Boss@Example.com' } as Env;

let keys: CryptoKeyPair;
let jwk: JsonWebKey;
const realFetch = globalThis.fetch;
let fetches = 0;
/** Simulates an Access outage: the JWKS endpoint answers 503. */
let down = false;
let lastSignal: AbortSignal | null | undefined;

async function sign(claims: Record<string, unknown>, kid = 'k1', key = keys.privateKey) {
  const enc = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));
  const head = `${enc({ alg: 'RS256', kid, typ: 'JWT' })}.${enc(claims)}`;
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(head));
  return `${head}.${b64url(sig)}`;
}
const now = () => Math.floor(Date.now() / 1000);
const good = (extra: Record<string, unknown> = {}) => ({
  aud: [AUD],
  iss: `https://${TEAM}`,
  sub: 'user-1',
  email: 'boss@example.com',
  exp: now() + 300,
  iat: now(),
  ...extra,
});

describe('Cloudflare Access sign-in', () => {
  before(async () => {
    keys = (await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    jwk = (await crypto.subtle.exportKey('jwk', keys.publicKey)) as JsonWebKey;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      fetches++;
      lastSignal = init?.signal;
      assert.equal(String(input), `https://${TEAM}/cdn-cgi/access/certs`);
      if (down) return new Response('unavailable', { status: 503 });
      return new Response(JSON.stringify({ keys: [{ ...jwk, kid: 'k1' }] }));
    }) as typeof fetch;
  });
  after(() => {
    globalThis.fetch = realFetch;
  });
  beforeEach(() => {
    resetAccessKeys();
    fetches = 0;
    down = false;
  });

  it('accepts a valid token and caches the keys', async () => {
    assert.equal((await verifyAccessJwt(await sign(good()), env))?.sub, 'user-1');
    assert.ok(await verifyAccessJwt(await sign(good()), env));
    assert.equal(fetches, 1);
  });

  // Each case changes one thing about an otherwise valid token. The last two are the classic algorithm attacks: "none"
  // (no signature at all) and HS256 keyed with the RSA public key, which anyone can fetch (RFC 8725 §2.1).
  const cases: [string, () => Promise<string>][] = [
    ['the wrong audience', () => sign(good({ aud: ['someone-else'] }))],
    ['the wrong issuer', () => sign(good({ iss: 'https://evil.cloudflareaccess.com' }))],
    ['an expired token', () => sign(good({ exp: now() - 3600 }))],
    ['a token not valid yet', () => sign(good({ nbf: now() + 3600 }))],
    ['an unknown key id', () => sign(good(), 'k2')],
    [
      'a tampered payload',
      async () => {
        const [h, , s] = (await sign(good())).split('.');
        return `${h}.${b64url(new TextEncoder().encode(JSON.stringify(good({ sub: 'admin' }))))}.${s}`;
      },
    ],
    [
      'alg none',
      async () =>
        `${b64url(new TextEncoder().encode('{"alg":"none","kid":"k1"}'))}.${b64url(new TextEncoder().encode(JSON.stringify(good())))}.`,
    ],
    [
      'HS256 signed with the public key',
      async () => {
        const enc = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));
        const head = `${enc({ alg: 'HS256', kid: 'k1', typ: 'JWT' })}.${enc(good())}`;
        const hmac = await crypto.subtle.importKey(
          'raw',
          new TextEncoder().encode(JSON.stringify(jwk)),
          { name: 'HMAC', hash: 'SHA-256' },
          false,
          ['sign'],
        );
        return `${head}.${b64url(await crypto.subtle.sign('HMAC', hmac, new TextEncoder().encode(head)))}`;
      },
    ],
  ];
  for (const [what, token] of cases) {
    it(`rejects ${what}`, async () => {
      assert.equal(await verifyAccessJwt(await token(), env), null);
    });
  }

  it('rejects a token signed by another key', async () => {
    const other = (await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    assert.equal(await verifyAccessJwt(await sign(good(), 'k1', other.privateKey), env), null);
  });

  // Random kids must not turn every sign-in attempt into an outbound request.
  it('refetches keys for an unknown kid at most every 30 seconds', async () => {
    assert.ok(await verifyAccessJwt(await sign(good()), env));
    for (let i = 0; i < 5; i++) assert.equal(await verifyAccessJwt(await sign(good(), `random-${i}`), env), null);
    assert.equal(fetches, 1);
  });

  // Roles are never trusted from the time of consent: lookupUser recomputes them on every request.
  it('re-derives roles on every call, so removing someone from ADMIN_EMAILS takes effect at once', async () => {
    const db = createD1();
    const e = { ...env, DB: db as unknown as D1Database } as Env;
    db.sqlite.exec(
      "INSERT INTO users (id, name, email, roles) VALUES ('access:user-1', 'boss@example.com', 'boss@example.com', '[\"admin\"]')",
    );
    assert.deepEqual((await accessProvider.lookupUser!('access:user-1', e))?.roles, ['admin']);
    assert.deepEqual((await accessProvider.lookupUser!('access:user-1', { ...e, ADMIN_EMAILS: '' }))?.roles, []);
    db.sqlite.exec("UPDATE users SET disabled_at = datetime('now')");
    assert.equal(await accessProvider.lookupUser!('access:user-1', e), null);
  });

  it('maps the person and the admin role from ADMIN_EMAILS', async () => {
    const req = new Request('https://mcp.example/oauth/continue', {
      headers: { 'cf-access-jwt-assertion': await sign(good()) },
    });
    const u = await accessProvider.currentUser(req, env, new URL(req.url));
    assert.deepEqual(u, { id: 'access:user-1', name: 'boss@example.com', email: 'boss@example.com', roles: ['admin'] });
  });

  // A failed fetch used to be retried on every request, so an outage multiplied outbound traffic.
  it('during an Access outage, asks for the keys at most every 30 seconds, with a timeout', async () => {
    down = true;
    assert.equal(await verifyAccessJwt(await sign(good()), env), null);
    assert.equal(await verifyAccessJwt(await sign(good()), env), null);
    assert.equal(fetches, 1);
    assert.ok(lastSignal instanceof AbortSignal, 'the fetch can time out');
  });
});

describe('development sign-in', () => {
  it('is off unless DEV_LOGIN=1', async () => {
    const k = setup({});
    assert.equal((await k.call('/dev/login')).status, 404);
  });

  // A DEV_LOGIN=1 copied into production by mistake must still do nothing.
  it('is off on any host but localhost, even with DEV_LOGIN=1', async () => {
    const db = createD1();
    const e = { DB: db as unknown as D1Database, DEV_LOGIN: '1' } as Env;
    const ctx = { waitUntil() {} } as unknown as ExecutionContext;
    const res = await worker.fetch(new Request('https://mcp.example.com/dev/login'), e, ctx);
    assert.equal(res.status, 404);
  });

  for (const next of ['//evil.example/x', '/\t/evil.example', '/\\evil.example', '/%0a/x\n']) {
    it(`only redirects to paths on this site after sign-in (${JSON.stringify(next)})`, async () => {
      const k = setup();
      const res = await k.call(`/dev/login?next=${encodeURIComponent(next)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'http://localhost:8787' },
        body: 'name=Alice',
      });
      assert.equal(new URL(res.headers.get('location')!, 'http://localhost:8787').host, 'localhost:8787');
    });
  }
});

describe('development sign-in: sessions and limits', () => {
  it('refuses an oversized sign-in form without reading it whole', async () => {
    const k = setup();
    const res = await k.call('/dev/login?next=/', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'http://localhost:8787' },
      body: `name=A&pad=${'x'.repeat(10000)}`,
    });
    assert.equal(res.status, 413);
  });

  // Clearing the cookie alone left a session token that still worked until it expired.
  it('ends the session on the server at logout', async () => {
    const k = setup();
    const login = await k.call('/dev/login?next=/', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'http://localhost:8787' },
      body: 'name=Alice',
    });
    const cookie = login.headers.getSetCookie()[0].split(';')[0];
    assert.equal(k.rows('SELECT * FROM dev_sessions').length, 1);
    await k.call('/dev/logout', { headers: { cookie } });
    assert.equal(k.rows('SELECT * FROM dev_sessions').length, 0);
  });
});

describe('no sign-in configured', () => {
  it('explains that only public tools are available', async () => {
    const k = setup({});
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
    const res = await k.call(a.headers.get('location')!, {
      headers: { cookie: a.headers.getSetCookie()[0].split(';')[0] },
    });
    assert.equal(res.status, 401);
    assert.match(await res.text(), /Sign-in isn’t set up/);
  });
});
