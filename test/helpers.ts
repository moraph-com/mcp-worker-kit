// A Worker under test: an in-memory database, the dev sign-in, and helpers that walk the OAuth flow the way an
// assistant and a browser would.
import assert from 'node:assert/strict';
import worker from '../src/index.ts';
import type { Env } from '../src/env.ts';
import { b64url } from '../src/util.ts';
import { createD1 } from './d1.ts';

export const ORIGIN = 'http://localhost:8787';
export const REDIRECT = 'https://assistant.example/callback';

export function setup(vars: Partial<Env> = { DEV_LOGIN: '1' }, opts: { latency?: boolean } = {}) {
  const db = createD1(opts);
  const env = { DB: db as unknown as D1Database, ...vars } as Env;
  const pending: Promise<unknown>[] = [];
  const ctx = {
    waitUntil: (p: Promise<unknown>) => {
      pending.push(p);
    },
    passThroughOnException() {},
    props: {},
  } as unknown as ExecutionContext;
  async function call(path: string, init: RequestInit = {}) {
    const res = await worker.fetch(new Request(new URL(path, ORIGIN), init), env, ctx);
    await Promise.all(pending.splice(0));
    return res;
  }
  const rows = (sql: string, ...b: unknown[]) =>
    db.sqlite
      .prepare(sql)
      .all(...(b as never[]))
      .map((r) => ({ ...r }));
  return { env, db, call, rows };
}
export type Kit = ReturnType<typeof setup>;

export const form = (o: Record<string, string>) => ({
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(o).toString(),
});

export async function registerClient(k: Kit, extra: Record<string, unknown> = {}) {
  const res = await k.call('/oauth/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client_name: 'Test assistant', redirect_uris: [REDIRECT], ...extra }),
  });
  assert.equal(res.status, 201);
  return (await res.json()) as { client_id: string; client_secret?: string };
}

export async function pkce() {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
  return { verifier, challenge };
}

const cookieOf = (res: Response) =>
  res.headers
    .getSetCookie()
    .map((c) => c.split(';')[0])
    .filter((c) => !c.endsWith('='));

/** Sign in with the dev provider; returns the session cookie. */
export async function devLogin(k: Kit, name = 'Alice', admin = false) {
  const res = await k.call('/dev/login?next=/', {
    ...form({ name, ...(admin ? { admin: '1' } : {}) }),
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: ORIGIN },
  });
  assert.equal(res.status, 302);
  return cookieOf(res)[0];
}

/** authorize → sign in → consent → code. Returns the code (or the redirect params on denial). */
export async function authorizeFlow(
  k: Kit,
  clientId: string,
  challenge: string,
  opts: { write?: boolean; scope?: string; name?: string; admin?: boolean; decision?: string } = {},
) {
  const qs = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'xyz',
    scope: opts.scope ?? 'read write',
    resource: `${ORIGIN}/mcp`,
  });
  const a = await k.call(`/oauth/authorize?${qs}`);
  assert.equal(a.status, 302, await a.clone().text());
  const reqCookie = cookieOf(a)[0];
  const next = a.headers.get('location')!;
  const session = await devLogin(k, opts.name, opts.admin);
  const cookie = `${reqCookie}; ${session}`;
  const consent = await k.call(next, { headers: { cookie } });
  assert.equal(consent.status, 200);
  const decision = { decision: opts.decision ?? 'approve', ...(opts.write ? { write: '1' } : {}) };
  const done = await k.call(next, {
    ...form(decision),
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: ORIGIN, cookie },
  });
  assert.equal(done.status, 302);
  const back = new URL(done.headers.get('location')!);
  assert.equal(`${back.origin}${back.pathname}`, REDIRECT);
  assert.equal(back.searchParams.get('state'), 'xyz');
  return back.searchParams;
}

export async function exchange(k: Kit, clientId: string, code: string, verifier: string) {
  return k.call(
    '/oauth/token',
    form({
      grant_type: 'authorization_code',
      client_id: clientId,
      code,
      code_verifier: verifier,
      redirect_uri: REDIRECT,
    }),
  );
}

/** A connected assistant's access and refresh tokens. */
export async function connect(k: Kit, opts: { write?: boolean; name?: string; admin?: boolean } = {}) {
  const client = await registerClient(k);
  const { verifier, challenge } = await pkce();
  const params = await authorizeFlow(k, client.client_id, challenge, opts);
  const res = await exchange(k, client.client_id, params.get('code')!, verifier);
  assert.equal(res.status, 200);
  const t = (await res.json()) as { access_token: string; refresh_token: string; scope: string };
  return { ...t, clientId: client.client_id };
}

let nextId = 1;
export async function mcp(k: Kit, path: '/mcp' | '/public', method: string, params: unknown = {}, token?: string) {
  const res = await k.call(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, params }),
  });
  return {
    status: res.status,
    body: res.status === 200 ? ((await res.json()) as any) : await res.text(),
    headers: res.headers,
  };
}
export const toolNames = async (k: Kit, path: '/mcp' | '/public', token?: string) =>
  (await mcp(k, path, 'tools/list', {}, token)).body.result.tools.map((t: { name: string }) => t.name).sort();
