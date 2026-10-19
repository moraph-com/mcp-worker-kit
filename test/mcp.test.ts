/**
 * @file The MCP endpoint (`src/mcp.ts`): JSON-RPC and Streamable HTTP rules, who sees which tool, argument checking,
 * and the audit trail.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { connect, mcp, post, setup, toolNames } from './helpers.ts';

describe('JSON-RPC over Streamable HTTP', () => {
  it('initializes with the client protocol version when supported', async () => {
    const k = setup();
    const r = await mcp(k, '/public', 'initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 't', version: '1' },
    });
    assert.equal(r.body.result.protocolVersion, '2025-06-18');
    assert.equal(r.body.result.serverInfo.name, 'mcp-worker-kit');
    assert.match(r.body.result.instructions, /public information only/);
  });

  it('falls back to the newest protocol version', async () => {
    const k = setup();
    const r = await mcp(k, '/public', 'initialize', { protocolVersion: '1999-01-01' });
    assert.equal(r.body.result.protocolVersion, '2025-11-25');
  });

  it('answers notifications with 202 and no body', async () => {
    const k = setup();
    const res = await k.call('/public', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
    });
    assert.equal(res.status, 202);
    assert.equal(await res.text(), '');
  });

  it('handles batches, skipping notifications', async () => {
    const k = setup();
    const res = await k.call('/public', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify([
        { jsonrpc: '2.0', id: 1, method: 'ping' },
        { jsonrpc: '2.0', method: 'notifications/initialized' },
        { jsonrpc: '2.0', id: 2, method: 'tools/list' },
      ]),
    });
    const out = (await res.json()) as any[];
    assert.deepEqual(
      out.map((m) => m.id),
      [1, 2],
    );
  });

  it('refuses batches over 20 messages', async () => {
    const k = setup();
    const batch = Array.from({ length: 21 }, (_, i) => ({ jsonrpc: '2.0', id: i, method: 'ping' }));
    const res = await k.call('/public', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(batch),
    });
    assert.equal(res.status, 400);
  });

  it('refuses bodies over 64 KB, bad JSON and unknown methods', async () => {
    const k = setup();
    const big = await post(k, { jsonrpc: '2.0', id: 1, method: 'ping', pad: 'x'.repeat(70000) });
    assert.equal(big.status, 413);
    const bad = await post(k, '{');
    assert.equal(((await bad.json()) as any).error.code, -32700);
    const r = await mcp(k, '/public', 'sampling/createMessage');
    assert.equal(r.body.error.code, -32601);
  });

  it('answers GET on the endpoint with 405 (no event stream)', async () => {
    const k = setup();
    assert.equal((await k.call('/public')).status, 405);
  });
});

describe('who sees which tools', () => {
  it('shows only public tools on /public', async () => {
    const k = setup();
    assert.deepEqual(await toolNames(k, '/public'), ['search_notes', 'server_time']);
  });

  it('hides write tools from a read-only connection, but still lets it disconnect', async () => {
    const k = setup();
    const t = await connect(k, { write: false });
    assert.deepEqual(await toolNames(k, '/mcp', t.access_token), [
      'my_connections',
      'revoke_connection',
      'search_notes',
      'server_time',
    ]);
  });

  it('shows write tools when the person allowed actions', async () => {
    const k = setup();
    const t = await connect(k, { write: true });
    const names = await toolNames(k, '/mcp', t.access_token);
    assert.ok(names.includes('create_note'));
    assert.ok(names.includes('revoke_connection'));
    assert.ok(!names.includes('audit_log'), 'admin-only tool hidden from a non-admin');
  });

  it('applies custom role rules', async () => {
    const k = setup();
    const t = await connect(k, { name: 'Ada', admin: true });
    assert.ok((await toolNames(k, '/mcp', t.access_token)).includes('audit_log'));
  });

  it('explains a refused write on a read-only connection', async () => {
    const k = setup();
    const t = await connect(k, { write: false });
    const r = await mcp(
      k,
      '/mcp',
      'tools/call',
      { name: 'create_note', arguments: { title: 'x', body: 'y' } },
      t.access_token,
    );
    assert.equal(r.body.result.isError, true);
    assert.match(r.body.result.content[0].text, /read-only/);
    assert.equal(k.rows('SELECT * FROM notes WHERE owner_id IS NOT NULL').length, 0);
  });

  it('explains a signed-in tool asked for on /public', async () => {
    const k = setup();
    const r = await mcp(k, '/public', 'tools/call', { name: 'create_note', arguments: {} });
    assert.match(r.body.result.content[0].text, /sign in/);
  });
});

describe('tools', () => {
  it('runs a public tool', async () => {
    const k = setup();
    const r = await mcp(k, '/public', 'tools/call', { name: 'search_notes', arguments: { query: 'welcome' } });
    assert.equal(r.body.result.structuredContent.notes[0].id, 'welcome');
  });

  it('creates a private note visible only to its owner', async () => {
    const k = setup();
    const alice = await connect(k, { write: true, name: 'Alice' });
    const bob = await connect(k, { write: true, name: 'Bob' });
    const made = await mcp(
      k,
      '/mcp',
      'tools/call',
      { name: 'create_note', arguments: { title: 'Plan', body: 'quarterly zebra' } },
      alice.access_token,
    );
    assert.equal(made.body.result.structuredContent.saved, true);
    const mine = await mcp(
      k,
      '/mcp',
      'tools/call',
      { name: 'search_notes', arguments: { query: 'zebra' } },
      alice.access_token,
    );
    assert.equal(mine.body.result.structuredContent.notes.length, 1);
    const theirs = await mcp(
      k,
      '/mcp',
      'tools/call',
      { name: 'search_notes', arguments: { query: 'zebra' } },
      bob.access_token,
    );
    assert.equal(theirs.body.result.structuredContent.notes.length, 0);
    const anon = await mcp(k, '/public', 'tools/call', { name: 'search_notes', arguments: { query: 'zebra' } });
    assert.equal(anon.body.result.structuredContent.notes.length, 0);
  });

  it('turns a ToolError into a message the assistant sees', async () => {
    const k = setup();
    const t = await connect(k, { write: true });
    const r = await mcp(
      k,
      '/mcp',
      'tools/call',
      { name: 'create_note', arguments: { title: '', body: 'x' } },
      t.access_token,
    );
    assert.equal(r.body.result.isError, true);
    assert.equal(r.body.result.content[0].text, 'A note needs a title.');
  });

  it('lists and revokes connections, own ones only', async () => {
    const k = setup();
    const t = await connect(k, { name: 'Alice' });
    const other = await connect(k, { name: 'Bob' });
    const list = await mcp(k, '/mcp', 'tools/call', { name: 'my_connections', arguments: {} }, t.access_token);
    const [conn] = list.body.result.structuredContent.connections;
    assert.equal(conn.this_connection, true);
    const otherGrant = k.rows("SELECT id FROM oauth_grants WHERE user_id = 'dev:bob'")[0].id;
    const refused = await mcp(
      k,
      '/mcp',
      'tools/call',
      { name: 'revoke_connection', arguments: { connection_id: otherGrant } },
      t.access_token,
    );
    assert.equal(refused.body.result.isError, true);
    assert.equal((await mcp(k, '/mcp', 'ping', {}, other.access_token)).status, 200);
    await mcp(
      k,
      '/mcp',
      'tools/call',
      { name: 'revoke_connection', arguments: { connection_id: conn.id } },
      t.access_token,
    );
    assert.equal((await mcp(k, '/mcp', 'ping', {}, t.access_token)).status, 401);
  });
});

describe('audit trail', () => {
  it('records every call without arguments or results', async () => {
    const k = setup();
    const t = await connect(k, { write: true });
    await mcp(
      k,
      '/mcp',
      'tools/call',
      { name: 'create_note', arguments: { title: 'Secret title', body: 'secret-text-xyz' } },
      t.access_token,
    );
    await mcp(k, '/public', 'tools/call', { name: 'server_time', arguments: {} });
    const calls = k.rows('SELECT * FROM tool_calls ORDER BY id');
    assert.equal(calls.length, 2);
    assert.equal(calls[0].tool, 'create_note');
    assert.equal(calls[0].user_id, 'dev:alice');
    assert.equal(calls[0].ok, 1);
    assert.equal(calls[1].user_id, null);
    const everything = JSON.stringify(calls);
    assert.ok(!everything.includes('secret-text-xyz'));
    assert.ok(!everything.includes('Secret title'));
  });

  it('records failures with the message the assistant saw', async () => {
    const k = setup();
    const t = await connect(k, { write: true });
    await mcp(k, '/mcp', 'tools/call', { name: 'create_note', arguments: { title: 'x', body: '' } }, t.access_token);
    const [call] = k.rows('SELECT ok, error FROM tool_calls');
    assert.deepEqual(call, { ok: 0, error: 'A note needs some text.' });
  });
});

describe('protocol version header', () => {
  const postV = (k: ReturnType<typeof setup>, body: unknown, version?: string) =>
    post(k, body, version ? { 'mcp-protocol-version': version } : {});

  it('answers an unsupported MCP-Protocol-Version with 400', async () => {
    const k = setup();
    assert.equal((await postV(k, { jsonrpc: '2.0', id: 1, method: 'ping' }, '1999-01-01')).status, 400);
    assert.equal((await postV(k, { jsonrpc: '2.0', id: 1, method: 'ping' }, '2025-11-25')).status, 200);
  });

  it('refuses batches from 2025-06-18 on, and accepts them before', async () => {
    const k = setup();
    const batch = [{ jsonrpc: '2.0', id: 1, method: 'ping' }];
    assert.equal((await postV(k, batch, '2025-06-18')).status, 400);
    assert.equal((await postV(k, batch, '2025-11-25')).status, 400);
    assert.equal((await postV(k, batch, '2025-03-26')).status, 200);
    assert.equal((await postV(k, batch)).status, 200, 'no header means 2025-03-26');
  });

  it('answers a client response (to a server request) with 202', async () => {
    const k = setup();
    const res = await postV(k, { jsonrpc: '2.0', id: 'srv-1', result: {} }, '2025-11-25');
    assert.equal(res.status, 202);
  });

  // 40,000 two-byte characters: under 64 K characters, over 64 KB. The limit protects memory, so bytes are what count.
  it('measures the body limit in bytes, not characters', async () => {
    const k = setup();
    const res = await postV(k, { jsonrpc: '2.0', id: 1, method: 'ping', pad: 'é'.repeat(40000) });
    assert.equal(res.status, 413);
  });
});

describe('argument checking', () => {
  it('returns schema problems as a tool error the assistant can fix, before the tool runs', async () => {
    const k = setup();
    const t = await connect(k, { write: true });
    const cases: [Record<string, unknown>, RegExp][] = [
      [{ title: 'x' }, /arguments\.body is required/],
      [{ title: { nested: true }, body: 'y' }, /arguments\.title must be string, not object/],
      [{ title: 'x', body: 'y', colour: 'red' }, /arguments\.colour isn't a known argument/],
      [{ title: 'x'.repeat(121), body: 'y' }, /at most 120 characters/],
    ];
    for (const [args, why] of cases) {
      const r = await mcp(k, '/mcp', 'tools/call', { name: 'create_note', arguments: args }, t.access_token);
      assert.equal(r.body.result.isError, true);
      assert.match(r.body.result.content[0].text, why);
    }
    assert.equal(k.rows('SELECT * FROM notes WHERE owner_id IS NOT NULL').length, 0);
    const lim = await mcp(k, '/public', 'tools/call', { name: 'search_notes', arguments: { limit: 500 } });
    assert.match(lim.body.result.content[0].text, /at most 50/);
  });

  it('refuses arguments that are not an object with -32602', async () => {
    const k = setup();
    const r = await mcp(k, '/public', 'tools/call', { name: 'server_time', arguments: ['x'] });
    assert.equal(r.body.error.code, -32602);
  });

  // A bare % would match every note if it reached LIKE unescaped.
  it('treats % and _ in a search as plain characters', async () => {
    const k = setup();
    const r = await mcp(k, '/public', 'tools/call', { name: 'search_notes', arguments: { query: '%' } });
    assert.equal(r.body.result.structuredContent.notes.length, 0);
  });
});

describe('audit of refusals', () => {
  it('records refused calls too', async () => {
    const k = setup();
    const t = await connect(k, { write: false });
    await mcp(k, '/public', 'tools/call', { name: 'create_note', arguments: {} });
    await mcp(k, '/mcp', 'tools/call', { name: 'create_note', arguments: { title: 'x', body: 'y' } }, t.access_token);
    await mcp(k, '/mcp', 'tools/call', { name: 'audit_log', arguments: {} }, t.access_token);
    const calls = k.rows('SELECT tool, user_id, ok, error FROM tool_calls ORDER BY id');
    assert.equal(calls.length, 3);
    assert.ok(calls.every((c) => c.ok === 0));
    assert.equal(calls[0].user_id, null);
    assert.match(String(calls[1].error), /read-only/);
    assert.match(String(calls[2].error), /isn’t available/);
  });
});

describe('Origin check (MCP transports, "Security Warning")', () => {
  const ping = { jsonrpc: '2.0', id: 1, method: 'ping' };

  // A browser page on another site must not reach the endpoint through DNS rebinding.
  it('refuses a foreign Origin with 403, on /public and on /mcp before authentication', async () => {
    const k = setup();
    assert.equal((await post(k, ping, { origin: 'https://evil.example' })).status, 403);
    const t = await connect(k);
    const res = await post(
      k,
      ping,
      { origin: 'https://evil.example', authorization: `Bearer ${t.access_token}` },
      '/mcp',
    );
    assert.equal(res.status, 403);
  });

  it('allows no Origin (server-side and native clients), its own origin, and ALLOWED_ORIGINS', async () => {
    assert.equal((await post(setup(), ping)).status, 200);
    assert.equal((await post(setup(), ping, { origin: 'http://localhost:8787' })).status, 200);
    const listed = setup({ ALLOWED_ORIGINS: 'http://localhost:6274, https://app.example' });
    assert.equal((await post(listed, ping, { origin: 'https://app.example' })).status, 200);
    assert.equal((await post(listed, ping, { origin: 'https://other.example' })).status, 403);
    assert.equal((await post(setup({ ALLOWED_ORIGINS: '*' }), ping, { origin: 'https://any.example' })).status, 200);
  });
});

describe('JSON-RPC edge cases', () => {
  it('refuses a body that is not declared as JSON with 415', async () => {
    const k = setup();
    const ping = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' });
    assert.equal((await post(k, ping, { 'content-type': 'text/plain' })).status, 415);
    assert.equal((await post(k, ping, { 'content-type': 'Application/JSON; charset=utf-8' })).status, 200);
  });

  // MCP: ids are strings or integers, never null. Echoing an object id back would be malformed JSON-RPC.
  it('refuses ids that are objects, null or fractional, and keeps 0 and strings', async () => {
    const k = setup();
    for (const id of [{ a: 1 }, null, 1.5]) {
      const out = (await (await post(k, { jsonrpc: '2.0', id, method: 'ping' })).json()) as any;
      assert.deepEqual([out.id, out.error.code], [null, -32600], JSON.stringify(id));
    }
    for (const id of [0, 'abc']) {
      const out = (await (await post(k, { jsonrpc: '2.0', id, method: 'ping' })).json()) as any;
      assert.deepEqual([out.id, out.result], [id, {}]);
    }
  });

  it('refuses params that are not an object with -32602', async () => {
    const k = setup();
    const out = (await (await post(k, { jsonrpc: '2.0', id: 1, method: 'tools/list', params: 'x' })).json()) as any;
    assert.equal(out.error.code, -32602);
  });

  // MCP 2025-03-26 lifecycle: initialize MUST NOT be part of a batch.
  it('refuses initialize inside a batch but answers the rest', async () => {
    const k = setup();
    const out = (await (
      await post(k, [
        { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } },
        { jsonrpc: '2.0', id: 2, method: 'ping' },
      ])
    ).json()) as any[];
    assert.equal(out[0].error.code, -32600);
    assert.deepEqual(out[1].result, {});
  });

  it('answers DELETE on the endpoint with 405 (no sessions to end)', async () => {
    const k = setup();
    assert.equal((await k.call('/mcp', { method: 'DELETE' })).status, 405);
  });

  // RFC 7235 §2.1: auth scheme names are case-insensitive.
  it('accepts the bearer scheme in any case', async () => {
    const k = setup();
    const t = await connect(k);
    const res = await post(
      k,
      { jsonrpc: '2.0', id: 1, method: 'ping' },
      { authorization: `bearer ${t.access_token}` },
      '/mcp',
    );
    assert.equal(res.status, 200);
  });
});

describe('argument checking: inherited property names', () => {
  // "constructor", "toString" and "__proto__" exist on every object's prototype; they must still count as unknown.
  it('refuses prototype keys under additionalProperties: false', async () => {
    const k = setup();
    for (const key of ['constructor', 'toString', '__proto__']) {
      const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"server_time","arguments":{"${key}":1}}}`;
      const out = (await (await post(k, body)).json()) as any;
      assert.equal(out.result.isError, true, key);
      assert.match(out.result.content[0].text, /isn't a known argument/);
    }
  });
});

describe('audit trail privacy', () => {
  // The validator's message quotes the caller's argument names; the audit row must not.
  it('never stores what the caller typed, even in a validation error', async () => {
    const k = setup();
    const r = await mcp(k, '/public', 'tools/call', { name: 'server_time', arguments: { 'patient 123-45-6789': 1 } });
    assert.match(r.body.result.content[0].text, /patient 123-45-6789/, 'the assistant still sees what to fix');
    const [row] = k.rows('SELECT ok, error FROM tool_calls');
    assert.deepEqual(row, { ok: 0, error: 'Arguments didn’t match the tool’s inputSchema.' });
  });
});

describe('my_connections', () => {
  // A grant whose code was never exchanged, or that passed GRANT_MAX_DAYS, is not a connection any more.
  it('lists only live connections', async () => {
    const k = setup();
    const old = await connect(k, { name: 'Alice' });
    const { authorizeFlow, pkce, registerClient } = await import('./helpers.ts');
    const abandoned = await registerClient(k);
    await authorizeFlow(k, abandoned.client_id, (await pkce()).challenge, { name: 'Alice' });
    k.db.sqlite.exec(
      `UPDATE oauth_grants SET created_at = datetime('now', '-40 days') WHERE client_id = '${old.clientId}'`,
    );
    k.db.sqlite.exec(
      `UPDATE oauth_tokens SET expires_at = datetime('now', '-10 days') WHERE client_id = '${old.clientId}'`,
    );
    const current = await connect(k, { name: 'Alice' });
    const r = await mcp(k, '/mcp', 'tools/call', { name: 'my_connections', arguments: {} }, current.access_token);
    const list = r.body.result.structuredContent.connections;
    assert.equal(list.length, 1);
    assert.equal(list[0].this_connection, true);
  });
});

describe('optional rate limiter', () => {
  it('answers 429 on anonymous endpoints when the RATE_LIMITER binding says no', async () => {
    const keys: string[] = [];
    const RATE_LIMITER = { limit: async ({ key }: { key: string }) => (keys.push(key), { success: false }) };
    const k = setup({ DEV_LOGIN: '1', RATE_LIMITER });
    const res = await post(
      k,
      { jsonrpc: '2.0', id: 1, method: 'ping' },
      { 'cf-connecting-ip': '2001:db8:1:2:3:4:5:6' },
    );
    assert.equal(res.status, 429);
    assert.deepEqual(keys, ['2001:db8:1:2::/64'], 'keyed by IPv6 /64, not by address');
    assert.equal((await k.call('/.well-known/oauth-authorization-server')).status, 200, 'metadata is never limited');
  });
});
