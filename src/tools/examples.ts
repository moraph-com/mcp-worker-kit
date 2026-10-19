// Example tools over the demo notes table. Replace them with your own; keep the shape.
import { SERVER } from '../config.ts';
import { revokeGrant } from '../oauth.ts';
import { all, one, q, randomId } from '../util.ts';
import { fail, lim, str, type Tool } from './types.ts';

export const EXAMPLE_TOOLS: Tool[] = [
  {
    name: 'server_time',
    title: 'Server time',
    description: 'The current time on the server (UTC) and the server version. Useful to check the connection works.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: false },
    access: 'public',
    run: async () => ({ now: new Date().toISOString(), server: SERVER.name, version: SERVER.version }),
  },
  {
    name: 'search_notes',
    title: 'Search notes',
    description:
      'Search notes by words in the title or body. Everyone sees public notes; signed in, you also see your own.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Words to look for; empty lists the newest notes.' },
        limit: { type: 'integer', minimum: 1, maximum: 50 },
      },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
    access: 'public',
    async run(c, args) {
      const words = str(args.query, 200).toLowerCase().split(/\s+/).filter(Boolean).slice(0, 8);
      // % and _ in what the person typed are literal characters, not wildcards.
      const like = words.map(() => "(lower(title) LIKE ? ESCAPE '\\' OR lower(body) LIKE ? ESCAPE '\\')").join(' AND ');
      const binds = words.map((w) => `%${w.replace(/[\\%_]/g, '\\$&')}%`).flatMap((p) => [p, p]);
      const notes = await all(
        c.env,
        `SELECT id, title, body, created_at, owner_id IS NOT NULL AS private FROM notes
        WHERE (owner_id IS NULL OR owner_id = ?)${like ? ` AND ${like}` : ''} ORDER BY created_at DESC, id LIMIT ?`,
        c.user?.id ?? '',
        ...binds,
        lim(args.limit),
      );
      return { notes: notes.map((n) => ({ ...n, private: !!n.private })) };
    },
  },
  {
    name: 'create_note',
    title: 'Create a note',
    description: 'Save a private note for the signed-in person. Confirm the text with them first.',
    inputSchema: {
      type: 'object',
      properties: { title: { type: 'string', maxLength: 120 }, body: { type: 'string', maxLength: 4000 } },
      required: ['title', 'body'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    access: 'signed_in',
    write: true,
    async run(c, args) {
      const title = str(args.title, 120) || fail('A note needs a title.');
      const body = str(args.body, 4000) || fail('A note needs some text.');
      const id = `note_${randomId(8)}`;
      await q(
        c.env,
        'INSERT INTO notes (id, owner_id, title, body) VALUES (?, ?, ?, ?)',
        id,
        c.user!.id,
        title,
        body,
      ).run();
      return { id, title, saved: true };
    },
  },
  {
    name: 'audit_log',
    title: 'Audit log',
    description:
      'Recent tool calls on this server: who, which tool, outcome and time taken (never arguments or results). Admins only.',
    inputSchema: {
      type: 'object',
      properties: { limit: { type: 'integer', minimum: 1, maximum: 50 } },
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
    access: (u) => u.roles.includes('admin'),
    run: async (c, args) => ({
      calls: await all(
        c.env,
        'SELECT tool, user_id, ok, error, ms, created_at FROM tool_calls ORDER BY id DESC LIMIT ?',
        lim(args.limit),
      ),
    }),
  },
];

/** Every person can see and end their own connections, even on a read-only connection. */
export const CONNECTION_TOOLS: Tool[] = [
  {
    name: 'my_connections',
    title: 'My connections',
    description: 'The assistants connected to your account: name, what they may do, when connected and last used.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: false },
    access: 'signed_in',
    run: async (c) => ({
      connections: (
        await all<{ id: string; name: string; scopes: string; created_at: string; last_used_at: string | null }>(
          c.env,
          `SELECT g.id, c.name, g.scopes, g.created_at, g.last_used_at FROM oauth_grants g JOIN oauth_clients c ON c.id = g.client_id
         WHERE g.user_id = ? AND g.revoked_at IS NULL ORDER BY g.created_at DESC`,
          c.user!.id,
        )
      ).map((g) => ({ ...g, scopes: g.scopes.split(' '), this_connection: g.id === c.grant?.id })),
    }),
  },
  {
    name: 'revoke_connection',
    title: 'Revoke a connection',
    description:
      'End one of your connections (from my_connections). Ending this_connection disconnects this assistant now.',
    inputSchema: {
      type: 'object',
      properties: { connection_id: { type: 'string' } },
      required: ['connection_id'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
    access: 'signed_in',
    async run(c, args) {
      const id = str(args.connection_id, 64);
      const g = await one(
        c.env,
        'SELECT id FROM oauth_grants WHERE id = ? AND user_id = ? AND revoked_at IS NULL',
        id,
        c.user!.id,
      );
      if (!g) fail('No active connection of yours has that id. Use my_connections to list them.');
      await revokeGrant(c.env, id, `user:${c.user!.id}`);
      return { revoked: id };
    },
  },
];
