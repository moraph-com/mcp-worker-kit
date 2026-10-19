// What a tool is, and what it gets when it runs.
//
//   access   'public'      anyone, including the unauthenticated /public endpoint
//            'signed_in'   anyone connected through /mcp
//            (user) => boolean   your own rule, e.g. (u) => u.roles.includes('admin')
//   write    true for tools that change something: hidden from connections that weren't allowed the write scope
//   run      returns structured data (sent as JSON text and structuredContent); throw ToolError for a message the
//            assistant should see. Any other error becomes a generic message and is logged.
import type { Env } from '../env.ts';
import type { User } from '../identity.ts';

export interface ToolContext {
  env: Env;
  ctx: ExecutionContext;
  request: Request;
  url: URL;
  /** null on /public. */
  user: User | null;
  scopes: Set<string>;
  grant: { id: string; client_id: string; user_id: string; scopes: string } | null;
}

export interface Tool {
  name: string;
  title: string;
  description: string;
  inputSchema: { type: 'object'; properties?: Record<string, unknown>; required?: string[]; additionalProperties?: boolean };
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean };
  access: 'public' | 'signed_in' | ((user: User) => boolean);
  write?: boolean;
  run(c: ToolContext, args: Record<string, unknown>): Promise<unknown>;
}

export class ToolError extends Error {}
export const fail = (msg: string): never => { throw new ToolError(msg); };

export const str = (v: unknown, max = 200) => String(v ?? '').trim().slice(0, max);
export const lim = (v: unknown, d = 20, max = 50) => Math.min(Math.max(parseInt(String(v), 10) || d, 1), max);
