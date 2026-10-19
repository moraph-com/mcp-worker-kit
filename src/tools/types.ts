/**
 * @file What a tool is, and what it receives when it runs.
 *
 * A tool is a plain object, listed in `TOOLS` (`tools/index.ts`). Three of its fields decide who can use it, and
 * `toolsFor` in `mcp.ts` applies them in one place:
 *
 * - `access`: who may see and call it at all.
 *   - `'public'`: anyone, including the unauthenticated `/public` endpoint.
 *   - `'signed_in'`: anyone connected through `/mcp`.
 *   - `(user) => boolean`: your own rule, e.g. `(u) => u.roles.includes('admin')`.
 * - `write: true`: the tool changes something. It is hidden from signed-in connections that weren't granted the
 *   `write` scope on the consent screen.
 * - `inputSchema`: checked before `run` (`validate.ts`), so `run` only ever sees arguments that fit it.
 */
import type { Env } from '../env.ts';
import type { User } from '../identity.ts';
import type { Grant } from '../oauth.ts';
import type { Schema } from './validate.ts';

/** Everything a tool's `run` gets besides its arguments. */
export interface ToolContext {
  env: Env;
  ctx: ExecutionContext;
  request: Request;
  url: URL;
  /** The signed-in person, or null on `/public`. **Scope every query to this person.** */
  user: User | null;
  /** The scopes this connection was granted. Empty on `/public`. */
  scopes: Set<string>;
  /** The connection (grant) making the call, or null on `/public`. */
  grant: Grant | null;
}

/**
 * One MCP tool (MCP 2025-11-25 server/tools). `name`, `title`, `description`, `inputSchema` and `annotations` are
 * sent to clients by `tools/list`. `access`, `write` and `run` stay on the server.
 */
export interface Tool {
  /** Unique, 1–128 characters of `A-Z a-z 0-9 _ - .` (checked at startup in `tools/index.ts`). */
  name: string;
  title: string;
  /** What the tool does and when to use it. The assistant reads this to decide whether to call the tool. */
  description: string;
  /** The JSON Schema for the arguments. Enforced before `run`, so the subset `validate.ts` checks is what you can rely on. */
  inputSchema: Schema & { type: 'object' };
  /**
   * Hints for the client (MCP "Tool annotations"). They're advisory and come from you, so clients may not trust
   * them. They are **not** a security boundary. `access` and `write` are.
   */
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
  /** Who may see and call this tool. See the file header. */
  access: 'public' | 'signed_in' | ((user: User) => boolean);
  /** True if the tool changes anything. It then requires the `write` scope on signed-in connections. */
  write?: boolean;
  /**
   * Does the work.
   *
   * @param args - Arguments that already passed `inputSchema`.
   * @returns Structured data. A plain object is also sent as `structuredContent`, and every value is sent as JSON text.
   * @throws {@link ToolError} for a message the assistant should see. Any other error becomes a generic message, and
   *   the details go to the Worker's logs.
   */
  run(c: ToolContext, args: Record<string, unknown>): Promise<unknown>;
}

/**
 * An error whose message the assistant sees, and which is **recorded in the audit log**.
 *
 * Write messages that say what to do next ("A note needs a title."). Never put argument values, record contents or
 * anything else the person typed into them: the audit trail promises to keep no such content.
 */
export class ToolError extends Error {}

/**
 * Throws a {@link ToolError}. Typed `never`, so it works inside expressions: `str(args.title) || fail('…')`.
 *
 * @throws ToolError, always.
 */
export const fail = (msg: string): never => {
  throw new ToolError(msg);
};

/** A string argument, trimmed and cut to `max` characters. Anything that isn't a string becomes `''`. */
export const str = (v: unknown, max = 200): string => (typeof v === 'string' ? v.trim().slice(0, max) : '');

/**
 * A page-size argument: an integer from 1 to `max`, defaulting to `d`. This is a second line of defence: the schema's
 * `minimum` and `maximum` should already have refused anything out of range.
 */
export const lim = (v: unknown, d = 20, max = 50): number =>
  Math.min(Math.max(typeof v === 'number' && Number.isInteger(v) ? v : d, 1), max);
