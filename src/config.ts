// What this server calls itself and what people can allow an assistant to do. Change these first.

export const SERVER = { name: 'mcp-worker-kit', title: 'MCP Worker Kit', version: '0.1.0' };

/** Newest first: initialize answers with the client's version if it's listed, otherwise the newest. */
export const PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

/** OAuth scopes, as the consent screen describes them. `read` is always granted; `write` only if the person ticks it. */
export const SCOPES: Record<string, string> = {
  read: 'See what your account can see through this server’s tools.',
  write: 'Take everyday actions your account can take through this server’s tools. Never approvals, deletions, payments or access changes.',
};

/** Sent to the assistant on initialize. Say what the data is and how to treat it. */
export function instructions(who: string | null): string {
  return `This server answers from live data${who ? `, as ${who}, limited to what that account may see and do` : ' (public information only: connect to /mcp and sign in for more)'}.
- Quote what tools return exactly; never invent records, people or commitments.
- Before any tool that changes something (not read-only), confirm the details with the person.
- Approvals, access changes and payments happen on the service's own website, not through these tools.`;
}

export const ACCESS_SECONDS = 3600;
export const REFRESH_DAYS = 30;
export const CODE_SECONDS = 300;
export const REQUEST_MINUTES = 15;
/** Dynamic client registrations allowed per network per hour. */
export const REGISTRATIONS_PER_HOUR = 30;
/** How long tool-call records are kept. */
export const AUDIT_DAYS = 395;
