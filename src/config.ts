/**
 * @file What this server calls itself, what people can allow an assistant to do, and how long everything lasts.
 * Change these first when you adopt the kit.
 *
 * Every lifetime and limit lives here, so a security reviewer can see all of them in one place. The defaults follow
 * the OAuth 2.0 Security BCP (RFC 9700): short-lived access tokens, rotating refresh tokens, single-use codes valid
 * for minutes, and a hard cap on how long a connection lasts without the person signing in again.
 */

/** Sent as `serverInfo` on `initialize`, and shown on the info and consent pages. */
export const SERVER = { name: 'mcp-worker-kit', title: 'MCP Worker Kit', version: '0.1.0' };

/**
 * MCP protocol versions this server speaks, newest first. `initialize` answers with the client's version when it's
 * listed and with the newest one otherwise (MCP lifecycle, "Version Negotiation"). A request whose
 * `MCP-Protocol-Version` header names anything else gets 400 (MCP 2025-11-25 transports, "Protocol Version Header").
 */
export const PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

/**
 * OAuth scopes, with the sentence the consent screen shows for each one. `read` is always granted. `write` is
 * granted only if the person ticks the box, so a connection is read-only unless someone actively chose otherwise.
 */
export const SCOPES: Record<string, string> = {
  read: 'See what your account can see through this server’s tools.',
  write:
    'Take everyday actions your account can take through this server’s tools. Never approvals, deletions, payments or access changes.',
};

/**
 * The `instructions` sent to the assistant on `initialize`. Say what the data is and how the assistant should treat
 * it.
 *
 * @param who - The signed-in person's display name, or null on `/public`.
 */
export function instructions(who: string | null): string {
  return `This server answers from live data${who ? `, as ${who}, limited to what that account may see and do` : ' (public information only: connect to /mcp and sign in for more)'}.
- Quote what tools return exactly; never invent records, people or commitments.
- Before any tool that changes something (not read-only), confirm the details with the person.
- Approvals, access changes and payments happen on the service's own website, not through these tools.`;
}

/**
 * Access-token lifetime. Short, because a bearer token works for whoever holds it. One hour bounds the damage from
 * a leaked token, and refreshing every hour costs nothing (MCP 2025-11-25 authorization, "Token Theft": authorization
 * servers SHOULD issue short-lived access tokens).
 */
export const ACCESS_SECONDS = 3600;
/** Refresh-token lifetime. Each refresh replaces the token (rotation, RFC 9700 §4.14.2), and the grant cap below still applies. */
export const REFRESH_DAYS = 30;
/**
 * The longest a connection lasts, however often it's refreshed. After that, the person signs in again through your
 * identity provider. Someone removed there therefore loses their assistants within this time, even when the provider
 * can't be asked directly (Cloudflare Access can't).
 */
export const GRANT_MAX_DAYS = 30;
/** Authorization-code lifetime. RFC 6749 §4.1.2 recommends at most 10 minutes; five is plenty for a redirect. */
export const CODE_SECONDS = 300;
/** How long a started authorization (sign-in, then the consent screen) stays valid. */
export const REQUEST_MINUTES = 15;

/**
 * Dynamic client registrations allowed per network (`util.network`) per hour.
 *
 * Registration is open by design (RFC 7591, and MCP clients rely on it), so this limit is what keeps the table from
 * being flooded. Hosted assistants register from their providers' servers, so many of your users can share one
 * network here. Raise the limit if a large rollout through a hosted assistant hits it.
 */
export const REGISTRATIONS_PER_HOUR = 30;
/**
 * Authorization requests a network may have started in any `REQUEST_MINUTES` window. Each one is a D1 row, and
 * `/oauth/authorize` takes no credentials, so without this limit one script could write rows indefinitely. These
 * requests come from people's browsers, so only a very large office behind a single NAT address gets near the limit.
 */
export const REQUESTS_PER_NETWORK = 60;
/** How long tool-call records are kept (about 13 months). Grants are kept as long, so an audit row's grant still exists. */
export const AUDIT_DAYS = 395;
/** Registered clients that have no connection are removed after this many days. */
export const UNUSED_CLIENT_DAYS = 30;
