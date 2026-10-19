/**
 * @file The Worker's bindings and settings, as declared in `wrangler.jsonc` (vars and bindings) or set with
 * `wrangler secret put` (secrets).
 *
 * Every optional setting is off when it is unset or empty, and "off" is always the safer behaviour: no sign-in, no
 * development login, no extra allowed origins.
 */
export interface Env {
  /** The D1 database: OAuth state, users, the audit trail and the example notes (`migrations/`). */
  DB: D1Database;

  /**
   * The Cloudflare Access team domain, e.g. `yourteam.cloudflareaccess.com`. Together with `ACCESS_AUD`, this turns on
   * Access sign-in (`identity.ts`).
   */
  ACCESS_TEAM_DOMAIN?: string;
  /** The Access application's audience (AUD) tag. The Access JWT verifier checks a token's `aud` claim against it. */
  ACCESS_AUD?: string;
  /** Comma-separated emails that get the `admin` role under Access sign-in. Re-read on every tool call. */
  ADMIN_EMAILS?: string;

  /**
   * `"1"` turns on the name-only development sign-in, and only on `localhost` / `127.0.0.1`. Set it in `.dev.vars` and
   * never in production. The hostname check means it does nothing on a real host anyway.
   */
  DEV_LOGIN?: string;

  /**
   * A secret salt for the per-network keys stored with registrations and authorization requests (`util.networkKey`).
   * Set it with `wrangler secret put IP_SALT`. Without it, the stored hashes can be reversed to IP addresses.
   */
  IP_SALT?: string;

  /**
   * Browser origins, besides this server's own, allowed to call `/mcp` and `/public` (comma-separated, e.g.
   * `http://localhost:6274` for the MCP Inspector's direct mode), or `*` for any.
   *
   * MCP requires servers to check `Origin` against DNS rebinding (Streamable HTTP, "Security Warning"). Requests
   * without an `Origin` header (assistants calling from their servers, native apps) are always allowed. See
   * `allowedOrigin` in `index.ts`.
   */
  ALLOWED_ORIGINS?: string;

  /**
   * Optional Workers Rate Limiting binding. When it's bound, every anonymous endpoint (`/public`,
   * `/oauth/register`, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`) is limited per network. The binding is
   * commented out in `wrangler.jsonc`, which explains when to turn it on.
   */
  RATE_LIMITER?: RateLimit;
}
