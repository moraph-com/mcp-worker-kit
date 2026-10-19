// The Worker's bindings and settings (wrangler.jsonc). Optional values are off when empty.
export interface Env {
  DB: D1Database;
  /** Cloudflare Access team domain, e.g. "yourteam.cloudflareaccess.com". With ACCESS_AUD, turns on Access sign-in. */
  ACCESS_TEAM_DOMAIN?: string;
  /** The Access application's audience (AUD) tag. */
  ACCESS_AUD?: string;
  /** Comma-separated emails that get the "admin" role (Access sign-in). */
  ADMIN_EMAILS?: string;
  /** "1" turns on the name-only development sign-in, on localhost only. Set it in .dev.vars, never in production. */
  DEV_LOGIN?: string;
  /** Optional salt for hashing client IP addresses (registration rate limit). */
  IP_SALT?: string;
}
