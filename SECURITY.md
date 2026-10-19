# Security policy

## Reporting a vulnerability

Please report security problems privately, not in public issues:

- **Email:** security@moraph.com
- **GitHub:** [report a vulnerability](https://github.com/moraph-com/mcp-worker-kit/security/advisories/new) (private advisory)

Include what you found, how to reproduce it, and what an attacker could do with it. We'll acknowledge your report,
keep you updated while we work on a fix, and credit you in the advisory if you'd like.

Moraph's wider vulnerability-reporting policy is at https://trust.moraph.com/vulnerability-reporting.

## Hardening checklist for your deployment

- Set `IP_SALT` as a secret (`npx wrangler secret put IP_SALT`).
- Protect only `/oauth/continue` with Cloudflare Access, or plug in your own `IdentityProvider`. Never set `DEV_LOGIN`
  outside `.dev.vars`.
- Keep `ALLOWED_ORIGINS` empty unless a browser-based client needs it.
- Turn on the `RATE_LIMITER` binding (see `wrangler.jsonc`) or Cloudflare WAF rate limiting if `/public` faces the
  internet.
- Review `src/config.ts`: token lifetimes, `GRANT_MAX_DAYS` and audit retention should match your own policies.

## Supported versions

Fixes go into the latest release on `main`. This kit is a starting point that you copy and change, so watch the
repository's releases and advisories and apply fixes to your copy.

## Scope

In scope: the OAuth server (`src/oauth.ts`), the MCP endpoint and tool filtering (`src/mcp.ts`), the identity
providers (`src/identity.ts`), argument checking (`src/tools/validate.ts`), the shared helpers (`src/util.ts`), the
schema (`migrations/`), and anything else in this repository. That includes the claims in the README's
"Security model": if the code doesn't do what it says there, that's a vulnerability.

Out of scope: tools you add yourself, your identity provider's own security, and Cloudflare's platform. Report those to
their owners.
