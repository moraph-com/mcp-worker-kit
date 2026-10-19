# Security policy

## Reporting a vulnerability

Please report security problems privately, not in public issues:

- **Email:** security@moraph.com
- **GitHub:** [report a vulnerability](https://github.com/moraph-com/mcp-worker-kit/security/advisories/new) (private advisory)

Include what you found, how to reproduce it, and what an attacker could do with it. We'll acknowledge your report,
keep you updated while we work on a fix, and credit you in the advisory if you'd like.

Moraph's wider vulnerability-reporting policy is at https://trust.moraph.com/vulnerability-reporting.

## Supported versions

Fixes go into the latest release on `main`. This kit is a starting point that you copy and change, so watch the
repository's releases and advisories and apply fixes to your copy.

## Scope

In scope: the OAuth server (`src/oauth.ts`), the MCP endpoint and tool filtering (`src/mcp.ts`), the identity
providers (`src/identity.ts`), and anything else in this repository.

Out of scope: tools you add yourself, your identity provider's own security, and Cloudflare's platform. Report those to
their owners.
