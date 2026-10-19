# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-19

First public release.

### Added

- Remote MCP server on Cloudflare Workers: Streamable HTTP with stateless JSON responses, protocol versions
  2024-11-05 to 2025-11-25 (checked through the `MCP-Protocol-Version` header), notifications, and batches for the
  versions that have them.
- `/public` endpoint for anonymous use and `/mcp` endpoint behind OAuth.
- OAuth 2.1 authorization server: protected-resource and authorization-server metadata, dynamic client registration,
  authorization code with PKCE S256, rotating refresh tokens with reuse detection, revocation, and resource indicators
  at both authorize and token. Tokens are bound to the resource they were issued for. Loopback redirect URIs match on
  any port. Codes and refresh tokens are claimed atomically, so a race counts as reuse. Connections last at most
  `GRANT_MAX_DAYS`. Every secret is stored as its SHA-256 only.
- Authorization errors are shown on a page with a link back instead of an automatic redirect, so open registration
  can't turn the server into an open redirector (RFC 9700 §4.11.2). The consent screen warns when the assistant
  returns to a loopback address or an app scheme.
- `IdentityProvider` interface, with Cloudflare Access JWT verification (RS256 only, JWKS cached with throttled,
  time-limited refetches, roles re-read on every call) and a localhost-only development sign-in.
- Tool model with `public`, `signed_in` and custom access rules, a `write` flag tied to the `write` scope, and
  `inputSchema` enforced (own properties only) before a tool runs. Tool names are checked at startup.
- Audit trail of every tool call, refusals included. It never stores arguments, results or caller-chosen text. A
  daily clean-up cron removes expired rows, grants and audit records older than `AUDIT_DAYS`, and registered clients
  that never connected. `my_connections` lists live connections only.
- `Origin` check on the MCP endpoints (403 for origins outside `ALLOWED_ORIGINS`).
- Abuse limits: request bodies capped and counted in bytes while reading (forms included). Registrations and pending
  authorization requests are limited per network (IPv4 address or IPv6 /64, salted with `IP_SALT`). An optional
  Workers Rate Limiting binding covers the anonymous endpoints.
- Example tools: `server_time`, `search_notes`, `create_note`, `audit_log`, `my_connections` and `revoke_connection`.
- Tooling: TypeScript type checks, ESLint (typescript-eslint, type-aware), Prettier, `node:test` suite against an
  in-memory D1, CI on Node 22 and 24 with SHA-pinned actions, Dependabot, issue and PR templates, Code of Conduct.

[Unreleased]: https://github.com/moraph-com/mcp-worker-kit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/moraph-com/mcp-worker-kit/releases/tag/v0.1.0
