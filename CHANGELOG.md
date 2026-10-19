# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-19

First public release.

### Added

- Remote MCP server on Cloudflare Workers: Streamable HTTP with stateless JSON responses, protocol versions
  2024-11-05 to 2025-11-25, batches and notifications.
- `/public` endpoint for anonymous use and `/mcp` endpoint behind OAuth.
- OAuth 2.1 authorization server: protected-resource and authorization-server metadata, dynamic client registration with
  a per-network limit, authorization code with PKCE S256, rotating refresh tokens with reuse detection, revocation and
  resource indicators. Every secret is stored as its SHA-256 only.
- `IdentityProvider` interface, with Cloudflare Access JWT verification and a localhost-only development sign-in.
- Tool model with `public`, `signed_in` and custom access rules, and a `write` flag tied to the `write` scope.
- Audit trail of every tool call (no arguments or results) and a daily clean-up cron.
- Example tools: `server_time`, `search_notes`, `create_note`, `audit_log`, `my_connections` and `revoke_connection`.
