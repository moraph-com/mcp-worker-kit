-- mcp-worker-kit: OAuth 2.1 for MCP clients acting for a signed-in person, plus the tool-call audit trail.
--
-- Conventions:
-- * Every secret (client secrets, codes, tokens, sessions) is stored as its SHA-256 only (src/util.ts sha256).
-- * Every timestamp is TEXT in SQLite's datetime('now') format, UTC ('YYYY-MM-DD HH:MM:SS'). The code writes the same
--   format (src/util.ts sqlTime), so comparing timestamps as text gives chronological order.
-- * Every table that anonymous requests can write to is cleaned up daily (src/oauth.ts daily()).

-- People who have connected an assistant, as the identity provider described them (src/identity.ts).
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,                         -- provider-scoped, e.g. access:<sub> or dev:<name>
  name TEXT NOT NULL,
  email TEXT,
  roles TEXT NOT NULL DEFAULT '[]',            -- JSON array of strings
  disabled_at TEXT,                            -- set it to stop every connection of this person at once
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Assistants that registered themselves (dynamic client registration, RFC 7591).
CREATE TABLE IF NOT EXISTS oauth_clients (
  id TEXT PRIMARY KEY,                         -- client_id: client_<32 hex>
  name TEXT NOT NULL,                          -- client_name, shown on the consent screen
  redirect_uris TEXT NOT NULL,                 -- JSON array, matched exactly (src/oauth.ts redirectMatches)
  secret_hash TEXT,                            -- NULL: a public client (PKCE only)
  uri TEXT,                                    -- client_uri, https only
  network_hash TEXT,                           -- salted hash of the registering network, for the rate limit
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS oauth_clients_network ON oauth_clients(network_hash, created_at);

-- An authorization request in progress: the browser is signing in or looking at the consent screen.
-- browser_hash ties it to the browser that started it, through an HttpOnly __Host- cookie.
CREATE TABLE IF NOT EXISTS oauth_requests (
  id TEXT PRIMARY KEY,
  browser_hash TEXT NOT NULL,
  client_id TEXT NOT NULL,
  params TEXT NOT NULL,                        -- JSON: redirect_uri, state, code_challenge, scopes, resource
  network_hash TEXT NOT NULL,                  -- for the per-network limit on pending requests
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS oauth_requests_network ON oauth_requests(network_hash, created_at);
CREATE INDEX IF NOT EXISTS oauth_requests_client ON oauth_requests(client_id);

-- A connection: what a person allowed one assistant to do. Revoking a grant ends all of its tokens.
CREATE TABLE IF NOT EXISTS oauth_grants (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  scopes TEXT NOT NULL,                        -- space-separated: read, or read write
  created_at TEXT NOT NULL DEFAULT (datetime('now')),  -- the grant ends GRANT_MAX_DAYS after this, however refreshed
  last_used_at TEXT,                           -- updated at most every 5 minutes
  revoked_at TEXT,
  revoked_by TEXT                              -- client | code_reuse | refresh_reuse | user:<id>
);
CREATE INDEX IF NOT EXISTS oauth_grants_user ON oauth_grants(user_id);
CREATE INDEX IF NOT EXISTS oauth_grants_client ON oauth_grants(client_id);

-- Authorization codes: 5 minutes, single use, PKCE S256.
CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,                  -- the exact URI the code was sent to
  code_challenge TEXT NOT NULL,                -- base64url(SHA-256(code_verifier))
  resource TEXT NOT NULL,                      -- RFC 8707: the resource the tokens will be for (<origin>/mcp)
  expires_at TEXT NOT NULL,
  used_at TEXT                                 -- set atomically on exchange; a second exchange revokes the grant
);

-- Access tokens (1 hour) and refresh tokens (30 days, rotated on use; reusing one revokes the grant).
CREATE TABLE IF NOT EXISTS oauth_tokens (
  token_hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL,                          -- access | refresh
  grant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  resource TEXT NOT NULL,                      -- audience: the token works only at this resource
  expires_at TEXT NOT NULL,
  used_at TEXT,                                -- refresh tokens only: set when rotated or revoked
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS oauth_tokens_grant ON oauth_tokens(grant_id);

-- Browser sessions for the development sign-in only (src/identity.ts devProvider).
CREATE TABLE IF NOT EXISTS dev_sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

-- Every tool call: who, which tool, outcome, time taken. Never arguments or results.
CREATE TABLE IF NOT EXISTS tool_calls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  grant_id TEXT,                               -- NULL: the public endpoint
  user_id TEXT,
  tool TEXT NOT NULL,
  ok INTEGER NOT NULL,
  error TEXT,                                  -- the refusal or tool error, at most 200 characters; never caller input
  ms INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS tool_calls_created ON tool_calls(created_at);

-- Demo data for the example tools (src/tools/examples.ts). Drop it when you replace them.
CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY,
  owner_id TEXT,                               -- NULL: a public note
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
INSERT OR IGNORE INTO notes (id, owner_id, title, body) VALUES
  ('welcome', NULL, 'Welcome', 'This server is built from mcp-worker-kit. Public notes are visible to everyone.'),
  ('scopes', NULL, 'Read and write', 'Signed-in assistants can always read. They can create notes only if the person allowed actions on the consent screen.');
