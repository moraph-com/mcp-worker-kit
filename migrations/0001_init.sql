-- mcp-worker-kit: OAuth 2.1 for MCP clients acting for a signed-in person, plus the tool-call audit trail.
-- Every secret (client secrets, codes, tokens, sessions) is stored as its SHA-256 only.

-- People who have connected an assistant, as the identity provider described them (src/identity.ts).
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,                         -- provider-scoped, e.g. access:<sub> or dev:<name>
  name TEXT NOT NULL,
  email TEXT,
  roles TEXT NOT NULL DEFAULT '[]',            -- JSON array
  disabled_at TEXT,                            -- set to stop every connection at once
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Assistants that registered themselves (dynamic client registration, RFC 7591).
CREATE TABLE IF NOT EXISTS oauth_clients (
  id TEXT PRIMARY KEY,                         -- client_id
  name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,                 -- JSON array
  secret_hash TEXT,                            -- NULL: public client (PKCE only)
  uri TEXT,
  ip_hash TEXT,                                -- for the registration rate limit
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS oauth_clients_ip ON oauth_clients(ip_hash, created_at);

-- An authorization request in progress (the browser is signing in or looking at the consent screen).
-- browser_hash ties it to the browser that started it, through a cookie.
CREATE TABLE IF NOT EXISTS oauth_requests (
  id TEXT PRIMARY KEY,
  browser_hash TEXT NOT NULL,
  client_id TEXT NOT NULL,
  params TEXT NOT NULL,                        -- JSON: redirect_uri, state, code_challenge, scopes, resource
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- What a person allowed an assistant to do. Revoking a grant ends all of its tokens.
CREATE TABLE IF NOT EXISTS oauth_grants (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  scopes TEXT NOT NULL,                        -- space-separated: read write
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  revoked_at TEXT,
  revoked_by TEXT
);
CREATE INDEX IF NOT EXISTS oauth_grants_user ON oauth_grants(user_id);

-- Authorization codes (5 minutes, single use, PKCE S256).
CREATE TABLE IF NOT EXISTS oauth_codes (
  code_hash TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  resource TEXT,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

-- Access tokens (1 hour) and refresh tokens (30 days, rotated on use; reusing one revokes the grant).
CREATE TABLE IF NOT EXISTS oauth_tokens (
  token_hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL,                          -- access | refresh
  grant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
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
  error TEXT,                                  -- the message the assistant saw, at most 200 characters
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
