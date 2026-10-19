/**
 * @file Small helpers shared by the OAuth server (`oauth.ts`), the MCP endpoint (`mcp.ts`) and the sign-in providers
 * (`identity.ts`).
 *
 * Nothing here knows about OAuth or MCP. The helpers fall into five groups:
 *
 * - **Crypto and encoding:** random identifiers, SHA-256, base64url. Every secret the server issues is
 *   `randomId(32)`, which is 256 bits from the platform CSPRNG, and only its SHA-256 is stored.
 * - **D1 shorthands:** `q`, `all`, `one`. Every query binds its values, so no SQL is ever built from input.
 * - **Request reading:** a byte-counted body reader, form parsing, cookies, same-origin checks, safe redirect paths.
 * - **Abuse control:** the per-network key that rate limits are counted against.
 * - **Responses:** JSON with CORS, and HTML pages with a strict Content-Security-Policy.
 */
import type { Env } from './env.ts';

const enc = new TextEncoder();
const hex = (buf: ArrayBuffer | Uint8Array) =>
  Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');

// ---------------------------------------------------------------- crypto and encoding

/**
 * A random identifier: `bytes` bytes from `crypto.getRandomValues`, as lowercase hex.
 *
 * @param bytes - How many random bytes. The default of 16 gives 128 bits, enough for identifiers that aren't secrets.
 *   Secrets (tokens, codes, client secrets) use 32 bytes.
 * @returns `2 × bytes` hex characters.
 */
export const randomId = (bytes = 16): string => hex(crypto.getRandomValues(new Uint8Array(bytes)));

/**
 * SHA-256 of a UTF-8 string, as lowercase hex.
 *
 * This is how secrets are stored. The secrets are 256-bit random values, so a fast unsalted hash is the right tool:
 * there is nothing to brute-force, and a lookup by hash needs the hash to be deterministic. Comparing these hashes
 * with `===` doesn't leak anything useful through timing, because the attacker can't choose the hash's input
 * byte by byte.
 */
export const sha256 = async (s: string): Promise<string> => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));

/** Base64url without padding (RFC 4648 §5), as PKCE (RFC 7636 §4.2) and JWTs (RFC 7515 §2) use it. */
export const b64url = (buf: ArrayBuffer | Uint8Array): string =>
  // Spreading into fromCharCode is fine for digests and signatures. It would overflow the stack for megabytes.
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

/**
 * Decodes base64url, with or without padding.
 *
 * @throws DOMException (`InvalidCharacterError`) if `s` isn't base64url. Callers that parse untrusted input (the JWT
 *   verifier) catch it.
 */
export const b64urlDecode = (s: string): Uint8Array =>
  Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)), (c) =>
    c.charCodeAt(0),
  );

/**
 * A time in SQLite's `datetime('now')` format (`YYYY-MM-DD HH:MM:SS`, UTC).
 *
 * Every timestamp column is stored this way, so comparing a column with `sqlTime(...)` is a plain text comparison,
 * and that comparison is also chronological. Mixing in ISO strings with a `T` would quietly break every `<` and `>`.
 */
export const sqlTime = (ms: number): string => new Date(ms).toISOString().replace('T', ' ').slice(0, 19);

/** Parses a `sqlTime` / `datetime('now')` string back to epoch milliseconds (UTC). */
export const fromSqlTime = (s: string): number => Date.parse(`${s.replace(' ', 'T')}Z`);

// ---------------------------------------------------------------- text

const asText = (v: unknown): string =>
  typeof v === 'string' ? v : typeof v === 'number' || typeof v === 'boolean' ? String(v) : '';

/**
 * Escapes text for HTML element content and quoted attribute values.
 *
 * Every value interpolated into the server's HTML goes through this function: client names, user names, hosts and tool
 * descriptions. Non-text values become an empty string rather than `[object Object]`.
 */
export const esc = (s: unknown): string =>
  asText(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

/**
 * One line of display text from untrusted input.
 *
 * Control characters become spaces, so a client name can't break a log line or a header. The result is trimmed and
 * cut to `max` characters. Anything that isn't a string, number or boolean becomes `''`.
 */
export const clean = (v: unknown, max = 200): string =>
  asText(v)
    // eslint-disable-next-line no-control-regex -- matching control characters is the point
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .trim()
    .slice(0, max);

// ---------------------------------------------------------------- D1

/** A prepared, bound statement. Values are always bound and never concatenated into the SQL. */
export const q = (env: Env, sql: string, ...b: unknown[]): D1PreparedStatement => env.DB.prepare(sql).bind(...b);

/** Every row of a query. */
export const all = async <T = Record<string, unknown>>(env: Env, sql: string, ...b: unknown[]): Promise<T[]> =>
  (await q(env, sql, ...b).all<T>()).results ?? [];

/** The first row of a query, or null. */
export const one = <T = Record<string, unknown>>(env: Env, sql: string, ...b: unknown[]): Promise<T | null> =>
  q(env, sql, ...b).first<T>();

// ---------------------------------------------------------------- reading requests

/**
 * Parses the Cookie header.
 *
 * A malformed percent-escape in another app's cookie on the same host is kept as raw text instead of throwing, so it
 * can't break sign-in. When a name repeats, the last value wins. The cookies this server relies on use the
 * `__Host-` prefix, which a subdomain can't set (RFC 6265bis §4.1.3.2), so a repeat can't be used to plant a value.
 */
export function parseCookies(request: Request): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (request.headers.get('cookie') || '').split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    const name = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    try {
      out[name] = decodeURIComponent(v);
    } catch {
      out[name] = v;
    }
  }
  return out;
}

/**
 * Whether a state-changing form post came from this site. This is the CSRF check for the consent and sign-in forms.
 *
 * Browsers send `Origin` on every cross-origin POST and on same-origin POSTs in practice. `Sec-Fetch-Site` is the
 * fallback for the rare same-origin POST that has no `Origin`. When neither header is present, the post is refused.
 * Script-free HTML forms have no other way to prove where they came from.
 */
export function sameOrigin(request: Request): boolean {
  const origin = request.headers.get('origin');
  if (origin) return origin === new URL(request.url).origin;
  return request.headers.get('sec-fetch-site') === 'same-origin';
}

/**
 * A path on this site to return to after signing in. It is always relative and never names another host, so it can't
 * be used as an open redirect.
 *
 * Control characters and backslashes are refused outright. Browsers drop tabs and newlines from URLs and read `\` as
 * `/`, so `"/\t/evil"` and `"/\\evil"` both mean `"//evil"`, which is protocol-relative and points at another host.
 *
 * @returns `next` itself (cut to 500 characters) if it is safe, otherwise `/`.
 */
export const safeNext = (next: unknown): string => {
  const s = typeof next === 'string' && next ? next : '/';
  // eslint-disable-next-line no-control-regex -- matching control characters is the point
  return s.startsWith('/') && !s.startsWith('//') && !/[\u0000-\u001f\u007f\\]/.test(s) ? s.slice(0, 500) : '/';
};

/**
 * Reads the request body as UTF-8 text, at most `max` bytes.
 *
 * `request.text()`, `.json()` and `.formData()` buffer the whole body before you can look at its size. Cloudflare
 * accepts bodies of 100 MB or more, while an isolate has 128 MB of memory. This reader gives up as soon as either the
 * declared `Content-Length` or the bytes actually received go over `max`, so an oversized body never sits in memory.
 * Chunked uploads don't declare a length, which is why the bytes are counted as they arrive as well.
 *
 * @returns The text, `''` when there's no body, or `null` when the body is larger than `max`.
 */
export async function readBody(request: Request, max: number): Promise<string | null> {
  const declared = Number(request.headers.get('content-length'));
  if (declared > max) return null;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = (await reader.read()) as ReadableStreamReadResult<Uint8Array>;
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) {
    bytes.set(c, at);
    at += c.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

/**
 * Reads an `application/x-www-form-urlencoded` body of at most `max` bytes.
 *
 * Used for the HTML forms (consent and dev sign-in) instead of `request.formData()`, which has no size limit. These
 * forms have no file inputs, so browsers always send them urlencoded.
 *
 * @returns The fields, or `null` if the body is larger than `max`.
 */
export async function readUrlEncoded(request: Request, max: number): Promise<URLSearchParams | null> {
  const text = await readBody(request, max);
  return text === null ? null : new URLSearchParams(text);
}

/**
 * Whether the request says its body is JSON (`application/json`, with any parameters). The media type is compared
 * case-insensitively (RFC 9110 §8.3.1).
 */
export const isJson = (request: Request): boolean =>
  (request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase() === 'application/json';

// ---------------------------------------------------------------- abuse control

/**
 * The network a request comes from: the full IPv4 address, or the /64 prefix of an IPv6 address.
 *
 * Counting IPv6 per address would make any limit meaningless. The smallest block an ISP or cloud normally assigns
 * to a host is a /64 (RFC 7421), which is 2^64 addresses one machine can rotate through for free.
 */
export function network(ip: string): string {
  if (!ip.includes(':')) return ip;
  // IPv4-mapped addresses (::ffff:192.0.2.1) count as the IPv4 address they carry.
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return mapped[1];
  const [head, tail] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups =
    tail === undefined ? h : [...h, ...Array<string>(Math.max(0, 8 - h.length - t.length)).fill('0'), ...t];
  return `${groups
    .slice(0, 4)
    .map((g) => (parseInt(g, 16) || 0).toString(16))
    .join(':')}::/64`;
}

/**
 * A key for counting requests per network (see `network`), salted with `IP_SALT` and hashed. It is stored in D1 for
 * the registration and authorization limits.
 *
 * Set `IP_SALT` as a secret (`wrangler secret put IP_SALT`). Without it, the stored value is the SHA-256 of an IP
 * address. All 2^32 IPv4 addresses can be hashed in minutes, so without a salt the column effectively holds IP
 * addresses.
 */
export const networkKey = async (request: Request, env: Env): Promise<string> =>
  sha256(`${env.IP_SALT || ''}:${network(request.headers.get('cf-connecting-ip') || 'unknown')}`);

// ---------------------------------------------------------------- responses

/**
 * CORS headers for every JSON response.
 *
 * `*` is safe here because nothing on these endpoints relies on cookies. `/mcp` needs a bearer token, which browsers
 * never attach automatically, and the OAuth endpoints are built to be called from anywhere. Browser-based MCP clients
 * (the MCP Inspector, web apps) need CORS to call them at all. The HTML pages, which do use cookies, send no CORS
 * headers.
 */
export const CORS: Record<string, string> = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type, accept, authorization, mcp-protocol-version, mcp-session-id',
  'access-control-expose-headers': 'mcp-protocol-version, www-authenticate',
};

/**
 * A JSON response with CORS headers and `Cache-Control: no-store`. Token responses must never be cached (RFC 6749
 * §5.1), and `no-store` is the safe default for everything else here.
 *
 * @param extra - Headers to add or override, such as `WWW-Authenticate` or a public cache policy for metadata.
 */
export const json = (body: unknown, status = 200, extra: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...CORS, ...extra },
  });

// ---------------------------------------------------------------- HTML pages (sign-in, consent, errors, info)
const STYLE = `body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#fafafa;color:#1a1a1a}main{max-width:36rem;margin:3rem auto;padding:0 1rem}
h1{font-size:1.5rem;line-height:1.25}code{font:0.9em ui-monospace,monospace;background:#eee;padding:0.1em 0.3em;border-radius:3px}
button,input[type=text]{font:inherit;padding:0.5rem 0.9rem;border-radius:6px;border:1px solid #888}button{background:#1a1a1a;color:#fff;cursor:pointer}
button.ghost{background:transparent;color:inherit}.small{font-size:0.875rem;color:#555}table{border-collapse:collapse}td,th{padding:0.3rem 0.6rem;border-bottom:1px solid #ddd;text-align:left}
.warn{border-left:4px solid #b45309;padding:0.25rem 0.75rem;background:#fef3c7}a{color:inherit}
@media (prefers-color-scheme:dark){body{background:#151515;color:#eee}code{background:#2a2a2a}button{background:#eee;color:#151515}.small{color:#aaa}td,th{border-color:#333}.warn{background:#3b2a07}}`;
let styleHash: Promise<string> | null = null;
const b64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)));

/**
 * An HTML page served with a strict security policy.
 *
 * - **No script can run.** `default-src 'none'` with no `script-src`, so even an escaping bug can't turn into
 *   script execution.
 * - The one inline stylesheet is allowed by its hash, never by `'unsafe-inline'`.
 * - **No framing** (`frame-ancestors 'none'`, plus `X-Frame-Options: DENY` for old browsers). This defends the
 *   consent screen against clickjacking (RFC 9700 §4.16).
 * - **No caching** (`no-store`), because consent and error pages are specific to one person.
 * - `Referrer-Policy: no-referrer`, so the authorization request's URL doesn't leak to the next site
 *   (RFC 9700 §4.2).
 *
 * @param title - Plain text. It is escaped here.
 * @param body - HTML. **The caller escapes every interpolated value with `esc`.**
 * @param status - HTTP status.
 * @param formTargets - Extra `form-action` sources. The consent form posts to this site, which then redirects to the
 *   assistant's address, and browsers apply `form-action` to that redirect too (CSP Level 3 §6.4.1).
 */
export async function page(title: string, body: string, status = 200, formTargets: string[] = []): Promise<Response> {
  styleHash ??= crypto.subtle.digest('SHA-256', enc.encode(STYLE)).then(b64);
  const csp = [
    `default-src 'none'`,
    `style-src 'sha256-${await styleHash}'`,
    `img-src 'self' data:`,
    `form-action 'self' ${formTargets.join(' ')}`.trim(),
    `frame-ancestors 'none'`,
    `base-uri 'none'`,
  ].join('; ');
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)}</title><style>${STYLE}</style></head><body><main>${body}</main></body></html>`;
  return new Response(html, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'content-security-policy': csp,
    },
  });
}
