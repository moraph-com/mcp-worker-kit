// Small helpers shared by the OAuth server, the MCP endpoint and the sign-in providers.
import type { Env } from './env.ts';

const enc = new TextEncoder();
const hex = (buf: ArrayBuffer | Uint8Array) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');

/** `bytes` random bytes as hex (16 → 32 characters). */
export const randomId = (bytes = 16) => hex(crypto.getRandomValues(new Uint8Array(bytes)));
export const sha256 = async (s: string) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
export const b64url = (buf: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const b64urlDecode = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));

/** A time in SQLite's datetime('now') format, so it compares as text with what the database writes. */
export const sqlTime = (ms: number) => new Date(ms).toISOString().replace('T', ' ').slice(0, 19);

export const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
export const clean = (v: unknown, max = 200) => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);

export const q = (env: Env, sql: string, ...b: unknown[]) => env.DB.prepare(sql).bind(...b);
export const all = async <T = Record<string, unknown>>(env: Env, sql: string, ...b: unknown[]) => ((await q(env, sql, ...b).all<T>()).results || []) as T[];
export const one = <T = Record<string, unknown>>(env: Env, sql: string, ...b: unknown[]) => q(env, sql, ...b).first<T>();

export function parseCookies(request: Request): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (request.headers.get('cookie') || '').split(';')) {
    const i = part.indexOf('=');
    if (i <= 0) continue;
    const v = part.slice(i + 1).trim();
    try { out[part.slice(0, i).trim()] = decodeURIComponent(v); } catch { out[part.slice(0, i).trim()] = v; } // another app's cookie
  }
  return out;
}

/** A form post from this site: the Origin header (or Sec-Fetch-Site) says so. */
export function sameOrigin(request: Request): boolean {
  const origin = request.headers.get('origin');
  if (origin) return origin === new URL(request.url).origin;
  return request.headers.get('sec-fetch-site') === 'same-origin';
}

/**
 * A path on this site to return to after signing in: relative, never another host. Control characters and
 * backslashes are refused outright: browsers drop tabs and newlines and read \ as /, so "/\t/evil" means "//evil".
 */
export const safeNext = (next: unknown) => {
  const s = String(next || '/');
  return s.startsWith('/') && !s.startsWith('//') && !/[\u0000-\u001f\u007f\\]/.test(s) ? s.slice(0, 500) : '/';
};

/**
 * The request body as text, at most `max` bytes, or null if it's bigger. Checks Content-Length first and counts bytes
 * while reading, so an oversized body is never held in memory.
 */
export async function readBody(request: Request, max: number): Promise<string | null> {
  const declared = Number(request.headers.get('content-length'));
  if (declared > max) return null;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) { await reader.cancel(); return null; }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) { all.set(c, at); at += c.byteLength; }
  return new TextDecoder().decode(all);
}

export const ipHash = async (request: Request, env: Env) => sha256(`${env.IP_SALT || ''}:${request.headers.get('cf-connecting-ip') || 'unknown'}`);

export const CORS: Record<string, string> = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type, accept, authorization, mcp-protocol-version, mcp-session-id',
  'access-control-expose-headers': 'mcp-protocol-version, www-authenticate',
};

export const json = (body: unknown, status = 200, extra: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...CORS, ...extra } });

// ---------------------------------------------------------------- HTML pages (sign-in, consent, errors, info)
const STYLE = `body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#fafafa;color:#1a1a1a}main{max-width:36rem;margin:3rem auto;padding:0 1rem}
h1{font-size:1.5rem;line-height:1.25}code{font:0.9em ui-monospace,monospace;background:#eee;padding:0.1em 0.3em;border-radius:3px}
button,input[type=text]{font:inherit;padding:0.5rem 0.9rem;border-radius:6px;border:1px solid #888}button{background:#1a1a1a;color:#fff;cursor:pointer}
button.ghost{background:transparent;color:inherit}.small{font-size:0.875rem;color:#555}table{border-collapse:collapse}td,th{padding:0.3rem 0.6rem;border-bottom:1px solid #ddd;text-align:left}
@media (prefers-color-scheme:dark){body{background:#151515;color:#eee}code{background:#2a2a2a}button{background:#eee;color:#151515}.small{color:#aaa}td,th{border-color:#333}}`;
let styleHash: Promise<string> | null = null;
const b64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)));

/**
 * An HTML page with a strict policy: no scripts at all, the one inline stylesheet allowed by hash, no framing, no
 * caching. formTargets: extra form-action sources (the consent form redirects to the assistant's address, and
 * browsers apply form-action to that redirect).
 */
export async function page(title: string, body: string, status = 200, formTargets: string[] = []): Promise<Response> {
  styleHash ??= crypto.subtle.digest('SHA-256', enc.encode(STYLE)).then(b64);
  const csp = [`default-src 'none'`, `style-src 'sha256-${await styleHash}'`, `img-src 'self' data:`, `form-action 'self' ${formTargets.join(' ')}`.trim(), `frame-ancestors 'none'`, `base-uri 'none'`].join('; ');
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)}</title><style>${STYLE}</style></head><body><main>${body}</main></body></html>`;
  return new Response(html, {
    status,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'content-security-policy': csp },
  });
}
