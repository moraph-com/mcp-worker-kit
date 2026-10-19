// A small D1 stand-in over node:sqlite, enough for these tests: prepare/bind/first/all/run/raw and batch (in one
// transaction, as D1 runs it). Migrations are applied from migrations/ in order.
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';

const norm = (v: unknown): SQLInputValue => (v === undefined ? null : typeof v === 'boolean' ? (v ? 1 : 0) : (v as SQLInputValue));
const plain = <T>(r: unknown) => ({ ...(r as object) }) as T;

class Statement {
  db: DatabaseSync;
  sql: string;
  args: SQLInputValue[];
  constructor(db: DatabaseSync, sql: string, args: SQLInputValue[] = []) { this.db = db; this.sql = sql; this.args = args; }
  bind(...args: unknown[]) { return new Statement(this.db, this.sql, args.map(norm)); }
  async first<T>(col?: string): Promise<T | null> {
    const r = this.db.prepare(this.sql).get(...this.args);
    if (!r) return null;
    return (col ? (r as Record<string, unknown>)[col] : plain(r)) as T;
  }
  async all<T>() { return { success: true, results: this.db.prepare(this.sql).all(...this.args).map((r) => plain<T>(r)), meta: {} }; }
  async run() {
    const r = this.db.prepare(this.sql).run(...this.args);
    return { success: true, results: [], meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } };
  }
  async raw() { return this.db.prepare(this.sql).all(...this.args).map((r) => Object.values(r as object)); }
  runSync() { return this.db.prepare(this.sql).run(...this.args); }
}

export function createD1() {
  const db = new DatabaseSync(':memory:');
  const dir = join(import.meta.dirname, '..', 'migrations');
  for (const f of readdirSync(dir).filter((f) => f.endsWith('.sql')).sort()) db.exec(readFileSync(join(dir, f), 'utf8'));
  return {
    sqlite: db,
    prepare: (sql: string) => new Statement(db, sql),
    async batch(stmts: Statement[]) {
      db.exec('BEGIN');
      try {
        const out = stmts.map((s) => { s.runSync(); return { success: true, results: [], meta: {} }; });
        db.exec('COMMIT');
        return out;
      } catch (e) {
        db.exec('ROLLBACK');
        throw e;
      }
    },
    async exec(sql: string) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}
