/**
 * @file The argument checker (`src/tools/validate.ts`) on its own, plus the small helpers whose edge cases matter for
 * security (`network`, `safeNext`).
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { check, type Schema } from '../src/tools/validate.ts';
import { network, safeNext } from '../src/util.ts';

describe('argument checking (validate.ts)', () => {
  const s: Schema = {
    type: 'object',
    properties: {
      n: { type: 'integer', minimum: 1, maximum: 5 },
      x: { type: 'number' },
      kind: { type: 'string', enum: ['a', 'b'] },
      tags: { type: 'array', items: { type: 'string', maxLength: 3 }, maxItems: 2 },
      maybe: { type: ['string', 'null'] },
      free: { type: 'string', format: 'email', pattern: '.*' },
    },
    required: ['n'],
    additionalProperties: false,
  };
  const ok = [
    { n: 1 },
    { n: 5, x: 1.5, kind: 'a', tags: ['abc'], maybe: null },
    { n: 2, x: 3, maybe: 's' },
    { n: 3, free: 'not checked' },
  ];
  for (const v of ok) it(`accepts ${JSON.stringify(v)}`, () => assert.equal(check(v, s), null));

  const bad: [unknown, RegExp][] = [
    [{}, /n is required/],
    [{ n: 1.5 }, /n must be integer, not number/],
    [{ n: 0 }, /at least 1/],
    [{ n: 6 }, /at most 5/],
    [{ n: 1, x: '1' }, /x must be number, not string/],
    [{ n: 1, kind: 'c' }, /one of "a", "b"/],
    [{ n: 1, tags: ['abcd'] }, /tags\[0\] must be at most 3 characters/],
    [{ n: 1, tags: ['a', 'b', 'c'] }, /at most 2 items/],
    [{ n: 1, extra: true }, /extra isn't a known argument/],
    [[], /arguments must be object, not array/],
  ];
  for (const [v, why] of bad) it(`refuses ${JSON.stringify(v)}`, () => assert.match(String(check(v, s)), why));

  it('counts characters, not UTF-16 units', () => {
    assert.equal(check('😀😀😀', { type: 'string', maxLength: 3 }), null);
  });
});

describe('argument checking: own properties only', () => {
  const closed: Schema = { type: 'object', properties: { a: { type: 'string' } }, additionalProperties: false };
  // These names exist on Object.prototype, so a plain lookup used to find a constraint-free "sub-schema" for them.
  for (const key of ['constructor', 'toString', 'hasOwnProperty', '__proto__'])
    it(`treats ${key} as an unknown argument`, () => {
      assert.match(String(check(JSON.parse(`{"${key}": 1}`), closed)), /isn't a known argument/);
    });

  it('does not count an inherited property as a present required argument', () => {
    assert.match(String(check({}, { type: 'object', required: ['toString'] })), /toString is required/);
  });
});

describe('network (rate-limit key)', () => {
  const cases: [string, string][] = [
    ['192.0.2.7', '192.0.2.7'],
    ['2001:db8:1:2:3:4:5:6', '2001:db8:1:2::/64'],
    ['2001:db8::1', '2001:db8:0:0::/64'],
    ['2001:DB8:0001:0002::', '2001:db8:1:2::/64'],
    ['::1', '0:0:0:0::/64'],
    ['::ffff:192.0.2.7', '192.0.2.7'],
  ];
  for (const [ip, want] of cases) it(`${ip} → ${want}`, () => assert.equal(network(ip), want));
});

describe('safeNext (post-sign-in redirect)', () => {
  // Browsers drop tabs and newlines and read \ as /, so each of these would leave the site.
  for (const bad of ['//evil.example', '/\\evil.example', '/\t/evil.example', 'https://evil.example', '', 42])
    it(`refuses ${JSON.stringify(bad)}`, () => assert.equal(safeNext(bad), '/'));
  it('keeps a path on this site', () => assert.equal(safeNext('/oauth/continue?req=1'), '/oauth/continue?req=1'));
});
