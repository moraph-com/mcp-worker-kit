import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { check, type Schema } from '../src/tools/validate.ts';

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
  const ok = [{ n: 1 }, { n: 5, x: 1.5, kind: 'a', tags: ['abc'], maybe: null }, { n: 2, x: 3, maybe: 's' }, { n: 3, free: 'not checked' }];
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
