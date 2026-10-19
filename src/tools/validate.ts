/**
 * @file Checks a tool's arguments against its `inputSchema` before the tool runs, so every tool can trust the shape
 * of what it receives.
 *
 * This covers the part of JSON Schema that MCP tools usually need: `type` (object, string, integer, number, boolean,
 * array, null, or a list of them), `properties`, `required`, `additionalProperties: false`, `enum`,
 * `minLength`/`maxLength` (counted in Unicode code points, as JSON Schema specifies), `minimum`/`maximum`, `items` and
 * `minItems`/`maxItems`. Other keywords (`format`, `pattern`, `oneOf`, …) are passed on to clients but **not
 * checked**, so a tool that relies on one must check it in `run`. For the full language, swap in a library such as
 * `@cfworker/json-schema`, which runs on Workers.
 *
 * The cost is bounded by the schema, not by the input. The checker only recurses where the schema has a
 * sub-schema, so a deeply nested argument can't make it do more work than the schema describes, and the 64 KB body
 * limit bounds everything else.
 */

/** The JSON Schema subset understood here. Unknown keywords are allowed and ignored. */
export type Schema = {
  type?: string | string[];
  properties?: Record<string, Schema>;
  required?: string[];
  additionalProperties?: boolean;
  enum?: unknown[];
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  items?: Schema;
  minItems?: number;
  maxItems?: number;
  description?: string;
  /** Other keywords (format, pattern, default…) are allowed in a schema and passed to clients, but not checked here. */
  [keyword: string]: unknown;
};

/** The JSON Schema type name of a parsed JSON value. Whole numbers count as `integer`, as JSON Schema says. */
const typeOf = (v: unknown) =>
  v === null ? 'null' : Array.isArray(v) ? 'array' : Number.isInteger(v) ? 'integer' : typeof v;
/** `integer` is a subtype of `number`, so a whole number satisfies `type: "number"` too. */
const fits = (v: unknown, type: string) =>
  typeOf(v) === type || (type === 'number' && typeof v === 'number' && Number.isFinite(v));

/** Names quoted in messages are cut short, so an absurd key can't produce an absurd message. */
const label = (k: string) => (k.length > 64 ? `${k.slice(0, 64)}…` : k);

/**
 * Finds the first way `value` fails `schema`.
 *
 * @param path - How to name `value` in the message. Nested calls extend it, e.g. `arguments.tags[2]`.
 * @returns A message an assistant can act on ("arguments.title is required."), or null if `value` fits. The message
 *   can quote argument names the caller chose, so it goes back to the caller but is never written to the audit log.
 */
export function check(value: unknown, schema: Schema, path = 'arguments'): string | null {
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((t) => fits(value, t))) return `${path} must be ${types.join(' or ')}, not ${typeOf(value)}.`;
  }
  if (schema.enum && !schema.enum.some((e) => e === value))
    return `${path} must be one of ${schema.enum.map((e) => JSON.stringify(e)).join(', ')}.`;
  if (typeof value === 'string') {
    // Code points, not UTF-16 units: "😀" is one character to JSON Schema and to the person typing it.
    const n = [...value].length;
    if (schema.minLength !== undefined && n < schema.minLength)
      return `${path} must be at least ${schema.minLength} characters.`;
    if (schema.maxLength !== undefined && n > schema.maxLength)
      return `${path} must be at most ${schema.maxLength} characters.`;
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) return `${path} must be at least ${schema.minimum}.`;
    if (schema.maximum !== undefined && value > schema.maximum) return `${path} must be at most ${schema.maximum}.`;
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems)
      return `${path} needs at least ${schema.minItems} items.`;
    if (schema.maxItems !== undefined && value.length > schema.maxItems)
      return `${path} can have at most ${schema.maxItems} items.`;
    if (schema.items)
      for (let i = 0; i < value.length; i++) {
        const e = check(value[i], schema.items, `${path}[${i}]`);
        if (e) return e;
      }
  }
  if (typeOf(value) === 'object') {
    const o = value as Record<string, unknown>;
    // Own properties only, on both sides. A plain `obj[k]` lookup would find Object.prototype members, so keys such as
    // "constructor", "toString" or "__proto__" (which JSON.parse creates as an own key) would match an inherited
    // "sub-schema" with no constraints, and slip past additionalProperties: false. An inherited member would also
    // count as a present `required` argument.
    for (const k of schema.required || [])
      if (!Object.hasOwn(o, k) || o[k] === undefined) return `${path}.${label(k)} is required.`;
    for (const [k, v] of Object.entries(o)) {
      const sub = schema.properties && Object.hasOwn(schema.properties, k) ? schema.properties[k] : undefined;
      if (sub) {
        const e = check(v, sub, `${path}.${label(k)}`);
        if (e) return e;
      } else if (schema.additionalProperties === false) return `${path}.${label(k)} isn't a known argument.`;
    }
  }
  return null;
}
