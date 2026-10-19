// Checks a tool's arguments against its inputSchema before it runs, so every tool can trust the shape it's given.
// Covers the JSON Schema an MCP tool usually needs: type (object, string, integer, number, boolean, array, null),
// properties, required, additionalProperties: false, enum, minLength/maxLength, minimum/maximum, items, minItems/maxItems.
// Anything else in a schema is ignored, not refused. For the full language, swap in a library such as @cfworker/json-schema.

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

const typeOf = (v: unknown) =>
  v === null ? 'null' : Array.isArray(v) ? 'array' : Number.isInteger(v) ? 'integer' : typeof v;
const fits = (v: unknown, type: string) =>
  typeOf(v) === type || (type === 'number' && typeof v === 'number' && Number.isFinite(v));

/** The first problem with `value`, in words an assistant can act on, or null if it fits. */
export function check(value: unknown, schema: Schema, path = 'arguments'): string | null {
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((t) => fits(value, t))) return `${path} must be ${types.join(' or ')}, not ${typeOf(value)}.`;
  }
  if (schema.enum && !schema.enum.some((e) => e === value))
    return `${path} must be one of ${schema.enum.map((e) => JSON.stringify(e)).join(', ')}.`;
  if (typeof value === 'string') {
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
    for (const k of schema.required || []) if (o[k] === undefined) return `${path}.${k} is required.`;
    for (const [k, v] of Object.entries(o)) {
      const sub = schema.properties?.[k];
      if (sub) {
        const e = check(v, sub, `${path}.${k}`);
        if (e) return e;
      } else if (schema.additionalProperties === false) return `${path}.${k} isn't a known argument.`;
    }
  }
  return null;
}
