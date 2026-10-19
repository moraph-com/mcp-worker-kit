// Every tool the server offers. Add yours here; mcp.ts decides who sees which.
import { CONNECTION_TOOLS, EXAMPLE_TOOLS } from './examples.ts';
import type { Tool } from './types.ts';

export const TOOLS: Tool[] = [...EXAMPLE_TOOLS, ...CONNECTION_TOOLS];

const names = new Set<string>();
for (const t of TOOLS) {
  if (names.has(t.name)) throw new Error(`Two tools are called ${t.name}`);
  names.add(t.name);
}
