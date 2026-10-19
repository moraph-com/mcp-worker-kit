/**
 * @file Every tool the server offers. Add yours to `TOOLS`. `toolsFor` in `mcp.ts` decides who sees which.
 *
 * The checks below run once, when the Worker starts. A duplicate or malformed name fails the deploy, instead of
 * producing a server that clients can't use.
 */
import { CONNECTION_TOOLS, EXAMPLE_TOOLS } from './examples.ts';
import type { Tool } from './types.ts';

export const TOOLS: Tool[] = [...EXAMPLE_TOOLS, ...CONNECTION_TOOLS];

/** MCP 2025-11-25 server/tools, "Tool Names": 1–128 characters, case-sensitive, from this set. */
const TOOL_NAME = /^[A-Za-z0-9_.-]{1,128}$/;
const names = new Set<string>();
for (const t of TOOLS) {
  if (!TOOL_NAME.test(t.name)) throw new Error(`Tool name ${JSON.stringify(t.name)} isn't a valid MCP tool name`);
  if (names.has(t.name)) throw new Error(`Two tools are called ${t.name}`);
  names.add(t.name);
}
