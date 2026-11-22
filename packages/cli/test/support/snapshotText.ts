import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/*
 * Snapshot text for the limit tests: the recorded fixtures, with one value
 * swapped for crafted JSON, and real-shaped snapshots of any size built from
 * the CF sample. Crafted lists are built as text with `String#repeat`, so a
 * test does not hold millions of JS values of its own while it measures
 * what reading the file costs.
 */

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonObject = { [key: string]: Json };
export type JsonPath = readonly (string | number)[];

export const fixturePath = (name: string): string =>
  fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));

export function readFixture(name: string): JsonObject {
  return JSON.parse(readFileSync(fixturePath(name), 'utf8')) as JsonObject;
}

const PLACEHOLDER = '\u0000crafted\u0000';

function child(node: Json | undefined, key: string | number): Json | undefined {
  if (Array.isArray(node)) return typeof key === 'number' ? node[key] : undefined;
  if (node !== null && typeof node === 'object') return node[String(key)];
  return undefined;
}

/** `snapshot` as JSON text with the value at `path` replaced by the text `json`. */
export function withJsonAt(snapshot: JsonObject, path: JsonPath, json: string): string {
  const copy = structuredClone(snapshot);
  const last = path.at(-1);
  let parent: Json | undefined = copy;
  for (const key of path.slice(0, -1)) parent = child(parent, key);
  if (last === undefined || parent === null || typeof parent !== 'object') {
    throw new Error(`no value at ${path.join('.')}`);
  }
  if (Array.isArray(parent)) parent[Number(last)] = PLACEHOLDER;
  else parent[String(last)] = PLACEHOLDER;
  return JSON.stringify(copy).replace(JSON.stringify(PLACEHOLDER), () => json);
}

/** The JSON text of `snapshot` before and after the value at `path`, for writing one in parts. */
export function splitAt(snapshot: JsonObject, path: JsonPath): [string, string] {
  const marker = '\u0000split\u0000';
  const text = withJsonAt(snapshot, path, marker);
  const at = text.indexOf(marker);
  return [text.slice(0, at), text.slice(at + marker.length)];
}

/** A JSON array of `count` copies of the JSON text `item`. */
export function repeated(item: string, count: number): string {
  return count === 0 ? '[]' : `[${`${item},`.repeat(count - 1)}${item}]`;
}

/** The text `json` wrapped in `depth` arrays: `[[[json]]]`. */
export function nested(json: string, depth: number): string {
  return `${'['.repeat(depth)}${json}${']'.repeat(depth)}`;
}

function asObject(value: Json | undefined): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('expected an object');
  }
  return value;
}

function asArray(value: Json | undefined): Json[] {
  if (!Array.isArray(value)) throw new Error('expected an array');
  return value;
}

function asString(value: Json | undefined): string {
  if (typeof value !== 'string') throw new Error('expected a string');
  return value;
}

/** A copy of `value` with every `from` string replaced by `to`, keys included. */
function renamed(value: Json, replacements: readonly [string, string][]): Json {
  let text = JSON.stringify(value);
  for (const [from, to] of replacements) text = text.replaceAll(from, to);
  return JSON.parse(text) as Json;
}

/**
 * A snapshot of `apps` apps shaped like a real scan: the CF sample's apps
 * repeated in turn, each with its own GUID and name and with the droplet,
 * routes, processes, traffic, history, inventory item and findings the
 * sample has for it: 3,190 bytes and 84 JSON values per app as
 * `writeSnapshot` writes it (pretty-printed), 2,288 bytes minified.
 */
export function realShapedSnapshot(apps: number): JsonObject {
  const sample = readFixture('sample-snapshot.json');
  const raw = asObject(sample.raw);
  const templates = asArray(raw.apps).map(asObject);
  const perApp = ['droplets', 'processes', 'traffic', 'history'] as const;
  const out: JsonObject = { ...sample, apps: [], findings: [] };
  const outRaw: JsonObject = { ...raw, apps: [], routes: [] };
  for (const key of perApp) outRaw[key] = [];
  for (let i = 0; i < apps; i++) {
    const template = templates[i % templates.length];
    if (template === undefined) throw new Error('the sample has no apps');
    const guid = `${i.toString(16).padStart(8, '0')}-0000-4000-8000-000000000000`;
    const name = asString(template.name);
    const replacements: [string, string][] = [
      [asString(template.guid), guid],
      [`"${name}"`, `"${name}-${i}"`],
    ];
    const ownedBy = (item: Json) => asObject(item).appGuid === template.guid;
    asArray(outRaw.apps).push(renamed(template, replacements));
    for (const key of perApp) {
      for (const item of asArray(raw[key]).filter(ownedBy)) {
        asArray(outRaw[key]).push(renamed(item, replacements));
      }
    }
    for (const route of asArray(raw.routes)) {
      if (!asArray(asObject(route).appGuids).includes(template.guid ?? null)) continue;
      const copy = asObject(renamed(route, replacements));
      asArray(outRaw.routes).push({ ...copy, guid: `r${guid.slice(1)}`, appGuids: [guid] });
    }
    for (const item of asArray(sample.apps)) {
      if (asObject(item).guid === template.guid) {
        asArray(out.apps).push(renamed(item, replacements));
      }
    }
    for (const finding of asArray(sample.findings)) {
      if (asObject(asObject(finding).app).guid === template.guid) {
        asArray(out.findings).push(renamed(finding, replacements));
      }
    }
  }
  out.raw = outRaw;
  return out;
}
