import { describe, expect, it } from 'vitest';
import { SNAPSHOT_LISTS } from '../../src/model/list.js';
import { SnapshotSchema } from '../../src/model/snapshot.js';

/*
 * A snapshot from someone else is parsed with SnapshotSchema, so no part of
 * it may raise one issue per bad member of a collection (SEC-21): every list
 * must come from list(), and nothing else may hold many members that are
 * checked one by one. This walks the schema itself, so the rule holds
 * however a schema is written; the ESLint rule only catches `z.array`.
 */

interface Walk {
  /** Paths of the lists found, `[]` standing for an element. */
  lists: string[];
  problems: string[];
}

type AnyDef = { type: string } & Record<string, unknown>;

/** A schema as the walk sees it: its definition, whatever its type. */
type Node = { _zod: { def: unknown } };

/** The schemas have no cycles (a `lazy` one is reported), so the walk ends. */
function walk(schema: Node, path: string, found: Walk): void {
  const list = SNAPSHOT_LISTS.get(schema);
  if (list !== undefined) {
    found.lists.push(path);
    walk(list.element, `${path}[]`, found);
    return;
  }
  const def = schema._zod.def as AnyDef;
  const child = (key: string) => def[key] as Node;
  switch (def.type) {
    case 'object': {
      if (def.catchall !== undefined) found.problems.push(`${path}: keeps unknown keys`);
      const shape = def.shape as Record<string, Node>;
      for (const [key, value] of Object.entries(shape)) walk(value, `${path}.${key}`, found);
      break;
    }
    case 'record': {
      // Values that cannot fail raise no issue per member; the preflight bounds the keys.
      if ((child('valueType')._zod.def as AnyDef).type !== 'unknown') {
        found.problems.push(`${path}: a record whose values are checked one by one`);
      }
      break;
    }
    case 'array':
    case 'tuple':
    case 'set':
    case 'map':
    case 'lazy':
      found.problems.push(`${path}: ${def.type}, not list()`);
      break;
    case 'optional':
    case 'nullable':
    case 'nonoptional':
    case 'default':
    case 'prefault':
    case 'readonly':
    case 'catch':
      walk(child('innerType'), path, found);
      break;
    case 'pipe':
      walk(child('in'), path, found);
      walk(child('out'), path, found);
      break;
    case 'union':
      for (const option of def.options as Node[]) walk(option, path, found);
      break;
    case 'intersection':
      walk(child('left'), path, found);
      walk(child('right'), path, found);
      break;
    default:
      // Strings, numbers, booleans, enums, literals, null, unknown: one value each.
      break;
  }
}

describe('the snapshot schema', () => {
  const found: Walk = { lists: [], problems: [] };
  walk(SnapshotSchema, 'snapshot', found);

  it('builds every collection with list(), so none raises an issue per member', () => {
    expect(found.problems).toEqual([]);
  });

  it('is walked down to the deepest list', () => {
    expect(found.lists).toEqual(
      expect.arrayContaining([
        'snapshot.checks',
        'snapshot.apps',
        'snapshot.findings',
        'snapshot.raw.routes',
        'snapshot.raw.routes[].appGuids',
        'snapshot.raw.projects[].cdsFiles[].services[].entities[].requires',
        'snapshot.raw.projects[].dependencies.lockfiles',
        'snapshot.raw.projects[].dependencies.packages',
        'snapshot.raw.projects[].dependencies.packages[].lockfiles',
        'snapshot.raw.advisories',
        'snapshot.raw.advisories[].aliases',
        'snapshot.raw.vulnerablePackages',
        'snapshot.raw.vulnerablePackages[].advisories',
        'snapshot.raw.vulnerablePackages[].advisories[].fixed',
        'snapshot.raw.deprecations',
      ]),
    );
    // Every list of the model: 27 outside the project record, 39 inside it.
    expect(found.lists.length).toBeGreaterThanOrEqual(66);
  });
});
