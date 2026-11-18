import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { list } from '../../src/model/list.js';
import { SnapshotSchema } from '../../src/model/snapshot.js';
import { type JsonPath, readFixture, repeated, withJsonAt } from '../support/snapshotText.js';

describe('list()', () => {
  const Item = z.object({ n: z.number(), tag: z.string().default('none') });

  it('parses up to `max` elements like z.array: defaults applied, unknown keys dropped', () => {
    const result = list(Item, 3).safeParse([{ n: 1 }, { n: 2, extra: true }, { n: 3, tag: 'x' }]);
    expect(result).toEqual({
      success: true,
      data: [
        { n: 1, tag: 'none' },
        { n: 2, tag: 'none' },
        { n: 3, tag: 'x' },
      ],
    });
  });

  it('refuses a longer list with one issue, before reading any element', () => {
    let read = 0;
    const counted = z.number().refine(() => ++read > 0);
    const result = list(counted, 3).safeParse([1, 2, 3, 4]);
    expect(result.error?.issues).toMatchObject([{ code: 'too_big', maximum: 3, path: [] }]);
    expect(read).toBe(0);
  });

  it('stops at the first invalid element and reports only its issues', () => {
    let read = 0;
    const counted = Item.refine(() => ++read > 0);
    const result = list(counted, 10).safeParse([{ n: 1 }, { n: 'two', tag: 2 }, 'three', {}]);
    expect(result.error?.issues.map((issue) => issue.path)).toEqual([
      [1, 'n'],
      [1, 'tag'],
    ]);
    expect(result.error?.issues[0]?.message).toBe(
      'Invalid input: expected number, received string',
    );
    // The element after the first invalid one is never read.
    expect(read).toBe(1);
  });

  it('refuses a value that is not a list', () => {
    expect(list(Item, 3).safeParse({ length: 1 }).error?.issues).toMatchObject([
      { code: 'invalid_type', expected: 'array', path: [] },
    ]);
  });
});

const cf = readFixture('sample-snapshot.json');
const project = readFixture('sample-project-snapshot.json');
const SERVICE_ROLES: JsonPath = ['raw', 'projects', 0, 'cdsFiles', 2, 'services', 0, 'requires'];

function issuesOf(text: string) {
  const result = SnapshotSchema.safeParse(JSON.parse(text));
  if (result.success) throw new Error('expected the snapshot to be refused');
  return result.error.issues;
}

/** A list of the snapshot, a base snapshot that has it, and a count within its limit. */
const LISTS: [string, typeof cf, JsonPath, number][] = [
  ['checks', cf, ['checks'], 1_000],
  ['apps', cf, ['apps'], 10_000],
  ['findings', cf, ['findings'], 10_000],
  ['scope.orgs', cf, ['scope', 'orgs'], 100],
  ['raw.apps', cf, ['raw', 'apps'], 10_000],
  ['raw.routes', cf, ['raw', 'routes'], 10_000],
  ['raw.history', cf, ['raw', 'history'], 10_000],
  ['raw.projects', project, ['raw', 'projects'], 1_000],
  ['the roles a project service requires', project, SERVICE_ROLES, 50],
];

describe('a snapshot list stops at its first invalid element', () => {
  it.each(LISTS)('%s: wrong-typed elements give the one issue of the first', (_, base, path, n) => {
    for (const count of [1, n]) {
      const issues = issuesOf(withJsonAt(base, path, repeated('0', count)));
      expect(issues.map((issue) => issue.path)).toEqual([[...path, 0]]);
    }
  });

  it('gives the issues of one element however many empty objects follow', () => {
    // A raw app has nine keys, all required: guid, name, spaceGuid, state,
    // createdAt, updatedAt, lifecycleType, buildpacks and stack.
    const issues = issuesOf(withJsonAt(cf, ['raw', 'apps'], repeated('{}', 10_000)));
    expect(issues).toHaveLength(9);
    expect(new Set(issues.map((issue) => issue.path.slice(0, 3).join('.')))).toEqual(
      new Set(['raw.apps.0']),
    );
  });

  it('stops at a value that fails a check, not only at a wrong type', () => {
    const entry = JSON.stringify({
      appGuid: 'a',
      spaceGuid: 's',
      lastRequestEverSeen: 'yesterday',
      firstScanWithoutTraffic: null,
      scansWithoutTraffic: 1,
    });
    const history = issuesOf(withJsonAt(cf, ['raw', 'history'], repeated(entry, 10_000)));
    expect(history.map((issue) => issue.path)).toEqual([
      ['raw', 'history', 0, 'lastRequestEverSeen'],
    ]);
    const files = issuesOf(
      withJsonAt(project, ['raw', 'projects', 0, 'files'], repeated('"../up"', 500)),
    );
    expect(files.map((issue) => issue.path)).toEqual([['raw', 'projects', 0, 'files', 0]]);
  });

  it('refuses a list over its limit at once', () => {
    const check = JSON.stringify((cf.checks as unknown[])[0]);
    expect(
      SnapshotSchema.safeParse(JSON.parse(withJsonAt(cf, ['checks'], repeated(check, 1_000))))
        .success,
    ).toBe(true);
    const issues = issuesOf(withJsonAt(cf, ['checks'], repeated('0', 1_001)));
    expect(issues).toMatchObject([{ code: 'too_big', maximum: 1_000, path: ['checks'] }]);
  });
});
