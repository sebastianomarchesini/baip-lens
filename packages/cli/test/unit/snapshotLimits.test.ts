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
const DEPENDENCIES: JsonPath = ['raw', 'projects', 0, 'dependencies'];

const ZERO_NOT_KEPT = {
  otherRegistry: 0,
  git: 0,
  file: 0,
  link: 0,
  bundled: 0,
  unknown: 0,
  excluded: 0,
  invalid: 0,
};

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
  ['the lockfiles of a project', project, [...DEPENDENCIES, 'lockfiles'], 50],
  ['the packages of a project', project, [...DEPENDENCIES, 'packages'], 20_000],
  ['the lockfiles of a package', project, [...DEPENDENCIES, 'packages', 0, 'lockfiles'], 20],
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

describe('the lockfile record of a project', () => {
  const packages: JsonPath = [...DEPENDENCIES, 'packages'];
  const lockfiles: JsonPath = [...DEPENDENCIES, 'lockfiles'];
  const firstPackage = (
    project.raw as { projects: { dependencies: { packages: Record<string, unknown>[] } }[] }
  ).projects[0]!.dependencies.packages[0]!;
  const firstLockfile = (
    project.raw as { projects: { dependencies: { lockfiles: Record<string, unknown>[] } }[] }
  ).projects[0]!.dependencies.lockfiles[0]!;

  const parsed = (path: JsonPath, json: string) =>
    SnapshotSchema.safeParse(JSON.parse(withJsonAt(project, path, json)));

  it('refuses each of its lists over the limit at once', () => {
    const item = JSON.stringify(firstPackage);
    expect(parsed(packages, repeated(item, 20_000)).success).toBe(true);
    expect(issuesOf(withJsonAt(project, packages, repeated('0', 20_001)))).toMatchObject([
      { code: 'too_big', maximum: 20_000, path: packages },
    ]);
    expect(issuesOf(withJsonAt(project, lockfiles, repeated('0', 51)))).toMatchObject([
      { code: 'too_big', maximum: 50, path: lockfiles },
    ]);
    expect(
      issuesOf(withJsonAt(project, [...packages, 0, 'lockfiles'], repeated('"a"', 21))),
    ).toMatchObject([{ code: 'too_big', maximum: 20, path: [...packages, 0, 'lockfiles'] }]);
  });

  it.each([
    ['a name that could be read as a path', { name: '../x' }],
    ['a name that starts with a dot', { name: '.hidden' }],
    ['a name with an encoded slash', { name: '@scope%2fname' }],
    ['a name of 215 characters', { name: 'n'.repeat(215) }],
    ['a range instead of a version', { version: '^1.0.0' }],
    ['a version of 65 characters', { version: `1.0.0-${'9'.repeat(59)}` }],
    ['a version that is an address', { version: 'https://example.com/x.tgz' }],
    ['a scope it does not know', { scope: 'peer' }],
    ['a lockfile path that climbs out', { lockfiles: ['../package-lock.json'] }],
    ['a direct flag that is not a boolean', { direct: 'yes' }],
  ])('refuses a package with %s', (_name, change) => {
    const item = JSON.stringify({ ...firstPackage, ...change });
    expect(parsed(packages, `[${item}]`).success).toBe(false);
  });

  it.each([
    ['a kind it does not know', { kind: 'bun' }],
    ['a status it does not know', { status: 'skipped' }],
    ['a lockfile version it does not know', { lockfileVersion: 4 }],
    ['a negative count', { kept: -1 }],
    ['a count that is not a whole number', { notKept: { ...ZERO_NOT_KEPT, git: 1.5 } }],
    ['a reason missing from the counts', { notKept: { otherRegistry: 0 } }],
    ['an absolute path', { file: '/etc/package-lock.json' }],
  ])('refuses a lockfile with %s', (_name, change) => {
    const item = JSON.stringify({ ...firstLockfile, ...change });
    expect(parsed(lockfiles, `[${item}]`).success).toBe(false);
  });

  it('drops every key of an entry it does not know, so nothing else of a lockfile can be stored', () => {
    const item = JSON.stringify({
      ...firstPackage,
      resolved: 'https://npm.internal.example.com/x/-/x-1.0.0.tgz',
      integrity: 'sha512-planted',
      deprecated: 'planted message',
      license: 'planted',
    });
    const result = parsed(packages, `[${item}]`);
    expect(result.success).toBe(true);
    expect(result.data?.raw.projects[0]?.dependencies?.packages).toEqual([firstPackage]);
    expect(JSON.stringify(result.data)).not.toMatch(/planted|internal\.example/);
  });

  it('reads a project without the record as one whose lockfiles were not collected', () => {
    const before = structuredClone(project) as { raw: { projects: Record<string, unknown>[] } };
    delete before.raw.projects[0]!.dependencies;
    const result = SnapshotSchema.safeParse(before);
    expect(result.success).toBe(true);
    expect(result.data?.raw.projects[0]?.dependencies).toBeNull();
    expect(parsed(DEPENDENCIES, 'null').success).toBe(true);
    expect(parsed(DEPENDENCIES, '{}').success).toBe(false);
  });
});
