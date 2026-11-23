import { mkdir, mkdtemp, realpath, rm, symlink, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { lockfileMissing } from '../../../../src/analyzers/dependencies/lockfileMissing.js';
import { notChecked } from '../../../../src/analyzers/dependencies/notChecked.js';
import {
  MAX_LOCKFILES,
  MAX_LOCKFILES_PER_PACKAGE,
  MAX_LOCKFILE_TOTAL_BYTES,
  MAX_PACKAGE_LOCKFILE_BYTES,
  PackageTable,
  chooseLockfiles,
  keptLockfilePaths,
  packageBudget,
} from '../../../../src/collectors/project/dependencies.js';
import { MAX_FILES_OPENED, collectProject } from '../../../../src/collectors/project/index.js';
import { MAX_PACKAGES, emptyNotKept } from '../../../../src/collectors/project/lockfile.js';
import { MAX_FILE_BYTES, MAX_LOCKFILE_BYTES } from '../../../../src/collectors/project/read.js';
import type { WalkedFile } from '../../../../src/collectors/project/walk.js';
import { MAX_RELATIVE_PATH_LENGTH } from '../../../../src/model/paths.js';
import { RawLockedPackageSchema, RawProjectSchema } from '../../../../src/model/raw.js';
import { lockfileV3, registryEntry } from '../../../support/lockfileFixture.js';
import { runRule } from '../../../support/project.js';

/*
 * The lockfile step of the project collector: which lockfiles are read, what
 * of them is kept, and what the limits do. Lockfiles are written into a
 * temporary folder with invented package names.
 */

/** Some of these folders hold tens of megabytes of lockfiles: they are removed when the file is done. */
const created: string[] = [];
afterAll(async () => {
  await Promise.all(created.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function tmp(): Promise<string> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'baip-lens-lockfiles-')));
  created.push(dir);
  return dir;
}

async function file(root: string, rel: string, content: string | Buffer): Promise<void> {
  const abs = join(root, ...rel.split('/'));
  await mkdir(join(abs, '..'), { recursive: true });
  await writeFile(abs, content);
}

/** A version 3 lockfile whose public packages are `name@version` strings; the root lists `direct`. */
function lock(packages: string[], direct: string[] = []): string {
  const entries = packages.map((spec) => {
    const at = spec.lastIndexOf('@');
    const [name, version] = [spec.slice(0, at), spec.slice(at + 1)];
    return [`node_modules/${name}`, registryEntry(name, version)] as const;
  });
  return lockfileV3(
    { name: 'acme', dependencies: Object.fromEntries(direct.map((name) => [name, '*'])) },
    Object.fromEntries(entries),
  );
}

/** Valid JSON of exactly `bytes` bytes that is a lockfile without packages. */
function paddedLockfile(bytes: number): Buffer {
  const head = '{"lockfileVersion":3,"packages":{},"padding":"';
  const tail = '"}';
  const buffer = Buffer.alloc(bytes, 0x78);
  buffer.write(head, 0, 'utf8');
  buffer.write(tail, bytes - tail.length, 'utf8');
  return buffer;
}

const walked = (rel: string, kind: WalkedFile['kind'] = 'lockfile'): WalkedFile => ({
  kind,
  abs: `/root/${rel}`,
  rel,
  size: 1,
});

describe('which lockfiles are read', () => {
  it('reads one per directory: npm-shrinkwrap.json wins, the root comes first, the rest in path order', () => {
    const choice = chooseLockfiles([
      walked('srv/package-lock.json'),
      walked('app/router/npm-shrinkwrap.json'),
      walked('app/router/package-lock.json'),
      walked('package.json', 'package.json'),
      walked('package-lock.json'),
      walked('npm-shrinkwrap.json'),
      walked('app/npm-shrinkwrap.json'),
      walked('yarn.lock', 'foreign-lockfile'),
      walked('pnpm-lock.yaml', 'foreign-lockfile'),
    ]);
    expect(choice.toRead.map((entry) => entry.rel)).toEqual([
      'npm-shrinkwrap.json',
      'app/npm-shrinkwrap.json',
      'app/router/npm-shrinkwrap.json',
      'srv/package-lock.json',
    ]);
    expect(choice.notRead).toBe(0);
    expect(choice.foreign).toEqual([
      {
        file: 'pnpm-lock.yaml',
        kind: 'pnpm',
        lockfileVersion: null,
        status: 'unsupported',
        kept: 0,
        notKept: emptyNotKept(),
      },
      {
        file: 'yarn.lock',
        kind: 'yarn',
        lockfileVersion: null,
        status: 'unsupported',
        kept: 0,
        notKept: emptyNotKept(),
      },
    ]);
  });

  it(`keeps at most ${MAX_LOCKFILES} records, the root lockfile among them, and counts the rest`, () => {
    const many = Array.from({ length: 60 }, (_, i) =>
      walked(`app/m${String(i).padStart(2, '0')}/package-lock.json`),
    );
    const choice = chooseLockfiles([
      ...many,
      walked('package-lock.json'),
      walked('yarn.lock', 'foreign-lockfile'),
    ]);
    expect(choice.toRead).toHaveLength(MAX_LOCKFILES - 1);
    expect(choice.toRead[0]?.rel).toBe('package-lock.json');
    expect(choice.toRead[1]?.rel).toBe('app/m00/package-lock.json');
    expect(choice.toRead.at(-1)?.rel).toBe('app/m47/package-lock.json');
    expect(choice.notRead).toBe(12);
    expect(choice.foreign).toHaveLength(1);
  });

  it('finds nothing to read in a project without lockfiles', () => {
    expect(chooseLockfiles([walked('package.json', 'package.json')])).toEqual({
      toRead: [],
      foreign: [],
      notRead: 0,
    });
  });
});

describe('the package list of a project', () => {
  const item = (
    name: string,
    version: string,
    direct = false,
    scope: 'prod' | 'dev' | 'optional' = 'prod',
  ) => ({ name, version, direct, scope });

  it('merges one package of several lockfiles: direct if any, strongest scope, lockfiles sorted', () => {
    const table = new PackageTable(10);
    expect(table.add('srv/package-lock.json', [item('a', '1.0.0', false, 'dev')])).toBe(true);
    expect(table.add('package-lock.json', [item('a', '1.0.0', true, 'optional')])).toBe(true);
    expect(table.add('app/package-lock.json', [item('a', '1.0.0', false, 'dev')])).toBe(true);
    expect(table.add('db/package-lock.json', [item('a', '2.0.0', false, 'dev')])).toBe(true);
    expect(table.list()).toEqual([
      {
        name: 'a',
        version: '1.0.0',
        direct: true,
        scope: 'optional',
        lockfiles: ['app/package-lock.json', 'package-lock.json', 'srv/package-lock.json'],
      },
      {
        name: 'a',
        version: '2.0.0',
        direct: false,
        scope: 'dev',
        lockfiles: ['db/package-lock.json'],
      },
    ]);
    expect(table.add('x/package-lock.json', [item('a', '2.0.0', false, 'prod')])).toBe(true);
    expect(table.list()[1]).toMatchObject({ scope: 'prod', direct: false });
  });

  it('adds a lockfile whole or not at all, counting only the packages that are new', () => {
    const table = new PackageTable(3);
    expect(table.add('a/package-lock.json', [item('a', '1.0.0'), item('b', '1.0.0')])).toBe(true);
    // Two known packages and one new one fit; two new ones do not.
    expect(
      table.add('b/package-lock.json', [
        item('a', '1.0.0'),
        item('b', '1.0.0'),
        item('c', '1.0.0'),
      ]),
    ).toBe(true);
    expect(table.add('c/package-lock.json', [item('a', '1.0.0'), item('d', '1.0.0')])).toBe(false);
    expect(table.size).toBe(3);
    expect(table.list().map((entry) => [entry.name, entry.lockfiles])).toEqual([
      ['a', ['a/package-lock.json', 'b/package-lock.json']],
      ['b', ['a/package-lock.json', 'b/package-lock.json']],
      ['c', ['b/package-lock.json']],
    ]);
    // Nothing new is nothing to refuse, even with no room left.
    expect(table.add('d/package-lock.json', [item('c', '1.0.0')])).toBe(true);
    expect(new PackageTable(0).add('package-lock.json', [])).toBe(true);
  });

  it(`names at most ${MAX_LOCKFILES_PER_PACKAGE} lockfiles per package`, () => {
    const table = new PackageTable(1);
    for (let i = 29; i >= 0; i -= 1) {
      table.add(`m${String(i).padStart(2, '0')}/package-lock.json`, [item('a', '1.0.0')]);
    }
    const [only] = table.list();
    expect(only?.lockfiles).toHaveLength(MAX_LOCKFILES_PER_PACKAGE);
    expect(only?.lockfiles[0]).toBe('m00/package-lock.json');
    expect(only?.lockfiles.at(-1)).toBe('m19/package-lock.json');
  });

  it(`keeps no more lockfile paths per package than fit ${MAX_PACKAGE_LOCKFILE_BYTES} bytes, and always the first`, () => {
    const paths = (length: number, fill = 'd'): string[] =>
      Array.from({ length: 30 }, (_, i) => {
        const tail = `/m${String(i).padStart(2, '0')}/package-lock.json`;
        return `${fill.repeat(length - tail.length)}${tail}`;
      });
    const listed = (all: string[]): string[] => {
      const table = new PackageTable(1);
      // Added in reverse: the paths kept are the first of the sorted ones.
      for (const path of [...all].reverse()) table.add(path, [item('a', '1.0.0')]);
      return table.list()[0]?.lockfiles ?? [];
    };
    const jsonBytes = (kept: string[]): number =>
      kept.reduce((sum, path) => sum + Buffer.byteLength(JSON.stringify(path)), 0);

    // Twenty paths of 100 characters fit: 20 x 102 bytes with their quotes.
    expect(listed(paths(100))).toEqual(paths(100).slice(0, MAX_LOCKFILES_PER_PACKAGE));
    // One character more each and the twentieth does not.
    expect(listed(paths(101))).toEqual(paths(101).slice(0, 19));
    // The longest path the model allows: three of 514 bytes fit, the fourth would not.
    expect(MAX_RELATIVE_PATH_LENGTH).toBe(512);
    const longest = listed(paths(MAX_RELATIVE_PATH_LENGTH));
    expect(longest).toEqual(paths(MAX_RELATIVE_PATH_LENGTH).slice(0, 3));
    expect(jsonBytes(longest)).toBeLessThanOrEqual(MAX_PACKAGE_LOCKFILE_BYTES);
    // Bytes count, not characters: a path of three-byte characters is a larger one.
    const wide = listed(paths(MAX_RELATIVE_PATH_LENGTH, '\u20ac'));
    expect(wide).toHaveLength(1);
    expect(jsonBytes(wide)).toBeLessThanOrEqual(MAX_PACKAGE_LOCKFILE_BYTES);
    // What JSON escapes counts as it is written. One path is kept whatever it takes:
    // a package is never without the lockfile that pins it.
    const escaped = listed(paths(MAX_RELATIVE_PATH_LENGTH, '\u0001'));
    expect(escaped).toEqual(paths(MAX_RELATIVE_PATH_LENGTH, '\u0001').slice(0, 1));
    expect(jsonBytes(escaped)).toBeGreaterThan(MAX_PACKAGE_LOCKFILE_BYTES);
    expect(keptLockfilePaths([])).toEqual([]);
    for (const kept of [longest, wide, escaped]) {
      expect(RawLockedPackageSchema.safeParse({ ...item('a', '1.0.0'), lockfiles: kept })).toEqual(
        expect.objectContaining({ success: true }),
      );
    }
  });

  it('sorts by name, then version, in code point order', () => {
    const table = new PackageTable(10);
    table.add('package-lock.json', [
      item('b', '1.0.0'),
      item('a', '9.0.0'),
      item('a', '10.0.0'),
      item('@s/a', '1.0.0'),
      item('B', '1.0.0'),
    ]);
    expect(table.list().map((entry) => `${entry.name}@${entry.version}`)).toEqual([
      '@s/a@1.0.0',
      'B@1.0.0',
      'a@10.0.0',
      'a@9.0.0',
      'b@1.0.0',
    ]);
  });

  it('never lets a caller raise the budget above the limit', () => {
    expect(packageBudget(undefined)).toBe(MAX_PACKAGES);
    expect(packageBudget(MAX_PACKAGES + 1)).toBe(MAX_PACKAGES);
    expect(packageBudget(Number.POSITIVE_INFINITY)).toBe(MAX_PACKAGES);
    expect(packageBudget(Number.NaN)).toBe(MAX_PACKAGES);
    expect(packageBudget(12.9)).toBe(12);
    expect(packageBudget(0)).toBe(0);
    expect(packageBudget(-5)).toBe(0);
  });
});

describe('collectProject and the lockfiles', () => {
  it('reads the lockfiles the walk reaches and keeps one package list for the project', async () => {
    const root = await tmp();
    await file(root, 'package.json', '{ "name": "acme", "dependencies": { "baip-server": "^2" } }');
    await file(
      root,
      'package-lock.json',
      lock(['baip-server@2.4.1', 'baip-merge@4.17.20'], ['baip-server']),
    );
    await file(
      root,
      'app/router/package-lock.json',
      lock(['baip-router@1.0.0', 'baip-merge@4.17.20'], ['baip-router']),
    );
    await file(root, 'srv/npm-shrinkwrap.json', lock(['baip-merge@3.10.1']));
    // The loser next to a shrinkwrap file is not opened: it would be unreadable if it were.
    await file(root, 'srv/package-lock.json', '{ not json');
    // Never reached: below node_modules, and in a folder the walk skips.
    await file(root, 'node_modules/.package-lock.json', lock(['POISON-hidden@1.0.0']));
    await file(root, 'node_modules/x/package-lock.json', lock(['POISON-nested@1.0.0']));
    await file(root, 'gen/srv/package-lock.json', lock(['POISON-gen@1.0.0']));

    const project = await collectProject(root);
    expect(RawProjectSchema.safeParse(project).success).toBe(true);
    expect(project.dependencies).toEqual({
      lockfiles: [
        {
          file: 'app/router/package-lock.json',
          kind: 'package-lock',
          lockfileVersion: 3,
          status: 'read',
          kept: 2,
          notKept: emptyNotKept(),
        },
        {
          file: 'package-lock.json',
          kind: 'package-lock',
          lockfileVersion: 3,
          status: 'read',
          kept: 2,
          notKept: emptyNotKept(),
        },
        {
          file: 'srv/npm-shrinkwrap.json',
          kind: 'shrinkwrap',
          lockfileVersion: 3,
          status: 'read',
          kept: 1,
          notKept: emptyNotKept(),
        },
      ],
      lockfilesNotRead: 0,
      packages: [
        {
          name: 'baip-merge',
          version: '3.10.1',
          direct: false,
          scope: 'prod',
          lockfiles: ['srv/npm-shrinkwrap.json'],
        },
        {
          name: 'baip-merge',
          version: '4.17.20',
          direct: false,
          scope: 'prod',
          lockfiles: ['app/router/package-lock.json', 'package-lock.json'],
        },
        {
          name: 'baip-router',
          version: '1.0.0',
          direct: true,
          scope: 'prod',
          lockfiles: ['app/router/package-lock.json'],
        },
        {
          name: 'baip-server',
          version: '2.4.1',
          direct: true,
          scope: 'prod',
          lockfiles: ['package-lock.json'],
        },
      ],
    });
    // A lockfile read is a file opened, and listed like every other one.
    expect(project.files).toEqual([
      'app/router/package-lock.json',
      'package-lock.json',
      'package.json',
      'srv/npm-shrinkwrap.json',
    ]);
    expect(project.unreadable).toEqual([]);
    expect(project.filesOpened).toBe(4);
    expect(JSON.stringify(project)).not.toMatch(/POISON|registry\.npmjs|sha512/);
  });

  it('takes the direct packages of a version 1 lockfile from the root package.json, in the root only', async () => {
    const legacy = JSON.stringify({
      lockfileVersion: 1,
      dependencies: Object.fromEntries(
        ['a', 'b', 'c', 'd', 'e'].map((name) => [
          name,
          { version: '1.0.0', resolved: `https://registry.npmjs.org/${name}/-/${name}-1.0.0.tgz` },
        ]),
      ),
    });
    const root = await tmp();
    await file(
      root,
      'package.json',
      JSON.stringify({
        name: 'acme',
        dependencies: { a: '^1' },
        devDependencies: { b: '^1' },
        optionalDependencies: { c: '^1' },
        peerDependencies: { d: '^1' },
        bundleDependencies: ['e'],
      }),
    );
    await file(root, 'package-lock.json', legacy);
    await file(root, 'app/package-lock.json', legacy);
    const project = await collectProject(root);
    expect(project.dependencies?.lockfiles.map((l) => [l.file, l.lockfileVersion])).toEqual([
      ['app/package-lock.json', 1],
      ['package-lock.json', 1],
    ]);
    // Direct through the root lockfile; the nested one has no manifest this tool reads.
    expect(project.dependencies?.packages.map((p) => [p.name, p.direct])).toEqual([
      ['a', true],
      ['b', true],
      ['c', true],
      ['d', true],
      ['e', false],
    ]);
    // The manifest keeps what it kept before: the two lists, no other section.
    expect(Object.keys(project.packageJson).sort()).toEqual([
      'dependencies',
      'devDependencies',
      'name',
      'nodeEngine',
      'present',
    ]);

    const nestedOnly = await tmp();
    await file(nestedOnly, 'package.json', '{ "dependencies": { "a": "^1" } }');
    await file(nestedOnly, 'app/package-lock.json', legacy);
    const nested = await collectProject(nestedOnly);
    expect(nested.dependencies?.packages.some((p) => p.direct)).toBe(false);
  });

  it('lists a yarn or pnpm lockfile of the root without opening it', async () => {
    const root = await tmp();
    await file(root, 'package.json', '{ "dependencies": { "a": "^1" } }');
    await file(root, 'yarn.lock', '# POISON_yarn\n');
    await file(root, 'pnpm-lock.yaml', 'POISON_pnpm: 1\n');
    await file(root, 'app/yarn.lock', '# POISON_nested\n');
    const project = await collectProject(root);
    expect(project.dependencies?.lockfiles.map((l) => [l.file, l.kind, l.status])).toEqual([
      ['pnpm-lock.yaml', 'pnpm', 'unsupported'],
      ['yarn.lock', 'yarn', 'unsupported'],
    ]);
    expect(project.files).toEqual(['package.json']);
    expect(project.filesOpened).toBe(1);
    expect(project.unreadable).toEqual([]);
  });

  it('records a lockfile it cannot use as unreadable, with a reason code and nothing of its content', async () => {
    const root = await tmp();
    await file(root, 'package.json', '{}');
    await file(root, 'package-lock.json', '<<<<<<< POISON_conflict\n{');
    await file(root, 'a/package-lock.json', Buffer.from([0x7b, 0x00, 0x7d]));
    await file(root, 'b/package-lock.json', '{ "lockfileVersion": 9, "POISON": true }');
    await file(root, 'c/package-lock.json', lock(['baip-ok@1.0.0']));
    await file(root, 'target-of-link.json', lock(['POISON-linked@1.0.0']));
    await mkdir(join(root, 'd'));
    await symlink(join(root, 'target-of-link.json'), join(root, 'd', 'package-lock.json'));
    const project = await collectProject(root);
    expect(
      project.dependencies?.lockfiles.map((l) => [l.file, l.status, l.lockfileVersion]),
    ).toEqual([
      ['a/package-lock.json', 'unreadable', null],
      ['b/package-lock.json', 'unreadable', null],
      ['c/package-lock.json', 'read', 3],
      ['package-lock.json', 'unreadable', null],
    ]);
    expect(project.unreadable).toEqual([
      { file: 'a/package-lock.json', kind: 'binary' },
      { file: 'b/package-lock.json', kind: 'json' },
      { file: 'package-lock.json', kind: 'json' },
    ]);
    expect(project.files).toEqual(['c/package-lock.json', 'package.json']);
    expect(project.filesOpened).toBe(project.files.length + project.unreadable.length);
    expect(project.dependencies?.packages.map((p) => p.name)).toEqual(['baip-ok']);
    expect(JSON.stringify(project)).not.toContain('POISON');
  });

  it(`reads a lockfile over ${MAX_FILE_BYTES} bytes and refuses one over ${MAX_LOCKFILE_BYTES}`, async () => {
    const root = await tmp();
    await file(root, 'package.json', '{}');
    // Larger than any other file may be, and still a lockfile.
    const padded = lock(['baip-big@1.0.0']).replace(
      '"lockfileVersion": 3',
      `"lockfileVersion": 3, "padding": "${'x'.repeat(MAX_FILE_BYTES + 1024)}"`,
    );
    expect(Buffer.byteLength(padded)).toBeGreaterThan(MAX_FILE_BYTES);
    await file(root, 'package-lock.json', padded);
    // Over the limit: refused from its size, never read (a sparse file costs no disk).
    await file(root, 'app/package-lock.json', '{}');
    await truncate(join(root, 'app', 'package-lock.json'), MAX_LOCKFILE_BYTES + 1);
    // The limit of a lockfile is not the limit of any other file.
    await file(root, 'srv/big.cds', Buffer.alloc(MAX_FILE_BYTES + 1, 0x20));

    const project = await collectProject(root);
    expect(project.dependencies?.lockfiles.map((l) => [l.file, l.status, l.kept])).toEqual([
      ['app/package-lock.json', 'too-large', 0],
      ['package-lock.json', 'read', 1],
    ]);
    expect(project.unreadable).toEqual([
      { file: 'app/package-lock.json', kind: 'too-large' },
      { file: 'srv/big.cds', kind: 'too-large' },
    ]);
    expect(project.files).toEqual(['package-lock.json', 'package.json']);
    expect(project.filesOpened).toBe(4);
    expect(project.dependencies?.packages.map((p) => p.name)).toEqual(['baip-big']);
  });

  it('records a lockfile with more keys than the shape limits allow as too large', async () => {
    const root = await tmp();
    await file(root, 'package.json', '{}');
    let keys = '';
    for (let i = 0; i <= 200_000; i += 1) keys += `${i === 0 ? '' : ','}"node_modules/p${i}":0`;
    await file(root, 'package-lock.json', `{"lockfileVersion":3,"packages":{${keys}}}`);
    const project = await collectProject(root);
    expect(project.dependencies?.lockfiles).toMatchObject([
      { file: 'package-lock.json', status: 'too-large', lockfileVersion: null },
    ]);
    expect(project.unreadable).toEqual([{ file: 'package-lock.json', kind: 'too-large' }]);
  });

  it('never keeps the name of a package that matches an exclude pattern', async () => {
    const root = await tmp();
    await file(root, 'package.json', '{}');
    await file(
      root,
      'package-lock.json',
      lock(['@poison-corp/billing@1.0.0', 'poison-internal-tool@2.0.0', 'baip-kept@1.0.0']),
    );
    await file(
      root,
      'app/package-lock.json',
      lock(['@POISON-corp/ledger@1.0.0', 'baip-kept@1.0.0']),
    );
    const project = await collectProject(root, {
      dependencyExclude: ['@poison-corp/*', '*-internal-*'],
    });
    expect(project.dependencies?.packages.map((p) => `${p.name}@${p.version}`)).toEqual([
      'baip-kept@1.0.0',
    ]);
    expect(
      project.dependencies?.lockfiles.map((l) => [l.file, l.kept, l.notKept.excluded]),
    ).toEqual([
      ['app/package-lock.json', 1, 1],
      ['package-lock.json', 1, 2],
    ]);
    // Neither the names nor the patterns are in the record.
    expect(JSON.stringify(project)).not.toMatch(/poison/i);

    const all = await collectProject(root);
    expect(all.dependencies?.packages).toHaveLength(4);
  });

  it('keeps no more packages than the budget: a lockfile that does not fit is not kept at all', async () => {
    const root = await tmp();
    await file(root, 'package.json', '{}');
    await file(root, 'package-lock.json', lock(['a@1.0.0', 'b@1.0.0']));
    // One new package next to two known ones fits; three new ones do not.
    await file(root, 'app/package-lock.json', lock(['a@1.0.0', 'b@1.0.0', 'c@1.0.0']));
    await file(root, 'srv/package-lock.json', lock(['d@1.0.0', 'e@1.0.0', 'f@1.0.0']));
    await file(root, 'web/package-lock.json', lock(['a@1.0.0']));
    const project = await collectProject(root, { maxPackages: 3 });
    expect(
      project.dependencies?.lockfiles.map((l) => [l.file, l.status, l.kept, l.lockfileVersion]),
    ).toEqual([
      ['app/package-lock.json', 'read', 3, 3],
      ['package-lock.json', 'read', 2, 3],
      ['srv/package-lock.json', 'too-many-packages', 0, 3],
      ['web/package-lock.json', 'read', 1, 3],
    ]);
    expect(project.dependencies?.packages.map((p) => p.name)).toEqual(['a', 'b', 'c']);
    // It was opened and parsed, so it is among the files; its status says what became of it.
    expect(project.files).toContain('srv/package-lock.json');
    expect(project.unreadable).toEqual([]);
    expect(project.filesOpened).toBe(project.files.length);

    const none = await collectProject(root, { maxPackages: 0 });
    expect(none.dependencies?.packages).toEqual([]);
    expect(none.dependencies?.lockfiles.every((l) => l.status === 'too-many-packages')).toBe(true);
  });

  it(`reads at most ${MAX_LOCKFILES} lockfiles, the root one among them, and counts the others`, async () => {
    const root = await tmp();
    await file(root, 'package.json', '{}');
    await file(root, 'package-lock.json', lock(['baip-root@1.0.0']));
    for (let i = 0; i < MAX_LOCKFILES + 2; i += 1) {
      await file(
        root,
        `app/m${String(i).padStart(2, '0')}/package-lock.json`,
        lock([`baip-m${i}@1.0.0`]),
      );
    }
    const project = await collectProject(root);
    expect(project.dependencies?.lockfiles).toHaveLength(MAX_LOCKFILES);
    expect(project.dependencies?.lockfilesNotRead).toBe(3);
    expect(project.dependencies?.lockfiles.at(-1)?.file).toBe('package-lock.json');
    expect(project.dependencies?.packages.map((p) => p.name)).toContain('baip-root');
    expect(project.dependencies?.packages).toHaveLength(MAX_LOCKFILES);
    expect(project.filesOpened).toBe(MAX_LOCKFILES + 1);
    expect(RawProjectSchema.safeParse(project).success).toBe(true);
  });

  it('gives the lockfiles a byte budget of their own, and counts a lockfile it leaves unopened', async () => {
    expect(MAX_LOCKFILE_TOTAL_BYTES).toBe(2 * MAX_LOCKFILE_BYTES);
    const root = await tmp();
    await file(root, 'package.json', '{}');
    await file(root, 'package-lock.json', paddedLockfile(MAX_LOCKFILE_BYTES));
    await file(root, 'a/package-lock.json', paddedLockfile(MAX_LOCKFILE_BYTES - 1024));
    // 1 KiB is left: a larger lockfile is too large, a smaller one is read.
    await file(root, 'b/package-lock.json', paddedLockfile(2048));
    await file(root, 'c/package-lock.json', paddedLockfile(1024));
    // Nothing is left: not opened at all.
    await file(root, 'd/package-lock.json', lock(['POISON-not-opened@1.0.0']));
    // The other files have their own budget and are read as before.
    await file(root, 'srv/service.cds', 'service S {}');

    const project = await collectProject(root);
    expect(project.dependencies?.lockfiles.map((l) => [l.file, l.status])).toEqual([
      ['a/package-lock.json', 'read'],
      ['b/package-lock.json', 'too-large'],
      ['c/package-lock.json', 'read'],
      ['package-lock.json', 'read'],
    ]);
    expect(project.dependencies?.lockfilesNotRead).toBe(1);
    expect(project.unreadable).toEqual([{ file: 'b/package-lock.json', kind: 'too-large' }]);
    expect(project.files).toEqual([
      'a/package-lock.json',
      'c/package-lock.json',
      'package-lock.json',
      'package.json',
      'srv/service.cds',
    ]);
    expect(project.filesOpened).toBe(project.files.length + project.unreadable.length);
    expect(project.cdsFiles.map((f) => f.file)).toEqual(['srv/service.cds']);
    expect(JSON.stringify(project)).not.toContain('POISON');
  }, 60_000);

  it('reads the root lockfile of a project that already used up the files a scan opens', async () => {
    const root = await tmp();
    await file(root, 'package.json', '{ "name": "acme", "dependencies": { "baip-server": "^2" } }');
    await mkdir(join(root, 'db'));
    for (let i = 0; i < MAX_FILES_OPENED; i += 500) {
      await Promise.all(
        Array.from({ length: 500 }, (_, k) =>
          writeFile(join(root, 'db', `e${String(i + k).padStart(4, '0')}.cds`), 'entity E {}'),
        ),
      );
    }
    await file(root, 'package-lock.json', lock(['baip-server@2.4.1'], ['baip-server']));
    await file(root, 'srv/package-lock.json', lock(['baip-merge@4.17.20']));
    const project = await collectProject(root);
    // The other files stop at their limit: package.json and all but one of the cds files.
    expect(project.cdsFiles).toHaveLength(MAX_FILES_OPENED - 1);
    expect(project.filesTruncated).toBe(true);
    // The lockfiles are read all the same: the limit of the other files is not theirs.
    expect(project.dependencies).toEqual({
      lockfiles: [
        {
          file: 'package-lock.json',
          kind: 'package-lock',
          lockfileVersion: 3,
          status: 'read',
          kept: 1,
          notKept: emptyNotKept(),
        },
        {
          file: 'srv/package-lock.json',
          kind: 'package-lock',
          lockfileVersion: 3,
          status: 'read',
          kept: 1,
          notKept: emptyNotKept(),
        },
      ],
      lockfilesNotRead: 0,
      packages: [
        {
          name: 'baip-merge',
          version: '4.17.20',
          direct: false,
          scope: 'prod',
          lockfiles: ['srv/package-lock.json'],
        },
        {
          name: 'baip-server',
          version: '2.4.1',
          direct: true,
          scope: 'prod',
          lockfiles: ['package-lock.json'],
        },
      ],
    });
    expect(project.filesOpened).toBe(MAX_FILES_OPENED + 2);
    expect(project.unreadable).toEqual([]);
    // So the project is not reported as one whose dependencies no lockfile pins.
    expect(runRule(lockfileMissing, project)).toEqual([]);
    expect(runRule(notChecked, project)).toEqual([]);
  }, 60_000);

  it('records no lockfile for a project without one', async () => {
    const root = await tmp();
    await file(root, 'package.json', '{ "dependencies": { "a": "^1" } }');
    const project = await collectProject(root);
    expect(project.dependencies).toEqual({ lockfiles: [], lockfilesNotRead: 0, packages: [] });
    expect(project.filesOpened).toBe(1);
  });
});
