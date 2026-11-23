import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { PackageTable } from '../../src/collectors/project/dependencies.js';
import type { LockedPackage } from '../../src/collectors/project/lockfile.js';
import { type JsonShapeLimits, jsonShapeExcess } from '../../src/io/jsonShape.js';
import { MAX_RELATIVE_PATH_LENGTH } from '../../src/model/paths.js';
import {
  MAX_SNAPSHOT_BYTES,
  MAX_SNAPSHOT_DEPTH,
  MAX_SNAPSHOT_ITEMS,
  MAX_SNAPSHOT_MEMBERS,
  readSnapshot,
} from '../../src/snapshot.js';
import { fixturePath, readFixture, realShapedSnapshot } from '../support/snapshotText.js';

/*
 * The limits of SEC-21 must never refuse a real snapshot: the recorded ones,
 * from every version, and the largest a real landscape could write. A
 * real-shaped app takes 157 keys and values, 3,190 bytes pretty-printed (as
 * `writeSnapshot` writes it) and 2,288 bytes minified, so the item limit is
 * the one a real snapshot meets first, at about 26,000 apps.
 */

const created: string[] = [];
afterAll(async () => {
  await Promise.all(created.map((dir) => rm(dir, { recursive: true, force: true })));
});

/** Writes `apps` real-shaped apps and returns the file. The text is not kept. */
async function writeRealShaped(apps: number, indent?: number): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'baip-lens-capacity-'));
  created.push(dir);
  const path = join(dir, 'snapshot.json');
  await writeFile(path, JSON.stringify(realShapedSnapshot(apps), null, indent));
  return path;
}

const itemLimit = (maxItems: number): JsonShapeLimits => ({
  maxDepth: MAX_SNAPSHOT_DEPTH,
  maxItems,
  maxMembers: MAX_SNAPSHOT_MEMBERS,
});

describe('real snapshots load within the limits', () => {
  it.each([
    'sample-snapshot.json',
    'sample-project-snapshot.json',
    'legacy/snapshot-0.1.0.json',
    'legacy/project-snapshot-0.3.1.json',
    'history/acme-previous.json',
  ])('%s', async (name) => {
    await expect(readSnapshot(fixturePath(name))).resolves.toMatchObject({ schemaVersion: 1 });
  });

  it.each([
    ['as a scan writes them', 2],
    ['without whitespace', undefined],
  ])(
    'loads 26,000 apps written %s, close to the item limit',
    async (_, indent) => {
      const path = await writeRealShaped(26_000, indent);
      const bytes = await readFile(path);
      expect(bytes.length).toBeLessThan(MAX_SNAPSHOT_BYTES);
      // Within 5 % of the limit, so the limit is not tighter than this.
      expect(jsonShapeExcess(bytes, itemLimit(0.95 * MAX_SNAPSHOT_ITEMS))).toBe('items');
      const snapshot = await readSnapshot(path);
      expect(snapshot.apps).toHaveLength(26_000);
      expect(snapshot.raw.apps).toHaveLength(26_000);
    },
    120_000,
  );
});

/*
 * A scan keeps at most 20,000 packages of the lockfiles, each with at most
 * 20 lockfile paths, and at most 50 lockfile records per project. A record
 * with that many of each, and paths of an ordinary length, must load again:
 * a scan must never write a snapshot that `report --from` refuses. (The
 * longest paths the model allows are the case after this one.)
 */
describe('a project snapshot at the limits of its lockfiles', () => {
  const PACKAGES = 20_000;
  const LOCKFILES_PER_PACKAGE = 20;
  const LOCKFILES = 50;

  function atTheLimits(): Record<string, unknown> {
    const sample = readFixture('sample-project-snapshot.json');
    const raw = sample.raw as { projects: Record<string, unknown>[] };
    const paths = Array.from(
      { length: LOCKFILES },
      (_, i) => `packages/module-${String(i).padStart(2, '0')}/package-lock.json`,
    );
    const first = (raw.projects[0]?.dependencies as { lockfiles: Record<string, unknown>[] })
      .lockfiles[0];
    raw.projects[0] = {
      ...raw.projects[0],
      dependencies: {
        lockfiles: paths.map((file) => ({ ...first, file })),
        lockfilesNotRead: 7,
        packages: Array.from({ length: PACKAGES }, (_, i) => ({
          // The longest name and version the patterns allow.
          name: `@baip-fixture/${'p'.repeat(193)}${String(i).padStart(7, '0')}`,
          version: `1.0.0-${'9'.repeat(58)}`,
          direct: i % 2 === 0,
          scope: 'prod',
          lockfiles: paths.slice(0, LOCKFILES_PER_PACKAGE),
        })),
      },
    };
    return sample;
  }

  it.each([
    ['as a scan writes it', 2],
    ['without whitespace', undefined],
  ])(
    'loads 20,000 packages pinned by 20 lockfiles each, written %s',
    async (_, indent) => {
      const dir = await mkdtemp(join(tmpdir(), 'baip-lens-capacity-'));
      created.push(dir);
      const path = join(dir, 'snapshot.json');
      await writeFile(path, JSON.stringify(atTheLimits(), null, indent));
      const bytes = await readFile(path);
      expect(bytes.length).toBeLessThan(MAX_SNAPSHOT_BYTES / 2);
      // A fifth of the item limit at most: the limits of the lists apply long before the file's.
      expect(jsonShapeExcess(bytes, itemLimit(0.2 * MAX_SNAPSHOT_ITEMS))).toBeUndefined();
      const snapshot = await readSnapshot(path);
      const dependencies = snapshot.raw.projects[0]?.dependencies;
      expect(dependencies?.packages).toHaveLength(PACKAGES);
      expect(dependencies?.packages[0]?.name).toHaveLength(214);
      expect(dependencies?.packages[0]?.version).toHaveLength(64);
      expect(dependencies?.packages[0]?.lockfiles).toHaveLength(LOCKFILES_PER_PACKAGE);
      expect(dependencies?.lockfiles).toHaveLength(LOCKFILES);
    },
    60_000,
  );
});

/*
 * The model alone allows more than a snapshot file may hold: 20 lockfile
 * paths of 512 characters for each of 20,000 packages are about 200 MB. The
 * collector therefore bounds the bytes of the paths a package keeps
 * (`MAX_PACKAGE_LOCKFILE_BYTES`). Here the package list is built by the
 * collector's own table from the longest names, versions and paths the model
 * allows, and written as a scan writes it.
 */
describe('the largest project record the collector can write', () => {
  const PACKAGES = 20_000;
  const LOCKFILES = 20;

  /** `LOCKFILES` lockfile paths of the longest length the model allows, made of `fill`. */
  function longestPaths(fill: string): string[] {
    return Array.from({ length: LOCKFILES }, (_, i) => {
      const tail = `/m${String(i).padStart(2, '0')}/package-lock.json`;
      return `${fill.repeat(MAX_RELATIVE_PATH_LENGTH - tail.length)}${tail}`;
    });
  }

  function largestProject(paths: string[]): Record<string, unknown> {
    const packages: LockedPackage[] = Array.from({ length: PACKAGES }, (_, i) => ({
      name: `@baip-fixture/${'p'.repeat(193)}${String(i).padStart(7, '0')}`,
      version: `1.0.0-${'9'.repeat(58)}`,
      direct: i % 2 === 0,
      scope: 'prod',
    }));
    const table = new PackageTable(PACKAGES);
    for (const path of paths) expect(table.add(path, packages)).toBe(true);
    const sample = readFixture('sample-project-snapshot.json');
    const raw = sample.raw as { projects: Record<string, unknown>[] };
    const first = (raw.projects[0]?.dependencies as { lockfiles: Record<string, unknown>[] })
      .lockfiles[0];
    raw.projects[0] = {
      ...raw.projects[0],
      dependencies: {
        lockfiles: paths.map((file) => ({ ...first, file })),
        lockfilesNotRead: 0,
        packages: table.list(),
      },
    };
    return sample;
  }

  it.each([
    // 20 x 102 bytes: the most lockfiles a package names.
    ['paths of 100 characters', longestPaths('d').map((p) => p.slice(-100)), 20, 0.5],
    ['the longest paths', longestPaths('d'), 3, 0.5],
    ['the longest paths, of three-byte characters', longestPaths('\u20ac'), 1, 0.5],
    // One path is always kept, also when JSON writes each of its characters as six.
    ['the longest paths, of characters JSON escapes', longestPaths('\u0001'), 1, 1],
  ] as const)(
    'loads 20,000 packages pinned by 20 lockfiles with %s',
    async (_, paths, kept, share) => {
      expect(new Set(paths.map((path) => path.length))).toEqual(new Set([paths[0]?.length]));
      const dir = await mkdtemp(join(tmpdir(), 'baip-lens-capacity-'));
      created.push(dir);
      const path = join(dir, 'snapshot.json');
      await writeFile(path, JSON.stringify(largestProject([...paths]), null, 2));
      const bytes = (await stat(path)).size;
      expect(bytes).toBeLessThan(share * MAX_SNAPSHOT_BYTES);
      const snapshot = await readSnapshot(path);
      const dependencies = snapshot.raw.projects[0]?.dependencies;
      expect(dependencies?.packages).toHaveLength(PACKAGES);
      expect(dependencies?.packages[0]?.name).toHaveLength(214);
      expect(dependencies?.packages[0]?.lockfiles).toEqual(paths.slice(0, kept));
      expect(dependencies?.packages.at(-1)?.lockfiles).toEqual(paths.slice(0, kept));
      // Without the bound the same record is one `report --from` would refuse.
      const unbounded = PACKAGES * paths.reduce((sum, p) => sum + Buffer.byteLength(p), 0);
      if (paths[0]?.length === MAX_RELATIVE_PATH_LENGTH) {
        expect(unbounded).toBeGreaterThan(MAX_SNAPSHOT_BYTES);
      }
    },
    120_000,
  );
});
