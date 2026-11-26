import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { reanalyze } from '../../src/analyzers/index.js';
import { MAX_DEPRECATION_TABLE_BYTES } from '../../src/collectors/deprecations.js';
import { MAX_TABLE_BYTES } from '../../src/collectors/osv.js';
import { PackageTable } from '../../src/collectors/project/dependencies.js';
import type { LockedPackage } from '../../src/collectors/project/lockfile.js';
import { type JsonShapeLimits, jsonShapeExcess } from '../../src/io/jsonShape.js';
import { rawListBytes } from '../../src/io/jsonSize.js';
import { MAX_RELATIVE_PATH_LENGTH } from '../../src/model/paths.js';
import type { RawAdvisory, RawDeprecation, RawVulnerablePackage } from '../../src/model/raw.js';
import { SnapshotSchema } from '../../src/model/snapshot.js';
import {
  MAX_SNAPSHOT_BYTES,
  MAX_SNAPSHOT_DEPTH,
  MAX_SNAPSHOT_ITEMS,
  MAX_SNAPSHOT_MEMBERS,
  loadableSnapshotText,
  readSnapshot,
  snapshotExcess,
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

/*
 * The lookup on OSV.dev stores at most 20,000 advisories and 20,000
 * vulnerable packages, and both tables together only as far as they take 16
 * MiB of the file (`MAX_TABLE_BYTES`, measured as the collector measures
 * it). The lookup on the npm registry stores at most 20,000 deprecated
 * versions, as far as they take 8 MiB (`MAX_DEPRECATION_TABLE_BYTES`). A
 * project scan at those limits, on top of the 20,000 packages its lockfiles
 * may keep, must load again. The findings a rule raises from the tables come
 * on top; the scan checks the whole result before it writes it
 * (`loadableSnapshotText`).
 */
describe('a project snapshot with the tables of the lookup at their limits', () => {
  const PACKAGES = 20_000;
  const name = (i: number): string => `baip-bulk-${String(i).padStart(5, '0')}`;
  const id = (i: number): string => `GHSA-fake-${String(i).padStart(5, '0')}`;

  interface Tables {
    advisories: RawAdvisory[];
    vulnerablePackages: RawVulnerablePackage[];
    deprecations: RawDeprecation[];
  }

  /**
   * Every package deprecated, each with a message as long as a row holds and
   * a latest version: as many rows as the table can have, near the bytes it
   * may take.
   */
  function deprecations(): RawDeprecation[] {
    return Array.from({ length: PACKAGES }, (_, i) => ({
      name: name(i),
      version: '1.0.0',
      message: 'word '.repeat(40),
      latest: '2.0.0',
      latestDeprecated: i % 2 === 0,
    }));
  }

  /** Each package with `perPackage` advisories that name no fix: the most rows for their bytes. */
  function tables(perPackage: number): Tables {
    return {
      deprecations: deprecations(),
      advisories: Array.from({ length: PACKAGES }, (_, i) => ({
        id: id(i),
        aliases: [],
        summary: null,
        cvssV3: null,
        label: null,
      })),
      vulnerablePackages: Array.from({ length: PACKAGES }, (_, i) => ({
        name: name(i),
        version: '1.0.0',
        advisories: Array.from({ length: perPackage }, (_, k) => ({
          id: id((i + k) % PACKAGES),
          fixed: [],
        })),
      })),
    };
  }

  /**
   * A few advisories that say as much as an advisory can (20 other ids of 100
   * characters, a summary of 200, a score), and every package has all of
   * them: the largest findings for the bytes of the tables.
   */
  function tablesOfLargeFindings(advisories: number): Tables {
    const ids = Array.from({ length: advisories }, (_, i) => id(i));
    return {
      deprecations: deprecations(),
      advisories: ids.map((advisoryId, i) => ({
        id: advisoryId,
        aliases: Array.from({ length: 20 }, (_, k) =>
          `CVE-${i}-${k}-${'9'.repeat(100)}`.slice(0, 100),
        ),
        summary: 'word '.repeat(40).trim(),
        cvssV3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        label: 'CRITICAL' as const,
      })),
      vulnerablePackages: Array.from({ length: PACKAGES }, (_, i) => ({
        name: name(i),
        version: '1.0.0',
        advisories: ids.map((advisoryId) => ({ id: advisoryId, fixed: [] })),
      })),
    };
  }

  const tableBytes = (found: Tables): number =>
    rawListBytes(found.advisories) + rawListBytes(found.vulnerablePackages);

  function atTheLimits(found: Tables): Record<string, unknown> {
    const sample = readFixture('sample-project-snapshot.json');
    const raw = sample.raw as Record<string, unknown> & { projects: Record<string, unknown>[] };
    const dependencies = raw.projects[0]?.dependencies as Record<string, unknown>;
    raw.projects[0] = {
      ...raw.projects[0],
      dependencies: {
        ...dependencies,
        packages: Array.from({ length: PACKAGES }, (_, i) => ({
          name: name(i),
          version: '1.0.0',
          direct: false,
          scope: 'prod',
          lockfiles: ['package-lock.json'],
        })),
      },
    };
    raw.advisories = found.advisories;
    raw.vulnerablePackages = found.vulnerablePackages;
    raw.deprecations = found.deprecations;
    return sample;
  }

  it('holds as many rows as fit into 16 MiB: six advisories for each of 20,000 packages', () => {
    expect(tableBytes(tables(6))).toBeLessThanOrEqual(MAX_TABLE_BYTES);
    expect(tableBytes(tables(6))).toBeGreaterThan(0.9 * MAX_TABLE_BYTES);
    // One more each and the collector stores nothing.
    expect(tableBytes(tables(7))).toBeGreaterThan(MAX_TABLE_BYTES);
  });

  it('holds a deprecation with a message of 200 characters for each of 20,000 packages in 8 MiB', () => {
    const rows = deprecations();
    expect(rows[0]?.message).toHaveLength(200);
    expect(rawListBytes(rows)).toBeLessThanOrEqual(MAX_DEPRECATION_TABLE_BYTES);
    expect(rawListBytes(rows)).toBeGreaterThan(0.85 * MAX_DEPRECATION_TABLE_BYTES);
    // With characters of three bytes each not every package fits: the collector then stores nothing.
    const widest = rows.map((row) => ({ ...row, message: '\u20ac'.repeat(200) }));
    expect(rawListBytes(widest)).toBeGreaterThan(MAX_DEPRECATION_TABLE_BYTES);
    expect(rawListBytes(widest.slice(0, 10_900))).toBeLessThanOrEqual(MAX_DEPRECATION_TABLE_BYTES);
  });

  it('loads again, written as a scan writes it, with room to spare', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'baip-lens-capacity-'));
    created.push(dir);
    const path = join(dir, 'snapshot.json');
    const text = JSON.stringify(atTheLimits(tables(6)), null, 2);
    // What the scan itself checks before it writes.
    expect(snapshotExcess(text)).toBeUndefined();
    await writeFile(path, text);
    const bytes = await readFile(path);
    expect(bytes.length).toBeLessThan(MAX_SNAPSHOT_BYTES / 4);
    // The packages and both tables take under half of the keys and values a snapshot may hold.
    expect(jsonShapeExcess(bytes, itemLimit(0.5 * MAX_SNAPSHOT_ITEMS))).toBeUndefined();
    const snapshot = await readSnapshot(path);
    expect(snapshot.raw.projects[0]?.dependencies?.packages).toHaveLength(PACKAGES);
    expect(snapshot.raw.advisories).toHaveLength(PACKAGES);
    expect(snapshot.raw.vulnerablePackages).toHaveLength(PACKAGES);
    expect(snapshot.raw.vulnerablePackages.at(-1)?.advisories).toHaveLength(6);
    expect(snapshot.raw.deprecations).toHaveLength(PACKAGES);
    expect(snapshot.raw.deprecations.at(-1)?.message).toHaveLength(200);
  }, 60_000);

  /**
   * The whole result of such a scan: the tables, and on top of them the
   * finding the rule raises for every package, checked and written as
   * `baip-lens project` does it, and read back.
   */
  async function writtenAndReadBack(found: Tables) {
    const scanned = reanalyze(SnapshotSchema.parse(atTheLimits(found)));
    // The check `baip-lens project` makes before it writes anything: it does not refuse this.
    const text = loadableSnapshotText(scanned, 'unused');
    const dir = await mkdtemp(join(tmpdir(), 'baip-lens-capacity-'));
    created.push(dir);
    const path = join(dir, 'snapshot.json');
    await writeFile(path, text);
    const snapshot = await readSnapshot(path);
    const vulnerable = snapshot.findings.filter((finding) => finding.id === 'DEP_KNOWN_CVE');
    return { bytes: Buffer.byteLength(text, 'utf8'), text, snapshot, vulnerable };
  }

  it('loads again with a finding for every one of 20,000 vulnerable packages', async () => {
    const { bytes, text, snapshot, vulnerable } = await writtenAndReadBack(tables(6));
    expect(vulnerable).toHaveLength(PACKAGES);
    expect(vulnerable.at(-1)?.evidence).toMatchObject({ advisoryCount: 6, lockfileCount: 1 });
    expect(snapshot.raw.vulnerablePackages).toHaveLength(PACKAGES);
    // The table of the registry at its limit is in the same file.
    expect(snapshot.raw.deprecations).toHaveLength(PACKAGES);
    // The findings are the larger part: with them the file takes about half of what it may.
    expect(bytes).toBeGreaterThan(MAX_SNAPSHOT_BYTES / 4);
    expect(bytes).toBeLessThan(0.6 * MAX_SNAPSHOT_BYTES);
    expect(
      jsonShapeExcess(Buffer.from(text), itemLimit(0.75 * MAX_SNAPSHOT_ITEMS)),
    ).toBeUndefined();
  }, 120_000);

  it('loads again when every one of those findings is as large as the rule makes one', async () => {
    // Eight advisories for each package fit into the tables; a ninth each does not.
    const found = tablesOfLargeFindings(8);
    expect(tableBytes(found)).toBeLessThanOrEqual(MAX_TABLE_BYTES);
    expect(tableBytes(tablesOfLargeFindings(9))).toBeGreaterThan(MAX_TABLE_BYTES);

    const { bytes, snapshot, vulnerable } = await writtenAndReadBack(found);
    expect(vulnerable).toHaveLength(PACKAGES);
    expect(snapshot.raw.deprecations).toHaveLength(PACKAGES);
    expect(vulnerable.at(-1)?.evidence).toMatchObject({
      advisoryCount: 8,
      fixedIn: null,
      score: 9.8,
    });
    // Eight ids, ten other ids of 100 characters and a summary of 200 in each finding.
    expect(vulnerable.at(-1)?.evidence.aliases).toHaveLength(10);
    expect(bytes).toBeGreaterThan(0.6 * MAX_SNAPSHOT_BYTES);
    expect(bytes).toBeLessThan(MAX_SNAPSHOT_BYTES);
  }, 120_000);
});
