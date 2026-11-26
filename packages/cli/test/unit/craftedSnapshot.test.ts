import { mkdtemp, open, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ConfigError } from '../../src/http/errors.js';
import { readSnapshot } from '../../src/snapshot.js';
import {
  type JsonPath,
  nested,
  readFixture,
  repeated,
  splitAt,
  withJsonAt,
} from '../support/snapshotText.js';

/*
 * Crafted snapshots. Before the limits of SEC-21, most of these made
 * `report --from` and `scan --previous` die out of memory (1.1 to 2.1 GB,
 * then SIGABRT instead of exit code 2), overflow the stack, take 8 to 14
 * seconds and a gigabyte or more, or load and break the reporters later.
 * Each is now refused, or loaded, within seconds and a few hundred
 * megabytes.
 *
 * Memory is measured as the growth of this process's peak resident size, a
 * high-water mark: garbage is collected before each read, and the large
 * files are written a megabyte at a time, so the mark ends at the costliest
 * read plus what the earlier ones kept. That holds only while this file has
 * a process of its own, which vitest gives every test file (`isolate`, on by
 * default); beforeAll checks it.
 */

const cf = readFixture('sample-snapshot.json');
const project = readFixture('sample-project-snapshot.json');
const MB = 1024 * 1024;
const peakRss = (): number => process.resourceUsage().maxRSS * 1024;

type Write = (path: string) => Promise<void>;

/** The snapshot with the value at `at` replaced by the text `json`. */
const text =
  (base: typeof cf, at: JsonPath, json: () => string): Write =>
  (path) =>
    writeFile(path, withJsonAt(base, at, json()));

/**
 * The snapshot with the value at `at` replaced by `count` members, `member(i)`
 * each, between `open` and `close`, written a megabyte at a time, so that
 * building the file costs the test no more than reading it.
 */
const joined =
  (
    base: typeof cf,
    at: JsonPath,
    [start, end]: [string, string],
    count: number,
    member: (i: number) => string,
  ): Write =>
  async (path) => {
    const [head, tail] = splitAt(base, at);
    const handle = await open(path, 'w');
    try {
      let batch = `${head}${start}`;
      for (let i = 0; i < count; i++) {
        batch += i === 0 ? member(i) : `,${member(i)}`;
        if (batch.length > MB) {
          await handle.write(batch);
          batch = '';
        }
      }
      await handle.write(`${batch}${end}${tail}`);
    } finally {
      await handle.close();
    }
  };

/** A project whose CDS files each declare 500 services requiring 50 invalid roles. */
function projectWithInvalidRoles(cdsFiles: number): string {
  const service = JSON.stringify({
    name: 'S',
    line: 1,
    requires: '\u0000roles',
    restrictTo: [],
    protocolNone: false,
    external: false,
    entities: [],
    actions: [],
  }).replace('"\\u0000roles"', repeated('"!"', 50));
  const file = JSON.stringify({
    file: 'srv/s.cds',
    usings: [],
    services: '\u0000services',
    entities: [],
    annotates: [],
  }).replace('"\\u0000services"', repeated(service, 500));
  return repeated(file, cdsFiles);
}

/** A distinct key: one the parser has not seen costs the most. */
const key = (i: number) => `"k${i.toString(36)}":0`;

/** A finding whose evidence holds 1,000 distinct keys. */
function wideFinding(i: number): string {
  const finding = (cf.findings as unknown[])[0] as Record<string, unknown>;
  let keys = '';
  for (let k = 0; k < 1_000; k++) keys += k === 0 ? key(i * 1_000) : `,${key(i * 1_000 + k)}`;
  return JSON.stringify({ ...finding, evidence: '\u0000e' }).replace('"\\u0000e"', `{${keys}}`);
}

const PACKAGES: JsonPath = ['raw', 'projects', 0, 'dependencies', 'packages'];

/** A package of a lockfile whose lockfile paths are 20 values that are not paths. */
const packageWithInvalidLockfiles = JSON.stringify({
  name: 'baip-fixture-server',
  version: '1.0.0',
  direct: false,
  scope: 'prod',
  lockfiles: '\u0000paths',
}).replace('"\\u0000paths"', repeated('"../up"', 20));

/** The sample project under another id, with 20,000 valid packages of its lockfile. */
function projectWithPackages(i: number): string {
  const sample = (project.raw as { projects: Record<string, unknown>[] }).projects[0]!;
  const dependencies = sample.dependencies as Record<string, unknown>;
  let packages = '';
  for (let k = 0; k < 20_000; k++) {
    packages +=
      `${k === 0 ? '' : ','}{"name":"baip-p${k}","version":"1.0.${i}","direct":false,` +
      '"scope":"prod","lockfiles":["package-lock.json"]}';
  }
  return JSON.stringify({
    ...sample,
    id: `acme-${i}`,
    dependencies: { ...dependencies, packages: '\u0000packages' },
  }).replace('"\\u0000packages"', () => `[${packages}]`);
}

/** A package of the lookup on OSV.dev whose advisories are 100 values that are not advisories. */
const vulnerableWithInvalidAdvisories = JSON.stringify({
  name: 'baip-fixture-server',
  version: '1.0.0',
  advisories: '\u0000advisories',
}).replace('"\\u0000advisories"', repeated('{}', 100));

/** An advisory whose aliases are 20 values that are not ids. */
const advisoryWithInvalidAliases = JSON.stringify({
  id: 'GHSA-fake-0001-baip',
  aliases: '\u0000aliases',
  summary: null,
  cvssV3: null,
  label: null,
}).replace('"\\u0000aliases"', repeated('"not an id"', 20));

/** A row of the lookup on the npm registry whose latest version is no version. */
const deprecationWithInvalidLatest = JSON.stringify({
  name: 'baip-fixture-server',
  version: '1.0.0',
  message: 'm'.repeat(200),
  latest: '../../up',
  latestDeprecated: true,
});

const ARRAY: [string, string] = ['[', ']'];
const OBJECT: [string, string] = ['{', '}'];

/** What each file holds, and how it is written. */
const CRAFTED: [string, Write][] = [
  ['4 MB of {} in the inventory', text(cf, ['apps'], () => repeated('{}', 1_400_000))],
  ['4 MB of {} in the findings', text(cf, ['findings'], () => repeated('{}', 1_400_000))],
  ['4 MB of {} in the checks', text(cf, ['checks'], () => repeated('{}', 1_400_000))],
  ['4 MB of {} in raw.apps', text(cf, ['raw', 'apps'], () => repeated('{}', 1_400_000))],
  [
    '4 MB of {} in raw.projects',
    text(project, ['raw', 'projects'], () => repeated('{}', 1_400_000)),
  ],
  [
    '4 MB of {} in the packages of a project',
    text(project, PACKAGES, () => repeated('{}', 1_400_000)),
  ],
  [
    '4 MB of {} in the lockfiles of a project',
    text(project, ['raw', 'projects', 0, 'dependencies', 'lockfiles'], () =>
      repeated('{}', 1_400_000),
    ),
  ],
  [
    '3 MB of packages with invalid lockfile paths',
    text(project, PACKAGES, () => repeated(packageWithInvalidLockfiles, 20_000)),
  ],
  [
    '4 MB of {} in the advisories of the lookup',
    text(project, ['raw', 'advisories'], () => repeated('{}', 1_400_000)),
  ],
  [
    '4 MB of {} in the vulnerable packages of the lookup',
    text(project, ['raw', 'vulnerablePackages'], () => repeated('{}', 1_400_000)),
  ],
  [
    '6 MB of vulnerable packages with invalid advisories',
    text(project, ['raw', 'vulnerablePackages'], () =>
      repeated(vulnerableWithInvalidAdvisories, 20_000),
    ),
  ],
  [
    '6 MB of advisories with invalid aliases',
    text(project, ['raw', 'advisories'], () => repeated(advisoryWithInvalidAliases, 20_000)),
  ],
  [
    '4 MB of {} in the deprecations of the lookup',
    text(project, ['raw', 'deprecations'], () => repeated('{}', 1_400_000)),
  ],
  [
    '6 MB of deprecations with an invalid latest version',
    text(project, ['raw', 'deprecations'], () => repeated(deprecationWithInvalidLatest, 20_000)),
  ],
  ['4 MB of 0 in raw.apps', text(cf, ['raw', 'apps'], () => repeated('0', 2_000_000))],
  [
    '4 MB of project services with invalid roles',
    text(project, ['raw', 'projects', 0, 'cdsFiles'], () => projectWithInvalidRoles(27)),
  ],
  [
    'a finding with evidence nested a million levels deep',
    text(cf, ['findings', 0, 'evidence', 'deep'], () => nested('0', 1_000_000)),
  ],
  ['13 MB of [] under a key the schema drops', text(cf, ['junk'], () => repeated('[]', 4_500_000))],
  [
    "42 MB of distinct keys in a finding's evidence",
    joined(cf, ['findings', 0, 'evidence'], OBJECT, 4_190_000, key),
  ],
  // The costliest files the limits let through to the parser, both just under the item limit.
  ['12 MB of {} in the inventory', text(cf, ['apps'], () => repeated('{}', 4_190_000))],
  [
    '16 MB of objects with a distinct key each in raw.apps',
    joined(cf, ['raw', 'apps'], ARRAY, 1_396_000, (i) => `{${key(i)}}`),
  ],
];

function collectGarbage(): void {
  if (globalThis.gc === undefined) throw new Error('run with --expose-gc (vitest.config.ts)');
  globalThis.gc();
}

describe('reading a crafted snapshot', () => {
  let dir = '';
  let before = 0;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), 'baip-lens-crafted-'));
    collectGarbage();
    before = peakRss();
    // A fresh process starts near 60 MB; far more means another file ran here first.
    if (before > 300 * MB) throw new Error('this file needs a process of its own (vitest isolate)');
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  /** Writes the file, then reads it with garbage collected first; returns the outcome. */
  async function read(name: string, write: Write) {
    const path = join(dir, `${name.replace(/\W+/g, '-')}.json`);
    await write(path);
    collectGarbage();
    const start = performance.now();
    const outcome = await readSnapshot(path).then(
      (snapshot) => ({ snapshot, error: undefined }),
      (error: unknown) => ({ snapshot: undefined, error }),
    );
    const seconds = (performance.now() - start) / 1000;
    await rm(path);
    return { ...outcome, seconds };
  }

  // Measured on a laptop: about 0.2 s for a 4 MB file and 1 to 1.5 s for
  // the costliest ones, with the mark rising to about 200 MB and then 530
  // MB. Before the limits, the first case alone passed 1.1 GB or aborted.
  // The bounds leave room for a busy CI runner with coverage on.
  const MAX_SECONDS = 10;
  const MAX_GROWTH_MB = 700;

  it.each(CRAFTED)(
    'refuses %s',
    async (name, write) => {
      const { error, seconds } = await read(name, write);
      expect(error).toBeInstanceOf(ConfigError);
      expect((error as ConfigError).message).toMatch(/^Snapshot .* is not valid: /);
      expect(seconds).toBeLessThan(MAX_SECONDS);
      expect((peakRss() - before) / MB).toBeLessThan(MAX_GROWTH_MB);
    },
    30_000,
  );

  it('loads a valid snapshot whose projects spend the item limit on lockfile packages', async () => {
    // 14 projects at the limit of 20,000 packages each: 14 keys and values per package.
    const { snapshot, error, seconds } = await read(
      'packages at the item limit',
      joined(project, ['raw', 'projects'], ARRAY, 14, projectWithPackages),
    );
    expect(error).toBeUndefined();
    expect(snapshot?.raw.projects).toHaveLength(14);
    expect(snapshot?.raw.projects.every((p) => p.dependencies?.packages.length === 20_000)).toBe(
      true,
    );
    expect(seconds).toBeLessThan(MAX_SECONDS);
    expect((peakRss() - before) / MB).toBeLessThan(MAX_GROWTH_MB);
  }, 30_000);

  it('loads a valid snapshot whose findings spend the item limit on wide evidence', async () => {
    const { snapshot, seconds } = await read(
      'wide evidence',
      joined(cf, ['findings'], ARRAY, 2_050, wideFinding),
    );
    expect(snapshot?.findings).toHaveLength(2_050);
    expect(seconds).toBeLessThan(MAX_SECONDS);
    expect((peakRss() - before) / MB).toBeLessThan(MAX_GROWTH_MB);
  }, 30_000);
});
