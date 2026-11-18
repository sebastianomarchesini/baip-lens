import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { readSnapshot } from '../../src/snapshot.js';
import {
  type JsonPath,
  nested,
  readFixture,
  repeated,
  withJsonAt,
} from '../support/snapshotText.js';

/*
 * Crafted snapshots of a few megabytes. Before the limits of SEC-21, each of
 * these made `report --from` and `scan --previous` die out of memory (1.1 to
 * 2.1 GB, then SIGABRT instead of exit code 2), overflow the stack, take 9 to
 * 14 seconds and 1.5 GB to refuse, or load and break the reporters later.
 * Each is now refused at once. Vitest runs every test file in a process of
 * its own, so the growth of this process's peak resident size is what reading
 * these files cost.
 */

const cf = readFixture('sample-snapshot.json');
const project = readFixture('sample-project-snapshot.json');
const MB = 1024 * 1024;
const peakRss = (): number => process.resourceUsage().maxRSS * 1024;

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
  return withJsonAt(project, ['raw', 'projects', 0, 'cdsFiles'], repeated(file, cdsFiles));
}

const at = (base: typeof cf, path: JsonPath, json: string) => () => withJsonAt(base, path, json);

/** What each file holds, and how it is built (lazily, so only one is in memory at a time). */
const CRAFTED: [string, () => string][] = [
  ['4 MB of {} in the inventory', at(cf, ['apps'], repeated('{}', 1_400_000))],
  ['4 MB of {} in the findings', at(cf, ['findings'], repeated('{}', 1_400_000))],
  ['4 MB of {} in the checks', at(cf, ['checks'], repeated('{}', 1_400_000))],
  ['4 MB of {} in raw.apps', at(cf, ['raw', 'apps'], repeated('{}', 1_400_000))],
  ['4 MB of {} in raw.projects', at(project, ['raw', 'projects'], repeated('{}', 1_400_000))],
  ['4 MB of 0 in raw.apps', at(cf, ['raw', 'apps'], repeated('0', 2_000_000))],
  ['4 MB of project services with invalid roles', () => projectWithInvalidRoles(27)],
  [
    'a finding with evidence nested a million levels deep',
    at(cf, ['findings', 0, 'evidence', 'deep'], nested('0', 1_000_000)),
  ],
  ['13 MB of [] under a key the schema drops', at(cf, ['junk'], repeated('[]', 4_500_000))],
  // The most values the limits let through to the parser: the costliest file to refuse.
  [
    '12 MB of {} in the inventory, just under the value limit',
    at(cf, ['apps'], repeated('{}', 4_190_000)),
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
  });

  it.each(CRAFTED)(
    'refuses %s at once',
    async (name, build) => {
      const path = join(dir, `${name.replace(/\W+/g, '-')}.json`);
      await writeFile(path, build());
      // What an earlier case left behind is freed, so the peak is one read's.
      collectGarbage();
      const start = performance.now();
      await expect(readSnapshot(path)).rejects.toThrow(/^Snapshot .* is not valid: /);
      // Measured on a laptop, alone: about 0.2 s and 190 MB for a 4 MB file,
      // 0.85 s and 425 MB for the file just under the value limit. Before the
      // limits, 1.1 GB and more, or 9 to 14 s. The time bound leaves room for
      // a busy CI runner with coverage on; the memory bound is the tight one.
      expect(performance.now() - start).toBeLessThan(10_000);
      expect((peakRss() - before) / MB).toBeLessThan(600);
    },
    30_000,
  );
});
