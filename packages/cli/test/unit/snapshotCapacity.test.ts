import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { type JsonShapeLimits, jsonShapeExcess } from '../../src/io/jsonShape.js';
import {
  MAX_SNAPSHOT_BYTES,
  MAX_SNAPSHOT_DEPTH,
  MAX_SNAPSHOT_ITEMS,
  MAX_SNAPSHOT_MEMBERS,
  readSnapshot,
} from '../../src/snapshot.js';
import { fixturePath, realShapedSnapshot } from '../support/snapshotText.js';

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
