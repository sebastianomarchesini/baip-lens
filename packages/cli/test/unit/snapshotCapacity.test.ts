import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { jsonShapeExcess } from '../../src/io/jsonShape.js';
import {
  MAX_SNAPSHOT_BYTES,
  MAX_SNAPSHOT_DEPTH,
  MAX_SNAPSHOT_VALUES,
  readSnapshot,
} from '../../src/snapshot.js';
import { fixturePath, realShapedSnapshot } from '../support/snapshotText.js';

/*
 * The limits of SEC-21 must never refuse a real snapshot: the recorded ones,
 * from every version, and the largest a real landscape could write. A
 * real-shaped app takes 3,190 bytes pretty-printed (as `writeSnapshot`
 * writes it), 2,288 bytes minified, and 84 values.
 */

/** Writes `apps` real-shaped apps and returns the file. The text is not kept. */
async function writeRealShaped(apps: number, indent?: number): Promise<string> {
  const path = join(await mkdtemp(join(tmpdir(), 'baip-lens-capacity-')), 'snapshot.json');
  await writeFile(path, JSON.stringify(realShapedSnapshot(apps), null, indent));
  return path;
}

describe('real snapshots load within the limits', () => {
  it.each([
    'sample-snapshot.json',
    'sample-project-snapshot.json',
    'legacy/snapshot-0.1.0.json',
    'history/acme-previous.json',
  ])('%s', async (name) => {
    await expect(readSnapshot(fixturePath(name))).resolves.toMatchObject({ schemaVersion: 1 });
  });

  it('loads 41,000 apps written as a scan writes them, close to the size limit', async () => {
    const path = await writeRealShaped(41_000, 2);
    const size = (await readFile(path)).length;
    expect(size).toBeGreaterThan(0.95 * MAX_SNAPSHOT_BYTES);
    expect(size).toBeLessThan(MAX_SNAPSHOT_BYTES);
    const snapshot = await readSnapshot(path);
    expect(snapshot.apps).toHaveLength(41_000);
    expect(snapshot.raw.apps).toHaveLength(41_000);
  }, 120_000);

  it('loads 49,000 apps written without whitespace, close to the value limit', async () => {
    const path = await writeRealShaped(49_000);
    const bytes = await readFile(path);
    expect(bytes.length).toBeLessThan(MAX_SNAPSHOT_BYTES);
    const limits = (maxValues: number) => ({ maxDepth: MAX_SNAPSHOT_DEPTH, maxValues });
    expect(jsonShapeExcess(bytes, limits(0.95 * MAX_SNAPSHOT_VALUES))).toBe('values');
    const snapshot = await readSnapshot(path);
    expect(snapshot.apps).toHaveLength(49_000);
  }, 120_000);
});
