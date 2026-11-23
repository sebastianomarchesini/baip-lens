import type * as FsPromises from 'node:fs/promises';
import { mkdir, mkdtemp, realpath, rm, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { collectProject } from '../../../../src/collectors/project/index.js';
import {
  MAX_LOCKFILE_BYTES,
  NUL_SCAN_BYTES,
  readProjectFile,
} from '../../../../src/collectors/project/read.js';

/*
 * A read may return fewer bytes than it was asked for; with a limit of 32 MiB
 * for a lockfile, one read is no longer sure to return the whole file. Here
 * every read returns at most seven bytes, as a slow or remote file system may,
 * and the test sees how far into each file the reads went.
 */
const SHORT_READ = 7;
/** The length each read asked for, in order. */
const reads: number[] = [];
/** Per file, the end of the furthest range a read asked for. */
const furthest = new Map<string, number>();
/** When set: reads at or beyond this position return nothing, as for a file that shrank after fstat. */
let endsAt: number | undefined;
/** Reads that returned nothing; a few of them in a row are a loop that does not end. */
let emptyReads = 0;

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof FsPromises>();
  const open = async (...args: Parameters<typeof actual.open>) => {
    const handle = await actual.open(...args);
    const path = String(args[0]);
    const read = handle.read.bind(handle) as (
      buffer: Buffer,
      offset: number,
      length: number,
      position: number,
    ) => Promise<{ bytesRead: number; buffer: Buffer }>;
    const short = (buffer: Buffer, offset: number, length: number, position: number) => {
      reads.push(length);
      furthest.set(path, Math.max(furthest.get(path) ?? 0, position + length));
      if (endsAt !== undefined && position >= endsAt) {
        emptyReads += 1;
        // A reader that asks again and again fails here instead of hanging the test run.
        if (emptyReads > 3) throw new Error('read after the end of the file, again');
        return Promise.resolve({ bytesRead: 0, buffer });
      }
      const allowed = endsAt === undefined ? length : Math.min(length, endsAt - position);
      return read(buffer, offset, Math.min(allowed, SHORT_READ), position);
    };
    handle.read = short as typeof handle.read;
    return handle;
  };
  return { ...actual, default: { ...actual, open }, open };
});

const created: string[] = [];
afterAll(async () => {
  await Promise.all(created.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function tmp(): Promise<string> {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'baip-lens-read-short-')));
  created.push(dir);
  return dir;
}

beforeEach(() => {
  reads.length = 0;
  furthest.clear();
  endsAt = undefined;
  emptyReads = 0;
});

describe('readProjectFile with short reads', () => {
  it('reads on until it has the whole file', async () => {
    const dir = await tmp();
    const content = `{"packages":{${'"a":1,'.repeat(40)}"b":2}}`;
    await writeFile(join(dir, 'package-lock.json'), content);
    expect(await readProjectFile(join(dir, 'package-lock.json'))).toEqual({
      ok: true,
      text: content,
      bytes: content.length,
    });
    // One read per seven bytes, each asking for what is still missing.
    expect(reads).toHaveLength(Math.ceil(content.length / SHORT_READ));
    expect(reads[0]).toBe(content.length);
    expect(reads.at(-1)).toBe(content.length % SHORT_READ || SHORT_READ);
  });

  it('stops at the end of a file without a read that returns nothing', async () => {
    const dir = await tmp();
    await writeFile(join(dir, 'exact.json'), '1234567');
    expect(await readProjectFile(join(dir, 'exact.json'))).toEqual({
      ok: true,
      text: '1234567',
      bytes: 7,
    });
    expect(reads).toEqual([7]);
  });

  it('stops when the file ends before the size fstat reported: it shrank in between', async () => {
    const dir = await tmp();
    await writeFile(join(dir, 'shrunk.json'), '1234567890abcd');
    endsAt = 7;
    expect(await readProjectFile(join(dir, 'shrunk.json'))).toEqual({
      ok: true,
      text: '1234567',
      bytes: 7,
    });
    // The first seven bytes, then one read that returns nothing, and no further one.
    expect(reads).toEqual([14, 7]);
    expect(emptyReads).toBe(1);
  }, 5_000);

  it('stops in the same way when the file ends beyond the bytes that are read first', async () => {
    const dir = await tmp();
    const content = 'x'.repeat(NUL_SCAN_BYTES + 100);
    await writeFile(join(dir, 'shrunk.json'), content);
    endsAt = NUL_SCAN_BYTES + 30;
    expect(await readProjectFile(join(dir, 'shrunk.json'))).toEqual({
      ok: true,
      text: content.slice(0, NUL_SCAN_BYTES + 30),
      bytes: NUL_SCAN_BYTES + 30,
    });
    expect(emptyReads).toBe(1);
    // And one that ends inside them is not read on beyond them.
    reads.length = 0;
    emptyReads = 0;
    endsAt = 21;
    expect(await readProjectFile(join(dir, 'shrunk.json'))).toEqual({
      ok: true,
      text: content.slice(0, 21),
      bytes: 21,
    });
    expect(emptyReads).toBe(1);
    expect(Math.max(...reads)).toBe(NUL_SCAN_BYTES);
  }, 5_000);
});

describe('a file that looks binary', () => {
  /** A sparse file of the largest size a lockfile may have: every byte is NUL, and it takes no disk. */
  async function binaryLockfile(path: string): Promise<void> {
    await mkdir(join(path, '..'), { recursive: true });
    await writeFile(path, '');
    await truncate(path, MAX_LOCKFILE_BYTES);
  }

  it(`is given up after its first ${NUL_SCAN_BYTES} bytes, not read in full`, async () => {
    const dir = await tmp();
    const path = join(dir, 'package-lock.json');
    await binaryLockfile(path);
    expect(await readProjectFile(path, { maxBytes: MAX_LOCKFILE_BYTES })).toEqual({
      ok: false,
      reason: 'binary',
    });
    expect(furthest.get(path)).toBe(NUL_SCAN_BYTES);
    expect(reads[0]).toBe(NUL_SCAN_BYTES);

    // A NUL byte beyond the head is not looked for: the file is read as text.
    const late = join(dir, 'late.json');
    await writeFile(late, `${'x'.repeat(NUL_SCAN_BYTES)}\0tail`);
    const result = await readProjectFile(late);
    expect(result).toMatchObject({ ok: true, bytes: NUL_SCAN_BYTES + 5 });
    expect(furthest.get(late)).toBe(NUL_SCAN_BYTES + 5);
  });

  it('costs the collector the head of each lockfile only: six of 32 MiB are not 192 MiB read', async () => {
    const root = await tmp();
    await writeFile(join(root, 'package.json'), '{ "name": "acme" }');
    const lockfiles = [
      'package-lock.json',
      ...[1, 2, 3, 4, 5].map((i) => `m${i}/package-lock.json`),
    ];
    for (const rel of lockfiles) await binaryLockfile(join(root, ...rel.split('/')));

    const project = await collectProject(root);
    expect(project.dependencies?.lockfiles.map((l) => [l.file, l.status])).toEqual(
      [...lockfiles].sort().map((rel) => [rel, 'unreadable']),
    );
    expect(project.unreadable).toEqual(
      [...lockfiles].sort().map((rel) => ({ file: rel, kind: 'binary' })),
    );
    // Each was opened and refused; none was read beyond the bytes that tell a binary file.
    expect(project.dependencies?.lockfilesNotRead).toBe(0);
    expect(project.filesOpened).toBe(lockfiles.length + 1);
    for (const rel of lockfiles) {
      expect(furthest.get(join(root, ...rel.split('/')))).toBe(NUL_SCAN_BYTES);
    }
    const bytesAsked = [...furthest.values()].reduce((sum, end) => sum + end, 0);
    expect(bytesAsked).toBeLessThan(lockfiles.length * NUL_SCAN_BYTES + 1024);
  }, 30_000);
});
