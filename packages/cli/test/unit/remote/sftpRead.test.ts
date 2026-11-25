import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { MAX_LOCKFILE_BYTES, NUL_SCAN_BYTES } from '../../../src/collectors/project/read.js';
import {
  RemoteSessionError,
  type SftpReadRequests,
  Ssh2ReadOnlySftp,
} from '../../../src/remote/sftp.js';
import {
  APP_ROOT,
  MAX_READ_BYTES,
  READS_IN_FLIGHT,
  READ_AHEAD,
  SftpProjectTree,
} from '../../../src/remote/sftpTree.js';
import { type HeldRead, MemorySftp, appFiles, settle } from '../../support/memorySftp.js';

/*
 * How the SFTP tree reads one file: the head first and alone, then the rest
 * in requests of a bounded size, a few in flight, each range into its own
 * place. `MemorySftp` records every request and can hold the answers back.
 */

const LOCATION = `${APP_ROOT}/package-lock.json`;
const LARGE = { maxBytes: MAX_LOCKFILE_BYTES };

/** Printable text of `bytes` bytes that differs from place to place, so a misplaced range shows. */
function content(bytes: number): string {
  const buffer = Buffer.alloc(bytes);
  for (let i = 0; i < bytes; i += 1) buffer[i] = 0x21 + ((i * 31 + (i >>> 7)) % 90);
  return buffer.toString('latin1');
}

/** A file of the head and `ranges` full ranges, plus `extra` bytes. */
const sizeOf = (ranges: number, extra = 0): number =>
  NUL_SCAN_BYTES + ranges * MAX_READ_BYTES + extra;

function treeOver(entry: string | { size: number; content?: string }) {
  const sftp = new MemorySftp(appFiles({ 'package-lock.json': entry }));
  return { sftp, tree: new SftpProjectTree(sftp, { rootName: 'acme' }) };
}

const read = (position: number, length: number) => ({ path: LOCATION, position, length });

/** Lets the held requests go, wave after wave, in the order `pick` gives each wave. */
async function answerAll(
  sftp: MemorySftp,
  pick: (wave: HeldRead[]) => HeldRead[] = (wave) => wave,
): Promise<void> {
  await settle();
  while (sftp.held.length > 0) {
    for (const request of pick(sftp.held.splice(0))) request.answer();
    await settle();
  }
}

describe('the size of a read request', () => {
  it('is what ssh2 sends as one READ to a server that is not OpenSSH', () => {
    // 34 000 bytes less 2 048 of overhead: asked for more, ssh2 splits the read itself.
    expect(MAX_READ_BYTES).toBe(31_952);
    expect(NUL_SCAN_BYTES).toBeLessThanOrEqual(MAX_READ_BYTES);
    expect(READS_IN_FLIGHT).toBe(4);
  });

  it('asks for the head first, then for the rest in requests of at most 31 952 bytes, in order', async () => {
    const text = content(sizeOf(3, 100));
    const { sftp, tree } = treeOver(text);
    sftp.maxAnswer = Infinity;
    expect(await tree.read(LOCATION, LARGE)).toEqual({ ok: true, text, bytes: text.length });
    expect(sftp.reads).toEqual([
      read(0, 8192),
      read(8192, 31_952),
      read(40_144, 31_952),
      read(72_096, 31_952),
      read(104_048, 100),
    ]);
    expect(Math.max(...sftp.reads.map((request) => request.length))).toBe(MAX_READ_BYTES);
    expect(sftp.requests.filter((r) => !r.startsWith('read '))).toEqual([
      `open ${LOCATION}`,
      `close ${LOCATION}`,
    ]);
  });

  it('reads a file that fits into the head with one request, and an empty file with none', async () => {
    const small = treeOver('{"lockfileVersion":3}');
    small.sftp.maxAnswer = Infinity;
    expect(await small.tree.read(LOCATION)).toEqual({
      ok: true,
      text: '{"lockfileVersion":3}',
      bytes: 21,
    });
    expect(small.sftp.reads).toEqual([read(0, 21)]);

    const exact = treeOver(content(NUL_SCAN_BYTES));
    exact.sftp.maxAnswer = Infinity;
    expect(await exact.tree.read(LOCATION)).toMatchObject({ ok: true, bytes: NUL_SCAN_BYTES });
    expect(exact.sftp.reads).toEqual([read(0, NUL_SCAN_BYTES)]);

    const empty = treeOver('');
    expect(await empty.tree.read(LOCATION)).toEqual({ ok: true, text: '', bytes: 0 });
    expect(empty.sftp.reads).toEqual([]);
    expect(empty.sftp.requests.at(-1)).toBe(`close ${LOCATION}`);
  });

  it('never asks for a byte beyond the size the file had when it was opened', async () => {
    // The file grew after fstat: the bytes it had then are read, and nothing after them.
    const { sftp, tree } = treeOver({ size: 10, content: '0123456789-grown-since' });
    sftp.maxAnswer = Infinity;
    expect(await tree.read(LOCATION)).toEqual({ ok: true, text: '0123456789', bytes: 10 });
    expect(sftp.reads).toEqual([read(0, 10)]);
  });

  it('reads a file ahead with the same requests', async () => {
    const text = `service S {} // ${content(sizeOf(2, 7))}`;
    const sftp = new MemorySftp(appFiles({ 'package.json': '{}', 'srv/big.cds': text }));
    sftp.maxAnswer = Infinity;
    const tree = new SftpProjectTree(sftp, { rootName: 'acme' });
    const location = `${APP_ROOT}/srv/big.cds`;
    await tree.list(`${APP_ROOT}/srv`, 100);
    await settle();
    // Fetched before the collector asks, and handed over when it does.
    const fetched = sftp.reads.filter((request) => request.path === location);
    expect(fetched.map((request) => request.position)).toEqual([0, 8192, 40_144, 72_096]);
    expect(fetched.every((request) => request.length <= MAX_READ_BYTES)).toBe(true);
    expect(await tree.read(location)).toEqual({ ok: true, text, bytes: text.length });
    expect(sftp.reads.filter((request) => request.path === location)).toHaveLength(4);
  });
});

describe('the requests in flight for one file', () => {
  it('sends nothing but the head before the NUL test, then keeps at most four in flight', async () => {
    const text = content(sizeOf(10));
    const { sftp, tree } = treeOver(text);
    sftp.maxAnswer = Infinity;
    sftp.hold = true;
    const pending = tree.read(LOCATION, LARGE);
    await settle();
    // Only the head is asked for until it has arrived and was looked at.
    expect(sftp.held.map((request) => request.position)).toEqual([0]);
    expect(sftp.reads).toEqual([read(0, NUL_SCAN_BYTES)]);

    sftp.held.splice(0)[0]?.answer();
    await settle();
    const first = NUL_SCAN_BYTES;
    expect(sftp.held.map((request) => request.position)).toEqual([
      first,
      first + MAX_READ_BYTES,
      first + 2 * MAX_READ_BYTES,
      first + 3 * MAX_READ_BYTES,
    ]);
    expect(sftp.inFlight).toBe(4);

    // One answer makes room for exactly one more request: the next range.
    sftp.held.splice(2, 1)[0]?.answer();
    await settle();
    expect(sftp.inFlight).toBe(4);
    expect(sftp.reads.at(-1)).toEqual(read(first + 4 * MAX_READ_BYTES, MAX_READ_BYTES));

    await answerAll(sftp);
    expect(await pending).toEqual({ ok: true, text, bytes: text.length });
    expect(sftp.maxInFlight).toBe(READS_IN_FLIGHT);
    expect(sftp.reads).toHaveLength(11);
    // Closed once, after the last answer.
    expect(sftp.requests.filter((r) => r.startsWith('close '))).toHaveLength(1);
    expect(sftp.requests.at(-1)).toBe(`close ${LOCATION}`);
  });

  it('puts every range in its place, whatever order the answers come in', async () => {
    const text = content(sizeOf(9, 4321));
    const { sftp, tree } = treeOver(text);
    sftp.maxAnswer = Infinity;
    sftp.hold = true;
    const pending = tree.read(LOCATION, LARGE);
    await answerAll(sftp, (wave) => [...wave].reverse());
    const result = await pending;
    expect(result.ok && result.text === text).toBe(true);
    expect(result).toMatchObject({ ok: true, bytes: text.length });
    // The requests themselves still went out in the order of the file.
    const positions = sftp.reads.map((request) => request.position);
    expect(positions).toEqual([...positions].sort((a, b) => a - b));
    expect(sftp.maxInFlight).toBe(READS_IN_FLIGHT);
  });

  it('decodes a character that lies across the head or across two ranges', async () => {
    // A character of three bytes cut by the end of the head, one of four cut by the end of a range.
    const text = `${'x'.repeat(NUL_SCAN_BYTES - 1)}€${'x'.repeat(MAX_READ_BYTES - 4)}\u{1F600}${'x'.repeat(100)}`;
    const bytes = Buffer.byteLength(text);
    expect(Buffer.from(text).subarray(0, NUL_SCAN_BYTES).toString()).toContain('�');
    for (const maxAnswer of [Infinity, 3]) {
      const { sftp, tree } = treeOver(text);
      sftp.maxAnswer = maxAnswer;
      // The ranges are decoded together, once all of them are in place.
      expect(await tree.read(LOCATION, LARGE)).toEqual({ ok: true, text, bytes });
    }
  });

  it('keeps the files of a scan within their own limit: four requests each', async () => {
    const big = content(sizeOf(6));
    const sftp = new MemorySftp(
      appFiles({ 'package-lock.json': big, 'srv/package-lock.json': big }),
    );
    sftp.maxAnswer = Infinity;
    sftp.hold = true;
    const tree = new SftpProjectTree(sftp, { rootName: 'acme' });
    const both = Promise.all([
      tree.read(LOCATION, LARGE),
      tree.read(`${APP_ROOT}/srv/package-lock.json`, LARGE),
    ]);
    await answerAll(sftp);
    expect((await both).map((result) => result.ok)).toEqual([true, true]);
    expect(sftp.maxInFlight).toBe(2 * READS_IN_FLIGHT);
  });
});

describe('the files read at the same time', () => {
  it('are at most eight, fetched ahead or asked for, so at most 32 requests are in flight', async () => {
    expect(READ_AHEAD).toBe(8);
    // Twenty models that are fetched ahead, each with its head and six ranges, and one lockfile.
    const text = content(sizeOf(6));
    const models = Array.from(
      { length: 20 },
      (_, i) => `${APP_ROOT}/srv/m${String(i).padStart(2, '0')}.cds`,
    );
    const sftp = new MemorySftp({
      [LOCATION]: text,
      ...Object.fromEntries(models.map((model) => [model, text])),
    });
    sftp.maxAnswer = Infinity;
    sftp.hold = true;
    const tree = new SftpProjectTree(sftp, { rootName: 'acme' });
    const opened = (): string[] => sftp.requests.filter((r) => r.startsWith('open '));

    await tree.list(`${APP_ROOT}/srv`, 100);
    await settle();
    // Eight files are open and asked for their heads; the other twelve wait for a place.
    expect(opened()).toEqual(models.slice(0, READ_AHEAD).map((model) => `open ${model}`));
    expect(sftp.held.map((request) => [request.path, request.position])).toEqual(
      models.slice(0, READ_AHEAD).map((model) => [model, 0]),
    );

    // A file the collector asks for itself waits for a place like the ones fetched ahead.
    const lockfile = tree.read(LOCATION, LARGE);
    await settle();
    expect(opened()).toHaveLength(READ_AHEAD);

    await answerAll(sftp);
    expect(await lockfile).toEqual({ ok: true, text, bytes: text.length });
    const fetched = await Promise.all(models.map((model) => tree.read(model)));
    expect(fetched.every((result) => result.ok)).toBe(true);
    expect(opened()).toHaveLength(models.length + 1);
    // Eight files with four requests each, and never one more.
    expect(sftp.maxInFlight).toBe(READ_AHEAD * READS_IN_FLIGHT);
    expect(sftp.inFlight).toBe(0);
  });
});

describe('answers that are shorter than the request', () => {
  it('asks again for the rest of the head and of each range', async () => {
    const text = content(sizeOf(1, 5000));
    const { sftp, tree } = treeOver(text);
    sftp.maxAnswer = 10_000;
    expect(await tree.read(LOCATION, LARGE)).toEqual({ ok: true, text, bytes: text.length });
    const second = NUL_SCAN_BYTES + MAX_READ_BYTES;
    const within = (from: number, to: number) =>
      sftp.reads.filter((request) => request.position >= from && request.position < to);
    expect(within(0, NUL_SCAN_BYTES)).toEqual([read(0, 8192)]);
    // 31 952 bytes in answers of 10 000: each new request asks for what is still missing.
    expect(within(NUL_SCAN_BYTES, second)).toEqual([
      read(8192, 31_952),
      read(18_192, 21_952),
      read(28_192, 11_952),
      read(38_192, 1952),
    ]);
    expect(within(second, text.length)).toEqual([read(second, 5000)]);
  });

  it('reads the head across short answers before anything else is asked for', async () => {
    const text = content(sizeOf(2));
    const { sftp, tree } = treeOver(text);
    sftp.maxAnswer = 3000;
    expect(await tree.read(LOCATION, LARGE)).toEqual({ ok: true, text, bytes: text.length });
    expect(sftp.reads.slice(0, 4)).toEqual([
      read(0, 8192),
      read(3000, 5192),
      read(6000, 2192),
      read(8192, 31_952),
    ]);
    expect(sftp.reads.every((request) => request.length <= MAX_READ_BYTES)).toBe(true);
  });
});

describe('a file that does not give the bytes its size promised', () => {
  it('is unreadable when a range ends early, and no further range is asked for', async () => {
    // 20 ranges promised; the file ends in the middle of the second.
    const size = sizeOf(20);
    const { sftp, tree } = treeOver({ size, content: content(sizeOf(1, 1000)) });
    sftp.maxAnswer = Infinity;
    expect(await tree.read(LOCATION, LARGE)).toEqual({ ok: false, reason: 'unreadable' });
    // The four that were in flight, what they asked again, and nothing of the other ranges.
    expect(sftp.reads.length).toBeLessThan(10);
    expect(sftp.reads.every((request) => request.position < sizeOf(6))).toBe(true);
    expect(sftp.requests.at(-1)).toBe(`close ${LOCATION}`);
  });

  it('is unreadable when the last range comes back short: no text with a missing tail', async () => {
    const size = sizeOf(2, 500);
    const { sftp, tree } = treeOver({ size, content: content(size - 1) });
    sftp.maxAnswer = Infinity;
    expect(await tree.read(LOCATION, LARGE)).toEqual({ ok: false, reason: 'unreadable' });
  });

  it('is unreadable when the head itself ends early, and binary when what arrived says so', async () => {
    const short = treeOver({ size: 5000, content: 'only this much' });
    short.sftp.maxAnswer = Infinity;
    expect(await short.tree.read(LOCATION)).toEqual({ ok: false, reason: 'unreadable' });
    // Asked once more for the rest of the head, which gave nothing; never beyond it.
    expect(short.sftp.reads).toEqual([read(0, 5000), read(14, 4986)]);

    const binary = treeOver({ size: sizeOf(3), content: 'ab\u0000' });
    binary.sftp.maxAnswer = Infinity;
    expect(await binary.tree.read(LOCATION, LARGE)).toEqual({ ok: false, reason: 'binary' });
  });
});

describe('a binary file', () => {
  it('is given up after its head: one request, and nothing beyond the first 8 KiB', async () => {
    const { sftp, tree } = treeOver(`{"lockfileVersion":3,\u0000${content(sizeOf(8))}`);
    sftp.maxAnswer = Infinity;
    expect(await tree.read(LOCATION, LARGE)).toEqual({ ok: false, reason: 'binary' });
    expect(sftp.reads).toEqual([read(0, NUL_SCAN_BYTES)]);
    expect(sftp.requests.at(-1)).toBe(`close ${LOCATION}`);
  });

  it('is told by its first 8 KiB only, as for a local file', async () => {
    const text = `${content(NUL_SCAN_BYTES)}\u0000${content(sizeOf(1))}`;
    const { sftp, tree } = treeOver(text);
    sftp.maxAnswer = Infinity;
    expect(await tree.read(LOCATION, LARGE)).toEqual({ ok: true, text, bytes: text.length });
  });
});

describe('a session that is lost while ranges are in flight', () => {
  const unhandled: unknown[] = [];
  const onUnhandled = (reason: unknown): void => {
    unhandled.push(reason);
  };
  beforeEach(() => {
    unhandled.length = 0;
    process.on('unhandledRejection', onUnhandled);
  });
  afterEach(() => {
    process.off('unhandledRejection', onUnhandled);
  });

  /** A read with its head answered and four ranges in flight. */
  async function inFlight() {
    const { sftp, tree } = treeOver(content(sizeOf(10)));
    sftp.maxAnswer = Infinity;
    sftp.hold = true;
    const pending = tree.read(LOCATION, LARGE);
    let outcome: 'pending' | 'done' | 'failed' = 'pending';
    pending.then(
      () => (outcome = 'done'),
      () => (outcome = 'failed'),
    );
    await settle();
    sftp.held.splice(0)[0]?.answer();
    await settle();
    expect(sftp.held).toHaveLength(4);
    return { sftp, pending, outcome: () => outcome };
  }

  const closes = (sftp: MemorySftp): number =>
    sftp.requests.filter((r) => r.startsWith('close ')).length;

  it('ends the read with the session error, once, after the last request in flight has ended', async () => {
    const { sftp, pending, outcome } = await inFlight();
    const [first, second, third, fourth] = sftp.held.splice(0);
    // ssh2 fails every pending request when the channel closes under them.
    second?.fail(new RemoteSessionError('gone'));
    await settle();
    // Three requests are still out: nothing is closed and nothing is reported yet.
    expect(outcome()).toBe('pending');
    expect(closes(sftp)).toBe(0);
    expect(sftp.reads).toHaveLength(5);

    sftp.gone = true;
    first?.fail(new RemoteSessionError('gone'));
    third?.fail(new RemoteSessionError('gone'));
    await settle();
    expect(outcome()).toBe('pending');
    fourth?.fail(new RemoteSessionError('gone'));

    await expect(pending).rejects.toBeInstanceOf(RemoteSessionError);
    await settle();
    // No range was started after the first failure, and the handle was closed exactly once.
    expect(sftp.reads).toHaveLength(5);
    expect(closes(sftp)).toBe(1);
    expect(sftp.requests.at(-1)).toBe(`close ${LOCATION}`);
    expect(sftp.inFlight).toBe(0);
    expect(unhandled).toEqual([]);
  });

  it('does not wait for a new range when the others still answer after the failure', async () => {
    const { sftp, pending } = await inFlight();
    const [first, ...others] = sftp.held.splice(0);
    first?.fail(new RemoteSessionError('gone'));
    for (const request of others) request.answer();
    await expect(pending).rejects.toBeInstanceOf(RemoteSessionError);
    await settle();
    expect(sftp.reads).toHaveLength(5);
    expect(closes(sftp)).toBe(1);
    expect(unhandled).toEqual([]);
  });

  it('reports an ordinary error of one request as an unreadable file, and closes it', async () => {
    const { sftp, pending } = await inFlight();
    const [first, ...others] = sftp.held.splice(0);
    first?.fail(Object.assign(new Error('Permission denied'), { code: 3 }));
    for (const request of others) request.answer();
    expect(await pending).toEqual({ ok: false, reason: 'unreadable' });
    await settle();
    expect(sftp.reads).toHaveLength(5);
    expect(closes(sftp)).toBe(1);
    expect(unhandled).toEqual([]);
  });

  it('prefers the session error over an ordinary one that came first', async () => {
    const { sftp, pending } = await inFlight();
    const [first, second, ...others] = sftp.held.splice(0);
    first?.fail(new Error('Failure'));
    second?.fail(new RemoteSessionError('gone'));
    for (const request of others) request.fail(new RemoteSessionError('gone'));
    await expect(pending).rejects.toBeInstanceOf(RemoteSessionError);
    await settle();
    expect(closes(sftp)).toBe(1);
    expect(unhandled).toEqual([]);
  });
});

describe('a file that is probed by its path', () => {
  it('is refused when it changed between the probe and the read, like a listed file', async () => {
    const { sftp, tree } = treeOver('{"lockfileVersion":3}');
    sftp.maxAnswer = Infinity;
    expect(await tree.isFile(LOCATION)).toBe(true);
    expect(await tree.read(LOCATION)).toMatchObject({ ok: true });

    // Swapped after the probe: another modification time once it is opened.
    sftp.swapped.add(LOCATION);
    expect(await tree.read(LOCATION)).toEqual({ ok: false, reason: 'unreadable' });
    expect(sftp.reads).toHaveLength(1);
  });

  it('is refused when only its size changed since the probe: the time counts whole seconds', async () => {
    const files = appFiles({ 'package-lock.json': '{"lockfileVersion":3}' });
    const sftp = new MemorySftp(files);
    const tree = new SftpProjectTree(sftp, { rootName: 'acme' });
    expect(await tree.isFile(LOCATION)).toBe(true);
    // Replaced within the same second by a file of another size: the same modification time.
    files[LOCATION] = '{"lockfileVersion":3,"packages":{}}';
    expect(await tree.read(LOCATION)).toEqual({ ok: false, reason: 'unreadable' });
    expect(sftp.reads).toEqual([]);
    expect(sftp.requests.at(-1)).toBe(`close ${LOCATION}`);
  });

  it('is not held to a probe that found no regular file there', async () => {
    const sftp = new MemorySftp(
      appFiles({ 'package.json': '{}', 'node_modules/.package-lock.json': { other: true } }),
    );
    const tree = new SftpProjectTree(sftp, { rootName: 'acme' });
    // A link, a directory and a path that does not exist are not files.
    expect(await tree.isFile(`${APP_ROOT}/node_modules/.package-lock.json`)).toBe(false);
    expect(await tree.isFile(`${APP_ROOT}/node_modules`)).toBe(false);
    expect(await tree.isFile(`${APP_ROOT}/missing.json`)).toBe(false);
    expect(sftp.requests.filter((r) => r.startsWith('open '))).toEqual([]);
  });
});

describe('a file that the listing showed', () => {
  it('is refused when only its size changed since the listing', async () => {
    const files = appFiles({ 'package-lock.json': '{"lockfileVersion":3}' });
    const sftp = new MemorySftp(files);
    const tree = new SftpProjectTree(sftp, { rootName: 'acme' });
    // A lockfile is listed and not fetched ahead: it is opened when the collector asks for it.
    expect(await tree.list(APP_ROOT, 100)).toEqual([
      { name: 'package-lock.json', type: 'file', size: 21 },
    ]);
    await settle();
    expect(sftp.requests).toEqual([`list ${APP_ROOT}`]);
    files[LOCATION] = '{"lockfileVersion":3,"packages":{}}';
    expect(await tree.read(LOCATION)).toEqual({ ok: false, reason: 'unreadable' });
    expect(sftp.reads).toEqual([]);

    // The same file, unchanged since it was listed, is read.
    files[LOCATION] = '{"lockfileVersion":3}';
    expect(await tree.read(LOCATION)).toMatchObject({ ok: true, bytes: 21 });
  });
});

describe('the timeout of a request', () => {
  const FILE = 0o100644;
  type Done = (error: Error | undefined, ...values: unknown[]) => void;

  /** An ssh2 client whose READ answers after `answerMs`, except those `silent` picks. */
  function slowClient(text: string, answerMs: number, silent: (position: number) => boolean) {
    const data = Buffer.from(text);
    const reads: { position: number; length: number }[] = [];
    let closed = 0;
    const client = {
      open: (_path: string, _flags: string, done: Done) => done(undefined, Buffer.from('h')),
      fstat: (_handle: Buffer, done: Done) =>
        done(undefined, { mode: FILE, size: data.length, mtime: 1 }),
      read: (
        _handle: Buffer,
        buffer: Buffer,
        offset: number,
        length: number,
        position: number,
        done: Done,
      ) => {
        reads.push({ position, length });
        if (silent(position)) return;
        setTimeout(() => {
          const n = Math.min(length, data.length - position);
          data.copy(buffer, offset, position, position + n);
          done(undefined, n);
        }, answerMs);
      },
      close: (_handle: Buffer, done: Done) => {
        closed += 1;
        done(undefined);
      },
    };
    return { client: client as unknown as SftpReadRequests, reads, closed: () => closed };
  }

  it('is counted for each request on its own, so a large file may take longer than one timeout', async () => {
    const text = content(sizeOf(12));
    const { client, reads } = slowClient(text, 15, () => false);
    const sftp = new Ssh2ReadOnlySftp(client, { isClosed: () => false, timeoutMs: 45 });
    const tree = new SftpProjectTree(sftp, { rootName: 'acme' });
    const started = performance.now();
    // The head and three waves of four ranges: four answers of 15 ms one after the other.
    expect(await tree.read(LOCATION, LARGE)).toEqual({ ok: true, text, bytes: text.length });
    expect(performance.now() - started).toBeGreaterThan(45);
    expect(reads).toHaveLength(13);
    // Never more than ssh2 sends as one READ: a longer read would be several requests under one timer.
    expect(Math.max(...reads.map((request) => request.length))).toBe(MAX_READ_BYTES);
  });

  it('ends the scan when one request of a file is never answered', async () => {
    const text = content(sizeOf(12));
    const lost = NUL_SCAN_BYTES + 5 * MAX_READ_BYTES;
    // The timeout is far longer than the answers take, so that a slow machine cannot change the count below.
    const { client, reads, closed } = slowClient(text, 2, (position) => position === lost);
    const sftp = new Ssh2ReadOnlySftp(client, { isClosed: () => false, timeoutMs: 150 });
    const tree = new SftpProjectTree(sftp, { rootName: 'acme' });
    await expect(tree.read(LOCATION, LARGE)).rejects.toBeInstanceOf(RemoteSessionError);
    expect(closed()).toBe(1);
    // The other three requests in flight went on, range after range, while the lost one waited for its timeout.
    expect(reads).toHaveLength(13);
  });
});
