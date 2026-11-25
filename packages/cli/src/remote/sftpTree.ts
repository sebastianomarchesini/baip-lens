import { MAX_FILES_OPENED, MAX_TOTAL_BYTES } from '../collectors/project/index.js';
import {
  MAX_FILE_BYTES,
  NUL_SCAN_BYTES,
  type ReadOptions,
  type ReadResult,
} from '../collectors/project/read.js';
import type { ProjectTree, RepositoryContext, TreeEntry } from '../collectors/project/tree.js';
import { classify } from '../collectors/project/walk.js';
import { Semaphore } from '../http/semaphore.js';
import { isSafeRelativePath } from '../model/paths.js';
import {
  type ReadOnlySftp,
  type RemoteEntry,
  type RemoteFile,
  RemoteSessionError,
} from './sftp.js';

/*
 * A deployed app's files, read live over SFTP (`baip-lens project --cf`).
 * The collector sees the same `ProjectTree` as for a local folder, so the
 * same allow-list, deny-list, limits and parsers apply, and nothing is
 * written to disk: file contents stay in memory until the parsers have
 * reduced them to names and counts.
 *
 * SFTP has no O_NOFOLLOW. The walk only lists entries whose lstat type is a
 * regular file, and a file is read only if, once opened, it still has the
 * size and modification time the listing showed; a file swapped for a link
 * between the listing and the read is therefore refused as unreadable.
 *
 * To keep a slow link from making the scan crawl, the files the collector
 * will read (allow-listed, within the size limit and the scan's file and byte
 * budgets) are fetched ahead as soon as their directory is listed, a few at a
 * time. A session that ends mid-scan rejects with `RemoteSessionError`.
 *
 * A file is read in requests of a bounded size: first its head, which decides
 * whether it is binary, then the rest in ranges, a few of them in flight.
 * Every request is one call of the session and has its own timeout there, so
 * a large file (an npm lockfile may have 32 MiB) is not held to the time one
 * request may take. The file must give exactly the bytes its size promised:
 * with ranges in flight, one that came back short would leave a hole.
 */

/** Where Cloud Foundry unpacks the droplet of a buildpack app. */
export const APP_ROOT = '/home/vcap/app';
/** Files being read at the same time. */
export const READ_AHEAD = 8;
/**
 * The most bytes one read request asks for: what ssh2 puts into one READ for
 * a server that identifies as neither OpenSSH nor Dropbear (34 000 bytes less
 * 2 048 of overhead; the Diego SSH daemon answers with at most 32 KiB).
 * Asked for more, ssh2 would split the read into requests of this size
 * itself and send them one after the other inside one call: one timeout for
 * all of them, and none in flight together.
 */
export const MAX_READ_BYTES = 31_952;
/** Read requests in flight for one file, once its head is read. */
export const READS_IN_FLIGHT = 4;

interface Listed {
  size: number;
  mtime: number | undefined;
}

function byName(a: RemoteEntry, b: RemoteEntry): number {
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}

function isSessionLost(error: unknown): boolean {
  return error instanceof RemoteSessionError;
}

/**
 * Reads the bytes from `start` up to `end` of the file into the buffer, at
 * the same offsets, one request after the other, and returns where it
 * stopped: at `end`, or earlier when the file ended there (it shrank since
 * it was opened). A server may answer with fewer bytes than it was asked
 * for; the rest of the range is then asked for again. The range must not be
 * longer than `MAX_READ_BYTES`, so that each call is one request.
 */
async function readRange(
  file: RemoteFile,
  buffer: Buffer,
  start: number,
  end: number,
): Promise<number> {
  let at = start;
  while (at < end) {
    const bytesRead = await file.read(buffer, at, end - at, at);
    if (bytesRead <= 0) break;
    at += bytesRead;
  }
  return at;
}

/**
 * Reads the bytes from `start` to the end of the buffer in ranges of at most
 * `MAX_READ_BYTES`, up to `READS_IN_FLIGHT` of them at a time, each into its
 * own place, and returns how many bytes arrived. Once a range ends early no
 * further range is asked for. When a request fails, the ranges in flight are
 * awaited before the error is passed on, so that none of them is left to
 * fail unnoticed and the file is closed only after its last request. Of
 * several errors the lost session is the one passed on: it ends the scan,
 * while any other error is about this file only.
 */
async function readRanges(file: RemoteFile, buffer: Buffer, start: number): Promise<number> {
  let next = start;
  let total = 0;
  let cut = false;
  let failure: { error: unknown } | undefined;
  const stopped = (): boolean => cut || failure !== undefined;
  const fail = (error: unknown): void => {
    if (failure === undefined || (isSessionLost(error) && !isSessionLost(failure.error))) {
      failure = { error };
    }
  };
  const readNext = async (): Promise<void> => {
    while (!stopped() && next < buffer.length) {
      const from = next;
      const to = Math.min(buffer.length, from + MAX_READ_BYTES);
      next = to;
      try {
        const reached = await readRange(file, buffer, from, to);
        total += reached - from;
        if (reached < to) cut = true;
      } catch (error) {
        fail(error);
      }
    }
  };
  await Promise.all(Array.from({ length: READS_IN_FLIGHT }, readNext));
  if (failure !== undefined) throw failure.error;
  return total;
}

export interface SftpProjectTreeOptions {
  /** The app name: the root's display name and the fallback project id. */
  rootName: string;
  /** The folder in the container (default /home/vcap/app). */
  root?: string;
}

export class SftpProjectTree implements ProjectTree {
  readonly root: string;
  readonly rootName: string;
  private readonly listed = new Map<string, Listed>();
  private readonly ahead = new Map<string, Promise<ReadResult>>();
  private readonly slots = new Semaphore(READ_AHEAD);
  private aheadFiles = 0;
  private aheadBytes = 0;

  constructor(
    private readonly sftp: ReadOnlySftp,
    options: SftpProjectTreeOptions,
  ) {
    this.root = (options.root ?? APP_ROOT).replace(/\/+$/, '') || '/';
    this.rootName = options.rootName;
  }

  join(dir: string, name: string): string {
    return dir.endsWith('/') ? `${dir}${name}` : `${dir}/${name}`;
  }

  async list(dir: string, max: number): Promise<TreeEntry[] | null> {
    let entries: RemoteEntry[];
    try {
      entries = await this.sftp.list(dir, Math.max(0, max));
    } catch (error) {
      if (error instanceof RemoteSessionError) throw error;
      return null;
    }
    entries.sort(byName);
    for (const entry of entries) {
      if (entry.type !== 'file') continue;
      const location = this.join(dir, entry.name);
      this.listed.set(location, { size: entry.size, mtime: entry.mtime });
      this.readAhead(location, entry.size);
    }
    return entries.map(({ name, type, size }) => ({ name, type, size }));
  }

  read(location: string, options: ReadOptions = {}): Promise<ReadResult> {
    const fetched = this.ahead.get(location);
    if (fetched !== undefined) {
      this.ahead.delete(location);
      return fetched;
    }
    return this.slots.run(() => this.fetch(location, options.maxBytes ?? MAX_FILE_BYTES));
  }

  async isFile(location: string): Promise<boolean> {
    try {
      const stat = await this.sftp.lstat(location);
      if (stat.type !== 'file') return false;
      // Remembered like a listed file: one that is probed by its path and then
      // read must still have this size and time once it is opened.
      this.listed.set(location, { size: stat.size, mtime: stat.mtime });
      return true;
    } catch (error) {
      if (error instanceof RemoteSessionError) throw error;
      return false;
    }
  }

  /** A container is not a git checkout: `cf push` does not upload `.git`. */
  repository(): Promise<RepositoryContext | null> {
    return Promise.resolve(null);
  }

  /** The `/`-separated path below the root, or null when the location is not inside it. */
  private relative(location: string): string | null {
    const prefix = this.root === '/' ? '/' : `${this.root}/`;
    return location.startsWith(prefix) ? location.slice(prefix.length) : null;
  }

  /** Starts reading a file the collector will ask for, while the budgets allow it. */
  private readAhead(location: string, size: number): void {
    const rel = this.relative(location);
    if (rel === null || !isSafeRelativePath(rel)) return;
    const kind = classify(rel);
    // Archives are never opened; .gitignore files only when an archive exists.
    if (kind === null || kind === 'mtar' || kind === 'gitignore') return;
    // A foreign lockfile is never opened. An npm lockfile is read on request
    // only: one per directory, with its own size limit and byte budget.
    if (kind === 'lockfile' || kind === 'foreign-lockfile') return;
    // Too large: read() answers `too-large` from fstat without reading.
    if (size > MAX_FILE_BYTES) return;
    if (this.aheadFiles >= MAX_FILES_OPENED || this.aheadBytes + size > MAX_TOTAL_BYTES) return;
    this.aheadFiles += 1;
    this.aheadBytes += size;
    const pending = this.slots.run(() => this.fetch(location, MAX_FILE_BYTES));
    // Handled here so that a session error is not reported as unhandled before read() awaits it.
    pending.catch(() => undefined);
    this.ahead.set(location, pending);
  }

  /** Opens, checks and reads one file with the same limits as a local read. */
  private async fetch(location: string, maxBytes: number): Promise<ReadResult> {
    let file: RemoteFile;
    try {
      file = await this.sftp.openForReading(location);
    } catch (error) {
      return this.failure(error);
    }
    try {
      const stats = await file.stat();
      if (stats.type !== 'file') return { ok: false, reason: 'unreadable' };
      const listed = this.listed.get(location);
      if (listed !== undefined && (listed.size !== stats.size || listed.mtime !== stats.mtime)) {
        return { ok: false, reason: 'unreadable' };
      }
      if (stats.size > maxBytes) return { ok: false, reason: 'too-large' };
      const buffer = Buffer.alloc(stats.size);
      // The head first, alone: a binary file is given up before anything else of it is asked for.
      const headEnd = Math.min(buffer.length, NUL_SCAN_BYTES);
      let total = await readRange(file, buffer, 0, headEnd);
      if (buffer.subarray(0, total).includes(0)) return { ok: false, reason: 'binary' };
      if (total === headEnd) total += await readRanges(file, buffer, headEnd);
      // Fewer bytes than fstat reported: the file changed while it was read, and
      // a range that ended early has left a hole in the middle of the text.
      if (total !== stats.size) return { ok: false, reason: 'unreadable' };
      return { ok: true, text: buffer.toString('utf8'), bytes: total };
    } catch (error) {
      return this.failure(error);
    } finally {
      await file.close();
    }
  }

  /** One unreadable file is a reason code; a session that is gone ends the scan. */
  private failure(error: unknown): ReadResult {
    if (error instanceof RemoteSessionError) throw error;
    return { ok: false, reason: 'unreadable' };
  }
}
