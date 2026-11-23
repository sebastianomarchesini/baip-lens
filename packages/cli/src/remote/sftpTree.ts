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
 */

/** Where Cloud Foundry unpacks the droplet of a buildpack app. */
export const APP_ROOT = '/home/vcap/app';
/** SFTP requests in flight for file reads. */
export const READ_AHEAD = 8;

interface Listed {
  size: number;
  mtime: number | undefined;
}

function byName(a: RemoteEntry, b: RemoteEntry): number {
  return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
}

/**
 * Reads the bytes from `start` up to `end` of the file into the buffer, at
 * the same offsets, and returns where it stopped: at `end`, or earlier when
 * the file ended (it shrank since it was opened).
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
      return (await this.sftp.lstat(location)).type === 'file';
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
      // The head first: a binary file is given up before the rest of it is fetched.
      const headEnd = Math.min(buffer.length, NUL_SCAN_BYTES);
      let total = await readRange(file, buffer, 0, headEnd);
      if (buffer.subarray(0, total).includes(0)) return { ok: false, reason: 'binary' };
      if (total === headEnd) total = await readRange(file, buffer, headEnd, buffer.length);
      return { ok: true, text: buffer.toString('utf8', 0, total), bytes: total };
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
