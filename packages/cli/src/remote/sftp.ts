import type { FileEntryWithStats, SFTPWrapper, Stats } from 'ssh2';
import { ConfigError } from '../http/errors.js';
import type { TreeEntryType } from '../collectors/project/tree.js';

/*
 * The read-only view of an SFTP session on a deployed app's container. The
 * wrapper is typed against `SftpReadRequests`, the subset of the ssh2 SFTP
 * client that reads: open a directory and read it, lstat, open a file for
 * reading (flag 'r' only), fstat it, read it, and close handles. It has no
 * way to write, rename, remove, create or change anything; a unit test proves
 * that no other request reaches the session. Every request has a timeout, and
 * nothing is sent once the session is gone, so a dropped connection ends the
 * scan with an error instead of hanging or looking like an empty app.
 */

/** The only SFTP client methods the wrapper may call. */
export type SftpReadRequests = Pick<
  SFTPWrapper,
  'opendir' | 'readdir' | 'lstat' | 'open' | 'fstat' | 'read' | 'close'
>;

export interface RemoteStat {
  type: TreeEntryType;
  size: number;
  /** Modification time in seconds, when the server sent one. */
  mtime: number | undefined;
}

export interface RemoteEntry extends RemoteStat {
  name: string;
}

export interface RemoteFile {
  stat(): Promise<RemoteStat>;
  /** Reads up to `length` bytes at `position` into `buffer` at `offset`; 0 at the end of the file. */
  read(buffer: Buffer, offset: number, length: number, position: number): Promise<number>;
  close(): Promise<void>;
}

export interface ReadOnlySftp {
  /** Up to `max` entries of a directory, in the server's order, without `.` and `..`. */
  list(path: string, max: number): Promise<RemoteEntry[]>;
  lstat(path: string): Promise<RemoteStat>;
  openForReading(path: string): Promise<RemoteFile>;
}

/**
 * The SSH session ended (closed, dropped or stopped answering): nothing more
 * can be read. A ConfigError, so the scan stops with exit code 2 and writes
 * nothing, instead of reporting a half-read app as clean.
 */
export class RemoteSessionError extends ConfigError {}

export const SESSION_GONE =
  'The connection to the app closed before the scan finished, so nothing was written. Run the command again.';

/** SFTP status code for the end of a file or directory listing (draft-ietf-secsh-filexfer-02). */
const STATUS_EOF = 1;
const S_IFMT = 0o170000;
const S_IFDIR = 0o040000;
const S_IFREG = 0o100000;
/** A hostile or broken server that answers every READDIR with an empty batch must not loop forever. */
const MAX_EMPTY_BATCHES = 100;
export const REQUEST_TIMEOUT_MS = 60_000;

/** File type from the POSIX mode bits the server sent; `other` when it sent none. */
export function entryType(mode: number | undefined): TreeEntryType {
  if (typeof mode !== 'number') return 'other';
  const format = mode & S_IFMT;
  if (format === S_IFDIR) return 'directory';
  if (format === S_IFREG) return 'file';
  return 'other';
}

function toStat(attrs: Partial<Stats> | undefined): RemoteStat {
  const size = attrs?.size;
  const mtime = attrs?.mtime;
  return {
    type: entryType(attrs?.mode),
    size: typeof size === 'number' && Number.isFinite(size) && size >= 0 ? size : 0,
    mtime: typeof mtime === 'number' && Number.isFinite(mtime) ? mtime : undefined,
  };
}

function isEof(error: unknown): boolean {
  return (error as { code?: unknown } | null)?.code === STATUS_EOF;
}

export interface Ssh2ReadOnlySftpOptions {
  /** Whether the SSH session has ended; checked before every request. */
  isClosed: () => boolean;
  timeoutMs?: number;
}

export class Ssh2ReadOnlySftp implements ReadOnlySftp {
  private readonly timeoutMs: number;

  constructor(
    private readonly sftp: SftpReadRequests,
    private readonly options: Ssh2ReadOnlySftpOptions,
  ) {
    this.timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;
  }

  async list(path: string, max: number): Promise<RemoteEntry[]> {
    const handle = await this.request<Buffer>((done) => this.sftp.opendir(path, done));
    const entries: RemoteEntry[] = [];
    try {
      let empty = 0;
      while (entries.length < max) {
        const batch = await this.request<FileEntryWithStats[] | null>((done) =>
          this.sftp.readdir(handle, (error, list) =>
            isEof(error) ? done(undefined, null) : done(error, list),
          ),
        );
        if (batch === null) break;
        if (batch.length === 0 && (empty += 1) >= MAX_EMPTY_BATCHES) break;
        for (const item of batch) {
          if (typeof item.filename !== 'string') continue;
          entries.push({ name: item.filename, ...toStat(item.attrs) });
        }
      }
    } finally {
      this.release(handle);
    }
    return entries.slice(0, max);
  }

  async lstat(path: string): Promise<RemoteStat> {
    return toStat(await this.request<Stats>((done) => this.sftp.lstat(path, done)));
  }

  async openForReading(path: string): Promise<RemoteFile> {
    const handle = await this.request<Buffer>((done) => this.sftp.open(path, 'r', done));
    let closed = false;
    return {
      stat: async () => toStat(await this.request<Stats>((done) => this.sftp.fstat(handle, done))),
      read: (buffer, offset, length, position) =>
        this.request<number>((done) =>
          this.sftp.read(handle, buffer, offset, length, position, (error, bytesRead) =>
            done(error, bytesRead),
          ),
        ),
      close: () => {
        if (!closed) this.release(handle);
        closed = true;
        return Promise.resolve();
      },
    };
  }

  /** Closes a handle without waiting for the answer; a failure changes nothing for the scan. */
  private release(handle: Buffer): void {
    if (this.options.isClosed()) return;
    try {
      this.sftp.close(handle, () => undefined);
    } catch {
      // The session is going away; the server frees the handle with it.
    }
  }

  /** ssh2 fails every pending request with this message when the channel closes under it. */
  private isGone(error: Error): boolean {
    return this.options.isClosed() || error.message === 'No response from server';
  }

  /** One request: refused when the session is gone, failed when it does not answer in time. */
  private request<T>(
    send: (done: (error: Error | undefined | null, value: T) => void) => void,
  ): Promise<T> {
    if (this.options.isClosed()) return Promise.reject(new RemoteSessionError(SESSION_GONE));
    return new Promise<T>((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        settled = true;
        reject(new RemoteSessionError(SESSION_GONE));
      }, this.timeoutMs);
      const done = (error: Error | undefined | null, value: T): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(this.isGone(error) ? new RemoteSessionError(SESSION_GONE) : error);
        else resolve(value);
      };
      try {
        send(done);
      } catch (error) {
        done(error instanceof Error ? error : new Error(String(error)), undefined as T);
      }
    });
  }
}
