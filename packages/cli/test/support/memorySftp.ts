import {
  type ReadOnlySftp,
  type RemoteEntry,
  type RemoteFile,
  type RemoteStat,
  RemoteSessionError,
} from '../../src/remote/sftp.js';
import { APP_ROOT } from '../../src/remote/sftpTree.js';

/*
 * An in-memory `ReadOnlySftp` over a map of container paths: what the SFTP
 * tree sees of a deployed app, without a server. Every request is recorded.
 * By default a read is answered at once and with at most four bytes (a short
 * answer, as a real server may give one); a test can set the size of an
 * answer, and can hold the answers back to look at what is in flight and to
 * let them go in an order of its own, or fail them.
 */

/**
 * What a path holds: the text of a regular file; a regular file whose
 * attributes promise `size` bytes while it holds `content` (nothing when
 * absent: a file that ends early); or an entry that is no regular file by
 * lstat (`other`: a symbolic link, a device).
 */
export type MemoryEntry = string | { size: number; content?: string } | { other: true };

/** One read request: where in the file, and how many bytes, it asked for. */
export interface MemoryRead {
  path: string;
  position: number;
  length: number;
}

/** A read request that waits for the test to answer it. */
export interface HeldRead extends MemoryRead {
  /** Answers with the bytes the file holds there (at most `maxAnswer`). */
  answer(): void;
  /** Fails the request. */
  fail(error: Error): void;
}

function isOther(entry: MemoryEntry): entry is { other: true } {
  return typeof entry === 'object' && 'other' in entry;
}

function contentOf(entry: MemoryEntry): Buffer {
  if (typeof entry === 'string') return Buffer.from(entry);
  return Buffer.from(isOther(entry) ? '' : (entry.content ?? ''));
}

export class MemorySftp implements ReadOnlySftp {
  /** `list|lstat|open|read|close <path>`, in the order the requests were made. */
  readonly requests: string[] = [];
  /** Every read request with its position and length, in the order they were made. */
  readonly reads: MemoryRead[] = [];
  /** The session is gone: every request from now on is refused. */
  gone = false;
  /** Paths whose content changes between the listing and the read. */
  readonly swapped = new Set<string>();
  /** The most bytes one read is answered with. */
  maxAnswer = 4;
  /** Hold the answers of read requests back in `held`, until the test lets each go. */
  hold = false;
  readonly held: HeldRead[] = [];
  /** Read requests without an answer right now, and the most there were at one time. */
  inFlight = 0;
  maxInFlight = 0;

  constructor(private readonly files: Record<string, MemoryEntry>) {}

  private stat(path: string): RemoteStat | undefined {
    const value = this.files[path];
    if (value !== undefined) {
      if (isOther(value)) return { type: 'other', size: 0, mtime: 100 };
      const size = typeof value === 'string' ? Buffer.byteLength(value) : value.size;
      return { type: 'file', size, mtime: 100 };
    }
    const isDir = Object.keys(this.files).some((p) => p.startsWith(`${path}/`));
    return isDir ? { type: 'directory', size: 0, mtime: 100 } : undefined;
  }

  list(path: string, max: number): Promise<RemoteEntry[]> {
    this.requests.push(`list ${path}`);
    if (this.gone) return Promise.reject(new RemoteSessionError('gone'));
    const names = new Set<string>();
    for (const p of Object.keys(this.files)) {
      if (p.startsWith(`${path}/`)) names.add(p.slice(path.length + 1).split('/')[0] ?? '');
    }
    const entries = [...names]
      .reverse()
      .map((name) => ({ name, ...this.stat(`${path}/${name}`)! }));
    return Promise.resolve(entries.slice(0, max));
  }

  lstat(path: string): Promise<RemoteStat> {
    this.requests.push(`lstat ${path}`);
    if (this.gone) return Promise.reject(new RemoteSessionError('gone'));
    const stat = this.stat(path);
    return stat ? Promise.resolve(stat) : Promise.reject(new Error('No such file'));
  }

  openForReading(path: string): Promise<RemoteFile> {
    this.requests.push(`open ${path}`);
    if (this.gone) return Promise.reject(new RemoteSessionError('gone'));
    const value = this.files[path];
    if (value === undefined) return Promise.reject(new Error('No such file'));
    const content = contentOf(value);
    const stat = this.stat(path)!;
    return Promise.resolve({
      stat: () => Promise.resolve(this.swapped.has(path) ? { ...stat, mtime: 999 } : stat),
      read: (buffer: Buffer, offset: number, length: number, position: number) =>
        this.read(path, content, { buffer, offset, length, position }),
      close: () => {
        this.requests.push(`close ${path}`);
        return Promise.resolve();
      },
    });
  }

  /** Lets every held read go, in the order the requests were made. */
  answerAll(): void {
    for (const read of this.held.splice(0)) read.answer();
  }

  private read(
    path: string,
    content: Buffer,
    target: { buffer: Buffer; offset: number; length: number; position: number },
  ): Promise<number> {
    const { buffer, offset, length, position } = target;
    this.requests.push(`read ${path}`);
    this.reads.push({ path, position, length });
    if (this.gone) return Promise.reject(new RemoteSessionError('gone'));
    const copy = (): number => {
      const n = Math.min(length, this.maxAnswer, content.length - position);
      if (n <= 0) return 0;
      content.copy(buffer, offset, position, position + n);
      return n;
    };
    if (!this.hold) return Promise.resolve(copy());
    this.inFlight += 1;
    this.maxInFlight = Math.max(this.maxInFlight, this.inFlight);
    return new Promise<number>((resolve, reject) => {
      this.held.push({
        path,
        position,
        length,
        answer: () => {
          this.inFlight -= 1;
          resolve(copy());
        },
        fail: (error) => {
          this.inFlight -= 1;
          reject(error);
        },
      });
    });
  }
}

/** The entries of an app folder, keyed by their path in the container. */
export function appFiles(files: Record<string, MemoryEntry>): Record<string, MemoryEntry> {
  return Object.fromEntries(Object.entries(files).map(([rel, v]) => [`${APP_ROOT}/${rel}`, v]));
}

/** Lets everything that can run without a new answer run: promise callbacks, then timers that are due. */
export function settle(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}
