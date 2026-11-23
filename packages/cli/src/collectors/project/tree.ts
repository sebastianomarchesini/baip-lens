import type { GitignoreLayer } from './gitignore.js';
import type { ReadOptions, ReadResult } from './read.js';

/*
 * Where a project's files come from. The collector walks and reads only
 * through this interface, so a local folder (`baip-lens project --path`) and
 * a deployed app's container (`baip-lens project --cf`) get the same
 * allow-list, limits, parsers and reason codes. A location is an absolute
 * path in the tree's own syntax (the local platform's for a folder, POSIX
 * for a container); the collector never builds one itself, it only joins a
 * directory location and an entry name through `join`.
 */

export type TreeEntryType = 'file' | 'directory' | 'other';

/** One directory entry as `lstat` describes it: a link is `other`, never followed. */
export interface TreeEntry {
  name: string;
  type: TreeEntryType;
  /** Size in bytes; only meaningful for files. */
  size: number;
}

/** Where the project sits in a git repository, for the archive decision. */
export interface RepositoryContext {
  /** The project root relative to the repository root, `/`-separated; `''` when they coincide. */
  prefix: string;
  /** The `.gitignore` layers between the repository root and the project root, bases relative to the repository root. */
  aboveLayers: GitignoreLayer[];
}

export interface ProjectTree {
  /** Location of the project root. */
  readonly root: string;
  /** The root folder's own name: the last fallback for the project id. */
  readonly rootName: string;
  /** The location of `name` inside the directory at `dir`. */
  join(dir: string, name: string): string;
  /**
   * Entries of a directory, sorted by name, at most `max` of them; null when
   * the directory cannot be listed. Rejects only when the whole tree is gone
   * (for example a closed connection), never for one unreadable entry.
   */
  list(dir: string, max: number): Promise<TreeEntry[] | null>;
  /**
   * Reads one file within the read limits (size, binary); a failure is a
   * reason code. The size limit is that of an ordinary project file unless
   * the options name another one (a lockfile).
   */
  read(location: string, options?: ReadOptions): Promise<ReadResult>;
  /** Whether a regular file exists at the location (`lstat`, links not followed). */
  isFile(location: string): Promise<boolean>;
  /** The git context of the root; null when it is not inside a repository. */
  repository(): Promise<RepositoryContext | null>;
}
