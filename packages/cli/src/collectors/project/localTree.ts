import { lstat, readdir } from 'node:fs/promises';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { type GitignoreLayer, parseGitignore } from './gitignore.js';
import { type ReadOptions, type ReadResult, readProjectFile } from './read.js';
import type { ProjectTree, RepositoryContext, TreeEntry } from './tree.js';

/*
 * A project folder on the local file system (`baip-lens project --path`).
 * `lstat` only, so links are listed as `other` and never followed; files are
 * read with `readProjectFile` (O_NOFOLLOW, regular files only, size and binary
 * limits). Outside the root only a `.git` entry is looked for (lstat) and the
 * `.gitignore` files between the repository root and the project root are
 * read, for the archive decision only.
 */

/** Ancestors of the root checked for a `.git` entry. */
export const MAX_ANCESTORS = 64;

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch {
    return false;
  }
}

/** The nearest directory, from the root upwards, with a `.git` entry (lstat only); null when none. */
async function findRepositoryRoot(root: string): Promise<string | null> {
  let dir = root;
  for (let level = 0; level < MAX_ANCESTORS; level += 1) {
    if (await exists(resolve(dir, '.git'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

/** The project root relative to the repository root, `/`-separated; `''` when they coincide. */
function ancestorPrefix(repositoryRoot: string, root: string): string {
  return relative(repositoryRoot, root).split(sep).join('/');
}

/**
 * The .gitignore layers of the directories from the repository root down to
 * the parent of the project root, with bases relative to the repository
 * root. They lie outside the project, so they are read directly: never
 * listed, counted or recorded as unreadable, and only their decision about
 * an archive is kept.
 */
async function ancestorGitignoreLayers(
  repositoryRoot: string,
  prefix: string,
): Promise<GitignoreLayer[]> {
  const layers: GitignoreLayer[] = [];
  if (prefix === '') return layers;
  const segments = prefix.split('/');
  for (let depth = 0; depth < segments.length; depth += 1) {
    const dirs = segments.slice(0, depth);
    const result = await readProjectFile(resolve(repositoryRoot, ...dirs, '.gitignore'));
    if (result.ok) layers.push({ base: dirs.join('/'), rules: parseGitignore(result.text) });
  }
  return layers;
}

export class LocalProjectTree implements ProjectTree {
  readonly rootName: string;

  /** @param root the real path of the project root (see `resolveProjectRoot`). */
  constructor(readonly root: string) {
    this.rootName = basename(root);
  }

  join(dir: string, name: string): string {
    return join(dir, name);
  }

  async list(dir: string, max: number): Promise<TreeEntry[] | null> {
    let names: string[];
    try {
      names = (await readdir(dir)).sort();
    } catch {
      return null;
    }
    const entries: TreeEntry[] = [];
    for (const name of names.slice(0, Math.max(0, max))) {
      try {
        const stats = await lstat(join(dir, name));
        const type = stats.isDirectory() ? 'directory' : stats.isFile() ? 'file' : 'other';
        entries.push({ name, type, size: stats.size });
      } catch {
        // Vanished or unreadable: counted as visited, never listed.
        entries.push({ name, type: 'other', size: 0 });
      }
    }
    return entries;
  }

  read(location: string, options?: ReadOptions): Promise<ReadResult> {
    return readProjectFile(location, options);
  }

  async isFile(location: string): Promise<boolean> {
    try {
      return (await lstat(location)).isFile();
    } catch {
      return false;
    }
  }

  async repository(): Promise<RepositoryContext | null> {
    const repositoryRoot = await findRepositoryRoot(this.root);
    if (repositoryRoot === null) return null;
    const prefix = ancestorPrefix(repositoryRoot, this.root);
    return { prefix, aboveLayers: await ancestorGitignoreLayers(repositoryRoot, prefix) };
  }
}
