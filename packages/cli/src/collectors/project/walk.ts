import { basename, dirname, relative, sep } from 'node:path';
import { isSafeRelativePath } from '../../model/paths.js';
import { LocalProjectTree } from './localTree.js';
import type { ProjectTree } from './tree.js';

/*
 * The directory walk lists candidate files only. It goes through a
 * `ProjectTree` (a local folder or a deployed app's container), whose
 * listings describe entries as lstat does, and visits regular files and
 * directories: symlinks, FIFOs, sockets and devices are skipped and never
 * listed. A file is listed only when its name is on the allow-list below;
 * everything else, including the deny-listed names, is invisible to the rest
 * of the collector. `node_modules` is never entered, so the lockfiles listed
 * are the ones a project commits, at any depth the walk reaches.
 */

export type FileKind =
  | 'package.json'
  | 'cdsrc.json'
  | 'cdsrc.yaml'
  | 'gitignore'
  | 'mta'
  | 'xs-security'
  | 'xs-app'
  | 'cds'
  | 'csv'
  | 'html'
  | 'mtar'
  /** `package-lock.json` or `npm-shrinkwrap.json`, read by the lockfile step. */
  | 'lockfile'
  /** `yarn.lock` or `pnpm-lock.yaml` in the root: listed by name, never opened. */
  | 'foreign-lockfile';

export interface WalkedFile {
  kind: FileKind;
  /** Location in the tree (an absolute path), built from the root without following links. */
  abs: string;
  /** `/`-separated path relative to the root; passes isSafeRelativePath. */
  rel: string;
  /** From lstat, for archives (never opened). */
  size: number;
}

export interface WalkOptions {
  /** Locations of directories the walk must not enter (real paths for a local folder). */
  excludeDirs?: string[];
}

export interface WalkResult {
  files: WalkedFile[];
  /** The entry limit was hit; the listing is incomplete. */
  truncated: boolean;
}

export const MAX_DEPTH = 12;
export const MAX_ENTRIES = 20_000;

export const SKIPPED_DIRS: ReadonlySet<string> = new Set([
  'node_modules',
  '.git',
  'gen',
  'dist',
  'dist-report',
  'target',
  'build',
  'coverage',
  '.vscode',
  '.idea',
]);

/** Directories where `*.csv` counts as seed data. */
const SEED_DIRS: ReadonlySet<string> = new Set(['data', 'csv']);

/**
 * Names that are never opened or listed. The allow-list below would not
 * match them anyway; this check runs first so that a future allow-list
 * change cannot reach them by accident.
 */
export function isDenied(name: string): boolean {
  return (
    name === '.cdsrc-private.json' ||
    name === '.cdsrc.js' ||
    name === 'default-env.json' ||
    name === 'manifest.json' ||
    // Can hold registry tokens; the lockfiles are read without it.
    name === '.npmrc' ||
    name.startsWith('.env') ||
    name.endsWith('.mtaext') ||
    name.endsWith('-key.json') ||
    name.endsWith('.pem') ||
    name.endsWith('.key') ||
    name.endsWith('.http') ||
    name.endsWith('.md')
  );
}

/** The kind of an allow-listed file, by its `/`-separated relative path, or null. */
export function classify(rel: string): FileKind | null {
  const name = rel.includes('/') ? rel.slice(rel.lastIndexOf('/') + 1) : rel;
  if (isDenied(name)) return null;
  const atRoot = !rel.includes('/');
  if (atRoot) {
    if (name === 'package.json') return 'package.json';
    if (name === '.cdsrc.json') return 'cdsrc.json';
    if (name === '.cdsrc.yaml') return 'cdsrc.yaml';
    if (name === 'mta.yaml' || name === 'mta.yml') return 'mta';
    if (name === 'yarn.lock' || name === 'pnpm-lock.yaml') return 'foreign-lockfile';
  }
  if (name === 'package-lock.json' || name === 'npm-shrinkwrap.json') return 'lockfile';
  if (name === '.gitignore') return 'gitignore';
  if (name === 'xs-security.json') return 'xs-security';
  if (name === 'xs-app.json') return 'xs-app';
  if (name.endsWith('.cds')) return 'cds';
  if (name.endsWith('.html')) return 'html';
  if (name.endsWith('.mtar')) return 'mtar';
  if (name.endsWith('.csv')) {
    const parent = atRoot ? '' : basename(dirname(rel));
    return SEED_DIRS.has(parent) ? 'csv' : null;
  }
  return null;
}

function shouldSkipDir(name: string, abs: string, depth: number, exclude: Set<string>): boolean {
  return depth > MAX_DEPTH || SKIPPED_DIRS.has(name) || name.startsWith('.') || exclude.has(abs);
}

/** Relative path with the platform separator turned into `/`, or null when unsafe. */
export function toRelativePath(realRoot: string, abs: string): string | null {
  const rel = relative(realRoot, abs).split(sep).join('/');
  return isSafeRelativePath(rel) ? rel : null;
}

/**
 * A name a listing may never carry: empty, `.`, `..`, or containing `/` or
 * NUL. A local `readdir` cannot return one; a remote listing could, and it
 * would otherwise turn into a misleading relative path.
 */
function isPlainName(name: string): boolean {
  return (
    name !== '' && name !== '.' && name !== '..' && !name.includes('/') && !name.includes('\0')
  );
}

/** The parts of a tree the walk needs. */
export type WalkableTree = Pick<ProjectTree, 'root' | 'join' | 'list'>;

export async function walkTree(tree: WalkableTree, options: WalkOptions = {}): Promise<WalkResult> {
  const exclude = new Set(options.excludeDirs ?? []);
  const files: WalkedFile[] = [];
  const pending: { abs: string; rel: string; depth: number }[] = [
    { abs: tree.root, rel: '', depth: 0 },
  ];
  let visited = 0;

  while (pending.length > 0) {
    const dir = pending.pop();
    if (dir === undefined) break;
    // One entry more than the budget left, so that reaching the limit is noticed.
    const entries = await tree.list(dir.abs, MAX_ENTRIES - visited + 1);
    if (entries === null) continue;
    for (const entry of entries) {
      if (visited >= MAX_ENTRIES) return { files, truncated: true };
      visited += 1;
      if (!isPlainName(entry.name)) continue;
      const abs = tree.join(dir.abs, entry.name);
      const rel = dir.rel === '' ? entry.name : `${dir.rel}/${entry.name}`;
      if (entry.type === 'directory') {
        if (!shouldSkipDir(entry.name, abs, dir.depth + 1, exclude)) {
          pending.push({ abs, rel, depth: dir.depth + 1 });
        }
      } else if (entry.type === 'file') {
        if (!isSafeRelativePath(rel)) continue;
        const kind = classify(rel);
        if (kind !== null) files.push({ kind, abs, rel, size: entry.size });
      }
    }
  }
  files.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  return { files, truncated: false };
}

/** Walks a local project folder; `realRoot` is its real path. */
export async function walkProject(
  realRoot: string,
  options: WalkOptions = {},
): Promise<WalkResult> {
  return walkTree(new LocalProjectTree(realRoot), options);
}
