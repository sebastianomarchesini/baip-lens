import type { RawLockedPackage, RawLockfile } from '../../model/raw.js';
import {
  type LockedPackage,
  type NpmLockfileKind,
  MAX_PACKAGES,
  lockfileRecord,
  strongerScope,
} from './lockfile.js';
import type { WalkedFile } from './walk.js';

/*
 * Which lockfiles of a project are read, and how the packages of several
 * lockfiles become the one list a project keeps (docs/data-sources.md §12.1).
 * An MTA project often has a lockfile per module; a package that several of
 * them pin at the same version is kept once, with the lockfiles that pin it.
 */

/** Lockfile records per project; equals the limit of `lockfiles` in the model. */
export const MAX_LOCKFILES = 50;
/** The bytes all lockfiles of a project may take together, apart from the budget of the other files. */
export const MAX_LOCKFILE_TOTAL_BYTES = 64 * 1024 * 1024;
/** Lockfile paths kept per package; equals the limit in the model. */
export const MAX_LOCKFILES_PER_PACKAGE = 20;
/**
 * The bytes the lockfile paths of one package may take together in the
 * snapshot, as JSON text. The model allows 20 paths of 512 characters for
 * each of 20 000 packages, which is more than a snapshot file may hold
 * (`MAX_SNAPSHOT_BYTES`): a scan must never write a snapshot that
 * `report --from` refuses. Twenty paths of up to 100 characters fit.
 */
export const MAX_PACKAGE_LOCKFILE_BYTES = 2048;

const SHRINKWRAP = 'npm-shrinkwrap.json';

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function directoryOf(rel: string): string {
  const slash = rel.lastIndexOf('/');
  return slash === -1 ? '' : rel.slice(0, slash);
}

function baseName(rel: string): string {
  return rel.slice(rel.lastIndexOf('/') + 1);
}

export function npmLockfileKind(rel: string): NpmLockfileKind {
  return baseName(rel) === SHRINKWRAP ? 'shrinkwrap' : 'package-lock';
}

/** Whether a relative path lies in the project root itself. */
export function inProjectRoot(rel: string): boolean {
  return !rel.includes('/');
}

export interface LockfileChoice {
  /** The npm lockfiles to read: the root one first, then the others in path order. */
  toRead: WalkedFile[];
  /** yarn and pnpm lockfiles of the root, as records: listed, never opened. */
  foreign: RawLockfile[];
  /** npm lockfiles beyond the limit, which are not opened. */
  notRead: number;
}

/**
 * Picks the lockfiles to read among the files the walk listed. In one
 * directory `npm-shrinkwrap.json` wins over `package-lock.json`, as it does
 * for npm, and the loser is not opened. The root lockfile comes first, so
 * that neither the limit on lockfiles nor their byte budget can leave out the
 * one that answers for the root manifest.
 */
export function chooseLockfiles(files: readonly WalkedFile[]): LockfileChoice {
  const foreign = files
    .filter((file) => file.kind === 'foreign-lockfile')
    .sort((a, b) => compareText(a.rel, b.rel))
    .map((file) =>
      lockfileRecord(
        { file: file.rel, kind: baseName(file.rel) === 'yarn.lock' ? 'yarn' : 'pnpm' },
        'unsupported',
      ),
    );
  const byDirectory = new Map<string, WalkedFile>();
  for (const file of files) {
    if (file.kind !== 'lockfile') continue;
    const directory = directoryOf(file.rel);
    const chosen = byDirectory.get(directory);
    if (chosen === undefined || baseName(file.rel) === SHRINKWRAP) {
      byDirectory.set(directory, file);
    }
  }
  const ordered = [...byDirectory.values()].sort(
    (a, b) =>
      Number(inProjectRoot(b.rel)) - Number(inProjectRoot(a.rel)) || compareText(a.rel, b.rel),
  );
  const room = Math.max(0, MAX_LOCKFILES - foreign.length);
  return {
    toRead: ordered.slice(0, room),
    foreign,
    notRead: Math.max(0, ordered.length - room),
  };
}

/** The packages a project may still keep: the caller's remaining budget, never above the limit. */
export function packageBudget(maxPackages: number | undefined): number {
  if (maxPackages === undefined || !Number.isFinite(maxPackages)) return MAX_PACKAGES;
  return Math.max(0, Math.min(MAX_PACKAGES, Math.floor(maxPackages)));
}

/**
 * The lockfile paths a package keeps: the first `MAX_LOCKFILES_PER_PACKAGE`
 * of the sorted paths, and of those only as many as fit
 * `MAX_PACKAGE_LOCKFILE_BYTES`. The first path is always kept.
 */
export function keptLockfilePaths(sorted: readonly string[]): string[] {
  const kept: string[] = [];
  let bytes = 0;
  for (const path of sorted.slice(0, MAX_LOCKFILES_PER_PACKAGE)) {
    // As the snapshot writes it: quoted, with what JSON escapes.
    bytes += Buffer.byteLength(JSON.stringify(path));
    if (kept.length > 0 && bytes > MAX_PACKAGE_LOCKFILE_BYTES) break;
    kept.push(path);
  }
  return kept;
}

interface Merged extends LockedPackage {
  lockfiles: Set<string>;
}

/**
 * The packages of a project, one per name and version, merged over its
 * lockfiles: direct when any lockfile has it as a direct dependency, and
 * with the strongest scope (`prod`, else `optional`, else `dev`).
 */
export class PackageTable {
  private readonly byKey = new Map<string, Merged>();

  /** @param max the most packages the table may hold (see `packageBudget`). */
  constructor(private readonly max: number) {}

  get size(): number {
    return this.byKey.size;
  }

  /**
   * Adds the packages of one lockfile. A lockfile whose new packages do not
   * fit is not added at all, and the answer is false: half a lockfile would
   * look like a checked one.
   */
  add(file: string, packages: readonly LockedPackage[]): boolean {
    const keyOf = (item: LockedPackage): string => `${item.name}@${item.version}`;
    const fresh = new Set<string>();
    for (const item of packages) {
      const key = keyOf(item);
      if (!this.byKey.has(key)) fresh.add(key);
    }
    if (this.byKey.size + fresh.size > this.max) return false;
    for (const item of packages) {
      const known = this.byKey.get(keyOf(item));
      if (known === undefined) {
        this.byKey.set(keyOf(item), { ...item, lockfiles: new Set([file]) });
        continue;
      }
      known.direct ||= item.direct;
      known.scope = strongerScope(known.scope, item.scope);
      known.lockfiles.add(file);
    }
    return true;
  }

  /** Sorted by name, then version, in code point order; each with its first lockfiles, sorted. */
  list(): RawLockedPackage[] {
    return [...this.byKey.values()]
      .sort((a, b) => compareText(a.name, b.name) || compareText(a.version, b.version))
      .map(({ name, version, direct, scope, lockfiles }) => ({
        name,
        version,
        direct,
        scope,
        lockfiles: keptLockfilePaths([...lockfiles].sort(compareText)),
      }));
  }
}

export function sortLockfiles(lockfiles: readonly RawLockfile[]): RawLockfile[] {
  return [...lockfiles].sort((a, b) => compareText(a.file, b.file));
}
