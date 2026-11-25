import { type JsonShapeLimits, jsonShapeExcess } from '../../io/jsonShape.js';
import {
  LOCKED_PACKAGE_NAME_PATTERN,
  PACKAGE_VERSION_PATTERN,
  type LockfileKind,
  type LockfileStatus,
  type PackageScope,
  type RawLockfile,
  type RawNotKept,
} from '../../model/raw.js';
import { directNamesOf } from './packageJson.js';
import { isPlainObject, parseJson } from './read.js';

/*
 * An npm lockfile (`package-lock.json`, `npm-shrinkwrap.json`, or the hidden
 * lockfile npm writes into `node_modules`), reduced to the packages it pins.
 * Pure: text in, a record out. Of an entry it reads the name, the version,
 * where the package was resolved from and the flags that say how it is
 * installed. The name and version are kept only when the entry was resolved
 * from the public npm registry; every other entry is counted under the
 * reason it is not kept, and its name goes nowhere (D10,
 * docs/data-sources.md §12.1). Never kept: the `resolved` URL (it can name an
 * internal host or carry a token), `integrity`, the `deprecated` message npm
 * copies into an entry, the lockfile's own name, licenses, scripts.
 *
 * The file is untrusted: its shape is checked before it is parsed, the tree
 * of a version 1 lockfile is walked without recursion, and no name from it
 * becomes a key of a plain object.
 */

/**
 * What a lockfile may be before it is parsed. `packages` has one key per
 * installed package, so one object may hold far more keys than a snapshot's
 * objects do; real lockfiles nest five levels and hold about 21 keys and
 * values per package.
 */
export const LOCKFILE_SHAPE_LIMITS: JsonShapeLimits = {
  maxDepth: 64,
  maxItems: 4 * 1024 * 1024,
  maxMembers: 200_000,
};
/** Packages kept per project, and per scan; equals the limit of `packages` in the model. */
export const MAX_PACKAGES = 20_000;
const MAX_NAME_LENGTH = 214;
const MAX_VERSION_LENGTH = 64;
/** A `resolved` longer than this is not looked at: where the package came from stays unknown. */
const MAX_REFERENCE_LENGTH = 4096;
/**
 * Limits on telling the direct dependencies of the local folders of a
 * lockfile (workspace members, `file:` folders): the dependency names looked
 * at over all folders, the length of a folder's key, and the folders walked
 * up from it. A real workspace stays far below them; beyond a limit a package
 * is simply not marked as direct.
 */
const MAX_FOLDER_DEPENDENCIES = 20_000;
const MAX_FOLDER_KEY_LENGTH = 512;
const MAX_FOLDER_LEVELS = 16;

/** The one origin whose packages are kept by name: the public npm registry, over https, default port. */
const PUBLIC_REGISTRY_HOST = 'registry.npmjs.org';
const PUBLIC_REGISTRY_PREFIX = `https://${PUBLIC_REGISTRY_HOST}/`;
const INSTALL_FOLDER = 'node_modules/';
const ALIAS_PREFIX = 'npm:';
/** Hosted-git shorthands npm accepts next to the `git` and `git+<transport>` protocols. */
const GIT_PROTOCOLS: ReadonlySet<string> = new Set([
  'git:',
  'ssh:',
  'github:',
  'gitlab:',
  'bitbucket:',
  'gist:',
]);

/** The lockfiles this parser reads; a yarn or pnpm lockfile is never opened. */
export type NpmLockfileKind = Exclude<LockfileKind, 'yarn' | 'pnpm'>;

/**
 * A `--dependency-exclude` pattern: a package name or scope in which `*`
 * stands for any run of characters. At most `MAX_DEPENDENCY_EXCLUDES` of
 * them; they are compared without regard to case.
 */
export const DEPENDENCY_EXCLUDE_PATTERN = /^[A-Za-z0-9@/._~*-]{1,214}$/;
export const MAX_DEPENDENCY_EXCLUDES = 100;

export interface LockfileSource {
  /** The lockfile's path relative to the project root. */
  file: string;
  kind: NpmLockfileKind;
  /**
   * The names the project's root `package.json` lists as dependencies, for a
   * lockfile without a root entry of its own (version 1, the hidden one);
   * null when that manifest does not describe this lockfile (a nested one).
   */
  rootDirectNames: ReadonlySet<string> | null;
}

export interface LockfileOptions {
  /** Whether a package name is held back (`--dependency-exclude`); default: none is. */
  exclude?: (name: string) => boolean;
  /** Stop once the lockfile holds more packages than this; default `MAX_PACKAGES`. */
  maxPackages?: number;
  /**
   * Leave out the entries npm marks `dev: true`, for a lockfile that was
   * pushed with a deployed app: a production install does not install them.
   * Such an entry is neither kept nor counted, because a package that is not
   * installed is not one that was left unchecked. Entries marked `optional`
   * or `devOptional` stay.
   */
  omitDev?: boolean;
}

/** A package of one lockfile that was resolved from the public npm registry. */
export interface LockedPackage {
  name: string;
  version: string;
  direct: boolean;
  scope: PackageScope;
}

export interface ParsedLockfile {
  /** The lockfile as a snapshot records it. */
  lockfile: RawLockfile;
  /** Its packages from the public npm registry, one per name and version, sorted; empty unless it was read. */
  packages: LockedPackage[];
}

type SourceClass = 'npm' | 'otherRegistry' | 'git' | 'file' | 'unknown';
type NotKeptReason = keyof RawNotKept;

export function emptyNotKept(): RawNotKept {
  return {
    otherRegistry: 0,
    git: 0,
    file: 0,
    link: 0,
    bundled: 0,
    unknown: 0,
    excluded: 0,
    invalid: 0,
  };
}

/** The record of a lockfile none of whose packages are kept. */
export function lockfileRecord(
  source: { file: string; kind: LockfileKind },
  status: Exclude<LockfileStatus, 'read'>,
  lockfileVersion: RawLockfile['lockfileVersion'] = null,
): RawLockfile {
  return {
    file: source.file,
    kind: source.kind,
    lockfileVersion,
    status,
    kept: 0,
    notKept: emptyNotKept(),
  };
}

/** Whether `name` matches `pattern`, where `*` stands for any run of characters. One pass, no backtracking. */
function matchesPattern(pattern: string, name: string): boolean {
  const parts = pattern.split('*');
  const first = parts[0] ?? '';
  if (parts.length === 1) return name === first;
  const last = parts[parts.length - 1] ?? '';
  const end = name.length - last.length;
  if (end < first.length || !name.startsWith(first) || !name.endsWith(last)) return false;
  let from = first.length;
  for (const part of parts.slice(1, -1)) {
    const at = name.indexOf(part, from);
    if (at === -1 || at + part.length > end) return false;
    from = at + part.length;
  }
  return true;
}

/**
 * The test for `--dependency-exclude`: whether a package name matches one of
 * the patterns. Every character but `*` stands for itself, so a pattern can
 * neither fail nor stall, whatever it holds.
 */
export function excludeMatcher(patterns: readonly string[]): (name: string) => boolean {
  const lowered = patterns.map((pattern) => pattern.toLowerCase());
  if (lowered.length === 0) return () => false;
  return (name) => {
    const candidate = name.toLowerCase();
    return lowered.some((pattern) => matchesPattern(pattern, candidate));
  };
}

function isPublicRegistry(reference: string, url: URL): boolean {
  // The prefix is compared as written, so nothing a URL parser would tidy up
  // (another letter case, a backslash, leading whitespace) counts as public.
  return (
    reference.startsWith(PUBLIC_REGISTRY_PREFIX) &&
    url.hostname === PUBLIC_REGISTRY_HOST &&
    url.port === '' &&
    url.username === '' &&
    url.password === ''
  );
}

/** A reference that is no URL: a path to a folder or tarball, or git's `user@host:path` form. */
function sourceOfPlainText(reference: string): SourceClass {
  if (/^(?:\.{1,2}|~)?[\\/]/.test(reference)) return 'file';
  return reference.startsWith('git@') ? 'git' : 'unknown';
}

/** Where an entry was resolved from, by its `resolved` URL; `unknown` when there is none. */
function sourceOf(reference: unknown): SourceClass {
  if (typeof reference !== 'string' || reference === '') return 'unknown';
  if (reference.length > MAX_REFERENCE_LENGTH) return 'unknown';
  let url: URL;
  try {
    url = new URL(reference);
  } catch {
    return sourceOfPlainText(reference);
  }
  const { protocol } = url;
  if (protocol === 'https:' || protocol === 'http:') {
    return isPublicRegistry(reference, url) ? 'npm' : 'otherRegistry';
  }
  if (protocol === 'file:') return 'file';
  if (protocol.startsWith('git+') || GIT_PROTOCOLS.has(protocol)) return 'git';
  return 'unknown';
}

function isLockedName(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= MAX_NAME_LENGTH &&
    LOCKED_PACKAGE_NAME_PATTERN.test(value)
  );
}

function isLockedVersion(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length <= MAX_VERSION_LENGTH &&
    PACKAGE_VERSION_PATTERN.test(value)
  );
}

/** The stronger of two scopes: a package any lockfile entry installs for production is `prod`. */
export function strongerScope(a: PackageScope, b: PackageScope): PackageScope {
  if (a === 'prod' || b === 'prod') return 'prod';
  return a === 'optional' || b === 'optional' ? 'optional' : 'dev';
}

/** The packages and counts of one lockfile while it is read. */
class Tally {
  readonly notKept = emptyNotKept();
  /** More packages than the budget: the lockfile is given up, not cut, and reading it can stop. */
  overBudget = false;
  private readonly kept = new Map<string, LockedPackage>();

  constructor(
    private readonly exclude: (name: string) => boolean,
    private readonly maxPackages: number,
  ) {}

  skip(reason: NotKeptReason): void {
    this.notKept[reason] += 1;
  }

  /** Keeps an entry from the public registry, or counts it as invalid or excluded. */
  keep(name: unknown, version: unknown, direct: boolean, scope: PackageScope): void {
    if (!isLockedName(name) || !isLockedVersion(version)) {
      this.skip('invalid');
      return;
    }
    if (this.exclude(name)) {
      this.skip('excluded');
      return;
    }
    // A name holds `@` only as its first character, so the key cannot be ambiguous.
    const key = `${name}@${version}`;
    const known = this.kept.get(key);
    if (known !== undefined) {
      known.direct ||= direct;
      known.scope = strongerScope(known.scope, scope);
      return;
    }
    if (this.kept.size >= this.maxPackages) {
      this.overBudget = true;
      return;
    }
    this.kept.set(key, { name, version, direct, scope });
  }

  /** Sorted by name, then version, in code point order. */
  packages(): LockedPackage[] {
    return [...this.kept.values()].sort((a, b) =>
      a.name !== b.name ? (a.name < b.name ? -1 : 1) : a.version < b.version ? -1 : 1,
    );
  }
}

/** The name a `packages` key installs under, and whether that is the top level; null outside `node_modules/`. */
function installOf(key: string): { name: string; topLevel: boolean } | null {
  const at = key.lastIndexOf(INSTALL_FOLDER);
  if (at === -1 || (at > 0 && key[at - 1] !== '/')) return null;
  return { name: key.slice(at + INSTALL_FOLDER.length), topLevel: at === 0 };
}

/** `dev`, else `optional` (also for an optional dependency of a dev package), else `prod`. */
function scopeOf(entry: Record<string, unknown>): PackageScope {
  if (entry.dev === true) return 'dev';
  return entry.optional === true || entry.devOptional === true ? 'optional' : 'prod';
}

/** The local folders that a link of the lockfile points at: workspace members and `file:` folders. */
function linkedFolders(packages: Record<string, unknown>): Set<string> {
  const folders = new Set<string>();
  for (const entry of Object.values(packages)) {
    if (!isPlainObject(entry) || entry.link !== true) continue;
    const { resolved } = entry;
    if (typeof resolved === 'string' && resolved.length <= MAX_FOLDER_KEY_LENGTH) {
      folders.add(resolved);
    }
  }
  return folders;
}

/**
 * Where a package that a local folder asks for is installed, found as Node
 * finds it: in the nearest `node_modules`, from the folder up to the root of
 * the lockfile. A folder outside the root (`../local-lib`) ends at the root
 * too, which is where npm installs what it asks for.
 */
function installKeyOf(
  packages: Record<string, unknown>,
  folder: string,
  name: string,
): string | undefined {
  let dir = folder;
  for (let level = 0; level < MAX_FOLDER_LEVELS && dir !== ''; level += 1) {
    const key = `${dir}/${INSTALL_FOLDER}${name}`;
    if (Object.hasOwn(packages, key)) return key;
    const slash = dir.lastIndexOf('/');
    dir = slash === -1 ? '' : dir.slice(0, slash);
  }
  const topLevel = `${INSTALL_FOLDER}${name}`;
  return Object.hasOwn(packages, topLevel) ? topLevel : undefined;
}

/**
 * The install locations of the packages that the local folders of a lockfile
 * list as their own dependencies. A workspace member has a manifest of its
 * own, and its entry carries the same sections as the root entry: what it
 * lists is a direct dependency of the project as much as what the root lists.
 */
function folderDirectKeys(packages: Record<string, unknown>): Set<string> {
  const keys = new Set<string>();
  let left = MAX_FOLDER_DEPENDENCIES;
  for (const [folder, entry] of Object.entries(packages)) {
    if (folder === '' || folder.length > MAX_FOLDER_KEY_LENGTH) continue;
    if (!isPlainObject(entry) || entry.link === true || installOf(folder) !== null) continue;
    for (const name of directNamesOf(entry)) {
      if (left === 0) return keys;
      left -= 1;
      if (name.length > MAX_NAME_LENGTH) continue;
      const key = installKeyOf(packages, folder, name);
      if (key !== undefined) keys.add(key);
    }
  }
  return keys;
}

/** Lockfile version 2 and 3, and the hidden lockfile: one entry per install location. */
function readPackages(
  packages: Record<string, unknown>,
  source: LockfileSource,
  tally: Tally,
  omitDev: boolean,
): void {
  const root = packages[''];
  const directNames = isPlainObject(root)
    ? directNamesOf(root)
    : (source.rootDirectNames ?? new Set<string>());
  const folderDirect = folderDirectKeys(packages);
  const linked = linkedFolders(packages);
  for (const [key, entry] of Object.entries(packages)) {
    if (tally.overBudget) return;
    // The project itself.
    if (key === '') continue;
    if (!isPlainObject(entry)) {
      tally.skip('invalid');
      continue;
    }
    // Not installed in production, whatever it is: a registry package, a link, a bundled one.
    if (omitDev && entry.dev === true) continue;
    const install = installOf(key);
    // A link to a local folder: a workspace member, or a `file:` folder.
    if (entry.link === true) {
      tally.skip('link');
      continue;
    }
    if (install === null) {
      // The folder itself. Its link is counted already; a folder no link points at counts here.
      if (!linked.has(key)) tally.skip('link');
      continue;
    }
    if (entry.inBundle === true) {
      tally.skip('bundled');
      continue;
    }
    const from = sourceOf(entry.resolved);
    if (from !== 'npm') {
      tally.skip(from);
      continue;
    }
    // An alias installs under its own name and records the real one.
    const name = typeof entry.name === 'string' ? entry.name : install.name;
    const direct = (install.topLevel && directNames.has(install.name)) || folderDirect.has(key);
    tally.keep(name, entry.version, direct, scopeOf(entry));
  }
}

/** The package and version inside `npm:<name>@<version>`, how version 1 writes an alias. */
function aliasOf(spec: string): { name: string; version: string } | null {
  const target = spec.slice(ALIAS_PREFIX.length);
  const at = target.lastIndexOf('@');
  return at > 0 ? { name: target.slice(0, at), version: target.slice(at + 1) } : null;
}

function readLegacyEntry(
  key: string,
  entry: Record<string, unknown>,
  direct: boolean,
  tally: Tally,
): void {
  if (entry.bundled === true) {
    tally.skip('bundled');
    return;
  }
  // Without `resolved`, the version says where a local or git package comes from.
  const from = sourceOf(typeof entry.resolved === 'string' ? entry.resolved : entry.version);
  if (from !== 'npm') {
    tally.skip(from);
    return;
  }
  const { version } = entry;
  // The key of an alias is its install name; the real package is in the version.
  const alias =
    typeof version === 'string' && version.startsWith(ALIAS_PREFIX) ? aliasOf(version) : undefined;
  if (alias === undefined) tally.keep(key, version, direct, scopeOf(entry));
  else tally.keep(alias?.name, alias?.version, direct, scopeOf(entry));
}

/** Lockfile version 1: a tree of `dependencies`, walked with a stack of its own. */
function readLegacyTree(
  dependencies: Record<string, unknown>,
  source: LockfileSource,
  tally: Tally,
  omitDev: boolean,
): void {
  const directNames = source.rootDirectNames ?? new Set<string>();
  const pending: { entries: Record<string, unknown>; topLevel: boolean }[] = [
    { entries: dependencies, topLevel: true },
  ];
  for (let level = pending.pop(); level !== undefined; level = pending.pop()) {
    for (const [key, entry] of Object.entries(level.entries)) {
      if (tally.overBudget) return;
      if (!isPlainObject(entry)) {
        tally.skip('invalid');
        continue;
      }
      // Every entry carries its own flag, so what is nested below a dev package is still looked at.
      if (isPlainObject(entry.dependencies)) {
        pending.push({ entries: entry.dependencies, topLevel: false });
      }
      if (omitDev && entry.dev === true) continue;
      readLegacyEntry(key, entry, level.topLevel && directNames.has(key), tally);
    }
  }
}

function knownVersion(value: unknown): RawLockfile['lockfileVersion'] {
  return value === 1 || value === 2 || value === 3 ? value : null;
}

/** The parsed lockfile when its shape is within the limits, else why it is not read. */
function parseWithinLimits(text: string): Record<string, unknown> | 'unreadable' | 'too-large' {
  // npm writes no byte order mark, but an editor may have added one.
  const json = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const excess = jsonShapeExcess(Buffer.from(json, 'utf8'), LOCKFILE_SHAPE_LIMITS);
  if (excess === 'depth') return 'unreadable';
  if (excess !== undefined) return 'too-large';
  const parsed = parseJson(json);
  return isPlainObject(parsed) ? parsed : 'unreadable';
}

/**
 * Reads one npm lockfile. The result always carries the lockfile's record:
 * `read` with its packages and counts, or `unreadable` (not JSON, not a
 * lockfile, an unknown version), `too-large` (more keys and values than the
 * shape limits allow) or `too-many-packages`, each with nothing kept.
 */
export function parseLockfile(
  text: string,
  source: LockfileSource,
  options: LockfileOptions = {},
): ParsedLockfile {
  const unread = (
    status: Exclude<LockfileStatus, 'read'>,
    version: RawLockfile['lockfileVersion'] = null,
  ): ParsedLockfile => ({ lockfile: lockfileRecord(source, status, version), packages: [] });
  const json = parseWithinLimits(text);
  if (typeof json === 'string') return unread(json);

  const lockfileVersion = knownVersion(json.lockfileVersion);
  // A version 1 lockfile of a project without dependencies has no tree at all.
  const legacyTree = json.dependencies === undefined ? {} : json.dependencies;
  const tally = new Tally(options.exclude ?? (() => false), options.maxPackages ?? MAX_PACKAGES);
  // Version 2 holds both forms; `packages` is the one npm itself reads.
  const omitDev = options.omitDev === true;
  if (isPlainObject(json.packages)) {
    readPackages(json.packages, source, tally, omitDev);
  } else if (lockfileVersion === 1 && isPlainObject(legacyTree)) {
    readLegacyTree(legacyTree, source, tally, omitDev);
  } else {
    return unread('unreadable');
  }
  if (tally.overBudget) return unread('too-many-packages', lockfileVersion);
  const packages = tally.packages();
  return {
    lockfile: {
      file: source.file,
      kind: source.kind,
      lockfileVersion,
      status: 'read',
      kept: packages.length,
      notKept: tally.notKept,
    },
    packages,
  };
}
