import { CheckSkipError } from '../checks.js';
import {
  MAX_BATCH_QUERIES,
  OSV_HOST,
  type OsvAdvisory,
  type OsvClient,
  OsvError,
  type OsvQuery,
} from '../http/osvClient.js';
import { rawListBytes } from '../io/jsonSize.js';
import { SNAPSHOT_LIST_LIMITS as LIMITS } from '../model/list.js';
import {
  type RawAdvisory,
  RawAdvisorySchema,
  type RawPackageAdvisory,
  type RawVulnerablePackage,
  RawVulnerablePackageSchema,
} from '../model/raw.js';
import { cleanExternalText } from './sanitize.js';

/*
 * The known vulnerabilities of the lockfile packages, from OSV.dev
 * (docs/data-sources.md §12.3). First the ids of the advisories of every
 * package version, in batches; then each advisory once, whatever the number
 * of packages that have it.
 *
 * All or nothing: the tables are handed over only when every request was
 * answered and every answer understood. Anything else ends in a
 * `CheckSkipError` with one of a few fixed reasons, the check is recorded as
 * skipped and nothing of what was already answered is kept, so that "no
 * finding" never stands for "not looked up". After a failure no further
 * request is started.
 *
 * The result does not depend on the order of the packages handed in, nor on
 * the order in which answers arrive: packages and advisories are sorted.
 */

/** A package version to look up: one the lockfile step kept, so one from the public npm registry. */
export interface PackageRef {
  name: string;
  version: string;
}

/** What the lookup stores in the snapshot. */
export interface OsvTables {
  advisories: RawAdvisory[];
  vulnerablePackages: RawVulnerablePackage[];
}

export interface OsvOptions {
  /** Requests in flight at the same time (default 8). */
  concurrency?: number;
}

const CONCURRENCY = 8;
/** OSV.dev pages a query with more than 1,000 advisories; nothing real comes near ten pages. */
export const MAX_QUERY_PAGES = 10;
/** The tables may take this much of a snapshot file, as it is written. */
export const MAX_TABLE_BYTES = 16 * 1024 * 1024;
/**
 * The least an advisory of a package takes in a snapshot: its braces, its
 * id and an empty list of fixed versions, each on a line of its own. More
 * advisories of packages than fit into `MAX_TABLE_BYTES` at this size are
 * refused while the ids come in, before they are held in memory.
 */
const MIN_PACKAGE_ADVISORY_BYTES = 64;
const MAX_PACKAGE_ADVISORIES_IN_ALL = Math.floor(MAX_TABLE_BYTES / MIN_PACKAGE_ADVISORY_BYTES);

const count = (value: number): string => value.toLocaleString('en-US');

const TOO_MANY_ADVISORIES = `more than ${count(LIMITS.advisories)} advisories`;
const TOO_MANY_FOR_ONE_PACKAGE = `more than ${count(LIMITS.packageAdvisories)} advisories for one package`;
const TOO_MANY_PACKAGES = `more than ${count(LIMITS.vulnerablePackages)} packages to look up`;
const TOO_LARGE = `${OSV_HOST} sent more than a snapshot can hold`;
const UNEXPECTED_ERROR = `the lookup on ${OSV_HOST} stopped with an unexpected error`;

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** The distinct package versions, sorted by name and then version, in code point order. */
export function distinctPackages(packages: readonly PackageRef[]): PackageRef[] {
  const seen = new Set<string>();
  const distinct: PackageRef[] = [];
  for (const { name, version } of packages) {
    // A name holds no blank, so the key cannot stand for two packages.
    const key = `${name} ${version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    distinct.push({ name, version });
  }
  return distinct.sort((a, b) => compareText(a.name, b.name) || compareText(a.version, b.version));
}

/**
 * Runs `work` on every item, at most `size` at a time. After the first
 * failure no further item is started; the ones in flight are waited for, and
 * the first failure is thrown.
 */
async function inPool<T>(
  items: readonly T[],
  size: number,
  work: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0;
  let failed = false;
  let failure: unknown;
  const worker = async (): Promise<void> => {
    while (!failed && next < items.length) {
      const item = items[next++] as T;
      try {
        await work(item);
      } catch (error) {
        if (!failed) failure = error;
        failed = true;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, worker));
  if (failed) throw failure;
}

function batchesOf<T>(items: readonly T[], size: number): T[][] {
  const batches: T[][] = [];
  for (let start = 0; start < items.length; start += size) {
    batches.push(items.slice(start, start + size));
  }
  return batches;
}

/** The ids of the advisories per package, as they come in, with the limits that hold while they do. */
class AdvisoryIds {
  /** Per package, in the order of the packages. */
  readonly byPackage: Set<string>[];
  readonly distinct = new Set<string>();
  private total = 0;

  constructor(packages: number) {
    this.byPackage = Array.from({ length: packages }, () => new Set<string>());
  }

  add(index: number, ids: readonly string[]): void {
    const own = this.byPackage[index];
    if (own === undefined) throw new Error('an answer for a package that was not asked about');
    for (const id of ids) {
      if (own.has(id)) continue;
      own.add(id);
      this.total += 1;
      this.distinct.add(id);
    }
    if (own.size > LIMITS.packageAdvisories) {
      throw new CheckSkipError('error', TOO_MANY_FOR_ONE_PACKAGE);
    }
    if (this.distinct.size > LIMITS.advisories) {
      throw new CheckSkipError('error', TOO_MANY_ADVISORIES);
    }
    if (this.total > MAX_PACKAGE_ADVISORIES_IN_ALL) throw new CheckSkipError('error', TOO_LARGE);
  }
}

/**
 * One batch of at most 1,000 packages, with the further pages of the
 * packages that have more advisories than one answer holds. `offset` is the
 * place of the batch's first package among all packages.
 */
async function queryBatch(
  client: OsvClient,
  batch: readonly PackageRef[],
  offset: number,
  ids: AdvisoryIds,
): Promise<void> {
  let pending: { index: number; query: OsvQuery }[] = batch.map((query, at) => ({
    index: offset + at,
    query,
  }));
  for (let page = 0; pending.length > 0; page += 1) {
    if (page >= MAX_QUERY_PAGES) throw new OsvError('unexpected');
    const results = await client.queryBatch(pending.map((item) => item.query));
    const next: typeof pending = [];
    for (const [at, item] of pending.entries()) {
      const result = results[at];
      if (result === undefined) throw new OsvError('unexpected');
      ids.add(item.index, result.ids);
      if (result.nextPageToken !== undefined) {
        next.push({
          index: item.index,
          query: { ...item.query, pageToken: result.nextPageToken },
        });
      }
    }
    pending = next;
  }
}

/** The ids of the advisories of every package: the first batch alone, the others a few at a time. */
async function queryAll(
  client: OsvClient,
  packages: readonly PackageRef[],
  concurrency: number,
): Promise<AdvisoryIds> {
  const ids = new AdvisoryIds(packages.length);
  const batches = batchesOf(packages, MAX_BATCH_QUERIES).map((batch, at) => ({
    batch,
    offset: at * MAX_BATCH_QUERIES,
  }));
  const [first, ...rest] = batches;
  if (first === undefined) return ids;
  // The first request decides whether OSV.dev can be asked at all: when it
  // cannot, one request failed, not one per batch.
  await queryBatch(client, first.batch, first.offset, ids);
  await inPool(rest, concurrency, ({ batch, offset }) => queryBatch(client, batch, offset, ids));
  return ids;
}

/** How a list of versions is stored: by number first, so that 1.10.0 follows 1.9.0. */
function compareVersions(a: string, b: string): number {
  const numbers = (version: string): number[] =>
    version.split(/[-+]/, 1)[0]?.split('.').map(Number) ?? [];
  const [left, right] = [numbers(a), numbers(b)];
  for (let part = 0; part < 3; part += 1) {
    const difference = (left[part] ?? 0) - (right[part] ?? 0);
    if (difference !== 0) return difference;
  }
  return compareText(a, b);
}

/**
 * The fixed versions an advisory names for one package, sorted. With more
 * than the snapshot keeps the highest stay: each of them is a version the
 * advisory calls fixed, so "upgrade to it" stays true, where "there is no
 * fix" would not.
 */
function fixedFor(advisory: OsvAdvisory, name: string): string[] {
  const versions = [...new Set(advisory.fixed.get(name) ?? [])].sort(compareVersions);
  return versions.slice(Math.max(0, versions.length - LIMITS.fixedVersions));
}

function toRawAdvisory(advisory: OsvAdvisory): RawAdvisory {
  const summary = advisory.summary === null ? '' : cleanExternalText(advisory.summary);
  return {
    id: advisory.id,
    aliases: [...advisory.aliases].sort(compareText),
    summary: summary === '' ? null : summary,
    cvssV3: advisory.cvssV3,
    label: advisory.label,
  };
}

/** The rows of the tables, from the ids per package and the advisories that are not withdrawn. */
function toTables(
  packages: readonly PackageRef[],
  ids: AdvisoryIds,
  advisories: ReadonlyMap<string, OsvAdvisory>,
): OsvTables {
  const kept = [...advisories.values()]
    .filter((advisory) => !advisory.withdrawn)
    .sort((a, b) => compareText(a.id, b.id));
  const vulnerablePackages: RawVulnerablePackage[] = [];
  for (const [index, { name, version }] of packages.entries()) {
    const own: RawPackageAdvisory[] = [];
    for (const id of [...(ids.byPackage[index] ?? [])].sort(compareText)) {
      const advisory = advisories.get(id);
      if (advisory === undefined) throw new OsvError('unexpected');
      if (!advisory.withdrawn) own.push({ id, fixed: fixedFor(advisory, name) });
    }
    if (own.length > 0) vulnerablePackages.push({ name, version, advisories: own });
  }
  return { advisories: kept.map(toRawAdvisory), vulnerablePackages };
}

/**
 * Refuses tables a snapshot could not hold, or that `report --from` would not
 * read again: a scan never writes what it cannot load.
 */
function assertStorable(tables: OsvTables): void {
  const valid =
    tables.advisories.every((row) => RawAdvisorySchema.safeParse(row).success) &&
    tables.vulnerablePackages.every((row) => RawVulnerablePackageSchema.safeParse(row).success);
  if (!valid) throw new OsvError('unexpected');
  const advisoryBytes = rawListBytes(tables.advisories, MAX_TABLE_BYTES);
  const bytes =
    advisoryBytes + rawListBytes(tables.vulnerablePackages, MAX_TABLE_BYTES - advisoryBytes);
  if (bytes > MAX_TABLE_BYTES) throw new CheckSkipError('error', TOO_LARGE);
}

/** The reason a failed lookup is recorded with: fixed words, never what a server sent. */
function skipFor(error: unknown): CheckSkipError {
  if (error instanceof CheckSkipError) return error;
  if (error instanceof OsvError) {
    return new CheckSkipError(
      error.failure === 'unreachable' ? 'unavailable' : 'error',
      error.message,
    );
  }
  return new CheckSkipError('error', UNEXPECTED_ERROR);
}

async function collect(
  client: OsvClient,
  packages: readonly PackageRef[],
  concurrency: number,
): Promise<OsvTables> {
  if (packages.length > LIMITS.vulnerablePackages) {
    throw new CheckSkipError('error', TOO_MANY_PACKAGES);
  }
  const ids = await queryAll(client, packages, concurrency);
  const names = new Set(packages.map((item) => item.name));
  const advisories = new Map<string, OsvAdvisory>();
  await inPool([...ids.distinct].sort(compareText), concurrency, async (id) => {
    advisories.set(id, await client.advisory(id, names));
  });
  const tables = toTables(packages, ids, advisories);
  assertStorable(tables);
  return tables;
}

/**
 * Looks the packages up on OSV.dev. Nothing is asked when there is nothing
 * to look up. Rejects with a `CheckSkipError` when the lookup could not be
 * completed, whatever the cause.
 */
export async function collectOsv(
  client: OsvClient,
  packages: readonly PackageRef[],
  options: OsvOptions = {},
): Promise<OsvTables> {
  try {
    return await collect(client, distinctPackages(packages), options.concurrency ?? CONCURRENCY);
  } catch (error) {
    throw skipFor(error);
  }
}
