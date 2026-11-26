import { CheckSkipError } from '../checks.js';
import {
  NPM_REGISTRY_HOST,
  type NpmRegistryClient,
  NpmRegistryError,
  type RegistryVersion,
  requestedVersion,
} from '../http/npmRegistryClient.js';
import { rawListBytes } from '../io/jsonSize.js';
import { SNAPSHOT_LIST_LIMITS as LIMITS } from '../model/list.js';
import {
  PACKAGE_VERSION_PATTERN,
  type RawDeprecation,
  RawDeprecationSchema,
} from '../model/raw.js';
import { type PackageRef, compareText, distinctPackages, inPool } from './packageLookup.js';
import { cleanExternalText } from './sanitize.js';

/*
 * Which of the lockfile packages are deprecated, from the public npm
 * registry (docs/data-sources.md §12.4). First every package version is
 * asked about once; then, for every package that has a deprecated version,
 * what the registry calls its latest version, once per package name: whether
 * there is a version to move to, or the package as a whole was given up.
 *
 * A version the registry does not know (404) is an answer: it is not
 * deprecated there, it is counted, and nothing is stored about it.
 *
 * All or nothing: the table is handed over only when every request was
 * answered and every answer understood. Anything else ends in a
 * `CheckSkipError` with one of a few fixed reasons, the check is recorded as
 * skipped and nothing of what was already answered is kept, so that "no
 * finding" never stands for "not looked up". After a failure no further
 * request is started.
 *
 * An answer is reduced to what the snapshot stores of it as soon as it
 * arrives, the message cleaned and cut: what is held while the other
 * packages are asked about is bounded by their number, not by what the
 * registry chose to send.
 *
 * The result does not depend on the order of the packages handed in, nor on
 * the order in which answers arrive: the rows are in the order of the sorted
 * packages.
 */

/** What the lookup hands over. */
export interface DeprecationResult {
  /** The deprecated package versions, as the snapshot stores them. */
  deprecations: RawDeprecation[];
  /** Package versions the registry does not know: not deprecated there, and counted for the log only. */
  unknown: number;
}

export interface DeprecationOptions {
  /** Requests in flight at the same time (default 8). */
  concurrency?: number;
  /** Progress, one line for every 2,000 packages that were answered. */
  log?: (message: string) => void;
}

const CONCURRENCY = 8;
/** A lookup of many thousand packages takes minutes: it says how far it is every so many answers. */
export const PROGRESS_EVERY = 2_000;
/** The table may take this much of a snapshot file, as it is written. */
export const MAX_DEPRECATION_TABLE_BYTES = 8 * 1024 * 1024;
const MAX_PACKAGE_VERSION_LENGTH = 64;

const count = (value: number): string => value.toLocaleString('en-US');

const TOO_MANY_PACKAGES = `more than ${count(LIMITS.deprecations)} packages to look up`;
const TOO_LARGE = `${NPM_REGISTRY_HOST} sent more than a snapshot can hold`;
const UNEXPECTED_ERROR = `the lookup on ${NPM_REGISTRY_HOST} stopped with an unexpected error`;

/** One request for a version, and the packages it answers for. */
interface VersionRequest {
  name: string;
  /** The version as it is asked for: without build metadata. */
  version: string;
  /** Where the packages are in the sorted list: more than one when they differ in build metadata only. */
  packages: number[];
}

/** One request per package name and requested version, in the order of the packages. */
function versionRequests(packages: readonly PackageRef[]): VersionRequest[] {
  const requests = new Map<string, VersionRequest>();
  for (const [index, { name, version }] of packages.entries()) {
    const asked = requestedVersion(version);
    // A name holds no blank, so the key cannot stand for two requests.
    const key = `${name} ${asked}`;
    const request = requests.get(key);
    if (request === undefined) requests.set(key, { name, version: asked, packages: [index] });
    else request.packages.push(index);
  }
  return [...requests.values()];
}

/** The answers about the versions, as they come in, with the limits that hold while they do. */
class Answers {
  /** Per package, in the order of the packages: the cleaned message of a deprecated one. */
  readonly messages: (string | undefined)[];
  unknown = 0;
  private answered = 0;
  /** What the names, versions and messages of the deprecated packages take at the very least. */
  private bytes = 0;

  constructor(
    private readonly packages: readonly PackageRef[],
    private readonly log: (message: string) => void,
  ) {
    this.messages = new Array<string | undefined>(packages.length).fill(undefined);
  }

  add(request: VersionRequest, answer: RegistryVersion | null): void {
    if (answer === null) this.unknown += request.packages.length;
    else if (answer.deprecated !== null) this.deprecated(request, answer.deprecated);
    this.progress(request.packages.length);
  }

  /** The names of the packages with a deprecated version, each once, sorted. */
  names(): string[] {
    const names = new Set<string>();
    for (const [index, message] of this.messages.entries()) {
      const name = this.packages[index]?.name;
      if (message !== undefined && name !== undefined) names.add(name);
    }
    return [...names].sort(compareText);
  }

  private deprecated(request: VersionRequest, text: string): void {
    // Reduced before the next answer is read: the text is not held as it came.
    const message = cleanExternalText(text);
    for (const index of request.packages) {
      const item = this.packages[index];
      if (item === undefined) throw new Error('an answer for a package that was not asked about');
      this.messages[index] = message;
      this.bytes +=
        Buffer.byteLength(item.name) + Buffer.byteLength(item.version) + Buffer.byteLength(message);
    }
    // Known before the last answer is in: nothing more is asked once the table cannot be stored.
    if (this.bytes > MAX_DEPRECATION_TABLE_BYTES) throw new CheckSkipError('error', TOO_LARGE);
  }

  private progress(packages: number): void {
    const before = this.answered;
    this.answered += packages;
    if (Math.floor(this.answered / PROGRESS_EVERY) === Math.floor(before / PROGRESS_EVERY)) return;
    this.log(
      `${NPM_REGISTRY_HOST}: ${this.answered} of ${this.packages.length} package(s) checked`,
    );
  }
}

/** What the registry says about the latest version of a package, as a row stores it. */
interface Latest {
  latest: string | null;
  latestDeprecated: boolean;
}

function isStorableVersion(value: string): boolean {
  return value.length <= MAX_PACKAGE_VERSION_LENGTH && PACKAGE_VERSION_PATTERN.test(value);
}

function latestOf(answer: RegistryVersion | null): Latest {
  // The registry names no latest version: there is none to move to.
  if (answer === null) return { latest: null, latestDeprecated: true };
  return {
    latest: isStorableVersion(answer.version) ? answer.version : null,
    latestDeprecated: answer.deprecated !== null,
  };
}

/** The rows of the table, in the order of the packages. */
function toRows(
  packages: readonly PackageRef[],
  answers: Answers,
  latest: ReadonlyMap<string, Latest>,
): RawDeprecation[] {
  const rows: RawDeprecation[] = [];
  for (const [index, { name, version }] of packages.entries()) {
    const message = answers.messages[index];
    if (message === undefined) continue;
    const newest = latest.get(name);
    if (newest === undefined) throw new NpmRegistryError('unexpected');
    rows.push({ name, version, message, ...newest });
  }
  return rows;
}

/**
 * Refuses a table a snapshot could not hold, or that `report --from` would
 * not read again: a scan never writes what it cannot load.
 */
function assertStorable(rows: readonly RawDeprecation[]): void {
  if (!rows.every((row) => RawDeprecationSchema.safeParse(row).success)) {
    throw new NpmRegistryError('unexpected');
  }
  if (rawListBytes(rows, MAX_DEPRECATION_TABLE_BYTES) > MAX_DEPRECATION_TABLE_BYTES) {
    throw new CheckSkipError('error', TOO_LARGE);
  }
}

/** The reason a failed lookup is recorded with: fixed words, never what a server sent. */
function skipFor(error: unknown): CheckSkipError {
  if (error instanceof CheckSkipError) return error;
  if (error instanceof NpmRegistryError) {
    return new CheckSkipError(
      error.failure === 'unreachable' ? 'unavailable' : 'error',
      error.message,
    );
  }
  return new CheckSkipError('error', UNEXPECTED_ERROR);
}

async function collect(
  client: NpmRegistryClient,
  packages: readonly PackageRef[],
  options: DeprecationOptions,
): Promise<DeprecationResult> {
  if (packages.length > LIMITS.deprecations) throw new CheckSkipError('error', TOO_MANY_PACKAGES);
  const concurrency = options.concurrency ?? CONCURRENCY;
  const answers = new Answers(packages, options.log ?? (() => {}));
  const ask = async (request: VersionRequest): Promise<void> => {
    answers.add(request, await client.version(request.name, request.version));
  };
  const [first, ...rest] = versionRequests(packages);
  if (first === undefined) return { deprecations: [], unknown: 0 };
  // The first request decides whether the registry can be asked at all: when
  // it cannot, one request failed, not one for each that was in flight.
  await ask(first);
  await inPool(rest, concurrency, ask);

  const latest = new Map<string, Latest>();
  await inPool(answers.names(), concurrency, async (name) => {
    latest.set(name, latestOf(await client.latest(name)));
  });
  const deprecations = toRows(packages, answers, latest);
  assertStorable(deprecations);
  return { deprecations, unknown: answers.unknown };
}

/**
 * Looks the packages up on the npm registry. Nothing is asked when there is
 * nothing to look up. Rejects with a `CheckSkipError` when the lookup could
 * not be completed, whatever the cause.
 */
export async function collectDeprecations(
  client: NpmRegistryClient,
  packages: readonly PackageRef[],
  options: DeprecationOptions = {},
): Promise<DeprecationResult> {
  try {
    return await collect(client, distinctPackages(packages), options);
  } catch (error) {
    throw skipFor(error);
  }
}
