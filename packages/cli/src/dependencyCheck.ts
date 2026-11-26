import { type CheckDefinition, type CheckRecorder, COLLECTOR_CHECKS } from './checks.js';
import { type DeprecationResult, collectDeprecations } from './collectors/deprecations.js';
import { type OsvTables, type PackageRef, collectOsv, distinctPackages } from './collectors/osv.js';
import { type FetchLike, HttpClient } from './http/httpClient.js';
import { NPM_REGISTRY_HOST, NpmRegistryClient } from './http/npmRegistryClient.js';
import { OSV_HOST, OsvClient } from './http/osvClient.js';
import type { RawDeprecation, RawProject } from './model/raw.js';
import { EgressPolicy } from './net/allowlist.js';
import type { DependencyLookup, DependencyTables } from './project.js';

/*
 * The network step of `baip-lens project`: what the lockfile step kept is
 * looked up on two public sources (docs/data-sources.md §12), on OSV.dev for
 * known vulnerabilities and on the npm registry for deprecated versions. It
 * lives outside the code that reads files and outside the rules, which stay
 * free of any request: `src/main.ts` builds the lookup here and hands it to
 * the project scan as a function.
 *
 * What is sent (D10): the name and version of the packages in
 * `raw.projects[].dependencies.packages`, and nothing else, to both sources
 * alike. Those are the packages a lockfile resolved from
 * `https://registry.npmjs.org/` that no `--dependency-exclude` pattern
 * matched; of every other package the lockfile step kept no name, so there
 * is none to send. Never the names the root `package.json` lists, never a
 * path, never an identifier of the project.
 *
 * No credential can go along: the lookup has an HTTP client of its own,
 * whose allow-list holds the fixed public sources only. The CF API of a
 * `project --cf` run is not on it, no rule on it accepts an `Authorization`
 * header or a cookie, and redirects are not followed.
 *
 * The two sources are asked one after the other and fail independently: each
 * has a check of its own, and stores all of its answers or none of them.
 */

export interface DependencyLookupOptions {
  /** False with `--no-dependency-check`: the checks are recorded as turned off and no request is made. */
  enabled: boolean;
  userAgent: string;
  /** Injected in tests; defaults to the global fetch. */
  fetch?: FetchLike;
  /** Injected in tests to skip retry backoff; defaults to a real timer. */
  sleep?: (ms: number) => Promise<void>;
  /** Progress and notices, one line each. */
  log?: (message: string) => void;
}

/** Requests in flight at the same time. Neither source states a rate limit; this keeps the load modest. */
const CONCURRENCY = 8;
/** A request is tried again at most twice, after a network error, a 429 or a 5xx answer. */
const MAX_RETRIES = 2;
/** For one advisory or one version of a package; a batch query has its own, longer time (`osvClient.ts`). */
const TIMEOUT_MS = 20_000;

/** The checks of the lookup, in the order they are recorded and the sources are asked. */
const CHECKS = [COLLECTOR_CHECKS.osv, COLLECTOR_CHECKS.npmDeprecations] as const;

/** Nothing of OSV.dev: its tables as a snapshot holds them when it was not asked, or could not answer. */
function noAdvisories(): OsvTables {
  return { advisories: [], vulnerablePackages: [] };
}

/** Nothing of either source: for a lookup that makes no request. */
function nothing(): DependencyTables {
  return { ...noAdvisories(), deprecations: [] };
}

/** Every package the lockfile step kept, over all projects of the scan, each name and version once. */
export function packagesToLookUp(projects: readonly RawProject[]): PackageRef[] {
  return distinctPackages(
    projects.flatMap((project) =>
      (project.dependencies?.packages ?? []).map(({ name, version }) => ({ name, version })),
    ),
  );
}

function ran(recorder: CheckRecorder, check: CheckDefinition): boolean {
  return recorder.list().find((result) => result.id === check.id)?.status === 'ran';
}

/** What a lookup needs once it is certain that requests are made. */
interface Asking {
  packages: readonly PackageRef[];
  recorder: CheckRecorder;
  http: HttpClient;
  log: (message: string) => void;
}

/** The known vulnerabilities of the packages, or nothing of them when OSV.dev could not be asked. */
async function askOsv({ packages, recorder, http, log }: Asking): Promise<OsvTables> {
  const tables: OsvTables | undefined = await recorder.run(COLLECTOR_CHECKS.osv, () =>
    collectOsv(new OsvClient(http), packages, { concurrency: CONCURRENCY }),
  );
  if (tables === undefined) return noAdvisories();
  log(
    `${OSV_HOST}: ${tables.vulnerablePackages.length} of ${packages.length} package(s) have a ` +
      `known vulnerability (${tables.advisories.length} advisories)`,
  );
  return tables;
}

/** The deprecated versions among the packages, or nothing of them when the registry could not be asked. */
async function askRegistry({ packages, recorder, http, log }: Asking): Promise<RawDeprecation[]> {
  const found: DeprecationResult | undefined = await recorder.run(
    COLLECTOR_CHECKS.npmDeprecations,
    () =>
      collectDeprecations(new NpmRegistryClient(http), packages, { concurrency: CONCURRENCY, log }),
  );
  if (found === undefined) return [];
  // A version the registry does not know is not deprecated there; how many there were is said.
  const unknown = found.unknown > 0 ? `, ${found.unknown} unknown to the registry` : '';
  log(
    `${NPM_REGISTRY_HOST}: ${found.deprecations.length} of ${packages.length} package(s) are ` +
      `deprecated${unknown}`,
  );
  return found.deprecations;
}

async function lookUp(
  options: DependencyLookupOptions,
  projects: readonly RawProject[],
  recorder: CheckRecorder,
): Promise<DependencyTables> {
  // The user's own switch first, then what the scan itself could not read.
  if (!options.enabled) {
    for (const check of CHECKS) {
      recorder.skip(check, 'disabled', 'turned off with --no-dependency-check');
    }
    return nothing();
  }
  const lockfiles = COLLECTOR_CHECKS.dependencies;
  if (!ran(recorder, lockfiles)) {
    for (const check of CHECKS) {
      recorder.skip(check, 'dependency_skipped', `needs ${lockfiles.id}, which did not run`);
    }
    return nothing();
  }
  const packages = packagesToLookUp(projects);
  if (packages.length === 0) {
    // Nothing to ask about is an answer: no package of a lockfile is left unchecked by it.
    for (const check of CHECKS) recorder.ran(check);
    return nothing();
  }
  const log = options.log ?? (() => {});
  // Said before the first request, so that nothing leaves the machine unannounced (SEC-10).
  log(
    `Looking up ${packages.length} public npm package(s) on ${OSV_HOST} and ${NPM_REGISTRY_HOST}: ` +
      'only their names and versions are sent (--no-dependency-check turns this off, ' +
      '--dependency-exclude holds packages back)',
  );
  const http = new HttpClient({
    // The fixed public sources only: no CF API, no host that may receive a credential.
    policy: new EgressPolicy(),
    userAgent: options.userAgent,
    fetch: options.fetch,
    concurrency: CONCURRENCY,
    maxRetries: MAX_RETRIES,
    timeoutMs: TIMEOUT_MS,
    ...(options.sleep === undefined ? {} : { sleep: options.sleep }),
  });
  const asking: Asking = { packages, recorder, http, log };
  // One source after the other, each with its own check: what one of them could not answer
  // takes nothing from the other.
  const tables = await askOsv(asking);
  const deprecations = await askRegistry(asking);
  return { ...tables, deprecations };
}

/**
 * The lookup `src/main.ts` hands to a project scan. It never rejects for a
 * source that fails: the check of that source is recorded as skipped, with a
 * fixed reason, and nothing of its answers is returned.
 */
export function createDependencyLookup(options: DependencyLookupOptions): DependencyLookup {
  return {
    enabled: options.enabled,
    checks: [...CHECKS],
    run: (projects, recorder) => lookUp(options, projects, recorder),
  };
}
