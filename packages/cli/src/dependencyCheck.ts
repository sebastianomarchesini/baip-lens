import { type CheckDefinition, type CheckRecorder, COLLECTOR_CHECKS } from './checks.js';
import { type OsvTables, type PackageRef, collectOsv, distinctPackages } from './collectors/osv.js';
import { type FetchLike, HttpClient } from './http/httpClient.js';
import { OSV_HOST, OsvClient } from './http/osvClient.js';
import type { RawProject } from './model/raw.js';
import { EgressPolicy } from './net/allowlist.js';
import type { DependencyLookup, DependencyTables } from './project.js';

/*
 * The network step of `baip-lens project`: what the lockfile step kept is
 * looked up on OSV.dev (docs/data-sources.md §12). It lives outside the code
 * that reads files and outside the rules, which stay free of any request:
 * `src/main.ts` builds the lookup here and hands it to the project scan as a
 * function.
 *
 * What is sent (D10): the name and version of the packages in
 * `raw.projects[].dependencies.packages`, and nothing else. Those are the
 * packages a lockfile resolved from `https://registry.npmjs.org/` that no
 * `--dependency-exclude` pattern matched; of every other package the lockfile
 * step kept no name, so there is none to send. Never the names the root
 * `package.json` lists, never a path, never an identifier of the project.
 *
 * No credential can go along: the lookup has an HTTP client of its own,
 * whose allow-list holds the fixed public sources only. The CF API of a
 * `project --cf` run is not on it, no rule on it accepts an `Authorization`
 * header, and redirects are not followed.
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

/** Requests in flight at the same time. OSV.dev has no rate limit; this keeps the load modest. */
const CONCURRENCY = 8;
/** A request is tried again at most twice, after a network error, a 429 or a 5xx answer. */
const MAX_RETRIES = 2;
/** For one advisory; a batch query has its own, longer time (`osvClient.ts`). */
const TIMEOUT_MS = 20_000;

const NOTHING: DependencyTables = { advisories: [], vulnerablePackages: [] };

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

async function lookUp(
  options: DependencyLookupOptions,
  projects: readonly RawProject[],
  recorder: CheckRecorder,
): Promise<DependencyTables> {
  const check = COLLECTOR_CHECKS.osv;
  // The user's own switch first, then what the scan itself could not read.
  if (!options.enabled) {
    recorder.skip(check, 'disabled', 'turned off with --no-dependency-check');
    return NOTHING;
  }
  const lockfiles = COLLECTOR_CHECKS.dependencies;
  if (!ran(recorder, lockfiles)) {
    recorder.skip(check, 'dependency_skipped', `needs ${lockfiles.id}, which did not run`);
    return NOTHING;
  }
  const packages = packagesToLookUp(projects);
  if (packages.length === 0) {
    // Nothing to ask about is an answer: no package of a lockfile is left unchecked by it.
    recorder.ran(check);
    return NOTHING;
  }
  const log = options.log ?? (() => {});
  // Said before the first request, so that nothing leaves the machine unannounced (SEC-10).
  log(
    `Looking up ${packages.length} public npm package(s) on ${OSV_HOST}: only their names and ` +
      'versions are sent (--no-dependency-check turns this off, --dependency-exclude holds packages back)',
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
  const tables: OsvTables | undefined = await recorder.run(check, () =>
    collectOsv(new OsvClient(http), packages, { concurrency: CONCURRENCY }),
  );
  if (tables === undefined) return NOTHING;
  log(
    `${OSV_HOST}: ${tables.vulnerablePackages.length} of ${packages.length} package(s) have a ` +
      `known vulnerability (${tables.advisories.length} advisories)`,
  );
  return tables;
}

/**
 * The lookup `src/main.ts` hands to a project scan. It never rejects for a
 * source that fails: the check of that source is recorded as skipped, with a
 * fixed reason, and nothing of its answers is returned.
 */
export function createDependencyLookup(options: DependencyLookupOptions): DependencyLookup {
  return {
    enabled: options.enabled,
    checks: [COLLECTOR_CHECKS.osv],
    run: (projects, recorder) => lookUp(options, projects, recorder),
  };
}
