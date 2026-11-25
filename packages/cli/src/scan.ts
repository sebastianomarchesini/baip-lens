import { trafficCandidates } from './analyzers/idleApps.js';
import { ANALYZERS, analyze } from './analyzers/index.js';
import { CheckRecorder, COLLECTOR_CHECKS } from './checks.js';
import { collectApps, type Scope } from './collectors/apps.js';
import { collectCurrentDroplets } from './collectors/droplets.js';
import { listSpaces, resolveOrg } from './collectors/orgs.js';
import { collectWebProcesses } from './collectors/processes.js';
import { collectRoutes } from './collectors/routes.js';
import { collectTraffic } from './collectors/traffic.js';
import { type CarriedHistory, carryHistory, checkPrevious, checkPreviousOrg } from './history.js';
import { type TokenProvider, resolveTokenProvider } from './http/auth.js';
import { ConfigError } from './http/errors.js';
import { CfClient, type CfRoot } from './http/cfClient.js';
import { type FetchLike, HttpClient } from './http/httpClient.js';
import { LogCacheClient } from './http/logCacheClient.js';
import { EgressPolicy, cfApiRule, logCacheRule, uaaRule } from './net/allowlist.js';
import type { RawApp, RawData, RawDroplet, RawProcess, RawRoute, RawTraffic } from './model/raw.js';
import { SNAPSHOT_SCHEMA_VERSION, type Snapshot, type SnapshotOptions } from './model/snapshot.js';
import { TOOL_NAME, TOOL_VERSION } from './version.js';

export interface ScanOptions {
  apiUrl: URL;
  org: string;
  space?: string;
  deep: boolean;
  probeRoutes: boolean;
  concurrency: number;
  env: NodeJS.ProcessEnv;
  /** Credentials already obtained (guided mode); otherwise resolved from env and the cf CLI. */
  tokens?: TokenProvider;
  /** Injected in tests; defaults to the global fetch. */
  fetch?: FetchLike;
  /** Injected in tests; defaults to the current time. */
  now?: () => Date;
  log?: (message: string) => void;
  /** Read Log Cache for APP_IDLE (default true; `--no-traffic-check`). */
  trafficCheck?: boolean;
  /** `--min-traffic-window` in hours (default 12, D5). */
  minTrafficWindowHours?: number;
  /** `--traffic-pages`: pages of LOG envelopes read per app (default 5). */
  trafficPages?: number;
  /** Injected in tests to skip retry backoff; defaults to a real timer. */
  sleep?: (ms: number) => Promise<void>;
  /**
   * `--previous`: an earlier snapshot of the same org, already validated
   * against the schema, whose traffic history this scan carries forward.
   */
  previous?: Snapshot;
}

function toUrl(href: string | undefined): URL | undefined {
  if (href === undefined) return undefined;
  try {
    return new URL(href);
  } catch {
    return undefined;
  }
}

/**
 * Adds the platform endpoints the CF root advertises to the allow-list, and
 * returns the OAuth token endpoint (UAA preferred, login server as fallback).
 */
export function trustRootLinks(policy: EgressPolicy, root: CfRoot): URL | undefined {
  const uaa = toUrl(root.links.uaa?.href);
  const login = toUrl(root.links.login?.href);
  const logCache = toUrl(root.links.log_cache?.href);
  for (const auth of [uaa, login]) if (auth) policy.add(uaaRule(auth));
  if (logCache) policy.add(logCacheRule(logCache));
  const base = uaa ?? login;
  return base
    ? new URL(`${base.pathname.replace(/\/+$/, '')}/oauth/token`, base.origin)
    : undefined;
}

/**
 * The log cache the CF root advertises (`links.log_cache`). Its host is never
 * derived from the API host name, as the log-cache CLI plugin does (§9.3).
 */
export function logCacheLink(root: CfRoot): URL | undefined {
  return toUrl(root.links.log_cache?.href);
}

/**
 * The traffic check of APP_IDLE: the last router request of every app that
 * has an HTTP route, from Log Cache. Off with `--no-traffic-check`; skipped
 * when the platform has no log cache. Whatever happens, the scan goes on and
 * the no-route signal stands.
 */
async function collectTrafficCheck(
  recorder: CheckRecorder,
  raw: RawData,
  logCacheUrl: URL | undefined,
  options: SnapshotOptions,
  io: { http: HttpClient; tokens: TokenProvider; log: (message: string) => void },
): Promise<RawTraffic[]> {
  const check = COLLECTOR_CHECKS.traffic;
  // The user's own switch first, then what no role can fix, then what a role can.
  if (!options.trafficCheck) {
    recorder.skip(check, 'disabled', 'turned off with --no-traffic-check');
    return [];
  }
  if (logCacheUrl === undefined) {
    recorder.skip(check, 'unavailable', 'the CF API does not advertise a log cache');
    return [];
  }
  // Which apps to read depends on the inventory, their routes and processes;
  // without them the check would "run" over nothing and look clean.
  const missing = [
    COLLECTOR_CHECKS.apps.id,
    COLLECTOR_CHECKS.routes.id,
    COLLECTOR_CHECKS.processes.id,
  ].filter((id) => recorder.list().find((c) => c.id === id)?.status !== 'ran');
  if (missing.length > 0) {
    recorder.skip(check, 'dependency_skipped', `needs ${missing.join(', ')}, which did not run`);
    return [];
  }
  const candidates = trafficCandidates(raw);
  io.log(
    `Reading the last request of ${candidates.length} app(s) with an HTTP route from Log Cache`,
  );
  const client = new LogCacheClient(io.http, logCacheUrl, io.tokens);
  const traffic = await recorder.run(check, () =>
    collectTraffic(client, candidates, { maxPages: options.trafficPages, log: io.log }),
  );
  const appGuids = new Set(raw.apps.map((app) => app.guid));
  return (traffic?.items ?? []).filter((item) => appGuids.has(item.appGuid));
}

/** The scan log line about `--previous`: what became of the previous history. */
function describeCarry(
  previousAt: string,
  carried: CarriedHistory,
  apps: { invalid: number } | undefined,
): string {
  if (apps === undefined) {
    return (
      `The app inventory could not be read, so the traffic history of the scan of ${previousAt} ` +
      `is kept as it was (${carried.kept} app(s))`
    );
  }
  const parts = [`${carried.matched} app(s) matched by GUID`];
  if (carried.kept > 0)
    parts.push(`${carried.kept} kept as they were for apps this scan did not see`);
  if (carried.dropped > 0) parts.push(`${carried.dropped} dropped for apps that are gone`);
  return `Traffic history carried forward from the scan of ${previousAt}: ${parts.join('; ')}`;
}

export async function scan(options: ScanOptions): Promise<Snapshot> {
  const log = options.log ?? (() => {});
  const scannedAt = (options.now?.() ?? new Date()).toISOString();
  // Another endpoint, a project scan or a snapshot that is not older fails
  // before anything is sent; another org fails right after the org lookup.
  if (options.previous !== undefined) {
    checkPrevious(options.previous, { apiUrl: options.apiUrl, scannedAt });
  }

  const policy = new EgressPolicy();
  policy.add(cfApiRule(options.apiUrl));
  const http = new HttpClient({
    policy,
    userAgent: `${TOOL_NAME}/${TOOL_VERSION}`,
    fetch: options.fetch,
    concurrency: options.concurrency,
    ...(options.sleep === undefined ? {} : { sleep: options.sleep }),
  });
  const cf = new CfClient(http, options.apiUrl);

  log(`Connecting to ${options.apiUrl.origin}`);
  const root = await cf.root();
  const tokenUrl = trustRootLinks(policy, root);
  const tokens =
    options.tokens ??
    (await resolveTokenProvider({ env: options.env, http, apiUrl: options.apiUrl, tokenUrl }));
  cf.setTokenProvider(tokens);
  log(`Credentials: ${tokens.source}`);

  const org = await resolveOrg(cf, options.org);
  if (options.previous !== undefined) checkPreviousOrg(options.previous, org);
  const spaces = await listSpaces(cf, org, options.space);
  // The v3 list endpoints filter by visibility instead of answering 403, so a
  // user without a space role would otherwise get an empty report that looks clean.
  if (spaces.length === 0) {
    throw new ConfigError(
      `You can see the org "${org.name}" but none of its spaces, so there is nothing to scan.\n` +
        'Ask your administrator for the Space Auditor role (read-only) on the spaces you want to scan; docs/permissions.md has the text to send.',
    );
  }
  const scope: Scope = {
    orgGuid: org.guid,
    ...(options.space === undefined ? {} : { spaceGuids: spaces.map((s) => s.guid) }),
  };
  log(
    `Scanning org "${org.name}" (${spaces.length} visible space${spaces.length === 1 ? '' : 's'})`,
  );

  const recorder = new CheckRecorder({ deep: options.deep }, log);
  const apps = await recorder.run(COLLECTOR_CHECKS.apps, () => collectApps(cf, scope));
  const droplets = await recorder.run(COLLECTOR_CHECKS.droplets, () =>
    collectCurrentDroplets(cf, scope),
  );
  // By space, not org: a route shared in from another org must still count (§9.1).
  const routes = await recorder.run(COLLECTOR_CHECKS.routes, () =>
    collectRoutes(
      cf,
      spaces.map((s) => s.guid),
    ),
  );
  const processes = await recorder.run(COLLECTOR_CHECKS.processes, () =>
    collectWebProcesses(cf, scope),
  );
  const dropped = [apps, droplets, routes, processes].reduce(
    (sum, collected) => sum + (collected?.invalid ?? 0),
    0,
  );
  if (dropped > 0) log(`Ignored ${dropped} resource(s) with an unexpected shape`);

  const appItems: RawApp[] = apps?.items ?? [];
  const appGuids = new Set(appItems.map((a) => a.guid));
  const raw: RawData = {
    orgs: [org],
    spaces,
    apps: appItems,
    droplets: (droplets?.items ?? []).filter((d: RawDroplet) => appGuids.has(d.appGuid)),
    // A destination outside the inventory (an app in a space the user cannot
    // read, reached through a shared route) is dropped and never reported.
    routes: (routes?.items ?? [])
      .map((route: RawRoute) => ({
        ...route,
        appGuids: route.appGuids.filter((guid) => appGuids.has(guid)),
      }))
      .filter((route) => route.appGuids.length > 0),
    processes: (processes?.items ?? []).filter((p: RawProcess) => appGuids.has(p.appGuid)),
    traffic: [],
    history: [],
    projects: [],
    // A CF scan reads no lockfiles, so it has no packages to look up.
    advisories: [],
    vulnerablePackages: [],
  };
  log(`Collected ${raw.apps.length} app(s)`);

  const snapshotOptions: SnapshotOptions = {
    deep: options.deep,
    // No collector probes app routes yet (planned with UI5_OUT_OF_MAINTENANCE), so the
    // snapshot records what happened, whatever --no-probe-routes said.
    probeRoutes: false,
    trafficCheck: options.trafficCheck ?? true,
    minTrafficWindowHours: options.minTrafficWindowHours ?? 12,
    trafficPages: options.trafficPages ?? 5,
    previousScannedAt: options.previous?.scannedAt ?? null,
    dependencyCheck: false,
  };
  raw.traffic = await collectTrafficCheck(recorder, raw, logCacheLink(root), snapshotOptions, {
    http,
    tokens,
    log,
  });

  // An app missing from an inventory that was not read in full may still exist.
  const inventoryComplete = apps !== undefined && apps.invalid === 0;
  const carried = carryHistory(
    raw,
    scannedAt,
    snapshotOptions.minTrafficWindowHours,
    options.previous,
    inventoryComplete,
  );
  raw.history = carried.history;
  if (options.previous !== undefined) log(describeCarry(options.previous.scannedAt, carried, apps));

  const collectorChecks = recorder.list();
  const analysis = analyze(raw, scannedAt, collectorChecks, ANALYZERS, snapshotOptions);
  return {
    schemaVersion: SNAPSHOT_SCHEMA_VERSION,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    scannedAt,
    scope: {
      apiEndpoint: options.apiUrl.href,
      orgs: [org.name],
      ...(options.space === undefined ? {} : { spaces: [options.space] }),
    },
    options: snapshotOptions,
    checks: [...collectorChecks, ...analysis.ruleChecks],
    raw,
    apps: analysis.apps,
    findings: analysis.findings,
  };
}
