import type { CheckResult } from '../model/check.js';
import type { Finding } from '../model/finding.js';
import type {
  HealthCheckType,
  RawApp,
  RawData,
  RawDroplet,
  RawHistory,
  RawProcess,
  RawTraffic,
  RouteKind,
} from '../model/raw.js';
import type { AppUsage, Confidence, UsageUnknownReason } from '../model/snapshot.js';
import type { Severity } from '../model/severity.js';
import { type Analyzer, type AnalyzerContext, ageInDays, ruleHelpUri } from './types.js';

export const RULE_ID = 'APP_IDLE';
/** A stopped app is reported after this many days without a change. */
export const STOPPED_AFTER_DAYS = 90;
/** Silent and unchanged this long: `confidence: "medium"` instead of `"low"`. */
export const UNCHANGED_AFTER_DAYS = 180;
/** Silent in this many counted scans in a row (`scan --previous`)... */
export const HIGH_CONFIDENCE_SCANS = 3;
/** ...spanning at least this many days: `confidence: "high"`. */
export const HIGH_CONFIDENCE_SPAN_DAYS = 30;
const TRAFFIC_CHECK = 'collect.traffic';
const HOUR_MS = 60 * 60 * 1000;

const ROUTE_REFERENCES = [
  'https://docs.cloudfoundry.org/devguide/deploy-apps/routes-domains.html',
  'https://docs.cloudfoundry.org/devguide/deploy-apps/manifest-attributes.html#no-route',
  'https://docs.cloudfoundry.org/devguide/deploy-apps/healthchecks.html#types',
];
const TRAFFIC_REFERENCES = [
  'https://docs.cloudfoundry.org/devguide/deploy-apps/streaming-logs.html#rtr',
  'https://github.com/cloudfoundry/log-cache-release/blob/main/src/README.md',
];
const STOPPED_REFERENCES = [
  'https://docs.cloudfoundry.org/devguide/deploy-apps/start-restart-restage.html',
  'https://cli.cloudfoundry.org/en-US/v8/delete.html',
];

const NO_ROUTE_REMEDIATION =
  'An app with a running web process but no route cannot receive HTTP requests, so it is ' +
  'probably not in use. Check with its owner whether it is still needed. If it should serve ' +
  'requests, map a route (`cf map-route`). If it is a background worker, make that explicit: ' +
  'run it as a `worker` process with `web` scaled to 0, or give `web` the `process` health ' +
  'check, so it is not mistaken for an unused app. If it is no longer needed, stop and delete ' +
  'it (`cf stop`, then `cf delete`) to free its memory quota.';

const NO_TRAFFIC_REMEDIATION =
  'No request reached the app in the router logs that Log Cache held (the window, and the ' +
  'scans in a row that saw none, are in the evidence). One window is short: Log Cache keeps ' +
  'logs in memory and caps them per app, so confirm over a longer period before acting, with ' +
  'request metrics or repeated scans (`scan --previous` with the last snapshot). If the app ' +
  'is no longer needed, stop it and delete it with its routes (`cf stop`, then ' +
  '`cf delete -r`) to free its memory quota.';

const STOPPED_REMEDIATION =
  'The app has been stopped for more than 90 days. If it is no longer needed, delete it with ' +
  'its routes (`cf delete -r`): a stopped app keeps its routes, service bindings and droplet, ' +
  'and starting it again brings back the libraries it was staged with. If it is kept on ' +
  'purpose, record why, for example in an annotation.';

/** What the rule found out about one app: the verdict, and the facts behind it. */
interface Assessment {
  usage: AppUsage;
  /** Highest desired instance count over the app's `web` processes. */
  webInstances: number;
  /** Health check types of the `web` processes that have instances, sorted. */
  healthCheckTypes: string[];
  /** The newer of the current droplet's creation and the last change of a web process. */
  lastChangeAt: string | null;
  traffic: RawTraffic | undefined;
  /** What earlier scans saw, this one included (`scan --previous`). */
  history: RawHistory | undefined;
  /** Hours from the window start to the scan time, one decimal, rounded down. */
  windowHours: number | null;
}

/** Everything the per-app verdict needs besides the app's own data. */
interface Environment {
  now: Date;
  /** The routes and processes collectors ran. */
  complete: boolean;
  /** Why traffic cannot be judged at all, or null when the traffic check ran. */
  trafficUnavailable: UsageUnknownReason | null;
  minWindowMs: number;
}

function groupBy<T>(items: readonly T[], key: (item: T) => string): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const list = groups.get(key(item));
    if (list === undefined) groups.set(key(item), [item]);
    else list.push(item);
  }
  return groups;
}

function routeKindsByApp(raw: RawData): Map<string, RouteKind[]> {
  const kinds = new Map<string, RouteKind[]>();
  for (const route of raw.routes) {
    for (const appGuid of route.appGuids) {
      const list = kinds.get(appGuid);
      if (list === undefined) kinds.set(appGuid, [route.kind]);
      else list.push(route.kind);
    }
  }
  return kinds;
}

const healthCheckLabel = (type: HealthCheckType | null): string => type ?? 'not reported';

const latest = (timestamps: readonly string[]): string | null =>
  timestamps.reduce<string | null>(
    (max, t) => (max === null || Date.parse(t) > Date.parse(max) ? t : max),
    null,
  );

/** The traffic check's outcome, as a reason to be unknown when it gave no data. */
function trafficUnavailable(checks: readonly CheckResult[]): UsageUnknownReason | null {
  const check = checks.find((c) => c.id === TRAFFIC_CHECK);
  if (check === undefined) return 'traffic_not_checked';
  if (check.status === 'ran') return null;
  return check.reasonCode === 'disabled' ? 'traffic_check_off' : 'traffic_unreadable';
}

/** Days from the first scan of the current silent run to `now`; 0 without one. */
function silentSpanDays(history: RawHistory | undefined, now: Date): number {
  const first = history?.firstScanWithoutTraffic;
  return first === null || first === undefined
    ? 0
    : (now.getTime() - Date.parse(first)) / (24 * HOUR_MS);
}

/** Enough scans in a row without a request, far enough apart, for high confidence. */
function historyIsLong(history: RawHistory | undefined, now: Date): boolean {
  return (
    history !== undefined &&
    history.scansWithoutTraffic >= HIGH_CONFIDENCE_SCANS &&
    silentSpanDays(history, now) >= HIGH_CONFIDENCE_SPAN_DAYS
  );
}

/**
 * The traffic verdict for an app with an HTTP route (docs/rules.md#app_idle):
 * a request in the window means in use; no request in a window shorter than
 * `--min-traffic-window` means unknown; otherwise idle. Confidence is high
 * after at least 3 scans in a row without a request over at least 30 days
 * (`scan --previous`), else medium when the droplet and the web processes
 * have not changed for 180 days, else low.
 */
function trafficVerdict(
  traffic: RawTraffic | undefined,
  droplet: RawDroplet | undefined,
  lastChangeAt: string | null,
  history: RawHistory | undefined,
  env: Environment,
): AppUsage {
  if (env.trafficUnavailable !== null) return { state: 'unknown', reason: env.trafficUnavailable };
  if (traffic === undefined) return { state: 'unknown', reason: 'traffic_unreadable' };
  if (traffic.lastRequestAt !== null)
    return { state: 'active', lastRequestAt: traffic.lastRequestAt };
  if (
    traffic.windowStart === null ||
    env.now.getTime() - Date.parse(traffic.windowStart) < env.minWindowMs
  ) {
    return { state: 'unknown', reason: 'window_too_short' };
  }
  if (historyIsLong(history, env.now)) {
    return { state: 'idle', signal: 'no_traffic', confidence: 'high' };
  }
  const unchanged =
    droplet !== undefined &&
    lastChangeAt !== null &&
    ageInDays(lastChangeAt, env.now) > UNCHANGED_AFTER_DAYS;
  const confidence: Confidence = unchanged ? 'medium' : 'low';
  return { state: 'idle', signal: 'no_traffic', confidence };
}

/**
 * The order of the checks is the rule (docs/rules.md#app_idle):
 * 1. a stopped app is idle once it has not changed for 90 days, worker or not:
 *    a stopped app serves nothing; without routes and processes the rule does
 *    not run, so a long-stopped app is unknown rather than "not judged";
 * 2. without routes and processes nothing is said about a started app;
 * 3. a started worker is never flagged (D7): no `web` instance, or an instanced
 *    `web` process with the `process` health check;
 * 4. no route at all: idle, high confidence;
 * 5. only TCP, internal or unclassified routes: unknown, they leave no router log (D6);
 * 6. an HTTP route: the traffic verdict.
 */
function assessApp(
  app: RawApp,
  web: readonly RawProcess[],
  routeKinds: readonly RouteKind[],
  droplet: RawDroplet | undefined,
  traffic: RawTraffic | undefined,
  history: RawHistory | undefined,
  env: Environment,
): Assessment {
  const instanced = web.filter((process) => process.instances > 0);
  const lastChangeAt = latest([
    ...(droplet === undefined ? [] : [droplet.createdAt]),
    ...web.map((process) => process.updatedAt),
  ]);
  const windowStart = traffic?.windowStart ?? null;
  const facts = {
    webInstances: Math.max(0, ...web.map((process) => process.instances)),
    healthCheckTypes: [
      ...new Set(instanced.map((p) => healthCheckLabel(p.healthCheckType))),
    ].sort(),
    lastChangeAt,
    traffic,
    history,
    windowHours:
      windowStart === null
        ? null
        : Math.floor(((env.now.getTime() - Date.parse(windowStart)) / HOUR_MS) * 10) / 10,
  };
  const verdict = (usage: AppUsage): Assessment => ({ usage, ...facts });

  if (app.state === 'STOPPED') {
    if (ageInDays(app.updatedAt, env.now) <= STOPPED_AFTER_DAYS) {
      return verdict({ state: 'not_assessed', reason: 'stopped' });
    }
    return verdict(
      env.complete
        ? { state: 'idle', signal: 'stopped', confidence: 'high' }
        : { state: 'unknown', reason: 'data_unavailable' },
    );
  }
  if (!env.complete) return verdict({ state: 'unknown', reason: 'data_unavailable' });
  if (instanced.length === 0) return verdict({ state: 'not_assessed', reason: 'no_web_instance' });
  if (instanced.some((process) => process.healthCheckType === 'process')) {
    return verdict({ state: 'not_assessed', reason: 'worker_health_check' });
  }
  if (routeKinds.length === 0) {
    return verdict({ state: 'idle', signal: 'no_route', confidence: 'high' });
  }
  if (!routeKinds.includes('http')) {
    return verdict({ state: 'unknown', reason: 'traffic_not_measurable' });
  }
  return verdict(trafficVerdict(traffic, droplet, lastChangeAt, history, env));
}

/** Pure: the same raw data, checks and options give the same verdicts, offline as well. */
export function assessApps(
  raw: RawData,
  complete: boolean,
  checks: readonly CheckResult[] = [],
  options: { now: Date; minTrafficWindowHours: number } = {
    now: new Date(0),
    minTrafficWindowHours: 12,
  },
): Map<string, Assessment> {
  const env: Environment = {
    now: options.now,
    complete,
    trafficUnavailable: trafficUnavailable(checks),
    minWindowMs: options.minTrafficWindowHours * HOUR_MS,
  };
  const web = groupBy(raw.processes, (process) => process.appGuid);
  const routes = routeKindsByApp(raw);
  const droplets = new Map(raw.droplets.map((d) => [d.appGuid, d]));
  const traffic = new Map(raw.traffic.map((t) => [t.appGuid, t]));
  const history = new Map(raw.history.map((h) => [h.appGuid, h]));
  return new Map(
    raw.apps.map((app) => [
      app.guid,
      assessApp(
        app,
        web.get(app.guid) ?? [],
        routes.get(app.guid) ?? [],
        droplets.get(app.guid),
        traffic.get(app.guid),
        history.get(app.guid),
        env,
      ),
    ]),
  );
}

/**
 * The apps whose traffic is worth reading: started, a web instance, not a
 * worker, and at least one HTTP route. The scan reads Log Cache for these only.
 */
export function trafficCandidates(raw: RawData): string[] {
  return [...assessApps(raw, true)]
    .filter(([, a]) => a.usage.state === 'unknown' && a.usage.reason === 'traffic_not_checked')
    .map(([guid]) => guid);
}

const count = (n: number, unit: string): string => `${n} ${unit}${n === 1 ? '' : 's'}`;

/** A window of logs, never rounded up: "30 minutes", "41 hours", "2.9 days". */
function describeWindow(hours: number): string {
  if (hours < 1) return count(Math.floor(hours * 60), 'minute');
  if (hours < 48) return count(Math.floor(hours), 'hour');
  return `${(Math.floor((hours / 24) * 10) / 10).toFixed(1)} days`;
}

/** A span of scans, never rounded up: "42 days", "36 hours". */
const describeSpan = (days: number): string =>
  days < 2 ? describeWindow(days * 24) : count(Math.floor(days), 'day');

/**
 * The run of silent scans this finding stands on. This scan always counts
 * when it reports `no_traffic` (D8), so without an entry that records a run,
 * as in a snapshot written before the history existed, the run is this scan.
 */
function silentRun(history: RawHistory | undefined, now: Date): RawHistory | undefined {
  if (history === undefined) return undefined;
  if (history.scansWithoutTraffic >= 1 && history.firstScanWithoutTraffic !== null) return history;
  return { ...history, scansWithoutTraffic: 1, firstScanWithoutTraffic: now.toISOString() };
}

function findingFor(context: AnalyzerContext, app: RawApp, assessment: Assessment): Finding[] {
  const ref = context.appRef(app.guid);
  if (ref === undefined || assessment.usage.state !== 'idle') return [];
  const { signal, confidence } = assessment.usage;
  const base = { id: RULE_ID, app: ref };
  switch (signal) {
    case 'no_route':
      return [
        {
          ...base,
          severity: 'low',
          title: 'Started, but no route is mapped',
          evidence: {
            signal,
            confidence,
            appState: app.state,
            webInstances: assessment.webInstances,
            healthCheckTypes: assessment.healthCheckTypes,
            mappedRoutes: 0,
          },
          remediation: NO_ROUTE_REMEDIATION,
          references: ROUTE_REFERENCES,
        },
      ];
    case 'no_traffic': {
      const hours = assessment.windowHours ?? 0;
      // The title is worded from the exact window; the evidence keeps one decimal.
      const windowStart = assessment.traffic?.windowStart ?? null;
      const exactHours =
        windowStart === null ? 0 : (context.now.getTime() - Date.parse(windowStart)) / HOUR_MS;
      // High confidence stays low severity, like a missing route (D9).
      const severity: Severity = confidence === 'low' ? 'info' : 'low';
      const unchangedDays =
        assessment.lastChangeAt === null ? null : ageInDays(assessment.lastChangeAt, context.now);
      const history = silentRun(assessment.history, context.now);
      const scans = history?.scansWithoutTraffic ?? 1;
      const spanDays = silentSpanDays(history, context.now);
      // The span of scans is named once it is longer than this scan's own
      // window; scans close together keep the window, which says more.
      const title =
        scans >= 2 && spanDays * 24 > exactHours
          ? `No requests seen across ${scans} scans over ${describeSpan(spanDays)}`
          : `No request in ${describeWindow(exactHours)} of router logs`;
      return [
        {
          ...base,
          severity,
          title,
          evidence: {
            signal,
            confidence,
            appState: app.state,
            lastRequestAt: null,
            windowStart,
            windowHours: hours,
            minWindowHours: context.options.minTrafficWindowHours,
            envelopesExamined: assessment.traffic?.envelopesExamined ?? 0,
            lastChangeAt: assessment.lastChangeAt,
            unchangedDays,
            unchangedThresholdDays: UNCHANGED_AFTER_DAYS,
            scansWithoutTraffic: scans,
            firstScanWithoutTraffic: history?.firstScanWithoutTraffic ?? context.now.toISOString(),
            silentSpanDays: Math.floor(spanDays * 10) / 10,
            lastRequestEverSeen: history?.lastRequestEverSeen ?? null,
            highConfidenceScans: HIGH_CONFIDENCE_SCANS,
            highConfidenceSpanDays: HIGH_CONFIDENCE_SPAN_DAYS,
          },
          remediation: NO_TRAFFIC_REMEDIATION,
          references: TRAFFIC_REFERENCES,
        },
      ];
    }
    case 'stopped': {
      const stoppedDays = ageInDays(app.updatedAt, context.now);
      return [
        {
          ...base,
          severity: 'low',
          title: `Stopped for ${stoppedDays} days`,
          evidence: {
            signal,
            confidence,
            appState: app.state,
            updatedAt: app.updatedAt,
            stoppedDays,
            thresholdDays: STOPPED_AFTER_DAYS,
          },
          remediation: STOPPED_REMEDIATION,
          references: STOPPED_REFERENCES,
        },
      ];
    }
  }
}

function assessContext(context: AnalyzerContext, complete: boolean): Map<string, Assessment> {
  return assessApps(context.raw, complete, context.checks, {
    now: context.now,
    minTrafficWindowHours: context.options.minTrafficWindowHours,
  });
}

/**
 * APP_IDLE: an app that nothing seems to use. Three signals: started with no
 * route, no router access log in the window Log Cache held, or stopped for
 * more than 90 days. A started worker is never flagged (D7). See docs/rules.md.
 */
export const idleApps: Analyzer = {
  rule: {
    id: RULE_ID,
    title: 'App looks unused',
    description:
      'Nothing shows that the app is used: it runs a web process but no route is mapped to it, ' +
      'or no request reached it in the router logs that Log Cache held, or it has been stopped ' +
      'for more than 90 days. With `scan --previous`, scans in a row that saw no request raise ' +
      'the confidence to high after 3 scans over 30 days. Workers are never flagged for missing ' +
      'routes or traffic, and a stopped worker only after 90 days, like any app. An unused app ' +
      'still takes memory quota and keeps old libraries running.',
    roles: ['SpaceAuditor'],
    owasp: ['A02:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.apps', 'collect.routes', 'collect.processes'],
  analyze(context) {
    const assessments = assessContext(context, true);
    return context.raw.apps.flatMap((app) => {
      const assessment = assessments.get(app.guid);
      return assessment === undefined ? [] : findingFor(context, app, assessment);
    });
  },
  usage(context, complete) {
    return new Map(
      [...assessContext(context, complete)].map(([guid, assessment]) => [guid, assessment.usage]),
    );
  },
};
