import { describe, expect, it } from 'vitest';
import { analyze } from '../../src/analyzers/index.js';
import { assessApps, idleApps, trafficCandidates } from '../../src/analyzers/idleApps.js';
import type { CheckResult } from '../../src/model/check.js';
import type {
  HealthCheckType,
  RawApp,
  RawData,
  RawDroplet,
  RawHistory,
  RawProcess,
  RawRoute,
  RawTraffic,
  RouteKind,
} from '../../src/model/raw.js';
import { AppInventoryItemSchema, DEFAULT_SNAPSHOT_OPTIONS } from '../../src/model/snapshot.js';

const NOW = '2026-09-29T00:00:00.000Z';
const hoursAgo = (hours: number) => new Date(Date.parse(NOW) - hours * 3_600_000).toISOString();
const daysAgo = (days: number) => hoursAgo(days * 24);

function app(
  guid: string,
  state: RawApp['state'] = 'STARTED',
  updatedAt = '2026-09-01T00:00:00Z',
): RawApp {
  return {
    guid,
    name: guid,
    spaceGuid: 's1',
    state,
    createdAt: '2025-01-01T00:00:00Z',
    updatedAt,
    lifecycleType: 'buildpack',
    buildpacks: ['nodejs_buildpack'],
    stack: 'cflinuxfs4',
  };
}

let processCount = 0;
function web(
  appGuid: string,
  instances: number,
  healthCheckType: HealthCheckType | null = 'port',
  updatedAt = '2026-09-01T00:00:00Z',
): RawProcess {
  processCount += 1;
  return {
    guid: `p-${processCount}`,
    appGuid,
    type: 'web',
    instances,
    healthCheckType,
    updatedAt,
  };
}

function droplet(appGuid: string, createdAt: string): RawDroplet {
  return {
    guid: `d-${appGuid}`,
    appGuid,
    state: 'STAGED',
    createdAt,
    updatedAt: createdAt,
    lifecycleType: 'buildpack',
    stack: 'cflinuxfs4',
    buildpacks: [],
    image: null,
  };
}

const traffic = (appGuid: string, values: Partial<RawTraffic> = {}): RawTraffic => ({
  appGuid,
  lastRequestAt: null,
  windowStart: hoursAgo(48),
  envelopesExamined: 120,
  ...values,
});

let routeCount = 0;
function route(kind: RouteKind, ...appGuids: string[]): RawRoute {
  routeCount += 1;
  return { guid: `r-${routeCount}`, spaceGuid: 's1', kind, appGuids };
}

function raw(
  apps: RawApp[],
  processes: RawProcess[],
  routes: RawRoute[] = [],
  traffic: RawTraffic[] = [],
  droplets: RawDroplet[] = [],
): RawData {
  return {
    orgs: [{ guid: 'o1', name: 'org' }],
    spaces: [{ guid: 's1', name: 'space', orgGuid: 'o1' }],
    apps,
    droplets,
    routes,
    processes,
    traffic,
    history: [],
    projects: [],
    advisories: [],
    vulnerablePackages: [],
  };
}

const check = (id: string, status: CheckResult['status'] = 'ran'): CheckResult => ({
  id,
  title: id,
  roles: ['SpaceAuditor'],
  status,
});
const COLLECTORS = ['collect.apps', 'collect.routes', 'collect.processes'].map((id) => check(id));

const WITH_TRAFFIC = [...COLLECTORS, check('collect.traffic')];

function run(data: RawData, checks: CheckResult[] = COLLECTORS, minTrafficWindowHours = 12) {
  return analyze(data, NOW, checks, [idleApps], {
    ...DEFAULT_SNAPSHOT_OPTIONS,
    trafficCheck: true,
    minTrafficWindowHours,
  });
}

const usageOf = (result: ReturnType<typeof run>, guid: string) =>
  result.apps.find((a) => a.guid === guid)?.usage;

describe('APP_IDLE: no route', () => {
  it('flags a started app that has a web instance and no route', () => {
    const result = run(raw([app('lonely')], [web('lonely', 1)]));
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      id: 'APP_IDLE',
      severity: 'low',
      title: 'Started, but no route is mapped',
      app: { guid: 'lonely', name: 'lonely', space: 'space', org: 'org' },
      evidence: {
        signal: 'no_route',
        confidence: 'high',
        appState: 'STARTED',
        webInstances: 1,
        healthCheckTypes: ['port'],
        mappedRoutes: 0,
      },
    });
    expect(result.findings[0]?.remediation).toContain('cf map-route');
    expect(result.findings[0]?.references).toContain(
      'https://docs.cloudfoundry.org/devguide/deploy-apps/manifest-attributes.html#no-route',
    );
    expect(usageOf(result, 'lonely')).toEqual({
      state: 'idle',
      signal: 'no_route',
      confidence: 'high',
    });
  });

  it('flags an http or unreported health check, which still listens for requests', () => {
    const result = run(
      raw([app('http'), app('unreported')], [web('http', 2, 'http'), web('unreported', 1, null)]),
    );
    expect(result.findings.map((f) => [f.app.name, f.evidence.healthCheckTypes])).toEqual([
      ['http', ['http']],
      ['unreported', ['not reported']],
    ]);
  });

  it('counts any destination as a route, whatever process type it targets', () => {
    const result = run(raw([app('routed')], [web('routed', 1)], [route('http', 'routed')]));
    expect(result.findings).toEqual([]);
  });
});

describe('APP_IDLE: never a worker', () => {
  it('does not flag an app without a web process or with web scaled to 0', () => {
    const result = run(raw([app('job'), app('scaled-down')], [web('scaled-down', 0)]));
    expect(result.findings).toEqual([]);
    expect(usageOf(result, 'job')).toEqual({ state: 'not_assessed', reason: 'no_web_instance' });
    expect(usageOf(result, 'scaled-down')).toEqual({
      state: 'not_assessed',
      reason: 'no_web_instance',
    });
  });

  it('does not flag a web process with the process health check, which CF documents for workers', () => {
    const result = run(raw([app('queue-consumer')], [web('queue-consumer', 3, 'process')]));
    expect(result.findings).toEqual([]);
    expect(usageOf(result, 'queue-consumer')).toEqual({
      state: 'not_assessed',
      reason: 'worker_health_check',
    });
  });

  it('looks at every web process of a rolling deployment', () => {
    const result = run(
      raw(
        [app('rolling'), app('switching')],
        [
          web('rolling', 0),
          web('rolling', 2),
          // A deployment that moves the app to the process health check is a worker.
          web('switching', 1, 'port'),
          web('switching', 1, 'process'),
        ],
      ),
    );
    expect(result.findings.map((f) => [f.app.name, f.evidence.webInstances])).toEqual([
      ['rolling', 2],
    ]);
    expect(usageOf(result, 'switching')).toEqual({
      state: 'not_assessed',
      reason: 'worker_health_check',
    });
  });

  it('ignores the health check of a web process that has no instance', () => {
    const result = run(raw([app('mixed')], [web('mixed', 0, 'process'), web('mixed', 1, 'port')]));
    expect(result.findings.map((f) => f.evidence.healthCheckTypes)).toEqual([['port']]);
  });
});

describe('APP_IDLE: what it does not judge', () => {
  it('does not judge a stopped app, with or without a route', () => {
    const result = run(
      raw(
        [app('off', 'STOPPED'), app('off-routed', 'STOPPED')],
        [web('off', 1), web('off-routed', 1)],
        [route('http', 'off-routed')],
      ),
    );
    expect(result.findings).toEqual([]);
    expect(usageOf(result, 'off')).toEqual({ state: 'not_assessed', reason: 'stopped' });
    expect(usageOf(result, 'off-routed')).toEqual({ state: 'not_assessed', reason: 'stopped' });
  });

  it('says unknown, not "no finding", for an app with an HTTP route', () => {
    const result = run(raw([app('busy')], [web('busy', 2)], [route('http', 'busy')]));
    expect(result.findings).toEqual([]);
    expect(usageOf(result, 'busy')).toEqual({ state: 'unknown', reason: 'traffic_not_checked' });
  });

  it('says traffic is not measurable when no route is an HTTP route (D6)', () => {
    const result = run(
      raw(
        [app('tcp'), app('internal'), app('unclassified'), app('both')],
        ['tcp', 'internal', 'unclassified', 'both'].map((guid) => web(guid, 1)),
        [
          route('tcp', 'tcp', 'both'),
          route('internal', 'internal'),
          route('unknown', 'unclassified'),
          route('http', 'both'),
        ],
      ),
    );
    expect(result.findings).toEqual([]);
    for (const guid of ['tcp', 'internal', 'unclassified']) {
      expect(usageOf(result, guid)).toEqual({ state: 'unknown', reason: 'traffic_not_measurable' });
    }
    // One HTTP route is enough to be measurable later.
    expect(usageOf(result, 'both')).toEqual({ state: 'unknown', reason: 'traffic_not_checked' });
  });
});

describe('APP_IDLE: missing data', () => {
  it('says unknown when the routes were not collected, and records the rule as skipped', () => {
    const checks = [
      check('collect.apps'),
      check('collect.routes', 'skipped'),
      check('collect.processes'),
    ];
    const result = run(raw([app('lonely'), app('off', 'STOPPED')], [web('lonely', 1)]), checks);
    expect(result.findings).toEqual([]);
    expect(result.ruleChecks).toEqual([
      expect.objectContaining({
        id: 'rule.APP_IDLE',
        status: 'skipped',
        reasonCode: 'dependency_skipped',
        reason: 'needs collect.routes, which did not run',
      }),
    ]);
    // An app with no route data must never look idle.
    expect(usageOf(result, 'lonely')).toEqual({ state: 'unknown', reason: 'data_unavailable' });
    expect(usageOf(result, 'off')).toEqual({ state: 'not_assessed', reason: 'stopped' });
  });

  it('says unknown when the processes were not collected', () => {
    const checks = [
      check('collect.apps'),
      check('collect.routes'),
      check('collect.processes', 'skipped'),
    ];
    // Without processes, an app with no route could be a worker: never idle.
    const result = run(raw([app('lonely'), app('off', 'STOPPED')], []), checks);
    expect(result.findings).toEqual([]);
    expect(result.ruleChecks).toEqual([
      expect.objectContaining({
        id: 'rule.APP_IDLE',
        status: 'skipped',
        reason: 'needs collect.processes, which did not run',
      }),
    ]);
    expect(usageOf(result, 'lonely')).toEqual({ state: 'unknown', reason: 'data_unavailable' });
    expect(usageOf(result, 'off')).toEqual({ state: 'not_assessed', reason: 'stopped' });
  });

  it('leaves usage empty when the rule is not part of the scan (an older snapshot)', () => {
    const checks = [check('collect.apps'), check('collect.droplets')];
    const result = run(raw([app('lonely')], [web('lonely', 1)]), checks);
    expect(result.ruleChecks).toEqual([]);
    expect(usageOf(result, 'lonely')).toBeNull();
  });
});

describe('APP_IDLE: consistency', () => {
  const data = raw(
    [app('a'), app('b'), app('c', 'STOPPED'), app('d'), app('e')],
    [web('a', 1), web('b', 1), web('c', 1), web('d', 0), web('e', 1, 'process')],
    [route('http', 'b')],
  );

  it('has exactly one finding for each app the inventory calls idle, and no other', () => {
    const result = run(data);
    const idle = result.apps.filter((a) => a.usage?.state === 'idle').map((a) => a.guid);
    expect(result.findings.map((f) => f.app.guid)).toEqual(idle);
    expect(idle).toEqual(['a']);
  });

  it('writes inventory items that pass the snapshot schema', () => {
    for (const item of run(data).apps) {
      expect(AppInventoryItemSchema.safeParse(item).success, item.guid).toBe(true);
    }
  });

  it('ignores processes and routes of apps outside the inventory', () => {
    const ghost = raw([app('a')], [web('a', 1), web('ghost', 1)], [route('http', 'ghost')]);
    const result = run(ghost);
    // Only inventory apps are judged, and a route to another app does not reach 'a'.
    expect([...assessApps(ghost, true).keys()]).toEqual(['a']);
    expect(result.findings.map((f) => f.app.guid)).toEqual(['a']);
    expect(usageOf(result, 'a')).toEqual({ state: 'idle', signal: 'no_route', confidence: 'high' });
  });

  it('is deterministic: same input, same output', () => {
    expect(run(data)).toEqual(run(data));
  });
});

describe('APP_IDLE: traffic', () => {
  /** A started web app with an HTTP route, last changed `changedDaysAgo` days ago. */
  const routed = (guid: string, changedDaysAgo: number, withDroplet = true) =>
    raw(
      [app(guid)],
      [web(guid, 2, 'port', daysAgo(changedDaysAgo))],
      [route('http', guid)],
      [],
      withDroplet ? [droplet(guid, daysAgo(changedDaysAgo))] : [],
    );
  const withTraffic = (data: RawData, ...entries: RawTraffic[]): RawData => ({
    ...data,
    traffic: entries,
  });

  it('calls an app with a request in the window in use, with no finding', () => {
    const data = withTraffic(routed('busy', 400), traffic('busy', { lastRequestAt: hoursAgo(1) }));
    const result = run(data, WITH_TRAFFIC);
    expect(result.findings).toEqual([]);
    expect(usageOf(result, 'busy')).toEqual({ state: 'active', lastRequestAt: hoursAgo(1) });
  });

  it('flags silence as low, medium confidence, when droplet and process are unchanged for 180 days', () => {
    const data = withTraffic(routed('quiet', 300), traffic('quiet'));
    const result = run(data, WITH_TRAFFIC);
    expect(usageOf(result, 'quiet')).toEqual({
      state: 'idle',
      signal: 'no_traffic',
      confidence: 'medium',
    });
    expect(result.findings).toEqual([
      expect.objectContaining({
        id: 'APP_IDLE',
        severity: 'low',
        title: 'No request in 2.0 days of router logs',
        evidence: {
          signal: 'no_traffic',
          confidence: 'medium',
          appState: 'STARTED',
          lastRequestAt: null,
          windowStart: hoursAgo(48),
          windowHours: 48,
          minWindowHours: 12,
          envelopesExamined: 120,
          lastChangeAt: daysAgo(300),
          unchangedDays: 300,
          unchangedThresholdDays: 180,
          // One scan and no history: the run of silent scans is this scan alone.
          scansWithoutTraffic: 1,
          firstScanWithoutTraffic: NOW,
          silentSpanDays: 0,
          lastRequestEverSeen: null,
          highConfidenceScans: 3,
          highConfidenceSpanDays: 30,
        },
      }),
    ]);
    expect(result.findings[0]?.references).toContain(
      'https://docs.cloudfoundry.org/devguide/deploy-apps/streaming-logs.html#rtr',
    );
  });

  it('flags silence as info, low confidence, when the app changed within 180 days', () => {
    const result = run(withTraffic(routed('new', 30), traffic('new')), WITH_TRAFFIC);
    expect(usageOf(result, 'new')).toEqual({
      state: 'idle',
      signal: 'no_traffic',
      confidence: 'low',
    });
    expect(result.findings.map((f) => [f.severity, f.title])).toEqual([
      ['info', 'No request in 2.0 days of router logs'],
    ]);
  });

  it('takes the newest change of droplet and web processes, so a recent scale or deploy lowers confidence', () => {
    const changed = (guid: string, dropletDays: number, processDays: number) =>
      withTraffic(
        raw(
          [app(guid)],
          [web(guid, 2, 'port', daysAgo(processDays))],
          [route('http', guid)],
          [],
          [droplet(guid, daysAgo(dropletDays))],
        ),
        traffic(guid),
      );
    // An old droplet on a web process scaled 30 days ago, and a fresh droplet on an old process.
    for (const [guid, data] of [
      ['scaled', changed('scaled', 400, 30)],
      ['deployed', changed('deployed', 30, 400)],
    ] as const) {
      const result = run(data, WITH_TRAFFIC);
      expect(usageOf(result, guid), guid).toMatchObject({ state: 'idle', confidence: 'low' });
      expect(result.findings[0]?.evidence, guid).toMatchObject({
        lastChangeAt: daysAgo(30),
        unchangedDays: 30,
      });
    }
  });

  it('keeps low confidence when no droplet shows the app unchanged', () => {
    const result = run(
      withTraffic(routed('nodroplet', 400, false), traffic('nodroplet')),
      WITH_TRAFFIC,
    );
    expect(usageOf(result, 'nodroplet')).toMatchObject({ confidence: 'low' });
  });

  it('says unknown, not idle, for a window shorter than --min-traffic-window, and names it', () => {
    const data = withTraffic(routed('short', 400), traffic('short', { windowStart: hoursAgo(6) }));
    expect(usageOf(run(data, WITH_TRAFFIC), 'short')).toEqual({
      state: 'unknown',
      reason: 'window_too_short',
    });
    expect(run(data, WITH_TRAFFIC).findings).toEqual([]);
    // With a shorter minimum the same six hours are enough.
    expect(run(data, WITH_TRAFFIC, 4).findings.map((f) => f.title)).toEqual([
      'No request in 6 hours of router logs',
    ]);
  });

  it('accepts a window exactly as long as the minimum', () => {
    const data = withTraffic(routed('edge', 400), traffic('edge', { windowStart: hoursAgo(12) }));
    expect(usageOf(run(data, WITH_TRAFFIC), 'edge')).toMatchObject({ state: 'idle' });
  });

  it('says unknown when Log Cache held nothing for the app', () => {
    const data = withTraffic(
      routed('empty', 400),
      traffic('empty', { windowStart: null, envelopesExamined: 0 }),
    );
    expect(usageOf(run(data, WITH_TRAFFIC), 'empty')).toEqual({
      state: 'unknown',
      reason: 'window_too_short',
    });
  });

  it('says why traffic is unknown when the check gave no data for the app', () => {
    const data = routed('x', 400);
    const skipped = (reasonCode: CheckResult['reasonCode']) => [
      ...COLLECTORS,
      { ...check('collect.traffic', 'skipped'), reasonCode },
    ];
    const reason = (checks: CheckResult[]) => usageOf(run(data, checks), 'x');
    expect(reason(skipped('insufficient_role'))).toEqual({
      state: 'unknown',
      reason: 'traffic_unreadable',
    });
    expect(reason(skipped('unavailable'))).toEqual({
      state: 'unknown',
      reason: 'traffic_unreadable',
    });
    expect(reason(skipped('disabled'))).toEqual({ state: 'unknown', reason: 'traffic_check_off' });
    // Ran, but this app's read failed: no entry for it.
    expect(reason(WITH_TRAFFIC)).toEqual({ state: 'unknown', reason: 'traffic_unreadable' });
    // A snapshot from before the traffic check.
    expect(reason(COLLECTORS)).toEqual({ state: 'unknown', reason: 'traffic_not_checked' });
  });

  it('reads Log Cache only for started non-workers with an HTTP route', () => {
    const data = raw(
      [app('http'), app('tcp'), app('none'), app('worker'), app('off', 'STOPPED')],
      [web('http', 1), web('tcp', 1), web('none', 1), web('worker', 1, 'process'), web('off', 1)],
      [route('http', 'http', 'worker', 'off'), route('tcp', 'tcp')],
    );
    expect(trafficCandidates(data)).toEqual(['http']);
  });
});

describe('APP_IDLE: stopped apps', () => {
  it('flags an app stopped for more than 90 days', () => {
    const result = run(raw([app('old', 'STOPPED', daysAgo(120))], [web('old', 1)]));
    expect(usageOf(result, 'old')).toEqual({
      state: 'idle',
      signal: 'stopped',
      confidence: 'high',
    });
    expect(result.findings).toEqual([
      expect.objectContaining({
        severity: 'low',
        title: 'Stopped for 120 days',
        evidence: {
          signal: 'stopped',
          confidence: 'high',
          appState: 'STOPPED',
          updatedAt: daysAgo(120),
          stoppedDays: 120,
          thresholdDays: 90,
        },
      }),
    ]);
    expect(result.findings[0]?.remediation).toContain('cf delete -r');
  });

  it('flags a long-stopped worker as stopped too: a stopped app serves nothing', () => {
    const result = run(
      raw(
        [app('old-worker', 'STOPPED', daysAgo(200)), app('old-job', 'STOPPED', daysAgo(200))],
        [web('old-worker', 1, 'process')],
      ),
    );
    expect(result.findings.map((f) => [f.app.guid, f.evidence.signal]).sort()).toEqual([
      ['old-job', 'stopped'],
      ['old-worker', 'stopped'],
    ]);
  });

  it('says unknown, not "not judged", for a long-stopped app when the rule could not run', () => {
    const checks = [
      check('collect.apps'),
      check('collect.routes', 'skipped'),
      check('collect.processes'),
    ];
    const result = run(
      raw([app('old', 'STOPPED', daysAgo(400)), app('recent', 'STOPPED', daysAgo(10))], []),
      checks,
    );
    expect(result.findings).toEqual([]);
    expect(usageOf(result, 'old')).toEqual({ state: 'unknown', reason: 'data_unavailable' });
    expect(usageOf(result, 'recent')).toEqual({ state: 'not_assessed', reason: 'stopped' });
  });

  it('does not flag an app stopped for 90 days or less', () => {
    const result = run(raw([app('recent', 'STOPPED', daysAgo(90))], [web('recent', 1)]));
    expect(result.findings).toEqual([]);
    expect(usageOf(result, 'recent')).toEqual({ state: 'not_assessed', reason: 'stopped' });
  });
});

describe('APP_IDLE: history across scans (scan --previous)', () => {
  /** A silent app with an HTTP route, changed `changedDaysAgo` days ago, and its history. */
  const silentWith = (history: RawHistory | undefined, changedDaysAgo = 400): RawData => ({
    ...raw(
      [app('h')],
      [web('h', 1, 'port', daysAgo(changedDaysAgo))],
      [route('http', 'h')],
      [traffic('h')],
      [droplet('h', daysAgo(changedDaysAgo))],
    ),
    history: history === undefined ? [] : [history],
  });
  const runOf = (
    scans: number,
    firstDaysAgo: number,
    lastRequestEverSeen: string | null = null,
  ) => ({
    appGuid: 'h',
    spaceGuid: 's1',
    lastRequestEverSeen,
    firstScanWithoutTraffic: daysAgo(firstDaysAgo),
    scansWithoutTraffic: scans,
  });
  /** The same, with this scan's window `hours` long. */
  const windowOf = (data: RawData, hours: number): RawData => ({
    ...data,
    traffic: [traffic('h', { windowStart: hoursAgo(hours) })],
  });
  const titleOf = (data: RawData, minWindowHours = 12) =>
    run(data, WITH_TRAFFIC, minWindowHours).findings[0]?.title;

  it('states the span of the scans that saw no request', () => {
    const result = run(silentWith(runOf(6, 42, daysAgo(50))), WITH_TRAFFIC);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      severity: 'low',
      title: 'No requests seen across 6 scans over 42 days',
      evidence: {
        confidence: 'high',
        windowHours: 48,
        scansWithoutTraffic: 6,
        firstScanWithoutTraffic: daysAgo(42),
        silentSpanDays: 42,
        lastRequestEverSeen: daysAgo(50),
        highConfidenceScans: 3,
        highConfidenceSpanDays: 30,
      },
    });
    expect(usageOf(result, 'h')).toEqual({
      state: 'idle',
      signal: 'no_traffic',
      confidence: 'high',
    });
  });

  it('raises confidence to high only after 3 scans over at least 30 days', () => {
    const confidence = (scans: number, days: number) =>
      usageOf(run(silentWith(runOf(scans, days)), WITH_TRAFFIC), 'h');
    expect(confidence(3, 30)).toMatchObject({ confidence: 'high' });
    // Short of either threshold, the single-scan rule applies: unchanged 400 days, so medium.
    expect(confidence(3, 29.9)).toMatchObject({ confidence: 'medium' });
    expect(confidence(2, 60)).toMatchObject({ confidence: 'medium' });
    expect(confidence(10, 20)).toMatchObject({ confidence: 'medium' });
  });

  it('keeps high confidence at low severity, also for an app that changed recently (D9)', () => {
    const verdict = (history: RawHistory | undefined) =>
      run(silentWith(history, 10), WITH_TRAFFIC).findings.map((f) => [
        f.severity,
        f.evidence.confidence,
      ]);
    expect(verdict(runOf(4, 35))).toEqual([['low', 'high']]);
    // The same app without history: changed 10 days ago, so info and low confidence.
    expect(verdict(undefined)).toEqual([['info', 'low']]);
  });

  it('names a span shorter than two days in hours, never rounded up', () => {
    const since = (hours: number) =>
      windowOf(silentWith({ ...runOf(2, 0), firstScanWithoutTraffic: hoursAgo(hours) }), 20);
    expect(titleOf(since(36.9))).toBe('No requests seen across 2 scans over 36 hours');
    expect(titleOf(since(47.9))).toBe('No requests seen across 2 scans over 47 hours');
    expect(titleOf(since(48))).toBe('No requests seen across 2 scans over 2 days');
  });

  it('names a span of days in whole days, never rounded up', () => {
    const result = run(silentWith(runOf(6, 41.96)), WITH_TRAFFIC);
    expect(result.findings[0]).toMatchObject({
      title: 'No requests seen across 6 scans over 41 days',
      evidence: { silentSpanDays: 41.9 },
    });
  });

  it('keeps the window in the title while the scans span less than one window', () => {
    // Two scans ten minutes apart, each with 48 hours of logs: "over 0 hours" would say less.
    const close = { ...runOf(2, 0), firstScanWithoutTraffic: hoursAgo(1 / 6) };
    const result = run(silentWith(close), WITH_TRAFFIC);
    expect(result.findings[0]).toMatchObject({
      title: 'No request in 2.0 days of router logs',
      evidence: { scansWithoutTraffic: 2, windowHours: 48 },
    });
  });

  it('never rounds the window up, and counts hours and minutes right', () => {
    expect(titleOf(windowOf(silentWith(undefined), 71.5))).toBe(
      'No request in 2.9 days of router logs',
    );
    expect(run(windowOf(silentWith(undefined), 47.96), WITH_TRAFFIC).findings[0]).toMatchObject({
      title: 'No request in 47 hours of router logs',
      evidence: { windowHours: 47.9 },
    });
    expect(titleOf(windowOf(silentWith(undefined), 1.5), 1)).toBe(
      'No request in 1 hour of router logs',
    );
    expect(titleOf(windowOf(silentWith(undefined), 0.75), 0.5)).toBe(
      'No request in 45 minutes of router logs',
    );
  });

  it('treats an entry that records no run as this scan alone, as for an older snapshot', () => {
    const ended = { ...runOf(0, 0, daysAgo(9)), firstScanWithoutTraffic: null };
    for (const history of [undefined, ended]) {
      expect(run(silentWith(history), WITH_TRAFFIC).findings[0]?.evidence).toMatchObject({
        scansWithoutTraffic: 1,
        firstScanWithoutTraffic: NOW,
        silentSpanDays: 0,
        lastRequestEverSeen: history === undefined ? null : daysAgo(9),
      });
    }
  });

  it('never turns a window shorter than the minimum into a finding, whatever the history (D8)', () => {
    const data = {
      ...silentWith(runOf(9, 90)),
      traffic: [traffic('h', { windowStart: hoursAgo(4) })],
    };
    expect(usageOf(run(data, WITH_TRAFFIC), 'h')).toEqual({
      state: 'unknown',
      reason: 'window_too_short',
    });
    expect(run(data, WITH_TRAFFIC).findings).toEqual([]);
  });

  it('calls an app with a request in this scan in use, whatever the history', () => {
    const data = {
      ...silentWith(runOf(9, 90)),
      traffic: [traffic('h', { lastRequestAt: hoursAgo(2) })],
    };
    expect(usageOf(run(data, WITH_TRAFFIC), 'h')).toEqual({
      state: 'active',
      lastRequestAt: hoursAgo(2),
    });
  });
});
