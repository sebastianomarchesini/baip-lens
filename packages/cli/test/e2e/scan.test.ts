import { describe, expect, it } from 'vitest';
import { ConfigError } from '../../src/http/errors.js';
import type { RawHistory } from '../../src/model/raw.js';
import { type Snapshot, SnapshotSchema } from '../../src/model/snapshot.js';
import { scan } from '../../src/scan.js';
import { ACME, ACME_TRAFFIC_APPS, acmeFetch, acmePrevious } from '../support/acme.js';
import { noSleep, routeKey } from '../support/fakeFetch.js';

interface Overrides {
  deep?: boolean;
  trafficCheck?: boolean;
  minTrafficWindowHours?: number;
  previous?: Snapshot;
  log?: (message: string) => void;
  space?: string;
  now?: Date;
}

function scanAcme(fake = acmeFetch(), overrides: Overrides = {}) {
  return scan({
    apiUrl: ACME.api,
    org: ACME.org,
    ...(overrides.space === undefined ? {} : { space: overrides.space }),
    deep: overrides.deep ?? false,
    probeRoutes: true,
    concurrency: 5,
    env: { BAIP_LENS_ACCESS_TOKEN: ACME.token },
    fetch: fake.fetch,
    now: () => overrides.now ?? ACME.now,
    // Retries of an unavailable Log Cache must not wait for real.
    sleep: noSleep,
    trafficCheck: overrides.trafficCheck,
    minTrafficWindowHours: overrides.minTrafficWindowHours,
    previous: overrides.previous,
    log: overrides.log,
  });
}

const usageByName = (snapshot: Awaited<ReturnType<typeof scanAcme>>) =>
  Object.fromEntries(snapshot.apps.map((a) => [a.name, a.usage]));

describe('scan against the acme fixture landscape', () => {
  it('stops with a role hint when the org is visible but none of its spaces', async () => {
    await expect(scanAcme(acmeFetch({ noVisibleSpaces: true }))).rejects.toThrow(
      /none of its spaces[\s\S]*Space Auditor/,
    );
  });

  it('matches the org name exactly, because `names` is a comma-separated list filter', async () => {
    const fake = acmeFetch();
    await expect(
      scan({
        apiUrl: ACME.api,
        org: 'acme-prod,other',
        deep: false,
        probeRoutes: true,
        concurrency: 5,
        env: { BAIP_LENS_ACCESS_TOKEN: ACME.token },
        fetch: fake.fetch,
        now: () => ACME.now,
      }),
    ).rejects.toThrow(/not found/);
  });

  it('records that no route was probed, whatever the flag said', async () => {
    const snapshot = await scanAcme();
    expect(snapshot.options.probeRoutes).toBe(false);
  });

  it('collects the full inventory across paginated responses', async () => {
    const snapshot = await scanAcme();
    expect(snapshot.apps).toHaveLength(8);
    expect(snapshot.raw.droplets).toHaveLength(7);
    expect(snapshot.scope).toEqual({
      apiEndpoint: 'https://api.cf.example.org/',
      orgs: ['acme-prod'],
    });
    const orders = snapshot.apps.find((a) => a.name === 'orders-srv');
    expect(orders).toMatchObject({
      org: 'acme-prod',
      space: 'prod',
      state: 'STARTED',
      stack: 'cflinuxfs4',
      buildpacks: [{ name: 'nodejs', version: '1.8.40' }],
      lastDeployAt: '2026-07-20T10:00:00Z',
    });
    const neverStaged = snapshot.apps.find((a) => a.name === 'never-staged');
    expect(neverStaged?.lastDeployAt).toBeNull();
  });

  it('issues only GET requests, to the CF API and its log cache, and sends the token nowhere else', async () => {
    const fake = acmeFetch();
    await scanAcme(fake);
    expect(fake.calls.length).toBeGreaterThan(0);
    for (const call of fake.calls) {
      expect(call.method).toBe('GET');
      expect(['api.cf.example.org', ACME.logCache]).toContain(call.url.host);
      expect(call.redirect).toBe('manual');
    }
    const authenticated = fake.calls.filter((c) => c.headers.authorization !== undefined);
    expect(authenticated.every((c) => c.headers.authorization === `bearer ${ACME.token}`)).toBe(
      true,
    );
    // The unauthenticated root call is the only one without a token.
    expect(
      fake.calls.filter((c) => c.headers.authorization === undefined).map((c) => c.url.pathname),
    ).toEqual(['/']);
    // On the log cache: one app's envelopes, nothing else (no meta, info or PromQL).
    const logCache = fake.calls.filter((c) => c.url.host === ACME.logCache);
    expect(logCache.length).toBeGreaterThan(0);
    for (const call of logCache) expect(call.url.pathname).toMatch(/^\/api\/v1\/read\/[0-9a-z-]+$/);
  });

  it('finds apps without a deploy in the last 12 months', async () => {
    const snapshot = await scanAcme();
    const stale = snapshot.findings.filter((f) => f.id === 'APP_NO_RECENT_DEPLOY');
    expect(stale.map((f) => [f.app.name, f.severity])).toEqual([
      ['legacy-reporting', 'medium'],
      ['docs-static', 'low'],
      ['orders-approuter', 'low'],
    ]);
    expect(snapshot.apps[0]?.name).toBe('legacy-reporting'); // highest risk first
  });

  it('judges every app: no route, no traffic, stopped, in use, unknown (APP_IDLE)', async () => {
    const snapshot = await scanAcme();
    const idle = snapshot.findings.filter((f) => f.id === 'APP_IDLE');
    expect(
      idle.map((f) => [f.app.name, f.severity, f.evidence.signal, f.evidence.confidence]),
    ).toEqual([
      ['custom-bp-app', 'low', 'no_route', 'high'],
      ['legacy-reporting', 'low', 'stopped', 'high'],
      ['orders-approuter', 'low', 'no_traffic', 'medium'],
    ]);
    expect(snapshot.checks.find((c) => c.id === 'rule.APP_IDLE')?.status).toBe('ran');
    expect(snapshot.checks.find((c) => c.id === 'collect.traffic')?.status).toBe('ran');
    expect(usageByName(snapshot)).toEqual({
      // A router access log 10 minutes before the scan.
      'orders-srv': { state: 'active', lastRequestAt: '2026-09-28T23:50:00.000Z' },
      // 42 hours of logs without a request, unchanged for more than 180 days.
      'orders-approuter': { state: 'idle', signal: 'no_traffic', confidence: 'medium' },
      // Stopped since June 2024.
      'legacy-reporting': { state: 'idle', signal: 'stopped', confidence: 'high' },
      // Its only route is on apps.internal, which leaves no router log (D6).
      'inventory-java': { state: 'unknown', reason: 'traffic_not_measurable' },
      // Log Cache held 4 hours of it, less than the 12-hour minimum (D5).
      'docs-static': { state: 'unknown', reason: 'window_too_short' },
      'custom-bp-app': { state: 'idle', signal: 'no_route', confidence: 'high' },
      // Legacy `none` health check, read as `process`: a worker (D7).
      'docker-worker': { state: 'not_assessed', reason: 'worker_health_check' },
      // Stopped 9 days ago: not long enough.
      'never-staged': { state: 'not_assessed', reason: 'stopped' },
    });
  });

  it('names the observed window in the evidence, so a finding never claims more than was seen', async () => {
    const snapshot = await scanAcme();
    const silent = snapshot.findings.find((f) => f.evidence.signal === 'no_traffic');
    expect(silent).toMatchObject({
      title: 'No request in 42 hours of router logs',
      evidence: {
        lastRequestAt: null,
        windowStart: '2026-09-27T06:00:00.000Z',
        windowHours: 42,
        minWindowHours: 12,
        envelopesExamined: 3,
        lastChangeAt: '2025-07-01T09:05:00Z',
        unchangedDays: 454,
        unchangedThresholdDays: 180,
      },
    });
    const stopped = snapshot.findings.find((f) => f.evidence.signal === 'stopped');
    expect(stopped).toMatchObject({
      title: 'Stopped for 820 days',
      evidence: { updatedAt: '2024-06-30T16:00:00Z', stoppedDays: 820, thresholdDays: 90 },
    });
  });

  it('keeps exactly three traffic values per app, and only for apps with an HTTP route', async () => {
    const snapshot = await scanAcme();
    expect(snapshot.raw.traffic).toEqual([
      {
        appGuid: ACME_TRAFFIC_APPS['orders-srv'],
        lastRequestAt: '2026-09-28T23:50:00.000Z',
        windowStart: '2026-09-28T23:40:00.000Z',
        envelopesExamined: 4,
      },
      {
        appGuid: ACME_TRAFFIC_APPS['orders-approuter'],
        lastRequestAt: null,
        windowStart: '2026-09-27T06:00:00.000Z',
        envelopesExamined: 3,
      },
      {
        appGuid: ACME_TRAFFIC_APPS['docs-static'],
        lastRequestAt: null,
        windowStart: '2026-09-28T20:00:00.000Z',
        envelopesExamined: 0,
      },
    ]);
    expect(snapshot.options).toMatchObject({
      trafficCheck: true,
      minTrafficWindowHours: 12,
      trafficPages: 5,
    });
  });

  it('records a Log Cache 404 as a skipped check that says what a 404 can mean', async () => {
    const snapshot = await scanAcme(acmeFetch({ logCache: 'not-found' }));
    const check = snapshot.checks.find((c) => c.id === 'collect.traffic');
    expect(check).toMatchObject({ status: 'skipped', reasonCode: 'insufficient_role' });
    expect(check?.reason).toMatch(/404[\s\S]*never answers 403/);
    // The no-route and stopped signals do not need Log Cache and stand.
    expect(snapshot.checks.find((c) => c.id === 'rule.APP_IDLE')?.status).toBe('ran');
    const usage = usageByName(snapshot);
    expect(usage['custom-bp-app']).toEqual({
      state: 'idle',
      signal: 'no_route',
      confidence: 'high',
    });
    for (const name of ['orders-srv', 'orders-approuter', 'docs-static']) {
      expect(usage[name], name).toEqual({ state: 'unknown', reason: 'traffic_unreadable' });
    }
    expect(snapshot.raw.traffic).toEqual([]);
  });

  it('records an unavailable Log Cache as skipped, and the scan goes on', async () => {
    const fake = acmeFetch({ logCache: 'down' });
    const snapshot = await scanAcme(fake);
    expect(snapshot.checks.find((c) => c.id === 'collect.traffic')).toMatchObject({
      status: 'skipped',
      reasonCode: 'unavailable',
    });
    expect(usageByName(snapshot)['orders-srv']).toEqual({
      state: 'unknown',
      reason: 'traffic_unreadable',
    });
    // The first app decides; nothing else is asked once Log Cache is down.
    const reads = fake.calls.filter((c) => c.url.host === ACME.logCache);
    expect(new Set(reads.map((c) => c.url.pathname)).size).toBe(1);
  });

  it('reads nothing from Log Cache with --no-traffic-check', async () => {
    const fake = acmeFetch();
    const snapshot = await scanAcme(fake, { trafficCheck: false });
    expect(fake.calls.some((c) => c.url.host === ACME.logCache)).toBe(false);
    expect(snapshot.checks.find((c) => c.id === 'collect.traffic')).toMatchObject({
      status: 'skipped',
      reasonCode: 'disabled',
    });
    expect(snapshot.options.trafficCheck).toBe(false);
    expect(usageByName(snapshot)['orders-approuter']).toEqual({
      state: 'unknown',
      reason: 'traffic_check_off',
    });
  });

  it('skips the traffic check when the platform advertises no log cache', async () => {
    const snapshot = await scanAcme(acmeFetch({ noLogCacheLink: true }));
    expect(snapshot.checks.find((c) => c.id === 'collect.traffic')).toMatchObject({
      status: 'skipped',
      reasonCode: 'unavailable',
    });
  });

  it('says unknown instead of idle when the window is shorter than --min-traffic-window', async () => {
    const snapshot = await scanAcme(acmeFetch(), { minTrafficWindowHours: 48 });
    expect(usageByName(snapshot)['orders-approuter']).toEqual({
      state: 'unknown',
      reason: 'window_too_short',
    });
    expect(snapshot.findings.some((f) => f.evidence.signal === 'no_traffic')).toBe(false);
  });

  it('keeps only routes and web processes of the inventory, without hosts, paths or commands', async () => {
    const snapshot = await scanAcme();
    // The unmapped promo route and the destination to an app the user cannot see are gone.
    expect(snapshot.raw.routes.map((r) => [r.guid.slice(-1), r.kind, r.appGuids.length])).toEqual([
      ['1', 'http', 1],
      ['2', 'http', 1],
      ['3', 'internal', 1],
      ['4', 'http', 1],
      ['5', 'tcp', 1],
      ['7', 'unknown', 1],
    ]);
    expect(snapshot.raw.processes.map((p) => p.type)).toEqual(Array(9).fill('web'));
    expect(JSON.stringify(snapshot.raw)).not.toMatch(/POISON|acme\.example\.com|command/);
  });

  it('records a 403 on routes as skipped, and says unknown rather than idle', async () => {
    const fake = acmeFetch({ routesForbidden: true });
    const snapshot = await scanAcme(fake);
    expect(snapshot.checks.find((c) => c.id === 'collect.routes')).toMatchObject({
      status: 'skipped',
      reasonCode: 'insufficient_role',
    });
    expect(snapshot.checks.find((c) => c.id === 'rule.APP_IDLE')).toMatchObject({
      status: 'skipped',
      reasonCode: 'dependency_skipped',
    });
    expect(snapshot.findings.filter((f) => f.id === 'APP_IDLE')).toEqual([]);
    const custom = snapshot.apps.find((a) => a.name === 'custom-bp-app');
    expect(custom?.usage).toEqual({ state: 'unknown', reason: 'data_unavailable' });
    // Stopped since 2024, but the rule could not run: unknown, never "not judged".
    expect(usageByName(snapshot)['legacy-reporting']).toEqual({
      state: 'unknown',
      reason: 'data_unavailable',
    });
    // Which apps to read depends on the routes: Log Cache is not asked at all.
    expect(snapshot.checks.find((c) => c.id === 'collect.traffic')).toMatchObject({
      status: 'skipped',
      reasonCode: 'dependency_skipped',
      reason: 'needs collect.routes, which did not run',
    });
    expect(fake.calls.some((c) => c.url.host === ACME.logCache)).toBe(false);
  });

  it('records a 403 on processes as skipped, so no app without a route is called idle', async () => {
    const snapshot = await scanAcme(acmeFetch({ processesForbidden: true }));
    expect(snapshot.checks.find((c) => c.id === 'collect.processes')).toMatchObject({
      status: 'skipped',
      reasonCode: 'insufficient_role',
    });
    expect(snapshot.findings.filter((f) => f.id === 'APP_IDLE')).toEqual([]);
    const states = new Set(snapshot.apps.map((a) => a.usage?.state));
    expect(states).toEqual(new Set(['unknown', 'not_assessed']));
    expect(snapshot.checks.find((c) => c.id === 'collect.traffic')).toMatchObject({
      status: 'skipped',
      reasonCode: 'dependency_skipped',
      reason: 'needs collect.processes, which did not run',
    });
  });

  it('strips credentials from buildpack URLs', async () => {
    const snapshot = await scanAcme();
    const custom = snapshot.raw.apps.find((a) => a.name === 'custom-bp-app');
    expect(custom?.buildpacks).toEqual(['https://github.com/acme/custom-buildpack.git']);
  });

  it('records a 403 as a skipped check and keeps going', async () => {
    const snapshot = await scanAcme(acmeFetch({ dropletsForbidden: true }));
    expect(snapshot.apps).toHaveLength(8);
    expect(snapshot.checks.find((c) => c.id === 'collect.droplets')).toMatchObject({
      status: 'skipped',
      reasonCode: 'insufficient_role',
      reason: 'insufficient role: needs SpaceAuditor',
    });
    expect(snapshot.checks.find((c) => c.id === 'rule.APP_NO_RECENT_DEPLOY')).toMatchObject({
      status: 'skipped',
      reasonCode: 'dependency_skipped',
    });
    // Losing the droplets skips only the deploy rule. APP_IDLE goes on, but
    // without a droplet "unchanged for 180 days" cannot be shown: low confidence, info.
    expect(
      snapshot.findings.map((f) => [f.id, f.app.name, f.severity, f.evidence.confidence]),
    ).toEqual([
      ['APP_IDLE', 'custom-bp-app', 'low', 'high'],
      ['APP_IDLE', 'legacy-reporting', 'low', 'high'],
      ['APP_IDLE', 'orders-approuter', 'info', 'low'],
    ]);
  });
});

describe('scan --previous: traffic history across scans', () => {
  const APPROUTER = ACME_TRAFFIC_APPS['orders-approuter'];
  const guid = (n: string) => `a99a0000-0000-4000-8000-${n.padStart(12, '0')}`;
  const PROD = '5pace000-0000-4000-8000-00000000prod';
  const DEV = '5pace000-0000-4000-8000-000000000dev';
  const MINUTE_BEFORE = new Date(ACME.now.getTime() - 60_000);
  /** A snapshot as the next `--previous` reads it from disk. */
  const reread = (snapshot: Snapshot) => SnapshotSchema.parse(JSON.parse(JSON.stringify(snapshot)));
  const entry = (
    appGuid: string,
    spaceGuid: string,
    lastRequestEverSeen: string | null,
    firstScanWithoutTraffic: string | null,
    scansWithoutTraffic: number,
  ): RawHistory => ({
    appGuid,
    spaceGuid,
    lastRequestEverSeen,
    firstScanWithoutTraffic,
    scansWithoutTraffic,
  });
  /** The previous history, minus the fields the schema does not know. */
  const unchanged = (appGuid: string) =>
    acmePrevious().raw.history.find((h) => h.appGuid === appGuid);

  it("carries each app's history forward by GUID and states the span in the finding", async () => {
    const logs: string[] = [];
    const snapshot = await scanAcme(acmeFetch(), {
      previous: acmePrevious(),
      log: (m) => logs.push(m),
    });
    expect(snapshot.options.previousScannedAt).toBe('2026-09-22T00:00:00.000Z');
    expect(snapshot.raw.history).toEqual([
      // A request in this scan: the run ends and the newest request ever seen
      // moves on. The app was renamed since: GUIDs match, names do not matter.
      entry(guid('1'), PROD, '2026-09-28T23:50:00.000Z', null, 0),
      // 42 hours of silence again: the sixth scan in a row since 18 August.
      entry(APPROUTER, PROD, '2026-08-10T14:00:00.000Z', '2026-08-18T00:00:00.000Z', 6),
      // Stopped, only an internal route, only 4 hours of logs, a worker: this
      // scan cannot tell, so each entry is carried forward unchanged (D8).
      entry(guid('3'), PROD, '2026-05-30T12:00:00.000Z', '2026-06-05T00:00:00.000Z', 3),
      entry(guid('4'), PROD, '2026-07-14T09:30:00.000Z', null, 0),
      entry(guid('5'), DEV, null, '2026-09-15T00:00:00.000Z', 2),
      entry(guid('7'), DEV, '2026-04-02T08:00:00.000Z', '2026-04-10T00:00:00.000Z', 2),
      // The app that is gone, and the custom-bp-app pushed again under a new
      // GUID, are dropped: the new custom-bp-app (...006) inherits nothing.
    ]);
    const silent = snapshot.findings.find((f) => f.app.guid === APPROUTER && f.id === 'APP_IDLE');
    expect(silent).toMatchObject({
      severity: 'low',
      title: 'No requests seen across 6 scans over 42 days',
      evidence: { confidence: 'high', scansWithoutTraffic: 6, silentSpanDays: 42 },
    });
    expect(usageByName(snapshot)['docs-static']).toEqual({
      state: 'unknown',
      reason: 'window_too_short',
    });
    expect(logs).toContain(
      'Traffic history carried forward from the scan of 2026-09-22T00:00:00.000Z: ' +
        '6 app(s) matched by GUID; 2 dropped for apps that are gone',
    );
    // The fields the schema does not know are not carried, not even on an
    // entry carried unchanged.
    expect(JSON.stringify(snapshot)).not.toMatch(
      /POISON-gone-app|POISON-history-note|jane\.doe|0000000000ff|0000000000fe/,
    );
  });

  it('keeps the history of the spaces a --space scan does not read', async () => {
    const logs: string[] = [];
    const dev = await scanAcme(acmeFetch(), {
      space: 'dev',
      previous: acmePrevious(),
      now: MINUTE_BEFORE,
      log: (m) => logs.push(m),
    });
    expect(dev.raw.apps.every((app) => app.spaceGuid === DEV)).toBe(true);
    // The prod apps were not seen, so their entries stay as they were; in dev,
    // the gone app and the re-pushed one are dropped.
    for (const prod of [guid('1'), APPROUTER, guid('3'), guid('4')]) {
      expect(dev.raw.history.find((h) => h.appGuid === prod)).toEqual(unchanged(prod));
    }
    expect(dev.raw.history.map((h) => h.appGuid)).toEqual([
      guid('1'),
      APPROUTER,
      guid('3'),
      guid('4'),
      guid('5'),
      guid('7'),
    ]);
    expect(logs).toContain(
      'Traffic history carried forward from the scan of 2026-09-22T00:00:00.000Z: ' +
        '2 app(s) matched by GUID; 4 kept as they were for apps this scan did not see; ' +
        '2 dropped for apps that are gone',
    );
    // The next org-wide scan, chained from the dev snapshot, goes on as if the
    // dev scan had not happened for prod.
    const next = await scanAcme(acmeFetch(), { previous: reread(dev) });
    expect(next.raw.history.find((h) => h.appGuid === APPROUTER)).toEqual(
      entry(APPROUTER, PROD, '2026-08-10T14:00:00.000Z', '2026-08-18T00:00:00.000Z', 6),
    );
  });

  it('keeps the whole history when the app inventory cannot be read', async () => {
    const logs: string[] = [];
    const failed = await scanAcme(acmeFetch({ appsFailing: true }), {
      previous: acmePrevious(),
      now: MINUTE_BEFORE,
      log: (m) => logs.push(m),
    });
    expect(failed.checks.find((c) => c.id === 'collect.apps')?.status).toBe('skipped');
    expect(failed.checks.find((c) => c.id === 'collect.traffic')).toMatchObject({
      status: 'skipped',
      reasonCode: 'dependency_skipped',
    });
    // No app could be matched or observed, so none is gone either.
    expect(failed.raw.history).toEqual(acmePrevious().raw.history);
    expect(logs).toContain(
      'The app inventory could not be read, so the traffic history of the scan of ' +
        '2026-09-22T00:00:00.000Z is kept as it was (8 app(s))',
    );
    const next = await scanAcme(acmeFetch(), { previous: reread(failed) });
    expect(next.raw.history.find((h) => h.appGuid === APPROUTER)).toEqual(
      entry(APPROUTER, PROD, '2026-08-10T14:00:00.000Z', '2026-08-18T00:00:00.000Z', 6),
    );
    expect(
      next.findings.find((f) => f.app.guid === APPROUTER && f.id === 'APP_IDLE'),
    ).toMatchObject({
      title: 'No requests seen across 6 scans over 42 days',
      evidence: { confidence: 'high' },
    });
  });

  it('refuses a snapshot of another API endpoint before sending anything', async () => {
    const fake = acmeFetch();
    const previous = acmePrevious();
    previous.scope.apiEndpoint = 'https://api.cf.other.example.org/';
    await expect(scanAcme(fake, { previous })).rejects.toThrow(ConfigError);
    expect(fake.calls).toEqual([]);
  });

  it('refuses a snapshot of another org with the same name right after the org lookup', async () => {
    const fake = acmeFetch();
    const previous = acmePrevious();
    previous.raw.orgs = [{ guid: '0a1b2c3d-0000-4000-8000-0000000000ee', name: ACME.org }];
    await expect(scanAcme(fake, { previous })).rejects.toThrow(/another org named "acme-prod"/);
    // The CF root and the org lookup, and nothing about spaces or apps.
    expect(fake.calls.map((c) => routeKey(c.url))).toEqual([
      'api.cf.example.org/',
      'api.cf.example.org/v3/organizations?names=acme-prod&per_page=5000',
    ]);
  });

  it('refuses a snapshot that is not older than this scan before sending anything', async () => {
    const fake = acmeFetch();
    const previous = { ...acmePrevious(), scannedAt: ACME.now.toISOString() };
    await expect(scanAcme(fake, { previous })).rejects.toThrow(/not before this scan/);
    expect(fake.calls).toEqual([]);
  });

  it('refuses a project snapshot before sending anything', async () => {
    const fake = acmeFetch();
    const previous = { ...acmePrevious(), scope: { orgs: [], projects: ['acme-incidents'] } };
    await expect(scanAcme(fake, { previous })).rejects.toThrow(/project scan/);
    expect(fake.calls).toEqual([]);
  });

  it('derives the history of a snapshot written before history existed', async () => {
    const previous = acmePrevious();
    previous.raw.history = [];
    previous.options.previousScannedAt = null;
    previous.raw.traffic = [
      {
        appGuid: APPROUTER,
        lastRequestAt: null,
        windowStart: '2026-09-21T04:00:00.000Z',
        envelopesExamined: 3,
      },
    ];
    const snapshot = await scanAcme(acmeFetch(), { previous });
    expect(snapshot.raw.history.find((h) => h.appGuid === APPROUTER)).toEqual(
      entry(APPROUTER, PROD, null, '2026-09-22T00:00:00.000Z', 2),
    );
    expect(
      snapshot.findings.find((f) => f.app.guid === APPROUTER && f.id === 'APP_IDLE')?.title,
    ).toBe('No requests seen across 2 scans over 7 days');
  });

  it('names the window, not the span, for scans closer together than one window', async () => {
    const first = await scanAcme(acmeFetch(), { now: new Date(ACME.now.getTime() - 600_000) });
    const second = await scanAcme(acmeFetch(), { previous: reread(first) });
    const silent = second.findings.find((f) => f.app.guid === APPROUTER && f.id === 'APP_IDLE');
    expect(silent).toMatchObject({
      title: 'No request in 42 hours of router logs',
      evidence: { scansWithoutTraffic: 2, windowHours: 42 },
    });
  });

  it('without --previous, the history is this scan alone', async () => {
    const snapshot = await scanAcme();
    expect(snapshot.options.previousScannedAt).toBeNull();
    expect(snapshot.raw.history).toEqual([
      entry(ACME_TRAFFIC_APPS['orders-srv'], PROD, '2026-09-28T23:50:00.000Z', null, 0),
      entry(APPROUTER, PROD, null, ACME.now.toISOString(), 1),
    ]);
  });
});
