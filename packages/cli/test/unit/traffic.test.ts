import { describe, expect, it } from 'vitest';
import { CheckSkipError } from '../../src/checks.js';
import { collectTraffic, readAppTraffic } from '../../src/collectors/traffic.js';
import { HttpClient } from '../../src/http/httpClient.js';
import { LogCacheClient } from '../../src/http/logCacheClient.js';
import { EgressPolicy, logCacheRule } from '../../src/net/allowlist.js';
import { FakeFetch, jsonResponse, noSleep } from '../support/fakeFetch.js';

const LOG_CACHE = new URL('https://log-cache.cf.example.org');
const APP = 'a99a0000-0000-4000-8000-0000000000aa';
const APP_B = 'a99a0000-0000-4000-8000-0000000000bb';
const APP_C = 'a99a0000-0000-4000-8000-0000000000cc';
/** Eight more apps, all of which fail in the "failures in a row" case. */
const FAILING = Array.from({ length: 8 }, (_, i) => `a99a0000-0000-4000-8000-00000000f00${i}`);

/** 2026-09-28T00:00:00Z in nanoseconds, plus `minutes`. */
const at = (minutes: number): string =>
  String(1_790_553_600_000_000_000n + BigInt(minutes) * 60_000_000_000n);
const iso = (minutes: number): string =>
  new Date(Date.UTC(2026, 8, 28) + minutes * 60_000).toISOString();

function envelope(minutes: number, sourceType: string, extra: Record<string, unknown> = {}) {
  return {
    timestamp: at(minutes),
    source_id: APP,
    instance_id: '0',
    deprecated_tags: {},
    tags: { source_type: sourceType, remote_address: '198.51.100.9:443', uri: '/secret-path' },
    log: {
      payload: Buffer.from('GET /secret-path HTTP/1.1 "curl/8"').toString('base64'),
      type: 'OUT',
    },
    ...extra,
  };
}
const page = (...batch: unknown[]) => jsonResponse({ envelopes: { batch } });
/** `count` app logs, newest first, from `start` minutes back one minute apart. */
const appLogs = (count: number, start: number) =>
  Array.from({ length: count }, (_, i) => envelope(start - i, 'APP/PROC/WEB'));

function client(fake: FakeFetch): LogCacheClient {
  const policy = new EgressPolicy([logCacheRule(LOG_CACHE)]);
  const http = new HttpClient({ policy, userAgent: 't', fetch: fake.fetch, sleep: noSleep });
  return new LogCacheClient(http, LOG_CACHE, {
    source: 'test',
    getToken: () => Promise.resolve('cf-token'),
    invalidate: () => {},
  });
}

const reads = (fake: FakeFetch, app = APP) =>
  fake.calls.filter((c) => c.url.pathname === `/api/v1/read/${app}`);

describe('readAppTraffic', () => {
  it('stops at the newest router log of the first page', async () => {
    const fake = new FakeFetch().on(
      'GET',
      (u) => u.pathname.endsWith(APP),
      () =>
        page(
          envelope(50, 'APP/PROC/WEB'),
          envelope(40, 'RTR'),
          envelope(45, 'RTR'),
          envelope(30, 'CELL'),
        ),
    );
    const { traffic } = await readAppTraffic(client(fake), APP, 5);
    // The newest router log wins even if the page is not sorted.
    expect(traffic).toEqual({
      appGuid: APP,
      lastRequestAt: iso(45),
      windowStart: iso(30),
      envelopesExamined: 4,
    });
    expect(reads(fake)).toHaveLength(1);
  });

  it('asks newest first for LOG envelopes only, never with start_time or name_filter', async () => {
    const fake = new FakeFetch().on(
      'GET',
      (u) => u.pathname.endsWith(APP),
      () => page(envelope(1, 'RTR')),
    );
    await readAppTraffic(client(fake), APP, 5);
    const query = reads(fake)[0]!.url.searchParams;
    expect(query.get('descending')).toBe('true');
    expect(query.getAll('envelope_types')).toEqual(['LOG']);
    expect(query.get('limit')).toBe('1000');
    expect(query.has('start_time')).toBe(false);
    expect(query.has('name_filter')).toBe(false);
    expect(reads(fake)[0]!.headers.authorization).toBe('bearer cf-token');
  });

  it('pages back with the exclusive end_time until a router log appears', async () => {
    const fake = new FakeFetch()
      .on(
        'GET',
        (u) => u.pathname.endsWith(APP) && !u.searchParams.has('end_time'),
        () => page(...appLogs(1000, 2000)),
      )
      .on(
        'GET',
        (u) => u.pathname.endsWith(APP) && u.searchParams.has('end_time'),
        () => page(envelope(900, 'APP/PROC/WEB'), envelope(800, 'RTR')),
      );
    const { traffic } = await readAppTraffic(client(fake), APP, 5);
    // The second page starts strictly below the oldest envelope of the first, as the raw string.
    expect(reads(fake)[1]!.url.searchParams.get('end_time')).toBe(at(1001));
    expect(traffic).toMatchObject({ lastRequestAt: iso(800), envelopesExamined: 1002 });
  });

  it('stops after the page cap and reports only the window it read', async () => {
    const fake = new FakeFetch()
      .on(
        'GET',
        (u) => !u.searchParams.has('end_time'),
        () => page(...appLogs(1000, 3000)),
      )
      .on(
        'GET',
        (u) => u.searchParams.get('end_time') === at(2001),
        () => page(...appLogs(1000, 2000)),
      );
    const { traffic } = await readAppTraffic(client(fake), APP, 2);
    expect(traffic).toEqual({
      appGuid: APP,
      lastRequestAt: null,
      windowStart: iso(1001),
      envelopesExamined: 2000,
    });
    // No third page, and no window-start read: the cap, not the cache, ended the walk.
    expect(reads(fake)).toHaveLength(2);
  });

  it('when the cache runs out first, starts the window at the oldest envelope of any type', async () => {
    const fake = new FakeFetch()
      .on(
        'GET',
        (u) => u.searchParams.get('descending') === 'true',
        () => page(envelope(600, 'APP/PROC/WEB'), envelope(500, 'STG')),
      )
      .on(
        'GET',
        (u) => u.searchParams.get('limit') === '1',
        () => page({ timestamp: at(-600), source_id: APP, tags: {}, gauge: { metrics: {} } }),
      );
    const { traffic } = await readAppTraffic(client(fake), APP, 5);
    expect(traffic).toEqual({
      appGuid: APP,
      lastRequestAt: null,
      windowStart: iso(-600),
      envelopesExamined: 2,
    });
    // Ascending (no `descending`) and unfiltered.
    const oldest = reads(fake)[1]!.url.searchParams;
    expect([oldest.has('descending'), oldest.has('envelope_types')]).toEqual([false, false]);
  });

  it('gives no window when Log Cache holds nothing for the app', async () => {
    const fake = new FakeFetch().on(
      'GET',
      (u) => u.pathname.endsWith(APP),
      () => page(),
    );
    const { traffic } = await readAppTraffic(client(fake), APP, 5);
    expect(traffic).toEqual({
      appGuid: APP,
      lastRequestAt: null,
      windowStart: null,
      envelopesExamined: 0,
    });
  });

  it('falls back to the window it read when the window-start read fails', async () => {
    const fake = new FakeFetch()
      .on(
        'GET',
        (u) => u.searchParams.get('descending') === 'true',
        () => page(envelope(500, 'APP/PROC/WEB')),
      )
      .on(
        'GET',
        (u) => u.searchParams.get('limit') === '1',
        () => new Response(null, { status: 503 }),
      );
    const { traffic } = await readAppTraffic(client(fake), APP, 5);
    expect(traffic.windowStart).toBe(iso(500));
  });

  it('halves the limit when the response is too large (429), instead of waiting', async () => {
    const fake = new FakeFetch()
      .on(
        'GET',
        (u) => u.searchParams.get('limit') === '1000',
        () => new Response(null, { status: 429 }),
        1,
      )
      .on(
        'GET',
        (u) => u.searchParams.get('limit') === '500',
        () => page(envelope(10, 'RTR')),
      );
    const { traffic } = await readAppTraffic(client(fake), APP, 5);
    expect(traffic.lastRequestAt).toBe(iso(10));
    expect(reads(fake).map((c) => c.url.searchParams.get('limit'))).toEqual(['1000', '500']);
  });

  it('counts dropped envelopes towards a full page, so a full page is never taken for the end', async () => {
    const broken = Array.from({ length: 999 }, () => ({ timestamp: 'not-a-number' }));
    const fake = new FakeFetch()
      .on(
        'GET',
        (u) => !u.searchParams.has('end_time') && u.searchParams.get('descending') === 'true',
        () => page(envelope(100, 'APP/PROC/WEB'), ...broken),
      )
      .on(
        'GET',
        (u) => u.searchParams.has('end_time'),
        () => page(envelope(50, 'RTR')),
      );
    const read = await readAppTraffic(client(fake), APP, 5);
    expect(read.invalid).toBe(999);
    expect(read.traffic.lastRequestAt).toBe(iso(50));
  });

  it('keeps nothing of the envelope but the timestamp and whether it is a router log', async () => {
    const fake = new FakeFetch().on(
      'GET',
      (u) => u.pathname.endsWith(APP),
      () => page(envelope(5, 'RTR')),
    );
    const result = await client(fake).read(APP, {
      descending: true,
      envelopeTypes: ['LOG'],
      limit: 10,
    });
    expect(result.envelopes).toEqual([{ timestamp: at(5), router: true, tagged: true }]);
    expect(JSON.stringify(result)).not.toMatch(/secret-path|198\.51\.100\.9|curl/);
  });

  it('halves the limit when the declared body is larger than it reads, as for a 429', async () => {
    const fake = new FakeFetch()
      .on(
        'GET',
        (u) => u.searchParams.get('limit') === '1000',
        () => new Response('{}', { headers: { 'content-length': String(17 * 1024 * 1024) } }),
        1,
      )
      .on(
        'GET',
        (u) => u.searchParams.get('limit') === '500',
        () => page(envelope(10, 'RTR')),
      );
    const { traffic } = await readAppTraffic(client(fake), APP, 5);
    expect(traffic.lastRequestAt).toBe(iso(10));
    expect(reads(fake).map((c) => c.url.searchParams.get('limit'))).toEqual(['1000', '500']);
  });
});

describe('untagged logs', () => {
  /** Drain metadata off: the envelope comes with an empty set of tags, or none (undefined is not sent). */
  const untagged = (minutes: number, empty: boolean) => ({
    ...envelope(minutes, 'RTR'),
    tags: empty ? {} : undefined,
  });

  it('skips the check when no envelope of the first app carries a source_type tag', async () => {
    const fake = new FakeFetch()
      .on(
        'GET',
        (u) => u.searchParams.get('descending') === 'true',
        () => page(untagged(20, true), untagged(10, false)),
      )
      .on(
        'GET',
        (u) => u.searchParams.get('limit') === '1',
        () => page(untagged(10, false)),
      );
    const error = await collectTraffic(client(fake), [APP, APP_B], { maxPages: 5 }).catch(
      (e: unknown) => e,
    );
    // Silence would only mean that router logs cannot be told apart: never "idle".
    expect(error).toBeInstanceOf(CheckSkipError);
    expect(error).toMatchObject({ reasonCode: 'error' });
    expect((error as CheckSkipError).reason).toMatch(/no source_type tag.*drain metadata/s);
    expect(reads(fake, APP_B)).toHaveLength(0);
  });

  it('skips the whole check when a later app shows untagged logs, and asks no further app', async () => {
    const fake = new FakeFetch()
      .on(
        'GET',
        (u) => u.pathname.endsWith(APP),
        () => page(envelope(1, 'RTR')),
      )
      .on(
        'GET',
        (u) => u.pathname.endsWith(APP_B),
        () => page(untagged(5, false)),
      );
    await expect(
      collectTraffic(client(fake), [APP, APP_B, APP_C], { maxPages: 5, concurrency: 1 }),
    ).rejects.toMatchObject({ reasonCode: 'error' });
    expect(reads(fake, APP_C)).toHaveLength(0);
  });

  it('judges an app whose log holds tagged envelopes but no router log', async () => {
    const fake = new FakeFetch()
      .on(
        'GET',
        (u) => u.searchParams.get('descending') === 'true',
        () => page(untagged(30, false), envelope(20, 'APP/PROC/WEB')),
      )
      .on(
        'GET',
        (u) => u.searchParams.get('limit') === '1',
        () => page(envelope(20, 'APP/PROC/WEB')),
      );
    const { traffic } = await readAppTraffic(client(fake), APP, 5);
    expect(traffic).toMatchObject({ lastRequestAt: null, windowStart: iso(20) });
  });
});

describe('collectTraffic', () => {
  it('skips the check with an explanation when the first app answers 404', async () => {
    const fake = new FakeFetch().on(
      'GET',
      () => true,
      () => new Response(null, { status: 404 }),
    );
    const error = await collectTraffic(client(fake), [APP, APP_B], { maxPages: 5 }).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(CheckSkipError);
    expect(error).toMatchObject({ reasonCode: 'insufficient_role' });
    expect((error as CheckSkipError).reason).toMatch(/404.*never answers 403/s);
    expect(reads(fake, APP_B)).toHaveLength(0);
  });

  it('skips the check as unavailable when the first app gets no answer', async () => {
    const fake = new FakeFetch().on(
      'GET',
      () => true,
      () => new Response('down', { status: 503 }),
    );
    await expect(collectTraffic(client(fake), [APP], { maxPages: 5 })).rejects.toMatchObject({
      reasonCode: 'unavailable',
    });
  });

  it('skips the check as an error when Log Cache rejects the request, asking only once', async () => {
    const fake = new FakeFetch().on(
      'GET',
      () => true,
      () => jsonResponse({ code: 2 }, 500),
    );
    await expect(collectTraffic(client(fake), [APP], { maxPages: 5 })).rejects.toMatchObject({
      reasonCode: 'error',
    });
    // A 500 is a bad parameter on Log Cache: retrying would only repeat it.
    expect(reads(fake)).toHaveLength(1);
  });

  it('skips the check as unavailable when the first app hits a network error', async () => {
    const fake = new FakeFetch().on(
      'GET',
      () => true,
      () => {
        throw new TypeError('fetch failed');
      },
    );
    const error = await collectTraffic(client(fake), [APP, APP_B], { maxPages: 5 }).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(CheckSkipError);
    expect(error).toMatchObject({ reasonCode: 'unavailable' });
    expect((error as CheckSkipError).reason).toMatch(/did not answer.*network error/s);
    expect(reads(fake, APP_B)).toHaveLength(0);
  });

  it('leaves a later app unknown after a network error and reads the rest', async () => {
    const fake = new FakeFetch()
      .on(
        'GET',
        (u) => u.pathname.endsWith(APP_B),
        () => {
          throw new TypeError('fetch failed');
        },
      )
      .on(
        'GET',
        () => true,
        () => page(envelope(1, 'RTR')),
      );
    const { items } = await collectTraffic(client(fake), [APP, APP_B, APP_C], { maxPages: 5 });
    expect(items.map((t) => t.appGuid)).toEqual([APP, APP_C]);
  });

  it('leaves a later app that fails unknown and reads the others, sorted by app', async () => {
    const log: string[] = [];
    const fake = new FakeFetch()
      .on(
        'GET',
        (u) => u.pathname.endsWith(APP_B),
        () => new Response(null, { status: 404 }),
      )
      .on(
        'GET',
        () => true,
        () => page(envelope(1, 'RTR')),
      );
    const { items } = await collectTraffic(client(fake), [APP_C, APP, APP_B], {
      maxPages: 5,
      log: (m) => log.push(m),
    });
    expect(items.map((t) => t.appGuid)).toEqual([APP, APP_C]);
    expect(log.join('\n')).toMatch(/1 app\(s\) could not be read/);
  });

  it('stops reading after three failed apps in a row', async () => {
    const fake = new FakeFetch()
      .on(
        'GET',
        (u) => u.pathname.endsWith(APP),
        () => page(envelope(1, 'RTR')),
      )
      .on(
        'GET',
        () => true,
        () => new Response(null, { status: 404 }),
      );
    const { items } = await collectTraffic(client(fake), [APP, ...FAILING], { maxPages: 5 });
    expect(items.map((t) => t.appGuid)).toEqual([APP]);
    // Two run at a time, so one more may already be in flight after the third failure;
    // the other four of the eight are never asked.
    const asked = new Set(
      fake.calls.filter((c) => !c.url.pathname.endsWith(APP)).map((c) => c.url.pathname),
    );
    expect(asked.size).toBeGreaterThanOrEqual(3);
    expect(asked.size).toBeLessThanOrEqual(4);
  });

  /** One worker, so the apps are read in this order; FAILING apps answer 404. */
  function inOrder(appGuids: readonly string[]) {
    const fake = new FakeFetch()
      .on(
        'GET',
        (u) => FAILING.some((guid) => u.pathname.endsWith(guid)),
        () => new Response(null, { status: 404 }),
      )
      .on(
        'GET',
        () => true,
        () => page(envelope(1, 'RTR')),
      );
    const log: string[] = [];
    const run = collectTraffic(client(fake), appGuids, {
      maxPages: 5,
      concurrency: 1,
      log: (m) => log.push(m),
    });
    return { fake, log, run };
  }
  /** The apps asked for, in the order of their first read. */
  const askedApps = (fake: FakeFetch) => [
    ...new Set(fake.calls.map((c) => c.url.pathname.slice('/api/v1/read/'.length))),
  ];

  it('counts failures in a row, not in total: a good read in between resets the count', async () => {
    const [f0, f1, f2, f3] = FAILING;
    const { fake, log, run } = inOrder([APP, f0!, f1!, APP_B, f2!, f3!, APP_C]);
    const { items } = await run;
    expect(items.map((t) => t.appGuid)).toEqual([APP, APP_B, APP_C]);
    expect(askedApps(fake)).toHaveLength(7);
    expect(log).toEqual(['Log Cache: 4 app(s) could not be read (4 failed); they are unknown']);
  });

  it('after three failures in a row asks no further app and says so', async () => {
    const { fake, log, run } = inOrder([APP, ...FAILING]);
    const { items } = await run;
    expect(items.map((t) => t.appGuid)).toEqual([APP]);
    expect(askedApps(fake)).toEqual([APP, ...FAILING.slice(0, 3)]);
    expect(log).toEqual([
      'Log Cache: 8 app(s) could not be read (3 failed, the rest were skipped); they are unknown',
    ]);
  });

  it('asks nothing when no app has an HTTP route', async () => {
    const fake = new FakeFetch();
    expect(await collectTraffic(client(fake), [], { maxPages: 5 })).toEqual({
      items: [],
      invalid: 0,
    });
    expect(fake.calls).toHaveLength(0);
  });
});
