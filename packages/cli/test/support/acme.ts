import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { type Snapshot, SnapshotSchema } from '../../src/model/snapshot.js';
import { FakeFetch, jsonResponse } from './fakeFetch.js';

/**
 * "acme-prod": a synthetic landscape built from the documented CF v3 shapes
 * (test/fixtures/cf/acme). It contains poison values — credentials in a
 * buildpack URL, a password in a start command, an owner email in
 * annotations — that must never reach any output.
 */
export const ACME = {
  api: new URL('https://api.cf.example.org'),
  org: 'acme-prod',
  orgGuid: '0a1b2c3d-0000-4000-8000-000000000001',
  now: new Date('2026-09-29T00:00:00Z'),
  token: 'test-access-token-POISON',
  /** Strings that must not appear in any report or snapshot. */
  poison: [
    'test-access-token-POISON',
    'FAKE-POISON-TOKEN-123',
    'deploy-bot',
    'POISON_hunter2',
    'POISON-execution-metadata',
    'POISON-annotation-contact',
    'jane.doe@example.com',
    'platform-team@example.com',
    // Routes and processes (slice 1 of APP_IDLE): a route path, a destination
    // app the user cannot see, a process command and a process annotation.
    'POISON-route-path',
    'POISONAPP',
    'POISON_cmd_password',
    'POISON-process-annotation',
    'route-owner@example.com',
    // Log Cache (slice 2): a router access log with a client address, a request
    // path and query, a user agent and a request id, in the base64 payload and
    // again as plain tags, plus the content of app logs.
    '203.0.113.77',
    'POISON-request-path',
    'POISON-query',
    'POISON-UserAgent',
    'POISON-vcap-id',
    'b3JkZXJzLXNydi5jZmFwcHMuZXhhbXBsZS5vcmcg',
    'order 4711 stored',
    'b3JkZXIgNDcxMSBzdG9yZWQ=',
    'token cache refreshed',
    'dG9rZW4gY2FjaGUgcmVmcmVzaGVk',
    // Tags on app logs, and an HTTP timer (the oldest envelope of an app) with
    // the request's address, path, query, user agent and id as tags.
    'POISON-app-tag',
    '198.51.100.23',
    'POISON-timer-path',
    'POISON-timer-query',
    'POISON-Timer-UserAgent',
    'POISON-timer-request-id',
    // History (slice 3): an app of the previous scan that no longer exists, and
    // fields the history schema does not know. None of them may carry forward.
    'POISON-gone-app',
    'POISON-history-note',
  ],
  logCache: 'log-cache.cf.example.org',
} as const;

/** The two visible spaces, in the sorted order the routes collector sends them. */
const ACME_SPACE_GUIDS = [
  '5pace000-0000-4000-8000-000000000dev',
  '5pace000-0000-4000-8000-00000000prod',
];
export const ACME_DEV_SPACE = '5pace000-0000-4000-8000-000000000dev';

/** `routeKey` form of the routes request: sorted keys, `%2C` between space GUIDs. */
export const ACME_ROUTES_KEY = `/v3/routes?${new URLSearchParams([
  ['include', 'domain'],
  ['per_page', '5000'],
  ['space_guids', ACME_SPACE_GUIDS.join(',')],
]).toString()}`;

function fixture(name: string): unknown {
  return JSON.parse(
    readFileSync(new URL(`../fixtures/cf/acme/${name}.json`, import.meta.url), 'utf8'),
  );
}

export interface AcmeOptions {
  /** Simulate a user who may not read droplets (403). */
  dropletsForbidden?: boolean;
  /** Simulate a user with an org role but no space role: lists come back empty, never 403. */
  noVisibleSpaces?: boolean;
  /** Simulate a 403 on the routes list (a token without the read scope). */
  routesForbidden?: boolean;
  /** Simulate a 403 on the processes list. */
  processesForbidden?: boolean;
  /** How Log Cache answers: normally, 404 (no access), or 503 (down). */
  logCache?: 'ok' | 'not-found' | 'down';
  /** Simulate a platform whose CF root advertises no log cache. */
  noLogCacheLink?: boolean;
  /**
   * orders-approuter's newest LOG page is full: 1000 app logs, one a minute
   * from an hour before the scan back, and no router log. Older pages are empty.
   */
  fullLogPage?: boolean;
  /** Simulate an app list that keeps failing (500), so the inventory is never read. */
  appsFailing?: boolean;
}

/** The app GUIDs Log Cache is asked about: the started non-workers with an HTTP route. */
export const ACME_TRAFFIC_APPS = {
  'orders-srv': 'a99a0000-0000-4000-8000-000000000001',
  'orders-approuter': 'a99a0000-0000-4000-8000-000000000002',
  'docs-static': 'a99a0000-0000-4000-8000-000000000005',
} as const;

function logCacheAnswer(options: AcmeOptions, key: string): Response {
  if (options.logCache === 'not-found') return new Response(null, { status: 404 });
  if (options.logCache === 'down') return new Response('upstream unavailable', { status: 503 });
  if (options.fullLogPage && key === 'orders-approuter-log') return jsonResponse(fullLogPage());
  return jsonResponse((fixture('log-cache') as Record<string, unknown>)[key]);
}

function fullLogPage(): unknown {
  const guid = ACME_TRAFFIC_APPS['orders-approuter'];
  const newest = BigInt(ACME.now.getTime() - 60 * 60_000) * 1_000_000n;
  const batch = Array.from({ length: 1000 }, (_, i) => ({
    timestamp: String(newest - BigInt(i) * 60_000_000_000n),
    source_id: guid,
    instance_id: '0',
    deprecated_tags: {},
    tags: { source_type: 'APP/PROC/WEB', app_name: 'orders-approuter' },
    log: { payload: 'dG9rZW4gY2FjaGUgcmVmcmVzaGVk', type: 'OUT' },
  }));
  return { envelopes: { batch } };
}

function root(options: AcmeOptions): unknown {
  const doc = fixture('root') as { links: Record<string, unknown> };
  if (options.noLogCacheLink) delete doc.links.log_cache;
  return doc;
}

function emptyPage(name: string): unknown {
  return { ...(fixture(name) as object), resources: [] };
}

interface Page {
  resources: { guid: string; relationships: Record<string, { data: { guid: string } | null }> }[];
  pagination: Record<string, unknown>;
}
const page = (name: string) => fixture(name) as Page;
const related = (resource: Page['resources'][number], kind: string) =>
  resource.relationships[kind]?.data?.guid;

/** One page of a list, keeping the resources that pass the filter. */
function onePage(name: string, keep: (resource: Page['resources'][number]) => boolean): unknown {
  const doc = page(name);
  const resources = doc.resources.filter(keep);
  return { ...doc, resources, pagination: { ...doc.pagination, next: null } };
}

/**
 * `scan --space dev`: the lists filtered by space GUID instead of org, with
 * only what the dev space holds.
 */
function addDevSpace(fake: FakeFetch): void {
  const isDev = (url: URL, path: string) =>
    url.host === ACME.api.host &&
    url.pathname === path &&
    url.searchParams.get('space_guids') === ACME_DEV_SPACE;
  const apps = [...page('apps-page1').resources, ...page('apps-page2').resources];
  const devApps = new Set(
    apps.filter((a) => related(a, 'space') === ACME_DEV_SPACE).map((a) => a.guid),
  );
  const ofDevApp = (r: Page['resources'][number]) => devApps.has(related(r, 'app') ?? '');
  fake
    .on(
      'GET',
      (url) => url.pathname === '/v3/spaces' && url.searchParams.get('names') === 'dev',
      () => jsonResponse(onePage('spaces', (s) => s.guid === ACME_DEV_SPACE)),
    )
    .on(
      'GET',
      (url) => isDev(url, '/v3/apps'),
      () =>
        jsonResponse({
          ...page('apps-page1'),
          resources: apps.filter((a) => devApps.has(a.guid)),
          pagination: { ...page('apps-page1').pagination, next: null },
        }),
    )
    .on(
      'GET',
      (url) => isDev(url, '/v3/droplets'),
      () => jsonResponse(onePage('droplets', ofDevApp)),
    )
    .on(
      'GET',
      (url) => isDev(url, '/v3/routes'),
      () => jsonResponse(onePage('routes', (r) => related(r, 'space') === ACME_DEV_SPACE)),
    )
    .on(
      'GET',
      (url) => isDev(url, '/v3/processes'),
      () => jsonResponse(onePage('processes', ofDevApp)),
    );
}

export function acmeFetch(options: AcmeOptions = {}): FakeFetch {
  const host = ACME.api.host;
  const org = ACME.orgGuid;
  const fake = new FakeFetch()
    .on('GET', `${host}/`, () => jsonResponse(root(options)))
    .on('GET', `${host}/v3/organizations?names=acme-prod&per_page=5000`, () =>
      jsonResponse(fixture('organizations')),
    )
    .on('GET', `${host}/v3/spaces?organization_guids=${org}&per_page=5000`, () =>
      jsonResponse(options.noVisibleSpaces ? emptyPage('spaces') : fixture('spaces')),
    )
    .on('GET', `${host}/v3/organizations?names=acme-prod%2Cother&per_page=5000`, () =>
      jsonResponse(fixture('organizations')),
    )
    .on('GET', `${host}/v3/apps?organization_guids=${org}&per_page=5000`, () =>
      options.appsFailing
        ? new Response('upstream unavailable', { status: 500 })
        : jsonResponse(fixture('apps-page1')),
    )
    .on('GET', `${host}/v3/apps?organization_guids=${org}&page=2&per_page=5000`, () =>
      jsonResponse(fixture('apps-page2')),
    )
    .on('GET', `${host}/v3/droplets?current=true&organization_guids=${org}&per_page=5000`, () =>
      options.dropletsForbidden
        ? jsonResponse(fixture('forbidden'), 403)
        : jsonResponse(fixture('droplets')),
    )
    .on('GET', `${host}${ACME_ROUTES_KEY}`, () =>
      options.routesForbidden
        ? jsonResponse(fixture('forbidden'), 403)
        : jsonResponse(fixture('routes')),
    )
    .on('GET', `${host}/v3/processes?organization_guids=${org}&per_page=5000&types=web`, () =>
      options.processesForbidden
        ? jsonResponse(fixture('forbidden'), 403)
        : jsonResponse(fixture('processes')),
    );
  // Newest-first LOG pages, and the ascending one-envelope read for the window start.
  for (const [name, guid] of Object.entries(ACME_TRAFFIC_APPS)) {
    const read = `${ACME.logCache}/api/v1/read/${guid}`;
    fake
      .on('GET', `${read}?descending=true&envelope_types=LOG&limit=1000`, () =>
        logCacheAnswer(options, `${name}-log`),
      )
      .on('GET', `${read}?limit=1`, () => logCacheAnswer(options, `${name}-oldest`));
  }
  addDevSpace(fake);
  if (options.fullLogPage) {
    fake.on(
      'GET',
      (url) => url.host === ACME.logCache && url.searchParams.has('end_time'),
      () => jsonResponse({ envelopes: { batch: [] } }),
    );
  }
  return fake;
}

/** "acme-prod" a week before ACME.now: the snapshot `scan --previous` carries forward. */
export const ACME_PREVIOUS_PATH = fileURLToPath(
  new URL('../fixtures/history/acme-previous.json', import.meta.url),
);

/** The previous snapshot as `--previous` loads it: validated, unknown fields dropped. */
export function acmePrevious(): Snapshot {
  return SnapshotSchema.parse(JSON.parse(readFileSync(ACME_PREVIOUS_PATH, 'utf8')));
}
