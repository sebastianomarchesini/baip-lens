import { describe, expect, it } from 'vitest';
import { collectWebProcesses, toHealthCheckType } from '../../src/collectors/processes.js';
import { SPACES_PER_REQUEST, collectRoutes, routeKind } from '../../src/collectors/routes.js';
import { CfClient } from '../../src/http/cfClient.js';
import { HttpClient } from '../../src/http/httpClient.js';
import { EgressPolicy, cfApiRule } from '../../src/net/allowlist.js';
import { FakeFetch, jsonResponse, noSleep } from '../support/fakeFetch.js';

const api = new URL('https://api.cf.example.org');

function client(fake: FakeFetch): CfClient {
  const policy = new EgressPolicy();
  policy.add(cfApiRule(api));
  const cf = new CfClient(
    new HttpClient({ policy, userAgent: 't', fetch: fake.fetch, sleep: noSleep }),
    api,
  );
  cf.setTokenProvider({
    source: 'test',
    getToken: () => Promise.resolve('t'),
    invalidate: () => {},
  });
  return cf;
}

const page = (resources: unknown[], included?: Record<string, unknown[]>) => ({
  pagination: { total_results: resources.length, next: null },
  resources,
  ...(included ? { included } : {}),
});

function cfRoute(
  guid: string,
  protocol: string | null,
  domainGuid: string,
  appGuids: string[] = [],
  spaceGuid = 's1',
) {
  return {
    guid,
    protocol,
    host: 'host-not-kept',
    path: '/path-not-kept',
    url: 'host-not-kept.example.org/path-not-kept',
    port: protocol === 'tcp' ? 61001 : null,
    destinations: appGuids.map((app, i) => ({ guid: `d-${guid}-${i}`, app: { guid: app } })),
    relationships: {
      space: { data: { guid: spaceGuid } },
      domain: { data: { guid: domainGuid } },
    },
  };
}

const domain = (guid: string, internal: boolean | null) => ({
  guid,
  name: `${guid}.example`,
  internal,
});

describe('routeKind', () => {
  const flags = new Map([
    ['external', false],
    ['internal', true],
  ]);
  const kind = (protocol: string | null, domainGuid: string) =>
    routeKind(cfRoute('r', protocol, domainGuid), flags);

  it('reads TCP from the route protocol', () => {
    expect(kind('tcp', 'external')).toBe('tcp');
  });

  it('reads internal from the domain, because an internal route still says http', () => {
    expect(kind('http', 'internal')).toBe('internal');
  });

  it('calls an http route on a known external domain http', () => {
    expect(kind('http', 'external')).toBe('http');
  });

  it('calls a route unknown when its domain was not returned or its protocol is missing', () => {
    expect(kind('http', 'not-included')).toBe('unknown');
    expect(kind(null, 'external')).toBe('unknown');
    expect(kind('quic', 'external')).toBe('unknown');
  });
});

describe('collectRoutes', () => {
  it('classifies routes from the included domains and drops host, path and URL', async () => {
    const fake = new FakeFetch().on('GET', /\/v3\/routes\?/, () =>
      jsonResponse(
        page(
          [
            cfRoute('r1', 'http', 'external', ['app-a']),
            cfRoute('r2', 'http', 'internal', ['app-b']),
            cfRoute('r3', 'http', 'no-flag', ['app-c']),
            cfRoute('r4', 'tcp', 'tcp-domain', ['app-d']),
          ],
          {
            domains: [
              domain('external', false),
              domain('internal', true),
              // A domain that does not say whether it is internal stays unknown.
              domain('no-flag', null),
            ],
          },
        ),
      ),
    );
    const { items, invalid } = await collectRoutes(client(fake), ['s1']);
    expect(invalid).toBe(0);
    expect(items).toEqual([
      { guid: 'r1', spaceGuid: 's1', kind: 'http', appGuids: ['app-a'] },
      { guid: 'r2', spaceGuid: 's1', kind: 'internal', appGuids: ['app-b'] },
      { guid: 'r3', spaceGuid: 's1', kind: 'unknown', appGuids: ['app-c'] },
      { guid: 'r4', spaceGuid: 's1', kind: 'tcp', appGuids: ['app-d'] },
    ]);
    expect(JSON.stringify(items)).not.toContain('not-kept');
    expect(fake.calls[0]?.url.searchParams.get('include')).toBe('domain');
  });

  it('asks by space, in sorted chunks, so a large org never builds an oversized URL', async () => {
    const spaces = Array.from(
      { length: 2 * SPACES_PER_REQUEST + 20 },
      (_, i) => `space-${String(1000 - i)}`,
    );
    const fake = new FakeFetch().on('GET', /\/v3\/routes\?/, () => jsonResponse(page([])));
    await collectRoutes(client(fake), spaces);
    const asked = fake.calls.map((c) => (c.url.searchParams.get('space_guids') ?? '').split(','));
    expect(asked.map((chunk) => chunk.length)).toEqual([50, 50, 20]);
    expect(asked.flat()).toEqual([...spaces].sort());
    expect(fake.calls.every((c) => !c.url.searchParams.has('organization_guids'))).toBe(true);
  });

  it('keeps a route shared into two chunks once, and each destination app once', async () => {
    const spaces = Array.from(
      { length: SPACES_PER_REQUEST + 1 },
      (_, i) => `s-${String(i).padStart(3, '0')}`,
    );
    const shared = cfRoute('shared', 'http', 'external', ['app-a', 'app-a', 'app-b']);
    const fake = new FakeFetch().on('GET', /\/v3\/routes\?/, () =>
      jsonResponse(page([shared], { domains: [domain('external', false)] })),
    );
    const { items } = await collectRoutes(client(fake), spaces);
    expect(fake.calls).toHaveLength(2);
    expect(items).toEqual([
      { guid: 'shared', spaceGuid: 's1', kind: 'http', appGuids: ['app-a', 'app-b'] },
    ]);
  });

  it('counts resources with an unexpected shape instead of failing', async () => {
    const fake = new FakeFetch().on('GET', /\/v3\/routes\?/, () =>
      jsonResponse(
        page([{ guid: 'broken' }, cfRoute('ok', 'http', 'external')], {
          domains: [domain('external', false)],
        }),
      ),
    );
    const { items, invalid } = await collectRoutes(client(fake), ['s1']);
    expect(invalid).toBe(1);
    expect(items.map((r) => r.guid)).toEqual(['ok']);
  });
});

describe('toHealthCheckType', () => {
  it('maps the legacy `none` to `process`, as Cloud Controller does', () => {
    expect(toHealthCheckType('none')).toBe('process');
  });

  it('keeps the documented types and turns anything else into unknown', () => {
    expect(['port', 'http', 'process', 'grpc'].map(toHealthCheckType)).toEqual([
      'port',
      'http',
      'process',
      'unknown',
    ]);
    expect(toHealthCheckType(undefined)).toBeNull();
    expect(toHealthCheckType(null)).toBeNull();
  });
});

describe('collectWebProcesses', () => {
  const cfProcess = (
    guid: string,
    type: string,
    instances: number,
    healthCheck: string | null,
  ) => ({
    guid,
    type,
    instances,
    command: 'java -jar app.jar --password=never-kept',
    updated_at: '2026-09-01T00:00:00Z',
    health_check: healthCheck === null ? null : { type: healthCheck, data: {} },
    relationships: { app: { data: { guid: `app-${guid}` } } },
  });

  it('asks for web processes only, keeps the facts the rule needs and never the command', async () => {
    const fake = new FakeFetch().on('GET', /\/v3\/processes\?/, () =>
      jsonResponse(
        page([
          cfProcess('p1', 'web', 2, 'port'),
          cfProcess('p2', 'web', 1, 'none'),
          cfProcess('p3', 'web', 0, null),
          // An API that ignored `types=web`.
          cfProcess('p4', 'worker', 3, 'process'),
        ]),
      ),
    );
    const { items } = await collectWebProcesses(client(fake), { orgGuid: 'o1' });
    expect(fake.calls[0]?.url.searchParams.get('types')).toBe('web');
    expect(fake.calls[0]?.url.searchParams.get('organization_guids')).toBe('o1');
    expect(items).toEqual([
      {
        guid: 'p1',
        appGuid: 'app-p1',
        type: 'web',
        instances: 2,
        healthCheckType: 'port',
        updatedAt: '2026-09-01T00:00:00Z',
      },
      {
        guid: 'p2',
        appGuid: 'app-p2',
        type: 'web',
        instances: 1,
        healthCheckType: 'process',
        updatedAt: '2026-09-01T00:00:00Z',
      },
      {
        guid: 'p3',
        appGuid: 'app-p3',
        type: 'web',
        instances: 0,
        healthCheckType: null,
        updatedAt: '2026-09-01T00:00:00Z',
      },
    ]);
    expect(JSON.stringify(items)).not.toContain('never-kept');
  });

  it('filters by space when the scan is limited to spaces', async () => {
    const fake = new FakeFetch().on('GET', /\/v3\/processes\?/, () => jsonResponse(page([])));
    await collectWebProcesses(client(fake), { orgGuid: 'o1', spaceGuids: ['s1', 's2'] });
    expect(fake.calls[0]?.url.searchParams.get('space_guids')).toBe('s1,s2');
    expect(fake.calls[0]?.url.searchParams.has('organization_guids')).toBe(false);
  });
});
