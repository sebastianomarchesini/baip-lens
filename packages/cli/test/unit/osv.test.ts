import { describe, expect, it } from 'vitest';
import { CheckSkipError } from '../../src/checks.js';
import {
  MAX_QUERY_PAGES,
  MAX_TABLE_BYTES,
  type OsvTables,
  type PackageRef,
  collectOsv,
  distinctPackages,
} from '../../src/collectors/osv.js';
import { HttpClient } from '../../src/http/httpClient.js';
import { OsvClient } from '../../src/http/osvClient.js';
import { rawListBytes } from '../../src/io/jsonSize.js';
import { RawAdvisorySchema, RawVulnerablePackageSchema } from '../../src/model/raw.js';
import { EgressPolicy } from '../../src/net/allowlist.js';
import {
  OSV_HOST,
  OSV_POISON,
  type OsvScript,
  QUERYBATCH,
  askedAdvisories,
  askedPackages,
  osvFetch,
  osvRecord,
  scriptOsv,
  sentQueries,
} from '../support/dependencyScript.js';
import { FakeFetch, jsonResponse, noSleep } from '../support/fakeFetch.js';
import { SUSPICIOUS } from '../support/leak.js';

/*
 * The lookup on OSV.dev against a scripted fetch, through the real client,
 * HTTP client and allow-list: which requests it makes, and that it hands
 * over everything or nothing.
 */

const A1 = 'GHSA-fake-0001-baip';
const A2 = 'GHSA-fake-0002-baip';
const A3 = 'GHSA-fake-0003-baip';
const MERGE = { name: 'baip-fixture-merge', version: '4.17.20' };
const ODATA = { name: '@baip-fixture/odata', version: '3.1.0' };
const SERVER = { name: 'baip-fixture-server', version: '2.4.1' };

function clientOn(fake: FakeFetch): OsvClient {
  return new OsvClient(
    new HttpClient({
      policy: new EgressPolicy(),
      userAgent: 'baip-lens/test',
      fetch: fake.fetch,
      sleep: noSleep,
      maxRetries: 2,
      concurrency: 8,
    }),
  );
}

const collect = (fake: FakeFetch, packages: readonly PackageRef[]): Promise<OsvTables> =>
  collectOsv(clientOn(fake), packages);

/** How a lookup that could not be completed is recorded: `[reason code, reason]`. */
async function skip(lookup: Promise<unknown>): Promise<[string, string]> {
  const error = await lookup.then(
    () => undefined,
    (reason: unknown) => reason,
  );
  if (!(error instanceof CheckSkipError)) {
    throw new Error(`expected a CheckSkipError, got ${String(error)}`);
  }
  return [error.reasonCode, error.reason];
}

const UNEXPECTED: [string, string] = ['error', 'api.osv.dev sent an unexpected answer'];

/** `count` packages with invented names, in name order. */
function bulk(count: number, version = '1.0.0'): PackageRef[] {
  return Array.from({ length: count }, (_, i) => ({
    name: `baip-bulk-${String(i).padStart(5, '0')}`,
    version,
  }));
}

const SAMPLE: OsvScript = {
  vulnerable: {
    'baip-fixture-merge@4.17.20': [A2, A1],
    '@baip-fixture/odata@3.1.0': [A1],
  },
  advisories: {
    [A1]: {
      aliases: ['CVE-2026-00002', 'CVE-2026-00001'],
      summary: 'Prototype pollution in baip-fixture-merge',
      cvssV3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      label: 'CRITICAL',
      affected: [
        { name: 'baip-fixture-merge', fixed: '4.17.21' },
        { name: '@baip-fixture/odata', fixed: '3.2.0' },
        { name: 'baip-fixture-other', fixed: '9.9.9' },
      ],
    },
    [A2]: { label: 'MODERATE', affected: [{ name: 'baip-fixture-merge' }] },
  },
};

const SAMPLE_TABLES: OsvTables = {
  advisories: [
    {
      id: A1,
      aliases: ['CVE-2026-00001', 'CVE-2026-00002'],
      summary: 'Prototype pollution in baip-fixture-merge',
      cvssV3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      label: 'CRITICAL',
    },
    { id: A2, aliases: [], summary: null, cvssV3: null, label: 'MODERATE' },
  ],
  vulnerablePackages: [
    { ...ODATA, advisories: [{ id: A1, fixed: ['3.2.0'] }] },
    {
      ...MERGE,
      advisories: [
        { id: A1, fixed: ['4.17.21'] },
        { id: A2, fixed: [] },
      ],
    },
  ],
};

describe('distinctPackages', () => {
  it('keeps each name and version once, sorted by name and then version in code point order', () => {
    expect(
      distinctPackages([
        { name: 'b', version: '1.0.0' },
        { name: 'a', version: '2.0.0' },
        { name: 'B', version: '1.0.0' },
        { name: 'a', version: '10.0.0' },
        { name: '@z/a', version: '1.0.0' },
        { name: 'a', version: '2.0.0' },
        { name: 'b', version: '1.0.0' },
      ]),
    ).toEqual([
      { name: '@z/a', version: '1.0.0' },
      { name: 'B', version: '1.0.0' },
      { name: 'a', version: '10.0.0' },
      { name: 'a', version: '2.0.0' },
      { name: 'b', version: '1.0.0' },
    ]);
  });
});

describe('collectOsv', () => {
  it('asks once about every package, then once for every advisory, and stores what it read', async () => {
    const fake = osvFetch(SAMPLE);
    const tables = await collect(fake, [SERVER, MERGE, ODATA, MERGE, SERVER]);
    expect(tables).toEqual(SAMPLE_TABLES);
    // One batch, the packages sorted and each once; then each advisory once, though two packages have one of them.
    expect(fake.calls.map((call) => `${call.method} ${call.url.pathname}`)).toEqual([
      'POST /v1/querybatch',
      `GET /v1/vulns/${A1}`,
      `GET /v1/vulns/${A2}`,
    ]);
    expect(askedPackages(fake)).toEqual([
      '@baip-fixture/odata@3.1.0',
      'baip-fixture-merge@4.17.20',
      'baip-fixture-server@2.4.1',
    ]);
    for (const row of tables.advisories)
      expect(RawAdvisorySchema.safeParse(row).success).toBe(true);
    for (const row of tables.vulnerablePackages) {
      expect(RawVulnerablePackageSchema.safeParse(row).success).toBe(true);
    }
    // Of a record nothing is kept but what the tables name.
    for (const never of OSV_POISON) expect(JSON.stringify(tables), never).not.toContain(never);
    expect(JSON.stringify(tables)).not.toContain('baip-fixture-other');
  });

  it('makes no request when there is nothing to look up', async () => {
    const fake = new FakeFetch();
    expect(await collect(fake, [])).toEqual({ advisories: [], vulnerablePackages: [] });
    expect(fake.calls).toEqual([]);
  });

  it('stores nothing for packages without advisories, having asked about each', async () => {
    const fake = osvFetch();
    expect(await collect(fake, [MERGE, ODATA])).toEqual({ advisories: [], vulnerablePackages: [] });
    expect(fake.calls).toHaveLength(1);
  });

  it('gives the same tables whatever the order of the packages and of the answers', async () => {
    const packages = [MERGE, ODATA, SERVER];
    const orders = [packages, [...packages].reverse(), [SERVER, MERGE, ODATA, ODATA]];
    for (const order of orders)
      expect(await collect(osvFetch(SAMPLE), order)).toEqual(SAMPLE_TABLES);

    // The advisory asked for first is answered last.
    const held: (() => void)[] = [];
    const slow = new FakeFetch()
      .on('POST', QUERYBATCH, (call) =>
        jsonResponse({
          results: sentQueries(call).map((query) => {
            const ids = SAMPLE.vulnerable?.[`${query.package.name}@${query.version}`];
            return ids === undefined ? {} : { vulns: ids.map((id) => ({ id })) };
          }),
        }),
      )
      .on(
        'GET',
        (url) => url.host === OSV_HOST,
        async (call) => {
          const id = call.url.pathname.slice('/v1/vulns/'.length);
          if (id === A1) await new Promise<void>((resolve) => held.push(resolve));
          else setTimeout(() => held.forEach((release) => release()), 5);
          return jsonResponse(osvRecord(id, SAMPLE.advisories?.[id]));
        },
      );
    expect(await collect(slow, packages)).toEqual(SAMPLE_TABLES);
    expect(askedAdvisories(slow)).toEqual([A1, A2]);
  });

  it('asks about 2,500 packages in three requests, the first of them alone', async () => {
    const packages = bulk(2_500);
    let inFlight = 0;
    const seen: number[] = [];
    const fake = new FakeFetch().on('POST', QUERYBATCH, async (call) => {
      inFlight += 1;
      seen.push(inFlight);
      await new Promise((resolve) => setTimeout(resolve, 5));
      inFlight -= 1;
      return jsonResponse({ results: sentQueries(call).map(() => ({})) });
    });
    // Handed over in another order than they are asked about.
    expect(await collect(fake, [...packages].reverse())).toEqual({
      advisories: [],
      vulnerablePackages: [],
    });
    expect(fake.calls).toHaveLength(3);
    const sizes = fake.calls.map((call) => sentQueries(call).length);
    expect(sizes).toEqual([1_000, 1_000, 500]);
    expect(askedPackages(fake)).toEqual(packages.map((item) => `${item.name}@${item.version}`));
    // Nothing else is in flight while the first request decides whether OSV.dev answers at all.
    expect(seen).toEqual([1, 1, 2]);
  });

  it('puts the answers of several batches together, each package with its own', async () => {
    const packages = bulk(2_001);
    const vulnerable = { 'baip-bulk-00000@1.0.0': [A1], 'baip-bulk-01000@1.0.0': [A2, A1] };
    const last = 'baip-bulk-02000@1.0.0';
    const fake = osvFetch({
      vulnerable: { ...vulnerable, [last]: [A3] },
      advisories: { [A1]: {}, [A2]: {}, [A3]: {} },
    });
    const tables = await collect(fake, packages);
    expect(
      tables.vulnerablePackages.map((row) => [row.name, row.advisories.map((a) => a.id)]),
    ).toEqual([
      ['baip-bulk-00000', [A1]],
      ['baip-bulk-01000', [A1, A2]],
      ['baip-bulk-02000', [A3]],
    ]);
    expect(tables.advisories.map((row) => row.id)).toEqual([A1, A2, A3]);
    expect(askedAdvisories(fake)).toEqual([A1, A2, A3]);
  });

  describe('a package with more advisories than one answer holds', () => {
    /** Answers `pages` pages for baip-fixture-merge, one id each; every other package is clean. */
    function paged(pages: number): FakeFetch {
      const advisories = Object.fromEntries(
        Array.from({ length: pages }, (_, i) => [`GHSA-fake-page-${i}`, {}]),
      );
      const fake = new FakeFetch().on('POST', QUERYBATCH, (call) =>
        jsonResponse({
          results: sentQueries(call).map((query) => {
            if (query.package.name !== MERGE.name) return {};
            const page = query.page_token === undefined ? 0 : Number(query.page_token.slice(5));
            return {
              vulns: [{ id: `GHSA-fake-page-${page}` }],
              ...(page + 1 < pages ? { next_page_token: `page-${page + 1}` } : {}),
            };
          }),
        }),
      );
      return scriptOsv(fake, { advisories });
    }

    it('asks for the further pages of that package only, and keeps every id', async () => {
      const fake = paged(3);
      const tables = await collect(fake, [ODATA, MERGE, SERVER]);
      expect(tables.vulnerablePackages).toEqual([
        {
          ...MERGE,
          advisories: [0, 1, 2].map((page) => ({ id: `GHSA-fake-page-${page}`, fixed: [] })),
        },
      ]);
      const batches = fake.calls.filter((call) => call.method === 'POST').map(sentQueries);
      expect(batches.map((queries) => queries.map((q) => [q.package.name, q.page_token]))).toEqual([
        [
          [ODATA.name, undefined],
          [MERGE.name, undefined],
          [SERVER.name, undefined],
        ],
        [[MERGE.name, 'page-1']],
        [[MERGE.name, 'page-2']],
      ]);
    });

    it(`reads ${MAX_QUERY_PAGES} pages, and gives up on a package that never ends`, async () => {
      const fits = paged(MAX_QUERY_PAGES);
      const tables = await collect(fits, [MERGE]);
      expect(tables.vulnerablePackages[0]?.advisories).toHaveLength(MAX_QUERY_PAGES);
      expect(fits.calls.filter((call) => call.method === 'POST')).toHaveLength(MAX_QUERY_PAGES);

      const endless = paged(MAX_QUERY_PAGES + 1);
      expect(await skip(collect(endless, [MERGE]))).toEqual(UNEXPECTED);
      // Not one page more, and no advisory was asked for.
      expect(endless.calls).toHaveLength(MAX_QUERY_PAGES);
    });
  });

  describe('advisories that were withdrawn', () => {
    const withdrawn = { withdrawn: '2026-09-15T00:00:00Z', label: 'CRITICAL' };

    it('are not stored, and count for nothing', async () => {
      const fake = osvFetch({
        vulnerable: {
          'baip-fixture-merge@4.17.20': [A1, A2],
          'baip-fixture-server@2.4.1': [A2],
        },
        advisories: { [A1]: { label: 'LOW' }, [A2]: withdrawn },
      });
      const tables = await collect(fake, [MERGE, SERVER]);
      expect(tables).toEqual({
        advisories: [{ id: A1, aliases: [], summary: null, cvssV3: null, label: 'LOW' }],
        // The server has no other advisory, so it is not a vulnerable package.
        vulnerablePackages: [{ ...MERGE, advisories: [{ id: A1, fixed: [] }] }],
      });
      expect(JSON.stringify(tables)).not.toContain(A2);
    });
  });

  describe('the fixed versions of an advisory', () => {
    it('are those named for the package itself: sorted by version, each once', async () => {
      const fake = osvFetch({
        vulnerable: {
          'baip-fixture-merge@4.17.20': [A1],
          'baip-fixture-merge@3.10.1': [A1],
          '@baip-fixture/odata@3.1.0': [A1],
        },
        advisories: {
          [A1]: {
            affected: [
              { name: 'baip-fixture-merge', fixed: '4.17.21' },
              { name: 'baip-fixture-merge', fixed: '10.0.1' },
              { name: 'baip-fixture-merge', fixed: '4.2.0' },
              { name: 'baip-fixture-merge', fixed: '4.17.21' },
              { name: 'baip-fixture-merge', fixed: '4.17.21-rc.1' },
              { name: 'baip-fixture-merge', fixed: '3.10.2' },
              { name: 'baip-fixture-other', fixed: '1.0.0' },
              { name: '@baip-fixture/odata' },
            ],
          },
        },
      });
      const tables = await collect(fake, [MERGE, ODATA, { ...MERGE, version: '3.10.1' }]);
      const fixed = ['3.10.2', '4.2.0', '4.17.21', '4.17.21-rc.1', '10.0.1'];
      expect(tables.vulnerablePackages).toEqual([
        { ...ODATA, advisories: [{ id: A1, fixed: [] }] },
        { ...MERGE, version: '3.10.1', advisories: [{ id: A1, fixed }] },
        { ...MERGE, advisories: [{ id: A1, fixed }] },
      ]);
    });

    it('keeps the ten highest when an advisory names more', async () => {
      const affected = Array.from({ length: 14 }, (_, i) => ({
        name: 'baip-fixture-merge',
        fixed: `${i + 1}.0.1`,
      }));
      const fake = osvFetch({
        vulnerable: { 'baip-fixture-merge@4.17.20': [A1] },
        advisories: { [A1]: { affected: affected.reverse() } },
      });
      const tables = await collect(fake, [MERGE]);
      expect(tables.vulnerablePackages[0]?.advisories[0]?.fixed).toEqual(
        Array.from({ length: 10 }, (_, i) => `${i + 5}.0.1`),
      );
    });
  });

  describe('the summary of an advisory', () => {
    const JWT = `eyJhbGciOiJSUzI1NiJ9.${'eyJzdWIiOiJQT0lTT04ifQ'.repeat(2)}.c2lnbmF0dXJlLVBPSVNPTg`;

    async function stored(summary: string): Promise<string | null | undefined> {
      const fake = osvFetch({
        vulnerable: { 'baip-fixture-merge@4.17.20': [A1] },
        advisories: { [A1]: { summary } },
      });
      return (await collect(fake, [MERGE])).advisories[0]?.summary;
    }

    it('is cleaned before it is stored: no address, no token, no control character', async () => {
      const summary = await stored(
        `Reported by jane.poison@example.com:\u001b[31m token ${JWT},\r\n see ` +
          `https://ci:POISON_osv_pw@poison-osv.example.com/x \u202eand\u200b more`,
      );
      expect(summary).toBe(
        'Reported by [e-mail]: token [redacted-token], see https://poison-osv.example.com/x and more',
      );
      for (const { name, pattern } of SUSPICIOUS)
        expect(pattern.test(summary ?? ''), name).toBe(false);
    });

    it('is cut to 200 characters', async () => {
      const summary = await stored(`Denial of service ${'through a very long input '.repeat(40)}`);
      expect(summary).toHaveLength(200);
      expect(summary?.endsWith('…')).toBe(true);
    });

    it('is null when nothing visible is left of it', async () => {
      expect(await stored(' \u200b\u202e\t\n ')).toBeNull();
      expect(await stored('')).toBeNull();
    });
  });

  describe('when OSV.dev cannot be reached', () => {
    const down = (): never => {
      throw new TypeError('fetch failed', {
        cause: Object.assign(new Error('connect ECONNREFUSED POISON_osv_address'), {
          code: 'ECONNREFUSED',
        }),
      });
    };

    it('gives up after the first request and its two repeats, however many packages there are', async () => {
      const fake = new FakeFetch().on('POST', QUERYBATCH, down);
      expect(await skip(collect(fake, bulk(2_500)))).toEqual([
        'unavailable',
        'api.osv.dev could not be reached',
      ]);
      // Three batches would have been asked: only the first was, three times.
      expect(fake.calls).toHaveLength(3);
      expect(new Set(fake.calls.map((call) => call.body)).size).toBe(1);
    });

    it('starts no further request once one failed, and stores nothing of what was answered', async () => {
      const ids = Array.from({ length: 60 }, (_, i) => `GHSA-fake-${String(i).padStart(4, '0')}`);
      const fake = new FakeFetch()
        .on('POST', QUERYBATCH, (call) =>
          jsonResponse({
            results: sentQueries(call).map((_, i) => ({ vulns: [{ id: ids[i] }] })),
          }),
        )
        .on('GET', (url) => url.pathname === `/v1/vulns/${ids[10]}`, down)
        .on(
          'GET',
          (url) => url.host === OSV_HOST,
          async (call) => {
            // An answer takes a moment; a refused connection does not.
            await new Promise((resolve) => setTimeout(resolve, 5));
            return jsonResponse(osvRecord(call.url.pathname.slice('/v1/vulns/'.length)));
          },
        );
      expect(await skip(collect(fake, bulk(60)))).toEqual([
        'unavailable',
        'api.osv.dev could not be reached',
      ]);
      const asked = askedAdvisories(fake);
      // The eleventh advisory was tried three times. Eight requests are in flight at a time:
      // the first eight were answered, and of the second eight none was followed by another.
      expect(asked.filter((id) => id === ids[10])).toHaveLength(3);
      expect(new Set(asked).size).toBeLessThanOrEqual(16);
      expect(asked.every((id) => ids.indexOf(id) < 16)).toBe(true);
    });
  });

  describe('when OSV.dev answers with something else than was asked', () => {
    it.each([
      ['a 500 to the query', 500, 'api.osv.dev answered HTTP 500', 3],
      ['a 400 to the query', 400, 'api.osv.dev answered HTTP 400', 1],
      ['a 403 to the query', 403, 'api.osv.dev answered HTTP 403', 1],
    ])('records %s by its status', async (_name, status, reason, calls) => {
      const fake = new FakeFetch().on(
        'POST',
        QUERYBATCH,
        jsonResponse({ code: 3, message: 'POISON_osv_message' }, status),
      );
      expect(await skip(collect(fake, [MERGE]))).toEqual(['error', reason]);
      expect(fake.calls).toHaveLength(calls);
    });

    it('records a 404 for an advisory it was just told about, and keeps nothing of the others', async () => {
      const fake = osvFetch({
        vulnerable: { 'baip-fixture-merge@4.17.20': [A1, A2] },
        advisories: { [A1]: { label: 'HIGH' } },
      });
      expect(await skip(collect(fake, [MERGE]))).toEqual([
        'error',
        'api.osv.dev answered HTTP 404',
      ]);
    });

    it('records an answer it does not understand as that, never with the text of the answer', async () => {
      const page = new FakeFetch().on(
        'POST',
        QUERYBATCH,
        new Response('<html>POISON_osv_page</html>', { status: 200 }),
      );
      expect(await skip(collect(page, [MERGE]))).toEqual(UNEXPECTED);
      const other = scriptOsv(
        new FakeFetch().on(
          'GET',
          `${OSV_HOST}/v1/vulns/${A1}`,
          jsonResponse(osvRecord(A2, { label: 'HIGH' })),
        ),
        { vulnerable: { 'baip-fixture-merge@4.17.20': [A1] } },
      );
      expect(await skip(collect(other, [MERGE]))).toEqual(UNEXPECTED);
    });

    it('records an error of its own as one, without its message', async () => {
      // A name that is not one never reaches a request: the client refuses to send it.
      const fake = osvFetch();
      expect(await skip(collect(fake, [{ name: '../POISON_osv_name', version: '1.0.0' }]))).toEqual(
        ['error', 'the lookup on api.osv.dev stopped with an unexpected error'],
      );
      expect(fake.calls).toEqual([]);
    });
  });

  describe('more than a snapshot holds', () => {
    /** Every package gets the ids `ids(i)` names for it; any advisory asked for is an empty record. */
    function flood(ids: (index: number) => string[]): FakeFetch {
      let asked = 0;
      return new FakeFetch()
        .on('POST', QUERYBATCH, (call) =>
          jsonResponse({
            results: sentQueries(call).map(() => ({ vulns: ids(asked++).map((id) => ({ id })) })),
          }),
        )
        .on(
          'GET',
          (url) => url.host === OSV_HOST,
          (call) => jsonResponse(osvRecord(call.url.pathname.slice('/v1/vulns/'.length))),
        );
    }

    const many = (count: number) => () =>
      Array.from({ length: count }, (_, i) => `GHSA-fake-${String(i).padStart(4, '0')}`);

    // Heavily reported packages have well over a hundred advisories: one of them must not
    // switch the whole lookup off.
    it.each([201, 1_000])('stores %i advisories of one package', async (count) => {
      const fits = await collect(flood(many(count)), [MERGE]);
      expect(fits.vulnerablePackages).toHaveLength(1);
      expect(fits.vulnerablePackages[0]?.advisories).toHaveLength(count);
      expect(fits.advisories).toHaveLength(count);
      expect(RawVulnerablePackageSchema.safeParse(fits.vulnerablePackages[0]).success).toBe(true);
    });

    it('stores nothing when one package has 1,001 advisories', async () => {
      const over = flood(many(1_001));
      expect(await skip(collect(over, [MERGE]))).toEqual([
        'error',
        'more than 1,000 advisories for one package',
      ]);
      // Known from the first answer: no advisory was asked for.
      expect(over.calls).toHaveLength(1);
    });

    it('stores nothing when the packages have more than 20,000 advisories between them', async () => {
      // 101 packages with 200 advisories each, none shared.
      const fake = flood((index) =>
        Array.from({ length: 200 }, (_, i) => `GHSA-fake-${index}-${String(i).padStart(3, '0')}`),
      );
      expect(await skip(collect(fake, bulk(101)))).toEqual([
        'error',
        'more than 20,000 advisories',
      ]);
      expect(fake.calls).toHaveLength(1);
    });

    it('stores nothing when the advisories of the packages would not fit, before it asks for one', async () => {
      // The same 200 advisories for each of 1,400 packages: 280,000 lines of a snapshot at the very least.
      const shared = Array.from(
        { length: 200 },
        (_, i) => `GHSA-fake-${String(i).padStart(4, '0')}`,
      );
      const fake = flood(() => shared);
      expect(await skip(collect(fake, bulk(1_400)))).toEqual([
        'error',
        'api.osv.dev sent more than a snapshot can hold',
      ]);
      expect(fake.calls.every((call) => call.method === 'POST')).toBe(true);
      expect(fake.calls).toHaveLength(2);
    });

    it('stores nothing when the tables would take more than 16 MiB as a snapshot writes them', async () => {
      // Each advisory with twenty aliases of a hundred characters and a summary of 200.
      const aliases = (index: number) =>
        Array.from({ length: 20 }, (_, i) => `CVE-${index}-${i}-${'9'.repeat(100)}`.slice(0, 100));
      const record = (id: string, index: number) =>
        osvRecord(id, { aliases: aliases(index), summary: 'word '.repeat(60) });
      const big = (count: number) => {
        const ids = Array.from(
          { length: count },
          (_, i) => `GHSA-fake-${String(i).padStart(5, '0')}`,
        );
        return new FakeFetch()
          .on('POST', QUERYBATCH, (call) =>
            jsonResponse({
              results: sentQueries(call).map((query) => ({
                vulns: [{ id: ids[Number(query.package.name.slice(-5))] }],
              })),
            }),
          )
          .on(
            'GET',
            (url) => url.host === OSV_HOST,
            (call) => {
              const id = call.url.pathname.slice('/v1/vulns/'.length);
              return jsonResponse(record(id, Number(id.slice(-5))));
            },
          );
      };
      const fits = await collect(big(5_000), bulk(5_000));
      const bytes = rawListBytes(fits.advisories) + rawListBytes(fits.vulnerablePackages);
      expect(bytes).toBeGreaterThan(0.8 * MAX_TABLE_BYTES);
      expect(bytes).toBeLessThanOrEqual(MAX_TABLE_BYTES);
      expect(fits.advisories).toHaveLength(5_000);

      expect(await skip(collect(big(6_500), bulk(6_500)))).toEqual([
        'error',
        'api.osv.dev sent more than a snapshot can hold',
      ]);
    }, 60_000);

    it('refuses more packages than a scan keeps, before anything is sent', async () => {
      const fake = osvFetch();
      expect(await skip(collect(fake, bulk(20_001)))).toEqual([
        'error',
        'more than 20,000 packages to look up',
      ]);
      expect(fake.calls).toEqual([]);
    });

    it('asks about 20,000 packages in twenty requests', async () => {
      const fake = osvFetch();
      expect(await collect(fake, bulk(20_000))).toEqual({ advisories: [], vulnerablePackages: [] });
      expect(fake.calls).toHaveLength(20);
    }, 60_000);
  });
});
