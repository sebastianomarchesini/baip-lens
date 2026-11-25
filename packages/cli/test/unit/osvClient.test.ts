import { describe, expect, it } from 'vitest';
import { HttpClient, type HttpRequest } from '../../src/http/httpClient.js';
import { MAX_BATCH_QUERIES, OsvClient, OsvError } from '../../src/http/osvClient.js';
import { EgressPolicy } from '../../src/net/allowlist.js';
import {
  OSV_POISON,
  QUERYBATCH,
  osvFetch,
  osvRecord,
  sentQueries,
} from '../support/dependencyScript.js';
import { FakeFetch, jsonResponse, noSleep } from '../support/fakeFetch.js';

/*
 * The OSV.dev client against a scripted fetch, through the real HTTP client
 * and the allow-list as the scan builds them: what is sent, and what is made
 * of every answer, the wrong ones above all.
 */

const MIB = 1024 * 1024;
const ID = 'GHSA-fake-0001-baip';
const VULN = (id: string): string => `api.osv.dev/v1/vulns/${id}`;

function client(fake: FakeFetch): OsvClient {
  const http = new HttpClient({
    policy: new EgressPolicy(),
    userAgent: 'baip-lens/test',
    fetch: fake.fetch,
    sleep: noSleep,
    maxRetries: 2,
  });
  return new OsvClient(http);
}

/** The failure a request ends in, as `[failure, status, message]`. */
async function failure(request: Promise<unknown>): Promise<unknown[]> {
  const error = await request.then(
    () => undefined,
    (reason: unknown) => reason,
  );
  if (!(error instanceof OsvError)) throw new Error(`expected an OsvError, got ${String(error)}`);
  return [error.failure, error.status, error.message];
}

const UNEXPECTED = ['unexpected', undefined, 'api.osv.dev sent an unexpected answer'];
const UNREACHABLE = ['unreachable', undefined, 'api.osv.dev could not be reached'];

/** The headers and the first bytes of an answer, and then the connection fails with `error`. */
function brokenAnswer(error: Error): Response {
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"results":[{'));
      },
      pull(controller) {
        controller.error(error);
      },
    }),
  );
}
const QUERY = [{ name: 'baip-fixture-merge', version: '4.17.20' }];

describe('OsvClient.queryBatch', () => {
  it('posts the names and versions of the packages, and nothing else', async () => {
    const fake = osvFetch({ vulnerable: { 'baip-fixture-merge@4.17.20': [ID] } });
    const results = await client(fake).queryBatch([
      { name: '@baip-fixture/odata', version: '3.1.0' },
      { name: 'baip-fixture-merge', version: '4.17.20' },
    ]);
    expect(results).toEqual([{ ids: [] }, { ids: [ID] }]);
    expect(fake.calls).toHaveLength(1);
    const call = fake.calls[0]!;
    expect([call.method, call.url.href]).toEqual(['POST', 'https://api.osv.dev/v1/querybatch']);
    expect(call.body).toBe(
      '{"queries":[{"package":{"name":"@baip-fixture/odata","ecosystem":"npm"},"version":"3.1.0"},' +
        '{"package":{"name":"baip-fixture-merge","ecosystem":"npm"},"version":"4.17.20"}]}',
    );
    // No credential, no cookie, and no redirect is followed.
    expect(call.headers).toEqual({
      accept: 'application/json',
      'content-type': 'application/json',
      'user-agent': 'baip-lens/test',
    });
    expect(call.redirect).toBe('manual');
  });

  it('keeps the results in the order of the queries, an empty object being "none"', async () => {
    const fake = new FakeFetch().on('POST', QUERYBATCH, () =>
      jsonResponse({
        results: [
          { vulns: [{ id: 'GHSA-fake-0002-baip', modified: 'x' }, { id: ID }] },
          {},
          { vulns: [] },
          { vulns: [{ id: 'MAL-0000-0001' }] },
        ],
      }),
    );
    const queries = ['a', 'b', 'c', 'd'].map((name) => ({ name, version: '1.0.0' }));
    expect(await client(fake).queryBatch(queries)).toEqual([
      { ids: ['GHSA-fake-0002-baip', ID] },
      { ids: [] },
      { ids: [] },
      { ids: ['MAL-0000-0001'] },
    ]);
  });

  // OSV.dev answers every query it was sent. A 200 without `results` comes from something in
  // between (a gateway, a portal), and "no advisory" must not be read into it.
  it.each([
    ['an empty object', {}],
    ['the words of a gateway', { status: 'blocked', message: 'POISON_osv_gateway' }],
    ['an error in the shape of the API', { code: 13, message: 'internal' }],
    ['results that are null', { results: null }],
  ])('refuses %s without `results` as a whole: it is not "no advisory"', async (_name, body) => {
    const fake = new FakeFetch().on('POST', QUERYBATCH, jsonResponse(body));
    expect(await failure(client(fake).queryBatch([...QUERY, ...QUERY]))).toEqual(UNEXPECTED);
    expect(fake.calls).toHaveLength(1);
  });

  it('sends a page token with the query it belongs to, and hands back the next one', async () => {
    const fake = new FakeFetch().on('POST', QUERYBATCH, (call) =>
      jsonResponse({
        results: sentQueries(call).map((query) =>
          query.page_token === 'page-2'
            ? { vulns: [{ id: ID }], next_page_token: '' }
            : { vulns: [{ id: 'GHSA-fake-0002-baip' }], next_page_token: 'page-2' },
        ),
      }),
    );
    const osv = client(fake);
    expect(await osv.queryBatch(QUERY)).toEqual([
      { ids: ['GHSA-fake-0002-baip'], nextPageToken: 'page-2' },
    ]);
    // An empty token is none.
    expect(await osv.queryBatch([{ ...QUERY[0]!, pageToken: 'page-2' }])).toEqual([{ ids: [ID] }]);
    expect(sentQueries(fake.calls[1]!)).toEqual([
      {
        package: { name: 'baip-fixture-merge', ecosystem: 'npm' },
        version: '4.17.20',
        page_token: 'page-2',
      },
    ]);
  });

  it('makes no request for no query', async () => {
    const fake = new FakeFetch();
    expect(await client(fake).queryBatch([])).toEqual([]);
    expect(fake.calls).toEqual([]);
  });

  it('refuses a batch OSV.dev would refuse, before anything is sent', async () => {
    const fake = osvFetch();
    const queries = Array.from({ length: MAX_BATCH_QUERIES + 1 }, (_, i) => ({
      name: `baip-bulk-${i}`,
      version: '1.0.0',
    }));
    await expect(client(fake).queryBatch(queries)).rejects.toThrow('too many queries');
    expect(await client(fake).queryBatch(queries.slice(1))).toHaveLength(MAX_BATCH_QUERIES);
    expect(fake.calls).toHaveLength(1);
  });

  it.each([
    ['a name that is a path', { name: '../etc/passwd', version: '1.0.0' }],
    ['a name with a blank', { name: 'baip fixture', version: '1.0.0' }],
    ['a name of 215 characters', { name: 'n'.repeat(215), version: '1.0.0' }],
    ['an empty name', { name: '', version: '1.0.0' }],
    ['a range', { name: 'baip-fixture-merge', version: '^4.17.0' }],
    [
      'an address as the version',
      { name: 'baip-fixture-merge', version: 'https://x.example/a.tgz' },
    ],
    [
      'a version of 65 characters',
      { name: 'baip-fixture-merge', version: `1.0.0-${'9'.repeat(59)}` },
    ],
  ])('refuses %s, before anything is sent', async (_name, query) => {
    const fake = osvFetch();
    await expect(client(fake).queryBatch([...QUERY, query])).rejects.toThrow(
      'not a package name and version that can be looked up',
    );
    expect(fake.calls).toEqual([]);
  });

  it('reports the status of an answer that is not 200, never its text', async () => {
    const fake = new FakeFetch().on(
      'POST',
      QUERYBATCH,
      jsonResponse({ code: 3, message: 'error in query at index 0: POISON_osv_message' }, 400),
    );
    expect(await failure(client(fake).queryBatch(QUERY))).toEqual([
      'status',
      400,
      'api.osv.dev answered HTTP 400',
    ]);
    // Not worth asking again.
    expect(fake.calls).toHaveLength(1);
  });

  it.each([
    [204, (): Response => new Response(null, { status: 204 })],
    [206, (body: unknown): Response => jsonResponse(body, 206)],
    [201, (body: unknown): Response => jsonResponse(body, 201)],
  ])('reads no answer but a 200: a %i is reported by its status', async (status, respond) => {
    const reported = ['status', status, `api.osv.dev answered HTTP ${status}`];
    const fake = new FakeFetch().on('POST', QUERYBATCH, () => respond({ results: [{}] }));
    expect(await failure(client(fake).queryBatch(QUERY))).toEqual(reported);
    const record = new FakeFetch().on('GET', VULN(ID), () => respond(osvRecord(ID)));
    expect(await failure(client(record).advisory(ID, new Set()))).toEqual(reported);
  });

  it('asks again twice after a server error, then reports it', async () => {
    const fake = new FakeFetch().on('POST', QUERYBATCH, new Response('busy', { status: 503 }));
    expect(await failure(client(fake).queryBatch(QUERY))).toEqual([
      'status',
      503,
      'api.osv.dev answered HTTP 503',
    ]);
    expect(fake.calls).toHaveLength(3);
    const recovering = new FakeFetch()
      .on('POST', QUERYBATCH, new Response('busy', { status: 429 }), 2)
      .on('POST', QUERYBATCH, jsonResponse({ results: [{}] }));
    expect(await client(recovering).queryBatch(QUERY)).toEqual([{ ids: [] }]);
    expect(recovering.calls).toHaveLength(3);
  });

  it('does not follow a redirect', async () => {
    const fake = new FakeFetch().on(
      'POST',
      QUERYBATCH,
      new Response(null, {
        status: 307,
        headers: { location: 'https://evil.example/v1/querybatch' },
      }),
    );
    expect(await failure(client(fake).queryBatch(QUERY))).toEqual([
      'status',
      307,
      'api.osv.dev answered HTTP 307',
    ]);
    expect(fake.calls.map((call) => call.url.host)).toEqual(['api.osv.dev']);
  });

  it('says that OSV.dev could not be reached after three tries, without the cause', async () => {
    const fake = new FakeFetch().on('POST', QUERYBATCH, () => {
      throw new TypeError('fetch failed', {
        cause: Object.assign(new Error('getaddrinfo ENOTFOUND POISON_osv_host'), {
          code: 'ENOTFOUND',
        }),
      });
    });
    expect(await failure(client(fake).queryBatch(QUERY))).toEqual([
      'unreachable',
      undefined,
      'api.osv.dev could not be reached',
    ]);
    expect(fake.calls).toHaveLength(3);
  });

  it.each([
    ['is reset', () => new TypeError('terminated', { cause: new Error('POISON_osv_cause') })],
    [
      'runs out of time',
      () => new DOMException('The operation was aborted due to timeout', 'TimeoutError'),
    ],
  ])('says the same when the connection %s while the answer is read', async (_name, error) => {
    const fake = new FakeFetch().on('POST', QUERYBATCH, () => brokenAnswer(error()));
    expect(await failure(client(fake).queryBatch(QUERY))).toEqual(UNREACHABLE);
    expect(fake.calls).toHaveLength(3);
    const record = new FakeFetch().on('GET', VULN(ID), () => brokenAnswer(error()));
    expect(await failure(client(record).advisory(ID, new Set()))).toEqual(UNREACHABLE);
    expect(record.calls).toHaveLength(3);
  });

  it('reads the answer of the second try when the first broke off', async () => {
    const fake = new FakeFetch()
      .on('POST', QUERYBATCH, () => brokenAnswer(new TypeError('terminated')), 1)
      .on('POST', QUERYBATCH, jsonResponse({ results: [{ vulns: [{ id: ID }] }] }));
    expect(await client(fake).queryBatch(QUERY)).toEqual([{ ids: [ID] }]);
    expect(fake.calls).toHaveLength(2);
  });

  it('gives a batch 40 seconds, and an advisory the time of the lookup', async () => {
    const seen: HttpRequest[] = [];
    const recording = new OsvClient({
      request: (request) => {
        seen.push(request);
        const text = request.method === 'POST' ? '{"results":[{}]}' : `{"id":"${ID}"}`;
        return Promise.resolve({ url: request.url, status: 200, headers: new Headers(), text });
      },
    });
    await recording.queryBatch(QUERY);
    await recording.advisory(ID, new Set());
    // OSV.dev allows itself 35 seconds for a batch; an advisory has no time of its own.
    expect(seen.map((request) => [request.method ?? 'GET', request.timeoutMs])).toEqual([
      ['POST', 40_000],
      ['GET', undefined],
    ]);
    // Nothing turns the repeats off either.
    expect(seen.map((request) => [request.retry, request.retryOn])).toEqual([
      [undefined, undefined],
      [undefined, undefined],
    ]);
    expect(seen.map((request) => request.maxBytes)).toEqual([32 * MIB, 8 * MIB]);
  });

  it.each([
    ['text that is not JSON', new Response('<html>POISON_osv_page</html>', { status: 200 })],
    ['an empty body', new Response('', { status: 200 })],
    ['a list', jsonResponse([{}])],
    ['results that are not a list', jsonResponse({ results: { 0: {} } })],
    ['one result too few', jsonResponse({ results: [] })],
    ['one result too many', jsonResponse({ results: [{}, {}] })],
    ['a result that is not an object', jsonResponse({ results: ['x'] })],
    ['advisories that are not a list', jsonResponse({ results: [{ vulns: 'x' }] })],
    ['advisories that are null', jsonResponse({ results: [{ vulns: null }] })],
    ['an advisory without an id', jsonResponse({ results: [{ vulns: [{ modified: 'x' }] }] })],
    ['an id that is not text', jsonResponse({ results: [{ vulns: [{ id: 7 }] }] })],
    ['an id with a slash', jsonResponse({ results: [{ vulns: [{ id: 'GHSA/../x' }] }] })],
    ['an id of two dots', jsonResponse({ results: [{ vulns: [{ id: '..' }] }] })],
    ['an id with a query', jsonResponse({ results: [{ vulns: [{ id: 'GHSA-1?x=1' }] }] })],
    ['an id of 101 characters', jsonResponse({ results: [{ vulns: [{ id: 'G'.repeat(101) }] }] })],
    ['a page token that is not text', jsonResponse({ results: [{ next_page_token: 7 }] })],
    [
      'a page token of 4,097 characters',
      jsonResponse({ results: [{ next_page_token: 't'.repeat(4_097) }] }),
    ],
    [
      'an answer that says it is larger than 32 MiB',
      jsonResponse({ results: [{}] }, 200, { 'content-length': String(32 * MIB + 1) }),
    ],
  ])('refuses %s as a whole', async (_name, response) => {
    const fake = new FakeFetch().on('POST', QUERYBATCH, response);
    expect(await failure(client(fake).queryBatch(QUERY))).toEqual(UNEXPECTED);
    expect(fake.calls).toHaveLength(1);
  });

  /*
   * What an answer may cost to parse (docs/data-sources.md §12.3). The part
   * that goes past a limit sits under a key the client does not read, so
   * nothing but the look at the shape of the text can refuse it; next to
   * each, the largest answer that is still read.
   */
  describe('the shape of an answer, before it is parsed', () => {
    const nested = (levels: number): string => `${'['.repeat(levels)}${']'.repeat(levels)}`;
    const values = (count: number): string => `[${'0,'.repeat(count - 1)}0]`;
    const keys = (count: number): string =>
      `{${Array.from({ length: count }, (_, i) => `"k${i}":0`).join(',')}}`;
    const answer = (extra: string): Response =>
      new Response(`{"results":[{}],"x":${extra}}`, { status: 200 });

    it.each([
      // The answer itself is one level.
      ['16 levels of nesting', nested(15)],
      // The answer, `results`, its one result, the key `x` and its list are six values.
      ['1,000,000 values', values(999_994)],
      ['an object of 100 keys', keys(100)],
    ])('reads an answer with %s', async (_name, extra) => {
      const fake = new FakeFetch().on('POST', QUERYBATCH, () => answer(extra));
      expect(await client(fake).queryBatch(QUERY)).toEqual([{ ids: [] }]);
    });

    it.each([
      ['17 levels of nesting', nested(16)],
      ['1,000,001 values', values(999_995)],
      ['an object of 101 keys', keys(101)],
    ])('refuses an answer with %s as a whole', async (_name, extra) => {
      const fake = new FakeFetch().on('POST', QUERYBATCH, () => answer(extra));
      expect(await failure(client(fake).queryBatch(QUERY))).toEqual(UNEXPECTED);
      expect(fake.calls).toHaveLength(1);
    });
  });

  it('stops reading an answer that grows past 32 MiB without saying so', async () => {
    const chunk = new TextEncoder().encode(' '.repeat(MIB));
    let sent = 0;
    const fake = new FakeFetch().on('POST', QUERYBATCH, () => {
      const body = new ReadableStream<Uint8Array>({
        pull(controller) {
          sent += 1;
          controller.enqueue(chunk);
        },
      });
      return new Response(body, { status: 200 });
    });
    expect(await failure(client(fake).queryBatch(QUERY))).toEqual(UNEXPECTED);
    expect(sent).toBeGreaterThan(32);
    expect(sent).toBeLessThan(40);
  });
});

describe('OsvClient.advisory', () => {
  const NAMES = new Set(['baip-fixture-merge', '@baip-fixture/odata']);

  it('reads the few fields it names from a record, and nothing else', async () => {
    const fake = osvFetch({
      advisories: {
        [ID]: {
          aliases: ['CVE-2026-00001'],
          summary: 'Prototype pollution in baip-fixture-merge',
          cvssV3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          label: 'CRITICAL',
          affected: [{ name: 'baip-fixture-merge', introduced: '3.7.0', fixed: '4.17.21' }],
        },
      },
    });
    const advisory = await client(fake).advisory(ID, NAMES);
    expect({ ...advisory, fixed: [...advisory.fixed] }).toEqual({
      id: ID,
      withdrawn: false,
      aliases: ['CVE-2026-00001'],
      summary: 'Prototype pollution in baip-fixture-merge',
      cvssV3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      label: 'CRITICAL',
      fixed: [['baip-fixture-merge', ['4.17.21']]],
    });
    // The record holds a long text, links, and the name and address of a person.
    const kept = JSON.stringify({ ...advisory, fixed: [...advisory.fixed] });
    for (const never of OSV_POISON) expect(kept, never).not.toContain(never);
    const call = fake.calls[0]!;
    expect([call.method, call.url.href, call.body]).toEqual([
      'GET',
      `https://api.osv.dev/v1/vulns/${ID}`,
      undefined,
    ]);
    expect(call.headers).toEqual({ accept: 'application/json', 'user-agent': 'baip-lens/test' });
    expect(call.redirect).toBe('manual');
  });

  it('reads a record that says next to nothing: a malicious package has no score and no alias', async () => {
    const fake = new FakeFetch().on('GET', VULN('MAL-0000-0001'), () =>
      jsonResponse({
        id: 'MAL-0000-0001',
        summary: 'Malicious code in baip-fixture-merge (npm)',
        database_specific: { 'malicious-packages-origins': null },
        affected: [
          {
            package: { name: 'baip-fixture-merge', ecosystem: 'npm' },
            ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }] }],
          },
        ],
      }),
    );
    const advisory = await client(fake).advisory('MAL-0000-0001', NAMES);
    expect({ ...advisory, fixed: [...advisory.fixed] }).toEqual({
      id: 'MAL-0000-0001',
      withdrawn: false,
      aliases: [],
      summary: 'Malicious code in baip-fixture-merge (npm)',
      cvssV3: null,
      label: null,
      // Named, and without a fixed version.
      fixed: [['baip-fixture-merge', []]],
    });
    const bare = new FakeFetch().on('GET', VULN(ID), jsonResponse({ id: ID }));
    const least = await client(bare).advisory(ID, NAMES);
    expect({ ...least, fixed: [...least.fixed] }).toEqual({
      id: ID,
      withdrawn: false,
      aliases: [],
      summary: null,
      cvssV3: null,
      label: null,
      fixed: [],
    });
  });

  it('says that an advisory was withdrawn, whatever the record says else', async () => {
    const fake = osvFetch({
      advisories: { [ID]: { withdrawn: '2026-09-15T00:00:00Z', label: 'HIGH' } },
    });
    expect((await client(fake).advisory(ID, NAMES)).withdrawn).toBe(true);
    const nulled = new FakeFetch().on('GET', VULN(ID), jsonResponse({ id: ID, withdrawn: null }));
    expect((await client(nulled).advisory(ID, NAMES)).withdrawn).toBe(false);
  });

  // "Present" decides, not what the field holds: a record that carries it is not counted.
  it.each([
    ['an empty text', ''],
    ['false', false],
    ['zero', 0],
    ['an object', {}],
  ])('says so as well when `withdrawn` is %s', async (_name, withdrawn) => {
    const fake = new FakeFetch().on('GET', VULN(ID), jsonResponse({ id: ID, withdrawn }));
    expect((await client(fake).advisory(ID, NAMES)).withdrawn).toBe(true);
  });

  it('keeps the fixed versions of the packages that were asked about, and of npm, only', async () => {
    const fake = osvFetch({
      advisories: {
        [ID]: {
          affected: [
            // Two ranges of one package, and the same fix named twice.
            { name: 'baip-fixture-merge', fixed: '4.17.21' },
            { name: 'baip-fixture-merge', introduced: '5.0.0-alpha.0', fixed: '5.0.0-alpha.4' },
            { name: 'baip-fixture-merge', fixed: '4.17.21' },
            // Affected, and never fixed.
            { name: '@baip-fixture/odata' },
            // Not asked about: another package, and the same name in another ecosystem.
            { name: 'baip-fixture-other', fixed: '9.9.9' },
            { name: 'baip-fixture-merge', ecosystem: 'RubyGems', fixed: '8.8.8' },
            { name: 'baip-fixture-merge', ecosystem: 'NPM', fixed: '7.7.7' },
          ],
        },
      },
    });
    const advisory = await client(fake).advisory(ID, NAMES);
    expect([...advisory.fixed]).toEqual([
      ['baip-fixture-merge', ['4.17.21', '5.0.0-alpha.4']],
      ['@baip-fixture/odata', []],
    ]);
  });

  it('drops a fixed version that is not a version, and every entry it cannot read', async () => {
    const entry = (events: unknown) => ({
      package: { name: 'baip-fixture-merge', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events }],
    });
    const fake = new FakeFetch().on('GET', VULN(ID), () =>
      jsonResponse({
        id: ID,
        affected: [
          entry([{ introduced: '0' }, { fixed: '1.2.3' }]),
          entry([{ fixed: '../../etc/passwd' }, { fixed: '^2.0.0' }, { fixed: 7 }, 'x', null]),
          entry([{ fixed: `3.0.0-${'9'.repeat(59)}` }, { limit: '4.0.0' }]),
          entry('x'),
          { package: { name: 'baip-fixture-merge', ecosystem: 'npm' }, ranges: 'x' },
          { package: { name: 'baip-fixture-merge', ecosystem: 'npm' }, versions: ['1.0.0'] },
          { package: 'baip-fixture-merge', ranges: [] },
          { ranges: [{ type: 'GIT', events: [{ fixed: '5.5.5' }] }] },
          'x',
          null,
        ],
      }),
    );
    expect([...(await client(fake).advisory(ID, NAMES)).fixed]).toEqual([
      ['baip-fixture-merge', ['1.2.3']],
    ]);
  });

  it('keeps the first 20 aliases that are ids, each once', async () => {
    const many = Array.from({ length: 30 }, (_, i) => `CVE-2026-${String(i).padStart(5, '0')}`);
    const fake = osvFetch({
      advisories: {
        [ID]: {
          aliases: [],
          extra: {
            aliases: ['not an id', 'CVE/../x', 7, null, many[0], many[0], 'G'.repeat(101), ...many],
          },
        },
      },
    });
    expect((await client(fake).advisory(ID, NAMES)).aliases).toEqual(many.slice(0, 20));
  });

  it('takes the first CVSS v3 vector that is one, and a label only when it is one of the four', async () => {
    const record = (severity: unknown, label: unknown) =>
      new FakeFetch().on('GET', VULN(ID), () =>
        jsonResponse({ id: ID, severity, database_specific: { severity: label } }),
      );
    const vector = 'CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N';
    const first = await client(
      record(
        [
          {
            type: 'CVSS_V4',
            score: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
          },
          { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N <script>' },
          { type: 'CVSS_V3', score: 9.8 },
          'x',
          { type: 'CVSS_V3', score: vector },
          { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
        ],
        'MODERATE',
      ),
    ).advisory(ID, NAMES);
    expect([first.cvssV3, first.label]).toEqual([vector, 'MODERATE']);
    for (const label of ['moderate', 'MEDIUM', 'POISON_osv_label', 7, null, ['HIGH']]) {
      const advisory = await client(record([{ type: 'CVSS_V2', score: 'AV:N' }], label)).advisory(
        ID,
        NAMES,
      );
      expect([advisory.cvssV3, advisory.label], String(label)).toEqual([null, null]);
    }
    // `database_specific` in a shape it does not have for GitHub advisories.
    const odd = new FakeFetch().on('GET', VULN(ID), () =>
      jsonResponse({ id: ID, database_specific: 'HIGH', severity: null }),
    );
    expect((await client(odd).advisory(ID, NAMES)).label).toBeNull();
  });

  it("hands the summary over as it came: cleaning it is the collector's part", async () => {
    const summary = `jane.poison@example.com\u202e in ${'x'.repeat(5_000)}`;
    const fake = osvFetch({ advisories: { [ID]: { summary } } });
    expect((await client(fake).advisory(ID, NAMES)).summary).toBe(summary);
  });

  it.each([
    ['two dots', '..'],
    ['one dot', '.'],
    ['a path', 'GHSA-1/../../v1/query'],
    ['a query', 'GHSA-1?a=b'],
    ['an encoded slash', 'GHSA%2f..'],
    ['a blank', 'GHSA 1'],
    ['nothing', ''],
    ['101 characters', 'G'.repeat(101)],
  ])('never puts an id of %s into a request', async (_name, id) => {
    const fake = new FakeFetch().on('GET', () => true, jsonResponse({ id }));
    expect(await failure(client(fake).advisory(id, NAMES))).toEqual(UNEXPECTED);
    expect(fake.calls).toEqual([]);
  });

  it('asks for an id with dots and colons as it is', async () => {
    const id = 'OSV:fake_2026.1-a';
    const fake = new FakeFetch().on('GET', VULN(id), jsonResponse({ id }));
    expect((await client(fake).advisory(id, NAMES)).id).toBe(id);
    expect(fake.calls[0]?.url.pathname).toBe(`/v1/vulns/${id}`);
  });

  it('counts a 404 for an id OSV.dev just named as a failure', async () => {
    const fake = osvFetch();
    expect(await failure(client(fake).advisory(ID, NAMES))).toEqual([
      'status',
      404,
      'api.osv.dev answered HTTP 404',
    ]);
    expect(fake.calls).toHaveLength(1);
  });

  it.each([
    ['text that is not JSON', new Response('POISON_osv_page', { status: 200 })],
    ['a record with another id', jsonResponse(osvRecord('GHSA-fake-0002-baip'))],
    ['a record without an id', jsonResponse({ summary: 'x' })],
    ['a list', jsonResponse([osvRecord(ID)])],
    ['a summary that is not text', jsonResponse({ id: ID, summary: ['x'] })],
    ['aliases that are not a list', jsonResponse({ id: ID, aliases: 'CVE-2026-00001' })],
    ['severities that are not a list', jsonResponse({ id: ID, severity: { type: 'CVSS_V3' } })],
    ['affected packages that are not a list', jsonResponse({ id: ID, affected: {} })],
    [
      'a record nested deeper than any real one',
      new Response(`{"id":"${ID}","x":${'['.repeat(40)}${']'.repeat(40)}}`, { status: 200 }),
    ],
    [
      'an object with more keys than any real record has',
      new Response(
        `{"id":"${ID}",${Array.from({ length: 1_001 }, (_, i) => `"k${i}":0`).join(',')}}`,
        { status: 200 },
      ),
    ],
    [
      'a record that says it is larger than 8 MiB',
      jsonResponse(osvRecord(ID), 200, { 'content-length': String(8 * MIB + 1) }),
    ],
  ])('refuses %s as a whole', async (_name, response) => {
    const fake = new FakeFetch().on('GET', VULN(ID), response);
    expect(await failure(client(fake).advisory(ID, NAMES))).toEqual(UNEXPECTED);
  });

  it('says that OSV.dev could not be reached after three tries', async () => {
    const fake = new FakeFetch().on('GET', VULN(ID), () => {
      throw new TypeError('fetch failed');
    });
    expect(await failure(client(fake).advisory(ID, NAMES))).toEqual([
      'unreachable',
      undefined,
      'api.osv.dev could not be reached',
    ]);
    expect(fake.calls).toHaveLength(3);
  });
});

describe('an error that is not about OSV.dev', () => {
  it('is passed on as it is: a request the allow-list refuses is a mistake of the code, not an answer', async () => {
    const broken = new OsvClient({ request: () => Promise.reject(new TypeError('boom')) });
    await expect(broken.queryBatch(QUERY)).rejects.toThrow(TypeError);
    await expect(broken.advisory(ID, new Set())).rejects.toThrow('boom');
  });
});

describe('what the client of the lookup can reach', () => {
  it('is refused everything but the two requests, and any credential, by its allow-list', async () => {
    const fake = new FakeFetch();
    const http = new HttpClient({
      policy: new EgressPolicy(),
      userAgent: 'baip-lens/test',
      fetch: fake.fetch,
      sleep: noSleep,
    });
    const refused: HttpRequest[] = [
      { url: new URL('https://api.osv.dev/v1/query'), method: 'POST', body: '{}' },
      { url: new URL('https://api.osv.dev/v1/querybatch') },
      { url: new URL('https://api.osv.dev/v1/vulns/x'), method: 'POST', body: '{}' },
      { url: new URL('https://api.cf.example.org/v3/apps') },
      { url: new URL('https://osv.dev/v1/querybatch'), method: 'POST', body: '{}' },
      { url: new URL('http://api.osv.dev/v1/vulns/x') },
      {
        url: new URL('https://api.osv.dev/v1/querybatch'),
        method: 'POST',
        body: '{}',
        headers: { authorization: 'bearer POISON-abcdef123456' },
      },
      {
        url: new URL('https://api.osv.dev/v1/vulns/x'),
        headers: { Authorization: 'Basic POISON-dXNlcjpwYXNz' },
      },
    ];
    for (const request of refused) {
      await expect(http.request(request), request.url.href).rejects.toThrow('Egress denied');
    }
    expect(fake.calls).toEqual([]);
  });
});
