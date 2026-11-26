import { describe, expect, it } from 'vitest';
import {
  HttpClient,
  type HttpGetRequest,
  type HttpRequest,
  type HttpResponse,
} from '../../src/http/httpClient.js';
import {
  NpmRegistryClient,
  NpmRegistryError,
  requestedVersion,
} from '../../src/http/npmRegistryClient.js';
import { EgressPolicy } from '../../src/net/allowlist.js';
import {
  REGISTRY_HOST,
  REGISTRY_POISON,
  registryDocument,
  registryFetch,
} from '../support/dependencyScript.js';
import { FakeFetch, jsonResponse, noSleep } from '../support/fakeFetch.js';

/*
 * The npm registry client against a scripted fetch, through the real HTTP
 * client and the allow-list as the scan builds them: what is sent, and what
 * is made of every answer, the wrong ones above all.
 */

const MIB = 1024 * 1024;
const MERGE = 'baip-fixture-merge';
const ODATA = '@baip-fixture/odata';
const MESSAGE = 'baip-fixture-merge 4.x is no longer supported, upgrade to 5.x';
const at = (path: string): string => `${REGISTRY_HOST}${path}`;

function client(fake: FakeFetch): NpmRegistryClient {
  const http = new HttpClient({
    policy: new EgressPolicy(),
    userAgent: 'baip-lens/test',
    fetch: fake.fetch,
    sleep: noSleep,
    maxRetries: 2,
  });
  return new NpmRegistryClient(http);
}

/** The failure a request ends in, as `[failure, status, message]`. */
async function failure(request: Promise<unknown>): Promise<unknown[]> {
  const error = await request.then(
    () => undefined,
    (reason: unknown) => reason,
  );
  if (!(error instanceof NpmRegistryError)) {
    throw new Error(`expected an NpmRegistryError, got ${String(error)}`);
  }
  return [error.failure, error.status, error.message];
}

const UNEXPECTED = ['unexpected', undefined, 'registry.npmjs.org sent an unexpected answer'];
const UNREACHABLE = ['unreachable', undefined, 'registry.npmjs.org could not be reached'];

/** The headers and the first bytes of an answer, and then the connection fails with `error`. */
function brokenAnswer(error: Error): Response {
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"name":"'));
      },
      pull(controller) {
        controller.error(error);
      },
    }),
  );
}

describe('NpmRegistryClient.version', () => {
  it('gets the document of one version, and reads its version and nothing else of it', async () => {
    const fake = registryFetch();
    expect(await client(fake).version(MERGE, '4.17.20')).toEqual({
      version: '4.17.20',
      deprecated: null,
    });
    expect(fake.calls).toHaveLength(1);
    const call = fake.calls[0]!;
    expect([call.method, call.url.href, call.body]).toEqual([
      'GET',
      'https://registry.npmjs.org/baip-fixture-merge/4.17.20',
      undefined,
    ]);
    // No credential, no cookie, and no redirect is followed.
    expect(call.headers).toEqual({ accept: 'application/json', 'user-agent': 'baip-lens/test' });
    expect(call.redirect).toBe('manual');
  });

  it('reads the message of a deprecated version as it came: cleaning it is the part of the collector', async () => {
    const message = `write to jane.poison@example.com\u202e ${'x'.repeat(5_000)}`;
    const fake = registryFetch({
      versions: {
        [`${MERGE}@4.17.20`]: { deprecated: MESSAGE },
        [`${MERGE}@3.10.1`]: { deprecated: message },
      },
    });
    const registry = client(fake);
    expect(await registry.version(MERGE, '4.17.20')).toEqual({
      version: '4.17.20',
      deprecated: MESSAGE,
    });
    expect((await registry.version(MERGE, '3.10.1'))?.deprecated).toBe(message);
  });

  it('keeps nothing of the people behind a package, nor any other field of the document', async () => {
    const fake = registryFetch({ versions: { [`${MERGE}@4.17.20`]: { deprecated: MESSAGE } } });
    const answer = await client(fake).version(MERGE, '4.17.20');
    // The document names its maintainers, its publisher and its author, with their addresses.
    const document = JSON.stringify(registryDocument(MERGE, '4.17.20'));
    for (const planted of REGISTRY_POISON.slice(0, 7)) expect(document).toContain(planted);
    expect(Object.keys(answer ?? {}).sort()).toEqual(['deprecated', 'version']);
    for (const never of REGISTRY_POISON) expect(JSON.stringify(answer), never).not.toContain(never);
  });

  it('asks for a scoped package with its slash encoded: one path of two segments', async () => {
    const fake = registryFetch({ versions: { [`${ODATA}@3.1.0`]: { deprecated: MESSAGE } } });
    expect(await client(fake).version(ODATA, '3.1.0')).toEqual({
      version: '3.1.0',
      deprecated: MESSAGE,
    });
    const url = fake.calls[0]!.url;
    // `URL` keeps the escape as it was written.
    expect(url.pathname).toBe('/@baip-fixture%2fodata/3.1.0');
    expect(url.href).toBe('https://registry.npmjs.org/@baip-fixture%2fodata/3.1.0');
    expect(url.pathname.split('/')).toHaveLength(3);
    expect(url.search).toBe('');
  });

  it.each([
    ['a prerelease', MERGE, '5.0.0-rc.1', '/baip-fixture-merge/5.0.0-rc.1'],
    ['capitals, dots and a tilde', 'Baip.Fixture~2', '1.0.0', '/Baip.Fixture~2/1.0.0'],
    ['a name with two dots in it', 'baip..fixture', '1.0.0', '/baip..fixture/1.0.0'],
    [
      'a scope and a name with dots',
      '@baip.fixture/o.data',
      '1.0.0',
      '/@baip.fixture%2fo.data/1.0.0',
    ],
    ['a package that is called latest', 'latest', '1.0.0', '/latest/1.0.0'],
    // The longest a lockfile package can be: the allow-list lets through all the lockfile step keeps.
    ['a name of 214 characters', 'n'.repeat(214), '1.0.0', `/${'n'.repeat(214)}/1.0.0`],
    [
      'a scoped name of 214 characters',
      `@baip-fixture/${'n'.repeat(200)}`,
      '1.0.0',
      `/@baip-fixture%2f${'n'.repeat(200)}/1.0.0`,
    ],
    [
      'a version of 64 characters',
      'baip-fixture-merge',
      `1.0.0-${'9'.repeat(58)}`,
      `/baip-fixture-merge/1.0.0-${'9'.repeat(58)}`,
    ],
    ['a prerelease that is empty', 'baip-fixture-merge', '1.0.0-', '/baip-fixture-merge/1.0.0-'],
  ])('asks for %s as it is written', async (_name, name, version, path) => {
    const fake = registryFetch();
    expect(await client(fake).version(name, version)).toEqual({ version, deprecated: null });
    expect(fake.calls.map((call) => call.url.pathname)).toEqual([path]);
  });

  it('asks for a version without its build metadata, and takes the answer for it', async () => {
    expect(requestedVersion('1.4.0+build.7')).toBe('1.4.0');
    expect(requestedVersion('1.4.0-rc.1+build.7')).toBe('1.4.0-rc.1');
    expect(requestedVersion('1.4.0-rc+a+b')).toBe('1.4.0-rc');
    expect(requestedVersion('1.4.0')).toBe('1.4.0');

    const fake = registryFetch({ versions: { [`${MERGE}@1.4.0`]: { deprecated: MESSAGE } } });
    expect(await client(fake).version(MERGE, '1.4.0+build.7')).toEqual({
      version: '1.4.0',
      deprecated: MESSAGE,
    });
    expect(fake.calls.map((call) => call.url.pathname)).toEqual(['/baip-fixture-merge/1.4.0']);
    // A registry that names the build in its answer is talking about the same release.
    const named = new FakeFetch().on('GET', at(`/${MERGE}/1.4.0`), () =>
      jsonResponse({ version: '1.4.0+build.7' }),
    );
    expect(await client(named).version(MERGE, '1.4.0+other')).toEqual({
      version: '1.4.0+build.7',
      deprecated: null,
    });
  });

  // What counts as deprecated: a text that is not empty, or `true`.
  it.each([
    ['a message', MESSAGE, MESSAGE],
    ['a message of one blank', ' ', ' '],
    ['true: deprecated without a reason', true, ''],
    ['an empty text, which takes a deprecation back', '', null],
    ['false', false, null],
    ['null', null, null],
    ['a number', 1, null],
    ['a list', [MESSAGE], null],
    ['an object', { message: MESSAGE }, null],
  ])('reads `deprecated` that is %s', async (_name, deprecated, expected) => {
    const fake = new FakeFetch().on('GET', at(`/${MERGE}/4.17.20`), () =>
      jsonResponse({ name: MERGE, version: '4.17.20', deprecated }),
    );
    expect(await client(fake).version(MERGE, '4.17.20')).toEqual({
      version: '4.17.20',
      deprecated: expected,
    });
  });

  it('takes a 404 as an answer: the registry does not know that version', async () => {
    const fake = registryFetch({ versions: { [`${MERGE}@9.9.9`]: { status: 404 } } });
    expect(await client(fake).version(MERGE, '9.9.9')).toBeNull();
    // Not worth asking again.
    expect(fake.calls).toHaveLength(1);
    // Whatever the body says: the registry answers with a JSON text, a gateway with a page.
    const page = new FakeFetch().on(
      'GET',
      at(`/${MERGE}/9.9.9`),
      new Response('<html>POISON_registry_page</html>', { status: 404 }),
    );
    expect(await client(page).version(MERGE, '9.9.9')).toBeNull();
  });

  it.each([
    ['a name that is a path', '../etc/passwd', '1.0.0'],
    ['a name of two dots', '..', '1.0.0'],
    ['a scope of two dots', '@../odata', '1.0.0'],
    ['a name that starts with a dot', '.npmrc', '1.0.0'],
    ['a name with an encoded slash', '@baip-fixture%2fodata', '1.0.0'],
    ['a name with two slashes', '@baip-fixture/odata/x', '1.0.0'],
    ['a name with a blank', 'baip fixture', '1.0.0'],
    ['a name with a query', 'baip-fixture?write=true', '1.0.0'],
    ['a name with a fragment', 'baip-fixture#x', '1.0.0'],
    ['a name of 215 characters', 'n'.repeat(215), '1.0.0'],
    ['an empty name', '', '1.0.0'],
    ['a range', MERGE, '^4.17.0'],
    ['a tag', MERGE, 'latest'],
    ['a version that is a path', MERGE, '1.0.0/../../x'],
    ['a version with a query', MERGE, '1.0.0?x=1'],
    ['an address as the version', MERGE, 'https://x.example/a.tgz'],
    ['a version of 65 characters', MERGE, `1.0.0-${'9'.repeat(59)}`],
    ['an empty version', MERGE, ''],
  ])('refuses %s, before anything is sent', async (_name, name, version) => {
    const fake = new FakeFetch().on('GET', () => true, jsonResponse({ version }));
    await expect(client(fake).version(name, version)).rejects.toThrow(
      'not a package name and version that can be looked up',
    );
    expect(fake.calls).toEqual([]);
  });

  it('reports the status of an answer that is neither 200 nor 404, never its text', async () => {
    const fake = registryFetch({ versions: { [`${MERGE}@4.17.20`]: { status: 403 } } });
    expect(await failure(client(fake).version(MERGE, '4.17.20'))).toEqual([
      'status',
      403,
      'registry.npmjs.org answered HTTP 403',
    ]);
    // Not worth asking again.
    expect(fake.calls).toHaveLength(1);
  });

  it.each([
    [204, (): Response => new Response(null, { status: 204 })],
    [206, (body: unknown): Response => jsonResponse(body, 206)],
    [201, (body: unknown): Response => jsonResponse(body, 201)],
    [304, (): Response => new Response(null, { status: 304 })],
    [401, (body: unknown): Response => jsonResponse(body, 401)],
    [410, (body: unknown): Response => jsonResponse(body, 410)],
  ])('reads no answer but a 200: a %i is reported by its status', async (status, respond) => {
    const reported = ['status', status, `registry.npmjs.org answered HTTP ${status}`];
    const fake = new FakeFetch().on('GET', at(`/${MERGE}/4.17.20`), () =>
      respond(registryDocument(MERGE, '4.17.20')),
    );
    expect(await failure(client(fake).version(MERGE, '4.17.20'))).toEqual(reported);
    const latest = new FakeFetch().on('GET', at(`/${MERGE}/latest`), () =>
      respond(registryDocument(MERGE, '5.0.0')),
    );
    expect(await failure(client(latest).latest(MERGE))).toEqual(reported);
  });

  it('asks again twice after a server error or a 429, then reports it', async () => {
    const fake = new FakeFetch().on(
      'GET',
      at(`/${MERGE}/4.17.20`),
      new Response('busy', { status: 503 }),
    );
    expect(await failure(client(fake).version(MERGE, '4.17.20'))).toEqual([
      'status',
      503,
      'registry.npmjs.org answered HTTP 503',
    ]);
    expect(fake.calls).toHaveLength(3);
    const recovering = new FakeFetch()
      .on('GET', at(`/${MERGE}/4.17.20`), new Response('slow down', { status: 429 }), 2)
      .on('GET', at(`/${MERGE}/4.17.20`), jsonResponse(registryDocument(MERGE, '4.17.20')));
    expect(await client(recovering).version(MERGE, '4.17.20')).toEqual({
      version: '4.17.20',
      deprecated: null,
    });
    expect(recovering.calls).toHaveLength(3);
  });

  it('waits as long as a 429 asks it to before it asks again', async () => {
    const sleeps: number[] = [];
    const fake = new FakeFetch()
      .on(
        'GET',
        at(`/${MERGE}/4.17.20`),
        new Response('slow down', { status: 429, headers: { 'retry-after': '7' } }),
        1,
      )
      .on('GET', at(`/${MERGE}/4.17.20`), jsonResponse(registryDocument(MERGE, '4.17.20')));
    const http = new HttpClient({
      policy: new EgressPolicy(),
      userAgent: 'baip-lens/test',
      fetch: fake.fetch,
      maxRetries: 2,
      sleep: (ms) => {
        sleeps.push(ms);
        return Promise.resolve();
      },
    });
    expect(await new NpmRegistryClient(http).version(MERGE, '4.17.20')).not.toBeNull();
    expect(sleeps).toEqual([7_000]);
  });

  it('does not follow a redirect', async () => {
    const fake = new FakeFetch().on(
      'GET',
      at(`/${MERGE}/4.17.20`),
      new Response(null, {
        status: 302,
        headers: { location: 'https://evil.example/baip-fixture-merge/4.17.20' },
      }),
    );
    expect(await failure(client(fake).version(MERGE, '4.17.20'))).toEqual([
      'status',
      302,
      'registry.npmjs.org answered HTTP 302',
    ]);
    expect(fake.calls.map((call) => call.url.host)).toEqual(['registry.npmjs.org']);
  });

  it('says that the registry could not be reached after three tries, without the cause', async () => {
    const fake = new FakeFetch().on('GET', at(`/${MERGE}/4.17.20`), () => {
      throw new TypeError('fetch failed', {
        cause: Object.assign(new Error('getaddrinfo ENOTFOUND POISON_registry_host'), {
          code: 'ENOTFOUND',
        }),
      });
    });
    expect(await failure(client(fake).version(MERGE, '4.17.20'))).toEqual(UNREACHABLE);
    expect(fake.calls).toHaveLength(3);
  });

  it.each([
    ['is reset', () => new TypeError('terminated', { cause: new Error('POISON_registry_cause') })],
    [
      'runs out of time',
      () => new DOMException('The operation was aborted due to timeout', 'TimeoutError'),
    ],
  ])('says the same when the connection %s while the answer is read', async (_name, error) => {
    const fake = new FakeFetch().on('GET', at(`/${MERGE}/4.17.20`), () => brokenAnswer(error()));
    expect(await failure(client(fake).version(MERGE, '4.17.20'))).toEqual(UNREACHABLE);
    expect(fake.calls).toHaveLength(3);
    const latest = new FakeFetch().on('GET', at(`/${MERGE}/latest`), () => brokenAnswer(error()));
    expect(await failure(client(latest).latest(MERGE))).toEqual(UNREACHABLE);
    expect(latest.calls).toHaveLength(3);
  });

  it('reads the answer of the second try when the first broke off', async () => {
    const fake = new FakeFetch()
      .on('GET', at(`/${MERGE}/4.17.20`), () => brokenAnswer(new TypeError('terminated')), 1)
      .on('GET', at(`/${MERGE}/4.17.20`), jsonResponse({ version: '4.17.20', deprecated: true }));
    expect(await client(fake).version(MERGE, '4.17.20')).toEqual({
      version: '4.17.20',
      deprecated: '',
    });
    expect(fake.calls).toHaveLength(2);
  });

  it('sends a GET through the read-only view of the HTTP layer: the time of the lookup, 1 MiB at most', async () => {
    const seen: HttpGetRequest[] = [];
    const recording = new NpmRegistryClient({
      get: (request) => {
        seen.push(request);
        const response: HttpResponse = {
          url: request.url,
          status: 200,
          headers: new Headers(),
          text: '{"version":"4.17.20"}',
        };
        return Promise.resolve(response);
      },
    });
    await recording.version(MERGE, '4.17.20');
    await recording.latest(MERGE);
    expect(seen.map((request) => request.url.href)).toEqual([
      'https://registry.npmjs.org/baip-fixture-merge/4.17.20',
      'https://registry.npmjs.org/baip-fixture-merge/latest',
    ]);
    for (const request of seen) {
      // Nothing but the address and the size limit: no header, no time of its own, and nothing
      // turns the repeats off. A method or a body the client has no way to name.
      expect(Object.keys(request).sort()).toEqual(['maxBytes', 'url']);
      expect(request.maxBytes).toBe(MIB);
    }
  });

  it.each([
    ['text that is not JSON', new Response('<html>POISON_registry_page</html>', { status: 200 })],
    ['an empty body', new Response('', { status: 200 })],
    ['a JSON text, as the registry answers a 404', jsonResponse('version not found: 4.17.20')],
    ['a list', jsonResponse([registryDocument(MERGE, '4.17.20')])],
    ['null', jsonResponse(null)],
    // A gateway or a portal can answer 200 as well: "not deprecated" must not be read into it.
    ['an empty object', jsonResponse({})],
    ['the words of a gateway', jsonResponse({ status: 'blocked', message: 'POISON_gateway' })],
    ['a document without a version', jsonResponse({ name: MERGE, deprecated: MESSAGE })],
    ['a version that is not text', jsonResponse({ name: MERGE, version: 4 })],
    ['a version that is null', jsonResponse({ name: MERGE, version: null })],
    ['the document of another version', jsonResponse(registryDocument(MERGE, '4.17.21'))],
    ['the document of another prerelease', jsonResponse(registryDocument(MERGE, '4.17.20-rc.1'))],
    ['a whole package document', jsonResponse({ name: MERGE, versions: { '4.17.20': {} } })],
    [
      'an answer that says it is larger than 1 MiB',
      jsonResponse(registryDocument(MERGE, '4.17.20'), 200, {
        'content-length': String(MIB + 1),
      }),
    ],
  ])('refuses %s as a whole', async (_name, response) => {
    const fake = new FakeFetch().on('GET', at(`/${MERGE}/4.17.20`), response);
    expect(await failure(client(fake).version(MERGE, '4.17.20'))).toEqual(UNEXPECTED);
    expect(fake.calls).toHaveLength(1);
  });

  /*
   * What an answer may cost to parse (docs/data-sources.md §12.4). The part
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
      new Response(`{"version":"4.17.20","exports":${extra}}`, { status: 200 });

    it.each([
      // The answer itself is one level.
      ['32 levels of nesting', nested(31)],
      // The answer, the key `version` and its value, the key `exports` and its list are five values.
      ['200,000 values', values(199_995)],
      ['an object of 50,000 keys', keys(50_000)],
    ])('reads an answer with %s', async (_name, extra) => {
      const fake = new FakeFetch().on('GET', at(`/${MERGE}/4.17.20`), () => answer(extra));
      expect(await client(fake).version(MERGE, '4.17.20')).toEqual({
        version: '4.17.20',
        deprecated: null,
      });
    });

    it.each([
      ['33 levels of nesting', nested(32)],
      ['200,001 values', values(199_996)],
      ['an object of 50,001 keys', keys(50_001)],
    ])('refuses an answer with %s as a whole', async (_name, extra) => {
      const fake = new FakeFetch().on('GET', at(`/${MERGE}/4.17.20`), () => answer(extra));
      expect(await failure(client(fake).version(MERGE, '4.17.20'))).toEqual(UNEXPECTED);
      expect(fake.calls).toHaveLength(1);
    });
  });

  it('reads a document as large as the largest real ones, and one of nearly 1 MiB', async () => {
    // A very large `exports` map: 3,000 entry points with their conditions, about 110 KB.
    const exports = Object.fromEntries(
      Array.from({ length: 3_000 }, (_, i) => [`./fn${i}`, { import: `./fn${i}.mjs` }]),
    );
    const large = registryDocument(MERGE, '4.17.20', { deprecated: MESSAGE, extra: { exports } });
    const padded = { ...large, readme: 'x'.repeat(MIB - JSON.stringify(large).length - 100) };
    for (const document of [large, padded]) {
      const fake = new FakeFetch().on('GET', at(`/${MERGE}/4.17.20`), jsonResponse(document));
      expect(await client(fake).version(MERGE, '4.17.20')).toEqual({
        version: '4.17.20',
        deprecated: MESSAGE,
      });
    }
    expect(JSON.stringify(large).length).toBeGreaterThan(100_000);
    expect(JSON.stringify(padded).length).toBeGreaterThan(MIB - 200);
    expect(JSON.stringify(padded).length).toBeLessThanOrEqual(MIB);
  });

  it('stops reading an answer that grows past 1 MiB without saying so', async () => {
    const chunk = new TextEncoder().encode(' '.repeat(64 * 1024));
    let sent = 0;
    const fake = new FakeFetch().on('GET', at(`/${MERGE}/4.17.20`), () => {
      const body = new ReadableStream<Uint8Array>({
        pull(controller) {
          sent += 1;
          controller.enqueue(chunk);
        },
      });
      return new Response(body, { status: 200 });
    });
    expect(await failure(client(fake).version(MERGE, '4.17.20'))).toEqual(UNEXPECTED);
    // 16 chunks are 1 MiB: the seventeenth is one too many, and little is read after it.
    expect(sent).toBeGreaterThan(16);
    expect(sent).toBeLessThan(24);
  });
});

describe('NpmRegistryClient.latest', () => {
  it('gets the version the registry calls the latest of a package, and whether that one is deprecated', async () => {
    const fake = registryFetch({
      latest: {
        [MERGE]: { version: '5.2.0' },
        [ODATA]: { version: '3.9.9', deprecated: MESSAGE },
        'baip-fixture-queue': { version: '6.0.0', deprecated: true },
      },
    });
    const registry = client(fake);
    expect(await registry.latest(MERGE)).toEqual({ version: '5.2.0', deprecated: null });
    expect(await registry.latest(ODATA)).toEqual({ version: '3.9.9', deprecated: MESSAGE });
    expect(await registry.latest('baip-fixture-queue')).toEqual({
      version: '6.0.0',
      deprecated: '',
    });
    expect(fake.calls.map((call) => `${call.method} ${call.url.href}`)).toEqual([
      'GET https://registry.npmjs.org/baip-fixture-merge/latest',
      'GET https://registry.npmjs.org/@baip-fixture%2fodata/latest',
      'GET https://registry.npmjs.org/baip-fixture-queue/latest',
    ]);
    for (const call of fake.calls) {
      expect(call.headers).toEqual({ accept: 'application/json', 'user-agent': 'baip-lens/test' });
      expect(call.body).toBeUndefined();
    }
  });

  it('takes a 404 as an answer: the registry names no latest version', async () => {
    const fake = registryFetch({ latest: { [MERGE]: null } });
    expect(await client(fake).latest(MERGE)).toBeNull();
    expect(fake.calls).toHaveLength(1);
  });

  it('hands the version on as it came: whether it can be stored is for the collector to say', async () => {
    for (const version of ['1.0', 'v2.0.0', 'x'.repeat(5_000), '']) {
      const fake = new FakeFetch().on('GET', at(`/${MERGE}/latest`), jsonResponse({ version }));
      expect(await client(fake).latest(MERGE)).toEqual({ version, deprecated: null });
    }
  });

  it.each([
    ['a path', '../etc/passwd'],
    ['two dots', '..'],
    ['an encoded slash', '@baip-fixture%2fodata'],
    ['a query', 'baip-fixture?x=1'],
    ['215 characters', 'n'.repeat(215)],
    ['nothing', ''],
  ])('never puts a name of %s into a request', async (_name, name) => {
    const fake = new FakeFetch().on('GET', () => true, jsonResponse({ version: '1.0.0' }));
    await expect(client(fake).latest(name)).rejects.toThrow(
      'not a package name and version that can be looked up',
    );
    expect(fake.calls).toEqual([]);
  });

  it.each([
    ['text that is not JSON', new Response('POISON_registry_page', { status: 200 })],
    ['an object without a version', jsonResponse({ name: MERGE })],
    ['a list', jsonResponse([{ version: '5.0.0' }])],
    [
      'a document that says it is larger than 1 MiB',
      jsonResponse({ version: '5.0.0' }, 200, { 'content-length': String(MIB + 1) }),
    ],
  ])('refuses %s as a whole', async (_name, response) => {
    const fake = new FakeFetch().on('GET', at(`/${MERGE}/latest`), response);
    expect(await failure(client(fake).latest(MERGE))).toEqual(UNEXPECTED);
  });

  it('says that the registry could not be reached after three tries', async () => {
    const fake = new FakeFetch().on('GET', at(`/${MERGE}/latest`), () => {
      throw new TypeError('fetch failed');
    });
    expect(await failure(client(fake).latest(MERGE))).toEqual(UNREACHABLE);
    expect(fake.calls).toHaveLength(3);
  });
});

describe('an error that is not about the registry', () => {
  it('is passed on as it is: a request the allow-list refuses is a mistake of the code, not an answer', async () => {
    const broken = new NpmRegistryClient({ get: () => Promise.reject(new TypeError('boom')) });
    await expect(broken.version(MERGE, '4.17.20')).rejects.toThrow(TypeError);
    await expect(broken.latest(MERGE)).rejects.toThrow('boom');
  });
});

describe('what the client of the lookup can reach on the registry', () => {
  function http(fake: FakeFetch): HttpClient {
    return new HttpClient({
      policy: new EgressPolicy(),
      userAgent: 'baip-lens/test',
      fetch: fake.fetch,
      sleep: noSleep,
    });
  }
  const url = (path: string): URL => new URL(`https://registry.npmjs.org${path}`);

  it('is refused everything but the two requests, and any credential, by its allow-list', async () => {
    const fake = new FakeFetch();
    const refused: HttpRequest[] = [
      { url: url('/baip-fixture-merge') },
      { url: url('/@baip-fixture/odata/3.1.0') },
      { url: url('/baip-fixture-merge/4.17.20+build.5') },
      { url: url('/baip-fixture-merge/4.17.20?write=true') },
      { url: url('/baip-fixture-merge/-/baip-fixture-merge-4.17.20.tgz') },
      { url: url('/-/whoami') },
      { url: url('/baip-fixture-merge/4.17.20'), method: 'POST', body: '{}' },
      { url: url('/-/user/org.couchdb.user:x'), method: 'POST', body: '{}' },
      { url: new URL('http://registry.npmjs.org/baip-fixture-merge/4.17.20') },
      { url: new URL('https://registry.npmjs.org:8443/baip-fixture-merge/4.17.20') },
      { url: new URL('https://registry.yarnpkg.com/baip-fixture-merge/4.17.20') },
      {
        url: url('/baip-fixture-merge/4.17.20'),
        headers: { authorization: 'Bearer POISON-abcdef123456' },
      },
      {
        url: url('/baip-fixture-merge/latest'),
        headers: { Authorization: 'Basic POISON-dXNlcjpwYXNz' },
      },
      { url: url('/baip-fixture-merge/4.17.20'), headers: { Cookie: 'session=POISON-abcdef' } },
      {
        url: url('/baip-fixture-merge/4.17.20'),
        headers: { 'Proxy-Authorization': 'Basic POISON-dXNlcjpwYXNz' },
      },
      // The same holds for the other source of the lookup.
      {
        url: new URL('https://api.osv.dev/v1/vulns/x'),
        headers: { cookie: 'session=POISON-abcdef' },
      },
    ];
    for (const request of refused) {
      await expect(http(fake).request(request), request.url.href).rejects.toThrow('Egress denied');
    }
    expect(fake.calls).toEqual([]);
  });

  it('cannot be made to send another method or a body through the read-only view', async () => {
    const fake = registryFetch();
    // Structural typing lets extra fields through; get() must override them.
    const smuggled = { url: url('/baip-fixture-merge/4.17.20'), method: 'PUT', body: '{"x":1}' };
    await http(fake).get(smuggled);
    expect(fake.calls.map((call) => [call.method, call.body])).toEqual([['GET', undefined]]);
  });
});
