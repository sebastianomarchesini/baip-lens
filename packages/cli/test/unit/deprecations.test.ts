import { describe, expect, it } from 'vitest';
import { CheckSkipError } from '../../src/checks.js';
import {
  type DeprecationResult,
  MAX_DEPRECATION_TABLE_BYTES,
  PROGRESS_EVERY,
  collectDeprecations,
} from '../../src/collectors/deprecations.js';
import type { PackageRef } from '../../src/collectors/packageLookup.js';
import { HttpClient } from '../../src/http/httpClient.js';
import { NpmRegistryClient } from '../../src/http/npmRegistryClient.js';
import { rawListBytes } from '../../src/io/jsonSize.js';
import { RawDeprecationSchema } from '../../src/model/raw.js';
import { EgressPolicy } from '../../src/net/allowlist.js';
import {
  LATEST_VERSION,
  REGISTRY_HOST,
  REGISTRY_POISON,
  type RegistryScript,
  askedLatest,
  askedVersions,
  registryDocument,
  registryFetch,
  registryRequest,
  scriptRegistry,
} from '../support/dependencyScript.js';
import { FakeFetch, jsonResponse, noSleep } from '../support/fakeFetch.js';
import { SUSPICIOUS } from '../support/leak.js';

/*
 * The lookup on the npm registry against a scripted fetch, through the real
 * client, HTTP client and allow-list: which requests it makes, and that it
 * hands over everything or nothing.
 */

const MERGE = { name: 'baip-fixture-merge', version: '4.17.20' };
const OLD_MERGE = { name: 'baip-fixture-merge', version: '3.10.1' };
const ODATA = { name: '@baip-fixture/odata', version: '3.1.0' };
const SERVER = { name: 'baip-fixture-server', version: '2.4.1' };
const GONE = 'baip-fixture-merge 4.x is no longer supported, upgrade to 5.x';
const NOTHING: DeprecationResult = { deprecations: [], unknown: 0 };
const isRegistry = (url: URL): boolean => url.host === REGISTRY_HOST;

function clientOn(fake: FakeFetch): NpmRegistryClient {
  return new NpmRegistryClient(
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

const collect = (
  fake: FakeFetch,
  packages: readonly PackageRef[],
  log?: (line: string) => void,
): Promise<DeprecationResult> => collectDeprecations(clientOn(fake), packages, { log });

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

const UNEXPECTED: [string, string] = ['error', 'registry.npmjs.org sent an unexpected answer'];
const UNREACHABLE: [string, string] = ['unavailable', 'registry.npmjs.org could not be reached'];
const TOO_LARGE: [string, string] = [
  'error',
  'registry.npmjs.org sent more than a snapshot can hold',
];

/** `count` packages with invented names, in name order. */
function bulk(count: number, version = '1.0.0'): PackageRef[] {
  return Array.from({ length: count }, (_, i) => ({
    name: `baip-bulk-${String(i).padStart(5, '0')}`,
    version,
  }));
}

/** `count` versions of one package, in the order they are asked about. */
function versionsOf(name: string, count: number): PackageRef[] {
  return Array.from({ length: count }, (_, i) => ({
    name,
    version: `1.${String(i).padStart(5, '0')}.0`,
  }));
}

const down = (): never => {
  throw new TypeError('fetch failed', {
    cause: Object.assign(new Error('connect ECONNREFUSED POISON_registry_address'), {
      code: 'ECONNREFUSED',
    }),
  });
};

const SAMPLE: RegistryScript = {
  versions: {
    'baip-fixture-merge@4.17.20': { deprecated: GONE },
    'baip-fixture-merge@3.10.1': { deprecated: 'baip-fixture-merge 3.x has reached its end' },
    '@baip-fixture/odata@3.1.0': { deprecated: true },
  },
  latest: {
    'baip-fixture-merge': { version: '5.2.0' },
    '@baip-fixture/odata': { version: '3.1.0', deprecated: true },
  },
};

const SAMPLE_ROWS = [
  { ...ODATA, message: '', latest: '3.1.0', latestDeprecated: true },
  {
    ...OLD_MERGE,
    message: 'baip-fixture-merge 3.x has reached its end',
    latest: '5.2.0',
    latestDeprecated: false,
  },
  { ...MERGE, message: GONE, latest: '5.2.0', latestDeprecated: false },
];

describe('collectDeprecations', () => {
  it('asks once about every package version, then once for the latest of each deprecated package', async () => {
    const fake = registryFetch(SAMPLE);
    const found = await collect(fake, [SERVER, MERGE, ODATA, OLD_MERGE, MERGE, SERVER]);
    expect(found).toEqual({ deprecations: SAMPLE_ROWS, unknown: 0 });
    // The packages sorted and each once; then the packages with a deprecated version, each
    // once, though two versions of one of them are deprecated. The one that is fine is not
    // asked about again.
    expect(fake.calls.map((call) => `${call.method} ${call.url.pathname}`)).toEqual([
      'GET /@baip-fixture%2fodata/3.1.0',
      'GET /baip-fixture-merge/3.10.1',
      'GET /baip-fixture-merge/4.17.20',
      'GET /baip-fixture-server/2.4.1',
      'GET /@baip-fixture%2fodata/latest',
      'GET /baip-fixture-merge/latest',
    ]);
    for (const call of fake.calls) {
      expect(call.url.origin).toBe('https://registry.npmjs.org');
      expect(call.url.search).toBe('');
      expect(call.body).toBeUndefined();
      expect(call.headers).toEqual({ accept: 'application/json', 'user-agent': 'baip-lens/test' });
      expect(call.redirect).toBe('manual');
    }
    for (const row of found.deprecations) {
      expect(RawDeprecationSchema.safeParse(row).success).toBe(true);
    }
  });

  it('keeps of an answer what a row names: nothing of the people behind a package', async () => {
    const found = await collect(registryFetch(SAMPLE), [SERVER, MERGE, ODATA, OLD_MERGE]);
    for (const row of found.deprecations) {
      expect(Object.keys(row)).toEqual([
        'name',
        'version',
        'message',
        'latest',
        'latestDeprecated',
      ]);
    }
    // Every document names its maintainers, its publisher and its author, with their addresses.
    for (const planted of REGISTRY_POISON.slice(0, 7)) {
      expect(JSON.stringify(registryDocument(MERGE.name, MERGE.version))).toContain(planted);
    }
    for (const never of REGISTRY_POISON) expect(JSON.stringify(found), never).not.toContain(never);
  });

  it('makes no request when there is nothing to look up', async () => {
    const fake = new FakeFetch();
    expect(await collect(fake, [])).toEqual(NOTHING);
    expect(fake.calls).toEqual([]);
  });

  it('stores nothing for packages that are not deprecated, having asked about each', async () => {
    const fake = registryFetch();
    expect(await collect(fake, [MERGE, ODATA, SERVER])).toEqual(NOTHING);
    expect(askedVersions(fake)).toEqual([
      '@baip-fixture/odata@3.1.0',
      'baip-fixture-merge@4.17.20',
      'baip-fixture-server@2.4.1',
    ]);
    // No package has a deprecated version: no latest version is asked for.
    expect(askedLatest(fake)).toEqual([]);
  });

  it('gives the same table whatever the order of the packages and of the answers', async () => {
    const packages = [MERGE, ODATA, SERVER, OLD_MERGE];
    const orders = [packages, [...packages].reverse(), [SERVER, MERGE, ODATA, ODATA, OLD_MERGE]];
    for (const order of orders) {
      expect(await collect(registryFetch(SAMPLE), order)).toEqual({
        deprecations: SAMPLE_ROWS,
        unknown: 0,
      });
    }

    // The first version asked about in the pool, and the latest version asked for first, are
    // answered last.
    const held: (() => void)[] = [];
    const hold = (): Promise<void> => new Promise<void>((resolve) => held.push(resolve));
    const release = (): void => void setTimeout(() => held.splice(0).forEach((go) => go()), 5);
    const scripted = scriptRegistry(new FakeFetch(), SAMPLE);
    const answered: string[] = [];
    const slow = new FakeFetch().on('GET', isRegistry, async (call) => {
      const asked = registryRequest(call.url);
      const what = `${asked?.name}@${asked?.version}`;
      if (what === 'baip-fixture-merge@3.10.1' || what === '@baip-fixture/odata@latest') {
        await hold();
      } else if (what === 'baip-fixture-server@2.4.1' || what === 'baip-fixture-merge@latest') {
        release();
      }
      answered.push(what);
      return scripted.fetch(call.url, { method: 'GET' });
    });
    expect(await collect(slow, packages)).toEqual({ deprecations: SAMPLE_ROWS, unknown: 0 });
    expect(answered).toEqual([
      '@baip-fixture/odata@3.1.0',
      'baip-fixture-merge@4.17.20',
      'baip-fixture-server@2.4.1',
      'baip-fixture-merge@3.10.1',
      'baip-fixture-merge@latest',
      '@baip-fixture/odata@latest',
    ]);
    expect(askedLatest(slow)).toEqual([ODATA.name, MERGE.name]);
  });

  describe('a version the registry does not know', () => {
    it('is an answer, not a failure: it is counted, and nothing is stored about it', async () => {
      const fake = registryFetch({
        versions: {
          'baip-fixture-merge@4.17.20': { deprecated: GONE },
          'baip-fixture-server@2.4.1': { status: 404 },
          '@baip-fixture/odata@3.1.0': { status: 404 },
        },
        latest: { 'baip-fixture-merge': { version: '5.2.0' } },
      });
      const found = await collect(fake, [MERGE, ODATA, SERVER, OLD_MERGE]);
      expect(found).toEqual({
        deprecations: [{ ...MERGE, message: GONE, latest: '5.2.0', latestDeprecated: false }],
        unknown: 2,
      });
      // Asked once each: a 404 is not worth a repeat, and its package is not asked about again.
      expect(fake.calls).toHaveLength(5);
      expect(askedLatest(fake)).toEqual([MERGE.name]);
    });

    it('is counted for every package, also when the registry knows none of them', async () => {
      const fake = new FakeFetch().on('GET', isRegistry, jsonResponse('Not Found', 404));
      expect(await collect(fake, bulk(40))).toEqual({ deprecations: [], unknown: 40 });
      expect(fake.calls).toHaveLength(40);
    });
  });

  describe('the latest version of a deprecated package', () => {
    const DEPRECATED = { versions: { 'baip-fixture-merge@4.17.20': { deprecated: GONE } } };
    const row = async (latest: RegistryScript['latest']): Promise<unknown> =>
      (await collect(registryFetch({ ...DEPRECATED, latest }), [MERGE])).deprecations[0];

    it('is stored with the row, and whether it is deprecated as well', async () => {
      expect(await row({ [MERGE.name]: { version: '5.2.0' } })).toEqual({
        ...MERGE,
        message: GONE,
        latest: '5.2.0',
        latestDeprecated: false,
      });
      expect(await row({ [MERGE.name]: { version: '4.17.21', deprecated: 'given up' } })).toEqual({
        ...MERGE,
        message: GONE,
        latest: '4.17.21',
        latestDeprecated: true,
      });
      // The installed version is the latest one: the package as a whole was given up.
      expect(await row({ [MERGE.name]: { version: '4.17.20', deprecated: GONE } })).toMatchObject({
        latest: '4.17.20',
        latestDeprecated: true,
      });
      // What the script does not name is a newer version that is fine.
      expect(await row({})).toMatchObject({ latest: LATEST_VERSION, latestDeprecated: false });
    });

    it('is none when the registry names none: there is no version to move to', async () => {
      expect(await row({ [MERGE.name]: null })).toEqual({
        ...MERGE,
        message: GONE,
        latest: null,
        latestDeprecated: true,
      });
    });

    it.each([
      ['two numbers', '5.2'],
      ['a leading v', 'v5.2.0'],
      ['a range', '^5.2.0'],
      ['a path', '../../etc/passwd'],
      ['markup', '<script>alert(1)</script>'],
      ['65 characters', `5.2.0-${'9'.repeat(59)}`],
      ['nothing', ''],
    ])('is not stored when it is %s, which is no exact version', async (_name, version) => {
      expect(await row({ [MERGE.name]: { version } })).toMatchObject({
        latest: null,
        latestDeprecated: false,
      });
      expect(await row({ [MERGE.name]: { version, deprecated: true } })).toMatchObject({
        latest: null,
        latestDeprecated: true,
      });
    });

    it('is stored with its prerelease and build metadata, as the registry names it', async () => {
      expect(await row({ [MERGE.name]: { version: '6.0.0-rc.1+build.7' } })).toMatchObject({
        latest: '6.0.0-rc.1+build.7',
      });
    });
  });

  describe('packages that differ in build metadata only', () => {
    const BUILDS = [
      { name: MERGE.name, version: '1.4.0' },
      { name: MERGE.name, version: '1.4.0+build.7' },
      { name: MERGE.name, version: '1.4.0+build.8' },
      { name: MERGE.name, version: '1.4.0-rc.1+build.7' },
    ];

    it('are asked about once, without it, and each of them gets the answer', async () => {
      const fake = registryFetch({
        versions: { 'baip-fixture-merge@1.4.0': { deprecated: GONE } },
        latest: { [MERGE.name]: { version: '5.2.0' } },
      });
      const found = await collect(fake, BUILDS);
      expect(fake.calls.map((call) => call.url.pathname)).toEqual([
        '/baip-fixture-merge/1.4.0',
        '/baip-fixture-merge/1.4.0-rc.1',
        '/baip-fixture-merge/latest',
      ]);
      // A row for each package as the lockfile names it: the rule looks a package up by that.
      expect(found.deprecations.map((item) => [item.version, item.message])).toEqual([
        ['1.4.0', GONE],
        ['1.4.0+build.7', GONE],
        ['1.4.0+build.8', GONE],
      ]);
      expect(found.unknown).toBe(0);
    });

    it('are each counted when the registry does not know the version', async () => {
      const fake = registryFetch({ versions: { 'baip-fixture-merge@1.4.0': { status: 404 } } });
      expect(await collect(fake, BUILDS)).toEqual({ deprecations: [], unknown: 3 });
    });
  });

  describe('the message of a deprecation', () => {
    const JWT = `eyJhbGciOiJSUzI1NiJ9.${'eyJzdWIiOiJQT0lTT04ifQ'.repeat(2)}.c2lnbmF0dXJlLVBPSVNPTg`;

    async function stored(deprecated: unknown): Promise<string | undefined> {
      const fake = registryFetch({ versions: { 'baip-fixture-merge@4.17.20': { deprecated } } });
      return (await collect(fake, [MERGE])).deprecations[0]?.message;
    }

    it('is cleaned before it is stored: no address, no token, no control character', async () => {
      const message = await stored(
        `Unmaintained, write to jane.poison@example.com:\u001b[31m token ${JWT},\r\n see ` +
          `https://ci:POISON_registry_pw@poison-registry.example.com/x \u202eor\u200b move on`,
      );
      expect(message).toBe(
        'Unmaintained, write to [e-mail]: token [redacted-token], see ' +
          'https://poison-registry.example.com/x or move on',
      );
      for (const { name, pattern } of SUSPICIOUS) {
        expect(pattern.test(message ?? ''), name).toBe(false);
      }
    });

    it('is cut to 200 characters', async () => {
      const message = await stored(
        `No longer supported ${'for a very long list of reasons '.repeat(40)}`,
      );
      expect(message).toHaveLength(200);
      expect(message?.endsWith('…')).toBe(true);
    });

    it('is empty when the registry gives no reason, or nothing visible is left of it', async () => {
      expect(await stored(true)).toBe('');
      expect(await stored(' \u200b\u202e\t\n ')).toBe('');
      // Deprecated all the same: the row is there.
      const fake = registryFetch({
        versions: { 'baip-fixture-merge@4.17.20': { deprecated: ' ' } },
      });
      expect((await collect(fake, [MERGE])).deprecations).toHaveLength(1);
    });

    it('is not one when the field takes the deprecation back, or is no text', async () => {
      for (const deprecated of ['', false, null, 0, 1, ['x'], { reason: 'x' }]) {
        expect(await stored(deprecated), JSON.stringify(deprecated)).toBeUndefined();
      }
    });
  });

  describe('what is held while the other packages are asked about', () => {
    const MIB = 1024 * 1024;
    const COUNT = 40;
    const packages = versionsOf(MERGE.name, COUNT);

    /**
     * Asks about `COUNT` versions of one package, one at a time, each answer
     * built by `document`, and measures the heap when the first and when the
     * last of them is asked about: what lies between is what was kept of the
     * thirty-eight others, in bytes.
     */
    async function heldMeanwhile(
      document: (version: string) => string,
    ): Promise<{ found: DeprecationResult; bytes: number }> {
      const collectGarbage = globalThis.gc;
      if (collectGarbage === undefined) throw new Error('run with --expose-gc (vitest.config.ts)');
      const heap: number[] = [];
      const fake = new FakeFetch().on('GET', isRegistry, (call) => {
        const asked = registryRequest(call.url);
        if (asked?.version === 'latest') return jsonResponse({ version: '2.0.0' });
        const version = asked?.version ?? '';
        if (version === packages[0]?.version || version === packages[COUNT - 1]?.version) {
          collectGarbage();
          heap.push(process.memoryUsage().heapUsed);
        }
        return new Response(document(version), { status: 200 });
      });
      const found = await collectDeprecations(clientOn(fake), packages, { concurrency: 1 });
      expect(askedVersions(fake)).toHaveLength(COUNT);
      expect(heap).toHaveLength(2);
      const [first = 0, last = 0] = heap;
      return { found, bytes: last - first };
    }

    it('is the 200 characters of a message, not the megabyte it came with', async () => {
      // An answer just below what the client reads at all.
      const text = 'word '.repeat((MIB - 1_024) / 5);
      const { found, bytes } = await heldMeanwhile((version) =>
        JSON.stringify({ version, deprecated: text }),
      );
      expect(found.deprecations).toHaveLength(COUNT);
      expect(found.deprecations[0]?.message).toHaveLength(200);
      // Held as they came, the thirty-eight messages take 38 MiB and more (measured: 40).
      // Reduced, about 1.5 MiB are measured: one answer, which does not grow with their number.
      expect(bytes).toBeLessThan(8 * MIB);
    }, 60_000);

    it.each([
      ['one word', `${'A'.repeat(150)} ${'B'.repeat(MIB - 1_024)}`, 'A'.repeat(150)],
      ['one short word', `Unmaintained ${'B'.repeat(MIB - 1_024)}`, 'Unmaintained'],
    ])(
      'is a copy of its own when what is kept of a message is %s: no part of the megabyte',
      async (_name, text, kept) => {
        // Nothing in the kept part is replaced, so without a copy it would be a part of the
        // text it was cut from, and would keep all of it in memory (measured: 40 MiB for 40).
        const { found, bytes } = await heldMeanwhile((version) =>
          JSON.stringify({ version, deprecated: text }),
        );
        expect(found.deprecations).toHaveLength(COUNT);
        expect(found.deprecations[0]?.message).toBe(kept);
        expect(bytes).toBeLessThan(8 * MIB);
      },
      60_000,
    );

    it('is nothing at all of a document that is not deprecated, whatever it holds', async () => {
      const readme = 'x'.repeat(MIB - 4_096);
      const { found, bytes } = await heldMeanwhile((version) =>
        JSON.stringify({ version, readme, maintainers: [{ name: readme.slice(0, 1_000) }] }),
      );
      expect(found).toEqual(NOTHING);
      expect(bytes).toBeLessThan(8 * MIB);
    }, 60_000);
  });

  describe('how many requests are in flight', () => {
    /** A registry that answers after a moment, and notes how many requests it holds at a time. */
    function counting(script: RegistryScript = {}): { fake: FakeFetch; seen: number[] } {
      let inFlight = 0;
      const seen: number[] = [];
      const scripted = scriptRegistry(new FakeFetch(), script);
      const fake = new FakeFetch().on('GET', isRegistry, async (call) => {
        inFlight += 1;
        seen.push(inFlight);
        await new Promise((resolve) => setTimeout(resolve, 2));
        inFlight -= 1;
        return scripted.fetch(call.url, { method: 'GET' });
      });
      return { fake, seen };
    }

    it('is eight at most, and one while the first answer is waited for', async () => {
      const deprecated = Object.fromEntries(
        bulk(60).map((item) => [`${item.name}@${item.version}`, { deprecated: GONE }]),
      );
      const { fake, seen } = counting({ versions: deprecated });
      const found = await collect(fake, bulk(60));
      expect(found.deprecations).toHaveLength(60);
      // Sixty versions, then the latest version of sixty packages.
      expect(fake.calls).toHaveLength(120);
      expect(Math.max(...seen)).toBe(8);
      // Nothing else is in flight while the first request decides whether the registry answers at all.
      expect(seen.slice(0, 2)).toEqual([1, 1]);
    });

    it('is what the caller asks for', async () => {
      const { fake, seen } = counting();
      await collectDeprecations(clientOn(fake), bulk(30), { concurrency: 3 });
      expect(Math.max(...seen)).toBe(3);
    });
  });

  describe('when the registry cannot be reached', () => {
    it('gives up after the first request and its two repeats, however many packages there are', async () => {
      const fake = new FakeFetch().on('GET', isRegistry, down);
      expect(await skip(collect(fake, bulk(2_500)))).toEqual(UNREACHABLE);
      // 2,500 versions would have been asked about: only the first was, three times.
      expect(fake.calls.map((call) => call.url.pathname)).toEqual([
        '/baip-bulk-00000/1.0.0',
        '/baip-bulk-00000/1.0.0',
        '/baip-bulk-00000/1.0.0',
      ]);
    });

    it('starts no further request once one failed, and stores nothing of what was answered', async () => {
      const packages = bulk(200);
      const fake = new FakeFetch()
        .on('GET', (url) => url.pathname === '/baip-bulk-00020/1.0.0', down)
        .on('GET', isRegistry, async (call) => {
          // An answer takes a moment; a refused connection does not.
          await new Promise((resolve) => setTimeout(resolve, 5));
          const asked = registryRequest(call.url);
          return jsonResponse(
            registryDocument(asked?.name ?? '', asked?.version ?? '', { deprecated: GONE }),
          );
        });
      expect(await skip(collect(fake, packages))).toEqual(UNREACHABLE);
      const asked = askedVersions(fake);
      // The twenty-first version was tried three times. Eight requests are in flight at a
      // time: of those that were, none was followed by another.
      expect(asked.filter((item) => item === 'baip-bulk-00020@1.0.0')).toHaveLength(3);
      expect(new Set(asked).size).toBeLessThanOrEqual(21 + 8);
      // Every version answered so far is deprecated; no latest version was asked for.
      expect(askedLatest(fake)).toEqual([]);
    });

    it('stores nothing either when it is the latest version of one package that is not answered', async () => {
      const deprecated = Object.fromEntries(
        bulk(30).map((item) => [`${item.name}@${item.version}`, { deprecated: GONE }]),
      );
      const fake = scriptRegistry(
        new FakeFetch().on('GET', (url) => url.pathname === '/baip-bulk-00029/latest', down),
        { versions: deprecated },
      );
      // Twenty-nine of the thirty packages were answered in full.
      expect(await skip(collect(fake, bulk(30)))).toEqual(UNREACHABLE);
      expect(askedVersions(fake)).toHaveLength(30);
      expect(askedLatest(fake).filter((name) => name === 'baip-bulk-00029')).toHaveLength(3);
    });
  });

  describe('when the connection fails while an answer is read', () => {
    /** The headers and the first bytes of an answer, and then `error`. */
    function brokenAnswer(error: Error): Response {
      return new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('{"'));
          },
          pull(controller) {
            controller.error(error);
          },
        }),
      );
    }
    const reset = (): Error =>
      new TypeError('terminated', {
        cause: Object.assign(new Error('read ECONNRESET POISON_registry_address'), {
          code: 'ECONNRESET',
        }),
      });
    const timeout = (): Error =>
      new DOMException('The operation was aborted due to timeout', 'TimeoutError');
    const MERGE_PATH = `${REGISTRY_HOST}/baip-fixture-merge/4.17.20`;

    it.each([
      ['a connection that is reset', reset],
      ['a timeout', timeout],
    ])(
      'records %s in the answer about a version as "could not be reached", after three tries',
      async (_name, error) => {
        const fake = new FakeFetch().on('GET', MERGE_PATH, () => brokenAnswer(error()));
        expect(await skip(collect(fake, [MERGE]))).toEqual(UNREACHABLE);
        expect(fake.calls).toHaveLength(3);
      },
    );

    it.each([
      ['a connection that is reset', reset],
      ['a timeout', timeout],
    ])('records %s in the latest version the same way, after three tries', async (_name, error) => {
      const fake = scriptRegistry(
        new FakeFetch().on('GET', `${REGISTRY_HOST}/baip-fixture-merge/latest`, () =>
          brokenAnswer(error()),
        ),
        SAMPLE,
      );
      expect(await skip(collect(fake, [MERGE]))).toEqual(UNREACHABLE);
      expect(askedLatest(fake)).toEqual([MERGE.name, MERGE.name, MERGE.name]);
    });

    it('reads on when the second try arrives whole', async () => {
      const fake = scriptRegistry(
        new FakeFetch()
          .on('GET', MERGE_PATH, () => brokenAnswer(reset()), 1)
          .on(
            'GET',
            `${REGISTRY_HOST}/@baip-fixture%2fodata/latest`,
            () => brokenAnswer(timeout()),
            1,
          ),
        SAMPLE,
      );
      expect(await collect(fake, [MERGE, ODATA, OLD_MERGE])).toEqual({
        deprecations: SAMPLE_ROWS,
        unknown: 0,
      });
      expect(
        askedVersions(fake).filter((item) => item === 'baip-fixture-merge@4.17.20'),
      ).toHaveLength(2);
      expect(askedLatest(fake).filter((name) => name === ODATA.name)).toHaveLength(2);
    });
  });

  describe('when the registry answers with something else than was asked', () => {
    it.each([
      ['a 500', 500, 'registry.npmjs.org answered HTTP 500', 3],
      ['a 429', 429, 'registry.npmjs.org answered HTTP 429', 3],
      ['a 403', 403, 'registry.npmjs.org answered HTTP 403', 1],
      ['a 401', 401, 'registry.npmjs.org answered HTTP 401', 1],
      ['a redirect', 302, 'registry.npmjs.org answered HTTP 302', 1],
    ])('records %s about a version by its status', async (_name, status, reason, calls) => {
      const fake = registryFetch({ versions: { 'baip-fixture-merge@4.17.20': { status } } });
      expect(await skip(collect(fake, [MERGE]))).toEqual(['error', reason]);
      expect(fake.calls).toHaveLength(calls);
    });

    it('records an error about the latest version the same way, and keeps nothing of the versions', async () => {
      const fake = registryFetch({
        versions: SAMPLE.versions,
        latest: { [MERGE.name]: { version: '5.2.0', status: 500 } },
      });
      expect(await skip(collect(fake, [MERGE, ODATA, OLD_MERGE]))).toEqual([
        'error',
        'registry.npmjs.org answered HTTP 500',
      ]);
    });

    it('records an answer it does not understand as that, never with the text of the answer', async () => {
      const page = new FakeFetch().on(
        'GET',
        isRegistry,
        new Response('<html>POISON_registry_page</html>', { status: 200 }),
      );
      expect(await skip(collect(page, [MERGE]))).toEqual(UNEXPECTED);
      // The document of another version than the one that was asked about.
      const other = new FakeFetch().on(
        'GET',
        isRegistry,
        jsonResponse(registryDocument(MERGE.name, '4.17.21', { deprecated: GONE })),
      );
      expect(await skip(collect(other, [MERGE]))).toEqual(UNEXPECTED);
      // A 200 that says nothing about a version: "not deprecated" is not read into it.
      const gateway = new FakeFetch().on('GET', isRegistry, jsonResponse({ status: 'blocked' }));
      expect(await skip(collect(gateway, [MERGE, SERVER]))).toEqual(UNEXPECTED);
      expect(gateway.calls).toHaveLength(1);
    });

    it('records an error of its own as one, without its message', async () => {
      // A name that is not one never reaches a request: the client refuses to send it.
      const fake = registryFetch();
      expect(
        await skip(collect(fake, [{ name: '../POISON_registry_name', version: '1.0.0' }])),
      ).toEqual(['error', 'the lookup on registry.npmjs.org stopped with an unexpected error']);
      expect(fake.calls).toEqual([]);
    });
  });

  describe('a lookup of many packages', () => {
    it(`says how far it is every ${PROGRESS_EVERY.toLocaleString('en-US')} answers`, async () => {
      const log: string[] = [];
      const fake = registryFetch();
      await collect(fake, bulk(4_500), (line) => log.push(line));
      expect(log).toEqual([
        'registry.npmjs.org: 2000 of 4500 package(s) checked',
        'registry.npmjs.org: 4000 of 4500 package(s) checked',
      ]);
      expect(fake.calls).toHaveLength(4_500);
    });

    it('says nothing for a lookup of fewer packages, and counts a version it does not know as answered', async () => {
      const log: string[] = [];
      await collect(registryFetch(SAMPLE), [MERGE, ODATA, SERVER], (line) => log.push(line));
      await collect(registryFetch(), bulk(1_999), (line) => log.push(line));
      expect(log).toEqual([]);
      const unknown = new FakeFetch().on('GET', isRegistry, jsonResponse('Not Found', 404));
      await collect(unknown, bulk(2_000), (line) => log.push(line));
      expect(log).toEqual(['registry.npmjs.org: 2000 of 2000 package(s) checked']);
    });

    it('refuses more packages than a scan keeps, before anything is sent', async () => {
      const fake = registryFetch();
      expect(await skip(collect(fake, bulk(20_001)))).toEqual([
        'error',
        'more than 20,000 packages to look up',
      ]);
      expect(fake.calls).toEqual([]);
    });

    it('asks about 20,000 packages in 20,000 requests, and stores every one that is deprecated', async () => {
      const log: string[] = [];
      // Every package is deprecated, with a message of an ordinary length: the latest version of
      // each is asked for as well.
      const fake = new FakeFetch().on('GET', isRegistry, (call) => {
        const asked = registryRequest(call.url);
        return asked?.version === 'latest'
          ? jsonResponse({ version: '2.0.0' })
          : jsonResponse({ version: asked?.version, deprecated: GONE });
      });
      const found = await collect(fake, bulk(20_000), (line) => log.push(line));
      expect(found.deprecations).toHaveLength(20_000);
      expect(found.unknown).toBe(0);
      expect(fake.calls).toHaveLength(40_000);
      expect(log).toHaveLength(10);
      expect(log.at(-1)).toBe('registry.npmjs.org: 20000 of 20000 package(s) checked');
      // About 5 MiB of the 8 the table may take.
      const bytes = rawListBytes(found.deprecations);
      expect(bytes).toBeGreaterThan(4 * 1024 * 1024);
      expect(bytes).toBeLessThanOrEqual(MAX_DEPRECATION_TABLE_BYTES);
    }, 120_000);
  });

  describe('more than a snapshot holds', () => {
    /** 200 characters of three bytes each: the longest message a row can hold, as it is written. */
    const LONGEST = '\u20ac'.repeat(200);
    const VERSIONS = 500;

    /** `packages` packages with `VERSIONS` versions each, every one deprecated with the longest message. */
    function flood(packages: number): { fake: FakeFetch; asked: PackageRef[] } {
      const asked = Array.from({ length: packages }, (_, i) =>
        versionsOf(`baip-bulk-${String(i).padStart(3, '0')}`, VERSIONS),
      ).flat();
      const fake = new FakeFetch().on('GET', isRegistry, (call) => {
        const request = registryRequest(call.url);
        return request?.version === 'latest'
          ? jsonResponse({ version: '2.0.0' })
          : jsonResponse({ version: request?.version, deprecated: LONGEST });
      });
      return { fake, asked };
    }

    it('stores a table of just under 8 MiB as a snapshot writes it', async () => {
      const { fake, asked } = flood(21);
      const found = await collect(fake, asked);
      expect(found.deprecations).toHaveLength(21 * VERSIONS);
      expect(found.deprecations[0]?.message).toBe(LONGEST);
      const bytes = rawListBytes(found.deprecations);
      expect(bytes).toBeGreaterThan(0.95 * MAX_DEPRECATION_TABLE_BYTES);
      expect(bytes).toBeLessThanOrEqual(MAX_DEPRECATION_TABLE_BYTES);
    }, 60_000);

    it('stores nothing when the table would take more than 8 MiB', async () => {
      // A row takes 765 bytes as it is written: 10,965 of them fit, 11,000 do not.
      const { fake, asked } = flood(22);
      expect(await skip(collect(fake, asked))).toEqual(TOO_LARGE);
      // Known for certain only when every version was answered: each was asked about.
      expect(askedVersions(fake)).toHaveLength(22 * VERSIONS);
    }, 60_000);

    it('stops asking once what was answered cannot be stored any more', async () => {
      const { fake, asked } = flood(40);
      expect(await skip(collect(fake, asked))).toEqual(TOO_LARGE);
      // 20,000 versions would have been asked about. The names, versions and messages of
      // about 13,000 of them are more than the table may take: the rest is not asked about,
      // and no latest version is asked for.
      expect(askedLatest(fake)).toEqual([]);
      expect(fake.calls.length).toBeGreaterThan(10_000);
      expect(fake.calls.length).toBeLessThan(14_000);
    }, 60_000);
  });
});
