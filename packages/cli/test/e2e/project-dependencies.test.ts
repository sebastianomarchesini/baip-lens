import { mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type * as HtmlReporter from '../../src/reporters/html.js';
import { type CliIo, EXIT, main } from '../../src/main.js';
import type { Snapshot } from '../../src/model/snapshot.js';
import {
  ACME_DEPRECATIONS,
  ACME_KNOWN_CVE,
  ACME_NO_FIX,
  ACME_MODERATE,
  ACME_OSV_SCRIPT,
  ACME_REGISTRY_SCRIPT,
  ACME_WITHDRAWN,
  OSV_HOST,
  OSV_POISON,
  type OsvScript,
  QUERYBATCH,
  REGISTRY_HOST,
  REGISTRY_POISON,
  type RegistryScript,
  askedAdvisories,
  askedLatest,
  askedPackages,
  askedVersions,
  dependencyFetch,
  osvCalls,
  osvFetch,
  registryCalls,
  registryFetch,
  scriptOsv,
  scriptRegistry,
} from '../support/dependencyScript.js';
import { FakeFetch, jsonResponse, noSleep } from '../support/fakeFetch.js';
import { ABSOLUTE_PATH, expectNoLeaks } from '../support/leak.js';
import { ACME_PUBLIC_PACKAGES, lockfileV3, registryEntry } from '../support/lockfileFixture.js';
import { POISON } from '../support/project.js';
import { type MaterializedFixture, materializeFixture } from '../support/projectFixture.js';

/* The real UI bundle is not under test here; a tiny template keeps the leak checks about our data. */
vi.mock('../../src/reporters/html.js', async (importOriginal) => {
  const actual = await importOriginal<typeof HtmlReporter>();
  return {
    ...actual,
    loadReportTemplate: () =>
      Promise.resolve(`<html><body>${actual.DATA_PLACEHOLDER}</body></html>`),
  };
});

/*
 * `baip-lens project --path` and the lookup of the lockfile packages on
 * OSV.dev and on the npm registry, end to end through `main()`: the
 * acme-incidents fixture is scanned with both sources scripted, and every
 * request they get is looked at. No test here reaches a real host: a request
 * the scripts do not know fails the lookup that made it.
 */

const NOW = new Date('2026-09-29T00:00:00.000Z');
const SNAPSHOT_FILE = 'snapshot-20260929T000000Z.json';
const A1 = 'GHSA-fake-0001-baip';
const A2 = 'GHSA-fake-0002-baip';
const A3 = 'MAL-0000-0001';
const OSV_CHECK = {
  id: 'collect.osv',
  title: 'Known vulnerabilities of npm packages (OSV.dev: POST /v1/querybatch, GET /v1/vulns)',
  roles: [],
};
const REGISTRY_CHECK = {
  id: 'collect.npm-deprecations',
  title: 'Deprecated npm packages (npm registry: GET /<package>/<version>, GET /<package>/latest)',
  roles: [],
};
const TURNED_OFF = {
  status: 'skipped',
  reasonCode: 'disabled',
  reason: 'turned off with --no-dependency-check',
};
/** What the scan says before its first request, for `packages` packages. */
const DISCLOSURE = (packages: number): string =>
  `Looking up ${packages} public npm package(s) on api.osv.dev and registry.npmjs.org: only ` +
  'their names and versions are sent (--no-dependency-check turns this off, ' +
  '--dependency-exclude holds packages back)';
/** What `fetch` throws when a host cannot be reached. */
const unreachable = (host: string): TypeError =>
  new TypeError('fetch failed', {
    cause: Object.assign(new Error(`getaddrinfo ENOTFOUND ${host}`), { code: 'ENOTFOUND' }),
  });
/** A credential of the environment the scan runs in; a folder scan needs none, and none may leave. */
const ENV_TOKEN = 'POISON-env-token-0123456789';
const ASKED = ACME_PUBLIC_PACKAGES.map((item) => `${item.name}@${item.version}`);

/** Two vulnerable packages of the fixture, a withdrawn advisory, and a summary that must be cleaned. */
const SCRIPT: OsvScript = {
  vulnerable: {
    'baip-fixture-merge@4.17.20': [A1, A2],
    'baip-fixture-queue@5.0.2': [A3],
  },
  advisories: {
    [A1]: {
      aliases: ['CVE-2026-00001'],
      summary:
        'Prototype pollution, reported by osv.poison@example.com\u001b[31m\u202e via ' +
        'https://ci:POISON_osv_pw@advisories.example.org/x',
      cvssV3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      label: 'CRITICAL',
      affected: [
        { name: 'baip-fixture-merge', fixed: '4.17.21' },
        { name: 'baip-fixture-other', fixed: '9.9.9' },
      ],
    },
    [A2]: { withdrawn: '2026-09-15T00:00:00Z', label: 'HIGH' },
    [A3]: {
      summary: 'Malicious code in baip-fixture-queue (npm)',
      affected: [{ name: 'baip-fixture-queue' }],
    },
  },
};

interface Run {
  code: number;
  out: string;
  err: string;
  outDir: string;
  fake: FakeFetch;
  snapshot: Snapshot;
  files: Record<string, string>;
}

const tmp = () => mkdtemp(join(tmpdir(), 'baip-lens-dependencies-out-'));

async function scan(root: string, fake: FakeFetch, ...extra: string[]): Promise<Run> {
  const outDir = await tmp();
  let out = '';
  let err = '';
  const io: CliIo = {
    stdout: (text) => (out += text),
    stderr: (text) => (err += text),
    env: { BAIP_LENS_ACCESS_TOKEN: ENV_TOKEN, CF_PASSWORD: ENV_TOKEN },
    fetch: fake.fetch,
    now: () => NOW,
    // No real wait between two tries of a lookup that fails.
    sleep: noSleep,
  };
  const args = ['project', '--path', root, '--out', outDir, '--format', 'html,json,csv,sarif'];
  const code = await main([...args, ...extra], io);
  const files: Record<string, string> = {};
  for (const name of await readdir(outDir))
    files[name] = await readFile(join(outDir, name), 'utf8');
  const snapshot = JSON.parse(files[SNAPSHOT_FILE] ?? '{}') as Snapshot;
  return { code, out, err, outDir, fake, snapshot, files };
}

/** Everything a request carried, as one text. */
const sent = (fake: FakeFetch): string =>
  fake.calls
    .map((call) => `${call.url.href}\n${JSON.stringify(call.headers)}\n${call.body ?? ''}`)
    .join('\n');

/** Terminal output without the lines that name the output files. */
const terminal = (r: Run): string =>
  `${r.out}\n${r.err}`
    .split('\n')
    .filter((line) => line !== 'Wrote:' && !line.trim().startsWith(r.outDir))
    .join('\n');

const check = (r: Run, id: string) => r.snapshot.checks.find((item) => item.id === id);
const skipped = (r: Run) => r.snapshot.checks.filter((item) => item.status === 'skipped');
/** The skipped checks of the scan itself; a rule that needs one of them is skipped with it. */
const skippedCollectors = (r: Run) => skipped(r).filter((item) => item.id.startsWith('collect.'));

/** Whatever else is skipped is a rule that reads the answers of the lookup, and says so. */
function expectOnlyRulesOfTheLookupSkipped(r: Run): void {
  for (const item of skipped(r).filter((other) => !other.id.startsWith('collect.'))) {
    expect(item).toMatchObject({
      reasonCode: 'dependency_skipped',
      reason: 'needs collect.osv, which did not run',
    });
    expect(item.id, item.id).toMatch(/^rule\.DEP_/);
  }
}
const findingIds = (r: Run): string[] => r.snapshot.findings.map((finding) => finding.id);

describe('baip-lens project --path and the lookup on OSV.dev', () => {
  let fixture: MaterializedFixture;
  let r: Run;
  /** The same scan without a lookup: what the lookup must not change. */
  let offline: Run;

  beforeAll(async () => {
    fixture = await materializeFixture('acme-incidents');
    r = await scan(fixture.root, osvFetch(SCRIPT));
    offline = await scan(fixture.root, new FakeFetch(), '--no-dependency-check');
  });
  afterAll(() => fixture.cleanup());

  it('asks OSV.dev about the public packages of the lockfile, and about nothing else', () => {
    expect(r.code, r.err).toBe(EXIT.ok);
    // One query for the nine packages, each once; then each advisory once.
    expect(
      osvCalls(r.fake).map((call) => `${call.method} ${call.url.host}${call.url.pathname}`),
    ).toEqual([
      `POST ${OSV_HOST}/v1/querybatch`,
      `GET ${OSV_HOST}/v1/vulns/${A1}`,
      `GET ${OSV_HOST}/v1/vulns/${A2}`,
      `GET ${OSV_HOST}/v1/vulns/${A3}`,
    ]);
    expect(askedPackages(r.fake)).toEqual(ASKED);
    expect(JSON.parse(r.fake.calls[0]?.body ?? '{}')).toEqual({
      queries: ACME_PUBLIC_PACKAGES.map(({ name, version }) => ({
        package: { name, ecosystem: 'npm' },
        version,
      })),
    });
    for (const call of r.fake.calls) {
      expect(call.url.search).toBe('');
      expect(call.url.username + call.url.password).toBe('');
    }
  });

  it('sends no credential, no cookie, and follows no redirect', () => {
    expect(registryCalls(r.fake).length).toBeGreaterThan(0);
    for (const call of r.fake.calls) {
      expect(['https://api.osv.dev', 'https://registry.npmjs.org']).toContain(call.url.origin);
      expect(Object.keys(call.headers).sort()).toEqual(
        call.method === 'POST'
          ? ['accept', 'content-type', 'user-agent']
          : ['accept', 'user-agent'],
      );
      expect(call.headers['user-agent']).toMatch(/^baip-lens\/\d+\.\d+\.\d+$/);
      expect(call.redirect).toBe('manual');
    }
    const requests = sent(r.fake).toLowerCase();
    for (const never of [ENV_TOKEN, 'authorization', 'cookie', 'bearer', 'token']) {
      expect(requests, never).not.toContain(never.toLowerCase());
    }
  });

  it('sends the name of no other package, and nothing else of the project', () => {
    const requests = sent(r.fake);
    // Planted in the lockfile, the manifest and the files around them: `@poison-scope/private` is among them.
    for (const never of POISON) expect(requests, never).not.toContain(never);
    for (const never of [
      'poison',
      fixture.root,
      tmpdir(),
      'acme',
      'incidents',
      // Listed by the root package.json, and not pinned by the lockfile from the public registry.
      '@sap/',
      'express',
      '@cap-js',
      'package-lock',
      'package.json',
      'sha512',
      // The install name of an alias: the package behind it is what is installed.
      'baip-fixture-alias',
    ]) {
      expect(requests, never).not.toContain(never);
    }
    // The address a package was resolved from goes nowhere: the registry is named by the
    // host of a request to it, and by nothing a request carries.
    const carried = r.fake.calls
      .map((call) => `${call.url.pathname}\n${JSON.stringify(call.headers)}\n${call.body ?? ''}`)
      .join('\n');
    expect(carried).not.toContain('registry.npmjs.org');
    expect(carried).not.toContain('.tgz');
    expect(sent(r.fake).split('registry.npmjs.org')).toHaveLength(registryCalls(r.fake).length + 1);
  });

  it('says what it sends before it sends it, and sums the answers up', () => {
    const lines = r.err.split('\n');
    const disclosed = lines.indexOf(DISCLOSURE(9));
    expect(disclosed).toBeGreaterThan(-1);
    expect(lines[disclosed - 1]).toBe(
      'Read 1 npm lockfile(s): 9 package(s) from the public npm registry, 6 other package(s) not checked',
    );
    expect(lines[disclosed + 1]).toBe(
      'api.osv.dev: 2 of 9 package(s) have a known vulnerability (2 advisories)',
    );
    expect(lines[disclosed + 2]).toBe('registry.npmjs.org: 0 of 9 package(s) are deprecated');
    expect(r.err.match(/Looking up/g)).toHaveLength(1);
  });

  it('records each lookup as a check of its own, between the lockfiles and the rules', () => {
    const ids = r.snapshot.checks.map((item) => item.id);
    expect(ids.slice(0, 4)).toEqual([
      'collect.project',
      'collect.dependencies',
      'collect.osv',
      'collect.npm-deprecations',
    ]);
    expect(ids.slice(4).every((id) => id.startsWith('rule.'))).toBe(true);
    expect(check(r, 'collect.osv')).toEqual({ ...OSV_CHECK, status: 'ran' });
    expect(check(r, 'collect.npm-deprecations')).toEqual({ ...REGISTRY_CHECK, status: 'ran' });
    expect(r.snapshot.options.dependencyCheck).toBe(true);
    expect(skipped(r)).toEqual([]);
  });

  it('stores what OSV.dev answered: the advisories that stand, cleaned, and the packages that have them', () => {
    expect(r.snapshot.raw.advisories).toEqual([
      {
        id: A1,
        aliases: ['CVE-2026-00001'],
        summary: 'Prototype pollution, reported by [e-mail] via https://advisories.example.org/x',
        cvssV3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        label: 'CRITICAL',
      },
      {
        id: A3,
        aliases: [],
        summary: 'Malicious code in baip-fixture-queue (npm)',
        cvssV3: null,
        label: null,
      },
    ]);
    expect(r.snapshot.raw.vulnerablePackages).toEqual([
      {
        name: 'baip-fixture-merge',
        version: '4.17.20',
        advisories: [{ id: A1, fixed: ['4.17.21'] }],
      },
      { name: 'baip-fixture-queue', version: '5.0.2', advisories: [{ id: A3, fixed: [] }] },
    ]);
  });

  it('changes nothing else of the result: the files, the lockfile record and the other rules are the same', () => {
    expect(r.snapshot.raw.projects).toEqual(offline.snapshot.raw.projects);
    const others = (run: Run) => run.snapshot.findings.filter((f) => f.id !== 'DEP_KNOWN_CVE');
    expect(others(r)).toEqual(others(offline));
    expect(findingIds(r)).toContain('CAP_MOCKED_AUTH_IN_PROD');
    expect(findingIds(r)).toContain('DEP_NOT_CHECKED');
  });

  it('leaks nothing into any output: no planted value, nothing of a record that is not read', () => {
    const never = [
      ...POISON,
      ...OSV_POISON,
      'POISON_osv_pw',
      'baip-fixture-other',
      // The withdrawn advisory.
      A2,
      ENV_TOKEN,
      fixture.root,
      tmpdir(),
    ];
    expect(Object.keys(r.files).sort()).toEqual([
      'baip-lens-apps.csv',
      'baip-lens-findings.csv',
      'baip-lens-report.html',
      'baip-lens-report.json',
      'baip-lens-report.sarif',
      SNAPSHOT_FILE,
    ]);
    expectNoLeaks({ ...r.files, terminal: terminal(r) }, never, [ABSOLUTE_PATH]);
  });

  it('gives the same result again offline: report --from keeps the check and reads the tables', async () => {
    const again = await tmp();
    let out = '';
    const io: CliIo = {
      stdout: (text) => (out += text),
      stderr: () => undefined,
      env: {},
      fetch: () => Promise.reject(new Error('network must not be used')),
      now: () => NOW,
    };
    const args = [
      'report',
      '--from',
      join(r.outDir, SNAPSHOT_FILE),
      '--out',
      again,
      '--format',
      'json',
    ];
    expect(await main(args, io)).toBe(EXIT.ok);
    const first = JSON.parse(r.files['baip-lens-report.json'] ?? '{}') as Snapshot;
    const second = JSON.parse(
      await readFile(join(again, 'baip-lens-report.json'), 'utf8'),
    ) as Snapshot;
    expect(second.findings).toEqual(first.findings);
    expect(second.checks).toEqual(first.checks);
    expect(second.checks).toContainEqual({ ...OSV_CHECK, status: 'ran' });
    expect(second.options.dependencyCheck).toBe(true);
    expect(out).toContain('Scanned project acme-incidents');
  });

  describe('with --no-dependency-check', () => {
    it('makes no request at all', () => {
      expect(offline.code, offline.err).toBe(EXIT.ok);
      expect(offline.fake.calls).toEqual([]);
      expect(offline.err).not.toContain('Looking up');
      expect(offline.err).not.toContain('api.osv.dev:');
      expect(offline.err).not.toContain('registry.npmjs.org');
    });

    it('records the lookup as turned off, in the snapshot, the reports and the terminal', () => {
      // Both sources: the switch is one, and each has its check.
      expect(skippedCollectors(offline)).toEqual([
        {
          ...OSV_CHECK,
          status: 'skipped',
          reasonCode: 'disabled',
          reason: 'turned off with --no-dependency-check',
        },
        { ...REGISTRY_CHECK, ...TURNED_OFF },
      ]);
      expectOnlyRulesOfTheLookupSkipped(offline);
      expect(offline.snapshot.options.dependencyCheck).toBe(false);
      expect(offline.snapshot.raw.advisories).toEqual([]);
      expect(offline.snapshot.raw.vulnerablePackages).toEqual([]);
      expect(offline.snapshot.raw.deprecations).toEqual([]);
      expect(offline.err).toContain('skipped collect.osv: turned off with --no-dependency-check\n');
      expect(offline.err).toContain(
        'skipped collect.npm-deprecations: turned off with --no-dependency-check\n',
      );
      expect(offline.out).toContain(
        '  skipped collect.npm-deprecations: turned off with --no-dependency-check\n',
      );
      expect(offline.files['baip-lens-report.sarif']).toContain(
        'Check collect.npm-deprecations skipped: turned off with --no-dependency-check',
      );
      expect(offline.out).toMatch(
        /^Scanned project acme-incidents: \d+ finding\(s\) \(.*\), \d+ check\(s\) skipped\.\n/,
      );
      expect(offline.out).toContain(
        '  skipped collect.osv: turned off with --no-dependency-check\n',
      );
      const report = JSON.parse(offline.files['baip-lens-report.json'] ?? '{}') as {
        summary: { checksSkipped: number };
      };
      expect(report.summary.checksSkipped).toBe(skipped(offline).length);
      expect(report.summary.checksSkipped).toBeGreaterThan(0);
      expect(offline.files['baip-lens-report.sarif']).toContain(
        'Check collect.osv skipped: turned off with --no-dependency-check',
      );
    });

    it('still reads the lockfile and runs the rules that need no lookup, with the same exit code', async () => {
      expect(offline.snapshot.raw.projects[0]?.dependencies?.packages).toHaveLength(9);
      expect(check(offline, 'collect.dependencies')?.status).toBe('ran');
      expect(check(offline, 'rule.DEP_NOT_CHECKED')?.status).toBe('ran');
      expect(findingIds(offline)).toContain('DEP_NOT_CHECKED');
      // --fail-on judges the findings there are, with and without a lookup.
      const strict = await scan(
        fixture.root,
        new FakeFetch(),
        '--no-dependency-check',
        '--fail-on',
        'high',
      );
      expect(strict.code).toBe(EXIT.findings);
      expect(strict.fake.calls).toEqual([]);
    });
  });

  describe('with --dependency-exclude', () => {
    it('holds the named packages back: not asked about, not kept, counted as excluded', async () => {
      const x = await scan(
        fixture.root,
        osvFetch(SCRIPT),
        '--dependency-exclude',
        '@baip-fixture/*, baip-fixture-MERGE,*-queue',
      );
      expect(x.code, x.err).toBe(EXIT.ok);
      const kept = ASKED.filter((item) => !/odata|merge|queue/.test(item));
      expect(kept).toHaveLength(5);
      expect(askedPackages(x.fake)).toEqual(kept);
      // Their advisories are not asked for either: nothing says they have any.
      expect(askedAdvisories(x.fake)).toEqual([]);
      expect(sent(x.fake)).not.toMatch(/odata|merge|queue/);
      // The registry is asked about the same five, and about none of the others.
      expect(askedVersions(x.fake)).toEqual(kept);
      expect(askedLatest(x.fake)).toEqual([]);
      expect(x.err).toContain(`${DISCLOSURE(5)}\n`);
      expect(x.err).toContain('registry.npmjs.org: 0 of 5 package(s) are deprecated\n');
      expect(x.err).toContain(
        'api.osv.dev: 0 of 5 package(s) have a known vulnerability (0 advisories)\n',
      );

      const dependencies = x.snapshot.raw.projects[0]?.dependencies;
      expect(dependencies?.packages.map((item) => `${item.name}@${item.version}`)).toEqual(kept);
      expect(dependencies?.lockfiles[0]).toMatchObject({ kept: 5, notKept: { excluded: 4 } });
      expect(x.snapshot.raw.vulnerablePackages).toEqual([]);
      const notChecked = x.snapshot.findings.find((f) => f.id === 'DEP_NOT_CHECKED');
      expect(notChecked?.evidence).toMatchObject({ excluded: 4, checked: 5 });

      // Neither a held-back name nor a pattern is written anywhere, or printed.
      for (const [name, content] of Object.entries({ ...x.files, terminal: terminal(x) })) {
        expect(content, name).not.toMatch(
          /baip-fixture\/odata|baip-fixture-merge|baip-fixture-queue/i,
        );
        expect(content, name).not.toContain('@baip-fixture/*');
        expect(content, name).not.toContain('*-queue');
      }
      expect(x.snapshot.options).toEqual(r.snapshot.options);
    });

    it('asks nothing when every public package is held back, and the lookup still ran', async () => {
      const x = await scan(fixture.root, new FakeFetch(), '--dependency-exclude', '*');
      expect(x.code, x.err).toBe(EXIT.ok);
      expect(x.fake.calls).toEqual([]);
      expect(x.err).not.toContain('Looking up');
      expect(check(x, 'collect.osv')).toEqual({ ...OSV_CHECK, status: 'ran' });
      expect(check(x, 'collect.npm-deprecations')).toEqual({ ...REGISTRY_CHECK, status: 'ran' });
      expect(x.snapshot.raw.projects[0]?.dependencies?.packages).toEqual([]);
    });

    it.each([
      ['a pattern with a blank', '@acme-private/billing tool'],
      ['an empty item', '@acme-private/*,,x'],
      ['an empty list', ''],
    ])('refuses %s: exit code 2, nothing read, sent or written', async (_name, list) => {
      const fake = osvFetch();
      const x = await scan(fixture.root, fake, '--dependency-exclude', list);
      expect(x.code).toBe(EXIT.error);
      expect(x.err).toContain(
        '--dependency-exclude needs package names or patterns such as @acme/*',
      );
      expect(x.err).not.toContain('acme-private');
      expect(fake.calls).toEqual([]);
      expect(x.files).toEqual({});
    });
  });

  describe('when OSV.dev cannot be reached', () => {
    let down: Run;
    beforeAll(async () => {
      // The registry answers: only OSV.dev is out of reach.
      const fake = scriptRegistry(
        new FakeFetch().on('POST', QUERYBATCH, () => {
          throw unreachable('api.osv.dev');
        }),
      );
      down = await scan(fixture.root, fake);
    });

    it('gives up after one request and its two repeats, and still exits 0 with every report', () => {
      expect(down.code, down.err).toBe(EXIT.ok);
      expect(osvCalls(down.fake).map((call) => `${call.method} ${call.url.pathname}`)).toEqual([
        'POST /v1/querybatch',
        'POST /v1/querybatch',
        'POST /v1/querybatch',
      ]);
      expect(Object.keys(down.files)).toHaveLength(6);
    });

    it('records the lookup as skipped, never as a clean result', () => {
      expect(skippedCollectors(down)).toEqual([
        {
          ...OSV_CHECK,
          status: 'skipped',
          reasonCode: 'unavailable',
          reason: 'api.osv.dev could not be reached',
        },
      ]);
      expect(down.snapshot.options.dependencyCheck).toBe(true);
      expect(down.snapshot.raw.advisories).toEqual([]);
      expect(down.snapshot.raw.vulnerablePackages).toEqual([]);
      // The other source was asked all the same, and its check ran.
      expect(check(down, 'collect.npm-deprecations')).toEqual({ ...REGISTRY_CHECK, status: 'ran' });
      expect(askedVersions(down.fake)).toEqual(ASKED);
      expect(down.err).toContain('registry.npmjs.org: 0 of 9 package(s) are deprecated\n');
      expect(down.err).toContain('skipped collect.osv: api.osv.dev could not be reached\n');
      expect(down.err).not.toContain('have a known vulnerability');
      expectOnlyRulesOfTheLookupSkipped(down);
      expect(down.out).toMatch(/, \d+ check\(s\) skipped\.\n/);
      expect(down.out).toContain('  skipped collect.osv: api.osv.dev could not be reached\n');
      // Why it could not be reached is not repeated: the cause may name a proxy or an address.
      expect(terminal(down)).not.toContain('ENOTFOUND');
    });

    it('still runs every other rule on the files it read', () => {
      const others = (run: Run) => run.snapshot.findings.filter((f) => f.id !== 'DEP_KNOWN_CVE');
      expect(others(down)).toEqual(others(offline));
      const rules = down.snapshot.checks.filter((item) => item.id.startsWith('rule.'));
      expect(
        rules
          .filter((item) => !item.reason?.includes('collect.osv'))
          .every((item) => item.status === 'ran'),
      ).toBe(true);
      expect(check(down, 'rule.DEP_NOT_CHECKED')?.status).toBe('ran');
    });
  });

  describe('when OSV.dev answers with an error', () => {
    it.each([
      [
        'HTTP 500, three times',
        jsonResponse({ code: 13, message: 'POISON_osv_message' }, 500),
        'api.osv.dev answered HTTP 500',
        3,
      ],
      [
        'HTTP 400',
        jsonResponse({ code: 3, message: 'POISON_osv_message' }, 400),
        'api.osv.dev answered HTTP 400',
        1,
      ],
      [
        'a page that is not JSON',
        new Response('<html>POISON_osv_message</html>', { status: 200 }),
        'api.osv.dev sent an unexpected answer',
        1,
      ],
      [
        'one result too few',
        jsonResponse({ results: [{}] }),
        'api.osv.dev sent an unexpected answer',
        1,
      ],
    ])(
      'records %s with a fixed reason, exits 0, and keeps nothing of the answer',
      async (_name, response, reason, calls) => {
        const x = await scan(
          fixture.root,
          scriptRegistry(new FakeFetch().on('POST', QUERYBATCH, response)),
        );
        expect(x.code, x.err).toBe(EXIT.ok);
        expect(osvCalls(x.fake)).toHaveLength(calls);
        expect(skippedCollectors(x)).toEqual([
          { ...OSV_CHECK, status: 'skipped', reasonCode: 'error', reason },
        ]);
        expect(x.snapshot.raw.advisories).toEqual([]);
        expect(x.snapshot.raw.vulnerablePackages).toEqual([]);
        expectNoLeaks({ ...x.files, terminal: terminal(x) }, ['POISON_osv_message', ...POISON]);
      },
    );

    it('keeps nothing of the packages that were answered when one advisory is not', async () => {
      // The query names two advisories; the second is answered with 404.
      const fake = osvFetch({
        vulnerable: SCRIPT.vulnerable,
        advisories: { [A1]: SCRIPT.advisories?.[A1] ?? {} },
      });
      const x = await scan(fixture.root, fake);
      expect(x.code, x.err).toBe(EXIT.ok);
      expect(skippedCollectors(x)).toEqual([
        {
          ...OSV_CHECK,
          status: 'skipped',
          reasonCode: 'error',
          reason: 'api.osv.dev answered HTTP 404',
        },
      ]);
      expect(x.snapshot.raw.advisories).toEqual([]);
      expect(x.snapshot.raw.vulnerablePackages).toEqual([]);
      expect(JSON.stringify(x.files)).not.toContain(A1);
    });
  });

  it('prints nothing with --quiet, and looks the packages up all the same', async () => {
    const quiet = await scan(fixture.root, osvFetch(SCRIPT), '--quiet');
    expect(quiet.code).toBe(EXIT.ok);
    expect(quiet.out + quiet.err).toBe('');
    expect(askedPackages(quiet.fake)).toEqual(ASKED);
    expect(askedVersions(quiet.fake)).toEqual(ASKED);
    expect(quiet.snapshot.raw.vulnerablePackages).toEqual(r.snapshot.raw.vulnerablePackages);
  });
});

/*
 * The rule that reads the answers, end to end: the scripted OSV.dev of the
 * sample data (test/support/dependencyScript.ts) has every case the rule
 * tells apart once, for the packages of the acme-incidents lockfile.
 */
describe('baip-lens project --path and the findings about vulnerable packages', () => {
  const NPM_LS = 'https://docs.npmjs.com/cli/v11/commands/npm-ls';
  const OVERRIDES = 'https://docs.npmjs.com/cli/v11/configuring-npm/package-json#overrides';
  const OWASP_A03 = 'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/';
  const ACME = { guid: 'project:acme-incidents', name: 'acme-incidents', space: 'project' };

  interface ReportJson {
    findings: Snapshot['findings'];
    checks: Snapshot['checks'];
    apps: Snapshot['apps'];
    summary: { findings: number; findingsBySeverity: Record<string, number> };
    rules: { id: string; owasp: string[] }[];
  }
  interface SarifResult {
    ruleId: string;
    level: string;
    message: { text: string };
    locations: { physicalLocation: { artifactLocation: { uri: string; uriBaseId?: string } } }[];
    properties: { 'security-severity': string; severity: string; evidence: { subject: string } };
  }
  interface SarifLog {
    runs: { tool: { driver: { rules: { id: string }[] } }; results: SarifResult[] }[];
  }

  let fixture: MaterializedFixture;
  let r: Run;
  let report: ReportJson;

  beforeAll(async () => {
    fixture = await materializeFixture('acme-incidents');
    r = await scan(fixture.root, osvFetch(ACME_OSV_SCRIPT));
    report = JSON.parse(r.files['baip-lens-report.json'] ?? '{}') as ReportJson;
  });
  afterAll(() => fixture.cleanup());

  const knownCve = (findings: Snapshot['findings']) =>
    findings.filter((finding) => finding.id === 'DEP_KNOWN_CVE');
  const facts = (findings: Snapshot['findings']) =>
    knownCve(findings).map((f) => [
      f.severity,
      f.evidence.subject,
      f.evidence.fixedIn,
      f.evidence.severityFrom,
    ]);

  it('reports each vulnerable package version of the lockfile once, by the severity of its advisories', () => {
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(check(r, 'collect.osv')?.status).toBe('ran');
    expect(check(r, 'rule.DEP_KNOWN_CVE')).toEqual({
      id: 'rule.DEP_KNOWN_CVE',
      title: 'Dependency with a known vulnerability',
      roles: [],
      status: 'ran',
    });
    expect(skipped(r)).toEqual([]);
    // Worst first: a critical score, malicious code, a high score without a fix, a severity in
    // words, an advisory that states none, and a low score on a package of development.
    expect(facts(r.snapshot.findings)).toEqual(ACME_KNOWN_CVE);
    // Among the findings of the files, in report order.
    expect(r.snapshot.findings.map((f) => [f.id, f.severity, f.evidence.subject])).toEqual([
      ['CAP_MOCKED_AUTH_IN_PROD', 'critical', 'requires.auth'],
      ['CAP_SERVICE_NO_RESTRICTION', 'critical', 'AdminService'],
      ['DEP_KNOWN_CVE', 'critical', '@baip-fixture/odata@3.1.0'],
      ['DEP_KNOWN_CVE', 'critical', 'baip-fixture-queue@5.0.2'],
      ['DEP_KNOWN_CVE', 'high', 'baip-fixture-merge@4.17.20'],
      ['SEED_DATA_SENSITIVE', 'high', 'db/data/acme.incidents-Customers.csv#6'],
      ['SEED_DATA_SENSITIVE', 'high', 'test/data/POISON-headerless.csv#2'],
      ['APPROUTER_CSRF_DISABLED', 'medium', '^/odata/(.*)$'],
      ['APPROUTER_ROUTE_NO_AUTH', 'medium', '^/public/(.*)$'],
      ['CAP_AUDITLOG_MISSING', 'medium', 'requires.audit-log'],
      ['CAP_AUDITLOG_NOT_BOUND', 'medium', 'auditlog'],
      ['CAP_PERSONAL_DATA_UNANNOTATED', 'medium', 'Customers'],
      ['CAP_PERSONAL_DATA_UNANNOTATED', 'medium', 'Addresses'],
      ['CAP_ROLE_NOT_IN_XSUAA', 'medium', 'auditor'],
      ['DEP_KNOWN_CVE', 'medium', 'baip-fixture-merge@3.10.1'],
      ['DEP_KNOWN_CVE', 'medium', 'baip-fixture-watcher@2.3.3'],
      ['DEPLOY_ARTIFACT_IN_REPO', 'medium', 'mta_archives/acme-incidents_1.0.0.mtar'],
      ['UI5_BOOTSTRAP_EXTERNAL', 'medium', 'app/incidents/webapp/index.html'],
      ['CAP_MOCKED_USER_PASSWORD', 'low', 'requires.auth.users'],
      ['DEP_KNOWN_CVE', 'low', 'baip-fixture-mkdir@0.5.1'],
      ['UI5_BOOTSTRAP_EXTERNAL', 'low', 'app/incidents/webapp/test/flpSandbox.html'],
      ['UI5_BOOTSTRAP_EXTERNAL', 'low', 'app/launchpage.html'],
      ['XSUAA_SCOPE_UNUSED', 'low', '$XSAPPNAME.unused'],
      ['DEP_NOT_CHECKED', 'info', 'dependencies'],
    ]);
    expect(r.err).toContain(
      'api.osv.dev: 6 of 9 package(s) have a known vulnerability (6 advisories)\n',
    );
    expect(r.out).toMatch(
      /^Scanned project acme-incidents: 24 finding\(s\) \(4 critical, 3 high, 11 medium, 5 low, 1 info\)\.\n/,
    );
  });

  it('says of a package what its advisories say, which version clears them and which lockfile pins it', () => {
    const [odata, , merge] = knownCve(r.snapshot.findings);
    // A direct dependency with one advisory and a fix.
    expect(odata?.remediation).toMatch(/^Upgrade the package to the version in `fixedIn`/);
    expect({ ...odata, remediation: '' }).toEqual({
      id: 'DEP_KNOWN_CVE',
      severity: 'critical',
      title: 'Dependency with a known vulnerability',
      app: { ...ACME, org: 'local' },
      evidence: {
        subject: '@baip-fixture/odata@3.1.0',
        package: '@baip-fixture/odata',
        version: '3.1.0',
        direct: true,
        scope: 'prod',
        advisories: ['GHSA-fake-0001-baip'],
        advisoryCount: 1,
        aliases: ['CVE-2026-00001'],
        fixedIn: '3.1.2',
        score: 9.8,
        severityFrom: 'cvss',
        summary: 'Requests inside a batch skip the authorization check in @baip-fixture/odata',
        lockfiles: ['package-lock.json'],
        lockfileCount: 1,
      },
      remediation: '',
      references: [
        NPM_LS,
        OVERRIDES,
        'https://osv.dev/vulnerability/GHSA-fake-0001-baip',
        OWASP_A03,
      ],
      location: { file: 'package-lock.json' },
    });
    // A transitive one with two advisories: the worse decides, and one of them has no fix.
    expect(merge).toMatchObject({
      severity: 'high',
      evidence: {
        subject: 'baip-fixture-merge@4.17.20',
        direct: false,
        advisories: [ACME_MODERATE, ACME_NO_FIX],
        advisoryCount: 2,
        aliases: ['CVE-2026-00002'],
        fixedIn: null,
        score: 7.5,
        severityFrom: 'cvss',
        summary: 'A crafted template string makes baip-fixture-merge run for a very long time',
      },
      references: [
        NPM_LS,
        OVERRIDES,
        `https://osv.dev/vulnerability/${ACME_MODERATE}`,
        `https://osv.dev/vulnerability/${ACME_NO_FIX}`,
        OWASP_A03,
      ],
    });
    expect(merge?.remediation).toMatch(/^At least one advisory of this finding names no fixed/);
    // The other version of the same package is in the range the advisory fixed in its own line.
    expect(knownCve(r.snapshot.findings)[3]?.evidence).toMatchObject({
      subject: 'baip-fixture-merge@3.10.1',
      advisories: [ACME_MODERATE],
      fixedIn: '3.10.2',
      score: null,
    });
  });

  it('reports the package behind an alias, and never the name it is installed under', () => {
    const queue = knownCve(r.snapshot.findings)[1];
    expect(queue?.evidence).toMatchObject({
      subject: 'baip-fixture-queue@5.0.2',
      direct: true,
      severityFrom: 'malicious',
      fixedIn: null,
    });
    expect(queue?.remediation).toMatch(/^This package version is reported as malicious code/);
    expect(JSON.stringify(knownCve(r.snapshot.findings))).not.toContain('baip-fixture-alias');
  });

  it('says nothing about a package whose only advisory was taken back', () => {
    expect(askedAdvisories(r.fake)).toContain(ACME_WITHDRAWN);
    expect(r.snapshot.raw.projects[0]?.dependencies?.packages.map((item) => item.name)).toContain(
      'baip-fixture-server',
    );
    for (const [name, content] of Object.entries(r.files)) {
      expect(content, name).not.toContain(ACME_WITHDRAWN);
      expect(content, name).not.toContain('baip-fixture-server@');
      expect(content, name).not.toContain('Reported in error');
    }
  });

  it('counts the findings in the inventory and in the summary', () => {
    expect(report.summary.findings).toBe(24);
    expect(report.summary.findingsBySeverity).toEqual({
      critical: 4,
      high: 3,
      medium: 11,
      low: 5,
      info: 1,
    });
    expect(report.apps[0]).toMatchObject({
      guid: 'project:acme-incidents',
      findingCounts: { critical: 4, high: 3, medium: 11, low: 5, info: 1 },
      highestSeverity: 'critical',
    });
  });

  it('writes the same findings into the JSON, the CSV, the SARIF and the HTML report', () => {
    expect(report.findings).toEqual(r.snapshot.findings);
    expect(report.rules.find((rule) => rule.id === 'DEP_KNOWN_CVE')?.owasp).toEqual(['A03:2025']);

    // CSV: one row per finding; the location is the lockfile, the evidence one cell of JSON.
    const rows = (r.files['baip-lens-findings.csv'] ?? '')
      .split('\r\n')
      .filter((row) => row.startsWith('DEP_KNOWN_CVE,'));
    expect(rows).toHaveLength(6);
    expect(rows.map((row) => row.split(',')[1])).toEqual([
      'critical',
      'critical',
      'high',
      'medium',
      'medium',
      'low',
    ]);
    for (const row of rows) {
      expect(row).toContain(',Dependency with a known vulnerability,local,project,acme-incidents,');
      expect(row).toMatch(/,A03:2025,package-lock\.json,$/);
    }
    expect(rows[0]).toContain('""subject"":""@baip-fixture/odata@3.1.0""');
    expect(rows[0]).toContain('""fixedIn"":""3.1.2""');

    // SARIF: a result per finding at the lockfile, ranked by the severity of the advisories.
    const sarif = JSON.parse(r.files['baip-lens-report.sarif'] ?? '{}') as SarifLog;
    const results = (sarif.runs[0]?.results ?? []).filter((x) => x.ruleId === 'DEP_KNOWN_CVE');
    expect(sarif.runs[0]?.tool.driver.rules.map((rule) => rule.id)).toContain('DEP_KNOWN_CVE');
    expect(
      results.map((x) => [
        x.properties.evidence.subject,
        x.level,
        x.properties['security-severity'],
      ]),
    ).toEqual([
      ['@baip-fixture/odata@3.1.0', 'error', '9.5'],
      ['baip-fixture-queue@5.0.2', 'error', '9.5'],
      ['baip-fixture-merge@4.17.20', 'error', '8.0'],
      ['baip-fixture-merge@3.10.1', 'warning', '5.5'],
      ['baip-fixture-watcher@2.3.3', 'warning', '5.5'],
      ['baip-fixture-mkdir@0.5.1', 'note', '3.0'],
    ]);
    for (const result of results) {
      expect(result.locations[0]?.physicalLocation.artifactLocation).toEqual({
        uri: 'package-lock.json',
        uriBaseId: 'PROJECTROOT',
      });
      expect(result.message.text).toMatch(
        /^Dependency with a known vulnerability \(local\/project\/acme-incidents\)\. /,
      );
    }

    // HTML: the data of the report, embedded.
    const html = r.files['baip-lens-report.html'] ?? '';
    for (const [, subject] of ACME_KNOWN_CVE) expect(html, subject).toContain(`"${subject}"`);
    expect(html).toContain('https://osv.dev/vulnerability/MAL-0000-0001');
  });

  it('leaks nothing into any output: only what the tables name of an advisory', () => {
    const never = [
      ...POISON,
      ...OSV_POISON,
      ACME_WITHDRAWN,
      // A package of an advisory that is not in the lockfile.
      'baip-fixture-merge-deep',
      ENV_TOKEN,
      fixture.root,
      tmpdir(),
    ];
    expect(Object.keys(r.files)).toHaveLength(6);
    expectNoLeaks({ ...r.files, terminal: terminal(r) }, never, [ABSOLUTE_PATH]);
    // The terminal says how many, never which.
    expect(terminal(r)).not.toMatch(/baip-fixture|GHSA|MAL-/);
  });

  it('gives the same findings again offline, in every format: report --from asks nothing', async () => {
    const again = await tmp();
    let out = '';
    const io: CliIo = {
      stdout: (text) => (out += text),
      stderr: () => undefined,
      env: {},
      fetch: () => Promise.reject(new Error('network must not be used')),
      now: () => NOW,
    };
    const args = ['report', '--from', join(r.outDir, SNAPSHOT_FILE), '--out', again];
    expect(await main([...args, '--format', 'html,json,csv,sarif'], io)).toBe(EXIT.ok);
    for (const name of [
      'baip-lens-report.json',
      'baip-lens-findings.csv',
      'baip-lens-apps.csv',
      'baip-lens-report.sarif',
      'baip-lens-report.html',
    ]) {
      expect(await readFile(join(again, name), 'utf8'), name).toBe(r.files[name]);
    }
    expect(out).toMatch(/^Scanned project acme-incidents: 24 finding\(s\) \(4 critical, 3 high, /);
    // The threshold judges them offline as it does after the scan.
    expect(await main([...args, '--format', 'json', '--fail-on', 'critical'], io)).toBe(
      EXIT.findings,
    );
  });

  it('reports none of them when the lookup is turned off, and says that the rule did not run', async () => {
    const off = await scan(fixture.root, osvFetch(ACME_OSV_SCRIPT), '--no-dependency-check');
    expect(off.fake.calls).toEqual([]);
    expect(knownCve(off.snapshot.findings)).toEqual([]);
    expect(check(off, 'rule.DEP_KNOWN_CVE')).toEqual({
      id: 'rule.DEP_KNOWN_CVE',
      title: 'Dependency with a known vulnerability',
      roles: [],
      status: 'skipped',
      reasonCode: 'dependency_skipped',
      reason: 'needs collect.osv, which did not run',
    });
    // The two lookups, and the rule that reads the answers of the first.
    expect(off.out).toMatch(
      /^Scanned project acme-incidents: 18 finding\(s\) .*3 check\(s\) skipped/,
    );
    expect(off.out).toContain(
      '  skipped rule.DEP_KNOWN_CVE: needs collect.osv, which did not run\n',
    );
  });

  it('reports none of a package that --dependency-exclude holds back', async () => {
    const x = await scan(
      fixture.root,
      osvFetch(ACME_OSV_SCRIPT),
      '--dependency-exclude',
      'baip-fixture-merge,@baip-fixture/*',
    );
    expect(x.code, x.err).toBe(EXIT.ok);
    expect(facts(x.snapshot.findings).map(([, subject]) => subject)).toEqual([
      'baip-fixture-queue@5.0.2',
      'baip-fixture-watcher@2.3.3',
      'baip-fixture-mkdir@0.5.1',
    ]);
    expect(check(x, 'rule.DEP_KNOWN_CVE')?.status).toBe('ran');
    // What was held back is counted by the other rule, and named nowhere.
    expect(x.snapshot.findings.find((f) => f.id === 'DEP_NOT_CHECKED')?.evidence).toMatchObject({
      excluded: 3,
      checked: 6,
    });
    for (const [name, content] of Object.entries({ ...x.files, terminal: terminal(x) })) {
      expect(content, name).not.toMatch(/baip-fixture-merge|baip-fixture\/odata/);
    }
  });
});

/*
 * The second source of the lookup, end to end: the npm registry is asked
 * about every public package of the lockfile, and what it marks as deprecated
 * is stored. The scripted registry (test/support/dependencyScript.ts) has
 * every case the lookup tells apart once, for the packages of the
 * acme-incidents lockfile; each of its documents names people and their
 * addresses, as the real ones do.
 */
describe('baip-lens project --path and the lookup on the npm registry', () => {
  let fixture: MaterializedFixture;
  let r: Run;
  /** The same scan against a registry on which no version is deprecated. */
  let plain: Run;

  beforeAll(async () => {
    fixture = await materializeFixture('acme-incidents');
    r = await scan(
      fixture.root,
      dependencyFetch({ osv: ACME_OSV_SCRIPT, registry: ACME_REGISTRY_SCRIPT }),
    );
    plain = await scan(fixture.root, osvFetch(ACME_OSV_SCRIPT));
  });
  afterAll(() => fixture.cleanup());

  it('asks the registry about every public package of the lockfile, and for the latest version of the deprecated ones', () => {
    expect(r.code, r.err).toBe(EXIT.ok);
    // The nine packages, each once, in the order OSV.dev was asked about them; then the two
    // packages that have a deprecated version. A scoped name is one segment, its slash encoded.
    expect(
      registryCalls(r.fake).map((call) => `${call.method} ${call.url.host}${call.url.pathname}`),
    ).toEqual([
      `GET ${REGISTRY_HOST}/@baip-fixture%2fodata/3.1.0`,
      `GET ${REGISTRY_HOST}/baip-fixture-legacy-http/1.9.3`,
      `GET ${REGISTRY_HOST}/baip-fixture-merge/3.10.1`,
      `GET ${REGISTRY_HOST}/baip-fixture-merge/4.17.20`,
      `GET ${REGISTRY_HOST}/baip-fixture-mkdir/0.5.1`,
      `GET ${REGISTRY_HOST}/baip-fixture-queue/5.0.2`,
      `GET ${REGISTRY_HOST}/baip-fixture-server/2.4.1`,
      `GET ${REGISTRY_HOST}/baip-fixture-test-kit/7.0.0`,
      `GET ${REGISTRY_HOST}/baip-fixture-watcher/2.3.3`,
      `GET ${REGISTRY_HOST}/baip-fixture-legacy-http/latest`,
      `GET ${REGISTRY_HOST}/baip-fixture-mkdir/latest`,
    ]);
    expect(askedVersions(r.fake)).toEqual(ASKED);
    expect(askedVersions(r.fake)).toEqual(askedPackages(r.fake));
    expect(askedLatest(r.fake)).toEqual(['baip-fixture-legacy-http', 'baip-fixture-mkdir']);
    // After OSV.dev: the first request to the registry follows the last one to OSV.dev.
    const hosts = r.fake.calls.map((call) => call.url.host);
    expect(hosts.lastIndexOf(OSV_HOST)).toBeLessThan(hosts.indexOf(REGISTRY_HOST));
  });

  it('sends a GET and nothing with it: no body, no query, no credential, no cookie, no redirect followed', () => {
    for (const call of registryCalls(r.fake)) {
      expect(call.url.origin).toBe('https://registry.npmjs.org');
      expect(call.method).toBe('GET');
      expect(call.body).toBeUndefined();
      expect(call.url.search).toBe('');
      expect(call.url.hash).toBe('');
      expect(call.url.username + call.url.password).toBe('');
      expect(call.url.pathname.split('/')).toHaveLength(3);
      expect(Object.keys(call.headers).sort()).toEqual(['accept', 'user-agent']);
      expect(call.headers.accept).toBe('application/json');
      expect(call.headers['user-agent']).toMatch(/^baip-lens\/\d+\.\d+\.\d+$/);
      expect(call.redirect).toBe('manual');
    }
    const requests = sent(r.fake).toLowerCase();
    for (const never of [ENV_TOKEN, 'authorization', 'cookie', 'bearer', 'basic', 'token']) {
      expect(requests, never).not.toContain(never.toLowerCase());
    }
  });

  it('sends the name of no other package to the registry, and nothing else of the project', () => {
    const requests = registryCalls(r.fake)
      .map((call) => `${call.url.href}\n${JSON.stringify(call.headers)}\n${call.body ?? ''}`)
      .join('\n');
    // Planted in the lockfile, the manifest and the files around them: `@poison-scope/private` is among them.
    for (const never of POISON) expect(requests, never).not.toContain(never);
    for (const never of [
      'poison',
      fixture.root,
      tmpdir(),
      'acme',
      'incidents',
      // Listed by the root package.json, and not pinned by the lockfile from the public registry.
      '@sap',
      'express',
      '@cap-js',
      'package-lock',
      'package.json',
      '.tgz',
      'sha512',
      // The install name of an alias: the package behind it is what is installed.
      'baip-fixture-alias',
    ]) {
      expect(requests, never).not.toContain(never);
    }
    // Every path is one the lockfile step kept a package for.
    const kept = new Set<string>(ACME_PUBLIC_PACKAGES.map((item) => item.name));
    for (const call of registryCalls(r.fake)) {
      const name = decodeURIComponent(call.url.pathname.split('/')[1] ?? '');
      expect(kept.has(name), name).toBe(true);
    }
  });

  it('says it before the first request, how many are deprecated, and how many the registry does not know', () => {
    const lines = r.err.split('\n');
    const disclosed = lines.indexOf(DISCLOSURE(9));
    expect(disclosed).toBeGreaterThan(-1);
    expect(lines.slice(disclosed + 1, disclosed + 3)).toEqual([
      'api.osv.dev: 6 of 9 package(s) have a known vulnerability (6 advisories)',
      'registry.npmjs.org: 2 of 9 package(s) are deprecated, 1 unknown to the registry',
    ]);
    // Nothing is unknown to the other registry, and it says nothing about that.
    expect(plain.err).toContain('registry.npmjs.org: 0 of 9 package(s) are deprecated\n');
    expect(plain.err).not.toContain('unknown to the registry');
    // The terminal says how many, never which.
    expect(terminal(r)).not.toMatch(/baip-fixture|GHSA|MAL-/);
  });

  it('records the lookup as a check of its own, after the one on OSV.dev, with no CF role', () => {
    const ids = r.snapshot.checks.map((item) => item.id);
    expect(ids.slice(0, 4)).toEqual([
      'collect.project',
      'collect.dependencies',
      'collect.osv',
      'collect.npm-deprecations',
    ]);
    expect(check(r, 'collect.npm-deprecations')).toEqual({ ...REGISTRY_CHECK, status: 'ran' });
    expect(skipped(r)).toEqual([]);
    expect(r.snapshot.options.dependencyCheck).toBe(true);
    const report = JSON.parse(r.files['baip-lens-report.json'] ?? '{}') as Snapshot;
    expect(report.checks).toContainEqual({ ...REGISTRY_CHECK, status: 'ran' });
  });

  it('stores the deprecated versions, the message cleaned: the version it does not know is not among them', () => {
    expect(r.snapshot.raw.deprecations).toEqual(ACME_DEPRECATIONS);
    // The message as the registry sent it holds an address of a person, an escape sequence, a
    // credential in a link and a direction mark: the row above is what is left of it.
    const message = r.snapshot.raw.deprecations[0]?.message ?? '';
    expect(message).toContain('[e-mail]');
    expect(message).toContain('https://deprecations.example.org/legacy-http');
    for (const row of r.snapshot.raw.deprecations) {
      expect(Object.keys(row)).toEqual([
        'name',
        'version',
        'message',
        'latest',
        'latestDeprecated',
      ]);
    }
    expect(JSON.stringify(r.snapshot.raw.deprecations)).not.toContain('baip-fixture-test-kit');
    expect(plain.snapshot.raw.deprecations).toEqual([]);
  });

  it('changes nothing else of the result: the files, the lockfile record and the answers of OSV.dev are the same', () => {
    expect(r.snapshot.raw.projects).toEqual(plain.snapshot.raw.projects);
    expect(r.snapshot.raw.advisories).toEqual(plain.snapshot.raw.advisories);
    expect(r.snapshot.raw.vulnerablePackages).toEqual(plain.snapshot.raw.vulnerablePackages);
    expect(r.snapshot.checks.slice(0, 4)).toEqual(plain.snapshot.checks.slice(0, 4));
    expect(findingIds(r)).toContain('DEP_KNOWN_CVE');
    expect(findingIds(r)).toContain('DEP_NOT_CHECKED');
  });

  it('leaks nothing into any output: nothing of a document but the two fields that are read', () => {
    const never = [...POISON, ...REGISTRY_POISON, ...OSV_POISON, ENV_TOKEN, fixture.root, tmpdir()];
    expect(Object.keys(r.files).sort()).toEqual([
      'baip-lens-apps.csv',
      'baip-lens-findings.csv',
      'baip-lens-report.html',
      'baip-lens-report.json',
      'baip-lens-report.sarif',
      SNAPSHOT_FILE,
    ]);
    // No address, no token and no absolute path either: the message was cleaned before it was stored.
    expectNoLeaks({ ...r.files, terminal: terminal(r) }, never, [ABSOLUTE_PATH]);
  });

  it('keeps the table and the check offline: report --from asks nothing', async () => {
    const again = await tmp();
    let out = '';
    const io: CliIo = {
      stdout: (text) => (out += text),
      stderr: () => undefined,
      env: {},
      fetch: () => Promise.reject(new Error('network must not be used')),
      now: () => NOW,
    };
    const args = ['report', '--from', join(r.outDir, SNAPSHOT_FILE), '--out', again];
    expect(await main([...args, '--format', 'html,json,csv,sarif'], io)).toBe(EXIT.ok);
    for (const name of [
      'baip-lens-report.json',
      'baip-lens-findings.csv',
      'baip-lens-apps.csv',
      'baip-lens-report.sarif',
      'baip-lens-report.html',
    ]) {
      expect(await readFile(join(again, name), 'utf8'), name).toBe(r.files[name]);
    }
    const second = JSON.parse(
      await readFile(join(again, 'baip-lens-report.json'), 'utf8'),
    ) as Snapshot;
    expect(second.checks).toContainEqual({ ...REGISTRY_CHECK, status: 'ran' });
    expect(out).toContain('Scanned project acme-incidents');
  });

  describe('with --no-dependency-check', () => {
    it('asks neither source, and records both lookups as turned off', async () => {
      const off = await scan(
        fixture.root,
        dependencyFetch({ osv: ACME_OSV_SCRIPT, registry: ACME_REGISTRY_SCRIPT }),
        '--no-dependency-check',
      );
      expect(off.code, off.err).toBe(EXIT.ok);
      expect(off.fake.calls).toEqual([]);
      expect(skippedCollectors(off)).toEqual([
        { ...OSV_CHECK, ...TURNED_OFF },
        { ...REGISTRY_CHECK, ...TURNED_OFF },
      ]);
      expect(off.snapshot.raw.deprecations).toEqual([]);
      expect(off.snapshot.options.dependencyCheck).toBe(false);
      expect(off.err).not.toContain('registry.npmjs.org');
      expect(off.out).toContain(
        '  skipped collect.npm-deprecations: turned off with --no-dependency-check\n',
      );
      // The lockfile is read all the same.
      expect(off.snapshot.raw.projects[0]?.dependencies?.packages).toHaveLength(9);
    });
  });

  describe('with --dependency-exclude', () => {
    it('holds the named packages back from the registry as well: not asked about, not stored', async () => {
      const x = await scan(
        fixture.root,
        dependencyFetch({ osv: ACME_OSV_SCRIPT, registry: ACME_REGISTRY_SCRIPT }),
        '--dependency-exclude',
        'baip-fixture-legacy-*,@baip-fixture/*',
      );
      expect(x.code, x.err).toBe(EXIT.ok);
      const kept = ASKED.filter((item) => !/legacy-http|odata/.test(item));
      expect(kept).toHaveLength(7);
      expect(askedVersions(x.fake)).toEqual(kept);
      expect(askedPackages(x.fake)).toEqual(kept);
      // The deprecated package that was held back is not asked for its latest version either.
      expect(askedLatest(x.fake)).toEqual(['baip-fixture-mkdir']);
      expect(sent(x.fake)).not.toMatch(/legacy-http|odata/);
      expect(x.snapshot.raw.deprecations).toEqual([ACME_DEPRECATIONS[1]]);
      expect(x.err).toContain(
        'registry.npmjs.org: 1 of 7 package(s) are deprecated, 1 unknown to the registry\n',
      );
      for (const [name, content] of Object.entries({ ...x.files, terminal: terminal(x) })) {
        expect(content, name).not.toMatch(/baip-fixture-legacy-http|baip-fixture\/odata/i);
        expect(content, name).not.toContain('baip-fixture-legacy-*');
      }
    });
  });

  describe('when the registry cannot be reached', () => {
    let down: Run;
    beforeAll(async () => {
      // OSV.dev answers: only the registry is out of reach.
      const fake = scriptOsv(new FakeFetch(), ACME_OSV_SCRIPT).on(
        'GET',
        (url) => url.host === REGISTRY_HOST,
        () => {
          throw unreachable('registry.npmjs.org');
        },
      );
      down = await scan(fixture.root, fake);
    });

    it('gives up after one request and its two repeats, and still exits 0 with every report', () => {
      expect(down.code, down.err).toBe(EXIT.ok);
      expect(registryCalls(down.fake).map((call) => `${call.method} ${call.url.pathname}`)).toEqual(
        [
          'GET /@baip-fixture%2fodata/3.1.0',
          'GET /@baip-fixture%2fodata/3.1.0',
          'GET /@baip-fixture%2fodata/3.1.0',
        ],
      );
      expect(Object.keys(down.files)).toHaveLength(6);
    });

    it('records that lookup as skipped, never as a clean result, and keeps what OSV.dev answered', () => {
      expect(skippedCollectors(down)).toEqual([
        {
          ...REGISTRY_CHECK,
          status: 'skipped',
          reasonCode: 'unavailable',
          reason: 'registry.npmjs.org could not be reached',
        },
      ]);
      expect(down.snapshot.options.dependencyCheck).toBe(true);
      expect(down.snapshot.raw.deprecations).toEqual([]);
      expect(down.err).toContain(
        'skipped collect.npm-deprecations: registry.npmjs.org could not be reached\n',
      );
      expect(down.err).not.toContain('are deprecated');
      expect(down.out).toMatch(/, \d+ check\(s\) skipped\.\n/);
      expect(down.out).toContain(
        '  skipped collect.npm-deprecations: registry.npmjs.org could not be reached\n',
      );
      expect(down.files['baip-lens-report.sarif']).toContain(
        'Check collect.npm-deprecations skipped: registry.npmjs.org could not be reached',
      );
      // Why it could not be reached is not repeated: the cause may name a proxy or an address.
      expect(terminal(down)).not.toContain('ENOTFOUND');
      // The other source answered: its check ran, and its findings are there.
      expect(check(down, 'collect.osv')).toEqual({ ...OSV_CHECK, status: 'ran' });
      expect(down.snapshot.raw.vulnerablePackages).toEqual(plain.snapshot.raw.vulnerablePackages);
      expect(down.snapshot.findings.filter((f) => f.id === 'DEP_KNOWN_CVE')).toEqual(
        plain.snapshot.findings.filter((f) => f.id === 'DEP_KNOWN_CVE'),
      );
      expect(check(down, 'rule.DEP_KNOWN_CVE')?.status).toBe('ran');
    });
  });

  describe('when neither source can be reached', () => {
    it('records both lookups as skipped, each for its own host, and still reports the files', async () => {
      const fake = new FakeFetch()
        .on('POST', QUERYBATCH, () => {
          throw unreachable('api.osv.dev');
        })
        .on(
          'GET',
          (url) => url.host === REGISTRY_HOST,
          () => {
            throw unreachable('registry.npmjs.org');
          },
        );
      const x = await scan(fixture.root, fake);
      expect(x.code, x.err).toBe(EXIT.ok);
      expect(skippedCollectors(x).map((item) => [item.id, item.reasonCode, item.reason])).toEqual([
        ['collect.osv', 'unavailable', 'api.osv.dev could not be reached'],
        ['collect.npm-deprecations', 'unavailable', 'registry.npmjs.org could not be reached'],
      ]);
      expect(osvCalls(x.fake)).toHaveLength(3);
      expect(registryCalls(x.fake)).toHaveLength(3);
      expect(findingIds(x)).toContain('CAP_MOCKED_AUTH_IN_PROD');
      expect(findingIds(x)).toContain('DEP_NOT_CHECKED');
      expect(Object.keys(x.files)).toHaveLength(6);
    });
  });

  describe('when the registry answers with an error', () => {
    const first = '@baip-fixture/odata@3.1.0';
    const cases: [string, RegistryScript, string, number][] = [
      [
        'HTTP 500, three times',
        { versions: { [first]: { status: 500 } } },
        'registry.npmjs.org answered HTTP 500',
        3,
      ],
      [
        'HTTP 403',
        { versions: { [first]: { status: 403 } } },
        'registry.npmjs.org answered HTTP 403',
        1,
      ],
      [
        'a redirect',
        { versions: { [first]: { status: 302 } } },
        'registry.npmjs.org answered HTTP 302',
        1,
      ],
      [
        'the document of another version',
        { versions: { [first]: { extra: { version: '3.1.1' } } } },
        'registry.npmjs.org sent an unexpected answer',
        1,
      ],
      [
        'a document without a version',
        { versions: { [first]: { extra: { version: undefined } } } },
        'registry.npmjs.org sent an unexpected answer',
        1,
      ],
    ];

    it.each(cases)(
      'records %s with a fixed reason, exits 0, and keeps nothing of the answer',
      async (_name, script, reason, calls) => {
        const x = await scan(fixture.root, registryFetch(script));
        expect(x.code, x.err).toBe(EXIT.ok);
        expect(registryCalls(x.fake)).toHaveLength(calls);
        expect(skippedCollectors(x)).toEqual([
          { ...REGISTRY_CHECK, status: 'skipped', reasonCode: 'error', reason },
        ]);
        // The other source answered, and the rule that reads its answers ran.
        expect(check(x, 'collect.osv')?.status).toBe('ran');
        expect(check(x, 'rule.DEP_KNOWN_CVE')?.status).toBe('ran');
        expect(x.snapshot.raw.deprecations).toEqual([]);
        expectNoLeaks({ ...x.files, terminal: terminal(x) }, [...REGISTRY_POISON, ...POISON]);
      },
    );

    it('keeps nothing of the versions that were answered when a latest version is not', async () => {
      // Two packages have a deprecated version; the latest version of the second is not answered.
      const x = await scan(
        fixture.root,
        registryFetch({
          versions: ACME_REGISTRY_SCRIPT.versions,
          latest: {
            ...ACME_REGISTRY_SCRIPT.latest,
            'baip-fixture-mkdir': { version: '1.0.4', status: 503 },
          },
        }),
      );
      expect(x.code, x.err).toBe(EXIT.ok);
      expect(skippedCollectors(x)).toEqual([
        {
          ...REGISTRY_CHECK,
          status: 'skipped',
          reasonCode: 'error',
          reason: 'registry.npmjs.org answered HTTP 503',
        },
      ]);
      expect(x.snapshot.raw.deprecations).toEqual([]);
      expect(JSON.stringify(x.files)).not.toContain('no longer maintained');
    });
  });

  it('prints nothing with --quiet, and asks the registry all the same', async () => {
    const quiet = await scan(
      fixture.root,
      dependencyFetch({ osv: ACME_OSV_SCRIPT, registry: ACME_REGISTRY_SCRIPT }),
      '--quiet',
    );
    expect(quiet.code).toBe(EXIT.ok);
    expect(quiet.out + quiet.err).toBe('');
    expect(askedVersions(quiet.fake)).toEqual(ASKED);
    expect(quiet.snapshot.raw.deprecations).toEqual(ACME_DEPRECATIONS);
  });
});

/*
 * `--fail-on` judges every finding, so since the lookup exists a vulnerable
 * package can fail a pipeline that passed before. The clean-cap fixture has
 * no finding of its own: what fails here is the package alone.
 */
describe('baip-lens project --path --fail-on and a vulnerable package', () => {
  const HIGH = 'GHSA-fake-0007-baip';
  /** One advisory of the high band for a package of the clean-cap lockfile. */
  const ONE_HIGH: OsvScript = {
    vulnerable: { 'baip-fixture-server@2.5.0': [HIGH] },
    advisories: {
      [HIGH]: {
        summary: 'A long header makes baip-fixture-server stop answering',
        cvssV3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
        affected: [{ name: 'baip-fixture-server', fixed: '2.5.1' }],
      },
    },
  };
  let fixture: MaterializedFixture;

  beforeAll(async () => {
    fixture = await materializeFixture('clean-cap');
  });
  afterAll(() => fixture.cleanup());

  it('passes a project whose packages have no advisory, at any threshold', async () => {
    const clean = await scan(fixture.root, osvFetch(), '--fail-on', 'info');
    expect(clean.code, clean.err).toBe(EXIT.ok);
    expect(askedPackages(clean.fake)).toHaveLength(4);
    expect(clean.snapshot.findings).toEqual([]);
    expect(clean.err).toContain(
      'api.osv.dev: 0 of 4 package(s) have a known vulnerability (0 advisories)\n',
    );
  });

  it('fails with exit code 1 when a package has an advisory at or above the threshold', async () => {
    const failing = await scan(fixture.root, osvFetch(ONE_HIGH), '--fail-on', 'high');
    expect(failing.code).toBe(EXIT.findings);
    expect(failing.snapshot.findings).toHaveLength(1);
    expect(failing.snapshot.findings[0]).toMatchObject({
      id: 'DEP_KNOWN_CVE',
      severity: 'high',
      evidence: { subject: 'baip-fixture-server@2.5.0', fixedIn: '2.5.1', score: 7.5 },
      location: { file: 'package-lock.json' },
    });
    // The reports are written all the same: the exit code is the verdict, not an error.
    expect(Object.keys(failing.files)).toHaveLength(6);
    expect(failing.out).toMatch(
      /^Scanned project clean-cap: 1 finding\(s\) \(0 critical, 1 high, /,
    );

    expect((await scan(fixture.root, osvFetch(ONE_HIGH), '--fail-on', 'medium')).code).toBe(
      EXIT.findings,
    );
  });

  it('passes when the advisory is below the threshold, or no threshold is set', async () => {
    expect((await scan(fixture.root, osvFetch(ONE_HIGH), '--fail-on', 'critical')).code).toBe(
      EXIT.ok,
    );
    expect((await scan(fixture.root, osvFetch(ONE_HIGH))).code).toBe(EXIT.ok);
  });

  it('cannot fail on a package it did not look up: turned off, or OSV.dev out of reach', async () => {
    const off = await scan(
      fixture.root,
      osvFetch(ONE_HIGH),
      '--fail-on',
      'low',
      '--no-dependency-check',
    );
    expect(off.code).toBe(EXIT.ok);
    expect(off.snapshot.findings).toEqual([]);
    // Not a clean result: the report says the rule did not run.
    expect(check(off, 'rule.DEP_KNOWN_CVE')?.status).toBe('skipped');

    const osvDown = scriptRegistry(
      new FakeFetch().on('POST', QUERYBATCH, () => {
        throw new TypeError('fetch failed');
      }),
    );
    const down = await scan(fixture.root, osvDown, '--fail-on', 'low');
    expect(down.code).toBe(EXIT.ok);
    expect(down.snapshot.findings).toEqual([]);
    expect(check(down, 'rule.DEP_KNOWN_CVE')).toMatchObject({
      status: 'skipped',
      reason: 'needs collect.osv, which did not run',
    });
    expect(down.out).toContain('2 check(s) skipped');
  });
});

describe('baip-lens project --path with nothing to look up', () => {
  const folder = async (files: Record<string, string>): Promise<string> => {
    const root = await mkdtemp(join(tmpdir(), 'baip-lens-dependencies-'));
    for (const [name, content] of Object.entries(files)) await writeFile(join(root, name), content);
    return root;
  };
  const MANIFEST = JSON.stringify({
    name: 'acme-tool',
    dependencies: { 'acme-private-ledger': '^1.0.0' },
  });

  it('makes no request for a project without a lockfile, and records the lookup as ran', async () => {
    const fake = new FakeFetch();
    const r = await scan(await folder({ 'package.json': MANIFEST }), fake);
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(fake.calls).toEqual([]);
    expect(r.err).not.toContain('Looking up');
    expect(check(r, 'collect.osv')).toEqual({ ...OSV_CHECK, status: 'ran' });
    expect(check(r, 'collect.npm-deprecations')).toEqual({ ...REGISTRY_CHECK, status: 'ran' });
    expect(r.snapshot.options.dependencyCheck).toBe(true);
    // That the versions are not pinned is said by the rule about the lockfile.
    expect(findingIds(r)).toEqual(['DEP_LOCKFILE_MISSING']);
  });

  it('makes no request for a lockfile without a package from the public registry', async () => {
    const lockfile = lockfileV3(
      { name: 'acme-tool', dependencies: { 'acme-private-ledger': '^1.0.0' } },
      {
        'node_modules/acme-private-ledger': {
          version: '1.0.0',
          resolved:
            'https://npm.acme-private.example/acme-private-ledger/-/acme-private-ledger-1.0.0.tgz',
        },
        'node_modules/acme-private-mirror': {
          version: '2.0.0',
          // The public host, asked through a port of its own: not the public registry.
          resolved:
            'https://registry.npmjs.org:8443/acme-private-mirror/-/acme-private-mirror-2.0.0.tgz',
        },
      },
    );
    const fake = new FakeFetch();
    const r = await scan(
      await folder({ 'package.json': MANIFEST, 'package-lock.json': lockfile }),
      fake,
    );
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(fake.calls).toEqual([]);
    expect(check(r, 'collect.osv')).toEqual({ ...OSV_CHECK, status: 'ran' });
    expect(check(r, 'collect.npm-deprecations')).toEqual({ ...REGISTRY_CHECK, status: 'ran' });
    expect(r.snapshot.raw.projects[0]?.dependencies?.lockfiles[0]).toMatchObject({
      kept: 0,
      notKept: { otherRegistry: 2 },
    });
    expect(findingIds(r)).toEqual(['DEP_NOT_CHECKED']);
  });

  it('asks about the one public package next to private ones, and names none of those', async () => {
    const lockfile = lockfileV3(
      {
        name: 'acme-tool',
        dependencies: { 'acme-private-ledger': '^1.0.0', 'baip-fixture-server': '^2.5.0' },
      },
      {
        'node_modules/acme-private-ledger': {
          version: '1.0.0',
          resolved:
            'https://ci:POISON_lock_token@registry.npmjs.org/acme-private-ledger/-/acme-private-ledger-1.0.0.tgz',
        },
        'node_modules/acme-private-git': {
          version: '3.0.0',
          resolved: 'git+ssh://git@github.com/acme/acme-private-git.git#0123abc',
        },
        'node_modules/baip-fixture-server': registryEntry('baip-fixture-server', '2.5.0'),
      },
    );
    const fake = dependencyFetch();
    const r = await scan(
      await folder({ 'package.json': MANIFEST, 'package-lock.json': lockfile }),
      fake,
    );
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(osvCalls(fake)).toHaveLength(1);
    expect(askedPackages(fake)).toEqual(['baip-fixture-server@2.5.0']);
    // The registry is asked about that one package as well, and about no other.
    expect(registryCalls(fake).map((call) => call.url.pathname)).toEqual([
      '/baip-fixture-server/2.5.0',
    ]);
    expect(sent(fake)).not.toContain('acme');
    expect(r.err).toContain(`${DISCLOSURE(1)}\n`);
  });

  it('says how far the registry is for a lockfile of thousands of packages', async () => {
    const packages: Record<string, unknown> = {};
    for (let i = 0; i < 4_001; i += 1) {
      const name = `baip-bulk-${String(i).padStart(5, '0')}`;
      packages[`node_modules/${name}`] = registryEntry(name, '1.0.0');
    }
    const lockfile = lockfileV3({ name: 'acme-tool', dependencies: {} }, packages);
    const fake = dependencyFetch();
    const r = await scan(
      await folder({ 'package.json': '{"name":"acme-tool"}', 'package-lock.json': lockfile }),
      fake,
    );
    expect(r.code, r.err).toBe(EXIT.ok);
    const lines = r.err.split('\n');
    expect(lines.slice(lines.indexOf(DISCLOSURE(4_001)))).toEqual([
      DISCLOSURE(4_001),
      'api.osv.dev: 0 of 4001 package(s) have a known vulnerability (0 advisories)',
      'registry.npmjs.org: 2000 of 4001 package(s) checked',
      'registry.npmjs.org: 4000 of 4001 package(s) checked',
      'registry.npmjs.org: 0 of 4001 package(s) are deprecated',
      '',
    ]);
    // Five batches for OSV.dev, one request per package for the registry.
    expect(osvCalls(fake)).toHaveLength(5);
    expect(registryCalls(fake)).toHaveLength(4_001);
    expect(check(r, 'collect.npm-deprecations')).toEqual({ ...REGISTRY_CHECK, status: 'ran' });
  }, 30_000);
});
