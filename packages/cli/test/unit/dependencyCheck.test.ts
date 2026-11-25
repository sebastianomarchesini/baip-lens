import { describe, expect, it, vi } from 'vitest';
import { CheckRecorder, COLLECTOR_CHECKS } from '../../src/checks.js';
import { createDependencyLookup, packagesToLookUp } from '../../src/dependencyCheck.js';
import type { RawProject } from '../../src/model/raw.js';
import { SnapshotSchema } from '../../src/model/snapshot.js';
import { type ProjectCollection, projectSnapshot } from '../../src/project.js';
import {
  OSV_HOST,
  type OsvScript,
  QUERYBATCH,
  askedAdvisories,
  askedPackages,
  osvFetch,
  osvRecord,
  sentQueries,
} from '../support/dependencyScript.js';
import { FakeFetch, jsonResponse } from '../support/fakeFetch.js';
import {
  dependencies,
  lockedPackage,
  lockfile,
  packageJson,
  rawProject,
} from '../support/project.js';

/*
 * The lookup `src/main.ts` hands to a project scan, against a scripted fetch:
 * when it asks, what it asks about, which check it records for every outcome,
 * and what it says in the log.
 */

const A1 = 'GHSA-fake-0001-baip';
const OSV_CHECK = {
  id: 'collect.osv',
  title: 'Known vulnerabilities of npm packages (OSV.dev: POST /v1/querybatch, GET /v1/vulns)',
  roles: [],
};

const SCRIPT: OsvScript = {
  vulnerable: { 'baip-fixture-merge@4.17.20': [A1] },
  advisories: {
    [A1]: { label: 'HIGH', affected: [{ name: 'baip-fixture-merge', fixed: '4.17.21' }] },
  },
};

/** A project whose lockfile kept these packages; its root manifest lists a private one. */
function projectWith(id: string, ...packages: [name: string, version: string][]): RawProject {
  return rawProject({
    id,
    packageJson: packageJson({ '@acme-private/billing': '^1.0.0', 'baip-fixture-merge': '^4' }),
    dependencies: dependencies(lockfile('package-lock.json', { kept: packages.length }), {
      packages: packages.map(([name, version]) => lockedPackage(name, version)),
    }),
  });
}

const SRV = projectWith(
  'acme-srv',
  ['baip-fixture-server', '2.4.1'],
  ['baip-fixture-merge', '4.17.20'],
);
const UI = projectWith(
  'acme-ui',
  ['baip-fixture-merge', '4.17.20'],
  ['@baip-fixture/odata', '3.1.0'],
);

interface Run {
  log: string[];
  recorder: CheckRecorder;
  sleeps: number[];
}

/** A recorder as a project scan has it when the lookup is called: the files and the lockfiles were read. */
function scan(lockfilesRead = true): Run {
  const log: string[] = [];
  const recorder = new CheckRecorder({ deep: false }, (line) => log.push(line));
  recorder.ran(COLLECTOR_CHECKS.project);
  if (lockfilesRead) recorder.ran(COLLECTOR_CHECKS.dependencies);
  else recorder.skip(COLLECTOR_CHECKS.dependencies, 'dependency_skipped', 'needs collect.project');
  log.length = 0;
  return { log, recorder, sleeps: [] };
}

function lookupOn(fake: FakeFetch, run: Run, enabled = true) {
  return createDependencyLookup({
    enabled,
    userAgent: 'baip-lens/test',
    fetch: fake.fetch,
    sleep: (ms) => {
      run.sleeps.push(ms);
      return Promise.resolve();
    },
    log: (line) => run.log.push(line),
  });
}

const osvCheck = (run: Run) => run.recorder.list().find((check) => check.id === 'collect.osv');
const NOTHING = { advisories: [], vulnerablePackages: [] };

describe('packagesToLookUp', () => {
  it('takes the packages the lockfile step kept, over all projects, each once and sorted', () => {
    expect(packagesToLookUp([SRV, UI])).toEqual([
      { name: '@baip-fixture/odata', version: '3.1.0' },
      { name: 'baip-fixture-merge', version: '4.17.20' },
      { name: 'baip-fixture-server', version: '2.4.1' },
    ]);
  });

  it('takes nothing from a project without lockfile packages, and never a name from its package.json', () => {
    const before = rawProject({ id: 'old', dependencies: null, packageJson: SRV.packageJson });
    const none = rawProject({ id: 'none', packageJson: SRV.packageJson });
    expect(packagesToLookUp([before, none])).toEqual([]);
    expect(packagesToLookUp([])).toEqual([]);
  });
});

describe('the dependency lookup', () => {
  it('says which checks it records, and whether it may ask', () => {
    const lookup = lookupOn(new FakeFetch(), scan());
    expect(lookup.enabled).toBe(true);
    expect(lookup.checks).toEqual([OSV_CHECK]);
    expect(lookupOn(new FakeFetch(), scan(), false).enabled).toBe(false);
  });

  it('asks OSV.dev about the kept packages of every project, once each, and returns the tables', async () => {
    const fake = osvFetch(SCRIPT);
    const run = scan();
    const tables = await lookupOn(fake, run).run([SRV, UI], run.recorder);
    expect(tables).toEqual({
      advisories: [{ id: A1, aliases: [], summary: null, cvssV3: null, label: 'HIGH' }],
      vulnerablePackages: [
        {
          name: 'baip-fixture-merge',
          version: '4.17.20',
          advisories: [{ id: A1, fixed: ['4.17.21'] }],
        },
      ],
    });
    expect(osvCheck(run)).toEqual({ ...OSV_CHECK, status: 'ran' });
    expect(askedPackages(fake)).toEqual([
      '@baip-fixture/odata@3.1.0',
      'baip-fixture-merge@4.17.20',
      'baip-fixture-server@2.4.1',
    ]);
    expect(askedAdvisories(fake)).toEqual([A1]);
    expect(run.log).toEqual([
      'Looking up 3 public npm package(s) on api.osv.dev: only their names and versions are sent ' +
        '(--no-dependency-check turns this off, --dependency-exclude holds packages back)',
      'api.osv.dev: 1 of 3 package(s) have a known vulnerability (1 advisories)',
    ]);
  });

  it('sends names and versions to api.osv.dev only: no credential, nothing of the project', async () => {
    const fake = osvFetch(SCRIPT);
    const run = scan();
    await lookupOn(fake, run).run([SRV, UI], run.recorder);
    expect(fake.calls.length).toBeGreaterThan(1);
    for (const call of fake.calls) {
      expect(call.url.origin).toBe('https://api.osv.dev');
      expect(Object.keys(call.headers).sort()).toEqual(
        call.method === 'POST'
          ? ['accept', 'content-type', 'user-agent']
          : ['accept', 'user-agent'],
      );
      expect(call.headers['user-agent']).toBe('baip-lens/test');
      expect(call.redirect).toBe('manual');
    }
    const sent = fake.calls.map((call) => `${call.url.href} ${call.body ?? ''}`).join('\n');
    // Not the private name of the root manifest, not a project id, not a lockfile path.
    for (const never of ['acme-private', 'acme-srv', 'acme-ui', 'package-lock', 'acme']) {
      expect(sent, never).not.toContain(never);
    }
  });

  it('says what it is about to send before the first request', async () => {
    const run = scan();
    const before: string[][] = [];
    const fake = new FakeFetch().on('POST', QUERYBATCH, () => {
      before.push([...run.log]);
      return jsonResponse({ results: [{}, {}] });
    });
    await lookupOn(fake, run).run([SRV], run.recorder);
    expect(before).toHaveLength(1);
    expect(before[0]).toHaveLength(1);
    expect(before[0]?.[0]).toMatch(/^Looking up 2 public npm package\(s\) on api\.osv\.dev: /);
    expect(run.log[1]).toBe(
      'api.osv.dev: 0 of 2 package(s) have a known vulnerability (0 advisories)',
    );
  });

  it('counts the packages that have an advisory and the advisories, each on its own', async () => {
    const A2 = 'GHSA-fake-0002-baip';
    const A3 = 'GHSA-fake-0003-baip';
    const line = async (vulnerable: Record<string, string[]>): Promise<string | undefined> => {
      const fake = osvFetch({ vulnerable, advisories: { [A1]: {}, [A2]: {}, [A3]: {} } });
      const run = scan();
      await lookupOn(fake, run).run([SRV, UI], run.recorder);
      return run.log.at(-1);
    };
    // One package with three advisories.
    expect(await line({ 'baip-fixture-merge@4.17.20': [A1, A2, A3] })).toBe(
      'api.osv.dev: 1 of 3 package(s) have a known vulnerability (3 advisories)',
    );
    // Two packages that share one.
    expect(
      await line({ 'baip-fixture-merge@4.17.20': [A1], '@baip-fixture/odata@3.1.0': [A1] }),
    ).toBe('api.osv.dev: 2 of 3 package(s) have a known vulnerability (1 advisories)');
  });

  it('gives a batch 40 seconds and an advisory 20', async () => {
    const timeouts = vi.spyOn(AbortSignal, 'timeout');
    try {
      const run = scan();
      await lookupOn(osvFetch(SCRIPT), run).run([SRV, UI], run.recorder);
      expect(osvCheck(run)?.status).toBe('ran');
      // One time limit per request: the batch (OSV.dev allows itself 35 seconds), then the advisory.
      expect(timeouts.mock.calls).toEqual([[40_000], [20_000]]);
    } finally {
      timeouts.mockRestore();
    }
  });

  it('has eight requests in flight at a time, and never more', async () => {
    const ids = Array.from({ length: 60 }, (_, i) => `GHSA-fake-${String(i).padStart(4, '0')}`);
    let inFlight = 0;
    let most = 0;
    const answered = async (response: Response): Promise<Response> => {
      inFlight += 1;
      most = Math.max(most, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 2));
      inFlight -= 1;
      return response;
    };
    const fake = new FakeFetch()
      .on('POST', QUERYBATCH, (call) =>
        answered(
          jsonResponse({
            results: sentQueries(call).map(() => ({ vulns: ids.map((id) => ({ id })) })),
          }),
        ),
      )
      .on(
        'GET',
        (url) => url.host === OSV_HOST,
        (call) => answered(jsonResponse(osvRecord(call.url.pathname.slice('/v1/vulns/'.length)))),
      );
    const run = scan();
    const tables = await lookupOn(fake, run).run([SRV], run.recorder);
    expect(tables.advisories).toHaveLength(60);
    expect(most).toBe(8);
  });

  it('is recorded as turned off with --no-dependency-check, and makes no request', async () => {
    const fake = new FakeFetch();
    const run = scan();
    expect(await lookupOn(fake, run, false).run([SRV, UI], run.recorder)).toEqual(NOTHING);
    expect(osvCheck(run)).toEqual({
      ...OSV_CHECK,
      status: 'skipped',
      reasonCode: 'disabled',
      reason: 'turned off with --no-dependency-check',
    });
    expect(fake.calls).toEqual([]);
    // No line about a lookup that is not made.
    expect(run.log).toEqual(['skipped collect.osv: turned off with --no-dependency-check']);
  });

  it('is skipped with the lockfiles it depends on, and makes no request', async () => {
    const fake = new FakeFetch();
    const run = scan(false);
    expect(await lookupOn(fake, run).run([], run.recorder)).toEqual(NOTHING);
    expect(osvCheck(run)).toEqual({
      ...OSV_CHECK,
      status: 'skipped',
      reasonCode: 'dependency_skipped',
      reason: 'needs collect.dependencies, which did not run',
    });
    expect(fake.calls).toEqual([]);
    // Turned off wins: it is what the user asked for.
    const off = scan(false);
    await lookupOn(fake, off, false).run([], off.recorder);
    expect(osvCheck(off)?.reasonCode).toBe('disabled');
  });

  it('ran, without a request and without a word, when no project has a package to look up', async () => {
    const fake = new FakeFetch();
    const run = scan();
    const projects = [rawProject({ id: 'none' }), rawProject({ id: 'old', dependencies: null })];
    expect(await lookupOn(fake, run).run(projects, run.recorder)).toEqual(NOTHING);
    expect(osvCheck(run)).toEqual({ ...OSV_CHECK, status: 'ran' });
    expect(fake.calls).toEqual([]);
    expect(run.log).toEqual([]);
  });

  it('is recorded as unavailable when OSV.dev cannot be reached, after two repeats without a real wait', async () => {
    const fake = new FakeFetch().on('POST', QUERYBATCH, () => {
      throw new TypeError('fetch failed', {
        cause: Object.assign(new Error('getaddrinfo ENOTFOUND api.osv.dev'), { code: 'ENOTFOUND' }),
      });
    });
    const run = scan();
    expect(await lookupOn(fake, run).run([SRV, UI], run.recorder)).toEqual(NOTHING);
    expect(osvCheck(run)).toEqual({
      ...OSV_CHECK,
      status: 'skipped',
      reasonCode: 'unavailable',
      reason: 'api.osv.dev could not be reached',
    });
    expect(fake.calls).toHaveLength(3);
    // The backoff went through the injected sleep.
    expect(run.sleeps).toHaveLength(2);
    expect(run.log).toEqual([
      expect.stringMatching(/^Looking up 3 public npm package\(s\) on api\.osv\.dev: /),
      'skipped collect.osv: api.osv.dev could not be reached',
    ]);
  });

  it('is recorded as an error, and returns nothing, when OSV.dev answers with one', async () => {
    const fake = new FakeFetch().on(
      'POST',
      QUERYBATCH,
      jsonResponse({ code: 3, message: 'POISON_osv_message' }, 400),
    );
    const run = scan();
    expect(await lookupOn(fake, run).run([SRV], run.recorder)).toEqual(NOTHING);
    expect(osvCheck(run)).toEqual({
      ...OSV_CHECK,
      status: 'skipped',
      reasonCode: 'error',
      reason: 'api.osv.dev answered HTTP 400',
    });
    expect(run.log.at(-1)).toBe('skipped collect.osv: api.osv.dev answered HTTP 400');
    expect(run.log.join('\n')).not.toContain('POISON');
  });

  it('returns nothing of a lookup that failed half-way', async () => {
    // The query is answered, the advisory it names is not there.
    const fake = osvFetch({ vulnerable: SCRIPT.vulnerable });
    const run = scan();
    expect(await lookupOn(fake, run).run([SRV, UI], run.recorder)).toEqual(NOTHING);
    expect(osvCheck(run)).toMatchObject({
      status: 'skipped',
      reasonCode: 'error',
      reason: 'api.osv.dev answered HTTP 404',
    });
  });
});

describe('a project scan that is handed a lookup', () => {
  const NOW = new Date('2026-09-29T00:00:00.000Z');
  const collection = (): ProjectCollection => ({
    projects: [SRV, UI],
    notRead: [
      {
        check: { id: 'collect.project.acme-db', title: 'Files of deployed app acme-db', roles: [] },
        reasonCode: 'unavailable',
        reason: 'it is stopped',
      },
    ],
  });

  function snapshotWith(fake: FakeFetch | null, log: string[] = [], enabled = true) {
    return projectSnapshot(() => Promise.resolve(collection()), {
      check: COLLECTOR_CHECKS.deployedApp,
      dependenciesCheck: COLLECTOR_CHECKS.deployedDependencies,
      now: () => NOW,
      log: (line) => log.push(line),
      ...(fake === null
        ? {}
        : {
            lookup: createDependencyLookup({
              enabled,
              userAgent: 'baip-lens/test',
              fetch: fake.fetch,
              sleep: () => Promise.resolve(),
              log: (line) => log.push(line),
            }),
          }),
    });
  }

  it('records collect.osv after the checks of the files and before the rules, and stores the tables', async () => {
    const log: string[] = [];
    const snapshot = await snapshotWith(osvFetch(SCRIPT), log);
    const ids = snapshot.checks.map((check) => check.id);
    expect(ids.slice(0, 5)).toEqual([
      'collect.project',
      'collect.dependencies',
      'collect.project.acme-db',
      'collect.osv',
      ids[4],
    ]);
    expect(ids[4]).toMatch(/^rule\./);
    expect(ids.slice(4).every((id) => id.startsWith('rule.'))).toBe(true);
    expect(snapshot.checks[3]).toEqual({ ...OSV_CHECK, status: 'ran' });
    expect(snapshot.raw.advisories.map((row) => row.id)).toEqual([A1]);
    expect(snapshot.raw.vulnerablePackages).toEqual([
      {
        name: 'baip-fixture-merge',
        version: '4.17.20',
        advisories: [{ id: A1, fixed: ['4.17.21'] }],
      },
    ]);
    expect(snapshot.options.dependencyCheck).toBe(true);
    expect(SnapshotSchema.safeParse(snapshot).success).toBe(true);
    // The lookup speaks after the files were read and the skipped apps named.
    expect(log).toEqual([
      'Read 0 project file(s) in project acme-srv',
      'Read 1 npm lockfile(s): 2 package(s) from the public npm registry, 0 other package(s) not checked',
      'Read 0 project file(s) in project acme-ui',
      'Read 1 npm lockfile(s): 2 package(s) from the public npm registry, 0 other package(s) not checked',
      'skipped collect.project.acme-db: it is stopped',
      expect.stringMatching(/^Looking up 3 public npm package\(s\) on api\.osv\.dev: /),
      'api.osv.dev: 1 of 3 package(s) have a known vulnerability (1 advisories)',
    ]);
  });

  it('records that the lookup was turned off, in the check and in the options', async () => {
    const fake = new FakeFetch();
    const snapshot = await snapshotWith(fake, [], false);
    expect(snapshot.checks[3]).toMatchObject({
      id: 'collect.osv',
      status: 'skipped',
      reasonCode: 'disabled',
    });
    expect(snapshot.options.dependencyCheck).toBe(false);
    expect(snapshot.raw.advisories).toEqual([]);
    expect(snapshot.raw.vulnerablePackages).toEqual([]);
    expect(fake.calls).toEqual([]);
  });

  it('keeps the scan going when OSV.dev cannot be reached: the other checks ran, the tables are empty', async () => {
    const fake = new FakeFetch().on('POST', QUERYBATCH, () => {
      throw new TypeError('fetch failed');
    });
    const snapshot = await snapshotWith(fake);
    expect(snapshot.checks[3]).toMatchObject({
      id: 'collect.osv',
      status: 'skipped',
      reasonCode: 'unavailable',
      reason: 'api.osv.dev could not be reached',
    });
    // It was allowed to ask; that it could not is the status of the check.
    expect(snapshot.options.dependencyCheck).toBe(true);
    expect(snapshot.raw.advisories).toEqual([]);
    expect(snapshot.raw.vulnerablePackages).toEqual([]);
    const rules = snapshot.checks.filter((check) => check.id.startsWith('rule.'));
    expect(rules.length).toBeGreaterThan(10);
    expect(
      rules
        .filter((check) => !check.reason?.includes('collect.osv'))
        .every((c) => c.status === 'ran'),
    ).toBe(true);
  });

  it('records no check of a lookup, and looks nothing up, when it is handed none', async () => {
    const snapshot = await snapshotWith(null);
    expect(snapshot.checks.map((check) => check.id)).not.toContain('collect.osv');
    expect(snapshot.options.dependencyCheck).toBe(false);
    expect(snapshot.raw.advisories).toEqual([]);
    expect(snapshot.raw.vulnerablePackages).toEqual([]);
  });

  it('is skipped with the lockfiles when the files could not be collected', async () => {
    const fake = new FakeFetch();
    const snapshot = await projectSnapshot(() => Promise.reject(new Error('boom')), {
      check: COLLECTOR_CHECKS.project,
      now: () => NOW,
      lookup: createDependencyLookup({
        enabled: true,
        userAgent: 'baip-lens/test',
        fetch: fake.fetch,
      }),
    });
    expect(
      snapshot.checks.slice(0, 3).map((c) => [c.id, c.status, c.reasonCode, c.reason]),
    ).toEqual([
      ['collect.project', 'skipped', 'error', 'error: boom'],
      [
        'collect.dependencies',
        'skipped',
        'dependency_skipped',
        'needs collect.project, which did not run',
      ],
      [
        'collect.osv',
        'skipped',
        'dependency_skipped',
        'needs collect.dependencies, which did not run',
      ],
    ]);
    expect(fake.calls).toEqual([]);
  });

  it('refuses a part of the scan that uses the id of the lookup for a check of its own', async () => {
    const own = (): ProjectCollection => ({
      projects: [SRV],
      notRead: [
        { check: COLLECTOR_CHECKS.osv, reasonCode: 'unavailable', reason: 'it is stopped' },
      ],
    });
    const options = { check: COLLECTOR_CHECKS.deployedApp, now: () => NOW };
    await expect(
      projectSnapshot(() => Promise.resolve(own()), {
        ...options,
        lookup: createDependencyLookup({
          enabled: false,
          userAgent: 'baip-lens/test',
          fetch: new FakeFetch().fetch,
        }),
      }),
    ).rejects.toThrow('two checks of one project scan have the same id');
  });
});
