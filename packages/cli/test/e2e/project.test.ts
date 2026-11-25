import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve, sep } from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type * as ChildProcess from 'node:child_process';
import type * as HtmlReporter from '../../src/reporters/html.js';
import { type CliIo, EXIT, main } from '../../src/main.js';
import { isSafeRelativePath } from '../../src/model/paths.js';
import type { RawProject } from '../../src/model/raw.js';
import type { Snapshot } from '../../src/model/snapshot.js';
import { osvFetch } from '../support/dependencyScript.js';
import { ABSOLUTE_PATH, expectNoLeaks } from '../support/leak.js';
import {
  ACME_NOT_KEPT,
  ACME_PUBLIC_PACKAGES,
  CLEAN_PUBLIC_PACKAGES,
  hiddenLockfile,
  lockfileV3,
  registryEntry,
} from '../support/lockfileFixture.js';
import { POISON } from '../support/project.js';
import { type MaterializedFixture, materializeFixture } from '../support/projectFixture.js';

/*
 * The project scan must never spawn a process. The fixture helper itself
 * creates a FIFO with mkfifo, which is the one call let through; everything
 * else throws, as the collector would if it ever tried.
 */
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof ChildProcess>();
  const refuse = (): never => {
    throw new Error('child processes must not be used');
  };
  const execFileSync = ((
    file: string,
    args?: readonly string[],
    options?: ChildProcess.ExecFileSyncOptions,
  ) =>
    file === 'mkfifo'
      ? actual.execFileSync(file, args, options)
      : refuse()) as typeof actual.execFileSync;
  return {
    ...actual,
    default: { ...actual, execFileSync, exec: refuse, execFile: refuse, spawn: refuse },
    execFileSync,
    exec: refuse,
    execFile: refuse,
    execSync: refuse,
    spawn: refuse,
    spawnSync: refuse,
    fork: refuse,
  };
});

/* The real UI bundle is not under test here; a tiny template keeps the leak checks about our data. */
vi.mock('../../src/reporters/html.js', async (importOriginal) => {
  const actual = await importOriginal<typeof HtmlReporter>();
  return {
    ...actual,
    loadReportTemplate: () =>
      Promise.resolve(`<html><body>${actual.DATA_PLACEHOLDER}</body></html>`),
  };
});

const NOW = new Date('2026-09-29T00:00:00.000Z');
const SNAPSHOT_FILE = 'snapshot-20260929T000000Z.json';
const REPORT_FILES = [
  'baip-lens-apps.csv',
  'baip-lens-findings.csv',
  'baip-lens-report.html',
  'baip-lens-report.json',
  'baip-lens-report.sarif',
];

interface Captured {
  io: CliIo;
  out: () => string;
  err: () => string;
}

function capture(): Captured {
  let out = '';
  let err = '';
  return {
    io: {
      stdout: (t) => (out += t),
      stderr: (t) => (err += t),
      env: {},
      fetch: () => Promise.reject(new Error('network must not be used')),
      now: () => NOW,
    },
    out: () => out,
    err: () => err,
  };
}

const tmp = () => mkdtemp(join(tmpdir(), 'baip-lens-project-out-'));

/** Terminal output without the `Wrote:` block, whose lines are the output paths. */
function terminalText(c: Captured, out: string): string {
  const lines = `${c.out()}\n${c.err()}`.split('\n');
  return lines.filter((line) => line !== 'Wrote:' && !line.trim().startsWith(out)).join('\n');
}

async function readOutputs(out: string): Promise<Record<string, string>> {
  const texts: Record<string, string> = {};
  for (const file of await readdir(out)) texts[file] = await readFile(join(out, file), 'utf8');
  return texts;
}

/** Every string value in a JSON-like structure, with its key path. */
function stringValues(value: unknown, path = '$'): [string, string][] {
  if (typeof value === 'string') return [[path, value]];
  if (Array.isArray(value)) return value.flatMap((item, i) => stringValues(item, `${path}[${i}]`));
  if (value !== null && typeof value === 'object') {
    return Object.entries(value).flatMap(([key, item]) => stringValues(item, `${path}.${key}`));
  }
  return [];
}

function pathFields(project: RawProject): string[] {
  return stringValues(project)
    .filter(([path]) => /\.(file|path)$/.test(path))
    .map(([, value]) => value);
}

async function scanFixture(
  fixture: MaterializedFixture,
  ...extra: string[]
): Promise<{ code: number; out: string; c: Captured; snapshot: Snapshot }> {
  const out = await tmp();
  const c = capture();
  // The public packages of the fixture's lockfile are looked up: on a scripted OSV.dev that
  // knows no advisory, so the findings are those of the files. Any other request fails the scan.
  c.io.fetch = osvFetch().fetch;
  const args = ['project', '--path', fixture.root, '--out', out, '--format', 'html,json,csv,sarif'];
  const code = await main([...args, ...extra], c.io);
  const snapshotText = await readFile(join(out, SNAPSHOT_FILE), 'utf8').catch(() => '{}');
  return { code, out, c, snapshot: JSON.parse(snapshotText) as Snapshot };
}

function expectCleanOutputs(
  texts: Record<string, string>,
  terminal: string,
  fixture: MaterializedFixture,
): void {
  const forbidden = [...POISON, fixture.root, tmpdir()];
  expectNoLeaks({ ...texts, terminal }, forbidden, [ABSOLUTE_PATH]);
}

describe('baip-lens project on the acme-incidents fixture', () => {
  let fixture: MaterializedFixture;
  let out: string;
  let c: Captured;
  let code: number;
  let snapshot: Snapshot;
  let texts: Record<string, string>;
  let project: RawProject;

  beforeAll(async () => {
    fixture = await materializeFixture('acme-incidents');
    ({ code, out, c, snapshot } = await scanFixture(fixture));
    texts = await readOutputs(out);
    project = snapshot.raw.projects[0]!;
  });
  afterAll(() => fixture.cleanup());

  it('writes the snapshot and every report format', () => {
    expect(code).toBe(EXIT.ok);
    expect(Object.keys(texts).sort()).toEqual([...REPORT_FILES, SNAPSHOT_FILE]);
    expect(c.out()).toMatch(/^Scanned project acme-incidents: \d+ finding\(s\)/);
    expect(c.err()).toMatch(
      /^Read \d+ project file\(s\), \d+ unreadable in project acme-incidents\n/,
    );
    // The lockfile line carries counts only.
    expect(c.err()).toContain(
      'Read 1 npm lockfile(s): 9 package(s) from the public npm registry, 6 other package(s) not checked\n',
    );
  });

  it('(1) leaks no poison value, personal data, secret or absolute path into any output', () => {
    expectCleanOutputs(texts, terminalText(c, out), fixture);
  });

  it('(2) stores only safe relative paths that resolve inside the project', () => {
    const paths = pathFields(project);
    expect(paths.length).toBeGreaterThan(10);
    for (const file of paths) {
      expect(isSafeRelativePath(file), file).toBe(true);
      expect(resolve(fixture.root, file).startsWith(fixture.root + sep), file).toBe(true);
    }
  });

  it('(3) never opens a deny-listed, linked, special or oversized file', () => {
    const listed = JSON.stringify(project.files);
    for (const name of [
      '.md',
      '.pem',
      '.env',
      '.npmrc',
      '.mtaext',
      '.cdsrc-private.json',
      'default-env.json',
      '.http',
      'link-out',
      'link.cds',
      'pipe.cds',
      'big.cds',
      '.git',
    ]) {
      expect(listed, name).not.toContain(name);
    }
    expect(project.unreadable).toEqual([{ file: 'db/big.cds', kind: 'too-large' }]);
    expect(project.files).toEqual([
      '.cdsrc.json',
      '.cdsrc.yaml',
      'app/incidents/annotations.cds',
      'app/incidents/webapp/index.html',
      'app/incidents/webapp/test/flpSandbox.html',
      'app/incidents/xs-app.json',
      'app/launchpage.html',
      'db/data/acme.incidents-Customers.csv',
      'db/data/acme.incidents-Status.csv',
      'db/schema.cds',
      'mta.yaml',
      'package-lock.json',
      'package.json',
      'srv/external/ExternalService.cds',
      'srv/services.cds',
      'test/data/POISON-export.csv',
      'test/data/POISON-headerless.csv',
      'xs-security.json',
    ]);
    expect(project.filesOpened).toBe(project.files.length + project.unreadable.length);
    expect(project.archives).toEqual([
      { file: 'mta_archives/acme-incidents_1.0.0.mtar', bytes: 64, ignored: false },
    ]);
    expect(project.repository).toBe(true);
  });

  it('(4) keeps every string short and every unreadable entry to file and kind', () => {
    for (const [path, value] of stringValues(snapshot.raw.projects)) {
      expect(value.length, path).toBeLessThanOrEqual(256);
    }
    for (const entry of project.unreadable)
      expect(Object.keys(entry).sort()).toEqual(['file', 'kind']);
  });

  it('(5) check reasons carry neither a rooted path nor a parser position', () => {
    for (const check of snapshot.checks) {
      expect(check.reason ?? '').not.toMatch(/(^|[\s"'(=])\//);
      expect(check.reason ?? '').not.toContain('at line');
    }
    expect(snapshot.checks.find((check) => check.id === 'collect.project')?.status).toBe('ran');
  });

  it('(6) stores bootstrap sources without query, fragment, userinfo or a relative path', () => {
    expect(project.html).toHaveLength(5);
    for (const bootstrap of project.html) expect(bootstrap.src).not.toMatch(/[?#@]/);
    expect(
      project.html.map((h) => [h.file, h.versionForm, h.external, h.integrity, h.testPage]),
    ).toEqual([
      ['app/incidents/webapp/index.html', 'latest', true, false, false],
      ['app/incidents/webapp/index.html', 'none', false, false, false],
      ['app/incidents/webapp/index.html', 'none', false, false, false],
      ['app/incidents/webapp/test/flpSandbox.html', 'specific', true, false, true],
      ['app/launchpage.html', 'evergreen', true, false, false],
    ]);
    // The absolute and the climbing src of the fixture keep their file name only.
    expect(project.html.filter((h) => !h.external).map((h) => h.src)).toEqual([
      'sap-ui-core.js',
      'sap-ui-core.js',
    ]);
  });

  it('(7) names the project with a safe id', () => {
    expect(snapshot.scope.projects?.[0]).toMatch(/^[A-Za-z0-9._-]+$/);
    expect(snapshot.scope.projects).toEqual(['acme-incidents']);
    for (const app of snapshot.apps) expect(app.guid).toMatch(/^(project:)?[A-Za-z0-9._-]+$/);
  });

  it('(8) counts one project and no app', () => {
    const report = JSON.parse(texts['baip-lens-report.json']!) as {
      summary: { projects: number; apps: number };
    };
    expect(report.summary.projects).toBe(1);
    expect(report.summary.apps).toBe(0);
  });

  it('(9) reports exactly the findings the fixture was designed to trigger', () => {
    // Every project rule fires at least once; Warehouses, Incidents, ProcessorService,
    // InternalService, ExternalService, the ui5/MTX/logout routes, $XSAPPNAME.callback
    // and the header-less test/data export stay silent (docs/rules.md). The header-less
    // file whose first row looks like a header fires by column position, never by name.
    // Of the dependency rules, DEP_NOT_CHECKED counts the packages of the lockfile that
    // do not come from the public npm registry; the lockfile is there, so
    // DEP_LOCKFILE_MISSING stays silent.
    expect(snapshot.findings.map((f) => [f.id, f.severity, f.evidence.subject])).toEqual([
      ['CAP_MOCKED_AUTH_IN_PROD', 'critical', 'requires.auth'],
      ['CAP_SERVICE_NO_RESTRICTION', 'critical', 'AdminService'],
      ['SEED_DATA_SENSITIVE', 'high', 'db/data/acme.incidents-Customers.csv#6'],
      ['SEED_DATA_SENSITIVE', 'high', 'test/data/POISON-headerless.csv#2'],
      ['APPROUTER_CSRF_DISABLED', 'medium', '^/odata/(.*)$'],
      ['APPROUTER_ROUTE_NO_AUTH', 'medium', '^/public/(.*)$'],
      ['CAP_AUDITLOG_MISSING', 'medium', 'requires.audit-log'],
      ['CAP_AUDITLOG_NOT_BOUND', 'medium', 'auditlog'],
      ['CAP_PERSONAL_DATA_UNANNOTATED', 'medium', 'Customers'],
      ['CAP_PERSONAL_DATA_UNANNOTATED', 'medium', 'Addresses'],
      ['CAP_ROLE_NOT_IN_XSUAA', 'medium', 'auditor'],
      ['DEPLOY_ARTIFACT_IN_REPO', 'medium', 'mta_archives/acme-incidents_1.0.0.mtar'],
      ['UI5_BOOTSTRAP_EXTERNAL', 'medium', 'app/incidents/webapp/index.html'],
      ['CAP_MOCKED_USER_PASSWORD', 'low', 'requires.auth.users'],
      ['UI5_BOOTSTRAP_EXTERNAL', 'low', 'app/incidents/webapp/test/flpSandbox.html'],
      ['UI5_BOOTSTRAP_EXTERNAL', 'low', 'app/launchpage.html'],
      ['XSUAA_SCOPE_UNUSED', 'low', '$XSAPPNAME.unused'],
      ['DEP_NOT_CHECKED', 'info', 'dependencies'],
    ]);
    // The facts a reader checks first: title branch, view and location of the one-per-project rules.
    const byId = new Map(
      snapshot.findings.map((f) => [`${f.id}:${String(f.evidence.subject)}`, f]),
    );
    expect(byId.get('CAP_SERVICE_NO_RESTRICTION:AdminService')).toMatchObject({
      title: 'Service is open to everyone',
      evidence: { authKind: 'mocked', restrictAllServices: true, writableEntities: 2, actions: 1 },
      location: { file: 'srv/services.cds', line: 4 },
    });
    expect(byId.get('CAP_AUDITLOG_MISSING:requires.audit-log')).toMatchObject({
      title:
        'Audit logging plugin is listed under devDependencies only, so it is inactive in production',
      evidence: { personalDataDeclared: false, inferredEntities: 2, pluginInDevDependencies: true },
    });
    expect(byId.get('CAP_AUDITLOG_NOT_BOUND:auditlog')).toMatchObject({
      evidence: { auditLogKind: null, auditLogConfigured: false },
      location: { file: 'mta.yaml' },
    });
    expect(byId.get('CAP_MOCKED_USER_PASSWORD:requires.auth.users')).toMatchObject({
      evidence: { view: 'development', usersWithPassword: 1 },
    });
    expect(byId.get('CAP_PERSONAL_DATA_UNANNOTATED:Addresses')?.evidence).toMatchObject({
      reason: 'linked-entity',
      linkedTo: 'Customers',
    });
    expect(byId.get('APPROUTER_ROUTE_NO_AUTH:^/public/(.*)$')?.evidence).toMatchObject({
      targetHint: 'other',
      apiLike: false,
      exemptedRoutes: 2,
    });
    expect(byId.get('UI5_BOOTSTRAP_EXTERNAL:app/launchpage.html')?.evidence).toMatchObject({
      host: 'cdn.example.com',
      versionForm: 'evergreen',
    });
    expect(byId.get('DEP_NOT_CHECKED:dependencies')?.evidence).toEqual({
      subject: 'dependencies',
      ...ACME_NOT_KEPT,
      lockfilesNotRead: 0,
      checked: ACME_PUBLIC_PACKAGES.length,
    });
    expect(byId.get('DEP_NOT_CHECKED:dependencies')?.location).toBeUndefined();
    for (const finding of snapshot.findings) {
      expect(typeof finding.evidence.subject, finding.id).toBe('string');
    }
  });

  it('(9b) keeps the lockfile packages from the public npm registry by name, the others as counts', () => {
    expect(project.dependencies).toEqual({
      lockfiles: [
        {
          file: 'package-lock.json',
          kind: 'package-lock',
          lockfileVersion: 3,
          status: 'read',
          kept: ACME_PUBLIC_PACKAGES.length,
          notKept: ACME_NOT_KEPT,
        },
      ],
      lockfilesNotRead: 0,
      packages: ACME_PUBLIC_PACKAGES.map((item) => ({ ...item, lockfiles: ['package-lock.json'] })),
    });
    // Nothing else of a lockfile entry is kept: no address, hash, licence or message.
    const kept = JSON.stringify(project.dependencies);
    for (const never of ['registry.npmjs.org', 'resolved', 'integrity', 'sha512', 'deprecated']) {
      expect(kept, never).not.toContain(never);
    }
    const checks = snapshot.checks.map((check) => [check.id, check.status]);
    expect(checks.slice(0, 2)).toEqual([
      ['collect.project', 'ran'],
      ['collect.dependencies', 'ran'],
    ]);
    expect(checks).toContainEqual(['rule.DEP_LOCKFILE_MISSING', 'ran']);
    expect(checks).toContainEqual(['rule.DEP_NOT_CHECKED', 'ran']);
  });

  it('(10) honours --fail-on', async () => {
    expect((await scanFixture(fixture, '--fail-on', 'high')).code).toBe(EXIT.findings);
    expect((await scanFixture(fixture, '--fail-on', 'none')).code).toBe(EXIT.ok);
  });

  it('(11) report --from reproduces the same findings offline', async () => {
    const again = await tmp();
    const d = capture();
    const args = ['report', '--from', join(out, SNAPSHOT_FILE), '--out', again, '--format', 'json'];
    expect(await main(args, d.io)).toBe(EXIT.ok);
    const first = JSON.parse(texts['baip-lens-report.json']!) as { findings: unknown };
    const second = JSON.parse(await readFile(join(again, 'baip-lens-report.json'), 'utf8')) as {
      findings: unknown;
    };
    expect(second.findings).toEqual(first.findings);
    expect(d.out()).toContain('Scanned project acme-incidents');
  });

  it('collects the structural facts the rules need', () => {
    expect(project.id).toBe('acme-incidents');
    expect(project.sourcesRead).toEqual(['.cdsrc.yaml', '.cdsrc.json', 'package.json']);
    expect(project.cds.effective.production).toMatchObject({
      authKind: 'mocked',
      mockedUsers: 0,
      mockedUsersWithPassword: 0,
      restrictAllServices: true,
      auditLogConfigured: false,
    });
    expect(project.cds.effective.development).toMatchObject({
      authKind: 'mocked',
      mockedUsers: 2,
      mockedUsersWithPassword: 1,
    });
    expect(project.packageJson.dependencies.map((d) => d.name)).toEqual([
      '@sap/cds',
      '@sap/xssec',
      'express',
      'poison-git',
      'poison-file',
      'poison-alias',
    ]);
    // The plugin under devDependencies only: CAP_AUDITLOG_MISSING (inactive in production)
    // and CAP_AUDITLOG_NOT_BOUND (adopted, but no auditlog resource) both apply.
    expect(project.packageJson.devDependencies.map((d) => d.name)).toEqual([
      '@cap-js/sqlite',
      '@cap-js/audit-logging',
    ]);
    expect(project.mta?.modules.map((m) => m.buildpack)).toEqual([
      'nodejs_buildpack',
      'https://github.com/acme/buildpack.git',
      'nodejs_buildpack',
      null,
    ]);
    expect(project.mta?.resources.map((r) => r.service)).toEqual(['xsuaa', 'hana', 'destination']);
    expect(project.xsSecurity.map((x) => [x.file, x.source])).toEqual([
      ['mta.yaml', 'mta.yaml'],
      ['xs-security.json', 'xs-security.json'],
    ]);
    expect(
      project.xsApps[0]?.routes.map((r) => [
        r.target,
        r.targetHint,
        r.authenticationType,
        r.isLogoutPage,
      ]),
    ).toEqual([
      ['destination', 'api', 'xsuaa', false],
      ['destination', 'other', 'none', false],
      ['destination', 'ui5-cdn', 'none', false],
      ['destination', 'api', 'none', false],
      ['localDir', 'other', 'none', true],
      ['service', 'html5-repo', 'xsuaa', false],
    ]);
    const services = project.cdsFiles.find((f) => f.file === 'srv/services.cds')?.services;
    expect(services?.map((s) => [s.name, s.requires, s.protocolNone])).toEqual([
      ['AdminService', [], false],
      ['ProcessorService', ['support'], false],
      ['InternalService', [], true],
    ]);
    expect(services?.[1]?.entities[0]?.restrictTo).toEqual(['auditor']);
    const external = project.cdsFiles.find((f) => f.file === 'srv/external/ExternalService.cds');
    expect(external?.services[0]?.external).toBe(true);
    const schema = project.cdsFiles.find((f) => f.file === 'db/schema.cds');
    expect(schema?.entities.map((e) => e.name)).toEqual([
      'Customers',
      'Addresses',
      'Warehouses',
      'Incidents',
      'Status',
    ]);
    expect(project.seedData.map((s) => [s.file, s.headerRejected, s.sensitiveColumns])).toEqual([
      [
        'db/data/acme.incidents-Customers.csv',
        false,
        [{ columnIndex: 6, kind: 'card', rowsMatching: 1 }],
      ],
      ['db/data/acme.incidents-Status.csv', false, []],
      ['test/data/POISON-export.csv', true, []],
      [
        'test/data/POISON-headerless.csv',
        false,
        [{ columnIndex: 2, kind: 'secret', rowsMatching: 1 }],
      ],
    ]);
  });
});

describe('baip-lens project on the clean-cap fixture', () => {
  it('(12) finds nothing and leaks nothing', async () => {
    const fixture = await materializeFixture('clean-cap');
    try {
      const { code, out, c, snapshot } = await scanFixture(fixture);
      expect(code).toBe(EXIT.ok);
      expect(snapshot.findings).toEqual([]);
      // Its lockfile holds public packages only, so nothing is left unchecked.
      expect(snapshot.raw.projects[0]?.dependencies?.packages).toEqual(
        CLEAN_PUBLIC_PACKAGES.map((item) => ({ ...item, lockfiles: ['package-lock.json'] })),
      );
      expect(snapshot.raw.projects[0]?.archives).toEqual([
        { file: 'mta_archives/clean-cap_1.0.0.mtar', bytes: 64, ignored: true },
      ]);
      expect(snapshot.raw.projects[0]?.unreadable).toEqual([]);
      expectCleanOutputs(await readOutputs(out), terminalText(c, out), fixture);
    } finally {
      await fixture.cleanup();
    }
  });
});

describe('baip-lens project and the npm lockfile of the root', () => {
  const lockfileFindings = (snapshot: Snapshot) =>
    snapshot.findings
      .filter((f) => f.id.startsWith('DEP_'))
      .map((f) => [f.id, f.severity, f.evidence.subject, f.evidence.cause, f.location?.file]);

  it('(14) reports dependencies without a lockfile, and says so offline too', async () => {
    const fixture = await materializeFixture('clean-cap');
    try {
      await rm(join(fixture.root, 'package-lock.json'));
      const { code, out, c, snapshot } = await scanFixture(fixture);
      expect(code).toBe(EXIT.ok);
      expect(lockfileFindings(snapshot)).toEqual([
        ['DEP_LOCKFILE_MISSING', 'low', 'package.json', 'none', 'package.json'],
      ]);
      expect(snapshot.raw.projects[0]?.dependencies).toEqual({
        lockfiles: [],
        lockfilesNotRead: 0,
        packages: [],
      });
      // No lockfile, no line about lockfiles.
      expect(c.err()).not.toContain('npm lockfile');

      const again = await tmp();
      const d = capture();
      const args = [
        'report',
        '--from',
        join(out, SNAPSHOT_FILE),
        '--out',
        again,
        '--format',
        'json',
      ];
      expect(await main(args, d.io)).toBe(EXIT.ok);
      const offline = JSON.parse(
        await readFile(join(again, 'baip-lens-report.json'), 'utf8'),
      ) as Snapshot;
      expect(offline.findings).toEqual(snapshot.findings);
      expectCleanOutputs(await readOutputs(out), terminalText(c, out), fixture);
    } finally {
      await fixture.cleanup();
    }
  });

  it('(15) says that a yarn lockfile pins the versions but is not read, without opening it', async () => {
    const fixture = await materializeFixture('clean-cap');
    try {
      await rm(join(fixture.root, 'package-lock.json'));
      await writeFile(join(fixture.root, 'yarn.lock'), '# POISON_lock_token\n');
      const { snapshot } = await scanFixture(fixture);
      expect(lockfileFindings(snapshot)).toEqual([
        ['DEP_LOCKFILE_MISSING', 'info', 'yarn.lock', 'unsupported', 'yarn.lock'],
      ]);
      const project = snapshot.raw.projects[0]!;
      expect(project.dependencies?.lockfiles.map((l) => [l.file, l.kind, l.status])).toEqual([
        ['yarn.lock', 'yarn', 'unsupported'],
      ]);
      // Listed by name only: not among the files opened.
      expect(project.files).not.toContain('yarn.lock');
      expect(project.filesOpened).toBe(project.files.length + project.unreadable.length);
    } finally {
      await fixture.cleanup();
    }
  });

  it('(16) reports a lockfile that is not valid as unreadable, never as a clean project', async () => {
    const fixture = await materializeFixture('clean-cap');
    try {
      await writeFile(join(fixture.root, 'package-lock.json'), '<<<<<<< POISON_lock_token\n{');
      const { c, out, snapshot } = await scanFixture(fixture);
      expect(lockfileFindings(snapshot)).toEqual([
        ['DEP_LOCKFILE_MISSING', 'low', 'package-lock.json', 'unreadable', 'package-lock.json'],
        ['DEP_NOT_CHECKED', 'info', 'dependencies', undefined, undefined],
      ]);
      const project = snapshot.raw.projects[0]!;
      expect(project.unreadable).toEqual([{ file: 'package-lock.json', kind: 'json' }]);
      expect(project.filesOpened).toBe(project.files.length + project.unreadable.length);
      expect(c.err()).toContain(
        'Read 0 npm lockfile(s): 0 package(s) from the public npm registry, 0 other package(s) not checked\n',
      );
      expectCleanOutputs(await readOutputs(out), terminalText(c, out), fixture);
    } finally {
      await fixture.cleanup();
    }
  });
});

describe('baip-lens project and the lockfile npm writes into node_modules', () => {
  /*
   * `node_modules/.package-lock.json` is read for a deployed app only
   * (`project --cf`). For a folder the committed lockfile is what the scan
   * judges, and nothing under `node_modules` is touched: a `node_modules`
   * that is a link would lead a read out of the project root.
   */
  const INSTALLED_ONLY = 'baip-fixture-installed-only';

  async function installHiddenLockfile(root: string): Promise<void> {
    await mkdir(join(root, 'node_modules'), { recursive: true });
    await writeFile(
      join(root, 'node_modules', '.package-lock.json'),
      hiddenLockfile('clean-cap', {
        [`node_modules/${INSTALLED_ONLY}`]: registryEntry(INSTALLED_ONLY, '9.9.9'),
      }),
    );
  }

  const underNodeModules = (project: RawProject): string[] =>
    [...project.files, ...project.unreadable.map((entry) => entry.file)].filter((file) =>
      file.includes('node_modules'),
    );

  it('(18) is not read for --path: the committed lockfile is read as before, dev entries included', async () => {
    const fixture = await materializeFixture('clean-cap');
    try {
      await installHiddenLockfile(fixture.root);
      const { code, out, c, snapshot } = await scanFixture(fixture);
      expect(code).toBe(EXIT.ok);
      const project = snapshot.raw.projects[0]!;
      expect(project.dependencies?.lockfiles.map((l) => [l.file, l.kind, l.status])).toEqual([
        ['package-lock.json', 'package-lock', 'read'],
      ]);
      // Every package of the committed lockfile, the dev one too; none of the installed tree.
      expect(project.dependencies?.packages).toEqual(
        CLEAN_PUBLIC_PACKAGES.map((item) => ({ ...item, lockfiles: ['package-lock.json'] })),
      );
      expect(project.dependencies?.packages.some((item) => item.scope === 'dev')).toBe(true);
      expect(underNodeModules(project)).toEqual([]);
      expect(project.filesOpened).toBe(project.files.length + project.unreadable.length);
      expect(snapshot.findings).toEqual([]);
      const outputs = await readOutputs(out);
      for (const [name, content] of Object.entries(outputs)) {
        expect(content, name).not.toContain(INSTALLED_ONLY);
      }
      expect(terminalText(c, out)).not.toContain(INSTALLED_ONLY);
    } finally {
      await fixture.cleanup();
    }
  });

  it('(19) does not stand in for a missing lockfile of a folder', async () => {
    const fixture = await materializeFixture('clean-cap');
    try {
      await rm(join(fixture.root, 'package-lock.json'));
      await installHiddenLockfile(fixture.root);
      const { code, c, snapshot } = await scanFixture(fixture);
      expect(code).toBe(EXIT.ok);
      const project = snapshot.raw.projects[0]!;
      expect(project.dependencies).toEqual({ lockfiles: [], lockfilesNotRead: 0, packages: [] });
      expect(underNodeModules(project)).toEqual([]);
      expect(project.filesOpened).toBe(project.files.length + project.unreadable.length);
      expect(
        snapshot.findings
          .filter((f) => f.id.startsWith('DEP_'))
          .map((f) => [f.id, f.evidence.cause, f.location?.file]),
      ).toEqual([['DEP_LOCKFILE_MISSING', 'none', 'package.json']]);
      expect(c.err()).not.toContain('npm lockfile');
      expect(JSON.stringify(snapshot)).not.toContain(INSTALLED_ONLY);
    } finally {
      await fixture.cleanup();
    }
  });
});

describe('baip-lens project and a private package the root package.json lists', () => {
  /*
   * The lockfile step keeps nothing of a package that is not from the public
   * npm registry. The names the root package.json lists under `dependencies`
   * and `devDependencies` are kept by the project collector, as they were
   * before lockfiles were read: the one place where the name of a private
   * direct dependency is stored (docs/privacy.md).
   */
  const PRIVATE = ['acme-private-ledger', '@acme-private/billing', 'acme-private-devtool'];
  const MARK = 'acme-private';

  it('(17) keeps its name in the snapshot manifest only: not among the packages, in no report, not in the terminal', async () => {
    const fixture = await materializeFixture('clean-cap');
    try {
      const manifest = JSON.parse(
        await readFile(join(fixture.root, 'package.json'), 'utf8'),
      ) as Record<string, Record<string, string>>;
      manifest.dependencies = {
        ...manifest.dependencies,
        'acme-private-ledger': '^1.0.0',
        '@acme-private/billing': '^2.0.0',
      };
      manifest.devDependencies = {
        ...manifest.devDependencies,
        'acme-private-devtool': '^3.0.0',
      };
      // Used for `direct` only, and not stored.
      manifest.optionalDependencies = { 'acme-private-optional': '^1.0.0' };
      manifest.peerDependencies = { 'acme-private-peer': '^1.0.0' };
      await writeFile(join(fixture.root, 'package.json'), JSON.stringify(manifest, null, 2));
      const from = (resolved: string) => ({ version: '1.0.0', resolved });
      await writeFile(
        join(fixture.root, 'package-lock.json'),
        lockfileV3(
          {
            name: 'clean-cap',
            dependencies: {
              'acme-private-ledger': '^1.0.0',
              '@acme-private/billing': '^2.0.0',
              'baip-fixture-server': '^2.5.0',
            },
            devDependencies: { 'acme-private-devtool': '^3.0.0' },
            optionalDependencies: { 'acme-private-optional': '^1.0.0' },
            peerDependencies: { 'acme-private-peer': '^1.0.0' },
          },
          {
            // A company registry, and the public one with credentials in the address.
            'node_modules/acme-private-ledger': from(
              'https://npm.acme-private.example/acme-private-ledger/-/acme-private-ledger-1.0.0.tgz',
            ),
            'node_modules/@acme-private/billing': from(
              'https://ci:acme-private-token@registry.npmjs.org/@acme-private/billing/-/billing-1.0.0.tgz',
            ),
            'node_modules/acme-private-devtool': {
              version: '3.0.0',
              resolved: 'git+ssh://git@github.com/acme/acme-private-devtool.git#0123abc',
              dev: true,
            },
            'node_modules/acme-private-optional': { version: '1.0.0', optional: true },
            'node_modules/acme-private-peer': {
              version: '1.0.0',
              resolved: 'file:vendor/acme-private-peer-1.0.0.tgz',
              peer: true,
            },
            'node_modules/baip-fixture-server': registryEntry('baip-fixture-server', '2.5.0'),
          },
        ),
      );

      const { code, out, c, snapshot } = await scanFixture(fixture);
      expect(code).toBe(EXIT.ok);
      const project = snapshot.raw.projects[0]!;

      // The lockfile step: counted by reason, never named.
      expect(project.dependencies?.packages.map((p) => p.name)).toEqual(['baip-fixture-server']);
      expect(project.dependencies?.lockfiles).toMatchObject([
        {
          file: 'package-lock.json',
          status: 'read',
          kept: 1,
          notKept: { otherRegistry: 2, git: 1, file: 1, unknown: 1 },
        },
      ]);
      expect(JSON.stringify(project.dependencies)).not.toContain(MARK);
      expect(JSON.stringify(snapshot.findings)).not.toContain(MARK);
      expect(JSON.stringify(snapshot.checks)).not.toContain(MARK);

      // The exception: the root manifest's own two lists, as before lockfiles were read.
      const listed = [
        ...project.packageJson.dependencies,
        ...project.packageJson.devDependencies,
      ].map((dependency) => dependency.name);
      expect(listed.filter((name) => name.includes(MARK)).sort()).toEqual([...PRIVATE].sort());
      // And nowhere else in the snapshot: each name once, the other two sections not at all.
      const texts = await readOutputs(out);
      const snapshotText = texts[SNAPSHOT_FILE]!;
      expect(snapshotText.split(MARK)).toHaveLength(PRIVATE.length + 1);
      for (const name of PRIVATE) expect(snapshotText).toContain(`"name": "${name}"`);

      // No report and no line of the terminal names one.
      for (const file of REPORT_FILES) {
        expect(texts[file], file).toBeDefined();
        expect(texts[file], file).not.toContain(MARK);
      }
      expect(terminalText(c, out)).not.toContain(MARK);
      expect(c.err()).toContain(
        'Read 1 npm lockfile(s): 1 package(s) from the public npm registry, 5 other package(s) not checked\n',
      );
      expectCleanOutputs(texts, terminalText(c, out), fixture);
    } finally {
      await fixture.cleanup();
    }
  });
});

describe('baip-lens project root errors', () => {
  it('(13) exits 2 and echoes the --path the user gave, never its real path', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'baip-lens-project-roots-'));
    // The directory link targets a second temp directory with its own unique name, so
    // that its real path is not a prefix of the --path the error legitimately echoes.
    const real = await mkdtemp(join(tmpdir(), 'baip-lens-project-real-'));
    await writeFile(join(dir, 'real-file.txt'), 'x');
    await symlink(join(dir, 'real-file.txt'), join(dir, 'file-link'));
    await symlink(real, join(dir, 'dir-link'));
    const cases: [string, string][] = [
      [join(dir, 'file-link'), 'is not a folder'],
      [join(dir, 'missing'), 'does not exist'],
      [join(dir, 'dir-link'), 'does not look like a CAP or MTA project'],
    ];
    for (const [path, reason] of cases) {
      const c = capture();
      const code = await main(['project', '--path', path, '--out', await tmp()], c.io);
      expect(code, path).toBe(EXIT.error);
      expect(c.err()).toContain(`Project path "${path}" ${reason}`);
      expect(c.err()).not.toContain('real-file');
      expect(c.err()).not.toContain(basename(real));
      expect(c.out()).toBe('');
    }
  });
});
