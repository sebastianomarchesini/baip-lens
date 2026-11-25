import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, symlink, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type * as HtmlReporter from '../../src/reporters/html.js';
import { ScriptedPrompter } from '../../src/guided/prompt.js';
import { type CliIo, EXIT, main } from '../../src/main.js';
import { MAX_FILE_BYTES } from '../../src/collectors/project/read.js';
import { MAX_READ_BYTES } from '../../src/remote/sftpTree.js';
import { FakeFetch, jsonResponse } from '../support/fakeFetch.js';
import {
  type FakeSshServer,
  READ_REQUESTS,
  newHostKey,
  sha256Fingerprint,
  startFakeSsh,
} from '../support/fakeSshServer.js';
import { ABSOLUTE_PATH, expectNoLeaks } from '../support/leak.js';
import { hiddenLockfile, lockfileV3, registryEntry } from '../support/lockfileFixture.js';

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
 * `baip-lens project --cf` end to end: the CF API and UAA are scripted
 * (FakeFetch), the app SSH proxy is a real SSH server on 127.0.0.1 that
 * serves a fixture folder per app as /home/vcap/app and records every login,
 * channel and SFTP request. Nothing here reaches a real landscape.
 */

const API = 'https://api.cf.example.org';
const API_HOST = 'api.cf.example.org';
const UAA_HOST = 'uaa.cf.example.org';
const ORG_GUID = '0a1b2c3d-0000-4000-8000-000000000001';
const SPACE_GUID = '5ace0000-0000-4000-8000-0000000000de';
const USER_GUID = 'feedbeef-0000-4000-8000-000000000001';
const SRV = { guid: 'a0000000-0000-4000-8000-000000000001', name: 'incidents-srv' };
const DB = { guid: 'a0000000-0000-4000-8000-000000000002', name: 'incidents-db' };
const UI = { guid: 'a0000000-0000-4000-8000-000000000003', name: 'legacy-ui' };
const PROCESS_GUID = 'b0000000-0000-4000-8000-000000000001';
const ONE_TIME_CODE = 'otc-POISON-4242';
/** The codes UAA hands out in a space of several apps, one per SSH session, in this order. */
const CODES = Array.from({ length: 8 }, (_, i) => `otc-POISON-code-${i + 1}`);
const NOW = new Date('2026-09-29T00:00:00.000Z');

/** Values that must never reach the terminal, a report or the snapshot. */
const POISON = [
  ONE_TIME_CODE,
  ...CODES,
  'POISON_default_env_secret',
  'POISON_dotenv',
  'LeakedThroughLink',
  'POISON_node_modules',
  // Planted in labels and annotations of the apps (see `deployed` and `SPOOFED`).
  'owner.POISON@example.com',
  'POISON_bound_service',
  'POISON_spoofed_mta',
  'POISON_spoofed_module',
  'POISON_stats_body',
  // Planted in the lockfiles of the containers and in `.npmrc` (see `installedLockfile`).
  '@poison-scope/private',
  'poison-internal.example.com',
  'POISON_lock_token',
  'POISON_lock_integrity',
  'POISON_lock_license',
  'poison-lock-git',
  'POISON_lock_repo',
  'poison-lock-link',
  'poison-lock-folder',
  'poison-pushed',
  'poison-dev-private',
  'POISON_npmrc',
];

/** The lockfile npm writes into the tree it installed: the one path under `node_modules` ever asked for. */
const HIDDEN = '/home/vcap/app/node_modules/.package-lock.json';
const PRIVATE_REGISTRY = 'https://ci:POISON_lock_token@poison-internal.example.com/npm';

/** A package from a company registry, with a token in its address: counted, never named. */
const privateEntry = (name: string, extra: Record<string, unknown> = {}) => ({
  version: '1.0.0',
  resolved: `${PRIVATE_REGISTRY}/${name}/-/${name.slice(name.lastIndexOf('/') + 1)}-1.0.0.tgz`,
  integrity: 'sha512-POISON_lock_integrity',
  ...extra,
});

/**
 * `node_modules/.package-lock.json` of the container fixture, as a production
 * install leaves it: no dev package, no root entry, and next to the public
 * packages one from another registry, one from git and a linked folder.
 */
function installedLockfile(): string {
  return hiddenLockfile('acme-incidents', {
    '../poison-lock-folder': { version: '0.1.0' },
    'node_modules/@baip-fixture/odata': registryEntry('@baip-fixture/odata', '3.1.0'),
    'node_modules/@poison-scope/private': privateEntry('@poison-scope/private'),
    'node_modules/baip-fixture-merge': registryEntry('baip-fixture-merge', '4.17.20'),
    'node_modules/baip-fixture-server': registryEntry('baip-fixture-server', '2.4.1'),
    'node_modules/baip-fixture-watcher': registryEntry('baip-fixture-watcher', '2.3.3', {
      optional: true,
    }),
    'node_modules/poison-lock-git': {
      version: '1.4.0',
      resolved: 'git+ssh://git@github.com/acme/POISON_lock_repo.git#semver:^1.4.0',
    },
    'node_modules/poison-lock-link': { resolved: '../poison-lock-folder', link: true },
  });
}

/** The packages of `installedLockfile` from the public npm registry, as the project record keeps them. */
const INSTALLED_PACKAGES = [
  { name: '@baip-fixture/odata', version: '3.1.0', direct: true, scope: 'prod' },
  { name: 'baip-fixture-merge', version: '4.17.20', direct: false, scope: 'prod' },
  { name: 'baip-fixture-server', version: '2.4.1', direct: true, scope: 'prod' },
  { name: 'baip-fixture-watcher', version: '2.3.3', direct: true, scope: 'optional' },
].map((item) => ({ ...item, lockfiles: ['node_modules/.package-lock.json'] }));

/**
 * The `package-lock.json` that was pushed with an app: what was asked for,
 * with other versions than the installed ones, the dev packages, and a
 * private package for production and one for development.
 */
function pushedLockfile(): string {
  return lockfileV3(
    {
      name: 'acme-incidents',
      dependencies: { '@baip-fixture/odata': '^3.0.0', 'baip-fixture-server': '^2.0.0' },
      devDependencies: { 'baip-fixture-test-kit': '^7.0.0' },
    },
    {
      'node_modules/@baip-fixture/odata': registryEntry('@baip-fixture/odata', '3.0.0'),
      'node_modules/baip-fixture-server': registryEntry('baip-fixture-server', '2.0.0'),
      'node_modules/baip-fixture-shared': registryEntry('baip-fixture-shared', '1.2.0', {
        devOptional: true,
      }),
      'node_modules/baip-fixture-test-kit': registryEntry('baip-fixture-test-kit', '7.0.0', {
        dev: true,
      }),
      'node_modules/baip-fixture-mkdir': registryEntry('baip-fixture-mkdir', '0.5.1', {
        dev: true,
      }),
      'node_modules/poison-pushed': privateEntry('poison-pushed'),
      'node_modules/poison-dev-private': privateEntry('poison-dev-private', { dev: true }),
    },
  );
}

const NO_OTHER_PACKAGES = {
  otherRegistry: 0,
  git: 0,
  file: 0,
  link: 0,
  bundled: 0,
  unknown: 0,
  excluded: 0,
  invalid: 0,
};

function base64url(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

/** A JWT-shaped access token with a user id, valid for an hour. */
function accessToken(userId = USER_GUID): string {
  const payload = {
    user_id: userId,
    scope: ['cloud_controller.read', 'cloud_controller.write', 'openid'],
    exp: Math.floor(Date.now() / 1000) + 3600,
  };
  return `${base64url({ alg: 'RS256', typ: 'JWT' })}.${base64url(payload)}.c2lnbmF0dXJlLXBvaXNvbg`;
}

const page = (resources: unknown[]) => ({
  pagination: { total_results: resources.length, total_pages: 1, next: null, previous: null },
  resources,
});

/** One app of the scripted space: what the CF API answers about it. */
interface AppSpec {
  guid: string;
  name: string;
  /** Default: STARTED. */
  state?: string;
  /** Default: buildpack. */
  lifecycle?: 'buildpack' | 'docker';
  metadata?: unknown;
  /** What `/ssh_enabled` answers. Absent: not scripted, so a request for it fails the run. */
  ssh?: { enabled: boolean; reason: string };
  /**
   * The web process and the state of each instance; 'none' for an app without
   * one; a `broken` process answers its stats with something else. Absent: not scripted.
   */
  web?: { process: string; instances: string[]; broken?: boolean } | 'none';
}

function appResource(app: AppSpec) {
  return {
    guid: app.guid,
    name: app.name,
    state: app.state ?? 'STARTED',
    lifecycle:
      app.lifecycle === 'docker'
        ? { type: 'docker', data: {} }
        : { type: 'buildpack', data: { buildpacks: ['nodejs_buildpack'], stack: 'cflinuxfs4' } },
    ...(app.metadata === undefined ? {} : { metadata: app.metadata }),
  };
}

const SSH_ON = { enabled: true, reason: '' };
/** The space the cf CLI config targets, unless a test names another one. */
const DEFAULT_SPACE = 'dev';

/** The space of the first tests: one app that can be read, two that cannot, none deployed as an MTA. */
const PLAIN_APPS: AppSpec[] = [
  { ...DB, state: 'STOPPED' },
  { ...SRV, ssh: SSH_ON, web: { process: PROCESS_GUID, instances: ['CRASHED', 'RUNNING'] } },
  { ...UI, ssh: { enabled: false, reason: 'ssh is disabled for app' } },
];

interface Landscape {
  fingerprint: string;
  sshHref: string;
  /** Roles the user holds in the space (empty: no Space Developer). */
  roles?: string[];
  /** The apps of the space, in the order the API lists them (default: `PLAIN_APPS`). */
  apps?: AppSpec[];
  /** The one-time codes UAA hands out, one per request; the last one again after that. */
  codes?: string[];
  /** UAA cannot be reached from this request for a one-time code on (1 is the first). */
  uaaDownFrom?: number;
  /** The name of the targeted space (default: `dev`). */
  spaceName?: string;
}

/** What Node's fetch throws when the connection is reset. */
function connectionReset(): TypeError {
  return new TypeError('fetch failed', {
    cause: Object.assign(new Error('connect ECONNRESET'), { code: 'ECONNRESET' }),
  });
}

function landscape(options: Landscape): FakeFetch {
  const roles = options.roles ?? ['space_developer'];
  const apps = options.apps ?? PLAIN_APPS;
  const codes = options.codes ?? [ONE_TIME_CODE];
  const spaceName = options.spaceName ?? DEFAULT_SPACE;
  let handedOut = 0;
  const authorizeQuery = 'client_id=ssh-proxy&response_type=code';
  const fake = new FakeFetch()
    .on('GET', `${API_HOST}/`, () =>
      jsonResponse({
        links: {
          self: { href: API },
          cloud_controller_v3: { href: `${API}/v3` },
          uaa: { href: `https://${UAA_HOST}` },
          login: { href: 'https://login.cf.example.org' },
          app_ssh: {
            href: options.sshHref,
            meta: { host_key_fingerprint: options.fingerprint, oauth_client: 'ssh-proxy' },
          },
        },
      }),
    )
    .on('GET', `${API_HOST}/v3/organizations?names=acme-prod&per_page=5000`, () =>
      jsonResponse(page([{ guid: ORG_GUID, name: 'acme-prod' }])),
    )
    .on(
      'GET',
      `${API_HOST}/v3/spaces?names=${spaceName}&organization_guids=${ORG_GUID}&per_page=5000`,
      () =>
        jsonResponse(
          page([
            {
              guid: SPACE_GUID,
              name: spaceName,
              relationships: { organization: { data: { guid: ORG_GUID } } },
            },
          ]),
        ),
    )
    .on(
      'GET',
      `${API_HOST}/v3/roles?per_page=5000&space_guids=${SPACE_GUID}&types=space_developer&user_guids=${USER_GUID}`,
      () => jsonResponse(page(roles.map((type) => ({ guid: `role-${type}`, type })))),
    )
    .on('GET', `${API_HOST}/v3/apps?order_by=name&per_page=5000&space_guids=${SPACE_GUID}`, () =>
      jsonResponse(page(apps.map(appResource))),
    )
    .on('GET', `${UAA_HOST}/oauth/authorize?${authorizeQuery}`, () => {
      const code = codes[Math.min(handedOut, codes.length - 1)] ?? '';
      handedOut += 1;
      if (options.uaaDownFrom !== undefined && handedOut >= options.uaaDownFrom) {
        throw connectionReset();
      }
      return new Response(null, {
        status: 302,
        headers: { location: `https://${UAA_HOST}/login?code=${code}` },
      });
    });
  for (const app of apps) {
    const { ssh, web } = app;
    if (ssh !== undefined) {
      fake.on('GET', `${API_HOST}/v3/apps/${app.guid}/ssh_enabled`, () => jsonResponse(ssh));
    }
    if (web === 'none') {
      fake.on('GET', `${API_HOST}/v3/apps/${app.guid}/processes/web`, () =>
        jsonResponse({ errors: [{ code: 10010, title: 'CF-ResourceNotFound' }] }, 404),
      );
    } else if (web !== undefined) {
      fake
        .on('GET', `${API_HOST}/v3/apps/${app.guid}/processes/web`, () =>
          jsonResponse({ guid: web.process, type: 'web', instances: web.instances.length }),
        )
        .on('GET', `${API_HOST}/v3/processes/${web.process}/stats`, () =>
          jsonResponse(
            web.broken
              ? { detail: 'POISON_stats_body' }
              : {
                  resources: web.instances.map((state, index) => ({
                    type: 'web',
                    index,
                    state,
                    ...(state === 'RUNNING' ? { host: '10.0.0.7' } : {}),
                  })),
                },
          ),
        );
    }
  }
  return fake;
}

/** What `cf push` leaves in /home/vcap/app, plus files the scan must never touch. */
async function containerFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'baip-lens-container-'));
  const app = join(root, 'app');
  const write = async (rel: string, content: string) => {
    const abs = join(app, ...rel.split('/'));
    await mkdir(join(abs, '..'), { recursive: true });
    await writeFile(abs, content);
  };
  await write(
    'package.json',
    JSON.stringify({
      name: 'acme-incidents',
      dependencies: {
        '@sap/cds': '^9',
        '@sap/xssec': '^4',
        '@baip-fixture/odata': '^3.0.0',
        'baip-fixture-server': '^2.0.0',
      },
      devDependencies: { 'baip-fixture-test-kit': '^7.0.0' },
      optionalDependencies: { 'baip-fixture-watcher': '^2.3.0' },
      cds: { requires: { auth: 'mocked' } },
    }),
  );
  await write(
    'xs-app.json',
    JSON.stringify({
      authenticationMethod: 'route',
      routes: [{ source: '^/api/(.*)$', destination: 'srv-api', authenticationType: 'none' }],
    }),
  );
  await write(
    'srv/cat-service.cds',
    'service CatalogService { entity Books { key ID : Integer; } }',
  );
  await write(
    'default-env.json',
    JSON.stringify({
      VCAP_SERVICES: { xsuaa: [{ credentials: { clientsecret: 'POISON_default_env_secret' } }] },
    }),
  );
  await write('.env', 'SECRET=POISON_dotenv\n');
  await write('node_modules/@sap/cds/package.json', '{"name":"POISON_node_modules"}');
  // What npm installed, what was pushed, and the file that can hold a registry token.
  await write('node_modules/.package-lock.json', installedLockfile());
  await write('package-lock.json', pushedLockfile());
  await write('.npmrc', '//registry.npmjs.org/:_authToken=POISON_npmrc\n');
  await writeFile(join(root, 'outside.cds'), 'service LeakedThroughLink {}');
  await symlink(join(root, 'outside.cds'), join(app, 'srv', 'link.cds'));
  await write('db/data/acme-Big.csv', 'ID;name\n');
  await truncate(join(app, 'db', 'data', 'acme-Big.csv'), MAX_FILE_BYTES + 1);
  return app;
}

/** A folder served as /home/vcap/app, with the given files. */
async function appFolder(files: Record<string, string>): Promise<string> {
  const app = join(await mkdtemp(join(tmpdir(), 'baip-lens-container-')), 'app');
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(app, ...rel.split('/'));
    await mkdir(join(abs, '..'), { recursive: true });
    await writeFile(abs, content);
  }
  return app;
}

/** A deployed approuter: its package.json and an xs-app.json with CSRF protection off. */
const approuterFixture = (): Promise<string> =>
  appFolder({
    'package.json': JSON.stringify({
      name: 'acme-approuter',
      dependencies: { '@sap/approuter': '^20' },
    }),
    'xs-app.json': JSON.stringify({
      authenticationMethod: 'route',
      routes: [
        {
          source: '^/odata/(.*)$',
          destination: 'srv-api',
          authenticationType: 'xsuaa',
          csrfProtection: false,
        },
      ],
    }),
  });

/** An app the project rules have nothing to read in: none of the marker files. */
const javaFixture = (): Promise<string> => appFolder({ 'META-INF/MANIFEST.MF': 'Main-Class: x\n' });

async function cfHome(token: string, target = API, space = DEFAULT_SPACE): Promise<string> {
  const home = await mkdtemp(join(tmpdir(), 'baip-lens-cfhome-'));
  await mkdir(join(home, '.cf'));
  await writeFile(
    join(home, '.cf', 'config.json'),
    JSON.stringify({
      ConfigVersion: 3,
      Target: target,
      AccessToken: `bearer ${token}`,
      RefreshToken: '',
      OrganizationFields: { GUID: ORG_GUID, Name: 'acme-prod' },
      SpaceFields: { GUID: SPACE_GUID, Name: space, AllowSSH: true },
    }),
  );
  return home;
}

interface Run {
  code: number;
  out: string;
  err: string;
  transcript: string[];
  outDir: string;
  fake: FakeFetch;
  server: FakeSshServer;
  token: string;
}

const servers: FakeSshServer[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

/** A space of several apps, each with its own folder behind the SSH proxy. */
interface Space {
  apps: AppSpec[];
  /** The folder served to each SSH user (`cf:<process guid>/<index>`). */
  folders: Record<string, string>;
  /** The one-time codes the SSH server accepts, each once (default: every code UAA hands out). */
  accept?: string[];
  /** SSH users whose session is cut at its first file read. */
  dropOnOpen?: string[];
  /** SSH users whose session is cut while the ranges of a large file are in flight. */
  dropOnRead?: string[];
  /** SSH users whose session is cut at the look for the hidden lockfile. */
  dropOnLstat?: string[];
  /** The name of the space (default: `dev`). */
  name?: string;
}

interface RunOptions {
  args?: string[];
  answers?: string[] | null;
  roles?: string[];
  /** The password the SSH server accepts (default: the one-time code UAA hands out). */
  acceptPassword?: string;
  /** Publish the fingerprint of another key in the CF root. */
  wrongHostKey?: boolean;
  /** Instead of the three apps of `PLAIN_APPS` and their one folder. */
  space?: Space;
  /** See `Landscape.uaaDownFrom`. */
  uaaDownFrom?: number;
  /** Environment variables next to CF_HOME. */
  env?: Record<string, string>;
}

async function startServer(options: RunOptions): Promise<FakeSshServer> {
  const { space } = options;
  if (space !== undefined) {
    return startFakeSsh({
      users: space.folders,
      codes: space.accept ?? CODES,
      dropOnOpen: space.dropOnOpen,
      dropOnRead: space.dropOnRead,
      dropOnLstat: space.dropOnLstat,
    });
  }
  return startFakeSsh({
    appDir: await containerFixture(),
    username: `cf:${PROCESS_GUID}/1`,
    password: options.acceptPassword ?? ONE_TIME_CODE,
  });
}

async function run(options: RunOptions = {}): Promise<Run> {
  const server = await startServer(options);
  servers.push(server);
  const fingerprint = options.wrongHostKey
    ? sha256Fingerprint(newHostKey().public)
    : server.fingerprint;
  const fake = landscape({
    fingerprint,
    sshHref: server.href,
    roles: options.roles,
    uaaDownFrom: options.uaaDownFrom,
    spaceName: options.space?.name,
    ...(options.space === undefined ? {} : { apps: options.space.apps, codes: CODES }),
  });
  const token = accessToken();
  const outDir = await mkdtemp(join(tmpdir(), 'baip-lens-cf-out-'));
  const prompter =
    options.answers === null ? undefined : new ScriptedPrompter(options.answers ?? ['1']);
  let out = '';
  let err = '';
  const io: CliIo = {
    stdout: (t) => (out += t),
    stderr: (t) => (err += t),
    env: { ...options.env, CF_HOME: await cfHome(token, API, options.space?.name) },
    isTTY: false,
    prompter,
    fetch: fake.fetch,
    now: () => NOW,
  };
  const args = [
    'project',
    '--cf',
    '--out',
    outDir,
    '--format',
    'json,csv,sarif',
    ...(options.args ?? []),
  ];
  const code = await main(args, io);
  return { code, out, err, transcript: prompter?.transcript ?? [], outDir, fake, server, token };
}

async function written(dir: string): Promise<Record<string, string>> {
  const files: Record<string, string> = {};
  for (const name of await readdir(dir)) files[name] = await readFile(join(dir, name), 'utf8');
  return files;
}

/** The SFTP requests that named a path under `node_modules`, as `TYPE path`. */
const underNodeModules = (r: Run): string[] =>
  r.server.requests
    .filter((q) => (q.path ?? '').includes('node_modules'))
    .map((q) => `${q.type} ${q.path ?? ''}`);

/**
 * What must hold for every session of every run: only read requests, files
 * opened read-only, no read request larger than one SFTP packet carries,
 * `.npmrc` never asked for, and under `node_modules` nothing but the lockfile
 * of the installed tree, by its full path.
 */
function expectOnlyReads(r: Run): void {
  expect(r.server.requests.length).toBeGreaterThan(5);
  for (const request of r.server.requests) {
    expect(READ_REQUESTS.has(request.type), request.type).toBe(true);
    if (request.type === 'OPEN') expect(request.flags).toBe('r');
    if (request.type === 'READ') expect(request.length).toBeLessThanOrEqual(MAX_READ_BYTES);
    const path = request.path ?? '';
    expect(path, `${request.type} ${path}`).not.toContain('.npmrc');
    if (path.includes('node_modules')) expect(path, request.type).toBe(HIDDEN);
  }
  // `node_modules` itself is never listed, looked at or opened.
  expect(r.server.requests.some((q) => q.type === 'OPENDIR' && q.path !== undefined)).toBe(true);
  expect(
    r.server.requests.some((q) => q.type === 'OPENDIR' && (q.path ?? '').includes('node_modules')),
  ).toBe(false);
}

describe('baip-lens project --cf', () => {
  it('lists the apps of the cf target space, reads the chosen one over read-only SFTP and reports it', async () => {
    const r = await run();
    expect(r.code, r.err).toBe(EXIT.ok);

    // The Space Developer warning and the audit event come first.
    expect(r.err).toContain('It needs the Space Developer role in the space');
    expect(r.err).toContain('audit.app.ssh-authorized');
    expect(r.err).toContain('Reading app "incidents-srv" (instance 1) over SSH, read-only');

    // The picker offers only what can be read, and says why the others cannot.
    expect(r.transcript).toContain('Apps in space "dev" of "acme-prod":');
    expect(r.transcript).toContain(
      '  - incidents-db: it is stopped: start it with `cf start incidents-db`',
    );
    expect(r.transcript).toContain(
      '  - legacy-ui: SSH is off for this app: turn it on with `cf enable-ssh legacy-ui`, then `cf restart legacy-ui`',
    );
    expect(r.transcript).toContain('  1) incidents-srv');
    expect(r.transcript.filter((line) => /^\s+\d\) /.test(line))).toHaveLength(1);

    // One SSH login, password only (no "none" probe), as cf:<process guid>/<running index>.
    expect(r.server.logins).toEqual([
      { method: 'password', username: `cf:${PROCESS_GUID}/1`, password: ONE_TIME_CODE },
    ]);
    // Only the SFTP subsystem: no shell, no command, no port forwarding.
    expect(r.server.channels).toEqual(['sftp']);
    // Only read requests, files opened read-only.
    expectOnlyReads(r);
    const touched = r.server.requests.map((q) => q.path ?? '');
    for (const never of ['default-env.json', '/.env', '.npmrc', '@sap', 'link.cds']) {
      expect(
        touched.some((path) => path.includes(never)),
        never,
      ).toBe(false);
    }
    // Under node_modules one path is asked for and no other: the lockfile of the installed
    // tree, looked at (LSTAT) and then read in the same way as every other file.
    expect([...new Set(underNodeModules(r))]).toEqual([
      `LSTAT ${HIDDEN}`,
      `OPEN ${HIDDEN}`,
      `FSTAT ${HIDDEN}`,
      `READ ${HIDDEN}`,
      `CLOSE ${HIDDEN}`,
    ]);
    // It says what is installed, so the lockfile that was pushed is not opened.
    expect(touched).not.toContain('/home/vcap/app/package-lock.json');
    // The oversized seed file is checked with fstat and never read.
    expect(touched).toContain('/home/vcap/app/db/data/acme-Big.csv');
    expect(
      r.server.requests.some((q) => q.type === 'READ' && q.path?.endsWith('acme-Big.csv')),
    ).toBe(false);

    const report = JSON.parse(await readFile(join(r.outDir, 'baip-lens-report.json'), 'utf8')) as {
      scope: { orgs: string[]; projects: string[]; apiEndpoint?: string };
      checks: { id: string; title: string; status: string; roles: string[] }[];
      findings: { id: string }[];
    };
    expect(report.scope).toEqual({ apiEndpoint: `${API}/`, orgs: [], projects: ['incidents-srv'] });
    expect(report.checks.find((c) => c.id === 'collect.project')).toMatchObject({
      status: 'ran',
      roles: ['SpaceDeveloper'],
    });
    // The lockfiles are read in the same session, so their check needs the same role.
    expect(report.checks.find((c) => c.id === 'collect.dependencies')).toEqual({
      id: 'collect.dependencies',
      title:
        'npm lockfiles of the deployed app (node_modules/.package-lock.json, package-lock.json)',
      roles: ['SpaceDeveloper'],
      status: 'ran',
    });
    const ids = report.findings.map((f) => f.id);
    expect(ids).toContain('CAP_MOCKED_AUTH_IN_PROD');
    expect(ids).toContain('APPROUTER_ROUTE_NO_AUTH');
    expect(r.out).toMatch(/^Scanned deployed app incidents-srv: \d+ finding\(s\)/);

    // The snapshot records the oversized file as unreadable, never its content.
    const snapshotName = (await readdir(r.outDir)).find((f) => f.startsWith('snapshot-')) ?? '';
    const snapshot = JSON.parse(await readFile(join(r.outDir, snapshotName), 'utf8')) as {
      raw: {
        projects: {
          files: string[];
          filesOpened: number;
          unreadable: { file: string; kind: string }[];
          dependencies: unknown;
        }[];
      };
    };
    const project = snapshot.raw.projects[0];
    expect(project?.files).toEqual([
      'node_modules/.package-lock.json',
      'package.json',
      'srv/cat-service.cds',
      'xs-app.json',
    ]);
    expect(project?.unreadable).toEqual([{ file: 'db/data/acme-Big.csv', kind: 'too-large' }]);
    expect(project?.filesOpened).toBe(5);

    // The installed tree: its public packages by name, direct by the root package.json; the
    // private, git and linked ones as counts. No record of the lockfile that was pushed.
    expect(project?.dependencies).toEqual({
      lockfiles: [
        {
          file: 'node_modules/.package-lock.json',
          kind: 'hidden',
          lockfileVersion: 3,
          status: 'read',
          kept: 4,
          notKept: { ...NO_OTHER_PACKAGES, otherRegistry: 1, git: 1, link: 1 },
        },
      ],
      lockfilesNotRead: 0,
      packages: INSTALLED_PACKAGES,
    });
    expect(r.err).toContain(
      'Read 1 npm lockfile(s): 4 package(s) from the public npm registry, 2 other package(s) not checked\n',
    );
    // The versions are known, so nothing is missing; the packages left unchecked are said.
    const dependencyFindings = report.findings.filter((f) => f.id.startsWith('DEP_'));
    expect(dependencyFindings.map((f) => f.id)).toEqual(['DEP_NOT_CHECKED']);
    // A finding never points into node_modules.
    expect(JSON.stringify(report.findings)).not.toContain('node_modules');

    // stdout lists the report files it wrote, so only the others must be free of absolute paths.
    expectNoLeaks({ stdout: r.out }, [...POISON, r.token]);
    expectNoLeaks(
      { stderr: r.err, transcript: r.transcript.join('\n'), ...(await written(r.outDir)) },
      [...POISON, r.token],
      [ABSOLUTE_PATH],
    );
  });

  it('reads the app named with --app without a terminal', async () => {
    const r = await run({ args: ['--app', 'incidents-srv'], answers: null });
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(r.server.logins).toHaveLength(1);
    // Only the named app's SSH status is asked for.
    expect(r.fake.calls.some((c) => c.url.pathname.includes(UI.guid))).toBe(false);
  });

  it('stops before any SSH attempt when the user is not a Space Developer', async () => {
    const r = await run({ roles: [] });
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain('does not have the Space Developer role in space "dev" of "acme-prod"');
    expect(r.server.connections).toBe(0);
    expect(r.fake.calls.some((c) => c.url.pathname === '/oauth/authorize')).toBe(false);
    expect(await readdir(r.outDir)).toEqual([]);
  });

  it('explains a refused SSH login as the missing role', async () => {
    const r = await run({ acceptPassword: 'some-other-code' });
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain('The SSH login to "incidents-srv" was refused');
    expect(r.err).toContain('Space Developer role in space "dev"');
    // The one-time code is tried once, then dropped.
    expect(r.server.logins).toHaveLength(1);
    expect(r.err).not.toContain(ONE_TIME_CODE);
    expect(await readdir(r.outDir)).toEqual([]);
  });

  it('never sends the one-time code to a server whose host key does not match', async () => {
    const r = await run({ wrongHostKey: true });
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain('did not present the host key the CF API published');
    expect(r.server.logins).toEqual([]);
    expect(r.server.channels).toEqual([]);
  });

  it('names the cf command when --app points at an app with SSH turned off', async () => {
    const r = await run({ args: ['--app', 'legacy-ui'], answers: null });
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain('App "legacy-ui" cannot be read');
    expect(r.err).toContain('cf enable-ssh legacy-ui');
    expect(r.server.connections).toBe(0);
  });

  it('lists the apps of the space when --app names none of them', async () => {
    const r = await run({ args: ['--app', 'nope'], answers: null });
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain(
      'There is no app named "nope" in space "dev" of "acme-prod". Apps there: incidents-db, incidents-srv, legacy-ui.',
    );
  });

  it('asks for --app when nobody is at the terminal', async () => {
    const r = await run({ answers: null });
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain('Name the app with --app <name>');
    expect(r.server.connections).toBe(0);
  });
});

/*
 * A deployed MTA project: the deploy service marks each app with labels and
 * annotations, the picker groups the apps by them, and one choice reads every
 * app of the project, one SSH session after the other, into one report.
 */

const md5 = (text: string): string => createHash('md5').update(text, 'utf8').digest('hex');

/** What the deploy service writes on a module of an MTA, plus keys BAIP Lens must never keep. */
function deployed(
  id: string,
  module: string,
  options: { version?: string; namespace?: string } = {},
): unknown {
  const { version = '1.2.0', namespace } = options;
  return {
    labels: {
      mta_id: md5(id),
      ...(namespace === undefined ? {} : { mta_namespace: md5(namespace) }),
    },
    annotations: {
      mta_id: id,
      mta_version: version,
      mta_module: JSON.stringify({ name: module }),
      ...(namespace === undefined ? {} : { mta_namespace: namespace }),
      mta_bound_services: '["POISON_bound_service"]',
      contact: 'owner.POISON@example.com',
    },
  };
}

/** An app that claims an MTA id its label is not the MD5 of: an app on its own. */
const SPOOFED = {
  labels: { mta_id: md5('acme') },
  annotations: {
    mta_id: 'POISON_spoofed_mta',
    mta_version: '9.9.9',
    mta_module: '{"name":"POISON_spoofed_module"}',
    contact: 'owner.POISON@example.com',
  },
};

const numbered = (prefix: string, n: number): string =>
  `${prefix}1000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const processOf = (n: number): string => numbered('b', n);
/** The SSH user of app number `n`: its web process and the instance read. */
const sshUser = (n: number, index = 0): string => `cf:${processOf(n)}/${index}`;

function app(n: number, name: string, spec: Partial<AppSpec> = {}): AppSpec {
  return { guid: numbered('a', n), name, ...spec };
}

/** Started, SSH on, one running instance. */
const ready = (n: number): Partial<AppSpec> => ({
  ssh: SSH_ON,
  web: { process: processOf(n), instances: ['RUNNING'] },
});

/** The project "acme" (a stopped deployer, an approuter, a service) and two apps on their own. */
async function acmeSpace(): Promise<Space> {
  return {
    apps: [
      app(1, 'acme-db-deployer', { state: 'STOPPED', metadata: deployed('acme', 'acme-db') }),
      app(2, 'acme-router', { ...ready(2), metadata: deployed('acme', 'acme-approuter') }),
      app(3, 'acme-srv', { ...ready(3), metadata: deployed('acme', 'acme-srv') }),
      app(4, 'spoof-app', { ...ready(4), metadata: SPOOFED }),
      app(5, 'standalone', ready(5)),
    ],
    folders: {
      [sshUser(2)]: await approuterFixture(),
      [sshUser(3)]: await containerFixture(),
      [sshUser(4)]: await containerFixture(),
      [sshUser(5)]: await containerFixture(),
    },
  };
}

interface CheckJson {
  id: string;
  title: string;
  roles: string[];
  status: string;
  reasonCode?: string;
  reason?: string;
}

interface ReportJson {
  scope: { orgs: string[]; projects: string[]; apiEndpoint?: string };
  checks: CheckJson[];
  apps: { guid: string; kind: string }[];
  findings: { id: string; app: { guid: string } }[];
}

interface SnapshotJson {
  raw: { projects: { id: string; files: string[]; deployment?: unknown }[] };
}

async function reportOf(dir: string): Promise<ReportJson> {
  return JSON.parse(await readFile(join(dir, 'baip-lens-report.json'), 'utf8')) as ReportJson;
}

async function snapshotPath(dir: string): Promise<string> {
  const name = (await readdir(dir)).find((file) => file.startsWith('snapshot-')) ?? '';
  return join(dir, name);
}

async function snapshotOf(dir: string): Promise<SnapshotJson> {
  return JSON.parse(await readFile(await snapshotPath(dir), 'utf8')) as SnapshotJson;
}

const skippedChecks = (report: ReportJson): CheckJson[] =>
  report.checks.filter((check) => check.status === 'skipped');

const sshStatusAsked = (r: Run): string[] =>
  r.fake.calls
    .map((call) => call.url.pathname)
    .filter((path) => path.endsWith('/ssh_enabled'))
    .sort();

const MTA_ACME = { id: 'acme', version: '1.2.0', namespace: null };

describe('baip-lens project --cf with a deployed MTA project', () => {
  it('groups the apps by project, reads every readable app of the chosen one and reports them together', async () => {
    const r = await run({ space: await acmeSpace(), answers: ['1'] });
    expect(r.code, r.err).toBe(EXIT.ok);

    // One list: the project first, then the apps on their own; the stopped app with its reason.
    expect(r.transcript).toEqual([
      '',
      'Apps in space "dev" of "acme-prod":',
      'Not readable right now:',
      '  - acme-db-deployer: it is stopped: start it with `cf start acme-db-deployer`',
      'A project reads all its apps. To read one app only, run again with --app <name>.',
      'Which project or app do you want to analyze?',
      '  1) acme 1.2.0 · project, 2 of 3 apps: acme-router (acme-approuter), acme-srv (acme-srv)',
      '  2) spoof-app',
      '  3) standalone',
      '? Enter a number (1-3)',
    ]);

    // One session per app, announced before the first one.
    const lines = r.err.split('\n');
    const position = (line: string): number => lines.indexOf(line);
    const announced = position(
      'Reading project "acme": 2 app(s), one read-only SSH session each (each is recorded as an audit event)',
    );
    const router = position('Reading app "acme-router" (instance 0) over SSH, read-only');
    const srv = position('Reading app "acme-srv" (instance 0) over SSH, read-only');
    expect(announced).toBeGreaterThan(-1);
    expect(router).toBeGreaterThan(announced);
    expect(srv).toBeGreaterThan(router);
    expect(r.err).toMatch(/^Read \d+ project file\(s\) in project acme-router$/m);
    expect(r.err).toMatch(/^Read \d+ project file\(s\), 1 unreadable in project acme-srv$/m);
    // The terminal says what to do about the stopped app; the record keeps the fixed reason only.
    expect(lines).toContain(
      'Not reading app "acme-db-deployer": it is stopped: start it with `cf start acme-db-deployer`',
    );
    expect(lines).toContain('skipped collect.project.acme-db-deployer: it is stopped');

    // Two logins in name order, each as its own app's user with a code of its own.
    expect(r.server.logins).toEqual([
      { method: 'password', username: sshUser(2), password: CODES[0] },
      { method: 'password', username: sshUser(3), password: CODES[1] },
    ]);
    expect(r.server.connections).toBe(2);
    expect(r.server.channels).toEqual(['sftp', 'sftp']);
    expect(new Set(r.server.requests.map((q) => q.username))).toEqual(
      new Set([sshUser(2), sshUser(3)]),
    );
    for (const request of r.server.requests) {
      expect(READ_REQUESTS.has(request.type), request.type).toBe(true);
      if (request.type === 'OPEN') expect(request.flags).toBe('r');
    }
    expectOnlyReads(r);
    // The stopped app is never asked for its SSH status or its process.
    expect(r.fake.calls.some((c) => c.url.pathname.includes(numbered('a', 1)))).toBe(false);

    const report = await reportOf(r.outDir);
    expect(report.scope).toEqual({
      apiEndpoint: `${API}/`,
      orgs: [],
      projects: ['acme-router', 'acme-srv'],
    });
    expect(report.checks[0]).toMatchObject({
      id: 'collect.project',
      status: 'ran',
      roles: ['SpaceDeveloper'],
    });
    expect(skippedChecks(report)).toEqual([
      {
        id: 'collect.project.acme-db-deployer',
        title: 'Files of deployed app acme-db-deployer',
        roles: ['SpaceDeveloper'],
        status: 'skipped',
        reasonCode: 'unavailable',
        reason: 'it is stopped',
      },
    ]);
    // One inventory row per app read, each with its own findings.
    expect(report.apps.map((item) => [item.guid, item.kind]).sort()).toEqual([
      ['project:acme-router', 'project'],
      ['project:acme-srv', 'project'],
    ]);
    const found = report.findings.map((f) => `${f.id} ${f.app.guid}`);
    expect(found).toContain('APPROUTER_CSRF_DISABLED project:acme-router');
    expect(found).toContain('CAP_MOCKED_AUTH_IN_PROD project:acme-srv');
    expect(found).not.toContain('CAP_MOCKED_AUTH_IN_PROD project:acme-router');

    expect(r.out).toMatch(
      /^Scanned deployed apps acme-router, acme-srv: \d+ finding\(s\) \([^)]*\), 1 check\(s\) skipped\.\n/,
    );
    expect(r.out).toContain('  skipped collect.project.acme-db-deployer: it is stopped\n');

    // Each project record says which app it is and which module of which MTA.
    const snapshot = await snapshotOf(r.outDir);
    expect(snapshot.raw.projects.map((p) => [p.id, p.deployment])).toEqual([
      ['acme-router', { app: 'acme-router', mta: { ...MTA_ACME, module: 'acme-approuter' } }],
      ['acme-srv', { app: 'acme-srv', mta: { ...MTA_ACME, module: 'acme-srv' } }],
    ]);
    expect(snapshot.raw.projects[0]?.files).toEqual(['package.json', 'xs-app.json']);

    // Nothing of the other annotations, of the spoofed app or of the codes gets anywhere.
    expectNoLeaks({ stdout: r.out }, [...POISON, r.token]);
    expectNoLeaks(
      { stderr: r.err, transcript: r.transcript.join('\n'), ...(await written(r.outDir)) },
      [...POISON, r.token],
      [ABSOLUTE_PATH],
    );
  }, 20_000);

  it('reads one app chosen from the grouped list as before, and records that it belongs to no project', async () => {
    const r = await run({ space: await acmeSpace(), answers: ['3'] });
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(r.server.logins).toEqual([
      { method: 'password', username: sshUser(5), password: CODES[0] },
    ]);
    expect(r.err).not.toContain('Reading project');
    expect(r.out).toMatch(/^Scanned deployed app standalone: \d+ finding\(s\)/);
    const report = await reportOf(r.outDir);
    expect(report.scope.projects).toEqual(['standalone']);
    expect(skippedChecks(report)).toEqual([]);
    expect((await snapshotOf(r.outDir)).raw.projects.map((p) => p.deployment)).toEqual([
      { app: 'standalone', mta: null },
    ]);
  });

  it('lists an app whose MTA label does not match its annotation on its own, and shows nothing of the claim', async () => {
    const r = await run({ space: await acmeSpace(), answers: ['2'] });
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(r.out).toMatch(/^Scanned deployed app spoof-app: /);
    expect((await snapshotOf(r.outDir)).raw.projects.map((p) => p.deployment)).toEqual([
      { app: 'spoof-app', mta: null },
    ]);
    expectNoLeaks(
      { stderr: r.err, transcript: r.transcript.join('\n'), ...(await written(r.outDir)) },
      [...POISON, r.token],
      [ABSOLUTE_PATH],
    );
  });

  it('reads one app of a project with --app, and keeps which module of which MTA it is', async () => {
    const r = await run({ space: await acmeSpace(), args: ['--app', 'acme-srv'], answers: null });
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(r.server.logins).toHaveLength(1);
    expect(sshStatusAsked(r)).toEqual([`/v3/apps/${numbered('a', 3)}/ssh_enabled`]);
    expect(r.out).toMatch(/^Scanned deployed app acme-srv: /);
    expect((await snapshotOf(r.outDir)).raw.projects.map((p) => p.deployment)).toEqual([
      { app: 'acme-srv', mta: { ...MTA_ACME, module: 'acme-srv' } },
    ]);
  });

  it('reads the project named with --mta without a terminal, asking only for its apps', async () => {
    const r = await run({ space: await acmeSpace(), args: ['--mta', 'acme'], answers: null });
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(r.server.logins.map((login) => login.username)).toEqual([sshUser(2), sshUser(3)]);
    // The SSH status of the apps outside the project is not asked for.
    expect(sshStatusAsked(r)).toEqual([
      `/v3/apps/${numbered('a', 2)}/ssh_enabled`,
      `/v3/apps/${numbered('a', 3)}/ssh_enabled`,
    ]);
    const report = await reportOf(r.outDir);
    expect(report.scope.projects).toEqual(['acme-router', 'acme-srv']);
    expect(skippedChecks(report).map((check) => check.id)).toEqual([
      'collect.project.acme-db-deployer',
    ]);
  });

  it('names the projects of the space when --mta names none of them', async () => {
    const r = await run({ space: await acmeSpace(), args: ['--mta', 'nope'], answers: null });
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain(
      'There is no project "nope" in space "dev" of "acme-prod". Projects there: acme.',
    );
    expect(sshStatusAsked(r)).toEqual([]);
    expect(r.server.connections).toBe(0);
    expect(await readdir(r.outDir)).toEqual([]);
    expectNoLeaks({ stderr: r.err }, [...POISON, r.token], [ABSOLUTE_PATH]);
  });

  it('says so when --mta is used in a space without any deployed project', async () => {
    const r = await run({ args: ['--mta', 'acme'], answers: null });
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain(
      'No app in space "dev" of "acme-prod" was deployed as a project (MTA). Name an app with --app <name>.',
    );
    expect(r.server.connections).toBe(0);
  });

  it('still asks for a name when nobody is at the terminal, and mentions --mta', async () => {
    const r = await run({ space: await acmeSpace(), answers: null });
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain(
      'Name the app with --app <name>, or a project with --mta <id>: the list to pick from needs a terminal.',
    );
    expect(r.server.connections).toBe(0);
  });
});

describe('baip-lens project --cf with two deployments of one MTA', () => {
  async function twoDeployments(): Promise<Space> {
    return {
      apps: [
        app(1, 'acme-srv', { ...ready(1), metadata: deployed('acme', 'srv') }),
        app(2, 'blue-acme-srv', {
          ...ready(2),
          metadata: deployed('acme', 'srv', { namespace: 'blue' }),
        }),
      ],
      folders: {
        [sshUser(1)]: await containerFixture(),
        [sshUser(2)]: await containerFixture(),
      },
    };
  }

  const mta = (...args: string[]): Promise<Run> =>
    twoDeployments().then((space) =>
      run({ space, args: ['--mta', 'acme', ...args], answers: null }),
    );

  it('offers them as two projects in the picker', async () => {
    const r = await run({ space: await twoDeployments(), answers: ['2'] });
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(r.transcript).toContain('  1) acme 1.2.0 · project, 1 app(s): acme-srv (srv)');
    expect(r.transcript).toContain(
      '  2) acme 1.2.0 (namespace blue) · project, 1 app(s): blue-acme-srv (srv)',
    );
    expect(r.server.logins.map((login) => login.username)).toEqual([sshUser(2)]);
  });

  it('asks which one when --mta fits both', async () => {
    const r = await mta();
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain(
      'Project "acme" is deployed 2 times in space "dev" (without a namespace, namespace blue). ' +
        'Add --mta-namespace <name>, or --mta-namespace "" for the one without a namespace.',
    );
    expect(sshStatusAsked(r)).toEqual([]);
    expect(r.server.connections).toBe(0);
    expect(await readdir(r.outDir)).toEqual([]);
  });

  it('reads the deployment in the namespace named with --mta-namespace', async () => {
    const r = await mta('--mta-namespace', 'blue');
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(r.server.logins.map((login) => login.username)).toEqual([sshUser(2)]);
    expect(sshStatusAsked(r)).toEqual([`/v3/apps/${numbered('a', 2)}/ssh_enabled`]);
    expect((await reportOf(r.outDir)).scope.projects).toEqual(['blue-acme-srv']);
    expect((await snapshotOf(r.outDir)).raw.projects.map((p) => p.deployment)).toEqual([
      {
        app: 'blue-acme-srv',
        mta: { id: 'acme', version: '1.2.0', module: 'srv', namespace: 'blue' },
      },
    ]);
    // One app read: the one id is named as an app, as in a run of one app.
    expect(r.out).toMatch(/^Scanned deployed app blue-acme-srv: /);
  });

  it('reads the deployment without a namespace with --mta-namespace ""', async () => {
    const r = await mta('--mta-namespace', '');
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(r.server.logins.map((login) => login.username)).toEqual([sshUser(1)]);
    expect((await snapshotOf(r.outDir)).raw.projects.map((p) => p.deployment)).toEqual([
      { app: 'acme-srv', mta: { id: 'acme', version: '1.2.0', module: 'srv', namespace: null } },
    ]);
  });

  it('says which deployments there are when --mta-namespace names none of them', async () => {
    const r = await mta('--mta-namespace', 'green');
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain(
      'Project "acme" has no deployment in namespace "green" in space "dev". Deployments there: without a namespace, namespace blue.',
    );
    expect(r.server.connections).toBe(0);
  });
});

describe('baip-lens project --cf when apps of a project cannot be read', () => {
  /** Two apps that can be read, with whatever each test changes. */
  async function pair(change: Partial<Space> = {}): Promise<Space> {
    return {
      apps: [
        app(1, 'acme-router', { ...ready(1), metadata: deployed('acme', 'acme-approuter') }),
        app(2, 'acme-srv', { ...ready(2), metadata: deployed('acme', 'acme-srv') }),
      ],
      folders: { [sshUser(1)]: await approuterFixture(), [sshUser(2)]: await containerFixture() },
      ...change,
    };
  }
  const mtaAcme = { args: ['--mta', 'acme'], answers: null };

  it('skips an app without project files and reads the other', async () => {
    const space = await pair();
    space.folders[sshUser(1)] = await javaFixture();
    const r = await run({ space, ...mtaAcme });
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(r.server.channels).toEqual(['sftp', 'sftp']);
    const report = await reportOf(r.outDir);
    expect(report.scope.projects).toEqual(['acme-srv']);
    expect(skippedChecks(report)).toEqual([
      {
        id: 'collect.project.acme-router',
        title: 'Files of deployed app acme-router',
        roles: ['SpaceDeveloper'],
        status: 'skipped',
        reasonCode: 'unavailable',
        reason:
          'it has no package.json, mta.yaml or .cdsrc.json in its app folder, so the project rules have nothing to read',
      },
    ]);
    expect(r.out).toMatch(/^Scanned deployed app acme-srv: .*, 1 check\(s\) skipped\.\n/);
  });

  it('skips an app whose SSH login is refused after another app was read, without blaming the role', async () => {
    const r = await run({ space: await pair({ accept: [CODES[0] ?? ''] }), ...mtaAcme });
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(r.server.logins).toEqual([
      { method: 'password', username: sshUser(1), password: CODES[0] },
      { method: 'password', username: sshUser(2), password: CODES[1] },
    ]);
    // Only the session that was accepted opened a channel.
    expect(r.server.channels).toEqual(['sftp']);
    const report = await reportOf(r.outDir);
    expect(report.scope.projects).toEqual(['acme-router']);
    expect(skippedChecks(report)).toEqual([
      {
        id: 'collect.project.acme-srv',
        title: 'Files of deployed app acme-srv',
        roles: ['SpaceDeveloper'],
        status: 'skipped',
        reasonCode: 'error',
        reason: 'the SSH login was refused for this app',
      },
    ]);
    expect(r.err).not.toContain('was refused. Reading a deployed app needs the Space Developer');
    expectNoLeaks(
      { stderr: r.err, ...(await written(r.outDir)) },
      [...POISON, r.token],
      [ABSOLUTE_PATH],
    );
  });

  it('stops at the first app when its SSH login is refused: one attempt, nothing written', async () => {
    const r = await run({ space: await pair({ accept: [] }), ...mtaAcme });
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain('The SSH login to "acme-router" was refused');
    expect(r.err).toContain('Space Developer role in space "dev"');
    expect(r.server.connections).toBe(1);
    expect(r.server.logins).toHaveLength(1);
    expect(r.fake.calls.filter((c) => c.url.pathname === '/oauth/authorize')).toHaveLength(1);
    expect(await readdir(r.outDir)).toEqual([]);
    expectNoLeaks({ stdout: r.out, stderr: r.err }, [...POISON, r.token]);
  });

  it('stops the whole run when the SSH server does not present the published host key', async () => {
    const r = await run({ space: await pair(), ...mtaAcme, wrongHostKey: true });
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain('did not present the host key the CF API published');
    expect(r.server.connections).toBe(1);
    expect(r.server.logins).toEqual([]);
    expect(await readdir(r.outDir)).toEqual([]);
  });

  it('keeps nothing of an app whose session is lost while it is read', async () => {
    const r = await run({ space: await pair({ dropOnOpen: [sshUser(2)] }), ...mtaAcme });
    expect(r.code, r.err).toBe(EXIT.ok);
    const report = await reportOf(r.outDir);
    expect(report.scope.projects).toEqual(['acme-router']);
    expect(skippedChecks(report)).toEqual([
      {
        id: 'collect.project.acme-srv',
        title: 'Files of deployed app acme-srv',
        roles: ['SpaceDeveloper'],
        status: 'skipped',
        reasonCode: 'error',
        reason: 'the connection closed before the app was read',
      },
    ]);
    expect(report.findings.some((f) => f.app.guid === 'project:acme-srv')).toBe(false);
    expect((await snapshotOf(r.outDir)).raw.projects.map((p) => p.id)).toEqual(['acme-router']);
    // "Nothing was written" is the message of a run of one app; here a report was written.
    expect(r.err).not.toContain('nothing was written');
  });

  it('ends a run of one app whose session is lost with exit code 2, and writes nothing', async () => {
    const r = await run({
      space: await pair({ dropOnOpen: [sshUser(2)] }),
      args: ['--app', 'acme-srv'],
      answers: null,
    });
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain(
      'The connection to the app closed before the scan finished, so nothing was written. Run the command again.',
    );
    // The session was opened and lost; it is not recorded as a skipped check of a report.
    expect(r.server.logins.map((login) => login.username)).toEqual([sshUser(2)]);
    expect(r.server.channels).toEqual(['sftp']);
    expect(r.out).toBe('');
    expect(await readdir(r.outDir)).toEqual([]);
  });

  it('stops the whole run when UAA cannot be reached for a later app, and names the network as the cause', async () => {
    const space = await pair();
    space.apps.push(app(3, 'acme-ui', { ...ready(3), metadata: deployed('acme', 'acme-ui') }));
    space.folders[sshUser(3)] = await approuterFixture();
    const r = await run({ space, ...mtaAcme, uaaDownFrom: 2 });
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain(`Network error for https://${UAA_HOST}/oauth/authorize`);
    expect(r.err).toContain('ECONNRESET');
    expect(r.err).not.toContain('an unexpected error');
    // The first app was read; UAA is asked once for the second app, and the third is not tried.
    expect(r.server.logins.map((login) => login.username)).toEqual([sshUser(1)]);
    expect(r.fake.calls.filter((c) => c.url.pathname === '/oauth/authorize')).toHaveLength(2);
    expect(
      r.fake.calls.some((c) => c.url.pathname === `/v3/apps/${numbered('a', 3)}/processes/web`),
    ).toBe(false);
    expect(r.out).toBe('');
    expect(await readdir(r.outDir)).toEqual([]);
    expectNoLeaks({ stderr: r.err }, [...POISON, r.token]);
  });

  it('stops at the first app when UAA cannot be reached at all: one request, nothing written', async () => {
    const r = await run({ space: await pair(), ...mtaAcme, uaaDownFrom: 1 });
    expect(r.code).toBe(EXIT.error);
    expect(r.err).toContain(`Network error for https://${UAA_HOST}/oauth/authorize`);
    expect(r.err).not.toContain('No app of project "acme" could be read');
    expect(r.fake.calls.filter((c) => c.url.pathname === '/oauth/authorize')).toHaveLength(1);
    expect(r.server.connections).toBe(0);
    expect(await readdir(r.outDir)).toEqual([]);
  });

  it('names the kind of error behind an app that was skipped unexpectedly only with BAIP_LENS_DEBUG', async () => {
    const space = await pair();
    space.apps[0] = app(1, 'acme-router', {
      ssh: SSH_ON,
      web: { process: processOf(1), instances: [], broken: true },
      metadata: deployed('acme', 'acme-approuter'),
    });
    const r = await run({ space, ...mtaAcme, env: { BAIP_LENS_DEBUG: '1' } });
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(skippedChecks(await reportOf(r.outDir)).map((c) => [c.id, c.reason])).toEqual([
      ['collect.project.acme-router', 'an unexpected error stopped the reading of this app'],
    ]);
    // The class of the error, never its message: that could repeat what the server answered.
    expect(r.err).toMatch(/^debug: app "acme-router" was not read after a \w+$/m);
    expectNoLeaks(
      { stderr: r.err, ...(await written(r.outDir)) },
      [...POISON, r.token],
      [ABSOLUTE_PATH],
    );
  });

  it('keeps the names and the cf commands of apps that were not read in the terminal: a report gets a fixed reason', async () => {
    // Cloud Foundry allows any printable character in an app name.
    const hostile = 'x$(id)`id` \'q\' "d" \\';
    const stale = 'acme-stale$(id)';
    // A name no rule text, field name or file name can hold by chance.
    const spaceName = 'quartz-7';
    const space: Space = {
      name: spaceName,
      apps: [
        app(1, 'acme-router', { ...ready(1), metadata: deployed('acme', 'acme-approuter') }),
        app(2, 'acme-spaceoff', {
          ssh: { enabled: false, reason: `ssh is disabled for space '${spaceName}'` },
          metadata: deployed('acme', 'spaceoff'),
        }),
        app(3, stale, {
          ssh: SSH_ON,
          web: { process: processOf(3), instances: ['DOWN'] },
          metadata: deployed('acme', 'stale'),
        }),
        app(4, hostile, { state: 'STOPPED', metadata: deployed('acme', 'db') }),
      ],
      folders: { [sshUser(1)]: await approuterFixture() },
    };
    const r = await run({ space, ...mtaAcme });
    expect(r.code, r.err).toBe(EXIT.ok);

    const report = await reportOf(r.outDir);
    expect(report.scope).toEqual({ apiEndpoint: `${API}/`, orgs: [], projects: ['acme-router'] });
    expect(skippedChecks(report).map((c) => [c.title, c.reasonCode, c.reason])).toEqual([
      ['Files of deployed app acme-spaceoff', 'unavailable', 'SSH is off for its space'],
      [`Files of deployed app ${stale}`, 'unavailable', 'no instance of it is running right now'],
      [`Files of deployed app ${hostile}`, 'unavailable', 'it is stopped'],
    ]);
    expect(r.out).toContain('  skipped collect.project.acme-spaceoff: SSH is off for its space\n');

    // No cf command and no space name in anything written: a report is shared, and a command
    // with a name in it is pasted into a shell.
    const files = await written(r.outDir);
    expect(Object.keys(files).length).toBeGreaterThan(3);
    for (const [name, content] of Object.entries(files)) {
      expect(content, name).not.toMatch(/`cf |cf start|cf app |allow-space-ssh|enable-ssh/);
      // The reason of a skipped check was the one place that named the space.
      expect(content, name).not.toContain(spaceName);
    }
    expect(r.out).not.toMatch(/`cf |allow-space-ssh/);
    expectNoLeaks(files, [...POISON, r.token], [ABSOLUTE_PATH]);

    // The terminal says what to do, with every name quoted so that a shell takes it as one word of text.
    expect(r.err).toContain(
      `Not reading app "acme-spaceoff": SSH is off for space "${spaceName}": a Space Manager can turn it on with \`cf allow-space-ssh ${spaceName}\`\n`,
    );
    expect(r.err).toContain(
      `Not reading app "${hostile}": it is stopped: start it with \`cf start 'x$(id)\`id\` '\\''q'\\'' "d" \\'\`\n`,
    );
    const one = await run({ space, args: ['--app', stale], answers: null });
    expect(one.code).toBe(EXIT.error);
    expect(one.err).toContain(
      `No instance of "${stale}" is running right now, so its files cannot be read. Check it with \`cf app 'acme-stale$(id)'\`.`,
    );
    expect(await readdir(one.outDir)).toEqual([]);
  });

  it('writes nothing when no app of the project is ready', async () => {
    const space: Space = {
      apps: [
        app(1, 'acme-db-deployer', { state: 'STOPPED', metadata: deployed('acme', 'db') }),
        app(2, 'acme-job', { lifecycle: 'docker', metadata: deployed('acme', 'job') }),
      ],
      folders: {},
    };
    const named = await run({ space, ...mtaAcme });
    expect(named.code).toBe(EXIT.error);
    expect(named.err).toContain(
      'No app of project "acme" can be read right now: ' +
        'acme-db-deployer: it is stopped: start it with `cf start acme-db-deployer`; ' +
        'acme-job: it runs a Docker image, which has no buildpack app folder to read.',
    );
    expect(named.server.connections).toBe(0);
    expect(await readdir(named.outDir)).toEqual([]);
    expectNoLeaks({ stderr: named.err }, [...POISON, named.token], [ABSOLUTE_PATH]);

    // The picker does not offer the project either.
    const picked = await run({ space, answers: ['1'] });
    expect(picked.code).toBe(EXIT.error);
    expect(picked.transcript).toContain(
      '  - acme-job: it runs a Docker image, which has no buildpack app folder to read',
    );
    expect(picked.transcript.some((line) => /^\s+\d\) /.test(line))).toBe(false);
    expect(picked.err).toContain(
      'None of the 2 app(s) in space "dev" can be read right now (reasons above).',
    );
    expect(await readdir(picked.outDir)).toEqual([]);
  });

  it('writes nothing when every app of the project turned out unreadable', async () => {
    const space = await pair();
    space.folders[sshUser(1)] = await javaFixture();
    space.folders[sshUser(2)] = await javaFixture();
    const r = await run({ space, ...mtaAcme });
    expect(r.code).toBe(EXIT.error);
    const why =
      'it has no package.json, mta.yaml or .cdsrc.json in its app folder, so the project rules have nothing to read';
    expect(r.err).toContain(
      `No app of project "acme" could be read: acme-router: ${why}; acme-srv: ${why}.`,
    );
    expect(r.server.connections).toBe(2);
    expect(await readdir(r.outDir)).toEqual([]);
    expectNoLeaks({ stdout: r.out, stderr: r.err }, [...POISON, r.token], [ABSOLUTE_PATH]);
  });

  it('records each app that was not read with its own reason, and report --from keeps them', async () => {
    const odd = 'acme srv (blue)';
    const space: Space = {
      apps: [
        app(11, 'acme-broken', {
          ssh: SSH_ON,
          web: { process: processOf(11), instances: [], broken: true },
          metadata: deployed('acme', 'broken'),
        }),
        app(1, 'acme-db-deployer', { state: 'STOPPED', metadata: deployed('acme', 'db') }),
        app(2, 'acme-docker', { lifecycle: 'docker', metadata: deployed('acme', 'job') }),
        app(3, 'acme-java', { ...ready(3), metadata: deployed('acme', 'java') }),
        app(4, 'acme-lost', { ...ready(4), metadata: deployed('acme', 'lost') }),
        app(5, 'acme-no-web', { ssh: SSH_ON, web: 'none', metadata: deployed('acme', 'worker') }),
        app(6, 'acme-nossh', {
          ssh: { enabled: false, reason: 'ssh is disabled for app' },
          metadata: deployed('acme', 'nossh'),
        }),
        app(7, 'acme-refused', { ...ready(7), metadata: deployed('acme', 'refused') }),
        app(8, 'acme-router', { ...ready(8), metadata: deployed('acme', 'acme-approuter') }),
        app(9, 'acme-stale', {
          ssh: SSH_ON,
          web: { process: processOf(9), instances: ['CRASHED', 'DOWN'] },
          metadata: deployed('acme', 'stale'),
        }),
        app(10, odd, { ...ready(10), metadata: deployed('acme', 'acme-srv') }),
      ],
      folders: {
        [sshUser(3)]: await javaFixture(),
        [sshUser(4)]: await containerFixture(),
        [sshUser(7)]: await containerFixture(),
        [sshUser(8)]: await approuterFixture(),
        [sshUser(10)]: await containerFixture(),
      },
      // Five sessions are opened, in name order; the third code (acme-refused) is not accepted.
      accept: CODES.filter((_, index) => index !== 2),
      dropOnOpen: [sshUser(4)],
    };
    const r = await run({ space, ...mtaAcme });
    expect(r.code, r.err).toBe(EXIT.ok);

    const oddId = `acme-srv-blue-${createHash('sha256').update(odd).digest('hex').slice(0, 8)}`;
    const report = await reportOf(r.outDir);
    expect(report.scope.projects).toEqual(['acme-router', oddId]);
    expect(report.checks[0]).toMatchObject({ id: 'collect.project', status: 'ran' });
    expect(skippedChecks(report).map((c) => [c.id, c.reasonCode, c.reason])).toEqual([
      // The API answered something unexpected about this app: a fixed sentence, not its text.
      [
        'collect.project.acme-broken',
        'error',
        'an unexpected error stopped the reading of this app',
      ],
      ['collect.project.acme-db-deployer', 'unavailable', 'it is stopped'],
      [
        'collect.project.acme-docker',
        'unavailable',
        'it runs a Docker image, which has no buildpack app folder to read',
      ],
      [
        'collect.project.acme-java',
        'unavailable',
        'it has no package.json, mta.yaml or .cdsrc.json in its app folder, so the project rules have nothing to read',
      ],
      ['collect.project.acme-lost', 'error', 'the connection closed before the app was read'],
      [
        'collect.project.acme-no-web',
        'unavailable',
        'it has no web process, so there is no instance to read',
      ],
      ['collect.project.acme-nossh', 'unavailable', 'SSH is off for this app'],
      ['collect.project.acme-refused', 'error', 'the SSH login was refused for this app'],
      ['collect.project.acme-stale', 'unavailable', 'no instance of it is running right now'],
    ]);
    // Every project rule still ran on the two apps that were read.
    const rules = report.checks.filter((check) => check.id.startsWith('rule.'));
    expect(rules.length).toBeGreaterThan(0);
    expect(rules.every((check) => check.status === 'ran')).toBe(true);
    expect(r.out).toMatch(
      new RegExp(`^Scanned deployed apps acme-router, ${oddId}: .*, 9 check\\(s\\) skipped\\.\\n`),
    );

    // The app whose name is not an id is reported under a derived one, and keeps its name.
    const snapshot = await snapshotOf(r.outDir);
    expect(snapshot.raw.projects.map((p) => [p.id, p.deployment])).toEqual([
      ['acme-router', { app: 'acme-router', mta: { ...MTA_ACME, module: 'acme-approuter' } }],
      [oddId, { app: odd, mta: { ...MTA_ACME, module: 'acme-srv' } }],
    ]);

    // No reason names the container path, a server message, a line of a file, an app or a command.
    for (const check of skippedChecks(report)) {
      expect(check.reason).not.toMatch(ABSOLUTE_PATH);
      expect(check.reason).not.toContain('at line');
      expect(check.reason).not.toMatch(/acme|`/);
    }
    // The cf commands that would change things are for the terminal.
    expect(r.err).toContain(
      'Not reading app "acme-nossh": SSH is off for this app: turn it on with `cf enable-ssh acme-nossh`, then `cf restart acme-nossh`\n',
    );
    // Why the unexpected error happened is not told unless asked for (BAIP_LENS_DEBUG).
    expect(r.err).not.toContain('debug:');
    expectNoLeaks({ stdout: r.out }, [...POISON, r.token]);
    expectNoLeaks(
      { stderr: r.err, ...(await written(r.outDir)) },
      [...POISON, r.token],
      [ABSOLUTE_PATH],
    );

    // Offline, from the snapshot: the same findings, and the apps that were not read are still named.
    const again = await mkdtemp(join(tmpdir(), 'baip-lens-cf-again-'));
    let out = '';
    const code = await main(
      ['report', '--from', await snapshotPath(r.outDir), '--format', 'json', '--out', again],
      {
        stdout: (text) => (out += text),
        stderr: () => undefined,
        env: {},
        isTTY: false,
        fetch: () => Promise.reject(new Error('network must not be used')),
      },
    );
    expect(code).toBe(EXIT.ok);
    const offline = await reportOf(again);
    expect(offline.findings).toEqual(report.findings);
    expect(offline.findings.length).toBeGreaterThan(0);
    expect(offline.checks).toEqual(report.checks);
    expect(offline.scope).toEqual(report.scope);
    expect(out).toMatch(
      new RegExp(`^Scanned deployed apps acme-router, ${oddId}: .*, 9 check\\(s\\) skipped\\.\\n`),
    );
    expect(out).toContain(
      '  skipped collect.project.acme-lost: the connection closed before the app was read\n',
    );
  }, 30_000);

  it('does not offer or read a project with more than 50 apps as a whole', async () => {
    const space: Space = {
      apps: Array.from({ length: 51 }, (_, i) =>
        app(i + 1, `big-${String(i + 1).padStart(2, '0')}`, {
          state: 'STOPPED',
          metadata: deployed('big', `module-${i + 1}`),
        }),
      ),
      folders: {},
    };
    const named = await run({ space, args: ['--mta', 'big'], answers: null });
    expect(named.code).toBe(EXIT.error);
    expect(named.err).toContain(
      'Project "big" cannot be read as a whole: it has 51 apps, more than the 50 one run reads; read one app with --app <name>.',
    );
    expect(named.server.connections).toBe(0);

    const picked = await run({ space, answers: ['1'] });
    expect(picked.code).toBe(EXIT.error);
    expect(picked.transcript).toContain(
      '  - project big: it has 51 apps, more than the 50 one run reads; read one app with --app <name>',
    );
    expect(picked.transcript.some((line) => /^\s+\d+\) /.test(line))).toBe(false);
    expect(await readdir(picked.outDir)).toEqual([]);
  });
});

/*
 * The npm lockfiles of a deployed app: the lockfile npm wrote into the tree
 * it installed is read in place of the one that was pushed, through the same
 * session and with read requests only; without it the pushed lockfile is the
 * fallback, without the dev packages a production install leaves out.
 */

/** A `package.json` whose dependencies the lockfiles of these tests pin. */
const LOCKED_MANIFEST = JSON.stringify({
  name: 'acme-incidents',
  dependencies: { '@baip-fixture/odata': '^3.0.0', 'baip-fixture-server': '^2.0.0' },
  devDependencies: { 'baip-fixture-test-kit': '^7.0.0' },
  optionalDependencies: { 'baip-fixture-watcher': '^2.3.0' },
});
const NPMRC = '//registry.npmjs.org/:_authToken=POISON_npmrc\n';

interface LockfileJson {
  file: string;
  kind: string;
  lockfileVersion: number | null;
  status: string;
  kept: number;
  notKept: Record<string, number>;
}

interface DependenciesJson {
  lockfiles: LockfileJson[];
  lockfilesNotRead: number;
  packages: {
    name: string;
    version: string;
    direct: boolean;
    scope: string;
    lockfiles: string[];
  }[];
}

interface LockedProjectJson {
  id: string;
  files: string[];
  filesOpened: number;
  unreadable: { file: string; kind: string }[];
  dependencies: DependenciesJson;
}

interface LockedReportJson {
  checks: CheckJson[];
  findings: {
    id: string;
    severity: string;
    app: { guid: string };
    evidence: Record<string, unknown>;
    location?: { file: string };
    remediation: string;
  }[];
}

async function lockedProjects(dir: string): Promise<LockedProjectJson[]> {
  const snapshot = JSON.parse(await readFile(await snapshotPath(dir), 'utf8')) as {
    raw: { projects: LockedProjectJson[] };
  };
  // Every file the collector opened is listed, as read or as unreadable.
  for (const project of snapshot.raw.projects) {
    expect(project.filesOpened).toBe(project.files.length + project.unreadable.length);
  }
  return snapshot.raw.projects;
}

async function dependencyFindings(dir: string): Promise<LockedReportJson['findings']> {
  const report = JSON.parse(
    await readFile(join(dir, 'baip-lens-report.json'), 'utf8'),
  ) as LockedReportJson;
  return report.findings.filter((finding) => finding.id.startsWith('DEP_'));
}

/** One app on its own in the space, read with --app. */
async function runOneApp(folder: string): Promise<Run> {
  const space: Space = {
    apps: [app(1, 'locked-srv', ready(1))],
    folders: { [sshUser(1)]: folder },
  };
  return run({ space, args: ['--app', 'locked-srv'], answers: null });
}

/** `report --from` on the snapshot of a run, without a network: the same findings and checks. */
async function expectSameOffline(r: Run): Promise<void> {
  const again = await mkdtemp(join(tmpdir(), 'baip-lens-cf-again-'));
  const code = await main(
    ['report', '--from', await snapshotPath(r.outDir), '--format', 'json', '--out', again],
    {
      stdout: () => undefined,
      stderr: () => undefined,
      env: {},
      isTTY: false,
      fetch: () => Promise.reject(new Error('network must not be used')),
    },
  );
  expect(code).toBe(EXIT.ok);
  const findings = await dependencyFindings(r.outDir);
  expect(findings.length).toBeGreaterThan(0);
  expect(await dependencyFindings(again)).toEqual(findings);
  expect((await reportOf(again)).checks).toEqual((await reportOf(r.outDir)).checks);
}

async function expectNothingLeaked(r: Run): Promise<void> {
  expectNoLeaks({ stdout: r.out }, [...POISON, r.token]);
  expectNoLeaks(
    { stderr: r.err, ...(await written(r.outDir)) },
    [...POISON, r.token],
    [ABSOLUTE_PATH],
  );
}

describe('baip-lens project --cf and the npm lockfiles of a deployed app', () => {
  it('reads the lockfile of the installed tree through a node_modules that is a symbolic link', async () => {
    // As the Node.js buildpack leaves it: node_modules is a link to a folder next to the app.
    const folder = await appFolder({
      'package.json': LOCKED_MANIFEST,
      'package-lock.json': pushedLockfile(),
      '.npmrc': NPMRC,
    });
    const installed = join(folder, '..', 'deps', '0', 'node_modules');
    await mkdir(join(installed, 'baip-fixture-server'), { recursive: true });
    await writeFile(join(installed, '.package-lock.json'), installedLockfile());
    await writeFile(
      join(installed, 'baip-fixture-server', 'package.json'),
      '{"name":"POISON_node_modules"}',
    );
    await symlink(join('..', 'deps', '0', 'node_modules'), join(folder, 'node_modules'));

    const r = await runOneApp(folder);
    expect(r.code, r.err).toBe(EXIT.ok);
    const [project] = await lockedProjects(r.outDir);
    expect(project?.dependencies).toEqual({
      lockfiles: [
        {
          file: 'node_modules/.package-lock.json',
          kind: 'hidden',
          lockfileVersion: 3,
          status: 'read',
          kept: 4,
          notKept: { ...NO_OTHER_PACKAGES, otherRegistry: 1, git: 1, link: 1 },
        },
      ],
      lockfilesNotRead: 0,
      packages: INSTALLED_PACKAGES,
    });
    expect(project?.files).toEqual(['node_modules/.package-lock.json', 'package.json']);

    // The link is never listed or entered; the one file behind it is asked for by its full path.
    expectOnlyReads(r);
    expect([...new Set(underNodeModules(r))]).toEqual([
      `LSTAT ${HIDDEN}`,
      `OPEN ${HIDDEN}`,
      `FSTAT ${HIDDEN}`,
      `READ ${HIDDEN}`,
      `CLOSE ${HIDDEN}`,
    ]);
    const touched = r.server.requests.map((q) => q.path ?? '');
    expect(touched.some((path) => path.includes('deps'))).toBe(false);
    expect(touched).not.toContain('/home/vcap/app/package-lock.json');
    expect((await dependencyFindings(r.outDir)).map((f) => f.id)).toEqual(['DEP_NOT_CHECKED']);
    await expectNothingLeaked(r);
    // The record of the hidden lockfile loads again: the same findings offline.
    await expectSameOffline(r);
  });

  it('does not follow a hidden lockfile that is itself a link, and falls back to the pushed one', async () => {
    const folder = await appFolder({
      'package.json': LOCKED_MANIFEST,
      'package-lock.json': pushedLockfile(),
      'node_modules/baip-fixture-server/package.json': '{"name":"POISON_node_modules"}',
    });
    const outside = join(folder, '..', 'outside-lock.json');
    await writeFile(
      outside,
      hiddenLockfile('outside', {
        'node_modules/baip-fixture-outside': registryEntry('baip-fixture-outside', '9.9.9'),
      }),
    );
    await symlink(outside, join(folder, 'node_modules', '.package-lock.json'));

    const r = await runOneApp(folder);
    expect(r.code, r.err).toBe(EXIT.ok);
    // Looked at once, found to be no regular file, and never opened.
    expect(underNodeModules(r)).toEqual([`LSTAT ${HIDDEN}`]);
    const [project] = await lockedProjects(r.outDir);
    expect(project?.dependencies.lockfiles.map((l) => [l.file, l.kind, l.status])).toEqual([
      ['package-lock.json', 'package-lock', 'read'],
    ]);
    expect(project?.dependencies.packages.map((item) => item.name)).not.toContain(
      'baip-fixture-outside',
    );
    expect(project?.unreadable).toEqual([]);
    expectOnlyReads(r);
  });

  it('falls back to the pushed package-lock.json, without its dev entries, when nothing else is there', async () => {
    const folder = await appFolder({
      'package.json': LOCKED_MANIFEST,
      'package-lock.json': pushedLockfile(),
      '.npmrc': NPMRC,
    });
    const r = await runOneApp(folder);
    expect(r.code, r.err).toBe(EXIT.ok);

    // One look for the hidden lockfile, which costs nothing else.
    expect(underNodeModules(r)).toEqual([`LSTAT ${HIDDEN}`]);
    expectOnlyReads(r);
    const [project] = await lockedProjects(r.outDir);
    expect(project?.files).toEqual(['package-lock.json', 'package.json']);
    expect(project?.unreadable).toEqual([]);
    expect(project?.filesOpened).toBe(2);
    // The two dev packages and the private dev package are not installed: not kept, not counted.
    expect(project?.dependencies).toEqual({
      lockfiles: [
        {
          file: 'package-lock.json',
          kind: 'package-lock',
          lockfileVersion: 3,
          status: 'read',
          kept: 3,
          notKept: { ...NO_OTHER_PACKAGES, otherRegistry: 1 },
        },
      ],
      lockfilesNotRead: 0,
      packages: [
        { name: '@baip-fixture/odata', version: '3.0.0', direct: true, scope: 'prod' },
        { name: 'baip-fixture-server', version: '2.0.0', direct: true, scope: 'prod' },
        { name: 'baip-fixture-shared', version: '1.2.0', direct: false, scope: 'optional' },
      ].map((item) => ({ ...item, lockfiles: ['package-lock.json'] })),
    });
    expect(r.err).toContain(
      'Read 1 npm lockfile(s): 3 package(s) from the public npm registry, 1 other package(s) not checked\n',
    );
    const findings = await dependencyFindings(r.outDir);
    expect(findings.map((f) => [f.id, f.evidence.otherRegistry, f.evidence.checked])).toEqual([
      ['DEP_NOT_CHECKED', 1, 3],
    ]);
    await expectNothingLeaked(r);

    await expectSameOffline(r);
  });

  it('says that an app without any lockfile has none, with the advice for a deployed app', async () => {
    const r = await runOneApp(await approuterFixture());
    expect(r.code, r.err).toBe(EXIT.ok);
    expect(underNodeModules(r)).toEqual([`LSTAT ${HIDDEN}`]);
    const [project] = await lockedProjects(r.outDir);
    expect(project?.dependencies).toEqual({ lockfiles: [], lockfilesNotRead: 0, packages: [] });
    expect(project?.files).toEqual(['package.json', 'xs-app.json']);
    expect(r.err).not.toContain('npm lockfile');
    const findings = await dependencyFindings(r.outDir);
    expect(
      findings.map((f) => [f.id, f.severity, f.evidence.cause, f.evidence.subject, f.location]),
    ).toEqual([['DEP_LOCKFILE_MISSING', 'low', 'none', 'package.json', { file: 'package.json' }]]);
    expect(findings[0]?.remediation).toContain('Push the lockfile with the app');
  });

  it('reads the lockfiles of every app of a project run, each in its own session', async () => {
    const router = await appFolder({
      'package.json': JSON.stringify({
        name: 'acme-approuter',
        dependencies: { 'baip-fixture-router': '^1.0.0', 'baip-fixture-server': '^2.0.0' },
      }),
      'xs-app.json': JSON.stringify({ authenticationMethod: 'route', routes: [] }),
      'node_modules/.package-lock.json': hiddenLockfile('acme-approuter', {
        'node_modules/baip-fixture-router': registryEntry('baip-fixture-router', '1.0.0'),
        'node_modules/baip-fixture-server': registryEntry('baip-fixture-server', '2.4.1'),
        'node_modules/@poison-scope/private': privateEntry('@poison-scope/private'),
      }),
      '.npmrc': NPMRC,
    });
    const space: Space = {
      apps: [
        app(1, 'acme-router', { ...ready(1), metadata: deployed('acme', 'acme-approuter') }),
        app(2, 'acme-srv', { ...ready(2), metadata: deployed('acme', 'acme-srv') }),
      ],
      folders: { [sshUser(1)]: router, [sshUser(2)]: await containerFixture() },
    };
    const r = await run({ space, args: ['--mta', 'acme'], answers: null });
    expect(r.code, r.err).toBe(EXIT.ok);

    const projects = await lockedProjects(r.outDir);
    expect(projects.map((p) => [p.id, p.dependencies.lockfiles.map((l) => l.kind)])).toEqual([
      ['acme-router', ['hidden']],
      ['acme-srv', ['hidden']],
    ]);
    // A package both apps have installed is kept for each of them.
    expect(projects[0]?.dependencies.packages).toEqual(
      [
        { name: 'baip-fixture-router', version: '1.0.0', direct: true, scope: 'prod' },
        { name: 'baip-fixture-server', version: '2.4.1', direct: true, scope: 'prod' },
      ].map((item) => ({ ...item, lockfiles: ['node_modules/.package-lock.json'] })),
    );
    expect(projects[1]?.dependencies.packages).toEqual(INSTALLED_PACKAGES);

    // One line per app, right after the line about its files.
    const lines = r.err.split('\n');
    const after = (start: RegExp): string | undefined =>
      lines[lines.findIndex((line) => start.test(line)) + 1];
    expect(after(/^Read \d+ project file\(s\) in project acme-router$/)).toBe(
      'Read 1 npm lockfile(s): 2 package(s) from the public npm registry, 1 other package(s) not checked',
    );
    expect(after(/^Read \d+ project file\(s\), 1 unreadable in project acme-srv$/)).toBe(
      'Read 1 npm lockfile(s): 4 package(s) from the public npm registry, 2 other package(s) not checked',
    );

    // Each session asked for its own hidden lockfile, and for nothing else under node_modules.
    expectOnlyReads(r);
    for (const user of [sshUser(1), sshUser(2)]) {
      const asked = r.server.requests
        .filter((q) => q.username === user && (q.path ?? '').includes('node_modules'))
        .map((q) => `${q.type} ${q.path ?? ''}`);
      expect(asked[0], user).toBe(`LSTAT ${HIDDEN}`);
      expect(asked).toContain(`OPEN ${HIDDEN}`);
    }
    const findings = await dependencyFindings(r.outDir);
    expect(findings.map((f) => [f.id, f.app.guid, f.evidence.checked])).toEqual([
      ['DEP_NOT_CHECKED', 'project:acme-router', 2],
      ['DEP_NOT_CHECKED', 'project:acme-srv', 4],
    ]);
    const report = await reportOf(r.outDir);
    expect(report.checks.find((check) => check.id === 'collect.dependencies')).toMatchObject({
      status: 'ran',
      roles: ['SpaceDeveloper'],
    });
    await expectNothingLeaked(r);
  }, 20_000);

  /** A hidden lockfile of `count` public packages with invented names. */
  function bulkLockfile(prefix: string, count: number): string {
    const packages: Record<string, unknown> = {};
    for (let i = 0; i < count; i += 1) {
      const name = `baip-bulk-${prefix}-${String(i).padStart(5, '0')}`;
      packages[`node_modules/${name}`] = {
        version: '1.0.0',
        resolved: `https://registry.npmjs.org/${name}/-/${name}-1.0.0.tgz`,
      };
    }
    return hiddenLockfile('bulk', packages);
  }

  it('shares one budget of 20,000 packages among the apps of a project run', async () => {
    const bulkApp = (prefix: string): Promise<string> =>
      appFolder({
        'package.json': JSON.stringify({
          name: `bulk-${prefix}`,
          dependencies: { [`baip-bulk-${prefix}-00000`]: '^1.0.0' },
        }),
        'node_modules/.package-lock.json': bulkLockfile(prefix, 10_500),
      });
    const space: Space = {
      apps: [
        app(1, 'bulk-a', { ...ready(1), metadata: deployed('bulk', 'a') }),
        app(2, 'bulk-b', { ...ready(2), metadata: deployed('bulk', 'b') }),
      ],
      folders: { [sshUser(1)]: await bulkApp('a'), [sshUser(2)]: await bulkApp('b') },
    };
    const r = await run({ space, args: ['--mta', 'bulk'], answers: null });
    expect(r.code, r.err).toBe(EXIT.ok);

    // The first app keeps its 10,500 packages; the 10,500 of the second do not fit into what is left.
    const projects = await lockedProjects(r.outDir);
    expect(
      projects.map((p) => [
        p.id,
        p.dependencies.lockfiles.map((l) => [l.kind, l.status, l.kept]),
        p.dependencies.packages.length,
      ]),
    ).toEqual([
      ['bulk-a', [['hidden', 'read', 10_500]], 10_500],
      ['bulk-b', [['hidden', 'too-many-packages', 0]], 0],
    ]);
    expect(projects[0]?.dependencies.packages[0]).toEqual({
      name: 'baip-bulk-a-00000',
      version: '1.0.0',
      direct: true,
      scope: 'prod',
      lockfiles: ['node_modules/.package-lock.json'],
    });
    // A lockfile that does not fit is reported, never passed over; the finding points nowhere.
    const findings = await dependencyFindings(r.outDir);
    expect(
      findings.map((f) => [f.id, f.app.guid, f.evidence.cause ?? null, f.location ?? null]),
    ).toEqual([
      ['DEP_LOCKFILE_MISSING', 'project:bulk-b', 'too-many-packages', null],
      ['DEP_NOT_CHECKED', 'project:bulk-b', null, null],
    ]);

    // A lockfile of more than a megabyte, in requests that each fit one SFTP packet.
    expectOnlyReads(r);
    const reads = r.server.requests.filter(
      (q) => q.username === sshUser(1) && q.type === 'READ' && q.path === HIDDEN,
    );
    expect(reads.length).toBeGreaterThan(30);
    expect(Math.max(...reads.map((q) => q.length ?? 0))).toBe(MAX_READ_BYTES);
    // Every byte was asked for once, in order, from the first to the last.
    const offsets = reads.map((q) => q.offset ?? -1);
    expect(offsets).toEqual([...offsets].sort((a, b) => a - b));
    expect(new Set(offsets).size).toBe(offsets.length);

    // On its own the second app has the whole budget.
    const alone = await run({ space, args: ['--app', 'bulk-b'], answers: null });
    expect(alone.code, alone.err).toBe(EXIT.ok);
    const [second] = await lockedProjects(alone.outDir);
    expect(second?.dependencies.lockfiles.map((l) => [l.kind, l.status, l.kept])).toEqual([
      ['hidden', 'read', 10_500],
    ]);
    expect(await dependencyFindings(alone.outDir)).toEqual([]);
  }, 60_000);

  describe('when the session is lost while the ranges of a lockfile are in flight', () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason);
    };
    beforeEach(() => {
      unhandled.length = 0;
      process.on('unhandledRejection', onUnhandled);
    });
    afterEach(() => {
      process.off('unhandledRejection', onUnhandled);
    });

    /** An app whose hidden lockfile needs its head and more than four ranges. */
    const largeLockfileApp = (): Promise<string> =>
      appFolder({
        'package.json': LOCKED_MANIFEST,
        'node_modules/.package-lock.json': bulkLockfile('lost', 2_000),
        'package-lock.json': pushedLockfile(),
      });

    /** The head was answered, and the session went with requests for what follows it sent. */
    function expectLostInFlight(r: Run, user: string): void {
      const reads = r.server.requests.filter(
        (q) => q.username === user && q.type === 'READ' && q.path === HIDDEN,
      );
      expect(reads[0]).toMatchObject({ offset: 0 });
      expect(reads.some((q) => (q.offset ?? 0) > 0)).toBe(true);
      // The lockfile that was pushed does not stand in for a hidden one that was half read.
      expect(r.server.requests.map((q) => q.path ?? '')).not.toContain(
        '/home/vcap/app/package-lock.json',
      );
    }

    it('ends a run of one app with exit code 2, writes nothing and leaves no request to fail unnoticed', async () => {
      const space: Space = {
        apps: [app(1, 'locked-srv', ready(1))],
        folders: { [sshUser(1)]: await largeLockfileApp() },
        dropOnRead: [sshUser(1)],
      };
      const r = await run({ space, args: ['--app', 'locked-srv'], answers: null });
      expect(r.code).toBe(EXIT.error);
      expect(r.err).toContain(
        'The connection to the app closed before the scan finished, so nothing was written. Run the command again.',
      );
      expectLostInFlight(r, sshUser(1));
      expect(r.out).toBe('');
      expect(await readdir(r.outDir)).toEqual([]);
      await new Promise((resolve) => setImmediate(resolve));
      expect(unhandled).toEqual([]);
    });

    it('keeps nothing of that app in a project run, and still reads the next one', async () => {
      const space: Space = {
        apps: [
          app(1, 'acme-lost', { ...ready(1), metadata: deployed('acme', 'acme-lost') }),
          app(2, 'acme-srv', { ...ready(2), metadata: deployed('acme', 'acme-srv') }),
        ],
        folders: { [sshUser(1)]: await largeLockfileApp(), [sshUser(2)]: await containerFixture() },
        dropOnRead: [sshUser(1)],
      };
      const r = await run({ space, args: ['--mta', 'acme'], answers: null });
      expect(r.code, r.err).toBe(EXIT.ok);
      expectLostInFlight(r, sshUser(1));
      const report = await reportOf(r.outDir);
      expect(skippedChecks(report)).toEqual([
        {
          id: 'collect.project.acme-lost',
          title: 'Files of deployed app acme-lost',
          roles: ['SpaceDeveloper'],
          status: 'skipped',
          reasonCode: 'error',
          reason: 'the connection closed before the app was read',
        },
      ]);
      // No package of the half-read lockfile is kept, and none of its budget is spent.
      const projects = await lockedProjects(r.outDir);
      expect(projects.map((p) => p.id)).toEqual(['acme-srv']);
      expect(projects[0]?.dependencies.packages).toEqual(INSTALLED_PACKAGES);
      expect(JSON.stringify(await written(r.outDir))).not.toContain('baip-bulk-lost');
      await new Promise((resolve) => setImmediate(resolve));
      expect(unhandled).toEqual([]);
    });
  });

  describe('when the session is lost at the look for the hidden lockfile', () => {
    /** An app that declares dependencies and has no lockfile: the look is its last request. */
    const unlockedApp = (): Promise<string> => appFolder({ 'package.json': LOCKED_MANIFEST });

    /** The look was sent and never answered, and nothing was asked for after it. */
    function expectLostAtTheLook(r: Run, user: string): void {
      const requests = r.server.requests.filter((q) => q.username === user);
      expect(requests.at(-1)).toMatchObject({ type: 'LSTAT', path: HIDDEN });
      expect(requests.filter((q) => q.type === 'LSTAT' && q.path === HIDDEN)).toHaveLength(1);
    }

    it('ends a run of one app with exit code 2: no answer is not an app without a lockfile', async () => {
      const space: Space = {
        apps: [app(1, 'unlocked-srv', ready(1))],
        folders: { [sshUser(1)]: await unlockedApp() },
        dropOnLstat: [sshUser(1)],
      };
      const r = await run({ space, args: ['--app', 'unlocked-srv'], answers: null });
      expect(r.code).toBe(EXIT.error);
      expect(r.err).toContain(
        'The connection to the app closed before the scan finished, so nothing was written. Run the command again.',
      );
      expectLostAtTheLook(r, sshUser(1));
      expect(r.out).toBe('');
      expect(await readdir(r.outDir)).toEqual([]);

      // The same app with its session intact is read, and is reported as one without a lockfile.
      const read = await run({
        space: { ...space, dropOnLstat: [] },
        args: ['--app', 'unlocked-srv'],
        answers: null,
      });
      expect(read.code, read.err).toBe(EXIT.ok);
      expect((await dependencyFindings(read.outDir)).map((f) => f.id)).toEqual([
        'DEP_LOCKFILE_MISSING',
      ]);
    });

    it('keeps nothing of that app in a project run: a skipped check, not a finding about its lockfile', async () => {
      const space: Space = {
        apps: [
          app(1, 'acme-lost', { ...ready(1), metadata: deployed('acme', 'acme-lost') }),
          app(2, 'acme-srv', { ...ready(2), metadata: deployed('acme', 'acme-srv') }),
        ],
        folders: { [sshUser(1)]: await unlockedApp(), [sshUser(2)]: await containerFixture() },
        dropOnLstat: [sshUser(1)],
      };
      const r = await run({ space, args: ['--mta', 'acme'], answers: null });
      expect(r.code, r.err).toBe(EXIT.ok);
      expectLostAtTheLook(r, sshUser(1));
      const report = await reportOf(r.outDir);
      expect(skippedChecks(report)).toEqual([
        {
          id: 'collect.project.acme-lost',
          title: 'Files of deployed app acme-lost',
          roles: ['SpaceDeveloper'],
          status: 'skipped',
          reasonCode: 'error',
          reason: 'the connection closed before the app was read',
        },
      ]);
      const projects = await lockedProjects(r.outDir);
      expect(projects.map((p) => p.id)).toEqual(['acme-srv']);
      expect((await dependencyFindings(r.outDir)).map((f) => f.id)).not.toContain(
        'DEP_LOCKFILE_MISSING',
      );
    });
  });
});

describe('project option checks', () => {
  const io = (): { io: CliIo; err: () => string } => {
    let err = '';
    return {
      io: { stdout: () => undefined, stderr: (t) => (err += t), env: {}, isTTY: false },
      err: () => err,
    };
  };

  it('refuses --cf together with --path', async () => {
    const c = io();
    expect(await main(['project', '--cf', '--path', '.'], c.io)).toBe(EXIT.error);
    expect(c.err()).toContain(
      'Use either --path (a local folder) or --cf (a deployed app), not both.',
    );
  });

  it('refuses the --cf options without --cf', async () => {
    const c = io();
    expect(await main(['project', '--path', '.', '--app', 'x'], c.io)).toBe(EXIT.error);
    expect(c.err()).toContain('--app works only together with --cf');
  });

  it('refuses --mta together with --app, and --mta-namespace without --mta', async () => {
    const both = io();
    expect(await main(['project', '--cf', '--app', 'x', '--mta', 'acme'], both.io)).toBe(
      EXIT.error,
    );
    expect(both.err()).toContain(
      'Use either --app (one app) or --mta (every app of a project), not both.',
    );
    const alone = io();
    expect(await main(['project', '--cf', '--mta-namespace', 'blue'], alone.io)).toBe(EXIT.error);
    expect(alone.err()).toContain('--mta-namespace works only together with --mta');
  });

  it('refuses the project options without --cf, and a project id that cannot be one', async () => {
    const local = io();
    const args = ['project', '--path', '.', '--mta', 'acme', '--mta-namespace', ''];
    expect(await main(args, local.io)).toBe(EXIT.error);
    expect(local.err()).toContain('--mta works only together with --cf');
    expect(local.err()).toContain('--mta-namespace works only together with --cf');
    const bad = io();
    expect(await main(['project', '--cf', '--mta', 'acme incidents'], bad.io)).toBe(EXIT.error);
    expect(bad.err()).toContain('--mta needs a project id (letters, digits, ".", "_" and "-")');
  });

  it('asks for a cf login when there is none', async () => {
    const c = io();
    c.io.env = { CF_HOME: await mkdtemp(join(tmpdir(), 'baip-lens-nologin-')) };
    expect(await main(['project', '--cf'], c.io)).toBe(EXIT.error);
    expect(c.err()).toContain('No Cloud Foundry login found. Run `cf login`');
  });
});
