import { mkdir, mkdtemp, readFile, readdir, symlink, truncate, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type * as HtmlReporter from '../../src/reporters/html.js';
import { ScriptedPrompter } from '../../src/guided/prompt.js';
import { type CliIo, EXIT, main } from '../../src/main.js';
import { MAX_FILE_BYTES } from '../../src/collectors/project/read.js';
import { FakeFetch, jsonResponse } from '../support/fakeFetch.js';
import {
  type FakeSshServer,
  READ_REQUESTS,
  newHostKey,
  sha256Fingerprint,
  startFakeSsh,
} from '../support/fakeSshServer.js';
import { ABSOLUTE_PATH, expectNoLeaks } from '../support/leak.js';

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
 * serves a fixture folder as /home/vcap/app and records every login, channel
 * and SFTP request. Nothing here reaches a real landscape.
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
const NOW = new Date('2026-09-29T00:00:00.000Z');

/** Values that must never reach the terminal, a report or the snapshot. */
const POISON = [
  ONE_TIME_CODE,
  'POISON_default_env_secret',
  'POISON_dotenv',
  'LeakedThroughLink',
  'POISON_node_modules',
];

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

function appResource(app: { guid: string; name: string }, state: string) {
  return {
    guid: app.guid,
    name: app.name,
    state,
    lifecycle: {
      type: 'buildpack',
      data: { buildpacks: ['nodejs_buildpack'], stack: 'cflinuxfs4' },
    },
  };
}

interface Landscape {
  fingerprint: string;
  sshHref: string;
  /** Roles the user holds in the space (empty: no Space Developer). */
  roles?: string[];
}

function landscape(options: Landscape): FakeFetch {
  const roles = options.roles ?? ['space_developer'];
  const authorizeQuery = 'client_id=ssh-proxy&response_type=code';
  return new FakeFetch()
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
    .on('GET', `${API_HOST}/v3/spaces?names=dev&organization_guids=${ORG_GUID}&per_page=5000`, () =>
      jsonResponse(
        page([
          {
            guid: SPACE_GUID,
            name: 'dev',
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
      jsonResponse(
        page([appResource(DB, 'STOPPED'), appResource(SRV, 'STARTED'), appResource(UI, 'STARTED')]),
      ),
    )
    .on('GET', `${API_HOST}/v3/apps/${SRV.guid}/ssh_enabled`, () =>
      jsonResponse({ enabled: true, reason: '' }),
    )
    .on('GET', `${API_HOST}/v3/apps/${UI.guid}/ssh_enabled`, () =>
      jsonResponse({ enabled: false, reason: 'ssh is disabled for app' }),
    )
    .on('GET', `${API_HOST}/v3/apps/${SRV.guid}/processes/web`, () =>
      jsonResponse({ guid: PROCESS_GUID, type: 'web', instances: 2 }),
    )
    .on('GET', `${API_HOST}/v3/processes/${PROCESS_GUID}/stats`, () =>
      jsonResponse({
        resources: [
          { type: 'web', index: 0, state: 'CRASHED' },
          { type: 'web', index: 1, state: 'RUNNING', host: '10.0.0.7' },
        ],
      }),
    )
    .on(
      'GET',
      `${UAA_HOST}/oauth/authorize?${authorizeQuery}`,
      () =>
        new Response(null, {
          status: 302,
          headers: { location: `https://${UAA_HOST}/login?code=${ONE_TIME_CODE}` },
        }),
    );
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
      dependencies: { '@sap/cds': '^9', '@sap/xssec': '^4' },
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
  await writeFile(join(root, 'outside.cds'), 'service LeakedThroughLink {}');
  await symlink(join(root, 'outside.cds'), join(app, 'srv', 'link.cds'));
  await write('db/data/acme-Big.csv', 'ID;name\n');
  await truncate(join(app, 'db', 'data', 'acme-Big.csv'), MAX_FILE_BYTES + 1);
  return app;
}

async function cfHome(token: string, target = API): Promise<string> {
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
      SpaceFields: { GUID: SPACE_GUID, Name: 'dev', AllowSSH: true },
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

interface RunOptions {
  args?: string[];
  answers?: string[] | null;
  roles?: string[];
  /** The password the SSH server accepts (default: the one-time code UAA hands out). */
  acceptPassword?: string;
  /** Publish the fingerprint of another key in the CF root. */
  wrongHostKey?: boolean;
}

async function run(options: RunOptions = {}): Promise<Run> {
  const appDir = await containerFixture();
  const server = await startFakeSsh({
    appDir,
    username: `cf:${PROCESS_GUID}/1`,
    password: options.acceptPassword ?? ONE_TIME_CODE,
  });
  servers.push(server);
  const fingerprint = options.wrongHostKey
    ? sha256Fingerprint(newHostKey().public)
    : server.fingerprint;
  const fake = landscape({ fingerprint, sshHref: server.href, roles: options.roles });
  const token = accessToken();
  const outDir = await mkdtemp(join(tmpdir(), 'baip-lens-cf-out-'));
  const prompter =
    options.answers === null ? undefined : new ScriptedPrompter(options.answers ?? ['1']);
  let out = '';
  let err = '';
  const io: CliIo = {
    stdout: (t) => (out += t),
    stderr: (t) => (err += t),
    env: { CF_HOME: await cfHome(token) },
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
    expect(r.server.requests.length).toBeGreaterThan(5);
    for (const request of r.server.requests) {
      expect(READ_REQUESTS.has(request.type), request.type).toBe(true);
      if (request.type === 'OPEN') expect(request.flags).toBe('r');
    }
    const touched = r.server.requests.map((q) => q.path ?? '');
    for (const never of ['default-env.json', '/.env', 'node_modules', 'link.cds']) {
      expect(
        touched.some((path) => path.includes(never)),
        never,
      ).toBe(false);
    }
    // The oversized seed file is checked with fstat and never read.
    expect(touched).toContain('/home/vcap/app/db/data/acme-Big.csv');
    expect(
      r.server.requests.some((q) => q.type === 'READ' && q.path?.endsWith('acme-Big.csv')),
    ).toBe(false);

    const report = JSON.parse(await readFile(join(r.outDir, 'baip-lens-report.json'), 'utf8')) as {
      scope: { orgs: string[]; projects: string[]; apiEndpoint?: string };
      checks: { id: string; status: string; roles: string[] }[];
      findings: { id: string }[];
    };
    expect(report.scope).toEqual({ apiEndpoint: `${API}/`, orgs: [], projects: ['incidents-srv'] });
    expect(report.checks.find((c) => c.id === 'collect.project')).toMatchObject({
      status: 'ran',
      roles: ['SpaceDeveloper'],
    });
    const ids = report.findings.map((f) => f.id);
    expect(ids).toContain('CAP_MOCKED_AUTH_IN_PROD');
    expect(ids).toContain('APPROUTER_ROUTE_NO_AUTH');
    expect(r.out).toMatch(/^Scanned deployed app incidents-srv: \d+ finding\(s\)/);

    // The snapshot records the oversized file as unreadable, never its content.
    const snapshotName = (await readdir(r.outDir)).find((f) => f.startsWith('snapshot-')) ?? '';
    const snapshot = JSON.parse(await readFile(join(r.outDir, snapshotName), 'utf8')) as {
      raw: { projects: { files: string[]; unreadable: { file: string; kind: string }[] }[] };
    };
    const project = snapshot.raw.projects[0];
    expect(project?.files).toEqual(['package.json', 'srv/cat-service.cds', 'xs-app.json']);
    expect(project?.unreadable).toEqual([{ file: 'db/data/acme-Big.csv', kind: 'too-large' }]);

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

  it('asks for a cf login when there is none', async () => {
    const c = io();
    c.io.env = { CF_HOME: await mkdtemp(join(tmpdir(), 'baip-lens-nologin-')) };
    expect(await main(['project', '--cf'], c.io)).toBe(EXIT.error);
    expect(c.err()).toContain('No Cloud Foundry login found. Run `cf login`');
  });
});
