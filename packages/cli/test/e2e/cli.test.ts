import { mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { type CliIo, EXIT, main } from '../../src/main.js';
import { TOOL_VERSION } from '../../src/version.js';
import { FakeFetch, jsonResponse } from '../support/fakeFetch.js';
import { ACME, ACME_PREVIOUS_PATH, ACME_TRAFFIC_APPS, acmeFetch } from '../support/acme.js';

interface Captured {
  io: CliIo;
  out: () => string;
  err: () => string;
}

function capture(fake = acmeFetch()): Captured {
  let out = '';
  let err = '';
  return {
    io: {
      stdout: (t) => (out += t),
      stderr: (t) => (err += t),
      env: { BAIP_LENS_ACCESS_TOKEN: ACME.token },
      fetch: fake.fetch,
      now: () => ACME.now,
    },
    out: () => out,
    err: () => err,
  };
}

const tmp = () => mkdtemp(join(tmpdir(), 'baip-lens-cli-'));
const scanArgs = (out: string, ...extra: string[]) => [
  'scan',
  '--api',
  'https://api.cf.example.org',
  '--org',
  'acme-prod',
  '--out',
  out,
  '--format',
  'json,csv,sarif',
  ...extra,
];

describe('baip-lens CLI', () => {
  it('scans and writes a snapshot plus the requested reports', async () => {
    const out = await tmp();
    const c = capture();
    expect(await main(scanArgs(out), c.io)).toBe(EXIT.ok);
    expect((await readdir(out)).sort()).toEqual([
      'baip-lens-apps.csv',
      'baip-lens-findings.csv',
      'baip-lens-report.json',
      'baip-lens-report.sarif',
      'snapshot-20260929T000000Z.json',
    ]);
    expect(c.out()).toContain(
      'Scanned 8 app(s) in acme-prod: 6 finding(s) (0 critical, 0 high, 1 medium, 5 low, 0 info)',
    );
    expect(c.err()).toContain('Credentials: BAIP_LENS_ACCESS_TOKEN');
    // SEC-22: the sharing warning is printed once per scan.
    expect(c.out().match(/do not commit them/g)).toHaveLength(1);
  });

  it('passes --traffic-pages and --min-traffic-window to the scan and records them', async () => {
    const out = await tmp();
    const fake = acmeFetch({ fullLogPage: true });
    const args = scanArgs(out, '--traffic-pages', '1', '--min-traffic-window', '48');
    expect(await main(args, capture(fake).io)).toBe(EXIT.ok);
    const snapshot = JSON.parse(
      await readFile(join(out, 'snapshot-20260929T000000Z.json'), 'utf8'),
    ) as { options: unknown; apps: { name: string; usage: unknown }[] };
    expect(snapshot.options).toMatchObject({
      trafficCheck: true,
      trafficPages: 1,
      minTrafficWindowHours: 48,
    });
    // One full page and the cap: no second page and no window-start read for that app,
    // and the 17.7 hours read are less than the 48 asked for.
    const approuter = fake.calls.filter((c) =>
      c.url.pathname.endsWith(ACME_TRAFFIC_APPS['orders-approuter']),
    );
    expect(approuter.map((c) => c.url.searchParams.get('limit'))).toEqual(['1000']);
    expect(snapshot.apps.find((a) => a.name === 'orders-approuter')?.usage).toEqual({
      state: 'unknown',
      reason: 'window_too_short',
    });
  });

  it('asks Log Cache nothing with --no-traffic-check and says the check was turned off', async () => {
    const out = await tmp();
    const fake = acmeFetch();
    const c = capture(fake);
    expect(await main(scanArgs(out, '--no-traffic-check'), c.io)).toBe(EXIT.ok);
    expect(fake.calls.some((call) => call.url.host === ACME.logCache)).toBe(false);
    expect(c.out()).toContain('skipped collect.traffic: turned off with --no-traffic-check');
  });

  it('carries history with --previous, and report --from gives the same results offline', async () => {
    const out = await tmp();
    const c = capture();
    expect(await main(scanArgs(out, '--previous', ACME_PREVIOUS_PATH), c.io)).toBe(EXIT.ok);
    expect(c.err()).toContain('Traffic history carried forward from the scan of 2026-09-22');
    type Report = { findings: { title: string }[]; apps: unknown[] };
    const read = async (dir: string) =>
      JSON.parse(await readFile(join(dir, 'baip-lens-report.json'), 'utf8')) as Report;
    const scanned = await read(out);
    expect(scanned.findings.map((f) => f.title)).toContain(
      'No requests seen across 6 scans over 42 days',
    );

    const again = await tmp();
    const r = capture();
    r.io.fetch = () => Promise.reject(new Error('report --from must not use the network'));
    const snapshot = join(out, 'snapshot-20260929T000000Z.json');
    const args = ['report', '--from', snapshot, '--format', 'json', '--out', again];
    expect(await main(args, r.io)).toBe(EXIT.ok);
    const offline = await read(again);
    expect(offline.findings).toEqual(scanned.findings);
    expect(offline.apps).toEqual(scanned.apps);
  });

  it('exits 2 for a --previous snapshot it cannot use, before any request', async () => {
    const dir = await tmp();
    const other = join(dir, 'other.json');
    const previous = JSON.parse(await readFile(ACME_PREVIOUS_PATH, 'utf8')) as {
      scope: { apiEndpoint: string };
    };
    previous.scope.apiEndpoint = 'https://api.cf.other.example.org/';
    await writeFile(other, JSON.stringify(previous));
    const fake = acmeFetch();
    const c = capture(fake);
    expect(await main(scanArgs(await tmp(), '--previous', other), c.io)).toBe(EXIT.error);
    expect(c.err()).toContain(
      'is of https://api.cf.other.example.org/, not https://api.cf.example.org/',
    );
    expect(fake.calls).toEqual([]);

    // A file that is not a snapshot, one that is missing, one that is not JSON
    // (its content is never quoted back) and a project scan: nothing is sent.
    const unused = acmeFetch();
    const cases: [string, string, string][] = [
      ['broken.json', '{ "schemaVersion": 1 }', 'is not valid'],
      ['missing.json', '', 'Could not read snapshot'],
      ['secret.txt', 'sk_live_51HxQzK9-POISON', 'the file is not valid JSON'],
    ];
    for (const [name, content, message] of cases) {
      const file = join(dir, name);
      if (content !== '') await writeFile(file, content);
      const d = capture(unused);
      expect(await main(scanArgs(await tmp(), '--previous', file), d.io)).toBe(EXIT.error);
      expect(d.err()).toContain(message);
      expect(d.err()).not.toContain('sk_live');
    }
    const project = join(dir, 'project.json');
    const sample = JSON.parse(await readFile(ACME_PREVIOUS_PATH, 'utf8')) as Record<
      string,
      unknown
    >;
    await writeFile(
      project,
      JSON.stringify({ ...sample, scope: { orgs: [], projects: ['acme-incidents'] } }),
    );
    const p = capture(unused);
    expect(await main(scanArgs(await tmp(), '--previous', project), p.io)).toBe(EXIT.error);
    expect(p.err()).toContain('is a project scan');
    expect(unused.calls).toEqual([]);
  });

  it('scans a local project directory without the network and names the project', async () => {
    const project = await tmp();
    await writeFile(join(project, 'package.json'), '{ "name": "acme-incidents" }\n');
    const out = await tmp();
    const c = capture();
    c.io.fetch = () => Promise.reject(new Error('network must not be used'));
    const args = ['project', '--path', project, '--out', out, '--format', 'json'];
    expect(await main(args, c.io)).toBe(EXIT.ok);
    const report = JSON.parse(await readFile(join(out, 'baip-lens-report.json'), 'utf8')) as {
      summary: { apps: number; projects: number };
      scope: { orgs: string[]; projects?: string[]; apiEndpoint?: string };
      apps: { kind: string; guid: string }[];
    };
    expect(report.summary).toMatchObject({ apps: 0, projects: 1 });
    expect(report.scope.orgs).toEqual([]);
    expect(report.scope.apiEndpoint).toBeUndefined();
    expect(report.apps).toMatchObject([
      { kind: 'project', guid: `project:${report.scope.projects?.[0]}` },
    ]);
    expect(c.out()).toMatch(/^Scanned project [A-Za-z0-9._-]+: \d+ finding\(s\) \(/);
    expect(c.out()).toContain('Reports describe your project');
    expect(c.out()).not.toContain('app(s) in');
    expect(c.err()).toMatch(/Read 1 project file\(s\) in project /);
    expect(c.err()).not.toContain(project);
  });

  it('exits 2 when --path is missing', async () => {
    const c = capture();
    expect(await main(['project'], c.io)).toBe(EXIT.error);
    expect(c.err()).toContain("required option '--path <dir>' not specified");
  });

  it('exits 1 when findings meet --fail-on', async () => {
    const out = await tmp();
    expect(await main(scanArgs(out, '--fail-on', 'medium'), capture().io)).toBe(EXIT.findings);
    expect(await main(scanArgs(out, '--fail-on', 'high'), capture().io)).toBe(EXIT.ok);
  });

  it('exits 2 on invalid options', async () => {
    const c = capture();
    expect(await main(scanArgs(await tmp(), '--fail-on', 'severe'), c.io)).toBe(EXIT.error);
    expect(c.err()).toContain('--fail-on must be one of');
    const d = capture();
    expect(await main(['scan', '--api', 'http://api.cf.example.org', '--org', 'x'], d.io)).toBe(
      EXIT.error,
    );
    expect(d.err()).toContain('--api must use https');
  });

  it('exits 2 when a required option is missing', async () => {
    const c = capture();
    expect(await main(['scan', '--api', 'https://api.cf.example.org'], c.io)).toBe(EXIT.error);
    expect(c.err()).toContain("required option '--org <name>' not specified");
  });

  it('exits 2 with a clear message when the org is not visible', async () => {
    const fake = acmeFetch().on(
      'GET',
      'api.cf.example.org/v3/organizations?names=nope&per_page=5000',
      () => jsonResponse({ pagination: { next: null }, resources: [] }),
    );
    const c = capture(fake);
    const args = [
      'scan',
      '--api',
      'https://api.cf.example.org',
      '--org',
      'nope',
      '--out',
      await tmp(),
    ];
    expect(await main(args, c.io)).toBe(EXIT.error);
    expect(c.err()).toContain('Organization "nope" was not found, or your user has no role in it.');
  });

  it('re-analyzes a snapshot offline with `report --from`', async () => {
    const scanOut = await tmp();
    await main(scanArgs(scanOut), capture().io);
    const reportOut = await tmp();
    const noNetwork = capture();
    noNetwork.io.fetch = () => Promise.reject(new Error('network must not be used'));
    const code = await main(
      [
        'report',
        '--from',
        join(scanOut, 'snapshot-20260929T000000Z.json'),
        '--format',
        'json',
        '--out',
        reportOut,
        '--fail-on',
        'low',
      ],
      noNetwork.io,
    );
    expect(code).toBe(EXIT.findings);
    const report = JSON.parse(await readFile(join(reportOut, 'baip-lens-report.json'), 'utf8')) as {
      findings: { id: string; app: { name: string } }[];
      apps: { name: string; usage: unknown }[];
    };
    // Three APP_NO_RECENT_DEPLOY findings and three APP_IDLE ones, recomputed offline.
    expect(report.findings).toHaveLength(6);
    expect(report.findings.filter((f) => f.id === 'APP_IDLE').map((f) => f.app.name)).toEqual([
      'custom-bp-app',
      'legacy-reporting',
      'orders-approuter',
    ]);
    expect(report.apps.find((a) => a.name === 'custom-bp-app')?.usage).toEqual({
      state: 'idle',
      signal: 'no_route',
      confidence: 'high',
    });
  });

  it('exits 2 for an unreadable snapshot', async () => {
    const c = capture();
    expect(await main(['report', '--from', '/nonexistent/snapshot.json'], c.io)).toBe(EXIT.error);
    expect(c.err()).toContain('Could not read snapshot');
  });

  it('without arguments in a script prints help and exits 2, and starts guided mode on a TTY', async () => {
    const script = capture();
    script.io.isTTY = false;
    expect(await main([], script.io)).toBe(EXIT.error);
    expect(script.err()).toContain('guided mode starts when a person is at the terminal');
    expect(script.err()).toContain('Usage:');

    const { ScriptedPrompter } = await import('../../src/guided/prompt.js');
    const tty = capture();
    tty.io.isTTY = true;
    tty.io.cwd = await tmp();
    tty.io.open = null;
    tty.io.env = { CF_HOME: tty.io.cwd, BAIP_LENS_ACCESS_TOKEN: ACME.token };
    tty.io.fetch = acmeFetch().on('GET', 'api.cf.example.org/v3/organizations?per_page=5000', () =>
      jsonResponse({
        pagination: { next: null },
        resources: [{ guid: ACME.orgGuid, name: ACME.org }],
      }),
    ).fetch;
    const prompter = new ScriptedPrompter(['https://api.cf.example.org', 'n']);
    tty.io.prompter = prompter;
    expect(await main([], tty.io)).toBe(EXIT.ok);
    expect(prompter.transcript.join('\n')).toContain('Cancelled. Nothing was written.');
  });

  it('strips terminal escape sequences and token shapes from everything it prints', async () => {
    const fake = acmeFetch().on('GET', /\/v3\/organizations\?.*names=evil/, () =>
      jsonResponse({ pagination: { next: null }, resources: [] }),
    );
    const c = capture(fake);
    const org = 'evil\u001b]0;pwned\u0007';
    expect(await main(['scan', '--api', 'https://api.cf.example.org', '--org', org], c.io)).toBe(
      EXIT.error,
    );
    expect(c.err()).not.toContain('\u001b');
    expect(c.err()).toContain('Organization "evil" was not found');
  });

  it('lists the regions with an example, without any network call', async () => {
    const fake = new FakeFetch();
    const c = capture(fake);
    expect(await main(['regions'], c.io)).toBe(EXIT.ok);
    expect(c.out()).toMatch(/^ {2}eu10 +Europe \(Frankfurt\), AWS$/m);
    expect(c.out()).toMatch(/^ {2}us10-001 +US East \(Virginia\), AWS, extension landscape$/m);
    expect(c.out()).toContain('baip-lens scan --api eu10 --org <name>');
    expect(fake.calls).toEqual([]);
  });

  it('runs doctor against the fixture API', async () => {
    const c = capture();
    c.io.cwd = await tmp();
    c.io.env = { CF_HOME: c.io.cwd };
    expect(await main(['doctor', '--api', 'https://api.cf.example.org'], c.io)).toBe(EXIT.ok);
    expect(c.out()).toContain('OK   Cloud Foundry API: api.cf.example.org answered');
    expect(c.out()).toContain('Everything looks fine.');
  });

  it('prints the version', async () => {
    const c = capture();
    expect(await main(['version'], c.io)).toBe(EXIT.ok);
    expect(c.out()).toBe(`baip-lens ${TOOL_VERSION}\n`);
    const v = capture();
    expect(await main(['--version'], v.io)).toBe(EXIT.ok);
    expect(v.out()).toContain(TOOL_VERSION);
  });
});
