import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ScriptedPrompter } from '../../../src/guided/prompt.js';
import type { CfClient } from '../../../src/http/cfClient.js';
import { CfApiError, CfForbiddenError, ConfigError } from '../../../src/http/errors.js';
import {
  type CfApp,
  CfAppSchema,
  type SelectOptions,
  type Selection,
  selectApps,
  shellName,
  sshOffAdvice,
  sshOffReason,
} from '../../../src/remote/selectApps.js';

/*
 * What `project --cf` decides to read, without a network: the app list is
 * given, and the CF client is a stub that answers each app's SSH status.
 */

const WHERE = { org: 'acme-prod', space: 'dev' };
const md5 = (text: string): string => createHash('md5').update(text, 'utf8').digest('hex');

const guid = (n: number): string => `a0000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

function cfApp(n: number, name: string, mta?: { id: string; namespace?: string }): CfApp {
  const metadata =
    mta === undefined
      ? undefined
      : {
          labels: {
            mta_id: md5(mta.id),
            ...(mta.namespace === undefined ? {} : { mta_namespace: md5(mta.namespace) }),
          },
          annotations: {
            mta_id: mta.id,
            mta_version: '1.0.0',
            ...(mta.namespace === undefined ? {} : { mta_namespace: mta.namespace }),
          },
        };
  return CfAppSchema.parse({ guid: guid(n), name, state: 'STARTED', metadata });
}

/** A CF client that answers `/ssh_enabled` per app GUID and records which apps were asked about. */
function stubCf(answer: (appGuid: string) => { enabled: boolean; reason?: string } = () => ON) {
  const asked: string[] = [];
  const cf = {
    get: (path: string) => {
      const appGuid = path.split('/')[3] ?? '';
      asked.push(appGuid);
      return Promise.resolve(answer(appGuid));
    },
  } as unknown as CfClient;
  return { cf, asked };
}
const ON = { enabled: true };

/** The labels and annotations of an app of the project "acme". */
const MTA = { labels: { mta_id: md5('acme') }, annotations: { mta_id: 'acme' } };

async function refusal(options: SelectOptions, apps: CfApp[], cf = stubCf().cf): Promise<string> {
  const error: unknown = await selectApps(options, cf, apps, WHERE).catch((e: unknown) => e);
  if (error instanceof ConfigError) return error.message;
  throw new Error(`expected a ConfigError, got ${String(error)}`);
}

const appNames = (selection: Selection): string[] =>
  selection.kind === 'app' ? [selection.app.name] : selection.states.map((s) => s.app.name);

describe('choosing a project with --mta', () => {
  const blue = cfApp(1, 'blue-srv', { id: 'acme', namespace: 'blue' });
  const green = cfApp(2, 'green-srv', { id: 'acme', namespace: 'green' });
  const other = cfApp(3, 'billing-srv', { id: 'billing' });

  it('takes the one deployment that carries the id, with or without a namespace', async () => {
    const { cf, asked } = stubCf();
    const selection = await selectApps({ mta: 'acme' }, cf, [blue, other], WHERE);
    expect(selection.kind).toBe('project');
    expect(appNames(selection)).toEqual(['blue-srv']);
    // Only the SSH status of that project's apps is asked for.
    expect(asked).toEqual([guid(1)]);
  });

  it('lists the namespaces when several deployments carry the id, and offers "" only when one has none', async () => {
    expect(await refusal({ mta: 'acme' }, [blue, green, other])).toBe(
      'Project "acme" is deployed 2 times in space "dev" (namespace blue, namespace green). Add --mta-namespace <name>.',
    );
    const bare = cfApp(4, 'acme-srv', { id: 'acme' });
    expect(await refusal({ mta: 'acme' }, [bare, blue, green])).toBe(
      'Project "acme" is deployed 3 times in space "dev" (without a namespace, namespace blue, namespace green). ' +
        'Add --mta-namespace <name>, or --mta-namespace "" for the one without a namespace.',
    );
  });

  it('says what is deployed when the namespace asked for is not', async () => {
    expect(await refusal({ mta: 'acme', mtaNamespace: '' }, [blue, green])).toBe(
      'Project "acme" has no deployment without a namespace in space "dev". Deployments there: namespace blue, namespace green.',
    );
    expect(await refusal({ mta: 'acme', mtaNamespace: 'red' }, [blue])).toBe(
      'Project "acme" has no deployment in namespace "red" in space "dev". Deployments there: namespace blue.',
    );
  });

  it('names each project id once when the id asked for is not there', async () => {
    expect(await refusal({ mta: 'nope' }, [blue, green, other])).toBe(
      'There is no project "nope" in space "dev" of "acme-prod". Projects there: acme, billing.',
    );
    const many = Array.from({ length: 23 }, (_, i) =>
      cfApp(i + 1, `app-${i}`, { id: `project-${String(i).padStart(2, '0')}` }),
    );
    expect(await refusal({ mta: 'nope' }, many)).toMatch(/project-18, project-19 and 3 more\.$/);
  });

  it('gives the reason of every app when none of the project is ready', async () => {
    const { cf } = stubCf(() => ({ enabled: false, reason: 'ssh is disabled globally' }));
    expect(await refusal({ mta: 'acme', mtaNamespace: 'blue' }, [blue, green], cf)).toBe(
      'No app of project "acme" can be read right now: ' +
        'blue-srv: SSH is turned off for the whole platform; only its operator can turn it on.',
    );
  });
});

describe('choosing from the list', () => {
  it('keeps the question about apps when the space has no project', async () => {
    const prompter = new ScriptedPrompter(['2']);
    const apps = [cfApp(1, 'a'), cfApp(2, 'b')];
    const selection = await selectApps({ prompter }, stubCf().cf, apps, WHERE);
    expect(appNames(selection)).toEqual(['b']);
    expect(prompter.transcript).toEqual([
      '',
      'Apps in space "dev" of "acme-prod":',
      'Which app do you want to analyze?',
      '  1) a',
      '  2) b',
      '? Enter a number (1-2)',
    ]);
  });

  it('hands over every app of the chosen project with its readiness, in the order of the list', async () => {
    const apps = [
      cfApp(1, 'acme-db', { id: 'acme' }),
      cfApp(2, 'acme-srv', { id: 'acme' }),
      cfApp(3, 'other'),
    ];
    const { cf } = stubCf((appGuid) =>
      appGuid === guid(1) ? { enabled: false, reason: 'ssh is disabled for app' } : ON,
    );
    const prompter = new ScriptedPrompter(['1']);
    const selection = await selectApps({ prompter }, cf, apps, WHERE);
    expect(selection.kind).toBe('project');
    if (selection.kind !== 'project') return;
    expect(selection.project.id).toBe('acme');
    expect(selection.states.map((s) => [s.app.name, s.readiness.ok])).toEqual([
      ['acme-db', false],
      ['acme-srv', true],
    ]);
    expect(prompter.transcript).toContain('  1) acme 1.0.0 · project, 1 of 2 apps: acme-srv');
  });

  it('names a project over the app limit with its namespace and offers none of its apps', async () => {
    const big = Array.from({ length: 51 }, (_, i) =>
      cfApp(i + 1, `big-${i}`, { id: 'big', namespace: 'blue' }),
    );
    const prompter = new ScriptedPrompter(['1']);
    const selection = await selectApps(
      { prompter },
      stubCf().cf,
      [...big, cfApp(99, 'solo')],
      WHERE,
    );
    expect(appNames(selection)).toEqual(['solo']);
    expect(prompter.transcript).toContain(
      '  - project big (namespace blue): it has 51 apps, more than the 50 one run reads; read one app with --app <name>',
    );
    expect(prompter.transcript.filter((line) => /^\s+\d+\) /.test(line))).toEqual(['  1) solo']);
    // No project is offered, so the question is about apps.
    expect(prompter.transcript).toContain('Which app do you want to analyze?');
  });

  it('counts an app whose SSH status may not be read as readable, and lets other errors through', async () => {
    const url = new URL('https://api.cf.example.org/v3/apps/x/ssh_enabled');
    const forbidden = { get: () => Promise.reject(new CfForbiddenError(403, url)) };
    const selection = await selectApps(
      { app: 'a' },
      forbidden as unknown as CfClient,
      [cfApp(1, 'a')],
      WHERE,
    );
    expect(appNames(selection)).toEqual(['a']);
    const broken = { get: () => Promise.reject(new CfApiError(500, url)) };
    await expect(
      selectApps({ app: 'a' }, broken as unknown as CfClient, [cfApp(1, 'a')], WHERE),
    ).rejects.toBeInstanceOf(CfApiError);
  });
});

describe('naming an app or a space in a cf command', () => {
  /** Names Cloud Foundry accepts (any printable character) that a shell would act on unquoted. */
  const HOSTILE = [
    'x$(echo INJECTED)',
    'x`echo INJECTED`',
    '${HOME}',
    'back\\slash\\',
    "it's",
    "''",
    'say "hi"',
    'a;b|c&d>e<f',
    'star * and ? and ~',
    '!history',
    '%PATH%',
    '#comment',
    'tab\there',
    'naïve—app',
  ];

  it('leaves a plain name as it is, and puts a name with spaces in double quotes', () => {
    expect(shellName('incidents-srv_1.0')).toBe('incidents-srv_1.0');
    expect(shellName('my app')).toBe('"my app"');
    expect(shellName(' padded ')).toBe('" padded "');
  });

  it('puts any other name in single quotes, where a shell expands nothing', () => {
    expect(shellName('x$(touch pwned)')).toBe("'x$(touch pwned)'");
    expect(shellName('x`id`')).toBe("'x`id`'");
    expect(shellName('back\\slash')).toBe("'back\\slash'");
    expect(shellName('say "hi"')).toBe(`'say "hi"'`);
    // A single quote ends the quoted text, is written escaped, and the quoted text goes on.
    expect(shellName("it's")).toBe("'it'\\''s'");
    expect(shellName('my app (blue)')).toBe("'my app (blue)'");
    for (const name of HOSTILE) {
      // Never double quotes around anything a shell expands inside them.
      expect(shellName(name), name).not.toMatch(/^"/);
    }
  });

  it.skipIf(process.platform === 'win32')(
    'gives a POSIX shell the name back as one word, whatever it holds',
    () => {
      for (const name of [...HOSTILE, 'plain', 'my app', '  two  spaces  ', 'my app (blue)']) {
        const seen = execFileSync('sh', ['-c', `printf '%s|' start ${shellName(name)} end`], {
          encoding: 'utf8',
        });
        expect(seen, name).toBe(`start|${name}|end|`);
      }
    },
  );

  it('quotes the names in the advice for an app with SSH off', () => {
    expect(sshOffAdvice('ssh is disabled for app', 'x$(id)', 'dev')).toBe(
      "SSH is off for this app: turn it on with `cf enable-ssh 'x$(id)'`, then `cf restart 'x$(id)'`",
    );
    expect(sshOffAdvice("ssh is disabled for space 'a`b`'", 'app', 'a`b`')).toBe(
      'SSH is off for space "a`b`": a Space Manager can turn it on with `cf allow-space-ssh \'a`b`\'`',
    );
  });
});

describe('why an app cannot be read', () => {
  it('has a fixed reason for the record: no name, no command and nothing of the text CF gives', () => {
    expect(sshOffReason('ssh is disabled globally')).toBe(
      'SSH is turned off for the whole platform; only its operator can turn it on',
    );
    expect(sshOffReason("ssh is disabled for space 'dev POISON'")).toBe('SSH is off for its space');
    expect(sshOffReason('ssh is disabled for app')).toBe('SSH is off for this app');
    expect(sshOffReason('POISON: something new')).toBe('SSH is off for this app');
    expect(sshOffReason('')).toBe('SSH is off for this app');
    // The phrase decides, not a name CF puts after it.
    expect(sshOffReason("ssh is disabled for space 'globally'")).toBe('SSH is off for its space');
    // A space named after another phrase: the first phrase of the reason still decides.
    for (const space of ['x disabled globally', 'ssh is disabled for app', 'DISABLED GLOBALLY']) {
      const reason = `ssh is disabled for space '${space}'`;
      expect(sshOffReason(reason), space).toBe('SSH is off for its space');
      expect(sshOffAdvice(reason, 'app', space), space).toContain('cf allow-space-ssh');
    }
  });

  it('hands over the fixed reason next to the words for the terminal, for every kind of app that is not ready', async () => {
    const hostile = 'x$(id) `id`';
    const apps = [
      CfAppSchema.parse({ guid: guid(1), name: hostile, state: 'STOPPED', metadata: MTA }),
      CfAppSchema.parse({
        guid: guid(2),
        name: 'acme-job',
        state: 'STARTED',
        lifecycle: { type: 'docker' },
        metadata: MTA,
      }),
      CfAppSchema.parse({ guid: guid(3), name: 'acme-spaceoff', state: 'STARTED', metadata: MTA }),
      CfAppSchema.parse({ guid: guid(4), name: 'acme-appoff', state: 'STARTED', metadata: MTA }),
      CfAppSchema.parse({ guid: guid(5), name: 'acme-srv', state: 'STARTED', metadata: MTA }),
    ];
    const { cf } = stubCf((appGuid) => {
      if (appGuid === guid(3)) return { enabled: false, reason: "ssh is disabled for space 'dev'" };
      if (appGuid === guid(4)) return { enabled: false, reason: 'ssh is disabled for app' };
      return ON;
    });
    const selection = await selectApps({ mta: 'acme' }, cf, apps, WHERE);
    if (selection.kind !== 'project') throw new Error('expected a project');
    expect(selection.states.map((state) => state.readiness)).toEqual([
      {
        ok: false,
        reason: 'it is stopped',
        why: "it is stopped: start it with `cf start 'x$(id) `id`'`",
      },
      {
        ok: false,
        reason: 'it runs a Docker image, which has no buildpack app folder to read',
        why: 'it runs a Docker image, which has no buildpack app folder to read',
      },
      {
        ok: false,
        reason: 'SSH is off for its space',
        why: 'SSH is off for space "dev": a Space Manager can turn it on with `cf allow-space-ssh dev`',
      },
      {
        ok: false,
        reason: 'SSH is off for this app',
        why: 'SSH is off for this app: turn it on with `cf enable-ssh acme-appoff`, then `cf restart acme-appoff`',
      },
      { ok: true },
    ]);
    for (const { readiness } of selection.states) {
      if (readiness.ok) continue;
      expect(readiness.reason).not.toMatch(/acme|dev|`|\$|"/);
    }
  });
});
