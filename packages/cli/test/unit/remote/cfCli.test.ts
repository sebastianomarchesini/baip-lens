import { mkdtemp, writeFile, chmod, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  CfCommandDeniedError,
  assertAllowedCfArgs,
  cfArgs,
  cfCommandLine,
  cfRunner,
} from '../../../src/remote/cfCli.js';

describe('cf CLI commands BAIP Lens may run', () => {
  it('builds the four commands with fixed shapes', () => {
    expect(cfArgs({ kind: 'enable-ssh', app: 'srv' })).toEqual(['enable-ssh', 'srv']);
    expect(cfArgs({ kind: 'disable-ssh', app: 'srv' })).toEqual(['disable-ssh', 'srv']);
    expect(cfArgs({ kind: 'restart', app: 'srv' })).toEqual([
      'restart',
      'srv',
      '--strategy',
      'rolling',
    ]);
    expect(
      cfArgs({
        kind: 'set-space-role',
        user: 'me@example.org',
        origin: 'sap.ids',
        org: 'o',
        space: 's',
      }),
    ).toEqual([
      'set-space-role',
      'me@example.org',
      'o',
      's',
      'SpaceDeveloper',
      '--origin',
      'sap.ids',
    ]);
  });

  it('refuses any other cf command, role or extra flag before spawning', () => {
    const denied = [
      ['delete', 'srv'],
      ['ssh', 'srv'],
      ['restart', 'srv'],
      ['restart', 'srv', '--strategy', 'rolling', '--no-wait'],
      ['set-space-role', 'me', 'o', 's', 'SpaceManager'],
      ['set-org-role', 'me', 'o', 'OrgManager'],
      ['enable-ssh', '-f'],
      ['enable-ssh', ''],
      ['enable-ssh', 'a', 'b'],
      [],
    ];
    for (const args of denied) {
      expect(() => assertAllowedCfArgs(args), args.join(' ')).toThrow(CfCommandDeniedError);
    }
    expect(() => assertAllowedCfArgs(['enable-ssh', 'srv'])).not.toThrow();
  });

  it('never lets an app name become a flag', async () => {
    const run = cfRunner({ env: { PATH: '/nonexistent' }, output: () => {} });
    await expect(run({ kind: 'enable-ssh', app: '--help' })).rejects.toThrow(CfCommandDeniedError);
  });

  it('quotes names for the command shown to the user', () => {
    expect(cfCommandLine({ kind: 'enable-ssh', app: 'my app' })).toBe("cf enable-ssh 'my app'");
    expect(cfCommandLine({ kind: 'enable-ssh', app: "it's" })).toBe(`cf enable-ssh 'it'\\''s'`);
  });

  it('runs cf without a shell and reports a missing cf CLI', async () => {
    const run = cfRunner({ env: { PATH: '/nonexistent' }, output: () => {} });
    expect(await run({ kind: 'enable-ssh', app: 'srv' })).toEqual({
      ok: false,
      reason: 'not-installed',
    });
  });

  it.skipIf(process.platform === 'win32')('passes the exact argv and the output on', async () => {
    const bin = await mkdtemp(join(tmpdir(), 'baip-lens-cfbin-'));
    const log = join(bin, 'argv.txt');
    await writeFile(
      join(bin, 'cf'),
      `#!/bin/sh\nprintf '%s\\n' "$@" > '${log}'\necho "OK from cf"\n[ "$1" = restart ] && exit 1\nexit 0\n`,
    );
    await chmod(join(bin, 'cf'), 0o755);
    let output = '';
    const run = cfRunner({ env: { PATH: bin }, output: (t) => (output += t) });
    expect(await run({ kind: 'enable-ssh', app: 'a;rm -rf x' })).toEqual({ ok: true });
    expect(await readFile(log, 'utf8')).toBe('enable-ssh\na;rm -rf x\n');
    expect(output).toContain('OK from cf');
    expect(await run({ kind: 'restart', app: 'a' })).toEqual({ ok: false, reason: 'failed' });
  });
});
