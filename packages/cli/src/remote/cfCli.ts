import { spawn } from 'node:child_process';

/*
 * The only changes BAIP Lens ever makes to a landscape, and only for
 * `project --cf` after the user said yes (or passed --enable-ssh): turning SSH
 * on for one app, restarting it so the change takes effect, turning SSH off
 * again, and giving the user the Space Developer role. They are run by the
 * user's own cf CLI, with the user's own cf session and target; BAIP Lens's
 * HTTP client stays GET-only. Nothing else can be run: every command is built
 * here from a fixed shape and checked against the allow-list before spawning.
 */

export type CfCommand =
  | { kind: 'enable-ssh'; app: string }
  | { kind: 'disable-ssh'; app: string }
  | { kind: 'restart'; app: string }
  | { kind: 'set-space-role'; user: string; origin?: string; org: string; space: string };

/** The argv of a command, as given to `cf`. */
export function cfArgs(command: CfCommand): string[] {
  switch (command.kind) {
    case 'enable-ssh':
      return ['enable-ssh', command.app];
    case 'disable-ssh':
      return ['disable-ssh', command.app];
    case 'restart':
      // Rolling: the new instances start before the old ones stop, so the app stays up.
      return ['restart', command.app, '--strategy', 'rolling'];
    case 'set-space-role':
      return [
        'set-space-role',
        command.user,
        command.org,
        command.space,
        'SpaceDeveloper',
        // The identity provider of the user (e.g. sap.ids): a user name alone can be ambiguous.
        ...(command.origin === undefined ? [] : ['--origin', command.origin]),
      ];
  }
}

/** An argument as it can be pasted into a shell. */
export function shellWord(value: string): string {
  return /^[A-Za-z0-9._@:/-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`;
}

/** The command line as the user would type it. */
export function cfCommandLine(command: CfCommand): string {
  return ['cf', ...cfArgs(command).map(shellWord)].join(' ');
}

const ALLOWED: readonly (readonly string[])[] = [
  ['enable-ssh', '*'],
  ['disable-ssh', '*'],
  ['restart', '*', '--strategy', 'rolling'],
  ['set-space-role', '*', '*', '*', 'SpaceDeveloper'],
  ['set-space-role', '*', '*', '*', 'SpaceDeveloper', '--origin', '*'],
];

/** Thrown before spawning for an argv outside the allow-list. */
export class CfCommandDeniedError extends Error {
  override readonly name = 'CfCommandDeniedError';
}

/** Refuses any argv that is not one of the shapes above, or an argument that looks like a flag. */
export function assertAllowedCfArgs(args: readonly string[]): void {
  const ok = ALLOWED.some(
    (shape) =>
      shape.length === args.length &&
      shape.every((part, i) => {
        const arg = args[i] ?? '';
        return part === '*' ? arg.length > 0 && !arg.startsWith('-') : part === arg;
      }),
  );
  if (!ok) throw new CfCommandDeniedError(`cf ${args[0] ?? ''} is not a command BAIP Lens runs.`);
}

export type CfRunResult = { ok: true } | { ok: false; reason: 'not-installed' | 'failed' };

/** Runs one cf command; injected in tests. */
export type RunCf = (command: CfCommand) => Promise<CfRunResult>;

export interface CfRunnerOptions {
  env: NodeJS.ProcessEnv;
  /** Where the cf output goes, line by line (the terminal's stderr). */
  output: (text: string) => void;
}

/**
 * Spawns the cf CLI without a shell, the argv checked first. Its output is
 * passed on as it comes (cf prints app names, routes and instance states,
 * never a token); stdout of BAIP Lens stays for the summary.
 */
export function cfRunner(options: CfRunnerOptions): RunCf {
  return async (command) => {
    const args = cfArgs(command);
    assertAllowedCfArgs(args);
    return await new Promise<CfRunResult>((resolve) => {
      let child;
      try {
        child = spawn('cf', args, {
          env: options.env,
          stdio: ['ignore', 'pipe', 'pipe'],
          windowsHide: true,
        });
      } catch {
        resolve({ ok: false, reason: 'not-installed' });
        return;
      }
      child.stdout.on('data', (chunk: Buffer) => options.output(chunk.toString('utf8')));
      child.stderr.on('data', (chunk: Buffer) => options.output(chunk.toString('utf8')));
      child.once('error', (error: NodeJS.ErrnoException) =>
        resolve({ ok: false, reason: error.code === 'ENOENT' ? 'not-installed' : 'failed' }),
      );
      child.once('close', (code) =>
        resolve(code === 0 ? { ok: true } : { ok: false, reason: 'failed' }),
      );
    });
  };
}
