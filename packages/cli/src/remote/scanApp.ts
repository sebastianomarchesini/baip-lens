import { z } from 'zod';
import { COLLECTOR_CHECKS } from '../checks.js';
import { listSpaces, resolveOrg } from '../collectors/orgs.js';
import { PROJECT_MARKERS, collectProjectTree } from '../collectors/project/index.js';
import { parseApiUrl } from '../config.js';
import { type Prompter, WizardCancelled } from '../guided/prompt.js';
import {
  type CfCliConfig,
  type TokenProvider,
  cfConfigPath,
  cfTargetNames,
  readCfCliConfig,
  resolveTokenProvider,
  sameEndpoint,
  tokenUser,
} from '../http/auth.js';
import { CfClient } from '../http/cfClient.js';
import { CfForbiddenError, CfNotFoundError, ConfigError } from '../http/errors.js';
import { type FetchLike, HttpClient } from '../http/httpClient.js';
import type { Snapshot } from '../model/snapshot.js';
import {
  EgressPolicy,
  type SshEndpoint,
  cfApiRule,
  sshEndpointFromRoot,
  uaaSshCodeRule,
} from '../net/allowlist.js';
import { projectSnapshot } from '../project.js';
import { trustRootLinks } from '../scan.js';
import { TOOL_NAME, TOOL_VERSION } from '../version.js';
import { type CfCommand, type RunCf, cfCommandLine, cfRunner, shellWord } from './cfCli.js';
import { fingerprintFormat } from './hostKey.js';
import { type SshConnect, SshConnectError, type SshSession, connectSsh } from './session.js';
import { APP_ROOT, SftpProjectTree } from './sftpTree.js';
import { DEFAULT_SSH_OAUTH_CLIENT, requestSshCode } from './sshCode.js';

/*
 * `baip-lens project --cf`: the project rules on a deployed app, read live.
 * The cf CLI login and target are reused; the user picks an app from the
 * targeted space (or names it with --app); one read-only SFTP session is
 * opened on one running instance, as `cf ssh` would open it; the files are
 * walked and read in memory with the same allow-list and limits as a local
 * project; the session is closed. Nothing is written to disk but the reports.
 *
 * CF calls are GET only (apps, the app's SSH status, its web process and the
 * process stats), plus the one-time SSH code from UAA (`cf ssh-code`). SSH
 * needs the Space Developer role, and Cloud Foundry records every session as
 * an `audit.app.ssh-authorized` event; the command says so before it starts.
 *
 * Two things can be fixed on the way, each only after a yes at the terminal
 * (or --enable-ssh for the first): SSH turned off for the app (`cf enable-ssh`
 * and a rolling `cf restart`, then `cf disable-ssh` once the scan is over),
 * and a missing Space Developer role for a user who is a Space or Org Manager
 * (`cf set-space-role`). Both run through the user's own cf CLI (cfCli.ts);
 * the HTTP client of BAIP Lens never sends anything but GET.
 */

export interface ScanAppOptions {
  /** --api; default: the cf CLI target. */
  apiUrl?: URL;
  /** --org; default: the cf CLI target. */
  org?: string;
  /** --space; default: the cf CLI target. */
  space?: string;
  /** --app: read this app without asking. */
  app?: string;
  env: NodeJS.ProcessEnv;
  /** Asks which app to read, and for consent; absent when nobody is at the terminal. */
  prompter?: Prompter;
  /** --enable-ssh: turn SSH on for the app (and off again after) without asking. */
  enableSsh?: boolean;
  /** Runs the cf CLI; injected in tests. */
  runCf?: RunCf;
  /** Called once SSH was turned on, with the step that turns it off again (for Ctrl+C). */
  onRestore?: (restore: () => Promise<void>) => void;
  /** Injected in tests. */
  fetch?: FetchLike;
  /** Injected in tests. */
  sshConnect?: SshConnect;
  now?: () => Date;
  /** Progress and notices, one line each. */
  log?: (message: string) => void;
}

const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

const CfAppSchema = z.object({
  guid: z.string().regex(GUID),
  name: z.string().min(1),
  state: z.string(),
  lifecycle: z.object({ type: z.string() }).nullish(),
});
type CfApp = z.infer<typeof CfAppSchema>;

const SshEnabledSchema = z.object({ enabled: z.boolean(), reason: z.string().nullish() });
const ProcessSchema = z.object({ guid: z.string().regex(GUID) });
const StatsSchema = z.object({ resources: z.array(z.unknown()) });
const InstanceSchema = z.object({ index: z.number().int().nonnegative(), state: z.string() });

/** How many app names an error lists before it says "and N more". */
const MAX_NAMES_LISTED = 20;

export const SSH_NOTICE =
  "Reads the app's files over a read-only SSH session (as `cf ssh` does); " +
  'Cloud Foundry records it as an audit event (audit.app.ssh-authorized).';

/** An app, org or space name as it can be pasted after a cf command. */
const shellName = shellWord;

function nameList(names: readonly string[]): string {
  const shown = names.slice(0, MAX_NAMES_LISTED);
  const more = names.length - shown.length;
  return `${shown.join(', ')}${more > 0 ? ` and ${more} more` : ''}`;
}

/** Where SSH is turned off, by the reason CF gives (`AppSshStatusPresenter`). */
export function sshOffScope(reason: string): 'platform' | 'space' | 'app' | 'unknown' {
  // The phrases come before any name CF puts into the reason, so a name cannot steer the match.
  const lower = reason.toLowerCase();
  if (/\bdisabled globally\b/.test(lower)) return 'platform';
  if (/\bdisabled for space\b/.test(lower)) return 'space';
  if (/\bdisabled for app\b/.test(lower)) return 'app';
  return 'unknown';
}

/**
 * Whether an app can be read: now, after turning SSH on for it (the one case
 * BAIP Lens can fix, with the user's consent), or not at all, grouped by a
 * reason shared by several apps and the cf command that would change it.
 */
type Readiness =
  { kind: 'ready' } | { kind: 'ssh-off' } | { kind: 'blocked'; reason: string; fix?: string };

function blockedReasons(
  space: string,
): Record<
  'docker' | 'stopped' | 'platform' | 'space' | 'unknown',
  { reason: string; fix?: string }
> {
  return {
    docker: { reason: `runs a Docker image, whose files are not in ${APP_ROOT}` },
    stopped: { reason: 'stopped', fix: 'cf start <app>' },
    platform: {
      reason: 'SSH is turned off for the whole platform; only its operator can turn it on',
    },
    space: {
      reason: `SSH is off for space "${space}"`,
      fix: `a Space Manager can run \`cf allow-space-ssh ${shellName(space)}\``,
    },
    unknown: { reason: 'SSH is off for this app' },
  };
}

async function readiness(cf: CfClient, app: CfApp, space: string): Promise<Readiness> {
  const reasons = blockedReasons(space);
  if (app.lifecycle?.type === 'docker') return { kind: 'blocked', ...reasons.docker };
  if (app.state !== 'STARTED') return { kind: 'blocked', ...reasons.stopped };
  try {
    const status = await cf.get(
      `/v3/apps/${encodeURIComponent(app.guid)}/ssh_enabled`,
      SshEnabledSchema,
    );
    if (!status.enabled) {
      const scope = sshOffScope(status.reason ?? '');
      return scope === 'app' ? { kind: 'ssh-off' } : { kind: 'blocked', ...reasons[scope] };
    }
  } catch (error) {
    // Unknown is not "off": the SSH login will tell.
    if (!(error instanceof CfForbiddenError || error instanceof CfNotFoundError)) throw error;
  }
  return { kind: 'ready' };
}

function blockedMessage(app: string, ready: { reason: string; fix?: string }): string {
  const fix = ready.fix?.replace('<app>', shellName(app));
  return `App "${app}" cannot be read: ${ready.reason}${fix ? ` (${fix})` : ''}.`;
}

interface Session {
  cf: CfClient;
  http: HttpClient;
  tokens: TokenProvider;
  apiUrl: URL;
  uaa: URL;
  ssh: SshEndpoint;
  oauthClient: string;
}

function toUrl(href: string | null | undefined): URL | undefined {
  if (!href) return undefined;
  try {
    return new URL(href);
  } catch {
    return undefined;
  }
}

async function connectToApi(
  options: ScanAppOptions,
  config: CfCliConfig | undefined,
  log: (m: string) => void,
): Promise<Session> {
  let apiUrl = options.apiUrl;
  if (apiUrl === undefined) {
    if (!config?.Target) {
      throw new ConfigError(
        'No Cloud Foundry login found. Run `cf login` (or `cf login --sso`) first, or pass --api.',
      );
    }
    apiUrl = parseApiUrl(config.Target);
  }

  const policy = new EgressPolicy();
  policy.add(cfApiRule(apiUrl));
  const http = new HttpClient({
    policy,
    userAgent: `${TOOL_NAME}/${TOOL_VERSION}`,
    fetch: options.fetch,
  });
  const cf = new CfClient(http, apiUrl);
  log(`Connecting to ${apiUrl.origin}`);
  const root = await cf.root();
  const tokenUrl = trustRootLinks(policy, root);

  // The one-time SSH code comes from UAA, as `cf ssh-code` gets it (links.uaa).
  const uaa = toUrl(root.links.uaa?.href);
  if (uaa === undefined || uaa.protocol !== 'https:') {
    throw new ConfigError(
      'This CF API does not advertise a UAA server, so no SSH session can be opened.',
    );
  }
  policy.add(uaaSshCodeRule(uaa));
  const appSsh = root.links.app_ssh;
  const ssh = sshEndpointFromRoot(appSsh?.href, appSsh?.meta?.host_key_fingerprint ?? undefined);
  if (ssh === null) {
    throw new ConfigError(
      'This CF API does not offer app SSH with a published host key fingerprint, so deployed apps cannot be read. Scan the project folder with --path instead.',
    );
  }
  if (fingerprintFormat(ssh.hostKeyFingerprint) === null) {
    throw new ConfigError(
      'The CF API published the SSH host key fingerprint in a format BAIP Lens does not know, so the connection could not be verified. Nothing was read.',
    );
  }

  const tokens = await resolveTokenProvider({ env: options.env, http, apiUrl, tokenUrl });
  cf.setTokenProvider(tokens);
  log(`Credentials: ${tokens.source}`);
  return {
    cf,
    http,
    tokens,
    apiUrl,
    uaa,
    ssh,
    oauthClient: appSsh?.meta?.oauth_client || DEFAULT_SSH_OAUTH_CLIENT,
  };
}

interface Where {
  org: string;
  space: string;
  /** Whether the cf CLI targets this API, org and space, so its commands act on the same app. */
  cfTargeted: boolean;
  /** Whether the cf CLI is logged in to this API (for commands that name org and space). */
  cfSameApi: boolean;
}

/** The org and space from the flags, else from `cf target` when it points at the same API. */
function targetNames(options: ScanAppOptions, config: CfCliConfig | undefined, apiUrl: URL): Where {
  const cfSameApi = config !== undefined && sameEndpoint(config.Target, apiUrl);
  const target: { org?: string; space?: string } = cfSameApi ? cfTargetNames(config) : {};
  const org = options.org ?? target.org;
  const space = options.space ?? target.space;
  if (org === undefined || space === undefined) {
    throw new ConfigError(
      'No org and space are targeted. Run `cf target -o <org> -s <space>`, or pass --org and --space.',
    );
  }
  return {
    org,
    space,
    cfSameApi,
    cfTargeted: cfSameApi && target.org === org && target.space === space,
  };
}

const RoleSchema = z.object({ type: z.string() });

async function holdsRole(
  cf: CfClient,
  query: Record<string, string>,
  type: string,
): Promise<boolean | undefined> {
  try {
    const { resources } = await cf.list('/v3/roles', RoleSchema, { types: type, ...query });
    return resources.some((role) => role.type === type);
  } catch (error) {
    if (error instanceof CfForbiddenError || error instanceof CfNotFoundError) return undefined;
    throw error;
  }
}

/**
 * Whether the signed-in user holds Space Developer in the space: true, false,
 * or undefined when that cannot be told (no user id in the token, or the
 * roles list could not be read). Admins (`cloud_controller.admin`) may SSH
 * without a space role. Asked before any SSH attempt, because a refused
 * attempt is recorded as `audit.app.ssh-unauthorized`.
 */
async function hasSpaceDeveloper(
  cf: CfClient,
  tokens: TokenProvider,
  spaceGuid: string,
): Promise<boolean | undefined> {
  const user = tokenUser(await tokens.getToken());
  if (user.scopes.includes('cloud_controller.admin')) return true;
  if (user.userId === undefined) return undefined;
  return holdsRole(cf, { space_guids: spaceGuid, user_guids: user.userId }, 'space_developer');
}

/** Whether the user may give roles in the space: Space Manager there, or Org Manager of the org. */
async function canAssignRoles(
  cf: CfClient,
  userId: string,
  orgGuid: string,
  spaceGuid: string,
): Promise<boolean> {
  if (
    (await holdsRole(cf, { space_guids: spaceGuid, user_guids: userId }, 'space_manager')) === true
  ) {
    return true;
  }
  return (
    (await holdsRole(
      cf,
      { organization_guids: orgGuid, user_guids: userId },
      'organization_manager',
    )) === true
  );
}

/**
 * The user lacks Space Developer. A Space or Org Manager is offered to give it
 * to themselves with the cf CLI; anyone else gets the command for a manager.
 * Returns when the role is now held; throws otherwise.
 */
async function ensureSpaceDeveloper(
  options: ScanAppOptions,
  session: Session,
  where: Where,
  ids: { org: string; space: string },
  log: (m: string) => void,
): Promise<void> {
  const user = tokenUser(await session.tokens.getToken());
  const missing =
    `You do not have the Space Developer role in space "${where.space}" of "${where.org}", ` +
    'which reading an app over SSH needs (Space Auditor is not enough).';
  if (user.userName === undefined || user.userId === undefined) {
    throw new ConfigError(
      `${missing} Ask a Space Manager for the role, or scan the project folder with --path instead.`,
    );
  }
  const command: CfCommand = {
    kind: 'set-space-role',
    user: user.userName,
    ...(user.origin === undefined || user.origin === 'uaa' ? {} : { origin: user.origin }),
    org: where.org,
    space: where.space,
  };
  const line = cfCommandLine(command);
  const p = options.prompter;
  const canAssign =
    p !== undefined &&
    where.cfSameApi &&
    (await canAssignRoles(session.cf, user.userId, ids.org, ids.space));
  if (!canAssign) {
    throw new ConfigError(
      `${missing} A Space Manager of "${where.space}" or an Org Manager of "${where.org}" can give it to you with:\n  ${line}`,
    );
  }
  p.say(missing);
  p.say('You are a manager here, so you can give it to yourself. BAIP Lens would run:');
  p.say(`  ${line}`);
  if (!(await p.confirm('Give yourself the Space Developer role now?', false))) {
    throw new WizardCancelled();
  }
  const result = await runCf(options)(command);
  if (!result.ok) throw new ConfigError(cfFailure(result.reason, line));
  if ((await hasSpaceDeveloper(session.cf, session.tokens, ids.space)) === false) {
    throw new ConfigError(
      `The role was given but Cloud Foundry does not show it yet. Try again in a minute.`,
    );
  }
  log(`You now have the Space Developer role in space "${where.space}".`);
}

function runCf(options: ScanAppOptions): RunCf {
  return options.runCf ?? cfRunner({ env: options.env, output: options.log ?? (() => {}) });
}

function cfFailure(reason: 'not-installed' | 'failed', line: string): string {
  return reason === 'not-installed'
    ? `The cf CLI was not found, so this could not be run: ${line}. Install the cf CLI, or run the command elsewhere and try again.`
    : `\`${line}\` did not succeed (its output is above). Nothing else was changed.`;
}

interface Choice {
  app: CfApp;
  /** SSH is off for this app only: BAIP Lens can turn it on with the user's consent. */
  sshOff: boolean;
}

async function chooseApp(
  options: ScanAppOptions,
  cf: CfClient,
  apps: CfApp[],
  where: Where,
): Promise<Choice> {
  if (options.app !== undefined) {
    const app = apps.find((a) => a.name === options.app);
    if (app === undefined) {
      throw new ConfigError(
        `There is no app named "${options.app}" in space "${where.space}" of "${where.org}". Apps there: ${nameList(apps.map((a) => a.name))}.`,
      );
    }
    const state = await readiness(cf, app, where.space);
    if (state.kind === 'blocked') throw new ConfigError(blockedMessage(app.name, state));
    return { app, sshOff: state.kind === 'ssh-off' };
  }
  const p = options.prompter;
  if (p === undefined) {
    throw new ConfigError(
      'Name the app with --app <name>: the list of apps to pick from needs a terminal.',
    );
  }
  const states = await Promise.all(
    apps.map(async (app) => ({ app, state: await readiness(cf, app, where.space) })),
  );
  const choices: Choice[] = states.flatMap(({ app, state }) =>
    state.kind === 'blocked' ? [] : [{ app, sshOff: state.kind === 'ssh-off' }],
  );
  // One line per reason, however many apps share it.
  const blocked = new Map<string, { fix?: string; names: string[] }>();
  for (const { app, state } of states) {
    if (state.kind !== 'blocked') continue;
    const group = blocked.get(state.reason) ?? { fix: state.fix, names: [] };
    group.names.push(app.name);
    blocked.set(state.reason, group);
  }

  p.say('');
  p.say(`Apps in space "${where.space}" of "${where.org}":`);
  if (blocked.size > 0) {
    p.say('Cannot be read:');
    for (const [reason, group] of blocked) {
      p.say(`  - ${reason}: ${nameList(group.names)}${group.fix ? ` (${group.fix})` : ''}`);
    }
  }
  if (choices.length === 0) {
    throw new ConfigError(
      `None of the ${apps.length} app(s) in space "${where.space}" can be read right now (reasons above).`,
    );
  }
  const label = (c: Choice): string =>
    c.sshOff ? `${c.app.name}  (SSH off: BAIP Lens turns it on for the scan)` : c.app.name;
  const [only] = choices;
  if (choices.length === 1 && only !== undefined) {
    p.say(`Only one app can be read: ${label(only)}`);
    return only;
  }
  const index = await p.choose('Which app do you want to analyze?', choices.map(label), 0);
  const choice = choices[index];
  if (choice === undefined) throw new ConfigError('No app was chosen.');
  return choice;
}

/**
 * Turns SSH on for one app with the user's cf CLI and restarts it (rolling),
 * after consent: the --enable-ssh flag, or a yes at the terminal. Returns the
 * step that turns SSH off again, which the caller runs when the scan is over.
 */
async function enableSsh(
  options: ScanAppOptions,
  app: CfApp,
  where: Where,
  log: (m: string) => void,
): Promise<() => Promise<void>> {
  const enable: CfCommand = { kind: 'enable-ssh', app: app.name };
  const restart: CfCommand = { kind: 'restart', app: app.name };
  const disable: CfCommand = { kind: 'disable-ssh', app: app.name };
  const plan = [
    `  ${cfCommandLine(enable)}`,
    `  ${cfCommandLine(restart)}   (new instances start before the old ones stop)`,
    `  ${cfCommandLine(disable)}   (after the scan; needs no restart)`,
  ];
  if (!where.cfTargeted) {
    throw new ConfigError(
      `SSH is off for "${app.name}". BAIP Lens turns it on with your cf CLI, but the cf CLI targets another org or space. ` +
        `Run \`cf target -o ${shellName(where.org)} -s ${shellName(where.space)}\` and try again.`,
    );
  }
  const p = options.prompter;
  if (options.enableSsh !== true) {
    if (p === undefined) {
      throw new ConfigError(
        `App "${app.name}" cannot be read: SSH is off for it. Pass --enable-ssh to let BAIP Lens run, with your cf CLI:\n${plan.join('\n')}`,
      );
    }
    p.say(`SSH is off for "${app.name}". To read it, BAIP Lens will run with your cf CLI:`);
    for (const step of plan) p.say(step);
    p.say("The restart runs the app's start command again; check that this is fine for this app.");
    if (!(await p.confirm('Turn SSH on and restart the app?', false))) throw new WizardCancelled();
  } else {
    log(`SSH is off for "${app.name}": --enable-ssh given, running with your cf CLI:`);
    for (const step of plan) log(step);
  }

  const run = runCf(options);
  const enabled = await run(enable);
  if (!enabled.ok) throw new ConfigError(cfFailure(enabled.reason, cfCommandLine(enable)));
  let restored = false;
  const restore = async (): Promise<void> => {
    if (restored) return;
    restored = true;
    const result = await run(disable);
    if (result.ok) log(`SSH is off again for "${app.name}".`);
    else
      log(
        `Warning: SSH is still on for "${app.name}". Turn it off with \`${cfCommandLine(disable)}\`.`,
      );
  };
  options.onRestore?.(restore);
  const restarted = await run(restart);
  if (!restarted.ok) {
    await restore();
    throw new ConfigError(cfFailure(restarted.reason, cfCommandLine(restart)));
  }
  return restore;
}

/** The lowest-numbered running instance of the app's web process, and the process GUID. */
async function runningInstance(
  cf: CfClient,
  app: CfApp,
): Promise<{ process: string; index: number }> {
  let process: string;
  try {
    ({ guid: process } = await cf.get(
      `/v3/apps/${encodeURIComponent(app.guid)}/processes/web`,
      ProcessSchema,
    ));
  } catch (error) {
    if (error instanceof CfNotFoundError) {
      throw new ConfigError(
        `App "${app.name}" has no web process, so there is no instance to read.`,
      );
    }
    throw error;
  }
  const stats = await cf.get(`/v3/processes/${encodeURIComponent(process)}/stats`, StatsSchema);
  const running = stats.resources
    .map((item) => InstanceSchema.safeParse(item))
    .flatMap((parsed) =>
      parsed.success && parsed.data.state === 'RUNNING' ? [parsed.data.index] : [],
    )
    .sort((a, b) => a - b);
  const index = running[0];
  if (index === undefined) {
    throw new ConfigError(
      `No instance of "${app.name}" is running right now, so its files cannot be read. Check it with \`cf app ${shellName(app.name)}\`.`,
    );
  }
  return { process, index };
}

/** One sentence on what went wrong with the SSH connection, one on what to do; never server text. */
export function explainSshFailure(
  error: SshConnectError,
  ssh: SshEndpoint,
  app: string,
  space: string,
): string {
  const address = `${ssh.host}:${ssh.port}`;
  const network =
    `Company networks often block SSH (port ${ssh.port}), and HTTPS proxies do not carry it. ` +
    'Try from another network, ask IT to allow this address, or scan the project folder with --path instead.';
  switch (error.failure) {
    case 'auth':
      return (
        `The SSH login to "${app}" was refused. Reading a deployed app needs the Space Developer role in space "${space}" ` +
        '(Space Auditor is not enough). Ask a Space Manager for the role, or scan the project folder with --path instead.'
      );
    case 'host-key':
      return (
        `The SSH server at ${address} did not present the host key the CF API published, so the connection was stopped before signing in. ` +
        'Nothing was read. If this keeps happening, tell your platform team.'
      );
    case 'unreachable':
      return `${address} could not be reached${error.code ? ` (${error.code})` : ''}. ${network}`;
    case 'timeout':
      return `${address} did not complete the SSH handshake in time. ${network}`;
    case 'sftp-refused':
      return `The SSH server at ${address} refused the read-only file channel (SFTP), so the files of "${app}" cannot be read.`;
    case 'other':
      return `The SSH connection to ${address} failed. Try again in a minute; if it keeps failing, scan the project folder with --path instead.`;
  }
}

async function openSession(
  options: ScanAppOptions,
  session: Session,
  app: CfApp,
  instance: { process: string; index: number },
  space: string,
): Promise<SshSession> {
  const password = await requestSshCode(
    session.http,
    session.uaa,
    session.oauthClient,
    session.tokens,
  );
  const connect = options.sshConnect ?? connectSsh;
  try {
    return await connect({
      endpoint: session.ssh,
      username: `cf:${instance.process}/${instance.index}`,
      password,
    });
  } catch (error) {
    if (error instanceof SshConnectError) {
      throw new ConfigError(explainSshFailure(error, session.ssh, app.name, space));
    }
    throw error;
  }
}

/** Refuses an app without any of the files that make a folder a project. */
async function requireProjectFiles(tree: SftpProjectTree, app: string): Promise<void> {
  for (const marker of PROJECT_MARKERS) {
    if (await tree.isFile(tree.join(tree.root, marker))) return;
  }
  throw new ConfigError(
    `App "${app}" has no package.json, mta.yaml or .cdsrc.json in ${APP_ROOT}, so the project rules have nothing to read. ` +
      'Node.js apps (CAP services, approuters, UI5 apps) can be read this way.',
  );
}

export async function scanApp(options: ScanAppOptions): Promise<Snapshot> {
  const log = options.log ?? (() => {});
  const config = await readCfCliConfig(cfConfigPath(options.env));
  const session = await connectToApi(options, config, log);
  const where = targetNames(options, config, session.apiUrl);
  const org = await resolveOrg(session.cf, where.org);
  const [space] = await listSpaces(session.cf, org, where.space);
  if (space === undefined) {
    throw new ConfigError(`Space "${where.space}" was not found in "${org.name}".`);
  }

  log(`Note: ${SSH_NOTICE}`);
  if ((await hasSpaceDeveloper(session.cf, session.tokens, space.guid)) === false) {
    await ensureSpaceDeveloper(options, session, where, { org: org.guid, space: space.guid }, log);
  }

  const { resources: apps } = await session.cf.list('/v3/apps', CfAppSchema, {
    space_guids: space.guid,
    order_by: 'name',
  });
  if (apps.length === 0) {
    throw new ConfigError(`There are no apps in space "${space.name}" of "${org.name}".`);
  }
  const { app, sshOff } = await chooseApp(options, session.cf, apps, where);
  const restore = sshOff ? await enableSsh(options, app, where, log) : undefined;
  try {
    const instance = await runningInstance(session.cf, app);
    log(`Reading app "${app.name}" (instance ${instance.index}) over SSH, read-only`);
    const ssh = await openSession(options, session, app, instance, space.name);
    try {
      const tree = new SftpProjectTree(ssh.sftp, { rootName: app.name });
      await requireProjectFiles(tree, app.name);
      return await projectSnapshot(() => collectProjectTree(tree, { id: app.name }), {
        check: COLLECTOR_CHECKS.deployedApp,
        apiEndpoint: session.apiUrl,
        now: options.now,
        log,
      });
    } finally {
      ssh.close();
    }
  } finally {
    await restore?.();
  }
}
