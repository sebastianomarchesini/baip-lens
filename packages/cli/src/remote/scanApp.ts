import { z } from 'zod';
import { COLLECTOR_CHECKS } from '../checks.js';
import { listSpaces, resolveOrg } from '../collectors/orgs.js';
import { PROJECT_MARKERS, collectProjectTree } from '../collectors/project/index.js';
import { parseApiUrl } from '../config.js';
import type { Prompter } from '../guided/prompt.js';
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
 * an `audit.app.ssh-authorized` event; the command says both before it starts.
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
  /** Asks which app to read when --app is not given; absent when nobody is at the terminal. */
  prompter?: Prompter;
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

export const SPACE_DEVELOPER_NOTICE =
  'Reading a deployed app opens a read-only SSH file session (as `cf ssh` does). ' +
  'It needs the Space Developer role in the space: Space Auditor is not enough.';

export const AUDIT_EVENT_NOTICE =
  'Cloud Foundry records the session as an audit event (audit.app.ssh-authorized). Nothing in the app is changed.';

/** An app name as it can be pasted after a cf command. */
function shellName(name: string): string {
  return /^[A-Za-z0-9._-]+$/.test(name) ? name : JSON.stringify(name);
}

function nameList(apps: readonly CfApp[]): string {
  const names = apps.slice(0, MAX_NAMES_LISTED).map((a) => a.name);
  const more = apps.length - names.length;
  return `${names.join(', ')}${more > 0 ? ` and ${more} more` : ''}`;
}

/** The cf commands that turn SSH on, by the reason CF gives (`AppSshStatusPresenter`). */
export function sshOffAdvice(reason: string, app: string, space: string): string {
  // The phrases come before any name CF puts into the reason, so a name cannot steer the match.
  const lower = reason.toLowerCase();
  if (/\bdisabled globally\b/.test(lower)) {
    return 'SSH is turned off for the whole platform; only its operator can turn it on';
  }
  if (/\bdisabled for space\b/.test(lower)) {
    return `SSH is off for space "${space}": a Space Manager can turn it on with \`cf allow-space-ssh ${shellName(space)}\``;
  }
  if (/\bdisabled for app\b/.test(lower)) {
    return `SSH is off for this app: turn it on with \`cf enable-ssh ${shellName(app)}\`, then \`cf restart ${shellName(app)}\``;
  }
  return 'SSH is off for this app';
}

type Readiness = { ok: true } | { ok: false; why: string };

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

/** The org and space from the flags, else from `cf target` when it points at the same API. */
function targetNames(
  options: ScanAppOptions,
  config: CfCliConfig | undefined,
  apiUrl: URL,
): { org: string; space: string } {
  let target: { org?: string; space?: string } = {};
  if (config !== undefined && sameEndpoint(config.Target, apiUrl)) target = cfTargetNames(config);
  const org = options.org ?? target.org;
  const space = options.space ?? target.space;
  if (org === undefined || space === undefined) {
    throw new ConfigError(
      'No org and space are targeted. Run `cf target -o <org> -s <space>`, or pass --org and --space.',
    );
  }
  return { org, space };
}

const RoleSchema = z.object({ type: z.string() });

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
  try {
    const { resources } = await cf.list('/v3/roles', RoleSchema, {
      types: 'space_developer',
      space_guids: spaceGuid,
      user_guids: user.userId,
    });
    return resources.some((role) => role.type === 'space_developer');
  } catch (error) {
    if (error instanceof CfForbiddenError || error instanceof CfNotFoundError) return undefined;
    throw error;
  }
}

async function sshReadiness(cf: CfClient, app: CfApp, space: string): Promise<Readiness> {
  if (app.lifecycle?.type === 'docker') {
    return { ok: false, why: `it runs a Docker image, whose files are not in ${APP_ROOT}` };
  }
  if (app.state !== 'STARTED') {
    return { ok: false, why: `it is stopped: start it with \`cf start ${shellName(app.name)}\`` };
  }
  try {
    const status = await cf.get(
      `/v3/apps/${encodeURIComponent(app.guid)}/ssh_enabled`,
      SshEnabledSchema,
    );
    if (!status.enabled)
      return { ok: false, why: sshOffAdvice(status.reason ?? '', app.name, space) };
  } catch (error) {
    // Unknown is not "off": the SSH login will tell.
    if (!(error instanceof CfForbiddenError || error instanceof CfNotFoundError)) throw error;
  }
  return { ok: true };
}

async function chooseApp(
  options: ScanAppOptions,
  cf: CfClient,
  apps: CfApp[],
  where: { org: string; space: string },
): Promise<CfApp> {
  if (options.app !== undefined) {
    const app = apps.find((a) => a.name === options.app);
    if (app === undefined) {
      throw new ConfigError(
        `There is no app named "${options.app}" in space "${where.space}" of "${where.org}". Apps there: ${nameList(apps)}.`,
      );
    }
    const readiness = await sshReadiness(cf, app, where.space);
    if (!readiness.ok) throw new ConfigError(`App "${app.name}" cannot be read: ${readiness.why}.`);
    return app;
  }
  const p = options.prompter;
  if (p === undefined) {
    throw new ConfigError(
      'Name the app with --app <name>: the list of apps to pick from needs a terminal.',
    );
  }
  const states = await Promise.all(
    apps.map(async (app) => ({ app, readiness: await sshReadiness(cf, app, where.space) })),
  );
  const readable = states.filter((s) => s.readiness.ok).map((s) => s.app);
  const blocked = states.filter(
    (s): s is { app: CfApp; readiness: { ok: false; why: string } } => !s.readiness.ok,
  );
  p.say('');
  p.say(`Apps in space "${where.space}" of "${where.org}":`);
  if (blocked.length > 0) {
    p.say('Not readable right now:');
    for (const { app, readiness } of blocked) p.say(`  - ${app.name}: ${readiness.why}`);
  }
  if (readable.length === 0) {
    throw new ConfigError(
      `None of the ${apps.length} app(s) in space "${where.space}" can be read right now (reasons above).`,
    );
  }
  const index = await p.choose(
    'Which app do you want to analyze?',
    readable.map((a) => a.name),
    0,
  );
  const app = readable[index];
  if (app === undefined) throw new ConfigError('No app was chosen.');
  return app;
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

  log(`Note: ${SPACE_DEVELOPER_NOTICE}`);
  log(`      ${AUDIT_EVENT_NOTICE}`);
  if ((await hasSpaceDeveloper(session.cf, session.tokens, space.guid)) === false) {
    throw new ConfigError(
      `Your user does not have the Space Developer role in space "${space.name}" of "${org.name}", ` +
        'so the SSH login would be refused (and recorded as a failed attempt). ' +
        'Ask a Space Manager for the role, or scan the project folder with --path instead.',
    );
  }

  const { resources: apps } = await session.cf.list('/v3/apps', CfAppSchema, {
    space_guids: space.guid,
    order_by: 'name',
  });
  if (apps.length === 0) {
    throw new ConfigError(`There are no apps in space "${space.name}" of "${org.name}".`);
  }
  const app = await chooseApp(options, session.cf, apps, { org: org.name, space: space.name });
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
}
