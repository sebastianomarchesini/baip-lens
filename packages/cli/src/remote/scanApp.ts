import { z } from 'zod';
import { COLLECTOR_CHECKS, deployedAppNotRead } from '../checks.js';
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
import {
  CfAuthError,
  CfForbiddenError,
  CfNotFoundError,
  ConfigError,
  HttpNetworkError,
} from '../http/errors.js';
import { type FetchLike, HttpClient } from '../http/httpClient.js';
import type { RawDeployment, RawProject } from '../model/raw.js';
import type { Snapshot } from '../model/snapshot.js';
import {
  EgressPolicy,
  type SshEndpoint,
  cfApiRule,
  sshEndpointFromRoot,
  uaaSshCodeRule,
} from '../net/allowlist.js';
import {
  type NotRead,
  type ProjectCollection,
  type ProjectSnapshotOptions,
  projectSnapshot,
} from '../project.js';
import { trustRootLinks } from '../scan.js';
import { TOOL_NAME, TOOL_VERSION } from '../version.js';
import { fingerprintFormat } from './hostKey.js';
import { mtaIdentity, projectIdOf, withProjectIds } from './mta.js';
import {
  type AppState,
  type CfApp,
  CfAppSchema,
  GUID,
  type Selection,
  capped,
  selectApps,
  shellName,
} from './selectApps.js';
import {
  type SshConnect,
  SshConnectError,
  type SshFailure,
  type SshSession,
  connectSsh,
} from './session.js';
import { RemoteSessionError } from './sftp.js';
import { SftpProjectTree } from './sftpTree.js';
import { DEFAULT_SSH_OAUTH_CLIENT, requestSshCode } from './sshCode.js';

export { sshOffAdvice } from './selectApps.js';

/*
 * `baip-lens project --cf`: the project rules on deployed apps, read live.
 * The cf CLI login and target are reused; the user picks one app, or a
 * deployed MTA project with all its apps, from the targeted space (or names
 * it with --app or --mta, `selectApps.ts`). For each app one read-only SFTP
 * session is opened on one running instance, as `cf ssh` would open it, one
 * app after the other; the files are walked and read in memory with the same
 * allow-list and limits as a local project; the session is closed. All apps
 * of a run go into one snapshot, one project record per app. Nothing is
 * written to disk but the reports.
 *
 * CF calls are GET only (apps, each app's SSH status, its web process and the
 * process stats), plus one one-time SSH code per session from UAA
 * (`cf ssh-code`). SSH needs the Space Developer role, and Cloud Foundry
 * records every session as an `audit.app.ssh-authorized` event; the command
 * says both before it starts.
 *
 * A run of one app stops on anything that keeps the app from being read. In
 * a project run an app that cannot be read is recorded as a skipped check and
 * the next app is read; only what would fail for every app (the SSH endpoint,
 * the cf login, a refused first login, a CF API or UAA that cannot be
 * reached) stops the run.
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
  /** --mta: read every app of this deployed project without asking. */
  mta?: string;
  /** --mta-namespace: which deployment of that project; the empty string is the one without a namespace. */
  mtaNamespace?: string;
  env: NodeJS.ProcessEnv;
  /** Asks what to read when neither --app nor --mta is given; absent when nobody is at the terminal. */
  prompter?: Prompter;
  /** Injected in tests. */
  fetch?: FetchLike;
  /** Injected in tests. */
  sshConnect?: SshConnect;
  now?: () => Date;
  /** Progress and notices, one line each. */
  log?: (message: string) => void;
}

const ProcessSchema = z.object({ guid: z.string().regex(GUID) });
const StatsSchema = z.object({ resources: z.array(z.unknown()) });
const InstanceSchema = z.object({ index: z.number().int().nonnegative(), state: z.string() });

export const SPACE_DEVELOPER_NOTICE =
  'Reading a deployed app opens a read-only SSH file session (as `cf ssh` does). ' +
  'It needs the Space Developer role in the space: Space Auditor is not enough.';

export const AUDIT_EVENT_NOTICE =
  'Cloud Foundry records every such session as an audit event (audit.app.ssh-authorized). Nothing in an app is changed.';

/** Why one app was not read, as the reason of its skipped check. */
type SkipReason = Pick<NotRead, 'reasonCode' | 'reason'>;

/**
 * One app cannot be read, for a reason that says nothing about the next app.
 * A ConfigError: a run of one app stops with the message (exit code 2,
 * nothing written). A project run records the app as a skipped check instead,
 * with `reason`: one fixed fragment per case that names no app, no space and
 * no path, and repeats no command and no server text, because it is written
 * to the snapshot and the reports.
 */
class AppNotReadableError extends ConfigError {
  constructor(
    message: string,
    readonly reasonCode: 'unavailable' | 'error',
    readonly reason: string,
    /** The SSH failure behind it, when there is one. */
    readonly sshFailure?: SshFailure,
  ) {
    super(message);
  }
}

/** The SSH failures that concern one app only, as skip reasons; the others stop a run. */
const APP_SSH_FAILURES: Partial<Record<SshFailure, string>> = {
  // Not the role: an earlier login of the same run was accepted.
  auth: 'the SSH login was refused for this app',
  'sftp-refused': 'the SSH server refused the read-only file channel (SFTP) for this app',
  other: 'the SSH connection failed for this app',
};

const SESSION_LOST_REASON = 'the connection closed before the app was read';
const UNEXPECTED_REASON = 'an unexpected error stopped the reading of this app';

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
      throw new AppNotReadableError(
        `App "${app.name}" has no web process, so there is no instance to read.`,
        'unavailable',
        'it has no web process, so there is no instance to read',
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
    throw new AppNotReadableError(
      `No instance of "${app.name}" is running right now, so its files cannot be read. Check it with \`cf app ${shellName(app.name)}\`.`,
      'unavailable',
      'no instance of it is running right now',
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

/** What reading the apps of one run needs, and what it remembers from one app to the next. */
interface ReadContext {
  options: ScanAppOptions;
  session: Session;
  /** The space name, for messages. */
  space: string;
  log: (message: string) => void;
  /** An SSH login of this run was accepted: a login refused after it is about that app, not the role. */
  loggedIn: boolean;
}

/** One new one-time code and one SSH session for one app instance. */
async function openSession(
  context: ReadContext,
  app: CfApp,
  instance: { process: string; index: number },
): Promise<SshSession> {
  const { options, session } = context;
  const password = await requestSshCode(
    session.http,
    session.uaa,
    session.oauthClient,
    session.tokens,
  );
  const connect = options.sshConnect ?? connectSsh;
  try {
    const ssh = await connect({
      endpoint: session.ssh,
      username: `cf:${instance.process}/${instance.index}`,
      password,
    });
    context.loggedIn = true;
    return ssh;
  } catch (error) {
    if (!(error instanceof SshConnectError)) throw error;
    // The file channel is asked for after the login was accepted.
    if (error.failure === 'sftp-refused') context.loggedIn = true;
    const message = explainSshFailure(error, session.ssh, app.name, context.space);
    const reason = APP_SSH_FAILURES[error.failure];
    throw reason === undefined
      ? new ConfigError(message)
      : new AppNotReadableError(message, 'error', reason, error.failure);
  }
}

/** Refuses an app without any of the files that make a folder a project. */
async function requireProjectFiles(tree: SftpProjectTree, app: string): Promise<void> {
  for (const marker of PROJECT_MARKERS) {
    if (await tree.isFile(tree.join(tree.root, marker))) return;
  }
  const missing = 'no package.json, mta.yaml or .cdsrc.json in its app folder';
  throw new AppNotReadableError(
    `App "${app}" has ${missing}, so the project rules have nothing to read. ` +
      'Node.js apps (CAP services, approuters, UI5 apps) can be read this way.',
    'unavailable',
    `it has ${missing}, so the project rules have nothing to read`,
  );
}

/**
 * One app: its running instance, a new one-time code, one SSH session, and
 * `read` on the app's files; the session is closed whatever happens.
 */
async function withAppFiles<T>(
  context: ReadContext,
  app: CfApp,
  read: (tree: SftpProjectTree) => Promise<T>,
): Promise<T> {
  const instance = await runningInstance(context.session.cf, app);
  context.log(`Reading app "${app.name}" (instance ${instance.index}) over SSH, read-only`);
  const ssh = await openSession(context, app, instance);
  try {
    const tree = new SftpProjectTree(ssh.sftp, { rootName: app.name });
    await requireProjectFiles(tree, app.name);
    return await read(tree);
  } finally {
    ssh.close();
  }
}

/** Which deployed app a project record comes from, and the MTA it belongs to when it has one. */
function deploymentOf(app: CfApp): RawDeployment {
  return { app: app.name, mta: mtaIdentity(app.metadata) };
}

function snapshotOptions(context: ReadContext): ProjectSnapshotOptions {
  return {
    check: COLLECTOR_CHECKS.deployedApp,
    apiEndpoint: context.session.apiUrl,
    now: context.options.now,
    log: context.log,
  };
}

/** A run of one app: anything that keeps it from being read stops the run. */
function scanOneApp(context: ReadContext, app: CfApp): Promise<Snapshot> {
  const record = { id: projectIdOf(app.name), deployment: deploymentOf(app) };
  return withAppFiles(context, app, (tree) =>
    projectSnapshot(
      async () => ({ projects: [await collectProjectTree(tree, record)], notRead: [] }),
      snapshotOptions(context),
    ),
  );
}

/**
 * Why a failed app of a project run is skipped, or null when the failure
 * stops the run: the SSH endpoint or the cf login would fail for every app,
 * and a login refused before any was accepted is most likely the missing
 * role, which one refused attempt per app would only repeat in the audit log.
 * A CF API or UAA that cannot be reached is not about one app either: the
 * run stops and says so, instead of asking again for every app and hiding
 * the cause behind a skipped check.
 */
function skipReason(error: unknown, loggedIn: boolean): SkipReason | null {
  if (error instanceof AppNotReadableError) {
    if (error.sshFailure === 'auth' && !loggedIn) return null;
    return { reasonCode: error.reasonCode, reason: error.reason };
  }
  // Nothing of a half-read app is kept, so it cannot look clean.
  if (error instanceof RemoteSessionError) {
    return { reasonCode: 'error', reason: SESSION_LOST_REASON };
  }
  if (
    error instanceof ConfigError ||
    error instanceof CfAuthError ||
    error instanceof HttpNetworkError
  ) {
    return null;
  }
  return { reasonCode: 'error', reason: UNEXPECTED_REASON };
}

/** Reads one app of a project; a skip reason when it cannot be read and the next app still can. */
async function readProjectApp(
  context: ReadContext,
  app: CfApp,
  id: string,
): Promise<RawProject | SkipReason> {
  try {
    return await withAppFiles(context, app, (tree) =>
      collectProjectTree(tree, { id, deployment: deploymentOf(app) }),
    );
  } catch (error) {
    const skip = skipReason(error, context.loggedIn);
    if (skip === null) throw error;
    if (context.options.env.BAIP_LENS_DEBUG && error instanceof Error) {
      // The kind of error only: its message may repeat what a server answered.
      context.log(`debug: app "${app.name}" was not read after a ${error.name}`);
    }
    return skip;
  }
}

function isSkip(result: RawProject | SkipReason): result is SkipReason {
  return 'reasonCode' in result;
}

/**
 * A project run: every app that can be read, one after the other, one
 * session each. An app that cannot be read is handed over as not read, with
 * its reason; when none could be read there is nothing to report.
 */
async function readProject(
  context: ReadContext,
  projectId: string,
  states: readonly AppState[],
): Promise<ProjectCollection> {
  const readable = states.filter((state) => state.readiness.ok).length;
  context.log(
    `Reading project "${projectId}": ${readable} app(s), one read-only SSH session each (each is recorded as an audit event)`,
  );
  const projects: RawProject[] = [];
  const notRead: NotRead[] = [];
  const reasons: string[] = [];
  for (const { item, id } of withProjectIds(states, (state) => state.app.name)) {
    const { app, readiness } = item;
    const check = deployedAppNotRead(id, app.name);
    if (!readiness.ok) {
      // What to do about it (a cf command with a name in it) is for the terminal; the record gets the fixed reason.
      context.log(`Not reading app "${app.name}": ${readiness.why}`);
      notRead.push({ check, reasonCode: 'unavailable', reason: readiness.reason });
      reasons.push(`${app.name}: ${readiness.why}`);
      continue;
    }
    const result = await readProjectApp(context, app, id);
    if (!isSkip(result)) {
      projects.push(result);
      continue;
    }
    notRead.push({ check, ...result });
    reasons.push(`${app.name}: ${result.reason}`);
  }
  if (projects.length === 0) {
    throw new ConfigError(
      `No app of project "${projectId}" could be read: ${capped(reasons, '; ')}.`,
    );
  }
  return { projects, notRead };
}

/** A project run: the apps are read first, then the snapshot is built from what was read. */
async function scanProjectApps(
  context: ReadContext,
  selection: Extract<Selection, { kind: 'project' }>,
): Promise<Snapshot> {
  const collection = await readProject(context, selection.project.id, selection.states);
  return projectSnapshot(() => Promise.resolve(collection), snapshotOptions(context));
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
  const selection = await selectApps(options, session.cf, apps, {
    org: org.name,
    space: space.name,
  });
  const context: ReadContext = { options, session, space: space.name, log, loggedIn: false };
  return selection.kind === 'app'
    ? scanOneApp(context, selection.app)
    : scanProjectApps(context, selection);
}
