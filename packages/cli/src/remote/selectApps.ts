import { z } from 'zod';
import type { Prompter } from '../guided/prompt.js';
import type { CfClient } from '../http/cfClient.js';
import { CfForbiddenError, CfNotFoundError, ConfigError } from '../http/errors.js';
import {
  MtaMetadataSchema,
  type MtaProject,
  deploymentName,
  groupByMta,
  overAppLimit,
  overAppLimitWhy,
  projectLabel,
} from './mta.js';

/*
 * What `baip-lens project --cf` reads: one app, or every app of a deployed
 * MTA project. The apps of the space are grouped by the project they were
 * deployed from (`mta.ts`); the user picks a project or an app from one list,
 * or names an app with --app or a project with --mta. Which apps can be read
 * right now (started, a buildpack app, SSH on) is asked from the CF API with
 * GET requests only; an app that cannot be read is named in the terminal with
 * the reason and the cf command that would change it, which BAIP Lens never
 * runs. What a report keeps of that is a fixed reason without any name.
 */

export const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** An app of the space. Of `metadata` only the six MTA keys are kept (`MtaMetadataSchema`). */
export const CfAppSchema = z.object({
  guid: z.string().regex(GUID),
  name: z.string().min(1),
  state: z.string(),
  lifecycle: z.object({ type: z.string() }).nullish(),
  metadata: MtaMetadataSchema,
});
export type CfApp = z.infer<typeof CfAppSchema>;

const SshEnabledSchema = z.object({ enabled: z.boolean(), reason: z.string().nullish() });

/** How many names an error lists before it says "and N more". */
const MAX_NAMES_LISTED = 20;

export interface SelectOptions {
  /** --app: read this app without asking. */
  app?: string;
  /** --mta: read every app of this project without asking. */
  mta?: string;
  /** --mta-namespace: which deployment of the project; the empty string is the one without a namespace. */
  mtaNamespace?: string;
  /** Asks what to read when neither is given; absent when nobody is at the terminal. */
  prompter?: Prompter;
}

/**
 * Why an app cannot be read right now, in two wordings. `reason` is one fixed
 * fragment per case, with no name and no command in it: it is recorded as the
 * reason of a skipped check and so reaches the snapshot and the reports.
 * `why` is for the terminal only: it may name the app or the space and the cf
 * command that would change things.
 */
export interface Blocker {
  reason: string;
  why: string;
}

export type Readiness = { ok: true } | ({ ok: false } & Blocker);

export interface AppState {
  app: CfApp;
  readiness: Readiness;
}

type Blocked = AppState & { readiness: { ok: false } & Blocker };

/** What the run reads: one app, or a project with every one of its apps and whether each can be read. */
export type Selection =
  { kind: 'app'; app: CfApp } | { kind: 'project'; project: MtaProject<CfApp>; states: AppState[] };

interface Where {
  org: string;
  space: string;
}

/**
 * An app or space name as it can be pasted after a cf command. Cloud Foundry
 * allows any printable character in a name, and whoever may create an app
 * chooses it, so a pasted name must never be more than one word of text to a
 * shell. A plain name stands as it is. A name with spaces gets double quotes,
 * which every common shell reads the same way. Any other name gets POSIX
 * single quotes, inside which a shell expands nothing (`$(...)`, backticks
 * and `\` stay text); a single quote in the name is written as `'\''`.
 */
export function shellName(name: string): string {
  if (/^[A-Za-z0-9._-]+$/.test(name)) return name;
  if (/^[A-Za-z0-9._ -]+$/.test(name)) return `"${name}"`;
  return `'${name.replaceAll("'", "'\\''")}'`;
}

/** The first names joined by `separator`, then "and N more". */
export function capped(names: readonly string[], separator = ', '): string {
  const listed = names.slice(0, MAX_NAMES_LISTED);
  const more = names.length - listed.length;
  return `${listed.join(separator)}${more > 0 ? ` and ${more} more` : ''}`;
}

const SSH_OFF_PLATFORM =
  'SSH is turned off for the whole platform; only its operator can turn it on';
const SSH_OFF_SPACE = 'SSH is off for its space';
const SSH_OFF_APP = 'SSH is off for this app';

/** Where SSH is turned off, by the reason CF gives (`AppSshStatusPresenter`). */
function sshOffLevel(reason: string): 'platform' | 'space' | 'app' | 'unknown' {
  // The first phrase decides: CF puts the space name after its phrase, so a name cannot steer the match.
  const phrase = reason.toLowerCase().match(/\bdisabled (globally|for space|for app)\b/)?.[1];
  switch (phrase) {
    case 'globally':
      return 'platform';
    case 'for space':
      return 'space';
    case 'for app':
      return 'app';
    default:
      return 'unknown';
  }
}

/** Why SSH is off, as the fixed reason of a skipped check: no name, no command, nothing of CF's text. */
export function sshOffReason(reason: string): string {
  const level = sshOffLevel(reason);
  if (level === 'platform') return SSH_OFF_PLATFORM;
  return level === 'space' ? SSH_OFF_SPACE : SSH_OFF_APP;
}

/** The cf commands that turn SSH on, by the reason CF gives; for the terminal. */
export function sshOffAdvice(reason: string, app: string, space: string): string {
  switch (sshOffLevel(reason)) {
    case 'platform':
      return SSH_OFF_PLATFORM;
    case 'space':
      return `SSH is off for space "${space}": a Space Manager can turn it on with \`cf allow-space-ssh ${shellName(space)}\``;
    case 'app':
      return `${SSH_OFF_APP}: turn it on with \`cf enable-ssh ${shellName(app)}\`, then \`cf restart ${shellName(app)}\``;
    case 'unknown':
      return SSH_OFF_APP;
  }
}

const DOCKER_IMAGE = 'it runs a Docker image, which has no buildpack app folder to read';
const STOPPED = 'it is stopped';

/** Whether an app can be read right now, else why not (`Blocker`). */
async function sshReadiness(cf: CfClient, app: CfApp, space: string): Promise<Readiness> {
  if (app.lifecycle?.type === 'docker') {
    return { ok: false, reason: DOCKER_IMAGE, why: DOCKER_IMAGE };
  }
  if (app.state !== 'STARTED') {
    return {
      ok: false,
      reason: STOPPED,
      why: `${STOPPED}: start it with \`cf start ${shellName(app.name)}\``,
    };
  }
  try {
    const status = await cf.get(
      `/v3/apps/${encodeURIComponent(app.guid)}/ssh_enabled`,
      SshEnabledSchema,
    );
    if (!status.enabled) {
      const off = status.reason ?? '';
      return {
        ok: false,
        reason: sshOffReason(off),
        why: sshOffAdvice(off, app.name, space),
      };
    }
  } catch (error) {
    // Unknown is not "off": the SSH login will tell.
    if (!(error instanceof CfForbiddenError || error instanceof CfNotFoundError)) throw error;
  }
  return { ok: true };
}

function readinessOf(cf: CfClient, apps: readonly CfApp[], space: string): Promise<AppState[]> {
  return Promise.all(
    apps.map(async (app) => ({ app, readiness: await sshReadiness(cf, app, space) })),
  );
}

function isBlocked(state: AppState): state is Blocked {
  return !state.readiness.ok;
}

async function namedApp(
  name: string,
  cf: CfClient,
  apps: readonly CfApp[],
  where: Where,
): Promise<Selection> {
  const app = apps.find((a) => a.name === name);
  if (app === undefined) {
    throw new ConfigError(
      `There is no app named "${name}" in space "${where.space}" of "${where.org}". Apps there: ${capped(apps.map((a) => a.name))}.`,
    );
  }
  const readiness = await sshReadiness(cf, app, where.space);
  if (!readiness.ok) throw new ConfigError(`App "${app.name}" cannot be read: ${readiness.why}.`);
  return { kind: 'app', app };
}

/** The deployment --mta and --mta-namespace name, or an error that says what there is instead. */
function namedDeployment(
  id: string,
  namespace: string | undefined,
  projects: readonly MtaProject<CfApp>[],
  where: Where,
): MtaProject<CfApp> {
  const deployments = projects.filter((project) => project.id === id);
  const [first] = deployments;
  if (first === undefined) {
    if (projects.length === 0) {
      throw new ConfigError(
        `No app in space "${where.space}" of "${where.org}" was deployed as a project (MTA). Name an app with --app <name>.`,
      );
    }
    const ids = [...new Set(projects.map((project) => project.id))];
    throw new ConfigError(
      `There is no project "${id}" in space "${where.space}" of "${where.org}". Projects there: ${capped(ids)}.`,
    );
  }
  const existing = capped(deployments.map((project) => deploymentName(project.namespace)));
  if (namespace === undefined) {
    if (deployments.length === 1) return first;
    const withoutOne = deployments.some((project) => project.namespace === null)
      ? ', or --mta-namespace "" for the one without a namespace'
      : '';
    throw new ConfigError(
      `Project "${id}" is deployed ${deployments.length} times in space "${where.space}" (${existing}). Add --mta-namespace <name>${withoutOne}.`,
    );
  }
  const wanted = namespace === '' ? null : namespace;
  const match = deployments.find((project) => project.namespace === wanted);
  if (match === undefined) {
    const which = wanted === null ? 'without a namespace' : `in namespace "${wanted}"`;
    throw new ConfigError(
      `Project "${id}" has no deployment ${which} in space "${where.space}". Deployments there: ${existing}.`,
    );
  }
  return match;
}

function overAppLimitError(project: MtaProject<CfApp>): ConfigError {
  return new ConfigError(
    `Project "${project.id}" cannot be read as a whole: ${overAppLimitWhy(project.members.length)}.`,
  );
}

/** --mta: the project's apps and their readiness; no other app's SSH status is asked for. */
async function namedProject(
  options: SelectOptions & { mta: string },
  cf: CfClient,
  apps: readonly CfApp[],
  where: Where,
): Promise<Selection> {
  const { projects } = groupByMta(apps);
  const project = namedDeployment(options.mta, options.mtaNamespace, projects, where);
  if (overAppLimit(project)) throw overAppLimitError(project);
  const states = await readinessOf(
    cf,
    project.members.map((member) => member.app),
    where.space,
  );
  const blocked = states.filter(isBlocked);
  if (blocked.length === states.length) {
    const reasons = blocked.map((state) => `${state.app.name}: ${state.readiness.why}`);
    throw new ConfigError(
      `No app of project "${project.id}" can be read right now: ${capped(reasons, '; ')}.`,
    );
  }
  return { kind: 'project', project, states };
}

/** The line of a project that is not offered because it has more apps than one run reads. */
function overAppLimitLine(project: MtaProject<CfApp>): string {
  const namespace = project.namespace === null ? '' : ` (${deploymentName(project.namespace)})`;
  return `project ${project.id}${namespace}: ${overAppLimitWhy(project.members.length)}`;
}

/** The picker: projects with an app that can be read first, then the apps on their own. */
async function pickFromList(
  prompter: Prompter,
  cf: CfClient,
  apps: readonly CfApp[],
  where: Where,
): Promise<Selection> {
  const states = await readinessOf(cf, apps, where.space);
  const ready = new Set(states.filter((state) => state.readiness.ok).map((state) => state.app));
  const isReady = (app: CfApp): boolean => ready.has(app);
  const { projects, singles } = groupByMta(apps);

  prompter.say('');
  prompter.say(`Apps in space "${where.space}" of "${where.org}":`);
  const blocked = [
    ...states.filter(isBlocked).map((state) => `${state.app.name}: ${state.readiness.why}`),
    ...projects.filter(overAppLimit).map(overAppLimitLine),
  ];
  if (blocked.length > 0) {
    prompter.say('Not readable right now:');
    for (const line of blocked) prompter.say(`  - ${line}`);
  }

  const offered = projects.filter(
    (project) => !overAppLimit(project) && project.members.some((member) => isReady(member.app)),
  );
  const choices: { label: string; selection: Selection }[] = [
    ...offered.map((project) => {
      const members = new Set(project.members.map((member) => member.app));
      return {
        label: projectLabel(project, isReady),
        selection: {
          kind: 'project' as const,
          project,
          states: states.filter((state) => members.has(state.app)),
        },
      };
    }),
    ...singles
      .filter(isReady)
      .map((app) => ({ label: app.name, selection: { kind: 'app' as const, app } })),
  ];
  if (choices.length === 0) {
    throw new ConfigError(
      `None of the ${apps.length} app(s) in space "${where.space}" can be read right now (reasons above).`,
    );
  }
  if (offered.length > 0) {
    prompter.say(
      'A project reads all its apps. To read one app only, run again with --app <name>.',
    );
  }
  const index = await prompter.choose(
    offered.length > 0
      ? 'Which project or app do you want to analyze?'
      : 'Which app do you want to analyze?',
    choices.map((choice) => choice.label),
    0,
  );
  const choice = choices[index];
  if (choice === undefined) throw new ConfigError('No app was chosen.');
  return choice.selection;
}

/** Decides what the run reads: the named app, the named project, or what the user picks. */
export async function selectApps(
  options: SelectOptions,
  cf: CfClient,
  apps: readonly CfApp[],
  where: Where,
): Promise<Selection> {
  if (options.app !== undefined) return namedApp(options.app, cf, apps, where);
  if (options.mta !== undefined) {
    return namedProject({ ...options, mta: options.mta }, cf, apps, where);
  }
  if (options.prompter === undefined) {
    throw new ConfigError(
      'Name the app with --app <name>, or a project with --mta <id>: the list to pick from needs a terminal.',
    );
  }
  return pickFromList(options.prompter, cf, apps, where);
}
