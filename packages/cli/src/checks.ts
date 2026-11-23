import { truncate } from './collectors/sanitize.js';
import { CfAuthError, CfForbiddenError, ConfigError } from './http/errors.js';
import type { CfRole, CheckResult, SkipReasonCode } from './model/check.js';

export interface CheckDefinition {
  id: string;
  title: string;
  /** Any one of these CF roles is enough. Empty: no CF role needed. */
  roles: CfRole[];
  /** Needs SpaceDeveloper-level access; runs only with --deep. */
  deep?: boolean;
}

/** Collectors. Rule checks are declared next to their analyzers. */
export const COLLECTOR_CHECKS = {
  apps: {
    id: 'collect.apps',
    title: 'App inventory (GET /v3/apps)',
    roles: ['SpaceAuditor'],
  },
  droplets: {
    id: 'collect.droplets',
    title: 'Current droplets (GET /v3/droplets?current=true)',
    roles: ['SpaceAuditor'],
  },
  routes: {
    id: 'collect.routes',
    title: 'Routes and their destinations (GET /v3/routes?include=domain)',
    roles: ['SpaceAuditor'],
  },
  processes: {
    id: 'collect.processes',
    title: 'Web processes (GET /v3/processes?types=web)',
    roles: ['SpaceAuditor'],
  },
  traffic: {
    id: 'collect.traffic',
    title: 'Last router request per app (Log Cache GET /api/v1/read)',
    roles: ['SpaceAuditor'],
  },
  project: {
    id: 'collect.project',
    title:
      'Project files (package.json, .cdsrc, mta.yaml, xs-security.json, xs-app.json, *.cds, seed CSV, *.html)',
    roles: [],
  },
  /**
   * The same collection from deployed apps (`baip-lens project --cf`): one
   * app, or every app of a deployed project. It keeps the id
   * `collect.project`, which every project rule requires; only the way the
   * files were read differs. It is recorded once per scan, as ran when at
   * least one app was read; an app that was not read gets a check of its own
   * (`deployedAppNotRead`).
   */
  deployedApp: {
    id: 'collect.project',
    title:
      'Deployed app files read over SSH, read-only SFTP (package.json, .cdsrc, xs-app.json, *.cds, seed CSV, *.html)',
    roles: ['SpaceDeveloper'],
  },
} as const satisfies Record<string, CheckDefinition>;

/** How much of an app name the title of a check repeats. */
const MAX_APP_NAME_IN_TITLE = 80;

/**
 * The check of one app of a deployed project that was not read; it is only
 * ever recorded as skipped. The id starts with `collect.`, so that
 * `report --from` keeps it, and is never `collect.project` itself: a skip
 * under that id would turn every project rule into "dependency skipped" and
 * lose the findings of the apps that were read.
 */
export function deployedAppNotRead(projectId: string, appName: string): CheckDefinition {
  return {
    id: `${COLLECTOR_CHECKS.deployedApp.id}.${projectId}`,
    title: `Files of deployed app ${truncate(appName, MAX_APP_NAME_IN_TITLE) ?? ''}`,
    roles: [...COLLECTOR_CHECKS.deployedApp.roles],
  };
}

/**
 * A check that cannot run and knows why better than a generic message: the
 * recorder records it as skipped with this reason code and text. Used where
 * the status code alone would mislead, e.g. Log Cache answers 404, never 403,
 * when the caller may not read an app's logs.
 */
export class CheckSkipError extends Error {
  override readonly name = 'CheckSkipError';

  constructor(
    readonly reasonCode: SkipReasonCode,
    readonly reason: string,
  ) {
    super(reason);
  }
}

function roleText(roles: readonly CfRole[]): string {
  return roles.length === 0 ? 'no CF role' : roles.join(' or ');
}

/**
 * What stopped the skipped checks, as the words after "N check(s)". The role
 * is blamed only when a missing role is all that stopped them (a check that
 * depends on a forbidden one counts too), never for a check that was turned
 * off or whose service is absent or did not answer. The report words it the
 * same way (packages/ui/src/data/summary.ts, which cannot import this file).
 */
export function skippedPhrase(skipped: readonly CheckResult[]): string {
  const codes = skipped.map((check) => check.reasonCode);
  if (
    codes.includes('insufficient_role') &&
    codes.every((code) => code === 'insufficient_role' || code === 'dependency_skipped')
  ) {
    return 'could not run with your role';
  }
  if (codes.length > 0 && codes.every((code) => code === 'disabled')) {
    return codes.length === 1 ? 'was turned off' : 'were turned off';
  }
  return 'did not run';
}

/**
 * Runs checks so that one failing check never fails the scan: a 403 is
 * recorded as "insufficient role", other errors as "error". Only auth and
 * configuration errors abort, because nothing else could succeed after them.
 */
export class CheckRecorder {
  private readonly results = new Map<string, CheckResult>();

  constructor(
    private readonly options: { deep: boolean },
    private readonly log: (message: string) => void = () => {},
  ) {}

  async run<T>(check: CheckDefinition, task: () => Promise<T>): Promise<T | undefined> {
    if (check.deep && !this.options.deep) {
      this.skip(check, 'requires_deep', `requires --deep (${roleText(check.roles)})`);
      return undefined;
    }
    try {
      const value = await task();
      this.ran(check);
      return value;
    } catch (error) {
      if (error instanceof CfAuthError || error instanceof ConfigError) throw error;
      if (error instanceof CheckSkipError) {
        this.skip(check, error.reasonCode, error.reason);
      } else if (error instanceof CfForbiddenError) {
        this.skip(check, 'insufficient_role', `insufficient role: needs ${roleText(check.roles)}`);
      } else {
        const message = error instanceof Error ? error.message : String(error);
        this.skip(check, 'error', `error: ${message}`);
      }
      return undefined;
    }
  }

  ran(check: CheckDefinition): void {
    this.results.set(check.id, {
      id: check.id,
      title: check.title,
      roles: [...check.roles],
      status: 'ran',
    });
  }

  skip(check: CheckDefinition, reasonCode: SkipReasonCode, reason: string): void {
    this.log(`skipped ${check.id}: ${reason}`);
    this.results.set(check.id, {
      id: check.id,
      title: check.title,
      roles: [...check.roles],
      status: 'skipped',
      reason,
      reasonCode,
    });
  }

  list(): CheckResult[] {
    return [...this.results.values()];
  }
}
