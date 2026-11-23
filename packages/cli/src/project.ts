import { resolve } from 'node:path';
import { analyze } from './analyzers/index.js';
import { type CheckDefinition, CheckRecorder, COLLECTOR_CHECKS } from './checks.js';
import { collectProject } from './collectors/project/index.js';
import type { SkipReasonCode } from './model/check.js';
import type { RawData, RawProject } from './model/raw.js';
import {
  DEFAULT_SNAPSHOT_OPTIONS,
  SNAPSHOT_SCHEMA_VERSION,
  type Snapshot,
} from './model/snapshot.js';
import { TOOL_NAME, TOOL_VERSION } from './version.js';

export interface ScanProjectOptions {
  /** The project directory, as the user gave it. */
  path: string;
  /** Output directory; the walk never enters it. */
  outDir?: string;
  /** Injected in tests; defaults to the current time. */
  now?: () => Date;
  log?: (message: string) => void;
}

/** A part of a project scan that was not read; recorded as a skipped check of its own. */
export interface NotRead {
  check: CheckDefinition;
  reasonCode: SkipReasonCode;
  reason: string;
}

/**
 * What a project collection hands over: one record per project read (a local
 * folder gives one, a deployed project one per app), and the parts that were
 * not read, in the order they are to be reported.
 */
export interface ProjectCollection {
  projects: RawProject[];
  notRead: NotRead[];
}

export interface ProjectSnapshotOptions {
  /**
   * How the files were collected; its id must stay `collect.project`, which
   * the rules require. Recorded as ran when the collection returned.
   */
  check: CheckDefinition;
  /** The CF API the files were read through (deployed apps); absent for a local folder. */
  apiEndpoint?: URL;
  now?: () => Date;
  log?: (message: string) => void;
}

/**
 * Findings, inventory rows and checks are keyed by id. Two projects with one
 * id would merge their rows, and a skip recorded under the id of the
 * collection itself would replace its result and turn every rule into
 * "dependency skipped". Either is a mistake of the caller, never of the data.
 */
function assertDistinctIds(check: CheckDefinition, collection: ProjectCollection): void {
  const projectIds = new Set(collection.projects.map((project) => project.id));
  if (projectIds.size !== collection.projects.length) {
    throw new Error('two projects of one scan have the same id');
  }
  const checkIds = new Set([check.id, ...collection.notRead.map((item) => item.check.id)]);
  if (checkIds.size !== collection.notRead.length + 1) {
    throw new Error('two checks of one project scan have the same id');
  }
}

/**
 * Runs one project collection and the project rules, and builds the
 * snapshot. Shared by a local folder and deployed apps: the collection hands
 * over its results, and this module makes no request itself. The log carries
 * counts and project ids only, never a path or file content.
 */
export async function projectSnapshot(
  collect: () => Promise<ProjectCollection>,
  options: ProjectSnapshotOptions,
): Promise<Snapshot> {
  const log = options.log ?? (() => {});
  const scannedAt = (options.now?.() ?? new Date()).toISOString();

  const recorder = new CheckRecorder({ deep: false }, log);
  const collection = (await recorder.run(options.check, collect)) ?? { projects: [], notRead: [] };
  assertDistinctIds(options.check, collection);
  const { projects } = collection;
  for (const project of projects) {
    log(
      `Read ${project.filesOpened} project file(s)` +
        `${project.unreadable.length > 0 ? `, ${project.unreadable.length} unreadable` : ''}` +
        ` in project ${project.id}`,
    );
  }
  // After the collection's own check, so that the checks keep the order of the apps.
  for (const item of collection.notRead) recorder.skip(item.check, item.reasonCode, item.reason);

  const raw: RawData = {
    orgs: [],
    spaces: [],
    apps: [],
    droplets: [],
    routes: [],
    processes: [],
    traffic: [],
    history: [],
    projects,
  };
  const collectorChecks = recorder.list();
  const analysis = analyze(raw, scannedAt, collectorChecks);
  return {
    schemaVersion: SNAPSHOT_SCHEMA_VERSION,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    scannedAt,
    scope: {
      ...(options.apiEndpoint === undefined ? {} : { apiEndpoint: options.apiEndpoint.href }),
      orgs: [],
      projects: projects.map((p) => p.id),
    },
    // No CF collector runs in a project scan, so no Log Cache either.
    options: { ...DEFAULT_SNAPSHOT_OPTIONS },
    checks: [...collectorChecks, ...analysis.ruleChecks],
    raw,
    apps: analysis.apps,
    findings: analysis.findings,
  };
}

/**
 * Scans a local CAP / MTA project directory: file-system reads only, no
 * network, no child processes.
 */
export async function scanProject(options: ScanProjectOptions): Promise<Snapshot> {
  const excludeDirs = options.outDir === undefined ? [] : [resolve(options.outDir)];
  const collect = async (): Promise<ProjectCollection> => ({
    projects: [await collectProject(options.path, { excludeDirs })],
    notRead: [],
  });
  return projectSnapshot(collect, {
    check: COLLECTOR_CHECKS.project,
    now: options.now,
    log: options.log,
  });
}
