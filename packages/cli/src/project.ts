import { resolve } from 'node:path';
import { analyze } from './analyzers/index.js';
import { type CheckDefinition, CheckRecorder, COLLECTOR_CHECKS } from './checks.js';
import { collectProject } from './collectors/project/index.js';
import type { SkipReasonCode } from './model/check.js';
import type { RawAdvisory, RawData, RawProject, RawVulnerablePackage } from './model/raw.js';
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
  /** `--dependency-exclude`: patterns of package names that are never kept from a lockfile. */
  dependencyExclude?: string[];
  /** Looks the lockfile packages up on the network; absent: nothing is looked up. */
  lookup?: DependencyLookup;
}

/** What a lookup of the lockfile packages found, as the snapshot stores it. */
export interface DependencyTables {
  advisories: RawAdvisory[];
  vulnerablePackages: RawVulnerablePackage[];
}

/**
 * The step of a project scan that asks public sources about the packages of
 * the lockfiles. This module makes no request: whoever starts the scan hands
 * the step in (`src/main.ts` builds it), and without one nothing is looked
 * up, no check of a lookup is recorded and the rules that read its answers
 * are left out.
 */
export interface DependencyLookup {
  /** False when the user turned the lookup off (`--no-dependency-check`); the snapshot records it. */
  readonly enabled: boolean;
  /** The checks it records, so that no other part of a scan uses their ids. */
  readonly checks: readonly CheckDefinition[];
  /**
   * Looks up the packages the lockfile step kept for these projects and
   * records its own checks: as ran, or as skipped with the reason. It never
   * throws for a source that fails; it then returns nothing of that source.
   */
  run(projects: readonly RawProject[], recorder: CheckRecorder): Promise<DependencyTables>;
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
  /**
   * How the npm lockfiles were collected; its id must stay
   * `collect.dependencies`, which the dependency rules require. Default: the
   * check of a local folder.
   */
  dependenciesCheck?: CheckDefinition;
  /** The CF API the files were read through (deployed apps); absent for a local folder. */
  apiEndpoint?: URL;
  now?: () => Date;
  log?: (message: string) => void;
  /**
   * Called once the files are collected and before the rules run, with the
   * projects that were read. Absent: nothing is looked up.
   */
  lookup?: DependencyLookup;
}

/**
 * Findings, inventory rows and checks are keyed by id. Two projects with one
 * id would merge their rows, and a skip recorded under the id of the
 * collection itself (or of its lockfile check) would replace that result and
 * turn the rules that need it into "dependency skipped". Either is a mistake
 * of the caller, never of the data.
 */
function assertDistinctIds(own: CheckDefinition[], collection: ProjectCollection): void {
  const projectIds = new Set(collection.projects.map((project) => project.id));
  if (projectIds.size !== collection.projects.length) {
    throw new Error('two projects of one scan have the same id');
  }
  const checks = [...own, ...collection.notRead.map((item) => item.check)];
  if (new Set(checks.map((check) => check.id)).size !== checks.length) {
    throw new Error('two checks of one project scan have the same id');
  }
}

const NOTHING_LOOKED_UP: DependencyTables = { advisories: [], vulnerablePackages: [] };

/**
 * The npm lockfiles of one project in a line, or undefined when it has none
 * (a yarn or pnpm lockfile is not read, so it is not one): counts only, never
 * a package name. A linked local folder (`link`) is code of the project, not
 * a package that was left unchecked, so it is not in the second count.
 */
function lockfileLine(project: RawProject): string | undefined {
  const dependencies = project.dependencies;
  if (dependencies === null) return undefined;
  const npm = dependencies.lockfiles.filter((lockfile) => lockfile.status !== 'unsupported');
  if (npm.length === 0 && dependencies.lockfilesNotRead === 0) return undefined;
  const read = npm.filter((lockfile) => lockfile.status === 'read');
  const notChecked = read
    .flatMap((lockfile) => Object.entries(lockfile.notKept))
    .reduce((sum, [reason, count]) => (reason === 'link' ? sum : sum + count), 0);
  return (
    `Read ${read.length} npm lockfile(s): ${dependencies.packages.length} package(s) ` +
    `from the public npm registry, ${notChecked} other package(s) not checked`
  );
}

/**
 * Runs one project collection, the lookup of the lockfile packages when the
 * caller handed one in, and the project rules, and builds the snapshot.
 * Shared by a local folder and deployed apps: the collection hands over its
 * results and the lookup its answers, and this module makes no request
 * itself. The log carries counts and project ids only, never a path or file
 * content.
 */
export async function projectSnapshot(
  collect: () => Promise<ProjectCollection>,
  options: ProjectSnapshotOptions,
): Promise<Snapshot> {
  const log = options.log ?? (() => {});
  const scannedAt = (options.now?.() ?? new Date()).toISOString();

  const recorder = new CheckRecorder({ deep: false }, log);
  const collected = await recorder.run(options.check, collect);
  // The lockfiles are read with the other files: they were read when the collection ran.
  const dependenciesCheck = options.dependenciesCheck ?? COLLECTOR_CHECKS.dependencies;
  if (collected === undefined) {
    recorder.skip(
      dependenciesCheck,
      'dependency_skipped',
      `needs ${options.check.id}, which did not run`,
    );
  } else {
    recorder.ran(dependenciesCheck);
  }
  const collection = collected ?? { projects: [], notRead: [] };
  const { lookup } = options;
  assertDistinctIds([options.check, dependenciesCheck, ...(lookup?.checks ?? [])], collection);
  const { projects } = collection;
  for (const project of projects) {
    log(
      `Read ${project.filesOpened} project file(s)` +
        `${project.unreadable.length > 0 ? `, ${project.unreadable.length} unreadable` : ''}` +
        ` in project ${project.id}`,
    );
    const lockfiles = lockfileLine(project);
    if (lockfiles !== undefined) log(lockfiles);
  }
  // After the collection's own check, so that the checks keep the order of the apps.
  for (const item of collection.notRead) recorder.skip(item.check, item.reasonCode, item.reason);
  // Its checks come after those of the files it depends on, and before the rules that read its answers.
  const found = lookup === undefined ? NOTHING_LOOKED_UP : await lookup.run(projects, recorder);

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
    advisories: found.advisories,
    vulnerablePackages: found.vulnerablePackages,
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
    options: { ...DEFAULT_SNAPSHOT_OPTIONS, dependencyCheck: lookup?.enabled ?? false },
    checks: [...collectorChecks, ...analysis.ruleChecks],
    raw,
    apps: analysis.apps,
    findings: analysis.findings,
  };
}

/**
 * Scans a local CAP / MTA project directory: file-system reads only, no
 * child processes, and no request of its own. The packages of its lockfiles
 * are looked up on the network only by the `lookup` the caller hands in.
 */
export async function scanProject(options: ScanProjectOptions): Promise<Snapshot> {
  const excludeDirs = options.outDir === undefined ? [] : [resolve(options.outDir)];
  const { dependencyExclude } = options;
  const collect = async (): Promise<ProjectCollection> => ({
    projects: [await collectProject(options.path, { excludeDirs, dependencyExclude })],
    notRead: [],
  });
  return projectSnapshot(collect, {
    check: COLLECTOR_CHECKS.project,
    dependenciesCheck: COLLECTOR_CHECKS.dependencies,
    now: options.now,
    log: options.log,
    lookup: options.lookup,
  });
}
