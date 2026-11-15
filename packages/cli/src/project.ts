import { resolve } from 'node:path';
import { analyze } from './analyzers/index.js';
import { type CheckDefinition, CheckRecorder, COLLECTOR_CHECKS } from './checks.js';
import { collectProject } from './collectors/project/index.js';
import type { RawData, RawProject } from './model/raw.js';
import { SNAPSHOT_SCHEMA_VERSION, type Snapshot } from './model/snapshot.js';
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

export interface ProjectSnapshotOptions {
  /** How the files were collected; its id must stay `collect.project`, which the rules require. */
  check: CheckDefinition;
  /** The CF API the files were read through (a deployed app); absent for a local folder. */
  apiEndpoint?: URL;
  now?: () => Date;
  log?: (message: string) => void;
}

/**
 * Runs one project collection and the project rules, and builds the
 * snapshot. Shared by a local folder and a deployed app; the log carries
 * counts and the project id only, never a path or file content.
 */
export async function projectSnapshot(
  collect: () => Promise<RawProject>,
  options: ProjectSnapshotOptions,
): Promise<Snapshot> {
  const log = options.log ?? (() => {});
  const scannedAt = (options.now?.() ?? new Date()).toISOString();

  const recorder = new CheckRecorder({ deep: false }, log);
  const project: RawProject | undefined = await recorder.run(options.check, collect);
  const projects = project === undefined ? [] : [project];
  if (project !== undefined) {
    log(
      `Read ${project.filesOpened} project file(s)` +
        `${project.unreadable.length > 0 ? `, ${project.unreadable.length} unreadable` : ''}` +
        ` in project ${project.id}`,
    );
  }

  const raw: RawData = { orgs: [], spaces: [], apps: [], droplets: [], projects };
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
    options: { deep: false, probeRoutes: false },
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
  return projectSnapshot(() => collectProject(options.path, { excludeDirs }), {
    check: COLLECTOR_CHECKS.project,
    now: options.now,
    log: options.log,
  });
}
