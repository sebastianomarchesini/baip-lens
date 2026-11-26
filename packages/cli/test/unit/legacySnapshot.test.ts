import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { reanalyze } from '../../src/analyzers/index.js';
import { ReportDataSchema, type Snapshot, SnapshotSchema } from '../../src/model/snapshot.js';
import { toReportData } from '../../src/reporters/reportData.js';

/**
 * A snapshot written by btp-lens 0.1.0 (the tool's name before it became BAIP Lens),
 * frozen (never regenerated). Newer
 * versions must keep reading it: the schema version stays 1, new fields are
 * optional or defaulted, and `report --from` gives the same findings.
 */
const legacy: unknown = JSON.parse(
  readFileSync(new URL('../fixtures/legacy/snapshot-0.1.0.json', import.meta.url), 'utf8'),
);

describe('0.1.0 snapshot compatibility', () => {
  it('still parses, with the new fields defaulted', () => {
    const parsed = SnapshotSchema.safeParse(legacy);
    expect(parsed.success).toBe(true);
    const snapshot = parsed.data as Snapshot;
    expect(snapshot.raw.projects).toEqual([]);
    // Nothing was looked up when it was written, and nothing says it was.
    expect(snapshot.raw.advisories).toEqual([]);
    expect(snapshot.raw.vulnerablePackages).toEqual([]);
    expect(snapshot.raw.deprecations).toEqual([]);
    expect(snapshot.options.dependencyCheck).toBe(false);
    expect(snapshot.apps.every((app) => app.kind === 'app')).toBe(true);
    expect(snapshot.scope.apiEndpoint).toBe('https://api.cf.example.org/');
    expect(snapshot.tool.name).toBe('btp-lens');
  });

  it('re-analyzes to the same three findings and omits the project rules', () => {
    const snapshot = SnapshotSchema.parse(legacy);
    const result = reanalyze(snapshot);
    expect(result.findings).toHaveLength(3);
    expect(result.findings).toEqual(snapshot.findings);
    expect(result.checks.map((c) => c.id)).toEqual([
      'collect.apps',
      'collect.droplets',
      'rule.APP_NO_RECENT_DEPLOY',
    ]);
  });

  it('produces valid report data', () => {
    const data = toReportData(reanalyze(SnapshotSchema.parse(legacy)));
    expect(ReportDataSchema.safeParse(data).success).toBe(true);
    expect(data.summary).toMatchObject({ apps: 8, projects: 0, findings: 3 });
  });
});

/**
 * A project snapshot written before the npm lockfiles were read (the sample of
 * 0.3.1, frozen, never regenerated). It has neither `collect.dependencies`
 * nor `raw.projects[].dependencies`, so reading it again must not make it
 * look as if its dependencies had been checked.
 */
const legacyProject: unknown = JSON.parse(
  readFileSync(new URL('../fixtures/legacy/project-snapshot-0.3.1.json', import.meta.url), 'utf8'),
);

describe('0.3.1 project snapshot compatibility', () => {
  it('still parses, with the dependencies of its project defaulted to "not collected"', () => {
    const parsed = SnapshotSchema.safeParse(legacyProject);
    expect(parsed.success).toBe(true);
    const snapshot = parsed.data as Snapshot;
    expect(snapshot.schemaVersion).toBe(1);
    expect(snapshot.tool).toEqual({ name: 'baip-lens', version: '0.3.1' });
    expect(snapshot.raw.projects).toHaveLength(1);
    expect(snapshot.raw.projects[0]?.dependencies).toBeNull();
    expect(snapshot.checks.some((check) => check.id === 'collect.dependencies')).toBe(false);
    // Its packages were never looked up either: no table, no check, and the option says so.
    expect(snapshot.raw.advisories).toEqual([]);
    expect(snapshot.raw.vulnerablePackages).toEqual([]);
    expect(snapshot.raw.deprecations).toEqual([]);
    expect(snapshot.options.dependencyCheck).toBe(false);
    expect(snapshot.checks.some((check) => check.id === 'collect.osv')).toBe(false);
    expect(snapshot.checks.some((check) => check.id === 'collect.npm-deprecations')).toBe(false);
  });

  it('re-analyzes to the same findings, and gains no dependency rule', () => {
    const snapshot = SnapshotSchema.parse(legacyProject);
    const result = reanalyze(snapshot);
    expect(result.findings).toHaveLength(17);
    expect(result.findings).toEqual(snapshot.findings);
    expect(result.apps).toEqual(snapshot.apps);
    // The same checks as when it was written: the collector and the thirteen project rules.
    expect(result.checks).toEqual(snapshot.checks);
    expect(result.checks).toHaveLength(14);
    expect(result.checks.some((check) => check.id.startsWith('rule.DEP_'))).toBe(false);
    expect(result.findings.some((finding) => finding.id.startsWith('DEP_'))).toBe(false);
    expect(result.checks.some((check) => check.id === 'collect.osv')).toBe(false);
    expect(result.checks.some((check) => check.id === 'collect.npm-deprecations')).toBe(false);
  });

  it('produces valid report data that lists the dependency rules without having run them', () => {
    const data = toReportData(reanalyze(SnapshotSchema.parse(legacyProject)));
    expect(ReportDataSchema.safeParse(data).success).toBe(true);
    expect(data.summary).toMatchObject({ apps: 0, projects: 1, findings: 17, checksSkipped: 0 });
    // Every report names every rule this version knows; whether one ran is in `checks`.
    expect(data.rules.map((rule) => rule.id)).toContain('DEP_LOCKFILE_MISSING');
    expect(data.checks.map((check) => check.id)).not.toContain('rule.DEP_LOCKFILE_MISSING');
  });
});
