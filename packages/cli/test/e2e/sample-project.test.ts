import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createDependencyLookup } from '../../src/dependencyCheck.js';
import { ReportDataSchema, SnapshotSchema } from '../../src/model/snapshot.js';
import { scanProject } from '../../src/project.js';
import { renderJson } from '../../src/reporters/json.js';
import { toReportData } from '../../src/reporters/reportData.js';
import { TOOL_NAME, TOOL_VERSION } from '../../src/version.js';
import {
  ACME_KNOWN_CVE,
  ACME_OSV_SCRIPT,
  osvFetch,
  registryCalls,
} from '../support/dependencyScript.js';
import { noSleep } from '../support/fakeFetch.js';
import { NOW } from '../support/project.js';
import { type MaterializedFixture, materializeFixture } from '../support/projectFixture.js';

/**
 * Golden files built from the acme-incidents project fixture:
 *  - test/fixtures/sample-project-snapshot.json feeds `npm run sample`;
 *  - packages/ui/src/test/fixtures/report-project.json is the UI's test data
 *    for a project scan.
 * Regenerate both with `UPDATE_SAMPLE=1 npm test -w baip-lens`.
 *
 * The packages of the fixture's lockfile are looked up as `baip-lens project`
 * does it, on a scripted OSV.dev and a scripted npm registry
 * (test/support/dependencyScript.ts): the advisories of the sample are
 * invented, the registry of `osvFetch` marks no version as deprecated, and
 * no request leaves the test.
 */
const SAMPLE_SNAPSHOT = fileURLToPath(
  new URL('../fixtures/sample-project-snapshot.json', import.meta.url),
);
const UI_REPORT = fileURLToPath(
  new URL('../../../ui/src/test/fixtures/report-project.json', import.meta.url),
);

async function readOrEmpty(path: string): Promise<string> {
  try {
    return await readFile(path, 'utf8');
  } catch {
    return '';
  }
}

describe('sample project data', () => {
  let fixture: MaterializedFixture;
  beforeAll(async () => {
    fixture = await materializeFixture('acme-incidents');
  });
  afterAll(() => fixture.cleanup());

  it('matches the committed sample project snapshot and UI report fixture', async () => {
    const osv = osvFetch(ACME_OSV_SCRIPT);
    const snapshot = await scanProject({
      path: fixture.root,
      now: () => new Date(NOW),
      lookup: createDependencyLookup({
        enabled: true,
        userAgent: `${TOOL_NAME}/${TOOL_VERSION}`,
        fetch: osv.fetch,
        sleep: noSleep,
      }),
    });
    const snapshotJson = `${JSON.stringify(snapshot, null, 2)}\n`;
    const reportJson = renderJson(toReportData(snapshot));

    if (process.env.UPDATE_SAMPLE) {
      for (const [path, content] of [
        [SAMPLE_SNAPSHOT, snapshotJson],
        [UI_REPORT, reportJson],
      ] as const) {
        await mkdir(dirname(path), { recursive: true });
        await writeFile(path, content, 'utf8');
      }
    }

    // The sample shows the lookup: it ran, and every case of the script is a finding.
    expect(osv.calls.length).toBeGreaterThan(0);
    expect(snapshot.options.dependencyCheck).toBe(true);
    expect(snapshot.checks.find((check) => check.id === 'collect.osv')?.status).toBe('ran');
    // The second source was asked as well, and its check ran.
    expect(registryCalls(osv).length).toBeGreaterThan(0);
    expect(snapshot.checks.find((check) => check.id === 'collect.npm-deprecations')?.status).toBe(
      'ran',
    );
    expect(
      snapshot.findings
        .filter((finding) => finding.id === 'DEP_KNOWN_CVE')
        .map((f) => [f.severity, f.evidence.subject, f.evidence.fixedIn, f.evidence.severityFrom]),
    ).toEqual(ACME_KNOWN_CVE);

    expect(SnapshotSchema.safeParse(JSON.parse(snapshotJson)).success).toBe(true);
    expect(ReportDataSchema.safeParse(JSON.parse(reportJson)).success).toBe(true);
    expect(await readOrEmpty(SAMPLE_SNAPSHOT), 'run UPDATE_SAMPLE=1 npm test -w baip-lens').toBe(
      snapshotJson,
    );
    expect(await readOrEmpty(UI_REPORT), 'run UPDATE_SAMPLE=1 npm test -w baip-lens').toBe(
      reportJson,
    );
  });
});
