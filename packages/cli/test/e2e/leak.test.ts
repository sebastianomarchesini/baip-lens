import { mkdtemp, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DATA_PLACEHOLDER } from '../../src/reporters/html.js';
import { writeReports } from '../../src/reporters/index.js';
import { toReportData } from '../../src/reporters/reportData.js';
import { scan } from '../../src/scan.js';
import { readSnapshot, writeSnapshot } from '../../src/snapshot.js';
import { ACME, ACME_PREVIOUS_PATH, ACME_TRAFFIC_APPS, acmeFetch } from '../support/acme.js';
import { ABSOLUTE_PATH, expectNoLeaks } from '../support/leak.js';

describe('no secrets or personal data in any output', () => {
  it('keeps poison values out of the snapshot and every report format', async () => {
    const out = await mkdtemp(join(tmpdir(), 'baip-lens-leak-'));
    const fake = acmeFetch();
    const logs: string[] = [];
    const snapshot = await scan({
      apiUrl: ACME.api,
      org: ACME.org,
      deep: false,
      probeRoutes: true,
      concurrency: 5,
      env: { BAIP_LENS_ACCESS_TOKEN: ACME.token },
      fetch: fake.fetch,
      now: () => ACME.now,
      log: (message) => logs.push(message),
    });
    // The router log with the client address, path and user agent was really
    // read and understood, so its absence below means it was dropped.
    expect(
      fake.calls.some((c) => c.url.pathname === `/api/v1/read/${ACME_TRAFFIC_APPS['orders-srv']}`),
    ).toBe(true);
    expect(
      snapshot.raw.traffic.find((t) => t.appGuid === ACME_TRAFFIC_APPS['orders-srv'])
        ?.lastRequestAt,
    ).toBe('2026-09-28T23:50:00.000Z');
    // So was the HTTP timer, with the same kind of tags, that starts docs-static's window.
    expect(
      fake.calls.some(
        (c) =>
          c.url.pathname === `/api/v1/read/${ACME_TRAFFIC_APPS['docs-static']}` &&
          c.url.searchParams.get('limit') === '1',
      ),
    ).toBe(true);
    expect(
      snapshot.raw.traffic.find((t) => t.appGuid === ACME_TRAFFIC_APPS['docs-static'])?.windowStart,
    ).toBe('2026-09-28T20:00:00.000Z');
    await writeSnapshot(snapshot, out);
    await writeReports(toReportData(snapshot), ['html', 'json', 'csv', 'sarif'], out, {
      htmlTemplate: `<html><body>${DATA_PLACEHOLDER}</body></html>`,
    });

    const files = await readdir(out);
    expect(files).toHaveLength(6);
    const texts: Record<string, string> = {};
    for (const file of files) texts[file] = await readFile(join(out, file), 'utf8');
    // What the scan printed while it ran, too.
    expect(logs.length).toBeGreaterThan(0);
    texts['scan log'] = logs.join('\n');
    expectNoLeaks(texts, [...ACME.poison], [ABSOLUTE_PATH]);
  });

  it('carries nothing of a --previous snapshot but the history of apps still there', async () => {
    const out = await mkdtemp(join(tmpdir(), 'baip-lens-leak-previous-'));
    const logs: string[] = [];
    // Loaded the way `scan --previous` loads it. It holds an app that no longer
    // exists, and unknown fields with poison values on an entry this scan
    // rebuilds (orders-approuter) and on one it carries unchanged (docs-static).
    const previous = await readSnapshot(ACME_PREVIOUS_PATH);
    const snapshot = await scan({
      apiUrl: ACME.api,
      org: ACME.org,
      deep: false,
      probeRoutes: true,
      concurrency: 5,
      env: { BAIP_LENS_ACCESS_TOKEN: ACME.token },
      fetch: acmeFetch().fetch,
      now: () => ACME.now,
      log: (message) => logs.push(message),
      previous,
    });
    expect(snapshot.raw.history.map((h) => h.appGuid)).toContain(ACME_TRAFFIC_APPS['docs-static']);
    await writeSnapshot(snapshot, out);
    await writeReports(toReportData(snapshot), ['html', 'json', 'csv', 'sarif'], out, {
      htmlTemplate: `<html><body>${DATA_PLACEHOLDER}</body></html>`,
    });
    const texts: Record<string, string> = { 'scan log': logs.join('\n') };
    for (const file of await readdir(out)) texts[file] = await readFile(join(out, file), 'utf8');
    // Neither the gone app nor the old GUID of the app pushed again is carried.
    const gone = ['a99a0000-0000-4000-8000-0000000000ff', 'a99a0000-0000-4000-8000-0000000000fe'];
    expectNoLeaks(texts, [...ACME.poison, ...gone], [ABSOLUTE_PATH]);
  });
});
