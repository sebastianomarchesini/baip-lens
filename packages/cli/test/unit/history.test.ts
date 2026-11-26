import { describe, expect, it } from 'vitest';
import {
  carryHistory,
  checkPrevious,
  checkPreviousOrg,
  observe,
  previousHistory,
} from '../../src/history.js';
import { ConfigError } from '../../src/http/errors.js';
import type { RawApp, RawData, RawHistory, RawTraffic } from '../../src/model/raw.js';
import { DEFAULT_SNAPSHOT_OPTIONS, type Snapshot } from '../../src/model/snapshot.js';

const NOW = '2026-09-29T00:00:00.000Z';
const hoursBefore = (hours: number, from = NOW) =>
  new Date(Date.parse(from) - hours * 3_600_000).toISOString();
const daysBefore = (days: number, from = NOW) => hoursBefore(days * 24, from);

const S1 = 'space-1';
const S2 = 'space-2';

/** An app whose name differs from its GUID, so nothing can match by name by accident. */
function app(
  guid: string,
  spaceGuid = S1,
  name = `app-named-${guid}`,
  state: RawApp['state'] = 'STARTED',
): RawApp {
  return {
    guid,
    name,
    spaceGuid,
    state,
    createdAt: '2025-01-01T00:00:00Z',
    updatedAt: '2026-09-01T00:00:00Z',
    lifecycleType: 'buildpack',
    buildpacks: [],
    stack: 'cflinuxfs4',
  };
}

const silent = (appGuid: string, windowHours: number, at = NOW): RawTraffic => ({
  appGuid,
  lastRequestAt: null,
  windowStart: hoursBefore(windowHours, at),
  envelopesExamined: 50,
});
const busy = (appGuid: string, lastRequestAt: string): RawTraffic => ({
  appGuid,
  lastRequestAt,
  windowStart: hoursBefore(2),
  envelopesExamined: 3,
});

function raw(apps: (string | RawApp)[], traffic: RawTraffic[] = []): RawData {
  return {
    orgs: [{ guid: 'o1', name: 'acme-prod' }],
    spaces: [],
    apps: apps.map((a) => (typeof a === 'string' ? app(a) : a)),
    droplets: [],
    routes: [],
    processes: [],
    traffic,
    history: [],
    projects: [],
    advisories: [],
    vulnerablePackages: [],
    deprecations: [],
  };
}

function snapshot(scannedAt: string, data: RawData, minTrafficWindowHours = 12): Snapshot {
  return {
    schemaVersion: 1,
    tool: { name: 'baip-lens', version: '0.2.0' },
    scannedAt,
    scope: { apiEndpoint: 'https://api.cf.example.org/', orgs: ['acme-prod'] },
    options: { ...DEFAULT_SNAPSHOT_OPTIONS, trafficCheck: true, minTrafficWindowHours },
    checks: [],
    raw: data,
    apps: [],
    findings: [],
  };
}

const entry = (
  appGuid: string,
  scansWithoutTraffic: number,
  firstScanWithoutTraffic: string | null,
  lastRequestEverSeen: string | null = null,
  spaceGuid = S1,
): RawHistory => ({
  appGuid,
  spaceGuid,
  lastRequestEverSeen,
  firstScanWithoutTraffic,
  scansWithoutTraffic,
});

/** A week before NOW, holding these history entries. */
const previousWith = (history: RawHistory[], apps: (string | RawApp)[] = []) =>
  snapshot(daysBefore(7), { ...raw(apps), history });

const historyOf = (...args: Parameters<typeof carryHistory>) => carryHistory(...args).history;

describe('observe', () => {
  it('counts a request, and silence only over at least the minimum window (D8)', () => {
    expect(observe(busy('a', hoursBefore(1)), NOW, 12)).toEqual({
      kind: 'request',
      at: hoursBefore(1),
    });
    expect(observe(silent('a', 12), NOW, 12)).toEqual({ kind: 'silence' });
    expect(observe(silent('a', 11.9), NOW, 12)).toEqual({ kind: 'none' });
    expect(observe(silent('a', 4), NOW, 4)).toEqual({ kind: 'silence' });
  });

  it('says nothing for an app that was not read or whose cache was empty', () => {
    expect(observe(undefined, NOW, 12)).toEqual({ kind: 'none' });
    const empty = { appGuid: 'a', lastRequestAt: null, windowStart: null, envelopesExamined: 0 };
    expect(observe(empty, NOW, 12)).toEqual({ kind: 'none' });
  });
});

describe('carryHistory', () => {
  it('starts a run of silent scans, and a request ends it', () => {
    expect(
      historyOf(raw(['a', 'b'], [silent('a', 20), busy('b', hoursBefore(1))]), NOW, 12),
    ).toEqual([entry('a', 1, NOW), entry('b', 0, null, hoursBefore(1))]);
  });

  it('extends a run from the previous snapshot and keeps where it began', () => {
    const previous = previousWith([entry('a', 5, daysBefore(42))]);
    expect(carryHistory(raw(['a'], [silent('a', 20)]), NOW, 12, previous)).toEqual({
      history: [entry('a', 6, daysBefore(42))],
      matched: 1,
      kept: 0,
      dropped: 0,
    });
  });

  it('ends a run on a request and keeps the newest request ever seen', () => {
    const previous = previousWith([
      entry('a', 4, daysBefore(30), daysBefore(31)),
      entry('b', 0, null, hoursBefore(3)),
    ]);
    // b's request in this window is older than the one seen before: the newer one stays.
    const now = raw(['a', 'b'], [busy('a', hoursBefore(1)), busy('b', hoursBefore(5))]);
    expect(historyOf(now, NOW, 12, previous)).toEqual([
      entry('a', 0, null, hoursBefore(1)),
      entry('b', 0, null, hoursBefore(3)),
    ]);
  });

  it('carries a run unchanged through a scan that could not tell (D8)', () => {
    const run = entry('a', 3, daysBefore(20));
    const previous = previousWith([run]);
    // A short window, and no read at all: neither counts nor ends the run.
    expect(historyOf(raw(['a'], [silent('a', 4)]), NOW, 12, previous)).toEqual([run]);
    expect(historyOf(raw(['a']), NOW, 12, previous)).toEqual([run]);
  });

  it('carries the run of a stopped app unchanged: the scan never reads its traffic (D8)', () => {
    // The scan asks Log Cache only about started non-workers with an HTTP
    // route, so a stopped app, a worker or an app without one has no traffic.
    const run = entry('a', 3, daysBefore(20), daysBefore(25));
    const stopped = app('a', S1, 'app-named-a', 'STOPPED');
    expect(historyOf(raw([stopped, 'b'], [silent('b', 20)]), NOW, 12, previousWith([run]))).toEqual(
      [run, entry('b', 1, NOW)],
    );
  });

  it('matches by GUID, never by name: a renamed app keeps its run, a re-pushed one starts over', () => {
    const previous = previousWith(
      [entry('g-old', 5, daysBefore(40)), entry('g-kept', 2, daysBefore(14))],
      [app('g-old', S1, 'shop'), app('g-kept', S1, 'cart')],
    );
    // 'shop' was deleted and pushed again (new GUID); 'cart' was renamed.
    const now = raw(
      [app('g-new', S1, 'shop'), app('g-kept', S1, 'cart-v2')],
      [silent('g-new', 20), silent('g-kept', 20)],
    );
    expect(carryHistory(now, NOW, 12, previous)).toEqual({
      history: [entry('g-kept', 3, daysBefore(14)), entry('g-new', 1, NOW)],
      matched: 1,
      kept: 0,
      dropped: 1,
    });
  });

  it('drops the entry of an app gone from a space whose apps were read', () => {
    const previous = previousWith([entry('gone', 9, daysBefore(90))]);
    expect(carryHistory(raw(['new'], [silent('new', 20)]), NOW, 12, previous)).toEqual({
      history: [entry('new', 1, NOW)],
      matched: 0,
      kept: 0,
      dropped: 1,
    });
  });

  it('keeps the entries of apps in spaces this scan did not read (--space, no access)', () => {
    const elsewhere = entry('p', 4, daysBefore(30), null, S2);
    const previous = previousWith([elsewhere, entry('a', 1, daysBefore(7))]);
    expect(carryHistory(raw(['a'], [silent('a', 20)]), NOW, 12, previous)).toEqual({
      history: [entry('a', 2, daysBefore(7)), elsewhere],
      matched: 1,
      kept: 1,
      dropped: 0,
    });
  });

  it('keeps every entry when the inventory could not be read in full', () => {
    const history = [entry('a', 2, daysBefore(7)), entry('gone', 9, daysBefore(90))];
    // Not read at all, and read with an app missing (an unexpected shape).
    expect(carryHistory(raw([]), NOW, 12, previousWith(history), false)).toEqual({
      history,
      matched: 0,
      kept: 2,
      dropped: 0,
    });
    expect(historyOf(raw(['a'], [silent('a', 20)]), NOW, 12, previousWith(history), false)).toEqual(
      [entry('a', 3, daysBefore(7)), entry('gone', 9, daysBefore(90))],
    );
  });

  it('carries only the fields it knows, also for an entry carried unchanged', () => {
    const extra = { ...entry('a', 3, daysBefore(20)), owner: 'jane.doe@example.com' };
    const elsewhere = { ...entry('p', 1, daysBefore(7), null, S2), note: 'secret' };
    const result = historyOf(raw(['a']), NOW, 12, previousWith([extra, elsewhere]));
    expect(result).toEqual([entry('a', 3, daysBefore(20)), entry('p', 1, daysBefore(7), null, S2)]);
    expect(JSON.stringify(result)).not.toMatch(/jane|secret/);
  });

  it('is sorted by app, whatever the inventory order', () => {
    const data = raw(['c', 'a', 'b'], [silent('c', 20), silent('a', 20), silent('b', 20)]);
    expect(historyOf(data, NOW, 12).map((h) => h.appGuid)).toEqual(['a', 'b', 'c']);
  });
});

describe('previousHistory', () => {
  it('uses the history a snapshot carries, without applying its traffic again', () => {
    const history = [entry('a', 2, daysBefore(10))];
    // The scan that wrote this history saw a's silence: applying it again would count it twice.
    const previous = snapshot(daysBefore(1), {
      ...raw(['a'], [silent('a', 20, daysBefore(1))]),
      history,
    });
    expect(previousHistory(previous)).toEqual(history);
    expect(previousHistory(undefined)).toEqual([]);
  });

  it('derives it for a snapshot written before the history existed, with its own minimum', () => {
    const at = daysBefore(7);
    const previous = snapshot(
      at,
      raw(
        ['a', app('b', S2), 'c'],
        [silent('a', 20, at), busy('b', hoursBefore(1, at)), silent('c', 6, at)],
      ),
      4,
    );
    // c's 6 hours count under that scan's own 4-hour minimum.
    expect(previousHistory(previous)).toEqual([
      entry('a', 1, at),
      entry('b', 0, null, hoursBefore(1, at), S2),
      entry('c', 1, at),
    ]);
  });
});

describe('checkPrevious', () => {
  const api = new URL('https://api.cf.example.org');
  const before = snapshot(daysBefore(7), raw(['a']));

  it('accepts an earlier scan of the same API endpoint', () => {
    expect(() => checkPrevious(before, { apiUrl: api, scannedAt: NOW })).not.toThrow();
    // The endpoint is compared as a URL, so a trailing slash makes no difference.
    expect(() =>
      checkPrevious(before, { apiUrl: new URL('https://API.cf.example.org/'), scannedAt: NOW }),
    ).not.toThrow();
  });

  it('refuses another endpoint, a project scan and a snapshot that is not older', () => {
    const other = new URL('https://api.cf.other.example.org');
    expect(() => checkPrevious(before, { apiUrl: other, scannedAt: NOW })).toThrow(ConfigError);
    expect(() => checkPrevious(before, { apiUrl: other, scannedAt: NOW })).toThrow(
      /of https:\/\/api\.cf\.example\.org\/, not https:\/\/api\.cf\.other\.example\.org\//,
    );
    const project = { ...before, scope: { orgs: [], projects: ['p'] } };
    expect(() => checkPrevious(project, { apiUrl: api, scannedAt: NOW })).toThrow(/project scan/);
    // `project --cf` read a deployed app through the same API: still a project scan, refused
    // before any request rather than after the org lookup.
    const deployedApp = {
      ...before,
      scope: { apiEndpoint: api.href, orgs: [], projects: ['incidents-srv'] },
    };
    expect(() => checkPrevious(deployedApp, { apiUrl: api, scannedAt: NOW })).toThrow(
      /project scan/,
    );
    expect(() => checkPrevious(before, { apiUrl: api, scannedAt: daysBefore(7) })).toThrow(
      /not before this scan/,
    );
    expect(() => checkPrevious(before, { apiUrl: api, scannedAt: daysBefore(8) })).toThrow(
      ConfigError,
    );
  });
});

describe('checkPreviousOrg', () => {
  const before = snapshot(daysBefore(7), raw(['a']));

  it('matches the org by GUID, so a renamed org still matches', () => {
    expect(() => checkPreviousOrg(before, { guid: 'o1', name: 'acme-renamed' })).not.toThrow();
  });

  it('refuses another org, even one with the same name', () => {
    expect(() => checkPreviousOrg(before, { guid: 'o2', name: 'acme-prod' })).toThrow(ConfigError);
    expect(() => checkPreviousOrg(before, { guid: 'o2', name: 'acme-prod' })).toThrow(
      /of another org named "acme-prod"/,
    );
  });

  it('falls back to the name for a snapshot that carries no org GUID', () => {
    const nameOnly = { ...before, raw: { ...before.raw, orgs: [] } };
    expect(() => checkPreviousOrg(nameOnly, { guid: 'o9', name: 'acme-prod' })).not.toThrow();
    expect(() => checkPreviousOrg(nameOnly, { guid: 'o9', name: 'other' })).toThrow(
      /of acme-prod, not of the org "other"/,
    );
  });
});
