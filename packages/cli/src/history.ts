import { ConfigError } from './http/errors.js';
import type { RawApp, RawData, RawHistory, RawOrg, RawTraffic } from './model/raw.js';
import type { Snapshot } from './model/snapshot.js';

const HOUR_MS = 60 * 60 * 1000;

/** What one scan saw of one app's traffic. */
export type Observation = { kind: 'request'; at: string } | { kind: 'silence' } | { kind: 'none' };

/**
 * A request in the window always counts. Silence counts only when the window
 * covers at least the minimum, the condition under which one scan alone
 * reports `no_traffic`; a shorter window, an empty cache or no read at all
 * says nothing either way (D8). The scan reads Log Cache only for started,
 * non-worker apps with an HTTP route, so a stopped app, a worker or an app
 * without an HTTP route has no traffic here and says nothing either.
 */
export function observe(
  traffic: RawTraffic | undefined,
  scannedAt: string,
  minWindowHours: number,
): Observation {
  if (traffic === undefined) return { kind: 'none' };
  if (traffic.lastRequestAt !== null) return { kind: 'request', at: traffic.lastRequestAt };
  if (traffic.windowStart === null) return { kind: 'none' };
  const windowMs = Date.parse(scannedAt) - Date.parse(traffic.windowStart);
  return windowMs >= minWindowHours * HOUR_MS ? { kind: 'silence' } : { kind: 'none' };
}

const newer = (a: string | null, b: string): string =>
  a !== null && Date.parse(a) >= Date.parse(b) ? a : b;

/** A copy with the schema's fields only, so nothing else is ever carried forward. */
const copy = (entry: RawHistory, spaceGuid = entry.spaceGuid): RawHistory => ({
  appGuid: entry.appGuid,
  spaceGuid,
  lastRequestEverSeen: entry.lastRequestEverSeen,
  firstScanWithoutTraffic: entry.firstScanWithoutTraffic,
  scansWithoutTraffic: entry.scansWithoutTraffic,
});

/** One app's history after one more scan. */
function advance(
  app: RawApp,
  before: RawHistory | undefined,
  observation: Observation,
  scannedAt: string,
): RawHistory | undefined {
  switch (observation.kind) {
    case 'none':
      return before === undefined ? undefined : copy(before, app.spaceGuid);
    case 'request':
      return {
        appGuid: app.guid,
        spaceGuid: app.spaceGuid,
        lastRequestEverSeen: newer(before?.lastRequestEverSeen ?? null, observation.at),
        firstScanWithoutTraffic: null,
        scansWithoutTraffic: 0,
      };
    case 'silence': {
      const running =
        before !== undefined &&
        before.scansWithoutTraffic > 0 &&
        before.firstScanWithoutTraffic !== null;
      return {
        appGuid: app.guid,
        spaceGuid: app.spaceGuid,
        lastRequestEverSeen: before?.lastRequestEverSeen ?? null,
        firstScanWithoutTraffic: running ? before.firstScanWithoutTraffic : scannedAt,
        scansWithoutTraffic: (running ? before.scansWithoutTraffic : 0) + 1,
      };
    }
  }
}

/** The history a scan writes, and what became of the previous one. */
export interface CarriedHistory {
  history: RawHistory[];
  /** Previous entries of apps in this inventory, matched by GUID. */
  matched: number;
  /** Previous entries of apps this scan could not see, carried unchanged. */
  kept: number;
  /** Previous entries of apps gone from a space whose apps this scan read. */
  dropped: number;
}

/**
 * The traffic history a snapshot carries: the previous scan's, advanced by
 * what this scan saw. Apps are matched by GUID, never by name. An app this
 * scan cannot see keeps its entry unchanged (D8: no read): its space was
 * outside `--space`, none of its space's apps were visible, or the inventory
 * could not be read in full (`inventoryComplete` false). An entry is dropped
 * only when this scan read other apps of the same space but not this one:
 * the app is gone, as after a blue-green deployment, and a new GUID starts
 * a new history. Without a previous snapshot, the history is this scan's own
 * observations.
 */
export function carryHistory(
  raw: RawData,
  scannedAt: string,
  minWindowHours: number,
  previous?: Snapshot,
  inventoryComplete = true,
): CarriedHistory {
  const carried = previousHistory(previous);
  const before = new Map(carried.map((entry) => [entry.appGuid, entry]));
  const traffic = new Map(raw.traffic.map((entry) => [entry.appGuid, entry]));
  const history: RawHistory[] = [];
  for (const app of raw.apps) {
    const observation = observe(traffic.get(app.guid), scannedAt, minWindowHours);
    const entry = advance(app, before.get(app.guid), observation, scannedAt);
    if (entry !== undefined) history.push(entry);
  }
  const listed = new Set(raw.apps.map((app) => app.guid));
  // Visibility is per space: seeing one of a space's apps means seeing them all.
  const readSpaces = new Set(inventoryComplete ? raw.apps.map((app) => app.spaceGuid) : []);
  const result: CarriedHistory = { history, matched: 0, kept: 0, dropped: 0 };
  for (const entry of carried) {
    if (listed.has(entry.appGuid)) {
      result.matched += 1;
    } else if (readSpaces.has(entry.spaceGuid)) {
      result.dropped += 1;
    } else {
      result.kept += 1;
      history.push(copy(entry));
    }
  }
  history.sort((a, b) => a.appGuid.localeCompare(b.appGuid));
  return result;
}

/**
 * The history the previous snapshot ends with. A snapshot written before
 * the history existed still contributes what its own scan saw, judged by its
 * own minimum window.
 */
export function previousHistory(previous: Snapshot | undefined): RawHistory[] {
  if (previous === undefined) return [];
  if (previous.raw.history.length > 0) return previous.raw.history;
  return carryHistory(previous.raw, previous.scannedAt, previous.options.minTrafficWindowHours)
    .history;
}

/**
 * Before any request: the previous snapshot must be an earlier Cloud Foundry
 * scan of the same API endpoint. A mismatch is a configuration error (exit
 * code 2), never a silent fresh start.
 */
export function checkPrevious(
  previous: Snapshot,
  current: { apiUrl: URL; scannedAt: string },
): void {
  const endpoint = previous.scope.apiEndpoint;
  // A project scan: of a folder (no endpoint), or of a deployed app (`project --cf`:
  // an endpoint, but no org). A scan of an org always names its org.
  if (endpoint === undefined || previous.scope.orgs.length === 0) {
    throw new ConfigError(
      'The --previous snapshot is a project scan; it needs a scan of a Cloud Foundry org.',
    );
  }
  if (new URL(endpoint).href !== current.apiUrl.href) {
    throw new ConfigError(
      `The --previous snapshot is of ${endpoint}, not ${current.apiUrl.href}; give a snapshot of the same API endpoint.`,
    );
  }
  if (Date.parse(previous.scannedAt) >= Date.parse(current.scannedAt)) {
    throw new ConfigError(
      `The --previous snapshot was taken at ${previous.scannedAt}, which is not before this scan (${current.scannedAt}).`,
    );
  }
}

/**
 * Right after the org lookup, before any app data is read: the same org.
 * Its GUID decides, so a renamed org still matches; a snapshot without the
 * org's GUID is compared by name.
 */
export function checkPreviousOrg(previous: Snapshot, org: RawOrg): void {
  const guids = previous.raw.orgs.map((o) => o.guid);
  const same =
    guids.length > 0
      ? guids.length === 1 && guids[0] === org.guid
      : previous.scope.orgs.length === 1 && previous.scope.orgs[0] === org.name;
  if (!same) {
    const was = previous.scope.orgs.join(', ') || 'no org';
    const what =
      was === org.name ? `another org named "${org.name}"` : `${was}, not of the org "${org.name}"`;
    throw new ConfigError(
      `The --previous snapshot is of ${what}; give a snapshot of the same org.`,
    );
  }
}
