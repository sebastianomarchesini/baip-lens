import { CheckSkipError } from '../checks.js';
import { type LogCacheClient, LogCacheError, MAX_LIMIT } from '../http/logCacheClient.js';
import type { RawTraffic } from '../model/raw.js';
import type { Collected } from './apps.js';

export interface TrafficOptions {
  /** Pages of LOG envelopes read per app, newest first, before giving up. */
  maxPages: number;
  /** Apps read at the same time (default 2). */
  concurrency?: number;
  log?: (message: string) => void;
}

/**
 * Apps read at the same time. Each app's first read makes Log Cache ask
 * Cloud Controller, with the user's token, whether the user may read it, so it
 * counts against the user's CF API rate limit (docs/data-sources.md §9.5).
 */
const CONCURRENCY = 2;
/** After this many failed apps in a row the rest are left unread (unknown). */
const MAX_CONSECUTIVE_FAILURES = 3;

const nanos = (timestamp: string): bigint => BigInt(timestamp);
const older = (a: string, b: string): string => (nanos(a) <= nanos(b) ? a : b);
const newer = (a: string, b: string): string => (nanos(a) >= nanos(b) ? a : b);

/** Nanoseconds to an ISO timestamp; null for a value no date can hold. */
function toIso(timestamp: string): string | null {
  const ms = Number(nanos(timestamp) / 1_000_000n);
  const date = new Date(ms);
  return ms > 0 && !Number.isNaN(date.getTime()) ? date.toISOString() : null;
}

interface AppRead {
  traffic: RawTraffic;
  invalid: number;
}

/** The oldest envelope of any type Log Cache holds for the app, or undefined. */
async function oldestHeld(client: LogCacheClient, appGuid: string): Promise<string | undefined> {
  try {
    // Ascending (the default) and unfiltered: pruning is oldest-first across all
    // types, so nothing newer than this envelope has been dropped (§9.4, §9.6).
    return (await client.read(appGuid, { limit: 1 })).envelopes[0]?.timestamp;
  } catch (error) {
    // Without it the window is what was read, which is shorter: still safe.
    if (error instanceof LogCacheError) return undefined;
    throw error;
  }
}

/**
 * Newest first, one page of LOG envelopes at a time, until a router access log
 * turns up, the cache holds nothing older, or `maxPages` pages were read.
 * Keeps three values and drops everything else it read (docs/privacy.md).
 */
export async function readAppTraffic(
  client: LogCacheClient,
  appGuid: string,
  maxPages: number,
): Promise<AppRead> {
  let limit = MAX_LIMIT;
  let endTime: string | undefined;
  let oldestRead: string | undefined;
  let examined = 0;
  let invalid = 0;
  let anyTagged = false;
  const result = (lastRequest: string | null, windowStart: string | undefined): AppRead => ({
    traffic: {
      appGuid,
      lastRequestAt: lastRequest === null ? null : toIso(lastRequest),
      windowStart: windowStart === undefined ? null : toIso(windowStart),
      envelopesExamined: examined,
    },
    invalid,
  });
  /**
   * Silence is only evidence when router logs could have been recognised: if
   * not one examined LOG envelope carries a `source_type` tag, the platform
   * strips the tags (drain metadata off, §9.3) and every app would look idle.
   */
  const silence = (windowStart: string | undefined): AppRead => {
    if (examined > 0 && !anyTagged) throw new CheckSkipError('error', UNTAGGED_REASON);
    return result(null, windowStart);
  };

  for (let page = 0; page < maxPages;) {
    let batch;
    try {
      batch = await client.read(appGuid, {
        descending: true,
        envelopeTypes: ['LOG'],
        limit,
        endTime,
      });
    } catch (error) {
      // 429 means the response was too large, not a rate limit: ask for less.
      if (error instanceof LogCacheError && error.status === 429 && limit > 1) {
        limit = Math.ceil(limit / 2);
        continue;
      }
      throw error;
    }
    page += 1;
    invalid += batch.invalid;
    examined += batch.envelopes.length;
    let newestRouter: string | undefined;
    for (const envelope of batch.envelopes) {
      oldestRead =
        oldestRead === undefined ? envelope.timestamp : older(oldestRead, envelope.timestamp);
      anyTagged ||= envelope.tagged;
      if (envelope.router) {
        newestRouter =
          newestRouter === undefined ? envelope.timestamp : newer(newestRouter, envelope.timestamp);
      }
    }
    if (newestRouter !== undefined) return result(newestRouter, oldestRead);
    // Fewer than asked for (dropped ones included): the store was walked to its
    // oldest LOG envelope. It may return more than `limit` rather than split
    // one timestamp, never fewer while older envelopes remain.
    if (batch.envelopes.length + batch.invalid < limit) {
      const held = await oldestHeld(client, appGuid);
      const start =
        held === undefined ? oldestRead : oldestRead === undefined ? held : older(held, oldestRead);
      return silence(start);
    }
    // `end_time` is exclusive, and a timestamp group is never split across pages.
    endTime = oldestRead;
  }
  // Page cap reached without a router log: the window is what was read.
  return silence(oldestRead);
}

const UNTAGGED_REASON =
  'Log Cache envelopes carry no source_type tag (is drain metadata turned off?), so router ' +
  'access logs cannot be recognised; no app is judged by its traffic.';

/** Why the traffic check cannot run at all, from the first app's failure. */
function skipFor(error: unknown): unknown {
  if (!(error instanceof LogCacheError)) return error;
  if (error.status === 404) {
    return new CheckSkipError(
      'insufficient_role',
      'Log Cache answered 404: no access to the app logs (needs SpaceAuditor or higher), ' +
        'an expired token, or a failed permission lookup. Log Cache never answers 403.',
    );
  }
  if (error.status === 'network' || (error.status >= 502 && error.status <= 504)) {
    return new CheckSkipError('unavailable', `Log Cache did not answer: ${error.message}`);
  }
  return new CheckSkipError('error', `Log Cache rejected the request: ${error.message}`);
}

async function inPool<T>(
  items: readonly T[],
  size: number,
  work: (item: T) => Promise<void>,
): Promise<void> {
  let next = 0;
  const worker = async (): Promise<void> => {
    for (let item = items[next++]; item !== undefined; item = items[next++]) await work(item);
  };
  await Promise.all(Array.from({ length: Math.min(size, items.length) }, worker));
}

/**
 * GET /api/v1/read/<app-guid> on the log cache, for every app that has an
 * HTTP route. The first app decides whether Log Cache can be read at all: a
 * 404 or an outage there skips the check, with a reason that says what a 404
 * can mean. After that, an app that fails stays unknown and the others go on.
 */
export async function collectTraffic(
  client: LogCacheClient,
  appGuids: readonly string[],
  options: TrafficOptions,
): Promise<Collected<RawTraffic>> {
  const items: RawTraffic[] = [];
  let invalid = 0;
  const [first, ...rest] = appGuids;
  if (first === undefined) return { items, invalid };

  try {
    const read = await readAppTraffic(client, first, options.maxPages);
    items.push(read.traffic);
    invalid += read.invalid;
  } catch (error) {
    throw skipFor(error);
  }

  let failedInARow = 0;
  let failed = 0;
  // Set when an error ends the whole check (untagged logs, a bug): the other
  // worker then stops asking instead of reading apps nobody will look at.
  let aborted = false;
  await inPool(rest, options.concurrency ?? CONCURRENCY, async (appGuid) => {
    if (aborted || failedInARow >= MAX_CONSECUTIVE_FAILURES) return;
    try {
      const read = await readAppTraffic(client, appGuid, options.maxPages);
      items.push(read.traffic);
      invalid += read.invalid;
      failedInARow = 0;
    } catch (error) {
      if (!(error instanceof LogCacheError)) {
        aborted = true;
        throw error;
      }
      failed += 1;
      failedInARow += 1;
    }
  });
  const unread = appGuids.length - items.length;
  if (unread > 0) {
    options.log?.(
      `Log Cache: ${unread} app(s) could not be read (${failed} failed` +
        `${failedInARow >= MAX_CONSECUTIVE_FAILURES ? ', the rest were skipped' : ''}); they are unknown`,
    );
  }
  // Reads finish in any order; sort so that the snapshot does not depend on it.
  items.sort((a, b) => a.appGuid.localeCompare(b.appGuid));
  return { items, invalid };
}
