import { z } from 'zod';
import { type JsonShapeLimits, jsonShapeExcess } from '../io/jsonShape.js';
import { SNAPSHOT_LIST_LIMITS } from '../model/list.js';
import {
  ADVISORY_ID_PATTERN,
  type AdvisoryLabel,
  AdvisoryLabelSchema,
  CVSS_V3_PATTERN,
  LOCKED_PACKAGE_NAME_PATTERN,
  PACKAGE_VERSION_PATTERN,
} from '../model/raw.js';
import { HttpBodyTooLargeError, HttpNetworkError } from './errors.js';
import type { HttpRequest, HttpResponse } from './httpClient.js';

/*
 * The client for OSV.dev (docs/data-sources.md §3.2, §12.3): which advisories
 * exist for a package version, and what an advisory says. It sends the names
 * and versions of public npm packages and nothing else: no credential, no
 * cookie, no identifier of the project they were found in. Both requests only
 * read (`POST /v1/querybatch` is a query with a body), so repeating one after
 * a network error or a 5xx answer changes nothing on the other side; the HTTP
 * client does that, and it follows no redirect.
 *
 * Every answer is treated as hostile text until it is parsed: bounded in
 * bytes, in nesting and in the number of its values before `JSON.parse` sees
 * it, read through schemas that keep the few fields named here and drop the
 * rest (`details`, `references`, `credits`, the people behind them), and
 * refused as a whole when it is not what the request asked for.
 */

export const OSV_HOST = 'api.osv.dev';
const OSV_ORIGIN = `https://${OSV_HOST}`;
const QUERYBATCH_PATH = '/v1/querybatch';
const VULNS_PATH = '/v1/vulns/';
const ECOSYSTEM = 'npm';

/** OSV.dev refuses a batch with more queries (`maxBatchQueries`). */
export const MAX_BATCH_QUERIES = 1_000;
/** OSV.dev gives a batch 35 seconds; a little more, so that its own answer arrives. */
const QUERYBATCH_TIMEOUT_MS = 40_000;
/** OSV.dev caps a response at 32 MiB itself. */
const QUERYBATCH_MAX_BYTES = 32 * 1024 * 1024;
/** One advisory takes a few kilobytes; one that lists every affected version of many packages far more. */
const ADVISORY_MAX_BYTES = 8 * 1024 * 1024;
const MAX_PAGE_TOKEN_LENGTH = 4_096;
const MAX_PACKAGE_NAME_LENGTH = 214;
const MAX_PACKAGE_VERSION_LENGTH = 64;
/** Other ids of an advisory that are kept: the first of them, as many as the snapshot holds. */
const MAX_ALIASES = SNAPSHOT_LIST_LIMITS.advisoryAliases;

/*
 * What an answer may cost to parse. A full batch holds about 3,000 ids, five
 * values each, and one result per query; an advisory a few hundred values,
 * some thousand when it lists the versions of many packages.
 */
const QUERYBATCH_SHAPE: JsonShapeLimits = { maxDepth: 16, maxItems: 1_000_000, maxMembers: 100 };
const ADVISORY_SHAPE: JsonShapeLimits = { maxDepth: 32, maxItems: 1_000_000, maxMembers: 1_000 };

/** Why a request to OSV.dev gave no usable answer. */
export type OsvFailure = 'unreachable' | 'status' | 'unexpected';

/**
 * A request to OSV.dev that gave no usable answer. The message is one of
 * three fixed sentences: it is recorded as the reason of a skipped check and
 * must never repeat what a server sent.
 */
export class OsvError extends Error {
  override readonly name = 'OsvError';

  constructor(
    readonly failure: OsvFailure,
    /** The HTTP status, for `status`. */
    readonly status?: number,
  ) {
    super(
      failure === 'unreachable'
        ? `${OSV_HOST} could not be reached`
        : failure === 'status'
          ? `${OSV_HOST} answered HTTP ${status ?? 0}`
          : `${OSV_HOST} sent an unexpected answer`,
    );
  }
}

/** The part of the HTTP layer this client needs: one request, checked against the allow-list. */
export interface OsvHttp {
  request(req: HttpRequest): Promise<HttpResponse>;
}

/** One package version to ask about; with `pageToken`, the next page of an earlier answer. */
export interface OsvQuery {
  name: string;
  version: string;
  pageToken?: string;
}

/** The answer to one query: the ids of the advisories, and a token when there are more. */
export interface OsvQueryResult {
  ids: string[];
  nextPageToken?: string;
}

/** An advisory as far as BAIP Lens reads it. */
export interface OsvAdvisory {
  id: string;
  /** Present in the record: the advisory was taken back, and counts for nothing. */
  withdrawn: boolean;
  /** Other ids, as the record lists them: pattern-checked, without repeats, the first 20. */
  aliases: string[];
  /** External text, as it came: to be cleaned and cut before it is stored. */
  summary: string | null;
  /** The first CVSS v3 vector of the record. */
  cvssV3: string | null;
  label: AdvisoryLabel | null;
  /** Per package name that was asked about: the fixed versions the record names for it. */
  fixed: Map<string, string[]>;
}

const BatchSchema = z.object({ results: z.array(z.unknown()).optional() });
const ResultSchema = z.object({
  vulns: z.array(z.unknown()).optional(),
  next_page_token: z.string().optional(),
});
const VulnRefSchema = z.object({ id: z.string() });

/** Only these keys are read; `z.object` drops every other one. */
const AdvisorySchema = z.object({
  id: z.string(),
  withdrawn: z.unknown().optional(),
  aliases: z.array(z.unknown()).nullish(),
  summary: z.string().nullish(),
  severity: z.array(z.unknown()).nullish(),
  database_specific: z.unknown().optional(),
  affected: z.array(z.unknown()).nullish(),
});
const SeveritySchema = z.object({ type: z.string(), score: z.string() });
const DatabaseSpecificSchema = z.object({ severity: z.unknown().optional() });
const AffectedSchema = z.object({
  package: z.object({ name: z.string(), ecosystem: z.string() }),
  ranges: z.array(z.unknown()).nullish(),
});
const RangeSchema = z.object({ events: z.array(z.unknown()).nullish() });
const EventSchema = z.object({ fixed: z.string() });

function unexpected(): OsvError {
  return new OsvError('unexpected');
}

/** The answer as JSON, once its shape is within what parsing may cost. */
function parseJson(text: string, limits: JsonShapeLimits): unknown {
  if (jsonShapeExcess(Buffer.from(text, 'utf8'), limits) !== undefined) throw unexpected();
  try {
    return JSON.parse(text) as unknown;
  } catch {
    // Not JSON, or nested deeper than the parser goes.
    throw unexpected();
  }
}

function isPackageName(value: string): boolean {
  return value.length <= MAX_PACKAGE_NAME_LENGTH && LOCKED_PACKAGE_NAME_PATTERN.test(value);
}

function isPackageVersion(value: string): boolean {
  return value.length <= MAX_PACKAGE_VERSION_LENGTH && PACKAGE_VERSION_PATTERN.test(value);
}

/**
 * An id that can stand in a request path as it is. The pattern allows dots,
 * and a path segment of one or two dots is not a name but a step in the
 * path, which a URL resolves away.
 */
function isRequestableId(value: string): boolean {
  return ADVISORY_ID_PATTERN.test(value) && value !== '.' && value !== '..';
}

function toResult(item: unknown): OsvQueryResult {
  const result = ResultSchema.safeParse(item);
  if (!result.success) throw unexpected();
  const ids = (result.data.vulns ?? []).map((vuln) => {
    const ref = VulnRefSchema.safeParse(vuln);
    if (!ref.success || !isRequestableId(ref.data.id)) throw unexpected();
    return ref.data.id;
  });
  const token = result.data.next_page_token;
  if (token === undefined || token === '') return { ids };
  if (token.length > MAX_PAGE_TOKEN_LENGTH) throw unexpected();
  return { ids, nextPageToken: token };
}

/** The first `MAX_ALIASES` distinct ids among the aliases that are ids at all. */
function aliasesOf(items: readonly unknown[]): string[] {
  const aliases = new Set<string>();
  for (const item of items) {
    if (aliases.size >= MAX_ALIASES) break;
    if (typeof item === 'string' && ADVISORY_ID_PATTERN.test(item)) aliases.add(item);
  }
  return [...aliases];
}

function cvssV3Of(items: readonly unknown[]): string | null {
  for (const item of items) {
    const severity = SeveritySchema.safeParse(item);
    if (!severity.success || severity.data.type !== 'CVSS_V3') continue;
    if (CVSS_V3_PATTERN.test(severity.data.score)) return severity.data.score;
  }
  return null;
}

function labelOf(databaseSpecific: unknown): AdvisoryLabel | null {
  const specific = DatabaseSpecificSchema.safeParse(databaseSpecific);
  if (!specific.success) return null;
  const label = AdvisoryLabelSchema.safeParse(specific.data.severity);
  return label.success ? label.data : null;
}

/** The fixed versions one `affected` entry names, pattern-checked. */
function fixedVersions(ranges: readonly unknown[]): string[] {
  const versions: string[] = [];
  for (const item of ranges) {
    const range = RangeSchema.safeParse(item);
    if (!range.success) continue;
    for (const entry of range.data.events ?? []) {
      const event = EventSchema.safeParse(entry);
      if (event.success && isPackageVersion(event.data.fixed)) versions.push(event.data.fixed);
    }
  }
  return versions;
}

/**
 * Per package that was asked about, the fixed versions the record names for
 * it. An advisory lists every package it affects, in every ecosystem; what it
 * says about the others is not kept.
 */
function fixedByPackage(
  affected: readonly unknown[],
  names: ReadonlySet<string>,
): Map<string, string[]> {
  const fixed = new Map<string, Set<string>>();
  for (const item of affected) {
    const entry = AffectedSchema.safeParse(item);
    if (!entry.success) continue;
    const { name, ecosystem } = entry.data.package;
    if (ecosystem !== ECOSYSTEM || !names.has(name)) continue;
    const versions = fixed.get(name) ?? new Set<string>();
    for (const version of fixedVersions(entry.data.ranges ?? [])) versions.add(version);
    fixed.set(name, versions);
  }
  return new Map([...fixed].map(([name, versions]) => [name, [...versions]]));
}

export class OsvClient {
  constructor(private readonly http: OsvHttp) {}

  /**
   * `POST /v1/querybatch`: one result per query, in the order of the
   * queries. A package without advisories gives an empty result. At most
   * `MAX_BATCH_QUERIES` queries; none makes no request.
   */
  async queryBatch(queries: readonly OsvQuery[]): Promise<OsvQueryResult[]> {
    if (queries.length === 0) return [];
    if (queries.length > MAX_BATCH_QUERIES) throw new Error('too many queries for one batch');
    for (const query of queries) {
      // Only what the lockfile step kept is asked about, and that passed these patterns.
      if (!isPackageName(query.name) || !isPackageVersion(query.version)) {
        throw new Error('not a package name and version that can be looked up');
      }
    }
    const body = JSON.stringify({
      queries: queries.map((query) => ({
        package: { name: query.name, ecosystem: ECOSYSTEM },
        version: query.version,
        ...(query.pageToken === undefined ? {} : { page_token: query.pageToken }),
      })),
    });
    const text = await this.send({
      url: new URL(QUERYBATCH_PATH, OSV_ORIGIN),
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
      timeoutMs: QUERYBATCH_TIMEOUT_MS,
      maxBytes: QUERYBATCH_MAX_BYTES,
    });
    const batch = BatchSchema.safeParse(parseJson(text, QUERYBATCH_SHAPE));
    if (!batch.success) throw unexpected();
    // OSV.dev answers every query that was sent, an empty object for a package
    // without advisories. An answer without `results` is not one of its
    // answers to this request (a gateway or a portal can answer 200 as well),
    // and "nothing found" must not be read into it.
    const { results } = batch.data;
    // Results are matched to the queries by position: one more or one less and none can be trusted.
    if (results === undefined || results.length !== queries.length) throw unexpected();
    return results.map(toResult);
  }

  /**
   * `GET /v1/vulns/<id>`: the advisory with that id. `names` are the package
   * names that were asked about; fixed versions are kept for those only.
   * Anything but that advisory, a 404 included, is a failure: the id came
   * from OSV.dev a moment ago.
   */
  async advisory(id: string, names: ReadonlySet<string>): Promise<OsvAdvisory> {
    if (!isRequestableId(id)) throw unexpected();
    const url = new URL(`${VULNS_PATH}${id}`, OSV_ORIGIN);
    if (url.pathname !== `${VULNS_PATH}${id}`) throw unexpected();
    const text = await this.send({ url, maxBytes: ADVISORY_MAX_BYTES });
    const record = AdvisorySchema.safeParse(parseJson(text, ADVISORY_SHAPE));
    if (!record.success || record.data.id !== id) throw unexpected();
    const { withdrawn, aliases, summary, severity, affected } = record.data;
    return {
      id,
      withdrawn: withdrawn !== undefined && withdrawn !== null,
      aliases: aliasesOf(aliases ?? []),
      summary: summary ?? null,
      cvssV3: cvssV3Of(severity ?? []),
      label: labelOf(record.data.database_specific),
      fixed: fixedByPackage(affected ?? [], names),
    };
  }

  /** The body of a 200 answer; every other outcome is an `OsvError`. */
  private async send(request: HttpRequest): Promise<string> {
    let response: HttpResponse;
    try {
      response = await this.http.request(request);
    } catch (error) {
      if (error instanceof HttpNetworkError) throw new OsvError('unreachable');
      if (error instanceof HttpBodyTooLargeError) throw unexpected();
      throw error;
    }
    if (response.status !== 200) throw new OsvError('status', response.status);
    return response.text;
  }
}
