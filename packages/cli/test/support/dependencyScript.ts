import { FakeFetch, type RecordedCall, jsonResponse } from './fakeFetch.js';

/**
 * A scripted OSV.dev for the tests: it answers `POST /v1/querybatch` and
 * `GET /v1/vulns/<id>` as the real service does (docs/data-sources.md §12.3),
 * from a table of invented advisories. No test reaches the real one.
 *
 * Without a script every package is clean, so a test that is not about
 * dependencies can scan a fixture with a lockfile and keep its findings.
 * Advisory ids are plainly fake (`GHSA-fake-0001-baip`) and package names
 * invented (`baip-fixture-…`): nothing here names a real vulnerability.
 */

export const OSV_HOST = 'api.osv.dev';
export const QUERYBATCH = `${OSV_HOST}/v1/querybatch`;

/** One `affected` entry of an advisory, as OSV.dev writes a range of an npm package. */
export interface ScriptedAffected {
  /** The package the entry is about. */
  name: string;
  /** Default: `npm`. */
  ecosystem?: string;
  /** The version that fixes it; absent: no fix (`last_affected`). */
  fixed?: string;
  introduced?: string;
}

/** An advisory of the script: what its record says, in the words of the tests. */
export interface ScriptedAdvisory {
  aliases?: string[];
  summary?: string;
  /** A CVSS v3 vector, sent as `severity: [{ type: 'CVSS_V3', score }]`. */
  cvssV3?: string;
  /** `database_specific.severity`. */
  label?: string;
  /** An RFC 3339 time: the advisory was taken back. */
  withdrawn?: string;
  affected?: ScriptedAffected[];
  /** Further keys of the record, as they are: for answers that are wrong on purpose. */
  extra?: Record<string, unknown>;
}

export interface OsvScript {
  /** `name@version` of a package to the ids of its advisories; every other package is clean. */
  vulnerable?: Record<string, string[]>;
  /** The advisories by id; an id that is not here is answered with 404. */
  advisories?: Record<string, ScriptedAdvisory>;
}

/**
 * Planted in every scripted advisory, in the fields BAIP Lens never reads
 * (`details`, `references`, `credits`, `database_specific` beyond the
 * severity): none of them may reach a snapshot, a report or the terminal.
 */
export const OSV_POISON = [
  'POISON_osv_details',
  'poison-osv-reference.example.com',
  'Osv Poison',
  'osv.poison@example.com',
  'POISON_osv_cwe',
  'POISON_osv_source',
];

/** The record `GET /v1/vulns/<id>` answers with, shaped like a real one. */
export function osvRecord(id: string, advisory: ScriptedAdvisory = {}): Record<string, unknown> {
  return {
    id,
    ...(advisory.summary === undefined ? {} : { summary: advisory.summary }),
    details: 'POISON_osv_details: a long text that is never read.',
    ...(advisory.aliases === undefined ? {} : { aliases: advisory.aliases }),
    modified: '2026-09-01T00:00:00Z',
    published: '2026-08-01T00:00:00Z',
    ...(advisory.withdrawn === undefined ? {} : { withdrawn: advisory.withdrawn }),
    database_specific: {
      cwe_ids: ['POISON_osv_cwe'],
      github_reviewed: true,
      ...(advisory.label === undefined ? {} : { severity: advisory.label }),
    },
    references: [{ type: 'WEB', url: 'https://poison-osv-reference.example.com/advisory' }],
    affected: (advisory.affected ?? []).map((entry) => ({
      package: {
        name: entry.name,
        ecosystem: entry.ecosystem ?? 'npm',
        purl: `pkg:npm/${entry.name}`,
      },
      ranges: [
        {
          type: 'SEMVER',
          events: [
            { introduced: entry.introduced ?? '0' },
            entry.fixed === undefined ? { last_affected: '99.0.0' } : { fixed: entry.fixed },
          ],
        },
      ],
      database_specific: { source: 'https://poison-osv-reference.example.com/POISON_osv_source' },
    })),
    schema_version: '1.7.3',
    ...(advisory.cvssV3 === undefined
      ? {}
      : { severity: [{ type: 'CVSS_V3', score: advisory.cvssV3 }] }),
    credits: [{ name: 'Osv Poison', contact: ['osv.poison@example.com'], type: 'FINDER' }],
    ...advisory.extra,
  };
}

/** A query of a `querybatch` body. */
export interface SentQuery {
  package: { name: string; ecosystem: string };
  version: string;
  page_token?: string;
}

/** The queries of one recorded `querybatch` request. */
export function sentQueries(call: RecordedCall): SentQuery[] {
  return (JSON.parse(call.body ?? '{}') as { queries?: SentQuery[] }).queries ?? [];
}

/** Adds the scripted OSV.dev to `fake`, and returns it. */
export function scriptOsv(fake: FakeFetch, script: OsvScript = {}): FakeFetch {
  const vulnerable = new Map(Object.entries(script.vulnerable ?? {}));
  const advisories = new Map(Object.entries(script.advisories ?? {}));
  return fake
    .on('POST', QUERYBATCH, (call) =>
      jsonResponse({
        results: sentQueries(call).map((query) => {
          const ids = vulnerable.get(`${query.package.name}@${query.version}`);
          return ids === undefined
            ? {}
            : { vulns: ids.map((id) => ({ id, modified: '2026-09-01T00:00:00Z' })) };
        }),
      }),
    )
    .on(
      'GET',
      (url) => url.host === OSV_HOST && url.pathname.startsWith('/v1/vulns/'),
      (call) => {
        const id = decodeURIComponent(call.url.pathname.slice('/v1/vulns/'.length));
        const advisory = advisories.get(id);
        return advisory === undefined
          ? jsonResponse({ code: 5, message: 'Vulnerability not found' }, 404)
          : jsonResponse(osvRecord(id, advisory));
      },
    );
}

/** A fetch that knows OSV.dev and nothing else: any other request fails the test that made it. */
export function osvFetch(script: OsvScript = {}): FakeFetch {
  return scriptOsv(new FakeFetch(), script);
}

/** The requests that went to OSV.dev. */
export function osvCalls(fake: FakeFetch): RecordedCall[] {
  return fake.calls.filter((call) => call.url.host === OSV_HOST);
}

/** Every package a run asked OSV.dev about, as `name@version`, in the order asked. */
export function askedPackages(fake: FakeFetch): string[] {
  return osvCalls(fake)
    .filter((call) => call.method === 'POST')
    .flatMap(sentQueries)
    .map((query) => `${query.package.name}@${query.version}`);
}

/** The ids a run asked OSV.dev for, in the order asked. */
export function askedAdvisories(fake: FakeFetch): string[] {
  return osvCalls(fake)
    .filter((call) => call.method === 'GET')
    .map((call) => call.url.pathname.slice('/v1/vulns/'.length));
}
