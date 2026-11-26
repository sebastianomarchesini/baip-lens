import { FakeFetch, type RecordedCall, jsonResponse } from './fakeFetch.js';

/**
 * The two public sources of the dependency lookup, scripted for the tests.
 *
 * A scripted OSV.dev: it answers `POST /v1/querybatch` and
 * `GET /v1/vulns/<id>` as the real service does (docs/data-sources.md §12.3),
 * from a table of invented advisories. And a scripted npm registry: it
 * answers `GET /<package>/<version>` and `GET /<package>/latest` as the real
 * one does (§12.4), from a table of invented deprecations. No test reaches
 * the real ones.
 *
 * Without a script every package is clean and no version is deprecated, so a
 * test that is not about dependencies can scan a fixture with a lockfile and
 * keep its findings. Advisory ids are plainly fake (`GHSA-fake-0001-baip`),
 * package names invented (`baip-fixture-…`) and so are the messages: nothing
 * here names a real vulnerability or repeats what a real registry says.
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

/*
 * What the scripted OSV.dev says about the packages of the acme-incidents
 * fixture (test/support/lockfileFixture.ts): the sample data of the golden
 * files, and of the tests that pin the findings of the fixture. Every case
 * the rule `DEP_KNOWN_CVE` tells apart is in it once. The packages of the
 * clean-cap fixture are other versions, and have no advisory.
 */

/** A critical score on a direct production package, with a fix. */
export const ACME_CRITICAL = 'GHSA-fake-0001-baip';
/** A severity in words only, with one fix per line of versions. */
export const ACME_MODERATE = 'GHSA-fake-0002-baip';
/** A high score (a CVSS v3.0 vector), and no fixed version. */
export const ACME_NO_FIX = 'GHSA-fake-0003-baip';
/** A low score on a package that is installed for development only. */
export const ACME_DEV = 'GHSA-fake-0004-baip';
/** Taken back: stored nowhere and reported nowhere. */
export const ACME_WITHDRAWN = 'GHSA-fake-0005-baip';
/** An advisory that states no severity and has no summary. */
export const ACME_UNRATED = 'GHSA-fake-0006-baip';
/** A report of malicious code. */
export const ACME_MALICIOUS = 'MAL-0000-0001';

export const ACME_OSV_SCRIPT: OsvScript = {
  vulnerable: {
    '@baip-fixture/odata@3.1.0': [ACME_CRITICAL],
    // The older line of the package has one advisory, the newer one a second without a fix.
    'baip-fixture-merge@3.10.1': [ACME_MODERATE],
    'baip-fixture-merge@4.17.20': [ACME_MODERATE, ACME_NO_FIX],
    'baip-fixture-mkdir@0.5.1': [ACME_DEV],
    // Installed under an alias; the package behind it is what is looked up.
    'baip-fixture-queue@5.0.2': [ACME_MALICIOUS],
    'baip-fixture-server@2.4.1': [ACME_WITHDRAWN],
    'baip-fixture-watcher@2.3.3': [ACME_UNRATED],
  },
  advisories: {
    [ACME_CRITICAL]: {
      aliases: ['CVE-2026-00001'],
      summary: 'Requests inside a batch skip the authorization check in @baip-fixture/odata',
      cvssV3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      label: 'CRITICAL',
      affected: [{ name: '@baip-fixture/odata', fixed: '3.1.2' }],
    },
    [ACME_MODERATE]: {
      aliases: ['CVE-2026-00002'],
      summary: 'Merging request data can overwrite properties shared by all objects',
      label: 'MODERATE',
      affected: [
        { name: 'baip-fixture-merge', fixed: '3.10.2' },
        { name: 'baip-fixture-merge', introduced: '4.0.0', fixed: '4.17.21' },
        // Another package of the same advisory: nothing of it is kept.
        { name: 'baip-fixture-merge-deep', fixed: '9.9.9' },
      ],
    },
    [ACME_NO_FIX]: {
      summary: 'A crafted template string makes baip-fixture-merge run for a very long time',
      cvssV3: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      label: 'HIGH',
      affected: [{ name: 'baip-fixture-merge' }],
    },
    [ACME_DEV]: {
      aliases: ['CVE-2026-00004'],
      summary: 'Folders can be created outside the target folder',
      cvssV3: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
      label: 'LOW',
      affected: [{ name: 'baip-fixture-mkdir', fixed: '0.5.2' }],
    },
    [ACME_WITHDRAWN]: {
      summary: 'Reported in error',
      withdrawn: '2026-09-15T00:00:00Z',
      label: 'HIGH',
      affected: [{ name: 'baip-fixture-server', fixed: '2.4.2' }],
    },
    [ACME_UNRATED]: { affected: [{ name: 'baip-fixture-watcher' }] },
    [ACME_MALICIOUS]: {
      summary: 'Malicious code in baip-fixture-queue (npm)',
      affected: [{ name: 'baip-fixture-queue' }],
    },
  },
};

/**
 * The findings of `DEP_KNOWN_CVE` for the acme-incidents fixture with the
 * script above, in report order: `[severity, subject, fixedIn, severityFrom]`.
 * The package with the withdrawn advisory is not among them.
 */
export const ACME_KNOWN_CVE = [
  ['critical', '@baip-fixture/odata@3.1.0', '3.1.2', 'cvss'],
  ['critical', 'baip-fixture-queue@5.0.2', null, 'malicious'],
  ['high', 'baip-fixture-merge@4.17.20', null, 'cvss'],
  ['medium', 'baip-fixture-merge@3.10.1', '3.10.2', 'label'],
  ['medium', 'baip-fixture-watcher@2.3.3', null, 'default'],
  ['low', 'baip-fixture-mkdir@0.5.1', '0.5.2', 'cvss'],
] as const;

/**
 * A fetch that knows the two sources of the lookup and nothing else: OSV.dev
 * as `script` says, and a registry on which no version is deprecated. Any
 * other request fails the test that made it.
 */
export function osvFetch(script: OsvScript = {}): FakeFetch {
  return dependencyFetch({ osv: script });
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

/*
 * The scripted npm registry.
 */

export const REGISTRY_HOST = 'registry.npmjs.org';

/** What the scripted registry says about one version of a package, in the words of the tests. */
export interface ScriptedVersion {
  /** The deprecation message, `true` for a deprecation without one. Absent: not deprecated. */
  deprecated?: unknown;
  /** Answer with this status instead of a document: 404 is "unknown to the registry". */
  status?: number;
  /** Further keys of the document, as they are: for answers that are wrong on purpose. */
  extra?: Record<string, unknown>;
}

/** The version the registry tags `latest` for a package; null: it names none (404). */
export type ScriptedLatest = (ScriptedVersion & { version: string }) | null;

export interface RegistryScript {
  /** `name@version` of a package to what the registry says about it; every other version is not deprecated. */
  versions?: Record<string, ScriptedVersion>;
  /** Package name to its latest version; every other package has `LATEST_VERSION`, not deprecated. */
  latest?: Record<string, ScriptedLatest>;
}

/** The latest version of every package the script does not name. */
export const LATEST_VERSION = '99.0.0';

/**
 * Planted in every document of the scripted registry, in the fields BAIP
 * Lens never reads (the people behind a package and their addresses, its
 * description, its repository, its tarball), in the body of an error it
 * answers with, and in a deprecation message of the acme script below: none
 * of them may reach a snapshot, a report or the terminal.
 */
export const REGISTRY_POISON = [
  'Registry Poison',
  'registry.poison@example.com',
  'POISON_registry_description',
  'POISON_registry_script',
  'POISON_registry_integrity',
  'poison-registry-repo.example.com',
  'poison-registry-dependency',
  'POISON_registry_error',
  'POISON_registry_pw',
];

/** The document `GET /<package>/<version>` answers with, shaped like a real one. */
export function registryDocument(
  name: string,
  version: string,
  answer: ScriptedVersion = {},
): Record<string, unknown> {
  const person = { name: 'Registry Poison', email: 'registry.poison@example.com' };
  const tarball = name.slice(name.lastIndexOf('/') + 1);
  return {
    name,
    version,
    description: 'POISON_registry_description',
    main: 'index.js',
    scripts: { test: 'POISON_registry_script' },
    author: person,
    contributors: [person],
    license: 'MIT',
    repository: { type: 'git', url: 'git+https://poison-registry-repo.example.com/x.git' },
    bugs: { url: 'https://poison-registry-repo.example.com/x/issues' },
    homepage: 'https://poison-registry-repo.example.com/x#readme',
    dependencies: { 'poison-registry-dependency': '^1.0.0' },
    _id: `${name}@${version}`,
    _nodeVersion: '22.0.0',
    _npmVersion: '10.0.0',
    dist: {
      integrity: 'sha512-POISON_registry_integrity',
      shasum: '0'.repeat(40),
      tarball: `https://${REGISTRY_HOST}/${name}/-/${tarball}-${version}.tgz`,
      fileCount: 12,
      unpackedSize: 34_567,
    },
    _npmUser: person,
    directories: {},
    maintainers: [person, person],
    _npmOperationalInternal: { host: 's3://npm-registry-packages', tmp: 'tmp/x' },
    _hasShrinkwrap: false,
    ...(answer.deprecated === undefined ? {} : { deprecated: answer.deprecated }),
    ...answer.extra,
  };
}

/** What a request to the registry asks for: a package and a version, or `latest`. */
export interface RegistryRequest {
  name: string;
  /** A version, or `latest`. */
  version: string;
}

/**
 * The package and version a registry address names, when it is written the
 * one way the scan writes it: two segments, a scoped name with its slash
 * encoded, no query. Null for any other address, which the scripted
 * registry answers with 404, as the real one answers a path it does not
 * know.
 */
export function registryRequest(url: URL): RegistryRequest | null {
  const segments = url.pathname.split('/');
  if (segments.length !== 3 || url.search !== '' || url.href.includes('?')) return null;
  const [, encoded = '', version = ''] = segments;
  const name = encoded.replace('%2f', '/');
  if (name === '' || version === '' || name.includes('%')) return null;
  return { name, version };
}

function registryAnswer(name: string, version: string, answer: ScriptedVersion): Response {
  if (answer.status === 404) return jsonResponse(`version not found: ${version}`, 404);
  if (answer.status !== undefined)
    return jsonResponse({ error: 'POISON_registry_error' }, answer.status);
  return jsonResponse(registryDocument(name, version, answer));
}

/** Adds the scripted npm registry to `fake`, and returns it. */
export function scriptRegistry(fake: FakeFetch, script: RegistryScript = {}): FakeFetch {
  const versions = new Map(Object.entries(script.versions ?? {}));
  const latest = new Map(Object.entries(script.latest ?? {}));
  return fake.on(
    'GET',
    (url) => url.host === REGISTRY_HOST,
    (call) => {
      const asked = registryRequest(call.url);
      if (asked === null) return jsonResponse('Not Found', 404);
      if (asked.version !== 'latest') {
        const answer = versions.get(`${asked.name}@${asked.version}`) ?? {};
        return registryAnswer(asked.name, asked.version, answer);
      }
      const newest = latest.get(asked.name);
      if (newest === null) return jsonResponse('Not Found', 404);
      return registryAnswer(asked.name, newest?.version ?? LATEST_VERSION, newest ?? {});
    },
  );
}

/** The requests that went to the npm registry. */
export function registryCalls(fake: FakeFetch): RecordedCall[] {
  return fake.calls.filter((call) => call.url.host === REGISTRY_HOST);
}

/** Every package version a run asked the registry about, as `name@version`, in the order asked. */
export function askedVersions(fake: FakeFetch): string[] {
  return registryCalls(fake)
    .map((call) => registryRequest(call.url))
    .filter((asked) => asked !== null && asked.version !== 'latest')
    .map((asked) => `${asked?.name}@${asked?.version}`);
}

/** The packages a run asked the registry for the latest version of, in the order asked. */
export function askedLatest(fake: FakeFetch): string[] {
  return registryCalls(fake)
    .map((call) => registryRequest(call.url))
    .filter((asked) => asked?.version === 'latest')
    .map((asked) => asked?.name ?? '');
}

/** The scripts of the two sources; a source that has none is clean. */
export interface DependencyScripts {
  osv?: OsvScript;
  registry?: RegistryScript;
}

/** A fetch that knows the two sources of the lookup, each as its script says, and nothing else. */
export function dependencyFetch(scripts: DependencyScripts = {}): FakeFetch {
  return scriptRegistry(scriptOsv(new FakeFetch(), scripts.osv), scripts.registry);
}

/** The same with the registry as `script` says, and an OSV.dev that knows no advisory. */
export function registryFetch(script: RegistryScript = {}): FakeFetch {
  return dependencyFetch({ registry: script });
}

/*
 * What the scripted registry says about the packages of the acme-incidents
 * fixture: every case the lookup tells apart is in it once. The packages of
 * the clean-cap fixture are other versions, and none of them is deprecated.
 */

export const ACME_REGISTRY_SCRIPT: RegistryScript = {
  versions: {
    // A direct dependency that was given up as a whole. The message is text from outside: an
    // address of a person, an escape sequence, a credential in a link and a direction mark.
    'baip-fixture-legacy-http@1.9.3': {
      deprecated:
        'baip-fixture-legacy-http is no longer maintained\u001b[31m, write to ' +
        'registry.poison@example.com or see ' +
        'https://ci:POISON_registry_pw@deprecations.example.org/legacy-http\u202e for a successor',
    },
    // An old line of a package that has a newer, supported one.
    'baip-fixture-mkdir@0.5.1': {
      deprecated:
        'Versions of baip-fixture-mkdir before 1.0 are no longer supported, upgrade to 1.x',
    },
    // A version the registry does not know: unpublished, or never public.
    'baip-fixture-test-kit@7.0.0': { status: 404 },
  },
  latest: {
    'baip-fixture-legacy-http': {
      version: '2.0.1',
      deprecated: 'baip-fixture-legacy-http is no longer maintained',
    },
    'baip-fixture-mkdir': { version: '1.0.4' },
  },
};

/** The rows the lookup stores for the acme-incidents fixture with the script above. */
export const ACME_DEPRECATIONS = [
  {
    name: 'baip-fixture-legacy-http',
    version: '1.9.3',
    message:
      'baip-fixture-legacy-http is no longer maintained, write to [e-mail] or see ' +
      'https://deprecations.example.org/legacy-http for a successor',
    latest: '2.0.1',
    latestDeprecated: true,
  },
  {
    name: 'baip-fixture-mkdir',
    version: '0.5.1',
    message: 'Versions of baip-fixture-mkdir before 1.0 are no longer supported, upgrade to 1.x',
    latest: '1.0.4',
    latestDeprecated: false,
  },
] as const;
