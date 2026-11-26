import { z } from 'zod';
import { SNAPSHOT_LIST_LIMITS as LIMITS, list } from './list.js';
import { RelativePathSchema } from './paths.js';

/*
 * Normalized, sanitized raw data collected from the CF API or from a local
 * project directory. This is what the analyzers read, and what
 * `report --from snapshot.json` re-analyzes offline. Only allow-listed fields
 * are kept: zod strips every unknown key, so user identities, env values and
 * credentials cannot slip into a snapshot.
 */

const Timestamp = z.iso.datetime({ offset: true });

export const LifecycleTypeSchema = z.enum(['buildpack', 'cnb', 'docker', 'unknown']);
export type LifecycleType = z.infer<typeof LifecycleTypeSchema>;

export const RawOrgSchema = z.object({
  guid: z.string(),
  name: z.string(),
});
export type RawOrg = z.infer<typeof RawOrgSchema>;

export const RawSpaceSchema = z.object({
  guid: z.string(),
  name: z.string(),
  orgGuid: z.string(),
});
export type RawSpace = z.infer<typeof RawSpaceSchema>;

export const RawAppSchema = z.object({
  guid: z.string(),
  name: z.string(),
  spaceGuid: z.string(),
  state: z.enum(['STARTED', 'STOPPED']),
  createdAt: Timestamp,
  updatedAt: Timestamp,
  lifecycleType: LifecycleTypeSchema,
  /** Buildpacks requested for the app (names, or URLs with credentials removed). */
  buildpacks: list(z.string(), LIMITS.buildpacks),
  stack: z.string().nullable(),
});
export type RawApp = z.infer<typeof RawAppSchema>;

export const RawDetectedBuildpackSchema = z.object({
  name: z.string(),
  buildpackName: z.string().nullable(),
  version: z.string().nullable(),
  detectOutput: z.string().nullable(),
});
export type RawDetectedBuildpack = z.infer<typeof RawDetectedBuildpackSchema>;

export const RawDropletSchema = z.object({
  guid: z.string(),
  appGuid: z.string(),
  state: z.string(),
  createdAt: Timestamp,
  updatedAt: Timestamp,
  lifecycleType: LifecycleTypeSchema,
  stack: z.string().nullable(),
  buildpacks: list(RawDetectedBuildpackSchema, LIMITS.buildpacks),
  /** Docker image reference for docker droplets (credentials removed). */
  image: z.string().nullable(),
});
export type RawDroplet = z.infer<typeof RawDropletSchema>;

/**
 * How a route can carry traffic (docs/data-sources.md §9.1). Only `http`
 * routes go through gorouter and leave access logs; `tcp` and `internal`
 * routes never do; `unknown` is a route whose domain was not returned.
 */
export const RouteKindSchema = z.enum(['http', 'tcp', 'internal', 'unknown']);
export type RouteKind = z.infer<typeof RouteKindSchema>;

/**
 * A route of the scanned spaces with at least one destination in the
 * inventory. Host, path, port and URL are not kept: the rules only need to
 * know that an app is reachable, and how.
 */
export const RawRouteSchema = z.object({
  guid: z.string(),
  /** The space that owns the route (it may be shared into a scanned space). */
  spaceGuid: z.string(),
  kind: RouteKindSchema,
  /**
   * Destination apps, limited to apps in the scanned inventory. CF allows at
   * most 100 destinations per route. The collector drops none, because
   * dropping one would make a reachable app look unrouted; reading a snapshot
   * refuses a route with more than ten times that.
   */
  appGuids: list(z.string(), LIMITS.routeDestinations),
});
export type RawRoute = z.infer<typeof RawRouteSchema>;

/** `health_check.type` of a process; anything unrecognised becomes `unknown`. */
export const HealthCheckTypeSchema = z.enum(['port', 'http', 'process', 'unknown']);
export type HealthCheckType = z.infer<typeof HealthCheckTypeSchema>;

/** A `web` process. Its `command` is never collected (docs/data-sources.md §9.2). */
export const RawProcessSchema = z.object({
  guid: z.string(),
  appGuid: z.string(),
  type: z.literal('web'),
  /** Desired instance count, not the number running. */
  instances: z.number().int().nonnegative(),
  healthCheckType: HealthCheckTypeSchema.nullable(),
  updatedAt: Timestamp,
});
export type RawProcess = z.infer<typeof RawProcessSchema>;

/**
 * What the traffic check keeps per app, and nothing else (docs/privacy.md):
 * the access-log lines, their tags and the instance are dropped as they are
 * read, so client addresses, paths and user agents never reach a snapshot.
 */
export const RawTrafficSchema = z.object({
  appGuid: z.string(),
  /** The newest router access log seen; null when the window held none. */
  lastRequestAt: Timestamp.nullable(),
  /** The oldest moment the window covers; null when Log Cache held nothing for the app. */
  windowStart: Timestamp.nullable(),
  /** LOG envelopes read to get there. */
  envelopesExamined: z.number().int().nonnegative(),
});
export type RawTraffic = z.infer<typeof RawTrafficSchema>;

/**
 * What earlier scans saw of an app's traffic, carried forward with
 * `scan --previous` and matched by app GUID (docs/rules.md#app_idle). A
 * request in any window ends a run; a scan without one counts only when it
 * read at least `--min-traffic-window` (D8). Like `RawTraffic`, it holds
 * times and a count, never anything about a request.
 */
export const RawHistorySchema = z.object({
  appGuid: z.string(),
  /** The app's space: an entry is dropped only when a scan read that space's apps without this one. */
  spaceGuid: z.string(),
  /** The newest request any counted scan saw; null when none ever did. */
  lastRequestEverSeen: Timestamp.nullable(),
  /** When the current run of scans without a request began; null while the latest counted scan saw one. */
  firstScanWithoutTraffic: Timestamp.nullable(),
  /** Scans in a row, the latest counted one included, that saw no request. */
  scansWithoutTraffic: z.number().int().nonnegative(),
});
export type RawHistory = z.infer<typeof RawHistorySchema>;

/*
 * Local project (`baip-lens project`). Every field is an allow-listed
 * structural fact: identifiers, relative file names, counts and booleans.
 * Never file contents, CSV values, user names, passwords, descriptions,
 * URLs with credentials or absolute paths. Every string has a maximum
 * length, every array a maximum size, and enum-shaped values have an
 * `other` bucket, so a hostile project cannot grow or poison a snapshot.
 * A project read from a deployed app also records which app it was
 * (`deployment`): the app name and the identifiers of its MTA. Of the npm
 * lockfiles (`dependencies`) the name and version of a package are kept only
 * when it was resolved from the public npm registry; every other package is
 * a count.
 */

/** Project ids: the mta ID, the package name without scope, or the directory name; for a deployed app, derived from the app name. */
export const PROJECT_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
/** Names of entities, services, scopes, roles, attributes, modules, resources, columns and targets. */
export const IDENTIFIER_PATTERN = /^[A-Za-z_$][\w.$:-]{0,127}$/;
/** A role name as it may appear in `@requires` or `@restrict.to`. */
export const ROLE_PATTERN = /^[A-Za-z0-9_.$:-]{1,64}$/;
/** npm package names, as `package.json#name` and dependency keys. */
export const PACKAGE_NAME_PATTERN = /^(@[a-z0-9._-]+\/)?[a-z0-9._-]{1,214}$/i;
/**
 * Names of packages read from an npm lockfile. Stricter than
 * PACKAGE_NAME_PATTERN, because these names go into request URLs: no leading
 * `.` or `_`, and no segment that could be read as a path. At most 214
 * characters (docs/data-sources.md §12.1).
 */
export const LOCKED_PACKAGE_NAME_PATTERN =
  /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i;
/** An exact version as npm locks it. At most 64 characters. */
export const PACKAGE_VERSION_PATTERN = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$/;
/** A dependency range or engine range; anything else is stored as this placeholder. */
export const NON_REGISTRY_RANGE = '[non-registry]';
export const RANGE_PATTERN = /^[\s0-9A-Za-z.*^~<>=|+-]{0,64}$/;
/** MTA ids and module names, as the deploy service writes them on an app (docs/data-sources.md §11). */
export const MTA_NAME_PATTERN = /^[A-Za-z0-9_.-]{1,128}$/;
/** An MTA version as the deploy service writes it on an app. */
export const MTA_VERSION_PATTERN = /^[0-9A-Za-z.+-]{1,64}$/;
/** The namespace of an MTA deployment; the deploy service allows at most 36 characters. */
export const MTA_NAMESPACE_PATTERN = /^[A-Za-z0-9_.-]{1,36}$/;

const Identifier = z.string().regex(IDENTIFIER_PATTERN);
const Role = z.string().regex(ROLE_PATTERN);
const Line = z.number().int().positive();
const Count = z.number().int().nonnegative();
const Roles = list(Role, 50);

export const CdsAuthKindSchema = z.enum([
  'mocked',
  'dummy',
  'basic',
  'xsuaa',
  'ias',
  'jwt',
  'ams',
  'other',
]);
export type CdsAuthKind = z.infer<typeof CdsAuthKindSchema>;

export const CdsAuditLogKindSchema = z.enum([
  'audit-log-to-restv2',
  'audit-log-to-alsng',
  'audit-log-to-console',
  'audit-log-to-library',
  'other',
]);
export type CdsAuditLogKind = z.infer<typeof CdsAuditLogKindSchema>;

/** The parts of the effective cds configuration a rule may look at, per profile. */
export const CdsViewSchema = z.object({
  /** `requires.auth` as a string, or `requires.auth.kind`; unknown strings become `other`. */
  authKind: CdsAuthKindSchema.nullable(),
  /** Number of keys in `requires.auth.users`; nothing else of `users` is read. */
  mockedUsers: Count,
  /** How many of those users carry a `password` key (the value is never read). */
  mockedUsersWithPassword: Count,
  restrictAllServices: z.boolean().nullable(),
  auditLogKind: CdsAuditLogKindSchema.nullable(),
  /** `requires['audit-log']` present in any shape, including `true`. */
  auditLogConfigured: z.boolean(),
});
export type CdsView = z.infer<typeof CdsViewSchema>;

export const CdsSourceSchema = z.enum(['.cdsrc.yaml', '.cdsrc.json', 'package.json']);
export type CdsSource = z.infer<typeof CdsSourceSchema>;

export const UnreadableKindSchema = z.enum([
  'json',
  'yaml',
  'csv',
  'cds',
  'html',
  'binary',
  'too-large',
]);
export type UnreadableKind = z.infer<typeof UnreadableKindSchema>;

export const RawUnreadableSchema = z.object({
  file: RelativePathSchema,
  kind: UnreadableKindSchema,
});
export type RawUnreadable = z.infer<typeof RawUnreadableSchema>;

export const RawDependencySchema = z.object({
  name: z.string().regex(PACKAGE_NAME_PATTERN),
  /** The range as written when it is registry-shaped, else `[non-registry]`. */
  range: z.string().max(64),
});
export type RawDependency = z.infer<typeof RawDependencySchema>;

export const RawPackageJsonSchema = z.object({
  present: z.boolean(),
  name: z.string().regex(PACKAGE_NAME_PATTERN).nullable(),
  dependencies: list(RawDependencySchema, 500),
  devDependencies: list(RawDependencySchema, 500),
  nodeEngine: z.string().max(64).nullable(),
});
export type RawPackageJson = z.infer<typeof RawPackageJsonSchema>;

export const RawMtaModuleSchema = z.object({
  name: Identifier,
  type: Identifier.nullable(),
  path: RelativePathSchema.nullable(),
  /** `parameters.buildpack` with credentials and query removed. */
  buildpack: z.string().max(200).nullable(),
  /** Names of the required resources. */
  requires: list(Identifier, 50),
});
export type RawMtaModule = z.infer<typeof RawMtaModuleSchema>;

export const RawMtaResourceSchema = z.object({
  name: Identifier,
  type: Identifier.nullable(),
  service: Identifier.nullable(),
  plan: Identifier.nullable(),
});
export type RawMtaResource = z.infer<typeof RawMtaResourceSchema>;

export const RawMtaSchema = z.object({
  file: z.enum(['mta.yaml', 'mta.yml']),
  id: z.string().regex(PROJECT_ID_PATTERN).nullable(),
  modules: list(RawMtaModuleSchema, 200),
  resources: list(RawMtaResourceSchema, 200),
});
export type RawMta = z.infer<typeof RawMtaSchema>;

export const RawXsSecurityScopeSchema = z.object({
  name: Identifier,
  /** Has `granted-apps` or `grant-as-authority-to-apps`. */
  grantedToApps: z.boolean(),
});
export type RawXsSecurityScope = z.infer<typeof RawXsSecurityScopeSchema>;

export const RawXsSecurityRoleTemplateSchema = z.object({
  name: Identifier,
  scopeReferences: list(Identifier, 500),
});
export type RawXsSecurityRoleTemplate = z.infer<typeof RawXsSecurityRoleTemplateSchema>;

/** An XSUAA descriptor: xs-security.json, or the `config` of an xsuaa resource in mta.yaml. */
export const RawXsSecuritySchema = z.object({
  file: RelativePathSchema,
  source: z.enum(['xs-security.json', 'mta.yaml']),
  scopes: list(RawXsSecurityScopeSchema, 500),
  roleTemplates: list(RawXsSecurityRoleTemplateSchema, 500),
  /** Attribute names only. */
  attributes: list(Identifier, 500),
});
export type RawXsSecurity = z.infer<typeof RawXsSecuritySchema>;

export const XsAppAuthenticationTypeSchema = z.enum(['xsuaa', 'ias', 'basic', 'none', 'other']);
export type XsAppAuthenticationType = z.infer<typeof XsAppAuthenticationTypeSchema>;

export const XsAppRouteTargetSchema = z.enum(['destination', 'service', 'localDir', 'unknown']);
export type XsAppRouteTarget = z.infer<typeof XsAppRouteTargetSchema>;

export const XsAppTargetHintSchema = z.enum(['ui5-cdn', 'html5-repo', 'api', 'other']);
export type XsAppTargetHint = z.infer<typeof XsAppTargetHintSchema>;

export const RawXsAppRouteSchema = z.object({
  /** The route regex as written. */
  source: z.string().max(200),
  authenticationType: XsAppAuthenticationTypeSchema.nullable(),
  csrfProtection: z.boolean().nullable(),
  target: XsAppRouteTargetSchema,
  /**
   * Computed from the destination or service name, which is not stored:
   * `ui5-cdn` for /^ui5$|sapui5|cdn/i, `html5-repo` for html5-apps-repo-rt,
   * `api` for /srv|api|backend/i, else `other`.
   */
  targetHint: XsAppTargetHintSchema,
  /** The source matches `logout.logoutPage`. */
  isLogoutPage: z.boolean(),
});
export type RawXsAppRoute = z.infer<typeof RawXsAppRouteSchema>;

export const RawXsAppSchema = z.object({
  file: RelativePathSchema,
  authenticationMethod: z.enum(['route', 'none', 'other']).nullable(),
  routes: list(RawXsAppRouteSchema, 200),
});
export type RawXsApp = z.infer<typeof RawXsAppSchema>;

export const RawCdsUsingSchema = z.object({
  alias: Identifier,
  target: Identifier,
});
export type RawCdsUsing = z.infer<typeof RawCdsUsingSchema>;

export const RawCdsServiceEntitySchema = z.object({
  name: Identifier,
  line: Line,
  requires: Roles,
  restrictTo: Roles,
  readonly: z.boolean(),
  /** The `as projection on` target as written (alias not resolved). */
  projectionOf: Identifier.nullable(),
});
export type RawCdsServiceEntity = z.infer<typeof RawCdsServiceEntitySchema>;

export const RawCdsActionSchema = z.object({
  name: Identifier,
  line: Line,
  requires: Roles,
  restrictTo: Roles,
});
export type RawCdsAction = z.infer<typeof RawCdsActionSchema>;

export const RawCdsServiceSchema = z.object({
  name: Identifier,
  line: Line,
  requires: Roles,
  restrictTo: Roles,
  /** `@protocol: 'none'`: an internal service with no HTTP endpoint. */
  protocolNone: z.boolean(),
  /** `@cds.external`: an imported remote service. */
  external: z.boolean(),
  entities: list(RawCdsServiceEntitySchema, 2000),
  actions: list(RawCdsActionSchema, 500),
});
export type RawCdsService = z.infer<typeof RawCdsServiceSchema>;

export const RawCdsAssociationSchema = z.object({
  field: Identifier,
  /** The association target as written (alias not resolved). */
  target: Identifier,
});
export type RawCdsAssociation = z.infer<typeof RawCdsAssociationSchema>;

/** A top-level or namespaced entity (not one inside a service block). */
export const RawCdsEntitySchema = z.object({
  name: Identifier,
  line: Line,
  fields: list(Identifier, 200),
  /** `@PersonalData` on the entity header or on any element inline. */
  personalData: z.boolean(),
  associations: list(RawCdsAssociationSchema, 200),
});
export type RawCdsEntity = z.infer<typeof RawCdsEntitySchema>;

export const RawCdsAnnotateSchema = z.object({
  /** The `annotate TARGET` as written (alias not resolved). */
  target: Identifier,
  line: Line,
  /** `@PersonalData` anywhere in the statement (header or element block). */
  personalData: z.boolean(),
  requires: Roles,
  restrictTo: Roles,
});
export type RawCdsAnnotate = z.infer<typeof RawCdsAnnotateSchema>;

export const RawCdsFileSchema = z.object({
  file: RelativePathSchema,
  /** `using X as Y from` within this file (identifiers only). */
  usings: list(RawCdsUsingSchema, 500),
  services: list(RawCdsServiceSchema, 500),
  entities: list(RawCdsEntitySchema, 2000),
  annotates: list(RawCdsAnnotateSchema, 2000),
});
export type RawCdsFile = z.infer<typeof RawCdsFileSchema>;

export const SeedSensitiveKindSchema = z.enum(['card', 'iban', 'secret']);
export type SeedSensitiveKind = z.infer<typeof SeedSensitiveKindSchema>;

export const RawSeedSensitiveColumnSchema = z.object({
  /** 1-based position of the column in the header; the name itself is never stored. */
  columnIndex: Line,
  kind: SeedSensitiveKindSchema,
  rowsMatching: Count,
});
export type RawSeedSensitiveColumn = z.infer<typeof RawSeedSensitiveColumnSchema>;

/** A seed CSV: header shape and value checks only; no header names or values are stored, only column positions. */
export const RawSeedDataSchema = z.object({
  file: RelativePathSchema,
  columnCount: Count,
  /** The header had a field that is not identifier-shaped, so no values were checked. */
  headerRejected: z.boolean(),
  rowsChecked: Count,
  sensitiveColumns: list(RawSeedSensitiveColumnSchema, 200),
});
export type RawSeedData = z.infer<typeof RawSeedDataSchema>;

/** An `*.mtar` seen by the walk; only `stat`ed, never opened. */
export const RawArchiveSchema = z.object({
  file: RelativePathSchema,
  bytes: Count,
  /** Matched by a .gitignore pattern. */
  ignored: z.boolean(),
});
export type RawArchive = z.infer<typeof RawArchiveSchema>;

export const Ui5VersionFormSchema = z.enum(['specific', 'evergreen', 'latest', 'none']);
export type Ui5VersionForm = z.infer<typeof Ui5VersionFormSchema>;

/** A SAPUI5 bootstrap script in an HTML file. */
export const RawHtmlBootstrapSchema = z.object({
  file: RelativePathSchema,
  line: Line,
  /**
   * Of an http(s) URL the origin and path only (no userinfo, query or fragment);
   * of a relative src the file name only; `[non-http]` for other schemes.
   */
  src: z.string().max(200),
  external: z.boolean(),
  /** An `integrity` attribute is present (its value is never stored). */
  integrity: z.boolean(),
  versionForm: Ui5VersionFormSchema,
  /** Under a `test/` directory, or named like flpSandbox.html / *.qunit.html. */
  testPage: z.boolean(),
});
export type RawHtmlBootstrap = z.infer<typeof RawHtmlBootstrapSchema>;

const PackageName = z.string().max(214).regex(LOCKED_PACKAGE_NAME_PATTERN);
const PackageVersion = z.string().max(64).regex(PACKAGE_VERSION_PATTERN);

/**
 * Which lockfile it is: `package-lock.json`, `npm-shrinkwrap.json`, the
 * hidden lockfile npm writes into `node_modules` (deployed apps only), or the
 * lockfile of another package manager, which is listed and never opened.
 */
export const LockfileKindSchema = z.enum(['package-lock', 'shrinkwrap', 'hidden', 'yarn', 'pnpm']);
export type LockfileKind = z.infer<typeof LockfileKindSchema>;

/**
 * What became of a lockfile. `unsupported` is a yarn or pnpm lockfile;
 * `unreadable` one that could not be opened or is not an npm lockfile;
 * `too-large` one over the size or shape limits; `too-many-packages` one
 * whose packages did not fit into the package budget of the scan. Only a
 * lockfile that was `read` has packages in the project's list.
 */
export const LockfileStatusSchema = z.enum([
  'read',
  'unsupported',
  'unreadable',
  'too-large',
  'too-many-packages',
]);
export type LockfileStatus = z.infer<typeof LockfileStatusSchema>;

/**
 * Why entries of a lockfile are not in the project's package list, as counts:
 * the name of such a package is never kept (D10). The first six are where the
 * entry was resolved from; `excluded` matched `--dependency-exclude`;
 * `invalid` has a name or version that is not a plain npm one.
 */
export const RawNotKeptSchema = z.object({
  /** Resolved from any http(s) host other than `https://registry.npmjs.org`. */
  otherRegistry: Count,
  git: Count,
  /** A local tarball or folder. */
  file: Count,
  /** A local folder linked into `node_modules` (a workspace member, a `file:` folder): code of the project itself, counted once. */
  link: Count,
  /** Shipped inside another package's tarball (`inBundle`, `bundled`). */
  bundled: Count,
  /** No `resolved` at all, so where it came from is not known. */
  unknown: Count,
  excluded: Count,
  invalid: Count,
});
export type RawNotKept = z.infer<typeof RawNotKeptSchema>;

/** One lockfile the collector saw (docs/data-sources.md §12.1). */
export const RawLockfileSchema = z.object({
  file: RelativePathSchema,
  kind: LockfileKindSchema,
  /** null when the file was not read, or names no version this tool knows. */
  lockfileVersion: z.literal([1, 2, 3]).nullable(),
  status: LockfileStatusSchema,
  /** Packages of this lockfile that are in the project's `packages`: resolved from the public npm registry. */
  kept: Count,
  notKept: RawNotKeptSchema,
});
export type RawLockfile = z.infer<typeof RawLockfileSchema>;

export const PackageScopeSchema = z.enum(['prod', 'dev', 'optional']);
export type PackageScope = z.infer<typeof PackageScopeSchema>;

/**
 * A package the lockfiles pin, resolved from the public npm registry: one
 * entry per name and version per project. Neither the `resolved` URL nor
 * `integrity` nor any other field of the lockfile entry is kept.
 */
export const RawLockedPackageSchema = z.object({
  name: PackageName,
  version: PackageVersion,
  /** Listed by the root manifest and installed at the top level, or listed by a workspace member, in any lockfile. */
  direct: z.boolean(),
  /** `prod` when any lockfile installs it for production, else `optional`, else `dev`. */
  scope: PackageScopeSchema,
  /** The lockfiles that pin it, sorted: the first 20, or fewer of them when their paths are long. */
  lockfiles: list(RelativePathSchema, 20),
});
export type RawLockedPackage = z.infer<typeof RawLockedPackageSchema>;

/** The npm lockfiles of a project and the packages they pin (docs/data-sources.md §12.1). */
export const RawProjectDependenciesSchema = z.object({
  lockfiles: list(RawLockfileSchema, 50),
  /** Lockfiles found and not opened: beyond the 50, or beyond the bytes lockfiles may take. */
  lockfilesNotRead: Count,
  packages: list(RawLockedPackageSchema, 20_000),
});
export type RawProjectDependencies = z.infer<typeof RawProjectDependenciesSchema>;

/*
 * What the lookup on OSV.dev found for the packages above (`baip-lens
 * project`, docs/data-sources.md §12.3). Of an advisory only what follows is
 * kept: never its details, its references or the people it credits. The
 * summary is text from outside: it is cleaned and cut before it is stored,
 * and bounded here again. The tables hold all of an answer or nothing of it:
 * when the lookup fails, both stay empty and the check `collect.osv` says so.
 */

/** An advisory id as the OSV schema allows it (`GHSA-…`, `CVE-…`, `MAL-…`); it goes into request URLs. */
export const ADVISORY_ID_PATTERN = /^[A-Za-z0-9:_.-]{1,100}$/;
/** A CVSS v3.0 or v3.1 vector; the rule computes the score from it. */
export const CVSS_V3_PATTERN = /^CVSS:3\.[01]\/[A-Za-z:/]{1,150}$/;

const AdvisoryId = z.string().regex(ADVISORY_ID_PATTERN);

/** The severity a GitHub advisory states in words (`database_specific.severity`). */
export const AdvisoryLabelSchema = z.enum(['LOW', 'MODERATE', 'HIGH', 'CRITICAL']);
export type AdvisoryLabel = z.infer<typeof AdvisoryLabelSchema>;

/** One advisory of OSV.dev; a withdrawn one is not stored. */
export const RawAdvisorySchema = z.object({
  id: AdvisoryId,
  /** Its other ids, CVE ids above all: the first 20, sorted. */
  aliases: list(AdvisoryId, LIMITS.advisoryAliases),
  /** One line of external text, cleaned and cut to 200 characters. */
  summary: z.string().max(200).nullable(),
  /** The first CVSS v3 vector the advisory carries. */
  cvssV3: z.string().regex(CVSS_V3_PATTERN).nullable(),
  label: AdvisoryLabelSchema.nullable(),
});
export type RawAdvisory = z.infer<typeof RawAdvisorySchema>;

/** An advisory of one package: its id, and the fixed versions it names for that package name, sorted. */
export const RawPackageAdvisorySchema = z.object({
  id: AdvisoryId,
  /** Empty when the advisory names no fixed version for this package. */
  fixed: list(PackageVersion, LIMITS.fixedVersions),
});
export type RawPackageAdvisory = z.infer<typeof RawPackageAdvisorySchema>;

/** A package version of the lockfiles with at least one advisory; shared by the projects of a scan. */
export const RawVulnerablePackageSchema = z.object({
  name: PackageName,
  version: PackageVersion,
  advisories: list(RawPackageAdvisorySchema, LIMITS.packageAdvisories),
});
export type RawVulnerablePackage = z.infer<typeof RawVulnerablePackageSchema>;

/**
 * A package version of the lockfiles that the public npm registry marks as
 * deprecated (`baip-lens project`, docs/data-sources.md §12.4); shared by
 * the projects of a scan. Of the registry's answer nothing else is kept:
 * never the people who maintain or published the package, nor an address of
 * theirs. The message is text from outside: it is cleaned and cut before it
 * is stored, and bounded here again. The table holds all of the registry's
 * answers or nothing of them: when the lookup fails it stays empty and the
 * check `collect.npm-deprecations` says so.
 */
export const RawDeprecationSchema = z.object({
  name: PackageName,
  version: PackageVersion,
  /** One line of external text, cleaned and cut to 200 characters; empty when the registry gives no reason. */
  message: z.string().max(200),
  /** The version the registry calls `latest` for the package; null when it names none that is a plain version. */
  latest: PackageVersion.nullable(),
  /** That version is deprecated as well, or the registry names none: the package as a whole is given up. */
  latestDeprecated: z.boolean(),
});
export type RawDeprecation = z.infer<typeof RawDeprecationSchema>;

const MtaName = z.string().regex(MTA_NAME_PATTERN);

/**
 * Where the files of a project were read from, for `baip-lens project --cf`:
 * the deployed app and, when the deploy service marked the app as a module of
 * an MTA, that identity (docs/data-sources.md §11). The MTA values are set by
 * whoever may update the app, so only pattern-checked identifiers are kept.
 */
export const RawDeploymentSchema = z.object({
  /** The Cloud Foundry app name, as the API returned it (at most 255 characters there). */
  app: z.string().min(1).max(255),
  /** null for an app that was not deployed as part of an MTA. */
  mta: z
    .object({
      id: MtaName,
      version: z.string().regex(MTA_VERSION_PATTERN).nullable(),
      /** The module of the MTA this app was built from. */
      module: MtaName.nullable(),
      /** null for a deployment without a namespace. */
      namespace: z.string().regex(MTA_NAMESPACE_PATTERN).nullable(),
    })
    .nullable(),
});
export type RawDeployment = z.infer<typeof RawDeploymentSchema>;

export const RawProjectSchema = z.object({
  id: z.string().regex(PROJECT_ID_PATTERN),
  /** Set for a deployed app (`project --cf`); absent for a local folder and in snapshots written before the field existed. */
  deployment: RawDeploymentSchema.optional(),
  /** Which optional cds config sources existed and were read. */
  sourcesRead: list(CdsSourceSchema, 3),
  /** Files the collector opened (allow-listed names only), sorted. */
  files: list(RelativePathSchema, 500),
  filesTruncated: z.boolean(),
  /** How many files inside the project the collector opened (listed or unreadable), whatever the listing cap. */
  filesOpened: Count,
  unreadable: list(RawUnreadableSchema, 200),
  /** A `.git` entry exists in the root or one of its ancestors (lstat only, never read). */
  repository: z.boolean(),
  gitIgnore: z.object({ present: z.boolean() }),
  packageJson: RawPackageJsonSchema,
  cds: z.object({
    /** Effective config per profile, after merging the sources in cds order and applying `[profile]` blocks. */
    effective: z.object({
      development: CdsViewSchema,
      production: CdsViewSchema,
    }),
  }),
  mta: RawMtaSchema.nullable(),
  xsSecurity: list(RawXsSecuritySchema, 100),
  xsApps: list(RawXsAppSchema, 100),
  cdsFiles: list(RawCdsFileSchema, 2000),
  seedData: list(RawSeedDataSchema, 500),
  archives: list(RawArchiveSchema, 200),
  html: list(RawHtmlBootstrapSchema, 200),
  /** The npm lockfiles and the packages they pin; null in snapshots written before they were read. */
  dependencies: RawProjectDependenciesSchema.nullable().default(null),
});
export type RawProject = z.infer<typeof RawProjectSchema>;

export const RawDataSchema = z.object({
  orgs: list(RawOrgSchema, LIMITS.orgs),
  spaces: list(RawSpaceSchema, LIMITS.spaces),
  apps: list(RawAppSchema, LIMITS.apps),
  /** Current droplet per app; absent when the droplet collector was skipped. */
  droplets: list(RawDropletSchema, LIMITS.droplets),
  /** Routes with a destination in the inventory; empty in snapshots written before 0.3. */
  routes: list(RawRouteSchema, LIMITS.routes).default([]),
  /** `web` processes of the inventory's apps; empty in snapshots written before 0.3. */
  processes: list(RawProcessSchema, LIMITS.processes).default([]),
  /** Last request per app that has an HTTP route, from Log Cache; empty before 0.3. */
  traffic: list(RawTrafficSchema, LIMITS.traffic).default([]),
  /** Traffic history per app, this scan included (`scan --previous`); empty before 0.3. */
  history: list(RawHistorySchema, LIMITS.history).default([]),
  /** Local projects (`baip-lens project`); empty for a CF scan and in snapshots written before 0.2. */
  projects: list(RawProjectSchema, LIMITS.projects).default([]),
  /**
   * The advisories OSV.dev lists for the lockfile packages of the projects;
   * empty when the lookup did not run (see the check `collect.osv`), for a CF
   * scan and in snapshots written before the lookup existed.
   */
  advisories: list(RawAdvisorySchema, LIMITS.advisories).default([]),
  /** The package versions that have at least one of them; empty in the same cases. */
  vulnerablePackages: list(RawVulnerablePackageSchema, LIMITS.vulnerablePackages).default([]),
  /**
   * The lockfile packages the npm registry marks as deprecated; empty when
   * that lookup did not run (see the check `collect.npm-deprecations`), for a
   * CF scan and in snapshots written before the lookup existed.
   */
  deprecations: list(RawDeprecationSchema, LIMITS.deprecations).default([]),
});
export type RawData = z.infer<typeof RawDataSchema>;
