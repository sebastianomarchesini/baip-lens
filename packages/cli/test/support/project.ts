import { expect } from 'vitest';
import { analyze } from '../../src/analyzers/index.js';
import type { Analyzer } from '../../src/analyzers/types.js';
import type { CheckResult } from '../../src/model/check.js';
import type { Finding } from '../../src/model/finding.js';
import type {
  CdsView,
  RawArchive,
  RawCdsAction,
  RawCdsAnnotate,
  RawCdsEntity,
  RawCdsFile,
  RawCdsService,
  RawCdsServiceEntity,
  RawAdvisory,
  RawData,
  RawDependency,
  RawDeprecation,
  RawHtmlBootstrap,
  RawLockedPackage,
  RawLockfile,
  RawMta,
  RawMtaModule,
  RawMtaResource,
  RawProject,
  RawProjectDependencies,
  RawSeedData,
  RawVulnerablePackage,
  RawXsApp,
  RawXsAppRoute,
  RawXsSecurity,
  RawXsSecurityRoleTemplate,
  RawXsSecurityScope,
} from '../../src/model/raw.js';

/**
 * Builders for project rule tests: a minimal valid RawProject and one helper
 * per collected shape, so a test states only the facts it is about.
 */

export const NOW = '2026-09-29T00:00:00.000Z';

export const PROJECT_COLLECTOR: CheckResult = {
  id: 'collect.project',
  title: 'Project files',
  roles: [],
  status: 'ran',
};

export const PROJECT_COLLECTOR_SKIPPED: CheckResult = {
  ...PROJECT_COLLECTOR,
  status: 'skipped',
  reasonCode: 'error',
  reason: 'error: not a project',
};

/** The lockfile check a project scan records next to `collect.project`; the dependency rules require it. */
export const DEPENDENCIES_COLLECTOR: CheckResult = {
  id: 'collect.dependencies',
  title: 'npm lockfiles',
  roles: [],
  status: 'ran',
};

export const DEPENDENCIES_COLLECTOR_SKIPPED: CheckResult = {
  ...DEPENDENCIES_COLLECTOR,
  status: 'skipped',
  reasonCode: 'dependency_skipped',
  reason: 'needs collect.project, which did not run',
};

/**
 * The lookup on OSV.dev a project scan records when it was handed one
 * (`baip-lens project`); a rule that reads its answers requires it.
 */
export const OSV_COLLECTOR: CheckResult = {
  id: 'collect.osv',
  title: 'Known vulnerabilities of npm packages',
  roles: [],
  status: 'ran',
};

export const OSV_COLLECTOR_SKIPPED: CheckResult = {
  ...OSV_COLLECTOR,
  status: 'skipped',
  reasonCode: 'unavailable',
  reason: 'api.osv.dev could not be reached',
};

/**
 * The lookup on the npm registry a project scan records next to the one on
 * OSV.dev; a rule that reads the deprecated versions requires it.
 */
export const NPM_DEPRECATIONS_COLLECTOR: CheckResult = {
  id: 'collect.npm-deprecations',
  title: 'Deprecated npm packages',
  roles: [],
  status: 'ran',
};

export const NPM_DEPRECATIONS_COLLECTOR_SKIPPED: CheckResult = {
  ...NPM_DEPRECATIONS_COLLECTOR,
  status: 'skipped',
  reasonCode: 'unavailable',
  reason: 'registry.npmjs.org could not be reached',
};

/**
 * Values planted in the acme-incidents fixture (test/fixtures/projects) that
 * must never reach a snapshot, a report or the terminal. Rule tests put them
 * in every free-text position of their input as well.
 */
export const POISON: string[] = [
  'POISON_git_token',
  '/Users/poison-user',
  '@poison-scope/private',
  'jane.poison@example.com',
  'Jane Poison',
  'POISON_repo_token',
  'poison.user@example.com',
  'POISON_hunter2',
  'alice',
  'POISON_clientsecret',
  'POISON_vcap_user',
  'POISON_vcap_password',
  'poison-client',
  'POISON_env',
  'POISON_mtaext',
  'mta-poison',
  'jane.poison-notes',
  'POISON-secret',
  'POISON_http',
  'poison-bp',
  'POISON_bp_token',
  'POISON_tools_token',
  'POISON_hook',
  'POISON-service-key',
  '00000000-POIS-ON00-0000-000000000000',
  'poison-internal.example.com',
  'poison-redirect.example.com',
  'poison-foreign',
  'POISON-destination',
  'POISON-dir',
  'POISON_query',
  'POISON_fragment',
  'POISON_root',
  'POISON_user',
  'POISON_pw',
  'POISON_format',
  'POISON_title',
  'POISON_default',
  '/home/poison-user',
  'C:\\Users\\poison-user',
  'poison.where@example.com',
  'poison.row@example.com',
  'poison.row2@example.com',
  '4111111111111111',
  '5500000000000004',
  'jane_doe_notes',
  'POISON_big',
  'POISON_ui',
  'passwd-poison',
  'POISON_password_cell',
  'POISON_bp_path',
  // Planted in the lockfile of the fixture (test/support/lockfileFixture.ts): packages that
  // do not come from the public npm registry, and the fields of an entry that are never kept.
  'poison-lock-git',
  'POISON_lock_repo',
  'poison-lock-link',
  'poison-lock-folder',
  'poison-lock-tarball',
  'poison-lock-bundled',
  'poison-lock-unresolved',
  'poison-lock-invalid',
  'POISON_lock_version',
  'POISON_lock_token',
  'POISON_lock_integrity',
  'POISON_lock_deprecated',
  'POISON_lock_license',
];

type DeepPartial<T> = T extends (infer U)[]
  ? DeepPartial<U>[]
  : T extends object
    ? { [K in keyof T]?: DeepPartial<T[K]> }
    : T;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Objects merge key by key; arrays and primitives replace. */
function merge<T>(base: T, overrides: DeepPartial<T> | undefined): T {
  if (overrides === undefined) return base;
  if (!isPlainObject(base) || !isPlainObject(overrides)) return overrides as T;
  const result: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(overrides)) {
    result[key] = merge(base[key], value);
  }
  return result as T;
}

function emptyView(): CdsView {
  return {
    authKind: null,
    mockedUsers: 0,
    mockedUsersWithPassword: 0,
    restrictAllServices: null,
    auditLogKind: null,
    auditLogConfigured: false,
  };
}

export function rawProject(overrides?: DeepPartial<RawProject>): RawProject {
  const base: RawProject = {
    id: 'acme',
    sourcesRead: [],
    files: [],
    filesTruncated: false,
    filesOpened: 0,
    unreadable: [],
    repository: false,
    gitIgnore: { present: false },
    packageJson: {
      present: false,
      name: null,
      dependencies: [],
      devDependencies: [],
      nodeEngine: null,
    },
    cds: { effective: { development: emptyView(), production: emptyView() } },
    mta: null,
    xsSecurity: [],
    xsApps: [],
    cdsFiles: [],
    seedData: [],
    archives: [],
    html: [],
    dependencies: { lockfiles: [], lockfilesNotRead: 0, packages: [] },
  };
  return merge(base, overrides);
}

type Deps = Record<string, string> | string[];

function toDependencies(deps: Deps): RawDependency[] {
  return Array.isArray(deps)
    ? deps.map((name) => ({ name, range: '*' }))
    : Object.entries(deps).map(([name, range]) => ({ name, range }));
}

/** `packageJson({ '@sap/cds': '^9' })` or `packageJson(['@sap/cds'])`. */
export function packageJson(
  deps: Deps,
  devDeps: Deps = {},
  nodeEngine: string | null = null,
): RawProject['packageJson'] {
  return {
    present: true,
    name: 'acme',
    dependencies: toDependencies(deps),
    devDependencies: toDependencies(devDeps),
    nodeEngine,
  };
}

/** One profile view with the given facts; the other profile stays empty. */
export function cdsEffective(
  view: 'development' | 'production',
  partial: Partial<CdsView>,
): RawProject['cds'] {
  return {
    effective: {
      development: view === 'development' ? { ...emptyView(), ...partial } : emptyView(),
      production: view === 'production' ? { ...emptyView(), ...partial } : emptyView(),
    },
  };
}

export function cdsFile(file: string, parts: Partial<Omit<RawCdsFile, 'file'>> = {}): RawCdsFile {
  return { file, usings: [], services: [], entities: [], annotates: [], ...parts };
}

export function service(
  name: string,
  opts: {
    line?: number;
    requires?: string[];
    restrictTo?: string[];
    protocolNone?: boolean;
    external?: boolean;
    entities?: RawCdsServiceEntity[];
    actions?: RawCdsAction[];
  } = {},
): RawCdsService {
  return {
    name,
    line: opts.line ?? 1,
    requires: opts.requires ?? [],
    restrictTo: opts.restrictTo ?? [],
    protocolNone: opts.protocolNone ?? false,
    external: opts.external ?? false,
    entities: opts.entities ?? [],
    actions: opts.actions ?? [],
  };
}

export function serviceEntity(
  name: string,
  opts: {
    line?: number;
    requires?: string[];
    restrictTo?: string[];
    readonly?: boolean;
    projectionOf?: string | null;
  } = {},
): RawCdsServiceEntity {
  return {
    name,
    line: opts.line ?? 1,
    requires: opts.requires ?? [],
    restrictTo: opts.restrictTo ?? [],
    readonly: opts.readonly ?? false,
    projectionOf: opts.projectionOf ?? null,
  };
}

export function action(
  name: string,
  opts: { line?: number; requires?: string[]; restrictTo?: string[] } = {},
): RawCdsAction {
  return {
    name,
    line: opts.line ?? 1,
    requires: opts.requires ?? [],
    restrictTo: opts.restrictTo ?? [],
  };
}

export function entity(
  name: string,
  fields: string[],
  opts: {
    line?: number;
    personalData?: boolean;
    associations?: { field: string; target: string }[];
  } = {},
): RawCdsEntity {
  return {
    name,
    line: opts.line ?? 1,
    fields,
    personalData: opts.personalData ?? false,
    associations: opts.associations ?? [],
  };
}

export function annotate(
  target: string,
  opts: { line?: number; personalData?: boolean; requires?: string[]; restrictTo?: string[] } = {},
): RawCdsAnnotate {
  return {
    target,
    line: opts.line ?? 1,
    personalData: opts.personalData ?? false,
    requires: opts.requires ?? [],
    restrictTo: opts.restrictTo ?? [],
  };
}

export function xsSecurity(opts: {
  file?: string;
  source?: RawXsSecurity['source'];
  scopes: (string | RawXsSecurityScope)[];
  roleTemplates?: (RawXsSecurityRoleTemplate | [name: string, scopeReferences: string[]])[];
  attributes?: string[];
}): RawXsSecurity {
  return {
    file: opts.file ?? 'xs-security.json',
    source: opts.source ?? 'xs-security.json',
    scopes: opts.scopes.map((scope) =>
      typeof scope === 'string' ? { name: scope, grantedToApps: false } : scope,
    ),
    roleTemplates: (opts.roleTemplates ?? []).map((template) =>
      Array.isArray(template) ? { name: template[0], scopeReferences: template[1] } : template,
    ),
    attributes: opts.attributes ?? [],
  };
}

export function xsApp(
  file: string,
  routes: Partial<RawXsAppRoute>[],
  opts: { authenticationMethod?: RawXsApp['authenticationMethod'] } = {},
): RawXsApp {
  return {
    file,
    authenticationMethod: opts.authenticationMethod ?? 'route',
    routes: routes.map((route) => ({
      source: '^/(.*)$',
      authenticationType: 'xsuaa',
      csrfProtection: null,
      target: 'destination',
      targetHint: 'other',
      isLogoutPage: false,
      ...route,
    })),
  };
}

export function mta(
  opts: {
    id?: string | null;
    modules?: Partial<RawMtaModule>[];
    resources?: Partial<RawMtaResource>[];
    file?: RawMta['file'];
  } = {},
): RawMta {
  return {
    file: opts.file ?? 'mta.yaml',
    id: opts.id === undefined ? 'acme' : opts.id,
    modules: (opts.modules ?? []).map((module, i) => ({
      name: `module-${i}`,
      type: null,
      path: null,
      buildpack: null,
      requires: [],
      ...module,
    })),
    resources: (opts.resources ?? []).map((resource, i) => ({
      name: `resource-${i}`,
      type: null,
      service: null,
      plan: null,
      ...resource,
    })),
  };
}

export function seedCsv(
  file: string,
  opts: {
    columnCount?: number;
    rowsChecked?: number;
    sensitiveColumns?: RawSeedData['sensitiveColumns'];
    headerRejected?: boolean;
  } = {},
): RawSeedData {
  return {
    file,
    columnCount: opts.columnCount ?? 3,
    headerRejected: opts.headerRejected ?? false,
    rowsChecked: opts.rowsChecked ?? 10,
    sensitiveColumns: opts.sensitiveColumns ?? [],
  };
}

export function archive(
  file: string,
  opts: { bytes?: number; ignored?: boolean } = {},
): RawArchive {
  return { file, bytes: opts.bytes ?? 64, ignored: opts.ignored ?? false };
}

export function htmlBootstrap(
  file: string,
  src: string,
  opts: {
    line?: number;
    integrity?: boolean;
    external?: boolean;
    versionForm?: RawHtmlBootstrap['versionForm'];
    testPage?: boolean;
  } = {},
): RawHtmlBootstrap {
  const external = opts.external ?? /^https?:\/\//.test(src);
  return {
    file,
    line: opts.line ?? 1,
    src,
    external,
    integrity: opts.integrity ?? false,
    versionForm: opts.versionForm ?? (external ? 'latest' : 'none'),
    testPage: opts.testPage ?? false,
  };
}

/** A lockfile record; `read` with nothing kept and nothing left out unless the options say so. */
export function lockfile(
  file: string,
  opts: {
    kind?: RawLockfile['kind'];
    lockfileVersion?: RawLockfile['lockfileVersion'];
    status?: RawLockfile['status'];
    kept?: number;
    notKept?: Partial<RawLockfile['notKept']>;
  } = {},
): RawLockfile {
  const status = opts.status ?? 'read';
  return {
    file,
    kind: opts.kind ?? 'package-lock',
    lockfileVersion:
      opts.lockfileVersion === undefined ? (status === 'read' ? 3 : null) : opts.lockfileVersion,
    status,
    kept: opts.kept ?? 0,
    notKept: {
      otherRegistry: 0,
      git: 0,
      file: 0,
      link: 0,
      bundled: 0,
      unknown: 0,
      excluded: 0,
      invalid: 0,
      ...opts.notKept,
    },
  };
}

/** A package from the public npm registry as a project keeps it. */
export function lockedPackage(
  name: string,
  version: string,
  opts: { direct?: boolean; scope?: RawLockedPackage['scope']; lockfiles?: string[] } = {},
): RawLockedPackage {
  return {
    name,
    version,
    direct: opts.direct ?? false,
    scope: opts.scope ?? 'prod',
    lockfiles: opts.lockfiles ?? ['package-lock.json'],
  };
}

/** `dependencies(lockfile('package-lock.json'))`, with packages and a count of lockfiles not opened. */
export function dependencies(
  lockfiles: RawLockfile | RawLockfile[],
  opts: { packages?: RawLockedPackage[]; lockfilesNotRead?: number } = {},
): RawProjectDependencies {
  return {
    lockfiles: Array.isArray(lockfiles) ? lockfiles : [lockfiles],
    lockfilesNotRead: opts.lockfilesNotRead ?? 0,
    packages: opts.packages ?? [],
  };
}

export function rawData(...projects: RawProject[]): RawData {
  return {
    orgs: [],
    spaces: [],
    apps: [],
    droplets: [],
    routes: [],
    processes: [],
    traffic: [],
    history: [],
    projects,
    advisories: [],
    vulnerablePackages: [],
    deprecations: [],
  };
}

/** An advisory as the lookup on OSV.dev stores it; nothing but the id unless the options say so. */
export function advisory(id: string, opts: Partial<Omit<RawAdvisory, 'id'>> = {}): RawAdvisory {
  return { id, aliases: [], summary: null, cvssV3: null, label: null, ...opts };
}

/**
 * A package version with advisories: `vulnerablePackage('baip-fixture-merge', '4.17.20',
 * { 'GHSA-fake-0001-baip': ['4.17.21'] })`, each id with the fixed versions it names.
 */
export function vulnerablePackage(
  name: string,
  version: string,
  advisories: Record<string, string[]>,
): RawVulnerablePackage {
  return {
    name,
    version,
    advisories: Object.entries(advisories).map(([id, fixed]) => ({ id, fixed })),
  };
}

/**
 * A deprecated package version as the lookup on the npm registry stores it:
 * without a message, and with a newer version that is fine, unless the
 * options say so.
 */
export function deprecation(
  name: string,
  version: string,
  opts: Partial<Omit<RawDeprecation, 'name' | 'version'>> = {},
): RawDeprecation {
  return { name, version, message: '', latest: '99.0.0', latestDeprecated: false, ...opts };
}

/** Runs one rule as a project scan would: the project files and the lockfiles were read, nothing else exists. */
export function runRule(analyzer: Analyzer, ...projects: RawProject[]): Finding[] {
  const checks = [PROJECT_COLLECTOR, DEPENDENCIES_COLLECTOR];
  return analyze(rawData(...projects), NOW, checks, [analyzer]).findings;
}

/** Same input, same output: twice on the same object, and once on a copy. */
export function expectDeterministic(analyzer: Analyzer, project: RawProject): void {
  const first = runRule(analyzer, project);
  expect(runRule(analyzer, project)).toEqual(first);
  expect(runRule(analyzer, structuredClone(project))).toEqual(first);
}

/** No forbidden string appears anywhere in the findings (keys, values, nested evidence). */
export function expectNoValueLeak(findings: Finding[], forbidden: string[]): void {
  const text = JSON.stringify(findings);
  for (const value of forbidden) {
    expect(text, `findings contain "${value}"`).not.toContain(value);
  }
}
