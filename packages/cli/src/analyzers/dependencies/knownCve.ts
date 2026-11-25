import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import {
  ADVISORY_ID_PATTERN,
  type AdvisoryLabel,
  type PackageScope,
  type RawAdvisory,
  type RawData,
  type RawLockedPackage,
  type RawProject,
  type RawVulnerablePackage,
} from '../../model/raw.js';
import { type Severity, severityRank } from '../../model/severity.js';
import { projectFinding } from '../project/support.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';
import { cvssV3BaseScore } from './cvss.js';
import { type SemVer, compareSemVer, parseSemVer } from './semver.js';

export const RULE_ID = 'DEP_KNOWN_CVE';

/** Where the severity of a finding comes from. */
export type SeverityFrom = 'malicious' | 'cvss' | 'label' | 'default';

/*
 * The severity is not taken from the criticality matrix: an advisory states
 * it itself, and the people who wrote it know the weakness. In this order:
 * a package reported as malicious code is `critical` whatever else is said
 * about it; else the CVSS v3 base score, computed from the vector with the
 * bands of the CVSS specification; else the label of the advisory database;
 * else `medium`, for an advisory that says nothing (and for one the tables
 * name but do not hold), so that it is neither hidden nor overstated.
 */
const MALICIOUS_PREFIX = 'MAL-';
const UNRATED: Severity = 'medium';
const LABEL_SEVERITY: Record<AdvisoryLabel, Severity> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MODERATE: 'medium',
  LOW: 'low',
};
/** Among advisories of one severity and score, the one whose source says more comes first. */
const FROM_ORDER: Record<SeverityFrom, number> = { malicious: 0, cvss: 1, label: 2, default: 3 };
const SCOPE_ORDER: Record<PackageScope, number> = { prod: 0, optional: 1, dev: 2 };

/*
 * A finding stays small whatever a package has: ten advisories and ten other
 * ids by name, with the true number next to them, and five lockfile paths.
 * The references are bounded with them (a snapshot holds at most 100 each).
 */
const MAX_IDS = 10;
const MAX_LOCKFILES = 5;

const TITLE = 'Dependency with a known vulnerability';

const WHERE_IT_COMES_FROM =
  '`npm ls <package>` shows which dependency brings the package in. For a direct dependency ' +
  '(`direct` is true), change its version in `package.json` and install again. For a ' +
  'transitive one, upgrade the dependency that requires it, or pin the version of the ' +
  'transitive package with `overrides` in `package.json` until that dependency follows.';

type Branch = 'fix' | 'noFix' | 'malicious';

const REMEDIATIONS: Record<Branch, string> = {
  fix:
    'Upgrade the package to the version in `fixedIn` or a later one. For each advisory of this ' +
    'finding the lowest fixed version above the installed one was taken, and `fixedIn` is the ' +
    `highest of them. ${WHERE_IT_COMES_FROM} Commit the lockfile, deploy the app again and ` +
    'scan again: the scan judges the version that is installed then, so a finding that is ' +
    'still there says the upgrade did not go far enough.',
  noFix:
    'At least one advisory of this finding names no fixed version above the installed one ' +
    '(`fixedIn` is null), so an upgrade alone may not clear it. Read the advisories linked ' +
    'below: they say which versions are affected and whether a setting, another major version ' +
    `or another package helps. ${WHERE_IT_COMES_FROM} ` +
    'Where the vulnerable code cannot be reached in this app, accept the finding and write ' +
    'down why.',
  malicious:
    'This package version is reported as malicious code (an advisory whose id starts with ' +
    '`MAL-`): it was published to do harm, not written with a flaw. Remove it, and treat every ' +
    'machine, pipeline and app that installed it as compromised: rotate the credentials that ' +
    'were within its reach (tokens, service keys, the contents of `.npmrc` and of the ' +
    'environment), and review what was built and deployed since it came in. ' +
    `${WHERE_IT_COMES_FROM} Install a version that is not reported, or replace the package.`,
};

const REFERENCES = [
  'https://docs.npmjs.com/cli/v11/commands/npm-ls',
  'https://docs.npmjs.com/cli/v11/configuring-npm/package-json#overrides',
];
const ADVISORY_PAGE = 'https://osv.dev/vulnerability/';

/** Code-point order, so the result does not depend on the process locale. */
function compareText(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/** A name holds no `@` after its first character and a version none at all, so the key is unambiguous. */
function packageKey(name: string, version: string): string {
  return `${name}@${version}`;
}

/** What one advisory says, as far as a finding needs it. */
interface Assessment {
  severity: Severity;
  from: SeverityFrom;
  /** The CVSS v3 base score; null without a vector that gives one above 0. */
  score: number | null;
  summary: string | null;
  aliases: readonly string[];
}

/** The severity band of a CVSS base score; a score of 0 rates nothing. */
function severityOfScore(score: number): Severity {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  return score >= 4 ? 'medium' : 'low';
}

function usableScore(advisory: RawAdvisory | undefined): number | null {
  if (advisory === undefined || advisory.cvssV3 === null) return null;
  const score = cvssV3BaseScore(advisory.cvssV3);
  return score !== null && score > 0 ? score : null;
}

/** `advisory` is undefined for an id the tables name but do not hold. */
function assess(id: string, advisory: RawAdvisory | undefined): Assessment {
  const score = usableScore(advisory);
  const rest = { score, summary: advisory?.summary ?? null, aliases: advisory?.aliases ?? [] };
  if (id.startsWith(MALICIOUS_PREFIX)) return { severity: 'critical', from: 'malicious', ...rest };
  if (score !== null) return { severity: severityOfScore(score), from: 'cvss', ...rest };
  const label = advisory?.label ?? null;
  if (label !== null) return { severity: LABEL_SEVERITY[label], from: 'label', ...rest };
  return { severity: UNRATED, from: 'default', ...rest };
}

/**
 * Worst first: by severity; among the critical ones a report of malicious
 * code before any score, because it changes what has to be done; then by
 * score, then by how much the source of the severity says.
 */
function compareAssessments(a: Assessment, b: Assessment): number {
  return (
    severityRank(b.severity) - severityRank(a.severity) ||
    Number(b.from === 'malicious') - Number(a.from === 'malicious') ||
    (b.score ?? 0) - (a.score ?? 0) ||
    FROM_ORDER[a.from] - FROM_ORDER[b.from]
  );
}

/** Everything of an assessment as one text: the last word between two readings of one id. */
function assessmentText(assessment: Assessment): string {
  return JSON.stringify([assessment.summary, [...assessment.aliases].sort(compareText)]);
}

/** A package version of the tables: id of each of its advisories to the fixed versions named for it. */
interface VulnerablePackage {
  version: string;
  advisories: Map<string, Set<string>>;
}

/** A package or an id listed twice is read as one: the advisories and the fixed versions add up. */
function indexPackages(rows: readonly RawVulnerablePackage[]): Map<string, VulnerablePackage> {
  const packages = new Map<string, VulnerablePackage>();
  for (const row of rows) {
    const key = packageKey(row.name, row.version);
    const own = packages.get(key) ?? {
      version: row.version,
      advisories: new Map<string, Set<string>>(),
    };
    packages.set(key, own);
    for (const { id, fixed } of row.advisories) {
      const versions = own.advisories.get(id) ?? new Set<string>();
      own.advisories.set(id, versions);
      for (const version of fixed) versions.add(version);
    }
  }
  return packages;
}

/** An advisory listed twice is read once: the worse reading, whatever the order of the two. */
function indexAdvisories(rows: readonly RawAdvisory[]): Map<string, Assessment> {
  const advisories = new Map<string, Assessment>();
  for (const row of rows) {
    const assessed = assess(row.id, row);
    const known = advisories.get(row.id);
    const order =
      known === undefined
        ? -1
        : compareAssessments(assessed, known) ||
          compareText(assessmentText(assessed), assessmentText(known));
    if (order < 0) advisories.set(row.id, assessed);
  }
  return advisories;
}

/** A fixed version an advisory names, as text and taken apart. */
interface Fix {
  text: string;
  version: SemVer;
}

/**
 * The lowest of the fixed versions that lies above the installed one, or
 * null: a version at or below it fixes nothing for this install (it closes
 * another range of the advisory), and a version that cannot be read as one
 * is not offered as advice.
 */
function lowestFixAbove(installed: SemVer | null, fixed: Iterable<string>): Fix | null {
  if (installed === null) return null;
  let lowest: Fix | null = null;
  for (const text of fixed) {
    const version = parseSemVer(text);
    if (version === null || compareSemVer(version, installed) <= 0) continue;
    const order =
      lowest === null
        ? -1
        : compareSemVer(version, lowest.version) || compareText(text, lowest.text);
    if (order < 0) lowest = { text, version };
  }
  return lowest;
}

/**
 * The highest of the fixes of the advisories, or null when one of them has
 * none. It is a version to try, not a promise: each advisory was asked for
 * its lowest fix above the installed version, and the highest of those can
 * still lie inside a later range of another advisory.
 */
function fixForAll(fixes: readonly (Fix | null)[]): string | null {
  let highest: Fix | null = null;
  for (const fix of fixes) {
    if (fix === null) return null;
    // Two spellings of one precedence (build metadata): the first in code-point order.
    const order =
      highest === null
        ? 1
        : compareSemVer(fix.version, highest.version) || compareText(highest.text, fix.text);
    if (order > 0) highest = fix;
  }
  return highest?.text ?? null;
}

/** An advisory of one package: what it says, and the fix it names for the installed version. */
interface PackageAdvisory extends Assessment {
  id: string;
  fix: Fix | null;
}

/** The advisories of a package, worst first; among equals by id. */
function advisoriesOf(
  own: VulnerablePackage,
  assessments: ReadonlyMap<string, Assessment>,
): PackageAdvisory[] {
  const installed = parseSemVer(own.version);
  return [...own.advisories]
    .map(([id, fixed]) => ({
      id,
      // An id the tables name but do not hold is judged by the id alone.
      ...(assessments.get(id) ?? assess(id, undefined)),
      fix: lowestFixAbove(installed, fixed),
    }))
    .sort((a, b) => compareAssessments(a, b) || compareText(a.id, b.id));
}

/**
 * What the advisories of one package version say together. It is the same
 * for every project that holds the package, so it is worked out once.
 */
interface Verdict {
  severity: Severity;
  branch: Branch;
  /** The part of the evidence that the advisories decide, in the order of the report. */
  evidence: {
    advisories: string[];
    advisoryCount: number;
    aliases: string[];
    fixedIn: string | null;
    score: number | null;
    severityFrom: SeverityFrom;
    summary: string | null;
  };
  references: string[];
}

/** Undefined for a package the tables list without an advisory: there is nothing to report. */
function verdictOf(advisories: readonly PackageAdvisory[]): Verdict | undefined {
  const [worst] = advisories;
  if (worst === undefined) return undefined;
  // The ten worst, by id: the advisory that decides the severity is always among them.
  const shown = advisories.slice(0, MAX_IDS).sort((a, b) => compareText(a.id, b.id));
  const ids = shown.map((advisory) => advisory.id);
  const aliases = [...new Set(shown.flatMap((advisory) => advisory.aliases))].sort(compareText);
  const fixedIn = fixForAll(advisories.map((advisory) => advisory.fix));
  return {
    severity: worst.severity,
    branch: worst.from === 'malicious' ? 'malicious' : fixedIn === null ? 'noFix' : 'fix',
    evidence: {
      advisories: ids,
      advisoryCount: advisories.length,
      aliases: aliases.slice(0, MAX_IDS),
      fixedIn,
      // The score that gave the severity, or none: a score of another advisory
      // next to a severity it did not decide would read as a mistake.
      score: worst.from === 'cvss' ? worst.score : null,
      severityFrom: worst.from,
      summary: worst.summary,
    },
    references: [
      ...REFERENCES,
      // An id becomes part of an address only when it is one, and a segment of dots is a step in a path.
      ...ids
        .filter((id) => ADVISORY_ID_PATTERN.test(id) && !/^\.+$/.test(id))
        .map((id) => `${ADVISORY_PAGE}${id}`),
      owaspUrl('A03:2025'),
    ],
  };
}

/**
 * The tables of the lookup, read once for all projects of the scan:
 * `name@version` of every package that has an advisory to what its
 * advisories say. No project is looked at here, and no table again later.
 */
function verdicts(raw: RawData): Map<string, Verdict> {
  const assessments = indexAdvisories(raw.advisories);
  const found = new Map<string, Verdict>();
  for (const [key, own] of indexPackages(raw.vulnerablePackages)) {
    const verdict = verdictOf(advisoriesOf(own, assessments));
    if (verdict !== undefined) found.set(key, verdict);
  }
  return found;
}

/** A package of a project, with what a second record of the same version adds. */
interface LockedPackage {
  name: string;
  version: string;
  direct: boolean;
  scope: PackageScope;
  lockfiles: Set<string>;
}

/**
 * The packages of a project, each version once. The lockfile step writes
 * one record per version; should a snapshot hold two, they are merged as
 * that step merges two lockfile entries: direct when one is, and the scope
 * that installs it most widely.
 */
function lockedPackages(packages: readonly RawLockedPackage[]): Map<string, LockedPackage> {
  const merged = new Map<string, LockedPackage>();
  for (const { name, version, direct, scope, lockfiles } of packages) {
    const key = packageKey(name, version);
    const known = merged.get(key);
    if (known === undefined) {
      merged.set(key, { name, version, direct, scope, lockfiles: new Set(lockfiles) });
      continue;
    }
    known.direct ||= direct;
    if (SCOPE_ORDER[scope] < SCOPE_ORDER[known.scope]) known.scope = scope;
    for (const file of lockfiles) known.lockfiles.add(file);
  }
  return merged;
}

/** A path with a `node_modules` folder in it: the lockfile npm wrote into the installed tree. */
function isInsideNodeModules(file: string): boolean {
  return file.split('/').includes('node_modules');
}

function findingFor(
  context: AnalyzerContext,
  project: RawProject,
  locked: LockedPackage,
  verdict: Verdict,
): Finding {
  const lockfiles = [...locked.lockfiles].sort(compareText);
  const [firstLockfile] = lockfiles;
  const { advisories, advisoryCount, aliases, fixedIn, score, severityFrom, summary } =
    verdict.evidence;
  return projectFinding(context, project, {
    id: RULE_ID,
    title: TITLE,
    subject: packageKey(locked.name, locked.version),
    severity: verdict.severity,
    evidence: {
      package: locked.name,
      version: locked.version,
      direct: locked.direct,
      scope: locked.scope,
      // Lists of a verdict are shared by the projects that hold the package: each finding gets its own.
      advisories: [...advisories],
      advisoryCount,
      aliases: [...aliases],
      fixedIn,
      score,
      severityFrom,
      summary,
      lockfiles: lockfiles.slice(0, MAX_LOCKFILES),
      lockfileCount: lockfiles.length,
    },
    // A finding never points into `node_modules`: the lockfile of the installed tree is named in the evidence only.
    ...(firstLockfile === undefined || isInsideNodeModules(firstLockfile)
      ? {}
      : { location: { file: firstLockfile } }),
    remediation: REMEDIATIONS[verdict.branch],
    references: [...verdict.references],
  });
}

function findingsFor(
  context: AnalyzerContext,
  project: RawProject,
  found: ReadonlyMap<string, Verdict>,
): Finding[] {
  // null: a snapshot written before lockfiles were read says nothing about packages.
  if (project.dependencies === null) return [];
  const locked = [...lockedPackages(project.dependencies.packages)].sort(([a], [b]) =>
    compareText(a, b),
  );
  return locked.flatMap(([key, item]) => {
    const verdict = found.get(key);
    return verdict === undefined ? [] : [findingFor(context, project, item, verdict)];
  });
}

/**
 * DEP_KNOWN_CVE: a package version that a lockfile of the project pins from
 * the public npm registry has a known vulnerability, or is reported as
 * malicious, according to OSV.dev. One finding per project and package
 * version; it reads the answers the lookup stored and asks nothing itself.
 * See docs/rules.md.
 */
export const knownCve: Analyzer = {
  rule: {
    id: RULE_ID,
    title: TITLE,
    description:
      'A package version that an npm lockfile of the project pins from the public npm registry has a known vulnerability, or is reported as malicious code, according to OSV.dev. The severity is the highest among its advisories: critical for a malicious package, else from the CVSS v3 base score, else from the severity the advisory states in words, else medium.',
    roles: [],
    owasp: ['A03:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.dependencies', 'collect.osv'],
  analyze(context): Finding[] {
    const found = verdicts(context.raw);
    return context.raw.projects.flatMap((project) => findingsFor(context, project, found));
  },
};
