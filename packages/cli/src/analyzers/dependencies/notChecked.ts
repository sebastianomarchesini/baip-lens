import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { RawNotKept, RawProject, RawProjectDependencies } from '../../model/raw.js';
import type { Severity } from '../../model/severity.js';
import { projectFinding } from '../project/support.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';

export const RULE_ID = 'DEP_NOT_CHECKED';

/*
 * Not a weakness of the project: the report says how much of the lockfiles
 * was not looked at, so that "no finding" is never read as "checked". No
 * cell of the criticality matrix says that, so the severity is fixed.
 */
const SEVERITY: Severity = 'info';

const SUBJECT = 'dependencies';

/** The reasons a package is not kept, in the order the evidence lists them. */
const REASONS = [
  'otherRegistry',
  'git',
  'file',
  'link',
  'bundled',
  'unknown',
  'excluded',
  'invalid',
] as const satisfies readonly (keyof RawNotKept)[];

const REMEDIATION =
  'A package is kept by name, and can be looked up for known vulnerabilities and deprecation, ' +
  'only when its lockfile entry was resolved from the public npm registry ' +
  '(`https://registry.npmjs.org`), so that no private package name is taken from a lockfile or ' +
  'sent anywhere. The evidence counts the others by reason, without their names. ' +
  '`otherRegistry`: resolved from a company registry or a mirror; check these with the audit ' +
  'that registry offers. `git`, `file` and `link`: taken from a repository, a local tarball or ' +
  'folder, or a workspace; review them where their source lives. `bundled`: shipped inside ' +
  'another package, and fixed by upgrading that package. `unknown`: the lockfile records no ' +
  '`resolved` address (for example with `omit-lockfile-registry-resolved`); recreate the ' +
  'lockfile with addresses to have these checked. `excluded`: held back on purpose with ' +
  '`--dependency-exclude`. `invalid`: a name or version that is not a plain npm one; look at ' +
  'the lockfile entry itself. `lockfilesNotRead`: lockfiles that were found but not read (more ' +
  'than 50 lockfiles or 64 MiB of them in one project, a lockfile that is not valid or too ' +
  'large, or more packages than one scan keeps); scan their folders on their own with `--path`.';

const REFERENCES = [
  'https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json',
  owaspUrl('A03:2025'),
];

type Counts = Record<(typeof REASONS)[number], number>;

/** The packages not kept, per reason, summed over the lockfiles of a project. */
function notKeptCounts(dependencies: RawProjectDependencies): Counts {
  const counts: Counts = {
    otherRegistry: 0,
    git: 0,
    file: 0,
    link: 0,
    bundled: 0,
    unknown: 0,
    excluded: 0,
    invalid: 0,
  };
  for (const lockfile of dependencies.lockfiles) {
    for (const reason of REASONS) counts[reason] += lockfile.notKept[reason];
  }
  return counts;
}

/**
 * npm lockfiles that were found and whose packages are not in the list: not
 * opened (beyond the limit on lockfiles or on their bytes), or opened and
 * not usable. A yarn or pnpm lockfile is not one of them: it is never read,
 * and `DEP_LOCKFILE_MISSING` speaks for it.
 */
function lockfilesNotRead(dependencies: RawProjectDependencies): number {
  const failed = dependencies.lockfiles.filter(
    ({ status }) =>
      status === 'unreadable' || status === 'too-large' || status === 'too-many-packages',
  );
  return dependencies.lockfilesNotRead + failed.length;
}

function findingFor(context: AnalyzerContext, project: RawProject): Finding | undefined {
  // null: a snapshot written before lockfiles were read says nothing about them.
  if (project.dependencies === null) return undefined;
  const counts = notKeptCounts(project.dependencies);
  const notRead = lockfilesNotRead(project.dependencies);
  const packagesNotKept = REASONS.reduce((sum, reason) => sum + counts[reason], 0);
  if (packagesNotKept + notRead === 0) return undefined;
  return projectFinding(context, project, {
    id: RULE_ID,
    title: notChecked.rule.title,
    subject: SUBJECT,
    severity: SEVERITY,
    evidence: {
      ...counts,
      lockfilesNotRead: notRead,
      checked: project.dependencies.packages.length,
    },
    remediation: REMEDIATION,
    references: [...REFERENCES],
  });
}

/**
 * DEP_NOT_CHECKED: some packages of the lockfiles are never looked up,
 * because they do not come from the public npm registry, were excluded, or
 * sit in a lockfile that was not read. The finding counts them by reason and
 * names none. See docs/rules.md.
 */
export const notChecked: Analyzer = {
  rule: {
    id: RULE_ID,
    title: 'Some packages of the npm lockfiles were not checked',
    description:
      'Packages that were not resolved from the public npm registry (another registry, git, a local file or link, bundled, unknown source), that were excluded, or that sit in a lockfile that was not read are never looked up. They are counted by reason, and nothing of their lockfile entries is kept, not even a name.',
    roles: [],
    owasp: ['A03:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.dependencies'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) => findingFor(context, project) ?? []);
  },
};
