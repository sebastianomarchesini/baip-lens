import type { Finding } from '../../model/finding.js';
import { owaspUrl } from '../../model/owasp.js';
import type { LockfileKind, LockfileStatus, RawLockfile, RawProject } from '../../model/raw.js';
import type { Severity } from '../../model/severity.js';
import { type MatrixSeverity, projectFinding } from '../project/support.js';
import { type Analyzer, type AnalyzerContext, ruleHelpUri } from '../types.js';

export const RULE_ID = 'DEP_LOCKFILE_MISSING';

/** Why no lockfile answers for the root manifest. */
export type LockfileMissingCause =
  | 'none'
  | 'unsupported'
  | Extract<LockfileStatus, 'unreadable' | 'too-large' | 'too-many-packages'>;

/*
 * Without a lockfile that could be read, the versions that are installed are
 * not known: the next install resolves the ranges anew, and no package can
 * be checked for a known vulnerability. That is hygiene, which pays off only
 * together with a bad release of a dependency, and to place one an attacker
 * needs the registry or the build first: `minor` × `complex`, the pair that
 * gives `low` (`minor` × `advanced` is `medium`).
 */
const NOT_PINNED: MatrixSeverity = { impact: 'minor', easeOfAttack: 'complex' };
/*
 * A yarn or pnpm lockfile pins the versions: nothing is wrong with the
 * project, only this tool did not look. No cell of the matrix says that, so
 * the severity is fixed.
 */
const NOT_READ_YET: Severity = 'info';

const MANIFEST = 'package.json';

const TITLES: Record<LockfileMissingCause, string> = {
  none: 'Dependencies are declared but no npm lockfile pins their versions',
  unreadable: 'The npm lockfile could not be read, so the installed packages were not checked',
  'too-large': 'The npm lockfile is too large to read, so the installed packages were not checked',
  'too-many-packages':
    'The npm lockfile pins more packages than one scan keeps, so they were not checked',
  unsupported: 'Dependencies are pinned by a lockfile BAIP Lens does not read yet',
};

const CREATE_LOCKFILE =
  'Create the lockfile with `npm install --package-lock-only` in the folder of the root ' +
  '`package.json` and commit it, then install in the pipeline with `npm ci`, which fails when ' +
  'the lockfile and `package.json` disagree instead of resolving other versions.';

const REMEDIATIONS: Record<LockfileMissingCause, string> = {
  none:
    `${CREATE_LOCKFILE} With the lockfile in place the installed versions are known and can be ` +
    'checked for known vulnerabilities and deprecation. If the scanned folder is a member of ' +
    'an npm workspace, its lockfile lies in the workspace root, outside the scanned folder, ' +
    'and was not seen: scan the workspace root instead.',
  unreadable:
    'The lockfile exists but is not one npm could use: it is not valid JSON (for example after ' +
    'an unresolved merge conflict), it names no lockfile version npm knows, or it is not a ' +
    'regular file. Delete it, recreate it with `npm install --package-lock-only` and commit it.',
  'too-large':
    'The lockfile is larger than BAIP Lens reads (32 MiB, or more keys and values than a ' +
    'lockfile of about 200,000 packages holds). Check that it really is the lockfile of this ' +
    'project; a repository of several packages can be scanned one package folder at a time ' +
    'with `--path`.',
  'too-many-packages':
    'The lockfiles of this scan pin more than 20,000 packages from the public npm registry, and ' +
    'a lockfile is read as a whole or not at all. Scan the package folders of the repository ' +
    'one at a time with `--path`, so that each scan stays under the limit.',
  unsupported:
    'BAIP Lens reads npm lockfiles only (`package-lock.json`, `npm-shrinkwrap.json`). The ' +
    'versions are pinned by yarn or pnpm, so nothing is wrong with the project, but its ' +
    'packages were not checked for known vulnerabilities or deprecation. Until BAIP Lens reads ' +
    'that lockfile, use the audit command of the package manager (`yarn npm audit`, `pnpm audit`).',
};

const REFERENCES = [
  'https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json',
  'https://docs.npmjs.com/cli/v11/commands/npm-ci',
  owaspUrl('A03:2025'),
];

const NPM_KINDS: readonly LockfileKind[] = ['package-lock', 'shrinkwrap', 'hidden'];

/** Code-point order, so the result does not depend on the process locale. */
function compareText(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/**
 * A lockfile that answers for the root manifest: `package-lock.json` or
 * `npm-shrinkwrap.json` next to it, the hidden lockfile of the installed
 * tree, or a yarn or pnpm lockfile (listed in the root only).
 */
function coversRoot(lockfile: RawLockfile): boolean {
  return lockfile.kind === 'hidden' || !lockfile.file.includes('/');
}

/**
 * How many dependencies the root manifest declares. A deployed app is
 * installed for production, so its `devDependencies` need no lockfile.
 */
function declaredDependencies(project: RawProject): number {
  const { dependencies, devDependencies } = project.packageJson;
  return dependencies.length + (project.deployment === undefined ? devDependencies.length : 0);
}

interface Missing {
  cause: LockfileMissingCause;
  /** The lockfile the finding is about; null when there is none at all. */
  lockfile: RawLockfile | null;
}

/**
 * Why the root has no lockfile that was read, or undefined when it has one.
 * An npm lockfile that could not be read comes before a yarn or pnpm one:
 * it is the file npm itself would use. Among several, the first by path.
 */
function missingLockfile(lockfiles: readonly RawLockfile[]): Missing | undefined {
  const atRoot = lockfiles
    .filter(coversRoot)
    .sort(
      (a, b) =>
        compareText(a.file, b.file) ||
        compareText(a.status, b.status) ||
        compareText(a.kind, b.kind),
    );
  const npm = atRoot.filter((lockfile) => NPM_KINDS.includes(lockfile.kind));
  if (npm.some((lockfile) => lockfile.status === 'read')) return undefined;
  for (const lockfile of npm) {
    const { status } = lockfile;
    if (status === 'unreadable' || status === 'too-large' || status === 'too-many-packages') {
      return { cause: status, lockfile };
    }
  }
  const foreign = atRoot.find((lockfile) => !NPM_KINDS.includes(lockfile.kind));
  return foreign === undefined
    ? { cause: 'none', lockfile: null }
    : { cause: 'unsupported', lockfile: foreign };
}

/*
 * A deployed app is not a folder of a repository: nothing in a container is
 * committed, the lockfile of the installed tree is written by the install
 * and not by `npm install --package-lock-only`, and the app is read with
 * `--cf`, not with `--path`. Where the advice for a folder could not be
 * followed, the deployed app has a text of its own; where it can (a pushed
 * lockfile that is not valid or too large, a yarn or pnpm lockfile), it gets
 * the one above.
 */
const DEPLOYED_REMEDIATIONS: Partial<Record<LockfileMissingCause, string>> = {
  none:
    'Push the lockfile with the app: create it with `npm install --package-lock-only` next to ' +
    'the `package.json` that is deployed, and check that neither `.cfignore` nor the build step ' +
    'that assembles the app folder leaves it out. The buildpack then installs exactly the ' +
    'locked versions, and they can be checked for known vulnerabilities and deprecation.',
  'too-many-packages':
    'The lockfiles of this scan pin more than 20,000 packages from the public npm registry, and ' +
    'a lockfile is read as a whole or not at all. The apps of a project run share that limit, ' +
    'so the apps that were read before this one may have used it up. Read this app alone with ' +
    '`baip-lens project --cf --app <name>`: a run of one app has the whole limit.',
};

/** The lockfile npm wrote into `node_modules` of the container (`lockfileKind: hidden`). */
const HIDDEN_REMEDIATIONS: Partial<Record<LockfileMissingCause, string>> = {
  unreadable:
    'The lockfile npm wrote for the installed packages of the app ' +
    '(`node_modules/.package-lock.json`) exists but could not be used: it is not valid JSON, it ' +
    'names no lockfile version npm knows, or it changed while it was read. The install itself ' +
    'writes that file, not `npm install --package-lock-only`. Restage the app, so that the ' +
    'buildpack installs again and npm writes it anew (when `node_modules` is pushed with the ' +
    'app: install again before the push), then scan again. A valid `package-lock.json` in the ' +
    'app folder also helps: it is read in place of a hidden lockfile that cannot be used.',
  'too-large':
    'The lockfile npm wrote for the installed packages of the app ' +
    '(`node_modules/.package-lock.json`) is larger than BAIP Lens reads (32 MiB, or more keys ' +
    'and values than a lockfile of about 200,000 packages holds). Check that it really is the ' +
    'file npm wrote for this app. A `package-lock.json` in the app folder is read in its place ' +
    'when it stays within those limits.',
};

/** The advice for the cause, for a folder or for a deployed app (see above). */
function remediationFor(project: RawProject, { cause, lockfile }: Missing): string {
  if (project.deployment === undefined) return REMEDIATIONS[cause];
  const hidden = lockfile?.kind === 'hidden' ? HIDDEN_REMEDIATIONS[cause] : undefined;
  return hidden ?? DEPLOYED_REMEDIATIONS[cause] ?? REMEDIATIONS[cause];
}

function findingFor(context: AnalyzerContext, project: RawProject): Finding | undefined {
  // null: a snapshot written before lockfiles were read says nothing about them.
  if (project.dependencies === null) return undefined;
  const declared = declaredDependencies(project);
  if (declared === 0) return undefined;
  const missing = missingLockfile(project.dependencies.lockfiles);
  if (missing === undefined) return undefined;
  const { cause, lockfile } = missing;
  const file = lockfile?.file ?? MANIFEST;
  return projectFinding(context, project, {
    id: RULE_ID,
    title: TITLES[cause],
    subject: file,
    severity: cause === 'unsupported' ? NOT_READ_YET : NOT_PINNED,
    evidence: {
      cause,
      declaredDependencies: declared,
      lockfile: lockfile?.file ?? null,
      lockfileKind: lockfile?.kind ?? null,
    },
    // The hidden lockfile lies inside `node_modules`: a finding never points there.
    ...(lockfile?.kind === 'hidden' ? {} : { location: { file } }),
    remediation: remediationFor(project, missing),
    references: [...REFERENCES],
  });
}

/**
 * DEP_LOCKFILE_MISSING: the root `package.json` declares dependencies, but
 * no npm lockfile could be read for it, so the installed versions are not
 * known and none of them was checked. See docs/rules.md.
 */
export const lockfileMissing: Analyzer = {
  rule: {
    id: RULE_ID,
    title: 'No npm lockfile could be read for the declared dependencies',
    description:
      'The root package.json declares dependencies, but no npm lockfile (package-lock.json or npm-shrinkwrap.json) could be read for it. Without one the installed versions are not known, and no package can be checked for known vulnerabilities or deprecation.',
    roles: [],
    owasp: ['A03:2025'],
    helpUri: ruleHelpUri(RULE_ID),
  },
  requires: ['collect.dependencies'],
  analyze(context): Finding[] {
    return context.raw.projects.flatMap((project) => findingFor(context, project) ?? []);
  },
};
