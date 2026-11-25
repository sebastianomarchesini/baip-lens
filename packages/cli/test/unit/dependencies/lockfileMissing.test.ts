import { describe, expect, it } from 'vitest';
import { RULE_ID, lockfileMissing } from '../../../src/analyzers/dependencies/lockfileMissing.js';
import { analyze } from '../../../src/analyzers/index.js';
import { ruleHelpUri } from '../../../src/analyzers/types.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { owaspUrl } from '../../../src/model/owasp.js';
import type { RawDeployment, RawLockfile, RawProject } from '../../../src/model/raw.js';
import {
  DEPENDENCIES_COLLECTOR,
  DEPENDENCIES_COLLECTOR_SKIPPED,
  NOW,
  POISON,
  PROJECT_COLLECTOR,
  PROJECT_COLLECTOR_SKIPPED,
  dependencies,
  expectDeterministic,
  expectNoValueLeak,
  lockedPackage,
  lockfile,
  packageJson,
  rawData,
  rawProject,
  runRule,
} from '../../support/project.js';
import { poisonedProject } from './poisoned.js';

const DEPLOYED: RawDeployment = { app: 'acme-srv', mta: null };

/** A project whose root manifest declares one dependency, with the given lockfiles. */
function project(lockfiles: RawLockfile[] = [], overrides: Partial<RawProject> = {}): RawProject {
  return rawProject({
    packageJson: packageJson({ 'baip-server': '^2' }),
    dependencies: dependencies(lockfiles),
    ...overrides,
  });
}

const summary = (findings: ReturnType<typeof runRule>) =>
  findings.map((f) => [f.severity, f.evidence.subject, f.evidence.cause]);

describe('DEP_LOCKFILE_MISSING', () => {
  it('declares the rule metadata from the spec', () => {
    expect(RULE_ID).toBe('DEP_LOCKFILE_MISSING');
    expect(lockfileMissing.rule).toMatchObject({
      id: RULE_ID,
      title: 'No npm lockfile could be read for the declared dependencies',
      roles: [],
      owasp: ['A03:2025'],
      helpUri: ruleHelpUri(RULE_ID),
    });
    expect(lockfileMissing.rule.title).not.toMatch(/\.$/);
    // Not `collect.project`: a snapshot written before lockfiles were read must not get this rule.
    expect(lockfileMissing.requires).toEqual(['collect.dependencies']);
  });

  it('fires low when the root manifest declares dependencies and the project has no lockfile', () => {
    const findings = runRule(lockfileMissing, project());
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('low');
    expect(finding.title).toBe('Dependencies are declared but no npm lockfile pins their versions');
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    expect(finding.evidence).toEqual({
      subject: 'package.json',
      cause: 'none',
      declaredDependencies: 1,
      lockfile: null,
      lockfileKind: null,
      impact: 'minor',
      easeOfAttack: 'complex',
    });
    expect(finding.location).toEqual({ file: 'package.json' });
    expect(finding.remediation).toContain('npm install --package-lock-only');
    expect(finding.remediation).toContain('npm ci');
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('counts dependencies and devDependencies of a folder', () => {
    const both = project([], {
      packageJson: packageJson({ a: '^1', b: '^1' }, { c: '^1', d: '^1', e: '^1' }),
    });
    expect(runRule(lockfileMissing, both)[0]!.evidence.declaredDependencies).toBe(5);
    const devOnly = project([], { packageJson: packageJson({}, { c: '^1' }) });
    expect(runRule(lockfileMissing, devOnly)[0]!.evidence.declaredDependencies).toBe(1);
  });

  it('counts only the dependencies of a deployed app: its devDependencies are not installed', () => {
    const deployed = project([], {
      deployment: DEPLOYED,
      packageJson: packageJson({ a: '^1', b: '^1' }, { c: '^1' }),
    });
    const [finding] = runRule(lockfileMissing, deployed);
    expect(finding!.evidence).toMatchObject({ cause: 'none', declaredDependencies: 2 });
    expect(finding!.remediation).toContain('Push the lockfile with the app');
    expect(finding!.remediation).toContain('.cfignore');

    const devOnly = project([], {
      deployment: DEPLOYED,
      packageJson: packageJson({}, { c: '^1' }),
    });
    expect(runRule(lockfileMissing, devOnly)).toEqual([]);
  });

  it.each([
    [
      'unreadable',
      'The npm lockfile could not be read, so the installed packages were not checked',
    ],
    [
      'too-large',
      'The npm lockfile is too large to read, so the installed packages were not checked',
    ],
    [
      'too-many-packages',
      'The npm lockfile pins more packages than one scan keeps, so they were not checked',
    ],
  ] as const)('fires low on the root lockfile when it is %s', (status, title) => {
    const findings = runRule(lockfileMissing, project([lockfile('package-lock.json', { status })]));
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.severity).toBe('low');
    expect(finding.title).toBe(title);
    expect(finding.evidence).toEqual({
      subject: 'package-lock.json',
      cause: status,
      declaredDependencies: 1,
      lockfile: 'package-lock.json',
      lockfileKind: 'package-lock',
      impact: 'minor',
      easeOfAttack: 'complex',
    });
    expect(finding.location).toEqual({ file: 'package-lock.json' });
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('names the shrinkwrap file when that is the root lockfile', () => {
    const [finding] = runRule(
      lockfileMissing,
      project([lockfile('npm-shrinkwrap.json', { kind: 'shrinkwrap', status: 'unreadable' })]),
    );
    expect(finding!.evidence).toMatchObject({
      subject: 'npm-shrinkwrap.json',
      lockfile: 'npm-shrinkwrap.json',
      lockfileKind: 'shrinkwrap',
    });
    expect(finding!.location).toEqual({ file: 'npm-shrinkwrap.json' });
  });

  it('gives no location for the hidden lockfile: a finding never points into node_modules', () => {
    const hidden = lockfile('node_modules/.package-lock.json', {
      kind: 'hidden',
      status: 'too-large',
    });
    const [finding] = runRule(lockfileMissing, project([hidden], { deployment: DEPLOYED }));
    expect(finding!.evidence).toEqual({
      subject: 'node_modules/.package-lock.json',
      cause: 'too-large',
      declaredDependencies: 1,
      lockfile: 'node_modules/.package-lock.json',
      lockfileKind: 'hidden',
      impact: 'minor',
      easeOfAttack: 'complex',
    });
    expect('location' in finding!).toBe(false);
    // A lockfile is there: the advice is about that file, not the one for an app without any.
    expect(finding!.remediation).toMatch(/32 MiB/);
    expect(finding!.remediation).not.toContain('Push the lockfile with the app');
    expect(finding!.remediation).toContain('`node_modules/.package-lock.json`');
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it.each([
    ['yarn.lock', 'yarn'],
    ['pnpm-lock.yaml', 'pnpm'],
  ] as const)('fires info when %s pins the versions: pinned, but not read yet', (file, kind) => {
    const findings = runRule(
      lockfileMissing,
      project([lockfile(file, { kind, status: 'unsupported' })]),
    );
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.severity).toBe('info');
    expect(finding.title).toBe('Dependencies are pinned by a lockfile BAIP Lens does not read yet');
    // A fixed severity: no matrix inputs.
    expect(finding.evidence).toEqual({
      subject: file,
      cause: 'unsupported',
      declaredDependencies: 1,
      lockfile: file,
      lockfileKind: kind,
    });
    expect(finding.location).toEqual({ file });
    expect(finding.remediation).toContain('yarn npm audit');
    expect(finding.remediation).toContain('pnpm audit');
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('reports an npm lockfile that could not be read before a yarn or pnpm one', () => {
    const findings = runRule(
      lockfileMissing,
      project([
        lockfile('yarn.lock', { kind: 'yarn', status: 'unsupported' }),
        lockfile('package-lock.json', { status: 'unreadable' }),
      ]),
    );
    expect(summary(findings)).toEqual([['low', 'package-lock.json', 'unreadable']]);
  });

  it('reports the first by path among several root lockfiles that could not be read', () => {
    const findings = runRule(
      lockfileMissing,
      project([
        lockfile('package-lock.json', { status: 'too-many-packages' }),
        lockfile('node_modules/.package-lock.json', { kind: 'hidden', status: 'unreadable' }),
        lockfile('npm-shrinkwrap.json', { kind: 'shrinkwrap', status: 'too-large' }),
      ]),
    );
    expect(summary(findings)).toEqual([['low', 'node_modules/.package-lock.json', 'unreadable']]);
  });

  it('does not count a nested lockfile for the root: the root manifest is still not pinned', () => {
    const findings = runRule(
      lockfileMissing,
      project([
        lockfile('app/router/package-lock.json', { kept: 3 }),
        lockfile('srv/package-lock.json', { status: 'unreadable' }),
      ]),
    );
    expect(summary(findings)).toEqual([['low', 'package.json', 'none']]);
    expect(findings[0]!.evidence).toMatchObject({ lockfile: null, lockfileKind: null });
  });

  it('takes an npm lockfile that is marked unsupported, which no scan writes, as no lockfile', () => {
    const crafted = lockfile('package-lock.json', { status: 'unsupported' });
    expect(summary(runRule(lockfileMissing, project([crafted])))).toEqual([
      ['low', 'package.json', 'none'],
    ]);
    // And a yarn lockfile that claims to have been read is still not an npm lockfile.
    const claimed = lockfile('yarn.lock', { kind: 'yarn', status: 'read' });
    expect(summary(runRule(lockfileMissing, project([claimed])))).toEqual([
      ['info', 'yarn.lock', 'unsupported'],
    ]);
  });

  describe('does not fire', () => {
    const none = (value: RawProject) => expect(runRule(lockfileMissing, value)).toEqual([]);

    it('when the root lockfile was read', () => {
      none(project([lockfile('package-lock.json', { kept: 12 })]));
      none(project([lockfile('npm-shrinkwrap.json', { kind: 'shrinkwrap' })]));
      none(project([lockfile('package-lock.json', { lockfileVersion: 1 })]));
    });

    it('when the hidden lockfile of the installed tree was read', () => {
      none(
        project([lockfile('node_modules/.package-lock.json', { kind: 'hidden' })], {
          deployment: DEPLOYED,
        }),
      );
      // The installed tree answers for the root even when the lockfile next to it could not be read.
      none(
        project([
          lockfile('node_modules/.package-lock.json', { kind: 'hidden' }),
          lockfile('package-lock.json', { status: 'unreadable' }),
        ]),
      );
    });

    it('when a lockfile was read next to a yarn lockfile', () => {
      none(
        project([
          lockfile('package-lock.json'),
          lockfile('yarn.lock', { kind: 'yarn', status: 'unsupported' }),
        ]),
      );
    });

    it('when the root manifest declares no dependency', () => {
      none(project([], { packageJson: packageJson({}) }));
      none(rawProject({ dependencies: dependencies([]) }));
      none(
        project([lockfile('package-lock.json', { status: 'unreadable' })], {
          packageJson: packageJson({}),
        }),
      );
    });

    it('for a project record written before lockfiles were read', () => {
      none(project([], { dependencies: null }));
    });
  });

  it('emits one finding per project, whatever the order and number of its lockfiles', () => {
    const lockfiles = [
      lockfile('yarn.lock', { kind: 'yarn', status: 'unsupported' }),
      lockfile('pnpm-lock.yaml', { kind: 'pnpm', status: 'unsupported' }),
      lockfile('app/package-lock.json', { status: 'too-large' }),
    ];
    const forward = runRule(lockfileMissing, project(lockfiles));
    expect(summary(forward)).toEqual([['info', 'pnpm-lock.yaml', 'unsupported']]);
    expect(runRule(lockfileMissing, project([...lockfiles].reverse()))).toEqual(forward);
  });

  it('emits one finding when one lockfile is listed twice, and none when one of the two was read', () => {
    const twice = [
      lockfile('package-lock.json', { status: 'unreadable' }),
      lockfile('package-lock.json', { status: 'too-large' }),
    ];
    const findings = runRule(lockfileMissing, project(twice));
    expect(summary(findings)).toEqual([['low', 'package-lock.json', 'too-large']]);
    expect(runRule(lockfileMissing, project([...twice].reverse()))).toEqual(findings);
    expect(
      runRule(lockfileMissing, project([...twice, lockfile('package-lock.json', { kept: 1 })])),
    ).toEqual([]);
    const kinds = [
      lockfile('npm-shrinkwrap.json', { kind: 'shrinkwrap', status: 'unreadable' }),
      lockfile('npm-shrinkwrap.json', { kind: 'package-lock', status: 'unreadable' }),
    ];
    expect(runRule(lockfileMissing, project(kinds))).toEqual(
      runRule(lockfileMissing, project([...kinds].reverse())),
    );
  });

  it('yields the same findings when the projects arrive in reverse order', () => {
    const projects = [
      project([], { id: 'none' }),
      project([lockfile('package-lock.json', { status: 'unreadable' })], { id: 'broken' }),
      project([lockfile('yarn.lock', { kind: 'yarn', status: 'unsupported' })], { id: 'yarn' }),
      project([lockfile('package-lock.json')], { id: 'fine' }),
    ];
    const expected = runRule(lockfileMissing, ...projects);
    expect(expected.map((f) => [f.app.name, f.severity, f.evidence.cause])).toEqual([
      ['broken', 'low', 'unreadable'],
      ['none', 'low', 'none'],
      ['yarn', 'info', 'unsupported'],
    ]);
    expect(runRule(lockfileMissing, ...[...projects].reverse())).toEqual(expected);
  });

  it('produces schema-valid findings with the same evidence keys in every branch', () => {
    const findings = runRule(
      lockfileMissing,
      project([], { id: 'a' }),
      project([lockfile('package-lock.json', { status: 'too-many-packages' })], { id: 'b' }),
      project([lockfile('yarn.lock', { kind: 'yarn', status: 'unsupported' })], { id: 'c' }),
    );
    expect(findings.map((f) => f.severity)).toEqual(['low', 'low', 'info']);
    const base = ['cause', 'declaredDependencies', 'lockfile', 'lockfileKind', 'subject'];
    expect(findings.map((f) => Object.keys(f.evidence).sort())).toEqual([
      [
        'cause',
        'declaredDependencies',
        'easeOfAttack',
        'impact',
        'lockfile',
        'lockfileKind',
        'subject',
      ],
      [
        'cause',
        'declaredDependencies',
        'easeOfAttack',
        'impact',
        'lockfile',
        'lockfileKind',
        'subject',
      ],
      base,
    ]);
    for (const finding of findings) expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  it('links the npm documentation and OWASP A03:2025, and gives a remediation per cause', () => {
    const causes: [RawLockfile[], RegExp][] = [
      [[], /Create the lockfile with `npm install --package-lock-only`/],
      [[lockfile('package-lock.json', { status: 'unreadable' })], /unresolved merge conflict/],
      [[lockfile('package-lock.json', { status: 'too-large' })], /32 MiB/],
      [[lockfile('package-lock.json', { status: 'too-many-packages' })], /20,000 packages/],
      [[lockfile('yarn.lock', { kind: 'yarn', status: 'unsupported' })], /npm lockfiles only/],
    ];
    const remediations = new Set<string>();
    for (const [lockfiles, expected] of causes) {
      const finding = runRule(lockfileMissing, project(lockfiles))[0]!;
      expect(finding.remediation).toMatch(expected);
      remediations.add(finding.remediation);
      expect(finding.references).toEqual([
        'https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json',
        'https://docs.npmjs.com/cli/v11/commands/npm-ci',
        owaspUrl('A03:2025'),
      ]);
    }
    expect(remediations.size).toBe(causes.length);
  });

  it('gives a deployed app the remediation of a folder only where that advice can be followed there', () => {
    const cases: RawLockfile[][] = [
      [],
      [lockfile('package-lock.json', { status: 'unreadable' })],
      [lockfile('package-lock.json', { status: 'too-large' })],
      [lockfile('package-lock.json', { status: 'too-many-packages' })],
      [lockfile('node_modules/.package-lock.json', { kind: 'hidden', status: 'unreadable' })],
      [lockfile('yarn.lock', { kind: 'yarn', status: 'unsupported' })],
    ];
    const changed = cases.map((lockfiles) => {
      const folder = runRule(lockfileMissing, project(lockfiles))[0]!;
      const deployed = runRule(lockfileMissing, project(lockfiles, { deployment: DEPLOYED }))[0]!;
      expect(deployed.evidence.cause).toBe(folder.evidence.cause);
      if (deployed.evidence.cause !== 'none') {
        expect(deployed.remediation).not.toContain('Push the lockfile with the app');
      }
      return deployed.remediation !== folder.remediation;
    });
    // Its own text: no lockfile at all, a lockfile that did not fit, and the hidden lockfile.
    expect(changed).toEqual([true, false, false, true, true, false]);
  });

  describe('on a deployed app', () => {
    const HIDDEN = 'node_modules/.package-lock.json';
    const hidden = (status: RawLockfile['status']): RawLockfile =>
      lockfile(HIDDEN, { kind: 'hidden', status });
    const advice = (lockfiles: RawLockfile[], overrides: Partial<RawProject> = {}): string =>
      runRule(lockfileMissing, project(lockfiles, { deployment: DEPLOYED, ...overrides }))[0]!
        .remediation;

    it('says of a hidden lockfile that is not valid how the file is written anew: by an install, not by a commit', () => {
      const text = advice([hidden('unreadable')]);
      expect(text).toContain('`node_modules/.package-lock.json`');
      expect(text).toContain('Restage the app');
      // The lockfile that is pushed with the app is read in its place.
      expect(text).toContain('A valid `package-lock.json` in the app folder also helps');
      // Nothing in a container is committed, and `--package-lock-only` does not write this file.
      expect(text).not.toMatch(/commit|Delete it|recreate it with/);
      expect(text).toContain('not `npm install --package-lock-only`');
      expect(text).not.toContain('--path');
    });

    it('says of a hidden lockfile that is too large which file is read in its place', () => {
      const text = advice([hidden('too-large')]);
      expect(text).toMatch(/32 MiB/);
      expect(text).toContain('`node_modules/.package-lock.json`');
      expect(text).toContain('A `package-lock.json` in the app folder is read in its place');
      expect(text).not.toMatch(/commit|--path/);
    });

    it.each([
      ['pushed', [lockfile('package-lock.json', { status: 'too-many-packages' })]],
      [
        'shrinkwrap',
        [lockfile('npm-shrinkwrap.json', { kind: 'shrinkwrap', status: 'too-many-packages' })],
      ],
      ['hidden', [hidden('too-many-packages')]],
    ] as [string, RawLockfile[]][])(
      'names `--app`, not `--path`, when the %s lockfile did not fit into what the apps before it left',
      (_which, lockfiles) => {
        const text = advice(lockfiles);
        expect(text).toMatch(/20,000 packages/);
        expect(text).toContain('`baip-lens project --cf --app <name>`');
        expect(text).toContain('The apps of a project run share that limit');
        expect(text).not.toMatch(/commit|--path/);
      },
    );

    it('keeps the texts of a folder for a pushed lockfile that is not valid or too large, and for yarn', () => {
      const folder = (lockfiles: RawLockfile[]): string =>
        runRule(lockfileMissing, project(lockfiles))[0]!.remediation;
      for (const lockfiles of [
        [lockfile('package-lock.json', { status: 'unreadable' })],
        [lockfile('npm-shrinkwrap.json', { kind: 'shrinkwrap', status: 'too-large' })],
        [lockfile('yarn.lock', { kind: 'yarn', status: 'unsupported' })],
      ]) {
        expect(advice(lockfiles)).toBe(folder(lockfiles));
      }
    });

    it('gives the hidden lockfile of a record without a deployment, which no scan writes, the text of a folder', () => {
      const crafted = runRule(lockfileMissing, project([hidden('unreadable')]))[0]!;
      expect(crafted.remediation).toMatch(/unresolved merge conflict/);
      expect('location' in crafted).toBe(false);
    });

    it('has one text per case, each of them a different one', () => {
      const texts = [
        advice([]),
        advice([hidden('unreadable')]),
        advice([hidden('too-large')]),
        advice([hidden('too-many-packages')]),
        advice([lockfile('package-lock.json', { status: 'unreadable' })]),
        advice([lockfile('package-lock.json', { status: 'too-large' })]),
        advice([lockfile('yarn.lock', { kind: 'yarn', status: 'unsupported' })]),
      ];
      expect(new Set(texts).size).toBe(texts.length);
      for (const text of texts) expect(text).toMatch(/\.$/);
    });
  });

  it('says in the remediation for no lockfile that a workspace member has its lockfile in the workspace root', () => {
    const [finding] = runRule(lockfileMissing, project());
    expect(finding!.remediation).toMatch(/member of an npm workspace/);
    expect(finding!.remediation).toMatch(/scan the workspace root instead/);
    // A deployed app is not a folder of a workspace.
    const [deployed] = runRule(lockfileMissing, project([], { deployment: DEPLOYED }));
    expect(deployed!.remediation).not.toMatch(/workspace/);
  });

  it('emits nothing and records dependency_skipped when the lockfiles were not collected', () => {
    const result = analyze(
      rawData(project()),
      NOW,
      [PROJECT_COLLECTOR_SKIPPED, DEPENDENCIES_COLLECTOR_SKIPPED],
      [lockfileMissing],
    );
    expect(result.findings).toEqual([]);
    expect(result.ruleChecks.map((c) => [c.id, c.status, c.reasonCode, c.reason])).toEqual([
      [
        `rule.${RULE_ID}`,
        'skipped',
        'dependency_skipped',
        'needs collect.dependencies, which did not run',
      ],
    ]);
  });

  it('is not a check of a scan that did not read lockfiles, such as an older snapshot', () => {
    const result = analyze(rawData(project()), NOW, [PROJECT_COLLECTOR], [lockfileMissing]);
    expect(result.findings).toEqual([]);
    expect(result.ruleChecks).toEqual([]);
    const ran = analyze(
      rawData(project()),
      NOW,
      [PROJECT_COLLECTOR, DEPENDENCIES_COLLECTOR],
      [lockfileMissing],
    );
    expect(ran.ruleChecks.map((c) => [c.id, c.status])).toEqual([[`rule.${RULE_ID}`, 'ran']]);
    expect(ran.findings).toHaveLength(1);
  });

  it('is deterministic', () => {
    expectDeterministic(
      lockfileMissing,
      project([
        lockfile('yarn.lock', { kind: 'yarn', status: 'unsupported' }),
        lockfile('package-lock.json', { status: 'too-large' }),
        lockfile('app/package-lock.json'),
      ]),
    );
  });

  it('copies nothing from the project but the name of a root lockfile', () => {
    const poisoned = poisonedProject({
      dependencies: dependencies(
        [
          // Nested lockfiles with poison names are no concern of this rule.
          ...POISON.slice(0, 40).map((value) =>
            lockfile(`${value}/package-lock.json`, { status: 'unreadable' }),
          ),
        ],
        {
          packages: POISON.slice(0, 20).map((value) =>
            lockedPackage(value, value, { lockfiles: [value] }),
          ),
          lockfilesNotRead: POISON.length,
        },
      ),
    });
    const findings = runRule(lockfileMissing, poisoned);
    expect(findings).toHaveLength(1);
    expectNoValueLeak(findings, POISON);
    expect(findings[0]!.evidence).toEqual({
      subject: 'package.json',
      cause: 'none',
      declaredDependencies: 2 * POISON.length,
      lockfile: null,
      lockfileKind: null,
      impact: 'minor',
      easeOfAttack: 'complex',
    });
    expect(findings[0]!.location).toEqual({ file: 'package.json' });
  });
});
