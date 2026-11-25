import { describe, expect, it } from 'vitest';
import { DEPENDENCY_ANALYZERS } from '../../../src/analyzers/dependencies/index.js';
import { RULE_ID, notChecked } from '../../../src/analyzers/dependencies/notChecked.js';
import { analyze } from '../../../src/analyzers/index.js';
import { ruleHelpUri } from '../../../src/analyzers/types.js';
import { FindingSchema } from '../../../src/model/finding.js';
import { OWASP_2025_IDS, owaspUrl } from '../../../src/model/owasp.js';
import type { RawLockfile, RawProject } from '../../../src/model/raw.js';
import { RuleMetaSchema } from '../../../src/model/snapshot.js';
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
  rawData,
  rawProject,
  runRule,
} from '../../support/project.js';
import { poisonedProject } from './poisoned.js';

function project(
  lockfiles: RawLockfile[],
  opts: { packages?: number; lockfilesNotRead?: number; id?: string } = {},
): RawProject {
  return rawProject({
    ...(opts.id === undefined ? {} : { id: opts.id }),
    dependencies: dependencies(lockfiles, {
      packages: Array.from({ length: opts.packages ?? 0 }, (_, i) =>
        lockedPackage(`baip-p${i}`, '1.0.0'),
      ),
      lockfilesNotRead: opts.lockfilesNotRead,
    }),
  });
}

const ZERO = {
  otherRegistry: 0,
  git: 0,
  file: 0,
  link: 0,
  bundled: 0,
  unknown: 0,
  excluded: 0,
  invalid: 0,
};

describe('DEP_NOT_CHECKED', () => {
  it('declares the rule metadata from the spec', () => {
    expect(RULE_ID).toBe('DEP_NOT_CHECKED');
    expect(notChecked.rule).toMatchObject({
      id: RULE_ID,
      title: 'Some packages of the npm lockfiles were not checked',
      roles: [],
      owasp: ['A03:2025'],
      helpUri: ruleHelpUri(RULE_ID),
    });
    expect(notChecked.rule.title).not.toMatch(/\.$/);
    expect(notChecked.requires).toEqual(['collect.dependencies']);
  });

  it('fires info with the packages that were not kept, counted by reason over all lockfiles', () => {
    const findings = runRule(
      notChecked,
      project(
        [
          lockfile('package-lock.json', {
            kept: 40,
            notKept: { otherRegistry: 3, git: 1, link: 2, excluded: 5 },
          }),
          lockfile('app/package-lock.json', {
            kept: 12,
            notKept: { otherRegistry: 1, file: 1, bundled: 4, unknown: 2, invalid: 1 },
          }),
          lockfile('srv/npm-shrinkwrap.json', { kind: 'shrinkwrap', kept: 7 }),
        ],
        { packages: 45 },
      ),
    );
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('info');
    expect(finding.title).toBe('Some packages of the npm lockfiles were not checked');
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    // A fixed severity: no matrix inputs. The keys are in this order in every report.
    expect(Object.keys(finding.evidence)).toEqual([
      'subject',
      'otherRegistry',
      'git',
      'file',
      'link',
      'bundled',
      'unknown',
      'excluded',
      'invalid',
      'lockfilesNotRead',
      'checked',
    ]);
    expect(finding.evidence).toEqual({
      subject: 'dependencies',
      otherRegistry: 4,
      git: 1,
      file: 1,
      link: 2,
      bundled: 4,
      unknown: 2,
      excluded: 5,
      invalid: 1,
      lockfilesNotRead: 0,
      checked: 45,
    });
    expect('location' in finding).toBe(false);
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  // Every reason but `link`: a linked local folder is code of the project itself.
  const RAISING = (Object.keys(ZERO) as (keyof typeof ZERO)[]).filter(
    (reason) => reason !== 'link',
  );

  it('knows seven reasons that raise the finding, and one that does not', () => {
    expect(RAISING).toEqual([
      'otherRegistry',
      'git',
      'file',
      'bundled',
      'unknown',
      'excluded',
      'invalid',
    ]);
  });

  it.each(RAISING)('fires for a single package not kept as %s', (reason) => {
    const findings = runRule(
      notChecked,
      project([lockfile('package-lock.json', { kept: 3, notKept: { [reason]: 1 } })], {
        packages: 3,
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toEqual({
      subject: 'dependencies',
      ...ZERO,
      [reason]: 1,
      lockfilesNotRead: 0,
      checked: 3,
    });
  });

  it('counts linked local folders in the evidence when another reason raises the finding', () => {
    const findings = runRule(
      notChecked,
      project([lockfile('package-lock.json', { kept: 3, notKept: { link: 4, git: 1 } })], {
        packages: 3,
      }),
    );
    expect(findings.map((f) => f.evidence)).toEqual([
      { subject: 'dependencies', ...ZERO, link: 4, git: 1, lockfilesNotRead: 0, checked: 3 },
    ]);
  });

  it('fires for lockfiles that were found and not opened, with nothing else left out', () => {
    const findings = runRule(
      notChecked,
      project([lockfile('package-lock.json', { kept: 9 })], {
        packages: 9,
        lockfilesNotRead: 2,
      }),
    );
    expect(findings.map((f) => f.evidence)).toEqual([
      { subject: 'dependencies', ...ZERO, lockfilesNotRead: 2, checked: 9 },
    ]);
  });

  it.each(['unreadable', 'too-large', 'too-many-packages'] as const)(
    'counts a lockfile that was opened and is %s among the lockfiles not read',
    (status) => {
      const findings = runRule(
        notChecked,
        project(
          [
            lockfile('package-lock.json', { kept: 2 }),
            lockfile('app/package-lock.json', { status }),
          ],
          { packages: 2, lockfilesNotRead: 1 },
        ),
      );
      expect(findings.map((f) => f.evidence)).toEqual([
        { subject: 'dependencies', ...ZERO, lockfilesNotRead: 2, checked: 2 },
      ]);
    },
  );

  describe('does not fire', () => {
    const none = (value: RawProject) => expect(runRule(notChecked, value)).toEqual([]);

    it('when every package of every lockfile was kept', () => {
      none(project([lockfile('package-lock.json', { kept: 30 })], { packages: 30 }));
      none(
        project(
          [
            lockfile('package-lock.json', { kept: 1 }),
            lockfile('app/package-lock.json', { kept: 1 }),
          ],
          { packages: 2 },
        ),
      );
    });

    it('for linked local folders alone: workspace members are code of the project', () => {
      none(
        project([lockfile('package-lock.json', { kept: 30, notKept: { link: 2 } })], {
          packages: 30,
        }),
      );
      none(
        project(
          [
            lockfile('package-lock.json', { kept: 1, notKept: { link: 7 } }),
            lockfile('app/package-lock.json', { kept: 1, notKept: { link: 1 } }),
          ],
          { packages: 2 },
        ),
      );
    });

    it('for a project without lockfiles', () => {
      none(project([]));
    });

    it('for a yarn or pnpm lockfile: it is never read, and DEP_LOCKFILE_MISSING speaks for it', () => {
      none(
        project([
          lockfile('yarn.lock', { kind: 'yarn', status: 'unsupported' }),
          lockfile('pnpm-lock.yaml', { kind: 'pnpm', status: 'unsupported' }),
        ]),
      );
    });

    it('for a project record written before lockfiles were read', () => {
      none(rawProject({ dependencies: null }));
    });
  });

  it('emits at most one finding per project, each with the counts of its own lockfiles', () => {
    const findings = runRule(
      notChecked,
      project([lockfile('package-lock.json', { notKept: { git: 2 } })], { id: 'one', packages: 1 }),
      project([lockfile('package-lock.json', { kept: 5 })], { id: 'clean', packages: 5 }),
      project(
        [
          lockfile('a/package-lock.json', { notKept: { link: 1 } }),
          lockfile('b/package-lock.json', { notKept: { link: 1, git: 1 } }),
        ],
        { id: 'two' },
      ),
      // Links only, in two lockfiles: no finding for this one.
      project(
        [
          lockfile('a/package-lock.json', { notKept: { link: 3 } }),
          lockfile('b/package-lock.json', { notKept: { link: 3 } }),
        ],
        { id: 'workspaces' },
      ),
    );
    expect(
      findings.map((f) => [f.app.name, f.evidence.git, f.evidence.link, f.evidence.checked]),
    ).toEqual([
      ['one', 2, 0, 1],
      ['two', 1, 2, 0],
    ]);
  });

  it('yields the same finding whatever the order of lockfiles and projects', () => {
    const lockfiles = [
      lockfile('z/package-lock.json', { notKept: { git: 1, unknown: 3 } }),
      lockfile('a/package-lock.json', { notKept: { otherRegistry: 2 } }),
      lockfile('m/package-lock.json', { status: 'unreadable' }),
      // The same lockfile listed twice counts twice: the rule sums what the record holds.
      lockfile('a/package-lock.json', { notKept: { otherRegistry: 2 } }),
    ];
    const projects = [project(lockfiles, { id: 'one' }), project(lockfiles, { id: 'two' })];
    const expected = runRule(notChecked, ...projects);
    expect(expected).toHaveLength(2);
    expect(expected[0]!.evidence).toMatchObject({
      otherRegistry: 4,
      git: 1,
      unknown: 3,
      lockfilesNotRead: 1,
    });
    const reversed = projects
      .map((p) => ({
        ...p,
        dependencies: dependencies([...lockfiles].reverse()),
      }))
      .reverse();
    expect(runRule(notChecked, ...reversed)).toEqual(expected);
  });

  it('explains every count in the remediation and links the lockfile documentation and OWASP A03:2025', () => {
    const finding = runRule(
      notChecked,
      project([lockfile('package-lock.json', { notKept: { git: 1 } })]),
    )[0]!;
    for (const key of [...Object.keys(ZERO), 'lockfilesNotRead']) {
      expect(finding.remediation, key).toContain(`\`${key}\``);
    }
    expect(finding.remediation).toContain('`https://registry.npmjs.org`');
    expect(finding.remediation).toContain('`--dependency-exclude`');
    expect(finding.references).toEqual([
      'https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json',
      owaspUrl('A03:2025'),
    ]);
  });

  it('says what to do about lockfiles that were not read, for a folder and for a deployed app', () => {
    const lockfiles = [
      lockfile('node_modules/.package-lock.json', { kind: 'hidden', status: 'too-many-packages' }),
      lockfile('package-lock.json', { kept: 2, notKept: { otherRegistry: 1 } }),
    ];
    const folder = runRule(notChecked, project(lockfiles))[0]!;
    const deployed = runRule(
      notChecked,
      rawProject({
        deployment: { app: 'acme-srv', mta: null },
        dependencies: dependencies(lockfiles),
      }),
    )[0]!;
    expect(deployed.evidence).toEqual(folder.evidence);
    // One fixed text: the rule does not read the deployment, so a snapshot re-analyses the same.
    expect(deployed.remediation).toBe(folder.remediation);
    const text = deployed.remediation;
    expect(text).toContain('scan their folders on their own with `--path`.');
    // A deployed app is not read with `--path`: the text names what can be done there.
    expect(text).toContain('A deployed app is not read with `--path`');
    expect(text).toContain('read it alone with `baip-lens project --cf --app <name>`');
    expect(text).toMatch(
      /restage it when the lockfile npm wrote for its installed packages is the one that is not valid\.$/,
    );
    // No path under `node_modules` in a finding that has no location: the words say which file.
    expect(text).not.toContain('node_modules');
  });

  it('emits nothing and records dependency_skipped when the lockfiles were not collected', () => {
    const value = project([lockfile('package-lock.json', { notKept: { git: 1 } })]);
    const result = analyze(
      rawData(value),
      NOW,
      [PROJECT_COLLECTOR_SKIPPED, DEPENDENCIES_COLLECTOR_SKIPPED],
      [notChecked],
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
    const value = project([lockfile('package-lock.json', { notKept: { git: 1 } })]);
    const before = analyze(rawData(value), NOW, [PROJECT_COLLECTOR], [notChecked]);
    expect(before.findings).toEqual([]);
    expect(before.ruleChecks).toEqual([]);
    const ran = analyze(
      rawData(value),
      NOW,
      [PROJECT_COLLECTOR, DEPENDENCIES_COLLECTOR],
      [notChecked],
    );
    expect(ran.ruleChecks.map((c) => [c.id, c.status])).toEqual([[`rule.${RULE_ID}`, 'ran']]);
    expect(ran.findings).toHaveLength(1);
  });

  it('is deterministic', () => {
    expectDeterministic(
      notChecked,
      project(
        [
          lockfile('package-lock.json', { kept: 4, notKept: { otherRegistry: 1, excluded: 2 } }),
          lockfile('app/package-lock.json', { status: 'too-many-packages' }),
        ],
        { packages: 4, lockfilesNotRead: 1 },
      ),
    );
  });

  it('copies nothing from the project: counts only, no lockfile and no package name', () => {
    const poisoned = poisonedProject({
      dependencies: dependencies(
        POISON.slice(0, 50).map((value, i) =>
          lockfile(value, {
            status: i % 2 === 0 ? 'read' : 'unreadable',
            notKept: i % 2 === 0 ? { otherRegistry: 1, git: 1, excluded: 1 } : {},
          }),
        ),
        {
          packages: POISON.slice(0, 30).map((value) =>
            lockedPackage(value, value, { lockfiles: [value] }),
          ),
          lockfilesNotRead: 3,
        },
      ),
    });
    const findings = runRule(notChecked, poisoned);
    expect(findings).toHaveLength(1);
    expectNoValueLeak(findings, POISON);
    expect(findings[0]!.evidence).toEqual({
      subject: 'dependencies',
      ...ZERO,
      otherRegistry: 25,
      git: 25,
      excluded: 25,
      lockfilesNotRead: 28,
      checked: 30,
    });
    expect('location' in findings[0]!).toBe(false);
  });
});

describe('the dependency rules', () => {
  it('declare final metadata: ids, OWASP A03, no CF role, the lockfile collector', () => {
    // Report order: what is known about the packages, then what could not be said about them.
    expect(DEPENDENCY_ANALYZERS.map((a) => a.rule.id)).toEqual([
      'DEP_KNOWN_CVE',
      'DEP_LOCKFILE_MISSING',
      'DEP_NOT_CHECKED',
    ]);
    for (const analyzer of DEPENDENCY_ANALYZERS) {
      expect(RuleMetaSchema.safeParse(analyzer.rule).success).toBe(true);
      expect(analyzer.rule.roles).toEqual([]);
      // Every dependency rule needs the lockfiles, which an older snapshot does not have.
      expect(analyzer.requires).toContain('collect.dependencies');
      expect(analyzer.requires).not.toContain('collect.project');
      expect(analyzer.rule.owasp).toEqual(['A03:2025']);
      expect(analyzer.rule.owasp.every((id) => OWASP_2025_IDS.includes(id))).toBe(true);
      expect(analyzer.rule.helpUri).toBe(ruleHelpUri(analyzer.rule.id));
      expect(analyzer.rule.title).not.toMatch(/\.$/);
      // A title that starts with one of these is prefixed in the CSV report.
      expect(analyzer.rule.title).not.toMatch(/^[=+\-@\t\r]/);
    }
  });
});
