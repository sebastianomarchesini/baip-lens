import { describe, expect, it } from 'vitest';
import { RULE_ID, knownCve } from '../../../src/analyzers/dependencies/knownCve.js';
import { type AnalysisResult, analyze } from '../../../src/analyzers/index.js';
import { ruleHelpUri } from '../../../src/analyzers/types.js';
import type { CheckResult } from '../../../src/model/check.js';
import { type Finding, FindingSchema } from '../../../src/model/finding.js';
import { owaspUrl } from '../../../src/model/owasp.js';
import type {
  RawAdvisory,
  RawData,
  RawLockedPackage,
  RawProject,
  RawVulnerablePackage,
} from '../../../src/model/raw.js';
import { RuleMetaSchema } from '../../../src/model/snapshot.js';
import {
  DEPENDENCIES_COLLECTOR,
  DEPENDENCIES_COLLECTOR_SKIPPED,
  NOW,
  OSV_COLLECTOR,
  OSV_COLLECTOR_SKIPPED,
  POISON,
  PROJECT_COLLECTOR,
  PROJECT_COLLECTOR_SKIPPED,
  advisory,
  dependencies,
  expectNoValueLeak,
  lockedPackage,
  lockfile,
  rawData,
  rawProject,
  vulnerablePackage,
} from '../../support/project.js';
import { poisonedProject } from './poisoned.js';

/*
 * Package names are invented and advisory ids plainly fake: nothing here
 * names a real vulnerability.
 */
const MERGE = 'baip-fixture-merge';
const A1 = 'GHSA-fake-0001-baip';
const A2 = 'GHSA-fake-0002-baip';
const A3 = 'GHSA-fake-0003-baip';
const MALICIOUS = 'MAL-0000-0001';

/** Vectors by the base score the CVSS specification gives them (cvss.test.ts). */
const VECTOR = {
  9.8: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  '9.0': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H',
  8.9: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L',
  7.5: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  '7.0': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L',
  6.9: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:L/A:N',
  5.3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
  '4.0': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:N',
  3.9: 'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L',
  1.6: 'CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N',
  '0.0': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
} as const;

const REFERENCE_LINKS = [
  'https://docs.npmjs.com/cli/v11/commands/npm-ls',
  'https://docs.npmjs.com/cli/v11/configuring-npm/package-json#overrides',
];
const page = (id: string): string => `https://osv.dev/vulnerability/${id}`;

const CHECKS = [PROJECT_COLLECTOR, DEPENDENCIES_COLLECTOR, OSV_COLLECTOR];

interface Tables {
  advisories?: RawAdvisory[];
  vulnerable?: RawVulnerablePackage[];
}

function raw(projects: RawProject | RawProject[], tables: Tables = {}): RawData {
  return {
    ...rawData(...(Array.isArray(projects) ? projects : [projects])),
    advisories: tables.advisories ?? [],
    vulnerablePackages: tables.vulnerable ?? [],
  };
}

function result(data: RawData, checks: CheckResult[] = CHECKS): AnalysisResult {
  return analyze(data, NOW, checks, [knownCve]);
}

/** The findings of a scan whose lookup ran. */
function run(projects: RawProject | RawProject[], tables: Tables = {}): Finding[] {
  return result(raw(projects, tables)).findings;
}

/** A project whose root lockfile pins these packages. */
function project(packages: RawLockedPackage[], id = 'acme'): RawProject {
  return rawProject({
    id,
    dependencies: dependencies(lockfile('package-lock.json', { kept: packages.length }), {
      packages,
    }),
  });
}

/** One finding for `baip-fixture-merge@4.17.20` with these advisories: id to `[record, fixed versions]`. */
function mergeFinding(
  advisories: Record<string, [Partial<Omit<RawAdvisory, 'id'>> | null, string[]]>,
  version = '4.17.20',
): Finding {
  const findings = run(project([lockedPackage(MERGE, version)]), {
    advisories: Object.entries(advisories).flatMap(([id, [record]]) =>
      record === null ? [] : [advisory(id, record)],
    ),
    vulnerable: [
      vulnerablePackage(
        MERGE,
        version,
        Object.fromEntries(Object.entries(advisories).map(([id, [, fixed]]) => [id, fixed])),
      ),
    ],
  });
  expect(findings).toHaveLength(1);
  return findings[0]!;
}

describe('DEP_KNOWN_CVE', () => {
  it('declares the rule metadata from the spec', () => {
    expect(RULE_ID).toBe('DEP_KNOWN_CVE');
    expect(knownCve.rule).toMatchObject({
      id: RULE_ID,
      title: 'Dependency with a known vulnerability',
      roles: [],
      owasp: ['A03:2025'],
      helpUri: ruleHelpUri(RULE_ID),
    });
    expect(RuleMetaSchema.safeParse(knownCve.rule).success).toBe(true);
    expect(knownCve.rule.title).not.toMatch(/\.$/);
    // A title that starts with one of these is prefixed in the CSV report.
    expect(knownCve.rule.title).not.toMatch(/^[=+\-@\t\r]/);
    expect(knownCve.rule.description).toContain('OSV.dev');
    // The lockfiles and the lookup: without either there is nothing to say.
    expect(knownCve.requires).toEqual(['collect.dependencies', 'collect.osv']);
  });

  it('fires for a package version of the lockfile that has an advisory, with what the advisory says', () => {
    const findings = run(
      project([
        lockedPackage(MERGE, '4.17.20', { direct: true }),
        lockedPackage('baip-fixture-server', '2.4.1', { direct: true }),
      ]),
      {
        advisories: [
          advisory(A1, {
            aliases: ['CVE-2026-00001'],
            summary: 'Prototype pollution in baip-fixture-merge',
            cvssV3: VECTOR[9.8],
            label: 'CRITICAL',
          }),
        ],
        vulnerable: [vulnerablePackage(MERGE, '4.17.20', { [A1]: ['4.17.21'] })],
      },
    );
    expect(findings).toHaveLength(1);
    const finding = findings[0]!;
    expect(finding.id).toBe(RULE_ID);
    expect(finding.severity).toBe('critical');
    expect(finding.title).toBe('Dependency with a known vulnerability');
    expect(finding.app).toEqual({
      guid: 'project:acme',
      name: 'acme',
      space: 'project',
      org: 'local',
    });
    // A severity of the advisory itself: no matrix inputs. The keys are in this order in every report.
    expect(Object.keys(finding.evidence)).toEqual([
      'subject',
      'package',
      'version',
      'direct',
      'scope',
      'advisories',
      'advisoryCount',
      'aliases',
      'fixedIn',
      'score',
      'severityFrom',
      'summary',
      'lockfiles',
      'lockfileCount',
    ]);
    expect(finding.evidence).toEqual({
      subject: 'baip-fixture-merge@4.17.20',
      package: 'baip-fixture-merge',
      version: '4.17.20',
      direct: true,
      scope: 'prod',
      advisories: [A1],
      advisoryCount: 1,
      aliases: ['CVE-2026-00001'],
      fixedIn: '4.17.21',
      score: 9.8,
      severityFrom: 'cvss',
      summary: 'Prototype pollution in baip-fixture-merge',
      lockfiles: ['package-lock.json'],
      lockfileCount: 1,
    });
    expect(finding.location).toEqual({ file: 'package-lock.json' });
    expect(finding.references).toEqual([...REFERENCE_LINKS, page(A1), owaspUrl('A03:2025')]);
    expect(finding.remediation).toMatch(/^Upgrade the package to the version in `fixedIn`/);
    expect(FindingSchema.safeParse(finding).success).toBe(true);
  });

  describe('severity', () => {
    it.each([
      [9.8, 'critical'],
      ['9.0', 'critical'],
      [8.9, 'high'],
      [7.5, 'high'],
      ['7.0', 'high'],
      [6.9, 'medium'],
      [5.3, 'medium'],
      ['4.0', 'medium'],
      [3.9, 'low'],
      [1.6, 'low'],
    ] as const)('is the band of the CVSS base score: %s is %s', (score, severity) => {
      const finding = mergeFinding({ [A1]: [{ cvssV3: VECTOR[score] }, []] });
      expect(finding.severity).toBe(severity);
      expect(finding.evidence).toMatchObject({ score: Number(score), severityFrom: 'cvss' });
    });

    it('takes the score before the label: the vector says how, the label only how bad', () => {
      const finding = mergeFinding({ [A1]: [{ cvssV3: VECTOR[3.9], label: 'CRITICAL' }, []] });
      expect(finding.severity).toBe('low');
      expect(finding.evidence).toMatchObject({ score: 3.9, severityFrom: 'cvss' });
    });

    it.each([
      ['CRITICAL', 'critical'],
      ['HIGH', 'high'],
      ['MODERATE', 'medium'],
      ['LOW', 'low'],
    ] as const)('is the label of an advisory without a vector: %s is %s', (label, severity) => {
      const finding = mergeFinding({ [A1]: [{ label }, []] });
      expect(finding.severity).toBe(severity);
      expect(finding.evidence).toMatchObject({ score: null, severityFrom: 'label' });
    });

    it.each([
      ['is not a CVSS v3 vector', 'CVSS:3.1/AV:N/AC:L'],
      ['is of another version', 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
      ['scores 0.0', VECTOR['0.0']],
    ])('falls back to the label when the vector %s', (_name, cvssV3) => {
      const labelled = mergeFinding({ [A1]: [{ cvssV3, label: 'HIGH' }, []] });
      expect(labelled.severity).toBe('high');
      expect(labelled.evidence).toMatchObject({ score: null, severityFrom: 'label' });
      // And to medium when the advisory has no label either.
      const bare = mergeFinding({ [A1]: [{ cvssV3 }, []] });
      expect(bare.severity).toBe('medium');
      expect(bare.evidence).toMatchObject({ score: null, severityFrom: 'default' });
    });

    it('is medium for an advisory that states no severity at all', () => {
      const finding = mergeFinding({ [A1]: [{ summary: 'Something is wrong' }, ['4.17.21']] });
      expect(finding.severity).toBe('medium');
      expect(finding.evidence).toMatchObject({
        score: null,
        severityFrom: 'default',
        summary: 'Something is wrong',
      });
    });

    it('is medium for an advisory the package names and the table of advisories does not hold', () => {
      const finding = mergeFinding({ [A1]: [null, ['4.17.21']] });
      expect(finding.severity).toBe('medium');
      expect(finding.evidence).toMatchObject({
        advisories: [A1],
        advisoryCount: 1,
        aliases: [],
        fixedIn: '4.17.21',
        score: null,
        severityFrom: 'default',
        summary: null,
      });
      expect(finding.references).toContain(page(A1));
    });

    it('is critical for a package reported as malicious code, whatever else its record says', () => {
      const bare = mergeFinding({ [MALICIOUS]: [{ summary: 'Malicious code in a package' }, []] });
      expect(bare.severity).toBe('critical');
      expect(bare.evidence).toMatchObject({
        advisories: [MALICIOUS],
        fixedIn: null,
        score: null,
        severityFrom: 'malicious',
        summary: 'Malicious code in a package',
      });
      const rated = mergeFinding({ [MALICIOUS]: [{ cvssV3: VECTOR[1.6], label: 'LOW' }, []] });
      expect(rated.severity).toBe('critical');
      expect(rated.evidence).toMatchObject({ score: 1.6, severityFrom: 'malicious' });
      // The id alone says it, also when the table of advisories does not hold the record.
      const unknown = mergeFinding({ [MALICIOUS]: [null, []] });
      expect(unknown.severity).toBe('critical');
      expect(unknown.evidence).toMatchObject({ severityFrom: 'malicious', summary: null });
    });

    it('reads `MAL-` at the start of an id only, and in upper case', () => {
      for (const id of ['GHSA-MAL-0001-baip', 'mal-0000-0001', 'MAL0000-0001']) {
        const finding = mergeFinding({ [id]: [{}, []] });
        expect(finding.severity, id).toBe('medium');
        expect(finding.evidence.severityFrom, id).toBe('default');
      }
    });

    it('is the highest among the advisories of the package, and says which source gave it', () => {
      const finding = mergeFinding({
        [A1]: [{ label: 'LOW', summary: 'The least of them' }, ['4.17.21']],
        [A2]: [{ cvssV3: VECTOR[7.5], summary: 'The worst of them' }, ['4.17.21']],
        [A3]: [{ cvssV3: VECTOR[5.3], label: 'CRITICAL', summary: 'Between' }, ['4.17.21']],
      });
      expect(finding.severity).toBe('high');
      expect(finding.evidence).toMatchObject({
        advisories: [A1, A2, A3],
        advisoryCount: 3,
        score: 7.5,
        severityFrom: 'cvss',
        summary: 'The worst of them',
      });
    });

    it('names the highest score among the advisories, also when another source decides the severity', () => {
      const finding = mergeFinding({
        [A1]: [{ cvssV3: VECTOR[5.3], summary: 'Scored' }, []],
        [A2]: [{ label: 'CRITICAL', summary: 'Labelled' }, []],
      });
      expect(finding.severity).toBe('critical');
      expect(finding.evidence).toMatchObject({
        score: 5.3,
        severityFrom: 'label',
        summary: 'Labelled',
      });
    });

    it('puts a report of malicious code before a critical score: it changes what has to be done', () => {
      const finding = mergeFinding({
        [A1]: [{ cvssV3: VECTOR[9.8], summary: 'A flaw' }, ['4.17.21']],
        [MALICIOUS]: [{ summary: 'Malicious code' }, []],
      });
      expect(finding.severity).toBe('critical');
      expect(finding.evidence).toMatchObject({
        score: 9.8,
        severityFrom: 'malicious',
        summary: 'Malicious code',
      });
      expect(finding.remediation).toMatch(/^This package version is reported as malicious code/);
    });

    it('among advisories of one severity, takes the summary of the higher score, then of the source that says more, then by id', () => {
      const byScore = mergeFinding({
        [A1]: [{ cvssV3: VECTOR[7.5], summary: 'Lower score' }, []],
        [A2]: [{ cvssV3: VECTOR[8.9], summary: 'Higher score' }, []],
      });
      expect(byScore.evidence).toMatchObject({ score: 8.9, summary: 'Higher score' });
      const bySource = mergeFinding({
        [A1]: [{ summary: 'No severity stated' }, []],
        [A2]: [{ label: 'MODERATE', summary: 'Labelled' }, []],
        [A3]: [{ cvssV3: VECTOR[5.3], summary: 'Scored' }, []],
      });
      expect(bySource.evidence).toMatchObject({ severityFrom: 'cvss', summary: 'Scored' });
      const byLabel = mergeFinding({
        [A1]: [{ summary: 'No severity stated' }, []],
        [A2]: [{ label: 'MODERATE', summary: 'Labelled' }, []],
      });
      expect(byLabel.evidence).toMatchObject({ severityFrom: 'label', summary: 'Labelled' });
      const byId = mergeFinding({
        [A2]: [{ label: 'HIGH', summary: 'Second id' }, []],
        [A1]: [{ label: 'HIGH', summary: 'First id' }, []],
      });
      expect(byId.evidence.summary).toBe('First id');
    });

    it('has no summary when the advisory that decides the severity has none', () => {
      const finding = mergeFinding({
        [A1]: [{ label: 'CRITICAL' }, []],
        [A2]: [{ label: 'LOW', summary: 'Of the lesser advisory' }, []],
      });
      expect(finding.evidence.summary).toBeNull();
    });
  });

  describe('the fixed version', () => {
    const fixedIn = (fixed: string[], version = '4.17.20'): unknown =>
      mergeFinding({ [A1]: [{ label: 'HIGH' }, fixed] }, version).evidence.fixedIn;

    it('is the lowest fixed version above the installed one, whatever the order of the list', () => {
      expect(fixedIn(['4.17.21'])).toBe('4.17.21');
      expect(fixedIn(['5.0.0', '4.17.21', '4.18.0'])).toBe('4.17.21');
      // By number, not by text: 4.17.100 is above 4.17.21, and 4.9.0 below 4.17.20.
      expect(fixedIn(['4.17.100', '4.17.21', '4.9.0'])).toBe('4.17.21');
      expect(fixedIn(['10.0.0', '9.0.0'])).toBe('9.0.0');
    });

    it('leaves out a fixed version at or below the installed one: it closes another range', () => {
      // An advisory with two ranges: fixed in 3.10.2 for the 3.x line, in 4.17.21 for 4.x.
      expect(fixedIn(['3.10.2', '4.17.21'])).toBe('4.17.21');
      expect(fixedIn(['3.10.2', '4.17.21'], '3.10.1')).toBe('3.10.2');
      // Every fixed version lies below: this install is in a range that has none.
      expect(fixedIn(['3.10.2', '4.17.19'])).toBeNull();
      expect(fixedIn(['4.17.20'])).toBeNull();
      expect(fixedIn([])).toBeNull();
    });

    it('follows the precedence of prereleases', () => {
      // Two lines of one package, one of them not released yet.
      const lines = ['7.23.2', '8.0.0-alpha.4'];
      expect(fixedIn(lines, '7.20.0')).toBe('7.23.2');
      expect(fixedIn(lines, '8.0.0-alpha.1')).toBe('8.0.0-alpha.4');
      expect(fixedIn(lines, '8.0.0-alpha.4')).toBeNull();
      // A prerelease lies before its release, and after the release before it.
      expect(fixedIn(['4.17.21'], '4.17.21-rc.1')).toBe('4.17.21');
      expect(fixedIn(['4.17.21-rc.1'], '4.17.21')).toBeNull();
      expect(fixedIn(['4.17.21-rc.1', '4.17.21-rc.10', '4.17.21-rc.2'], '4.17.20')).toBe(
        '4.17.21-rc.1',
      );
    });

    it('ignores build metadata: two spellings of one version are one, the first by code point', () => {
      expect(fixedIn(['4.17.21+b', '4.17.21+a'])).toBe('4.17.21+a');
      expect(fixedIn(['4.17.20+later'])).toBeNull();
    });

    it('offers no version it cannot read as one, and none for an installed version it cannot read', () => {
      expect(fixedIn(['4.17.21-', '4.18.0'])).toBe('4.18.0');
      expect(fixedIn(['4.17.21-'])).toBeNull();
      expect(fixedIn(['4.18.0'], '4.17.20-')).toBeNull();
    });

    it('is the highest of the fixes of all advisories: the version that clears every one', () => {
      const finding = mergeFinding({
        [A1]: [{ label: 'HIGH' }, ['4.17.21']],
        [A2]: [{ label: 'LOW' }, ['4.17.5', '4.18.2', '5.1.0']],
        [A3]: [{ label: 'LOW' }, ['4.17.21']],
      });
      expect(finding.evidence.fixedIn).toBe('4.18.2');
      expect(finding.remediation).toMatch(/^Upgrade the package to the version in `fixedIn`/);
    });

    it('is null as soon as one advisory names no fix, and the advice changes with it', () => {
      const finding = mergeFinding({
        [A1]: [{ label: 'HIGH' }, ['4.17.21']],
        [A2]: [{ label: 'LOW' }, []],
      });
      expect(finding.evidence.fixedIn).toBeNull();
      expect(finding.remediation).toMatch(/^At least one advisory of this finding names no fixed/);
    });

    it('takes one of two fixes of the same precedence, whatever the order of the advisories', () => {
      const tables = (order: string[]): Finding =>
        mergeFinding(
          Object.fromEntries(
            order.map((id) => [id, [{}, [id === A1 ? '4.17.21+b' : '4.17.21+a']]]),
          ),
        );
      expect(tables([A1, A2]).evidence.fixedIn).toBe('4.17.21+a');
      expect(tables([A2, A1]).evidence.fixedIn).toBe('4.17.21+a');
    });
  });

  describe('remediation and references', () => {
    const fix = mergeFinding({ [A1]: [{ label: 'HIGH' }, ['4.17.21']] });
    const noFix = mergeFinding({ [A1]: [{ label: 'HIGH' }, []] });
    const malicious = mergeFinding({ [MALICIOUS]: [{}, ['4.17.21']] });

    it('has one fixed text per case: a fix, no fix, malicious code', () => {
      const texts = [fix.remediation, noFix.remediation, malicious.remediation];
      expect(new Set(texts).size).toBe(3);
      expect(fix.remediation).toContain('`fixedIn`');
      expect(noFix.remediation).toContain('`fixedIn` is null');
      expect(malicious.remediation).toContain('`MAL-`');
      // Malicious code is not cleared by the fixed version a record may name.
      expect(malicious.evidence.fixedIn).toBe('4.17.21');
      expect(malicious.remediation).toContain('rotate the credentials');
    });

    it('says in every case how to find and change a transitive package', () => {
      for (const { remediation } of [fix, noFix, malicious]) {
        expect(remediation).toContain('`npm ls <package>`');
        expect(remediation).toContain('`overrides`');
        expect(remediation).toContain('`direct`');
      }
    });

    it('is not built from the package: no name, no version, no path under node_modules', () => {
      const other = run(
        project([
          lockedPackage('@baip-fixture/odata', '3.1.0', {
            lockfiles: ['node_modules/.package-lock.json'],
          }),
        ]),
        {
          advisories: [advisory(A1, { label: 'HIGH' })],
          vulnerable: [vulnerablePackage('@baip-fixture/odata', '3.1.0', { [A1]: ['3.1.2'] })],
        },
      )[0]!;
      expect(other.remediation).toBe(fix.remediation);
      expect(other.title).toBe(fix.title);
      for (const { remediation } of [fix, noFix, malicious]) {
        expect(remediation).not.toContain('node_modules');
        expect(remediation).not.toMatch(/baip-fixture|4\.17\./);
      }
    });

    it('links the npm documentation, the page of each advisory on OSV.dev, and OWASP A03:2025 last', () => {
      const finding = mergeFinding({
        [A2]: [{ label: 'HIGH', aliases: ['CVE-2026-00002'] }, []],
        [A1]: [{ label: 'LOW' }, []],
      });
      expect(finding.references).toEqual([
        ...REFERENCE_LINKS,
        page(A1),
        page(A2),
        owaspUrl('A03:2025'),
      ]);
      // An alias is named in the evidence; it has no page of its own here.
      expect(finding.references.join(' ')).not.toContain('CVE-2026-00002');
    });

    it('makes no address of an id that is not one, or that is a step in a path', () => {
      const finding = mergeFinding({
        '..': [{ label: 'LOW' }, []],
        '.': [{ label: 'LOW' }, []],
        'GHSA fake/../x?y#z': [{ label: 'LOW' }, []],
        [A1]: [{ label: 'LOW' }, []],
      });
      expect(finding.evidence.advisoryCount).toBe(4);
      expect(finding.references).toEqual([...REFERENCE_LINKS, page(A1), owaspUrl('A03:2025')]);
      expect(FindingSchema.safeParse(finding).success).toBe(true);
    });
  });

  describe('keeps a finding small', () => {
    const ids = Array.from(
      { length: 12 },
      (_, i) => `GHSA-fake-${String(i).padStart(4, '0')}-baip`,
    );

    it('names ten advisories and ten other ids, sorted, next to the true number', () => {
      const finding = mergeFinding(
        Object.fromEntries(
          ids.map((id, i) => [
            id,
            [{ label: 'HIGH', aliases: [`CVE-2026-1${i}000`, `CVE-2026-0${i}000`] }, []],
          ]),
        ),
      );
      expect(finding.evidence.advisories).toEqual(ids.slice(0, 10));
      expect(finding.evidence.advisoryCount).toBe(12);
      // Of the advisories that are named: 20 other ids, the first ten by code point.
      expect(finding.evidence.aliases).toEqual([
        'CVE-2026-00000',
        'CVE-2026-01000',
        'CVE-2026-02000',
        'CVE-2026-03000',
        'CVE-2026-04000',
        'CVE-2026-05000',
        'CVE-2026-06000',
        'CVE-2026-07000',
        'CVE-2026-08000',
        'CVE-2026-09000',
      ]);
      expect(finding.references).toEqual([
        ...REFERENCE_LINKS,
        ...ids.slice(0, 10).map(page),
        owaspUrl('A03:2025'),
      ]);
      expect(FindingSchema.safeParse(finding).success).toBe(true);
    });

    it('names the ten worst when there are more, so that the one that decides the severity is among them', () => {
      const finding = mergeFinding(
        Object.fromEntries(
          ids.map((id, i) => [
            id,
            // The last two by id are the worst.
            [i === 11 ? { cvssV3: VECTOR[9.8], summary: 'The worst' } : { label: 'LOW' }, []],
          ]),
        ),
      );
      expect(finding.severity).toBe('critical');
      expect(finding.evidence.summary).toBe('The worst');
      expect(finding.evidence.advisories).toEqual([...ids.slice(0, 9), ids[11]]);
      expect(finding.evidence.advisoryCount).toBe(12);
      expect(finding.references).toContain(page(ids[11]!));
      expect(finding.references).not.toContain(page(ids[9]!));
    });

    it('names an alias once, however many advisories carry it', () => {
      const finding = mergeFinding({
        [A1]: [{ aliases: ['CVE-2026-00002', 'CVE-2026-00001'] }, []],
        [A2]: [{ aliases: ['CVE-2026-00001', 'PYSEC-0000-1'] }, []],
      });
      expect(finding.evidence.aliases).toEqual([
        'CVE-2026-00001',
        'CVE-2026-00002',
        'PYSEC-0000-1',
      ]);
    });

    it('names five lockfiles of the package, sorted, next to the number the record holds', () => {
      const paths = ['z', 'c', 'a', 'f', 'b', 'e', 'd'].map((dir) => `${dir}/package-lock.json`);
      const findings = run(project([lockedPackage(MERGE, '4.17.20', { lockfiles: paths })]), {
        vulnerable: [vulnerablePackage(MERGE, '4.17.20', { [A1]: [] })],
      });
      expect(findings[0]!.evidence).toMatchObject({
        lockfiles: ['a', 'b', 'c', 'd', 'e'].map((dir) => `${dir}/package-lock.json`),
        lockfileCount: 7,
      });
      expect(findings[0]!.location).toEqual({ file: 'a/package-lock.json' });
    });

    const fakeIds = (count: number): string[] =>
      Array.from({ length: count }, (_, i) => `GHSA-fake-${String(i).padStart(4, '0')}-baip`);

    // A heavily reported package has well over a hundred advisories; the tables hold 1,000 for one.
    it.each([201, 1_000])(
      'reports a package with %i advisories as one finding of the same size',
      (count) => {
        const many = fakeIds(count);
        const finding = mergeFinding(
          Object.fromEntries(
            many.map((id, i) => [
              id,
              // The worst is the last by id.
              [
                i === count - 1 ? { cvssV3: VECTOR[9.8], summary: 'The worst' } : { label: 'LOW' },
                [],
              ],
            ]),
          ),
        );
        expect(finding.severity).toBe('critical');
        expect(finding.evidence).toMatchObject({
          advisoryCount: count,
          score: 9.8,
          severityFrom: 'cvss',
          summary: 'The worst',
        });
        expect(finding.evidence.advisories).toEqual([...many.slice(0, 9), many[count - 1]]);
        expect(finding.references).toHaveLength(13);
        expect(FindingSchema.safeParse(finding).success).toBe(true);
      },
    );

    it('stays within what a snapshot holds for the largest package the tables can describe', () => {
      // 1,000 advisories, each with 20 other ids and 10 fixed versions, and 20 lockfiles.
      const many = fakeIds(1_000);
      const finding = run(
        project([
          lockedPackage(MERGE, '4.17.20', {
            lockfiles: Array.from({ length: 20 }, (_, i) => `m${i}/package-lock.json`),
          }),
        ]),
        {
          advisories: many.map((id, i) =>
            advisory(id, {
              aliases: Array.from({ length: 20 }, (_, n) => `CVE-2026-${i * 20 + n + 10_000}`),
              summary: 'x'.repeat(200),
              cvssV3: VECTOR[7.5],
            }),
          ),
          vulnerable: [
            vulnerablePackage(
              MERGE,
              '4.17.20',
              Object.fromEntries(
                many.map((id) => [id, Array.from({ length: 10 }, (_, n) => `5.${n}.0`)]),
              ),
            ),
          ],
        },
      )[0]!;
      expect(finding.evidence).toMatchObject({ advisoryCount: 1_000, lockfileCount: 20 });
      expect(finding.evidence.advisories).toHaveLength(10);
      expect(finding.evidence.aliases).toHaveLength(10);
      expect(finding.evidence.lockfiles).toHaveLength(5);
      expect(finding.references).toHaveLength(13);
      expect(FindingSchema.safeParse(finding).success).toBe(true);
      expect(JSON.stringify(finding).length).toBeLessThan(4_000);
    });

    it('judges a package once, however many projects hold it', () => {
      // 20 packages with 1,000 advisories each, in every one of 500 projects: read project by
      // project, that would be ten million advisories to sort.
      const many = fakeIds(1_000);
      const names = Array.from({ length: 20 }, (_, i) => `baip-bulk-${i}`);
      const packages = names.map((name) => lockedPackage(name, '1.0.0'));
      const data = raw(
        Array.from({ length: 500 }, (_, i) => project(packages, `app-${i}`)),
        {
          advisories: many.map((id) => advisory(id, { label: 'LOW' })),
          vulnerable: names.map((name) =>
            vulnerablePackage(name, '1.0.0', Object.fromEntries(many.map((id) => [id, []]))),
          ),
        },
      );
      const started = performance.now();
      const findings = result(data).findings;
      const elapsed = performance.now() - started;
      expect(findings).toHaveLength(10_000);
      expect(findings.every((finding) => finding.evidence.advisoryCount === 1_000)).toBe(true);
      // The lists of a finding are its own: changing one changes no other.
      (findings[0]!.evidence.advisories as string[]).push('changed');
      findings[0]!.references.push('changed');
      expect(findings[1]!.evidence.advisories).toHaveLength(10);
      expect(findings[1]!.references).toHaveLength(13);
      expect(elapsed).toBeLessThan(3_000);
    });
  });

  describe('location', () => {
    const vulnerable = [vulnerablePackage(MERGE, '4.17.20', { [A1]: [] })];
    const located = (lockfiles: string[]): Finding =>
      run(project([lockedPackage(MERGE, '4.17.20', { lockfiles })]), { vulnerable })[0]!;

    it('is the first lockfile of the package, by path', () => {
      expect(located(['srv/package-lock.json', 'app/npm-shrinkwrap.json']).location).toEqual({
        file: 'app/npm-shrinkwrap.json',
      });
      expect(located(['package-lock.json']).location).toEqual({ file: 'package-lock.json' });
    });

    it('is left out for the lockfile of the installed tree: a finding never points into node_modules', () => {
      const hidden = located(['node_modules/.package-lock.json']);
      expect('location' in hidden).toBe(false);
      // The evidence still says where the installed version was read.
      expect(hidden.evidence).toMatchObject({
        lockfiles: ['node_modules/.package-lock.json'],
        lockfileCount: 1,
      });
      expect(FindingSchema.safeParse(hidden).success).toBe(true);
      // Also when it is the first of several, or lies deeper.
      const first = located(['srv/package-lock.json', 'node_modules/.package-lock.json']);
      expect('location' in first).toBe(false);
      expect(first.evidence.lockfiles).toEqual([
        'node_modules/.package-lock.json',
        'srv/package-lock.json',
      ]);
      expect('location' in located(['app/node_modules/.package-lock.json'])).toBe(false);
    });

    it('points at a lockfile of the app when one comes before the installed tree', () => {
      const finding = located(['node_modules/.package-lock.json', 'app/package-lock.json']);
      expect(finding.location).toEqual({ file: 'app/package-lock.json' });
    });

    it('is left out for a package record that names no lockfile', () => {
      const finding = located([]);
      expect('location' in finding).toBe(false);
      expect(finding.evidence).toMatchObject({ lockfiles: [], lockfileCount: 0 });
    });
  });

  describe('does not fire', () => {
    const tables: Tables = {
      advisories: [advisory(A1, { label: 'HIGH' })],
      vulnerable: [vulnerablePackage(MERGE, '4.17.20', { [A1]: ['4.17.21'] })],
    };
    const none = (value: RawProject, with_: Tables = tables) =>
      expect(run(value, with_)).toEqual([]);

    it('for a package without an advisory', () => {
      none(project([lockedPackage('baip-fixture-server', '2.4.1')]));
    });

    it('for another version of a package that has one', () => {
      none(project([lockedPackage(MERGE, '4.17.21'), lockedPackage(MERGE, '3.10.1')]));
    });

    it('for another package of the same version', () => {
      none(project([lockedPackage('baip-fixture-merge-deep', '4.17.20')]));
      // The scope is part of the name.
      none(project([lockedPackage(`@baip-fixture/${MERGE}`, '4.17.20')]));
    });

    it('when the lookup found nothing', () => {
      none(project([lockedPackage(MERGE, '4.17.20')]), {});
      // An advisory alone says nothing about a package.
      none(project([lockedPackage(MERGE, '4.17.20')]), { advisories: tables.advisories });
    });

    it('for a package the tables list without an advisory', () => {
      none(project([lockedPackage(MERGE, '4.17.20')]), {
        advisories: tables.advisories,
        vulnerable: [vulnerablePackage(MERGE, '4.17.20', {})],
      });
    });

    it('for a project without lockfile packages', () => {
      none(project([]));
      none(rawProject());
    });

    it('for a project record written before lockfiles were read', () => {
      none(rawProject({ dependencies: null }));
    });

    it('for a vulnerable package that no project of the scan holds', () => {
      expect(run([], tables)).toEqual([]);
    });

    it('for a name the root package.json lists and no lockfile pins', () => {
      none(
        rawProject({
          packageJson: {
            present: true,
            name: 'acme',
            dependencies: [{ name: MERGE, range: '4.17.20' }],
            devDependencies: [{ name: MERGE, range: '4.17.20' }],
            nodeEngine: null,
          },
        }),
      );
    });
  });

  describe('with several projects', () => {
    const tables: Tables = {
      advisories: [advisory(A1, { label: 'HIGH' }), advisory(A2, { label: 'LOW' })],
      vulnerable: [
        vulnerablePackage(MERGE, '4.17.20', { [A1]: ['4.17.21'] }),
        vulnerablePackage('baip-fixture-server', '2.4.1', { [A2]: [] }),
      ],
    };

    it('raises one finding per project that holds the package, each with its own facts', () => {
      const findings = run(
        [
          rawProject({
            id: 'acme-srv',
            dependencies: dependencies(lockfile('node_modules/.package-lock.json'), {
              packages: [
                lockedPackage(MERGE, '4.17.20', { lockfiles: ['node_modules/.package-lock.json'] }),
                lockedPackage('baip-fixture-server', '2.4.1', { direct: true }),
              ],
            }),
          }),
          project(
            [
              lockedPackage(MERGE, '4.17.20', { direct: true, scope: 'dev' }),
              lockedPackage(MERGE, '4.17.21'),
            ],
            'acme-ui',
          ),
          project([lockedPackage('baip-fixture-router', '1.0.0')], 'acme-router'),
        ],
        tables,
      );
      expect(
        findings.map((f) => [
          f.app.name,
          f.evidence.subject,
          f.severity,
          f.evidence.direct,
          f.evidence.scope,
          f.location?.file,
        ]),
      ).toEqual([
        ['acme-srv', 'baip-fixture-merge@4.17.20', 'high', false, 'prod', undefined],
        ['acme-ui', 'baip-fixture-merge@4.17.20', 'high', true, 'dev', 'package-lock.json'],
        ['acme-srv', 'baip-fixture-server@2.4.1', 'low', true, 'prod', 'package-lock.json'],
      ]);
    });

    it('raises one finding per version when a project holds two versions that have advisories', () => {
      const findings = run(
        project([lockedPackage(MERGE, '4.17.20'), lockedPackage(MERGE, '3.10.1')]),
        {
          advisories: tables.advisories,
          vulnerable: [
            vulnerablePackage(MERGE, '4.17.20', { [A1]: ['4.17.21'] }),
            vulnerablePackage(MERGE, '3.10.1', { [A1]: ['4.17.21'], [A2]: [] }),
          ],
        },
      );
      expect(findings.map((f) => [f.evidence.subject, f.evidence.advisoryCount])).toEqual([
        ['baip-fixture-merge@3.10.1', 2],
        ['baip-fixture-merge@4.17.20', 1],
      ]);
    });

    it('gives a deployed app the finding of a folder: the rule does not read where a project came from', () => {
      const packages = [lockedPackage(MERGE, '4.17.20', { direct: true })];
      const folder = run(project(packages), tables);
      const deployed = run(
        { ...project(packages), deployment: { app: 'acme-srv', mta: null } },
        tables,
      );
      expect(deployed).toEqual(folder);
    });
  });

  describe('whatever the order and however often a row is listed', () => {
    const advisories = [
      advisory(A1, { cvssV3: VECTOR[7.5], aliases: ['CVE-2026-00002', 'CVE-2026-00001'] }),
      advisory(A2, { label: 'LOW', summary: 'Second' }),
      advisory(A3, { label: 'HIGH', summary: 'Third' }),
    ];
    const vulnerable = [
      vulnerablePackage(MERGE, '4.17.20', { [A3]: ['4.18.0', '4.17.21'], [A1]: ['5.0.0'] }),
      vulnerablePackage('baip-fixture-server', '2.4.1', { [A2]: [] }),
      vulnerablePackage('@baip-fixture/odata', '3.1.0', { [A2]: ['3.1.2'], [A1]: ['3.1.1'] }),
    ];
    const packages = [
      lockedPackage('baip-fixture-server', '2.4.1', { direct: true }),
      lockedPackage(MERGE, '4.17.20', {
        lockfiles: ['srv/package-lock.json', 'package-lock.json'],
      }),
      lockedPackage('@baip-fixture/odata', '3.1.0', { scope: 'dev' }),
    ];
    const expected = run([project(packages, 'one'), project(packages, 'two')], {
      advisories,
      vulnerable,
    });

    it('yields the same findings in the same order', () => {
      // Report order: worst first, then by project, then by package.
      expect(expected.map((f) => [f.severity, f.app.name, f.evidence.subject])).toEqual([
        ['high', 'one', '@baip-fixture/odata@3.1.0'],
        ['high', 'one', 'baip-fixture-merge@4.17.20'],
        ['high', 'two', '@baip-fixture/odata@3.1.0'],
        ['high', 'two', 'baip-fixture-merge@4.17.20'],
        ['low', 'one', 'baip-fixture-server@2.4.1'],
        ['low', 'two', 'baip-fixture-server@2.4.1'],
      ]);
      const reverseRows = (row: RawVulnerablePackage): RawVulnerablePackage => ({
        ...row,
        advisories: [...row.advisories]
          .reverse()
          .map((item) => ({ ...item, fixed: [...item.fixed].reverse() })),
      });
      const reversed = run(
        [project([...packages].reverse(), 'two'), project([...packages].reverse(), 'one')],
        {
          advisories: [...advisories]
            .reverse()
            .map((item) => ({ ...item, aliases: [...item.aliases].reverse() })),
          vulnerable: [...vulnerable].reverse().map(reverseRows),
        },
      );
      expect(reversed).toEqual(expected);
    });

    it('reads a package version the project lists twice as one: direct when one is, the wider scope, every lockfile', () => {
      const twice = [
        lockedPackage(MERGE, '4.17.20', { scope: 'dev', lockfiles: ['z/package-lock.json'] }),
        lockedPackage(MERGE, '4.17.20', {
          direct: true,
          scope: 'optional',
          lockfiles: ['a/package-lock.json', 'z/package-lock.json'],
        }),
      ];
      const findings = run(project(twice), { advisories, vulnerable });
      expect(findings).toHaveLength(1);
      expect(findings[0]!.evidence).toMatchObject({
        direct: true,
        scope: 'optional',
        lockfiles: ['a/package-lock.json', 'z/package-lock.json'],
        lockfileCount: 2,
      });
      expect(findings[0]!.location).toEqual({ file: 'a/package-lock.json' });
      expect(run(project([...twice].reverse()), { advisories, vulnerable })).toEqual(findings);
      // `prod` is the widest of the three.
      const prod = [...twice, lockedPackage(MERGE, '4.17.20', { lockfiles: [] })];
      expect(run(project(prod), { advisories, vulnerable })[0]!.evidence.scope).toBe('prod');
    });

    it('reads a package the tables list twice as one: its advisories and their fixed versions add up', () => {
      const split = [
        vulnerablePackage(MERGE, '4.17.20', { [A3]: ['4.18.0'] }),
        vulnerablePackage(MERGE, '4.17.20', { [A1]: ['5.0.0'], [A3]: ['4.17.21'] }),
        ...vulnerable.slice(1),
      ];
      const one = [project(packages, 'one'), project(packages, 'two')];
      expect(run(one, { advisories, vulnerable: split })).toEqual(expected);
      expect(run(one, { advisories, vulnerable: [...split].reverse() })).toEqual(expected);
    });

    it('reads an advisory the tables list twice once: the worse reading, whichever comes first', () => {
      const worse = advisory(A2, { label: 'CRITICAL', summary: 'Second, worse' });
      const twice = [...advisories, worse];
      const findings = run(project(packages), { advisories: twice, vulnerable });
      const server = findings.find((f) => f.evidence.subject === 'baip-fixture-server@2.4.1')!;
      expect(server.severity).toBe('critical');
      expect(server.evidence).toMatchObject({ advisoryCount: 1, summary: 'Second, worse' });
      expect(run(project(packages), { advisories: [...twice].reverse(), vulnerable })).toEqual(
        findings,
      );
      // Two readings of the same severity: one of them, the same either way.
      const same = [...advisories, advisory(A2, { label: 'LOW', summary: 'Another text' })];
      const first = run(project(packages), { advisories: same, vulnerable });
      expect(run(project(packages), { advisories: [...same].reverse(), vulnerable })).toEqual(
        first,
      );
      expect(
        first.find((f) => f.evidence.subject === 'baip-fixture-server@2.4.1')!.evidence.summary,
      ).toBe('Another text');
    });

    it('is deterministic: twice on the same data, and once on a copy', () => {
      const data = raw([project(packages, 'one'), project(packages, 'two')], {
        advisories,
        vulnerable,
      });
      const first = result(data).findings;
      expect(first).toEqual(expected);
      expect(result(data).findings).toEqual(first);
      expect(result(structuredClone(data)).findings).toEqual(first);
      // The data is read, never changed.
      expect(data).toEqual(
        raw([project(packages, 'one'), project(packages, 'two')], { advisories, vulnerable }),
      );
    });
  });

  describe('as a check of the scan', () => {
    const data = raw(project([lockedPackage(MERGE, '4.17.20')]), {
      advisories: [advisory(A1, { label: 'HIGH' })],
      vulnerable: [vulnerablePackage(MERGE, '4.17.20', { [A1]: ['4.17.21'] })],
    });
    const checksOf = (checks: CheckResult[]) =>
      result(data, checks).ruleChecks.map((c) => [c.id, c.status, c.reasonCode, c.reason]);

    it('ran when the lockfiles were read and the lookup was made', () => {
      const ran = result(data);
      expect(ran.ruleChecks).toEqual([
        {
          id: `rule.${RULE_ID}`,
          title: 'Dependency with a known vulnerability',
          roles: [],
          status: 'ran',
        },
      ]);
      expect(ran.findings).toHaveLength(1);
    });

    it('emits nothing and records dependency_skipped when the lookup could not be made', () => {
      const skipped = result(data, [
        PROJECT_COLLECTOR,
        DEPENDENCIES_COLLECTOR,
        OSV_COLLECTOR_SKIPPED,
      ]);
      // The tables are not read: a lookup that failed stored nothing, and "no finding" must not follow from it.
      expect(skipped.findings).toEqual([]);
      expect(skipped.ruleChecks.map((c) => [c.id, c.status, c.reasonCode, c.reason])).toEqual([
        [
          `rule.${RULE_ID}`,
          'skipped',
          'dependency_skipped',
          'needs collect.osv, which did not run',
        ],
      ]);
    });

    it('is skipped in the same way when the lookup was turned off', () => {
      expect(
        checksOf([
          PROJECT_COLLECTOR,
          DEPENDENCIES_COLLECTOR,
          {
            ...OSV_COLLECTOR,
            status: 'skipped',
            reasonCode: 'disabled',
            reason: 'turned off with --no-dependency-check',
          },
        ]),
      ).toEqual([
        [
          `rule.${RULE_ID}`,
          'skipped',
          'dependency_skipped',
          'needs collect.osv, which did not run',
        ],
      ]);
    });

    it('names both checks when the lockfiles were not read either', () => {
      expect(
        checksOf([
          PROJECT_COLLECTOR_SKIPPED,
          DEPENDENCIES_COLLECTOR_SKIPPED,
          { ...OSV_COLLECTOR_SKIPPED, reasonCode: 'dependency_skipped' },
        ]),
      ).toEqual([
        [
          `rule.${RULE_ID}`,
          'skipped',
          'dependency_skipped',
          'needs collect.dependencies, collect.osv, which did not run',
        ],
      ]);
      expect(checksOf([PROJECT_COLLECTOR, DEPENDENCIES_COLLECTOR_SKIPPED, OSV_COLLECTOR])).toEqual([
        [
          `rule.${RULE_ID}`,
          'skipped',
          'dependency_skipped',
          'needs collect.dependencies, which did not run',
        ],
      ]);
    });

    it('is not a check of a scan without a lookup, or of one that did not read lockfiles', () => {
      // A snapshot written before the lookup existed, or a scan that was handed none.
      const before = result(data, [PROJECT_COLLECTOR, DEPENDENCIES_COLLECTOR]);
      expect(before.findings).toEqual([]);
      expect(before.ruleChecks).toEqual([]);
      // An older snapshot still: no lockfiles either.
      expect(result(data, [PROJECT_COLLECTOR]).ruleChecks).toEqual([]);
      expect(result(data, [PROJECT_COLLECTOR, OSV_COLLECTOR]).ruleChecks).toEqual([]);
      // A Cloud Foundry scan has neither.
      expect(result(data, []).ruleChecks).toEqual([]);
    });
  });

  it('copies nothing from the project but the vulnerable package and its lockfile paths', () => {
    const poisoned = poisonedProject({
      dependencies: dependencies(
        POISON.slice(0, 50).map((value) => lockfile(value, { notKept: { otherRegistry: 3 } })),
        {
          packages: [
            lockedPackage(MERGE, '4.17.20', { direct: true }),
            // Packages without an advisory: none of them is named.
            ...POISON.slice(0, 40).map((value) =>
              lockedPackage(value, '1.0.0', { lockfiles: [value] }),
            ),
          ],
          lockfilesNotRead: 3,
        },
      ),
    });
    const findings = run(poisoned, {
      advisories: [
        advisory(A1, { cvssV3: VECTOR[9.8], summary: 'A summary', aliases: ['CVE-2026-00001'] }),
        // Advisories of packages the project does not hold.
        ...POISON.slice(0, 20).map((_, i) =>
          advisory(`GHSA-poison-${i}`, { summary: POISON[i] ?? null }),
        ),
      ],
      vulnerable: [
        vulnerablePackage(MERGE, '4.17.20', { [A1]: ['4.17.21'] }),
        ...POISON.slice(0, 20).map((_, i) =>
          vulnerablePackage(`poison-package-${i}`, '1.0.0', { [`GHSA-poison-${i}`]: [] }),
        ),
      ],
    });
    expect(findings).toHaveLength(1);
    expectNoValueLeak(findings, [...POISON, 'poison']);
    expect(findings[0]!.evidence).toEqual({
      subject: 'baip-fixture-merge@4.17.20',
      package: 'baip-fixture-merge',
      version: '4.17.20',
      direct: true,
      scope: 'prod',
      advisories: [A1],
      advisoryCount: 1,
      aliases: ['CVE-2026-00001'],
      fixedIn: '4.17.21',
      score: 9.8,
      severityFrom: 'cvss',
      summary: 'A summary',
      lockfiles: ['package-lock.json'],
      lockfileCount: 1,
    });
  });

  it('holds strings, numbers, booleans, null and lists of strings in its evidence, and nothing else', () => {
    const finding = mergeFinding({
      [A1]: [{ cvssV3: VECTOR[9.8], summary: 'A summary', aliases: ['CVE-2026-00001'] }, ['5.0.0']],
      [MALICIOUS]: [{}, []],
    });
    for (const [key, value] of Object.entries(finding.evidence)) {
      const plain =
        value === null ||
        ['string', 'number', 'boolean'].includes(typeof value) ||
        (Array.isArray(value) && value.every((item) => typeof item === 'string'));
      expect(plain, key).toBe(true);
    }
  });
});
