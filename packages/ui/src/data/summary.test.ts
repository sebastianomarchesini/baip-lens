import type { ReportData, SkipReasonCode } from '@baip-lens/model';
import { describe, expect, it } from 'vitest';
import projectSample from '../test/fixtures/report-project.json';
import sample from '../test/fixtures/report.json';
import {
  isProjectInventory,
  isProjectScope,
  scopeLabel,
  scopePhrase,
  startHereSentences,
} from './summary';

const data = sample as unknown as ReportData;
const project = projectSample as unknown as ReportData;

/** The sample with these checks skipped, each for its reason code. */
function skipping(codes: Record<string, SkipReasonCode>): ReportData {
  const checks = data.checks.map((check) => {
    const reasonCode = codes[check.id];
    return reasonCode === undefined
      ? check
      : { ...check, status: 'skipped' as const, reason: 'test', reasonCode };
  });
  const checksSkipped = checks.filter((check) => check.status === 'skipped').length;
  expect(checksSkipped).toBe(Object.keys(codes).length);
  return { ...data, checks, summary: { ...data.summary, checksSkipped } };
}

describe('startHereSentences', () => {
  it('summarises the sample scan in plain language', () => {
    const s = startHereSentences(data);
    expect(s[0]).toBe('8 apps in acme-prod were scanned on Sep 29, 2026.');
    // The sample carries the traffic history of an earlier scan forward (scan --previous).
    expect(s[1]).toBe(
      'Whether apps are used also counts the earlier scans, up to the one of Sep 22, 2026.',
    );
    expect(s[2]).toBe(
      '4 apps need attention: 3 have not been deployed in over a year; 3 look unused.',
    );
    expect(s.at(-1)).toBe('Nothing in your account was changed: this scan only read information.');
  });

  it('says nothing about earlier scans when none was carried forward', () => {
    const alone = { ...data, options: { ...data.options, previousScannedAt: null } };
    expect(startHereSentences(alone).join(' ')).not.toContain('earlier scans');
  });

  it('says nothing about earlier scans when traffic was not read or APP_IDLE did not run', () => {
    for (const id of ['collect.traffic', 'rule.APP_IDLE']) {
      const s = startHereSentences(skipping({ [id]: 'dependency_skipped' }));
      expect(s.join(' ')).not.toContain('earlier scans');
    }
  });

  it('says when nothing was found and when checks were skipped', () => {
    const skipped = skipping({
      'collect.routes': 'insufficient_role',
      'collect.traffic': 'dependency_skipped',
    });
    const s = startHereSentences({
      ...skipped,
      findings: [],
      summary: { ...skipped.summary, findings: 0 },
    });
    expect(s).toEqual([
      '8 apps in acme-prod were scanned on Sep 29, 2026.',
      'No rule found a problem in the checks that ran.',
      '2 checks could not run with your role, so some things were not looked at. That is not a problem with your apps.',
      'Nothing in your account was changed: this scan only read information.',
    ]);
  });

  it('blames the role only when a missing role is what stopped the checks', () => {
    // Every case skips the traffic check, so no sentence about earlier scans comes first.
    const sentence = (codes: Record<string, SkipReasonCode>) =>
      startHereSentences(skipping(codes))[2];
    expect(sentence({ 'collect.traffic': 'disabled' })).toBe(
      '1 check was turned off, so some things were not looked at. That is not a problem with your apps.',
    );
    expect(sentence({ 'collect.traffic': 'unavailable' })).toBe(
      '1 check did not run, so some things were not looked at. That is not a problem with your apps.',
    );
    expect(sentence({ 'collect.traffic': 'error' })).toMatch(/^1 check did not run, /);
    expect(
      sentence({ 'collect.droplets': 'insufficient_role', 'collect.traffic': 'unavailable' }),
    ).toMatch(/^2 checks did not run, /);
  });

  it('names the space when the scan was limited to one', () => {
    const scope = { ...data.scope, spaces: ['prod'] };
    expect(startHereSentences({ ...data, scope })[0]).toBe(
      '8 apps in space prod of acme-prod were scanned on Sep 29, 2026.',
    );
    expect(scopeLabel(scope)).toBe('acme-prod / prod');
    expect(scopePhrase({ ...scope, spaces: ['dev', 'qa'] })).toBe('spaces dev, qa of acme-prod');
    expect(scopeLabel(data.scope)).toBe('acme-prod');
  });

  it('describes a project scan by its findings', () => {
    const s = startHereSentences(project);
    expect(s).toEqual([
      'The project acme-incidents was scanned on Sep 29, 2026.',
      '18 findings need attention: 3 pages load SAPUI5 from an external CDN without integrity protection; 2 seed data columns contain card numbers, IBANs or secrets; 2 entities hold personal data without @PersonalData annotations.',
      'Nothing in your project was changed: this scan only read files in the project folder.',
    ]);
  });

  it('counts findings, not projects, per project rule', () => {
    const open = project.findings.find((f) => f.id === 'CAP_SERVICE_NO_RESTRICTION')!;
    const twice = [open, { ...open, location: { file: 'srv/other.cds' } }];
    // The sentence counts the skipped checks themselves, not the summary figure.
    const checks = project.checks.map((check, i) =>
      i === 0
        ? { ...check, status: 'skipped' as const, reason: 'test', reasonCode: 'error' as const }
        : check,
    );
    const s = startHereSentences({
      ...project,
      checks,
      findings: twice,
      summary: { ...project.summary, findings: 2, checksSkipped: 1 },
    });
    expect(s[1]).toBe(
      '2 findings need attention: 2 services are open to every authenticated user.',
    );
    expect(s[2]).toBe(
      '1 check could not run, so some things were not looked at. That is not a problem with your project.',
    );
  });

  it('has a phrase for every project rule', () => {
    const projectRules = project.rules.filter(
      (r) => r.roles.length === 0 && r.id !== 'APP_NO_RECENT_DEPLOY',
    );
    // The thirteen project rules and the two dependency rules.
    expect(projectRules).toHaveLength(15);
    for (const rule of projectRules) {
      const finding = { ...project.findings[0]!, id: rule.id };
      const s = startHereSentences({ ...project, findings: [finding, finding] });
      // The fallback wording quotes the rule title; a phrase never does.
      expect(s[1]).not.toContain(`"${rule.title}"`);
    }
  });

  it('words the dependency rules as statements about the project, counted only across projects', () => {
    const notChecked = project.findings.find((f) => f.id === 'DEP_NOT_CHECKED')!;
    const missing = { ...notChecked, id: 'DEP_LOCKFILE_MISSING' };
    expect(startHereSentences({ ...project, findings: [notChecked] })[1]).toBe(
      '1 finding needs attention: some packages of the npm lockfiles were not checked.',
    );
    expect(startHereSentences({ ...project, findings: [missing] })[1]).toBe(
      '1 finding needs attention: dependencies are declared but no npm lockfile could be read.',
    );
    const other = { ...missing, app: { ...missing.app, guid: 'project:other', name: 'other' } };
    expect(startHereSentences({ ...project, findings: [missing, other, notChecked] })[1]).toBe(
      '3 findings need attention: dependencies are declared but no npm lockfile could be read in 2 projects; some packages of the npm lockfiles were not checked.',
    );
  });

  it('labels the scope of a project scan', () => {
    expect(isProjectScope(project.scope)).toBe(true);
    expect(isProjectScope(data.scope)).toBe(false);
    expect(scopeLabel(project.scope)).toBe('acme-incidents');
    expect(scopePhrase(project.scope)).toBe('project acme-incidents');
    expect(scopePhrase({ orgs: [], projects: ['a', 'b'] })).toBe('projects a, b');
    expect(isProjectInventory(project.apps)).toBe(true);
    expect(isProjectInventory(data.apps)).toBe(false);
    expect(isProjectInventory([])).toBe(false);
  });

  it('falls back to the rule title for rules without a phrase', () => {
    const finding = { ...data.findings[0]!, id: 'SOMETHING_NEW' };
    const s = startHereSentences({
      ...data,
      findings: [finding],
      rules: [...data.rules, { ...data.rules[0]!, id: 'SOMETHING_NEW', title: 'Something new' }],
    });
    expect(s).toContain('1 app needs attention: 1 has "Something new".');
  });
});
