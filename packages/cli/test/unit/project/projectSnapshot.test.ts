import { describe, expect, it } from 'vitest';
import { PROJECT_ANALYZERS } from '../../../src/analyzers/project/index.js';
import { COLLECTOR_CHECKS, deployedAppNotRead } from '../../../src/checks.js';
import { SnapshotSchema } from '../../../src/model/snapshot.js';
import { type NotRead, type ProjectCollection, projectSnapshot } from '../../../src/project.js';
import { cdsEffective, rawProject } from '../../support/project.js';

/*
 * `projectSnapshot` turns what a collection hands over (one project for a
 * local folder, one per app for a deployed project, plus the apps that were
 * not read) into one snapshot. It makes no request: the collection is given.
 */

const NOW = new Date('2026-09-29T00:00:00.000Z');
const API = new URL('https://api.cf.example.org');

const mocked = (id: string) =>
  rawProject({
    id,
    deployment: { app: id, mta: { id: 'acme', version: '1.0.0', module: null, namespace: null } },
    cds: cdsEffective('production', { authKind: 'mocked' }),
  });

const notRead = (id: string, app: string, reason: string): NotRead => ({
  check: deployedAppNotRead(id, app),
  reasonCode: 'unavailable',
  reason,
});

function snapshotOf(collection: ProjectCollection, log: string[] = []) {
  return projectSnapshot(() => Promise.resolve(collection), {
    check: COLLECTOR_CHECKS.deployedApp,
    apiEndpoint: API,
    now: () => NOW,
    log: (line) => log.push(line),
  });
}

describe('projectSnapshot with several projects', () => {
  const collection: ProjectCollection = {
    projects: [mocked('acme-router'), mocked('acme-srv')],
    notRead: [
      notRead('acme-db', 'acme-db', 'it is stopped'),
      notRead('acme-job-1f0c', 'acme job', 'it has no web process'),
    ],
  };

  it('records the collection as ran, then one skipped check per app not read, then the rules', async () => {
    const snapshot = await snapshotOf(collection);
    expect(snapshot.checks.slice(0, 3)).toEqual([
      {
        id: 'collect.project',
        title: COLLECTOR_CHECKS.deployedApp.title,
        roles: ['SpaceDeveloper'],
        status: 'ran',
      },
      {
        id: 'collect.project.acme-db',
        title: 'Files of deployed app acme-db',
        roles: ['SpaceDeveloper'],
        status: 'skipped',
        reasonCode: 'unavailable',
        reason: 'it is stopped',
      },
      {
        id: 'collect.project.acme-job-1f0c',
        title: 'Files of deployed app acme job',
        roles: ['SpaceDeveloper'],
        status: 'skipped',
        reasonCode: 'unavailable',
        reason: 'it has no web process',
      },
    ]);
    const rules = snapshot.checks.slice(3);
    expect(rules).toHaveLength(PROJECT_ANALYZERS.length);
    // A skipped app does not stop the rules on the apps that were read.
    expect(rules.every((check) => check.id.startsWith('rule.') && check.status === 'ran')).toBe(
      true,
    );
  });

  it('lists the projects read in the scope and judges each on its own', async () => {
    const snapshot = await snapshotOf(collection);
    expect(snapshot.scope).toEqual({
      apiEndpoint: 'https://api.cf.example.org/',
      orgs: [],
      projects: ['acme-router', 'acme-srv'],
    });
    expect(snapshot.raw.projects).toEqual(collection.projects);
    expect(snapshot.apps.map((item) => item.guid).sort()).toEqual([
      'project:acme-router',
      'project:acme-srv',
    ]);
    const mockedAuth = snapshot.findings.filter((f) => f.id === 'CAP_MOCKED_AUTH_IN_PROD');
    expect(mockedAuth.map((f) => f.app.guid)).toEqual(['project:acme-router', 'project:acme-srv']);
    expect(SnapshotSchema.safeParse(snapshot).success).toBe(true);
  });

  it('logs one line per project read, then the skipped checks', async () => {
    const log: string[] = [];
    await snapshotOf(collection, log);
    expect(log).toEqual([
      'Read 0 project file(s) in project acme-router',
      'Read 0 project file(s) in project acme-srv',
      'skipped collect.project.acme-db: it is stopped',
      'skipped collect.project.acme-job-1f0c: it has no web process',
    ]);
  });

  it('refuses two projects with the same id: findings and rows are keyed by it', async () => {
    await expect(
      snapshotOf({ projects: [mocked('acme-srv'), mocked('acme-srv')], notRead: [] }),
    ).rejects.toThrow('two projects of one scan have the same id');
  });

  it('refuses a skip under the id of the collection, or the same id twice', async () => {
    const own: NotRead = {
      check: COLLECTOR_CHECKS.deployedApp,
      reasonCode: 'unavailable',
      reason: 'it is stopped',
    };
    await expect(snapshotOf({ projects: [mocked('acme-srv')], notRead: [own] })).rejects.toThrow(
      'two checks of one project scan have the same id',
    );
    const twice = [notRead('acme-db', 'a', 'it is stopped'), notRead('acme-db', 'b', 'stopped')];
    await expect(snapshotOf({ projects: [mocked('acme-srv')], notRead: twice })).rejects.toThrow(
      'two checks of one project scan have the same id',
    );
  });

  it('keeps a collection that fails as a skipped collect.project, as for a local folder', async () => {
    const snapshot = await projectSnapshot(() => Promise.reject(new Error('boom')), {
      check: COLLECTOR_CHECKS.project,
      now: () => NOW,
    });
    expect(snapshot.scope).toEqual({ orgs: [], projects: [] });
    expect(snapshot.checks[0]).toMatchObject({
      id: 'collect.project',
      status: 'skipped',
      reasonCode: 'error',
      reason: 'error: boom',
    });
  });
});

describe('the check of an app that was not read', () => {
  it('has an id under collect.project, which report --from keeps, and is never collect.project', () => {
    const check = deployedAppNotRead('acme-db', 'acme-db');
    expect(check).toEqual({
      id: 'collect.project.acme-db',
      title: 'Files of deployed app acme-db',
      roles: ['SpaceDeveloper'],
    });
    expect(check.id.startsWith('collect.')).toBe(true);
    expect(check.id).not.toBe(COLLECTOR_CHECKS.deployedApp.id);
  });

  it('cuts a long app name in the title to 80 characters and collapses its whitespace', () => {
    const title = deployedAppNotRead('x', `my  app\n${'n'.repeat(200)}`).title;
    expect(title).toBe(`Files of deployed app my app ${'n'.repeat(72)}…`);
    expect(title.slice('Files of deployed app '.length)).toHaveLength(80);
  });
});
