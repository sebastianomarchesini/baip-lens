import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { reanalyze } from '../../src/analyzers/index.js';
import { type RawDeployment, RawDeploymentSchema, RawProjectSchema } from '../../src/model/raw.js';
import { SNAPSHOT_SCHEMA_VERSION, SnapshotSchema } from '../../src/model/snapshot.js';
import { rawProject } from '../support/project.js';

/*
 * `raw.projects[].deployment`: which deployed app a project record was read
 * from (`project --cf`). The field is optional, so the schema version stays 1
 * and a project snapshot written before it existed loads unchanged.
 */

/** A project snapshot as `project --path` writes it, committed before the field existed. */
const sample = (): Record<string, unknown> =>
  JSON.parse(
    readFileSync(new URL('../fixtures/sample-project-snapshot.json', import.meta.url), 'utf8'),
  ) as Record<string, unknown>;

/** The sample with `deployment` set on its one project. */
function withDeployment(deployment: unknown): unknown {
  const snapshot = sample();
  const raw = snapshot.raw as { projects: Record<string, unknown>[] };
  raw.projects = raw.projects.map((project) => ({ ...project, deployment }));
  return snapshot;
}

const DEPLOYED: RawDeployment = {
  app: 'incidents-srv',
  mta: { id: 'acme.incidents', version: '1.2.0', module: 'incidents-srv', namespace: 'blue' },
};

describe('the deployment of a project record', () => {
  it('is absent in a snapshot written before the field existed, which still loads', () => {
    const parsed = SnapshotSchema.parse(sample());
    expect(parsed.schemaVersion).toBe(SNAPSHOT_SCHEMA_VERSION);
    expect(parsed.raw.projects).toHaveLength(1);
    for (const project of parsed.raw.projects) expect('deployment' in project).toBe(false);
    // Nothing is added on the way through: a local scan keeps its exact shape.
    expect(parsed).toEqual(sample());
  });

  it('round-trips through the snapshot schema', () => {
    const parsed = SnapshotSchema.parse(withDeployment(DEPLOYED));
    expect(parsed.raw.projects.map((project) => project.deployment)).toEqual([DEPLOYED]);
    const again = SnapshotSchema.parse(JSON.parse(JSON.stringify(parsed)));
    expect(again).toEqual(parsed);
    // The rules do not read it: the same findings with and without.
    expect(reanalyze(parsed).findings).toEqual(reanalyze(SnapshotSchema.parse(sample())).findings);
  });

  it('holds null for an app that belongs to no MTA, and for each part the app does not carry', () => {
    expect(RawDeploymentSchema.parse({ app: 'standalone', mta: null })).toEqual({
      app: 'standalone',
      mta: null,
    });
    const bare = { id: 'acme', version: null, module: null, namespace: null };
    expect(RawDeploymentSchema.parse({ app: 'acme srv (blue)', mta: bare })).toEqual({
      app: 'acme srv (blue)',
      mta: bare,
    });
    expect(RawProjectSchema.parse(rawProject({ deployment: DEPLOYED })).deployment).toEqual(
      DEPLOYED,
    );
  });

  it('drops every key it does not know', () => {
    const parsed = RawDeploymentSchema.parse({
      ...DEPLOYED,
      guid: 'a0000000-0000-4000-8000-000000000001',
      mta: { ...DEPLOYED.mta, contact: 'owner@example.com', boundServices: ['db'] },
    });
    expect(parsed).toEqual(DEPLOYED);
  });

  it.each([
    ['no app name', { ...DEPLOYED, app: '' }],
    ['an app name of 256 characters', { ...DEPLOYED, app: 'a'.repeat(256) }],
    ['a missing mta key', { app: 'incidents-srv' }],
    ['an id with a space', { ...DEPLOYED, mta: { ...DEPLOYED.mta, id: 'acme incidents' } }],
    ['an id of 129 characters', { ...DEPLOYED, mta: { ...DEPLOYED.mta, id: 'a'.repeat(129) } }],
    ['a version with markup', { ...DEPLOYED, mta: { ...DEPLOYED.mta, version: '<1.0>' } }],
    [
      'a version of 65 characters',
      { ...DEPLOYED, mta: { ...DEPLOYED.mta, version: '1'.repeat(65) } },
    ],
    ['a module with a slash', { ...DEPLOYED, mta: { ...DEPLOYED.mta, module: 'srv/api' } }],
    [
      'a namespace of 37 characters',
      { ...DEPLOYED, mta: { ...DEPLOYED.mta, namespace: 'n'.repeat(37) } },
    ],
    [
      'an e-mail as namespace',
      { ...DEPLOYED, mta: { ...DEPLOYED.mta, namespace: 'a@example.com' } },
    ],
  ])('refuses %s', (_name, deployment) => {
    expect(RawDeploymentSchema.safeParse(deployment).success).toBe(false);
    expect(SnapshotSchema.safeParse(withDeployment(deployment)).success).toBe(false);
  });

  it('accepts the longest values the patterns allow', () => {
    const longest: RawDeployment = {
      app: 'a'.repeat(255),
      mta: {
        id: 'i'.repeat(128),
        version: '1'.repeat(64),
        module: 'm'.repeat(128),
        namespace: 'n'.repeat(36),
      },
    };
    expect(RawDeploymentSchema.parse(longest)).toEqual(longest);
  });
});
