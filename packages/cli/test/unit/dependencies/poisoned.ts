import type { RawProject } from '../../../src/model/raw.js';
import {
  POISON,
  action,
  annotate,
  archive,
  cdsEffective,
  cdsFile,
  entity,
  htmlBootstrap,
  mta,
  packageJson,
  rawProject,
  seedCsv,
  service,
  serviceEntity,
  xsApp,
  xsSecurity,
} from '../../support/project.js';

/**
 * A project record with a poison value in every position that holds text
 * from the project, for the "copies nothing from the project" test of a
 * dependency rule. `overrides` sets what the rule under test reads.
 */
export function poisonedProject(overrides: Partial<RawProject>): RawProject {
  return rawProject({
    repository: true,
    gitIgnore: { present: true },
    sourcesRead: ['.cdsrc.yaml', '.cdsrc.json', 'package.json'],
    files: POISON,
    unreadable: POISON.map((file) => ({ file, kind: 'binary' as const })),
    packageJson: packageJson(
      Object.fromEntries(POISON.map((value) => [value, value])),
      POISON,
      POISON[0],
    ),
    cds: cdsEffective('production', {
      authKind: 'mocked',
      mockedUsers: POISON.length,
      mockedUsersWithPassword: POISON.length,
      restrictAllServices: false,
    }),
    mta: mta({
      id: null,
      modules: POISON.map((value) => ({
        name: value,
        type: value,
        path: value,
        buildpack: value,
        requires: [value],
      })),
      resources: POISON.map((value) => ({ name: value, type: value, service: value, plan: value })),
    }),
    xsSecurity: POISON.map((value) =>
      xsSecurity({
        file: value,
        scopes: [value, { name: `$XSAPPNAME.${value}`, grantedToApps: true }],
        roleTemplates: [[value, [value]]],
        attributes: [value],
      }),
    ),
    xsApps: POISON.map((value) =>
      xsApp(value, [{ source: value, authenticationType: 'none', csrfProtection: false }]),
    ),
    cdsFiles: POISON.map((value) =>
      cdsFile(value, {
        usings: [{ alias: value, target: value }],
        services: [
          service(value, {
            requires: [value],
            restrictTo: [value],
            entities: [serviceEntity(value, { projectionOf: value })],
            actions: [action(value)],
          }),
        ],
        entities: [entity(value, [value], { associations: [{ field: value, target: value }] })],
        annotates: [annotate(value, { requires: [value], restrictTo: [value] })],
      }),
    ),
    seedData: POISON.map((value) =>
      seedCsv(value, { sensitiveColumns: [{ columnIndex: 1, kind: 'secret', rowsMatching: 1 }] }),
    ),
    archives: POISON.map((value) => archive(value, { bytes: POISON.length })),
    html: POISON.map((value) => htmlBootstrap(value, value)),
    ...overrides,
  });
}
