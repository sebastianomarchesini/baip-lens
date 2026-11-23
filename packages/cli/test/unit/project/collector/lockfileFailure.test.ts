import { mkdtemp, realpath, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import type * as Lockfile from '../../../../src/collectors/project/lockfile.js';
import { collectProject } from '../../../../src/collectors/project/index.js';

/*
 * Nothing a file holds may end the collection: a lockfile parser that throws
 * (it does not today) must leave an unreadable lockfile behind, never an
 * error whose message could carry a path or a package name.
 */
vi.mock('../../../../src/collectors/project/lockfile.js', async (importOriginal) => {
  const actual = await importOriginal<typeof Lockfile>();
  return {
    ...actual,
    parseLockfile: () => {
      throw new Error('POISON_parser_message in @poison-scope/private');
    },
  };
});

describe('a lockfile parser that throws', () => {
  it('is recorded as an unreadable lockfile, and the rest of the project is still collected', async () => {
    const root = await realpath(await mkdtemp(join(tmpdir(), 'baip-lens-lockfile-failure-')));
    await writeFile(join(root, 'package.json'), '{ "name": "acme" }');
    await writeFile(join(root, 'package-lock.json'), '{ "lockfileVersion": 3, "packages": {} }');
    const project = await collectProject(root);
    expect(project.dependencies).toEqual({
      lockfiles: [
        {
          file: 'package-lock.json',
          kind: 'package-lock',
          lockfileVersion: null,
          status: 'unreadable',
          kept: 0,
          notKept: {
            otherRegistry: 0,
            git: 0,
            file: 0,
            link: 0,
            bundled: 0,
            unknown: 0,
            excluded: 0,
            invalid: 0,
          },
        },
      ],
      lockfilesNotRead: 0,
      packages: [],
    });
    expect(project.unreadable).toEqual([{ file: 'package-lock.json', kind: 'json' }]);
    expect(project.files).toEqual(['package.json']);
    expect(project.packageJson.name).toBe('acme');
    expect(JSON.stringify(project)).not.toMatch(/poison/i);
  });
});
