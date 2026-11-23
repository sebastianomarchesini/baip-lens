import { describe, expect, it } from 'vitest';
import {
  DEPENDENCY_EXCLUDE_PATTERN,
  LOCKFILE_SHAPE_LIMITS,
  type LockfileOptions,
  type LockfileSource,
  MAX_PACKAGES,
  emptyNotKept,
  excludeMatcher,
  parseLockfile,
} from '../../../../src/collectors/project/lockfile.js';
import {
  LOCKED_PACKAGE_NAME_PATTERN,
  PACKAGE_VERSION_PATTERN,
  RawLockfileSchema,
} from '../../../../src/model/raw.js';

/*
 * The lockfile parser, fed inline text. Package names are invented; `POISON`
 * marks what must never come out: the name of a package that is not from the
 * public npm registry, and every field of an entry but its name and version.
 */

const REGISTRY = 'https://registry.npmjs.org';

/** A `resolved` address on the public npm registry. */
const registry = (name: string, version = '1.0.0'): string =>
  `${REGISTRY}/${name}/-/${name.slice(name.lastIndexOf('/') + 1)}-${version}.tgz`;

const SOURCE: LockfileSource = {
  file: 'package-lock.json',
  kind: 'package-lock',
  rootDirectNames: null,
};

function parse(
  lockfile: unknown,
  source: Partial<LockfileSource> = {},
  options: LockfileOptions = {},
) {
  const text = typeof lockfile === 'string' ? lockfile : JSON.stringify(lockfile);
  return parseLockfile(text, { ...SOURCE, ...source }, options);
}

/** A version 3 lockfile with the given entries next to its root entry. */
const v3 = (packages: Record<string, unknown>, root: Record<string, unknown> = {}) => ({
  name: 'POISON_lock_name',
  version: '1.0.0',
  lockfileVersion: 3,
  requires: true,
  packages: { '': { name: 'POISON_lock_name', version: '1.0.0', ...root }, ...packages },
});

/** A version 1 lockfile: a tree of dependencies, no root entry. */
const v1 = (dependencies: Record<string, unknown>) => ({
  name: 'POISON_lock_name',
  version: '1.0.0',
  lockfileVersion: 1,
  requires: true,
  dependencies,
});

const names = (result: ReturnType<typeof parse>) =>
  result.packages.map((item) => `${item.name}@${item.version}`);

const counted = (notKept: Partial<ReturnType<typeof emptyNotKept>>) => ({
  ...emptyNotKept(),
  ...notKept,
});

describe('lockfile version 3', () => {
  it('keeps name and version of the packages from the public npm registry, and nothing else', () => {
    const result = parse(
      v3(
        {
          'node_modules/baip-server': {
            version: '2.4.1',
            resolved: registry('baip-server', '2.4.1'),
            integrity: 'sha512-POISON_integrity',
            license: 'POISON_license',
            deprecated: 'POISON_deprecated: do not use',
            funding: { url: 'https://POISON_funding.example.org' },
            bin: { POISON_bin: 'cli.js' },
            engines: { node: 'POISON_engine' },
            dependencies: { POISON_requirement: '^1' },
            hasInstallScript: true,
          },
          'node_modules/@baip/odata': {
            version: '3.1.0-beta.1+build.5',
            resolved: registry('@baip/odata', '3.1.0-beta.1'),
          },
          'node_modules/baip-server/node_modules/baip-merge': {
            version: '3.10.1',
            resolved: registry('baip-merge', '3.10.1'),
          },
        },
        { dependencies: { 'baip-server': '^2', '@baip/odata': 'POISON_range' } },
      ),
    );
    expect(result).toEqual({
      lockfile: {
        file: 'package-lock.json',
        kind: 'package-lock',
        lockfileVersion: 3,
        status: 'read',
        kept: 3,
        notKept: emptyNotKept(),
      },
      packages: [
        { name: '@baip/odata', version: '3.1.0-beta.1+build.5', direct: true, scope: 'prod' },
        { name: 'baip-merge', version: '3.10.1', direct: false, scope: 'prod' },
        { name: 'baip-server', version: '2.4.1', direct: true, scope: 'prod' },
      ],
    });
    expect(JSON.stringify(result)).not.toMatch(/POISON|registry\.npmjs|sha512/);
    expect(RawLockfileSchema.safeParse(result.lockfile).success).toBe(true);
  });

  it('reads the real name of an alias from the entry, and tells direct by the install name', () => {
    const result = parse(
      v3(
        {
          'node_modules/my-alias': {
            name: 'baip-queue',
            version: '5.0.2',
            resolved: registry('baip-queue', '5.0.2'),
          },
          // The real name sits one level down as well, required by something else.
          'node_modules/baip-x/node_modules/baip-queue': {
            version: '4.0.0',
            resolved: registry('baip-queue', '4.0.0'),
          },
        },
        { dependencies: { 'my-alias': 'npm:baip-queue@^5' } },
      ),
    );
    expect(result.packages).toEqual([
      { name: 'baip-queue', version: '4.0.0', direct: false, scope: 'prod' },
      { name: 'baip-queue', version: '5.0.2', direct: true, scope: 'prod' },
    ]);
  });

  it('calls a package direct when the root lists it in any of the four sections, at the top level only', () => {
    const entry = (name: string) => ({ version: '1.0.0', resolved: registry(name) });
    const result = parse(
      v3(
        {
          'node_modules/a-prod': entry('a-prod'),
          'node_modules/b-dev': { ...entry('b-dev'), dev: true },
          'node_modules/c-optional': { ...entry('c-optional'), optional: true },
          'node_modules/d-peer': { ...entry('d-peer'), peer: true },
          'node_modules/e-transitive': entry('e-transitive'),
          // Listed by the root, but this copy is nested: installed for another package.
          'node_modules/e-transitive/node_modules/f-nested': entry('f-nested'),
          // A workspace's own install folder is not the top level.
          'packages/app/node_modules/a-prod': { version: '2.0.0', resolved: registry('a-prod') },
        },
        {
          dependencies: { 'a-prod': '^1', 'f-nested': '^1' },
          devDependencies: { 'b-dev': '^1' },
          optionalDependencies: { 'c-optional': '^1' },
          peerDependencies: { 'd-peer': '^1' },
        },
      ),
    );
    expect(result.packages.map((item) => [item.name, item.version, item.direct])).toEqual([
      ['a-prod', '1.0.0', true],
      ['a-prod', '2.0.0', false],
      ['b-dev', '1.0.0', true],
      ['c-optional', '1.0.0', true],
      ['d-peer', '1.0.0', true],
      ['e-transitive', '1.0.0', false],
      ['f-nested', '1.0.0', false],
    ]);
  });

  it('reads the scope from the flags: dev, else optional, else prod', () => {
    const entry = (name: string, flags: Record<string, unknown>) => ({
      version: '1.0.0',
      resolved: registry(name),
      ...flags,
    });
    const result = parse(
      v3({
        'node_modules/a': entry('a', {}),
        'node_modules/b': entry('b', { dev: true }),
        'node_modules/c': entry('c', { optional: true }),
        'node_modules/d': entry('d', { devOptional: true }),
        'node_modules/e': entry('e', { dev: true, optional: true }),
        'node_modules/f': entry('f', { peer: true }),
        'node_modules/g': entry('g', { extraneous: true }),
        // Only `true` is a flag.
        'node_modules/h': entry('h', { dev: 'true', optional: 1 }),
      }),
    );
    expect(result.packages.map((item) => [item.name, item.scope])).toEqual([
      ['a', 'prod'],
      ['b', 'dev'],
      ['c', 'optional'],
      ['d', 'optional'],
      ['e', 'dev'],
      ['f', 'prod'],
      ['g', 'prod'],
      ['h', 'prod'],
    ]);
  });

  it('keeps one entry per name and version: direct if any is, with the strongest scope', () => {
    const copy = (flags: Record<string, unknown>) => ({
      version: '1.0.0',
      resolved: registry('baip-merge'),
      ...flags,
    });
    const result = parse(
      v3(
        {
          'node_modules/x/node_modules/baip-merge': copy({ dev: true }),
          'node_modules/baip-merge': copy({ optional: true }),
          'node_modules/y/node_modules/baip-merge': copy({ dev: true }),
          'node_modules/z/node_modules/baip-only-dev': {
            version: '1.0.0',
            resolved: registry('baip-only-dev'),
            dev: true,
          },
          'node_modules/baip-only-dev': {
            version: '1.0.0',
            resolved: registry('baip-only-dev'),
            dev: true,
          },
        },
        { dependencies: { 'baip-merge': '^1' } },
      ),
    );
    expect(result.packages).toEqual([
      { name: 'baip-merge', version: '1.0.0', direct: true, scope: 'optional' },
      { name: 'baip-only-dev', version: '1.0.0', direct: false, scope: 'dev' },
    ]);
    expect(result.lockfile.kept).toBe(2);

    const prod = parse(
      v3({
        'node_modules/a/node_modules/baip-merge': copy({ optional: true }),
        'node_modules/b/node_modules/baip-merge': copy({}),
        'node_modules/c/node_modules/baip-merge': copy({ dev: true }),
      }),
    );
    expect(prod.packages).toEqual([
      { name: 'baip-merge', version: '1.0.0', direct: false, scope: 'prod' },
    ]);
  });

  it('counts every entry that is not from the public registry under its reason, without its name', () => {
    const result = parse(
      v3({
        'node_modules/baip-kept': { version: '1.0.0', resolved: registry('baip-kept') },
        'node_modules/@POISON-scope/private': {
          version: '1.0.0',
          resolved:
            'https://npm.POISON-internal.example.com/@POISON-scope/private/-/private-1.0.0.tgz',
        },
        'node_modules/POISON-mirror': {
          version: '1.0.0',
          resolved: 'http://registry.npmjs.org/POISON-mirror/-/POISON-mirror-1.0.0.tgz',
        },
        'node_modules/POISON-git': {
          version: '1.0.0',
          resolved: 'git+ssh://git@github.com/acme/POISON-git.git#0123abc',
        },
        'node_modules/POISON-github': {
          version: '1.0.0',
          resolved: 'github:acme/POISON-github#0123abc',
        },
        'node_modules/POISON-tarball': {
          version: '1.0.0',
          resolved: 'file:vendor/POISON-tarball-1.0.0.tgz',
        },
        'node_modules/POISON-path': { version: '1.0.0', resolved: '../POISON-path-1.0.0.tgz' },
        'node_modules/POISON-link': { resolved: '../POISON-folder', link: true },
        '../POISON-folder': { version: '0.1.0', dependencies: { POISON_requirement: '1' } },
        'packages/POISON-workspace': { name: '@POISON/workspace', version: '1.0.0' },
        'node_modules/baip-kept/node_modules/POISON-bundled': {
          version: '1.0.0',
          inBundle: true,
          resolved: registry('POISON-bundled'),
        },
        'node_modules/POISON-unresolved': { version: '1.0.0' },
        'node_modules/POISON-empty': { version: '1.0.0', resolved: '' },
        'node_modules/POISON-ftp': { version: '1.0.0', resolved: 'ftp://POISON.example.com/x.tgz' },
      }),
    );
    expect(names(result)).toEqual(['baip-kept@1.0.0']);
    expect(result.lockfile).toMatchObject({
      status: 'read',
      kept: 1,
      notKept: counted({ otherRegistry: 2, git: 2, file: 2, link: 3, bundled: 1, unknown: 3 }),
    });
    expect(JSON.stringify(result)).not.toMatch(/POISON/i);
  });

  it('takes a key for an install only when `node_modules/` is a folder of its own in it', () => {
    const entry = { version: '1.0.0', resolved: registry('POISON') };
    const result = parse(
      v3({
        // A folder whose name only ends in `node_modules`: a linked folder, not an install.
        'vendor/POISON-node_modules/POISON': entry,
        'POISON_node_modules/POISON': entry,
        'xnode_modules/POISON': entry,
        // No folder of that name at all, and one that is not followed by a name.
        'packages/POISON': entry,
        node_modules: entry,
        // An install below a workspace folder is one.
        'packages/app/node_modules/baip-nested': {
          version: '1.0.0',
          resolved: registry('baip-nested'),
        },
      }),
    );
    expect(names(result)).toEqual(['baip-nested@1.0.0']);
    expect(result.lockfile.notKept).toEqual(counted({ link: 5 }));
    expect(JSON.stringify(result)).not.toContain('POISON');
  });

  it.each([
    ['git://github.com/acme/POISON.git#0123abc', 'git'],
    ['ssh://git@github.com/acme/POISON.git#0123abc', 'git'],
    ['git+https://github.com/acme/POISON.git#0123abc', 'git'],
    ['git+ssh://git@github.com/acme/POISON.git', 'git'],
    ['git+file:///srv/git/POISON.git', 'git'],
    ['github:acme/POISON#0123abc', 'git'],
    ['gitlab:acme/POISON#0123abc', 'git'],
    ['bitbucket:acme/POISON#0123abc', 'git'],
    ['gist:0123456789abcdef', 'git'],
    ['git@github.com:acme/POISON.git', 'git'],
    ['file:../POISON', 'file'],
    ['file:///srv/POISON-1.0.0.tgz', 'file'],
    ['../POISON-1.0.0.tgz', 'file'],
    ['./POISON-1.0.0.tgz', 'file'],
    ['/abs/POISON-1.0.0.tgz', 'file'],
    ['~/POISON-1.0.0.tgz', 'file'],
    ['..\\POISON-1.0.0.tgz', 'file'],
    ['.\\POISON-1.0.0.tgz', 'file'],
    ['\\\\host\\share\\POISON-1.0.0.tgz', 'file'],
    ['~\\POISON-1.0.0.tgz', 'file'],
    // Not a path and no address this tool knows.
    ['POISON-1.0.0.tgz', 'unknown'],
    ['~POISON/x.tgz', 'unknown'],
    ['...//POISON.tgz', 'unknown'],
    ['svn://POISON.example.com/x', 'unknown'],
    ['gitx:acme/POISON', 'unknown'],
  ] as const)('classes the address %s as %s', (resolved, reason) => {
    const modern = parse(v3({ 'node_modules/POISON-pkg': { version: '1.0.0', resolved } }));
    expect(modern.packages).toEqual([]);
    expect(modern.lockfile.notKept).toEqual(counted({ [reason]: 1 }));
    // Version 1 writes such an address into `version` and has no `resolved`.
    const legacy = parse(v1({ 'POISON-pkg': { version: resolved } }));
    expect(legacy.packages).toEqual([]);
    expect(legacy.lockfile.notKept).toEqual(counted({ [reason]: 1 }));
    expect(JSON.stringify([modern, legacy])).not.toContain('POISON');
  });

  it('takes only https://registry.npmjs.org, written exactly so, for the public registry', () => {
    const notPublic = [
      'http://registry.npmjs.org/p/-/p-1.0.0.tgz',
      'https://registry.npmjs.org:8443/p/-/p-1.0.0.tgz',
      'https://registry.npmjs.org:443/p/-/p-1.0.0.tgz',
      'https://user@registry.npmjs.org/p/-/p-1.0.0.tgz',
      'https://user:token@registry.npmjs.org/p/-/p-1.0.0.tgz',
      'https://REGISTRY.NPMJS.ORG/p/-/p-1.0.0.tgz',
      'HTTPS://registry.npmjs.org/p/-/p-1.0.0.tgz',
      'https://registry.npmjs.org./p/-/p-1.0.0.tgz',
      'https://registry.npmjs.org.evil.example/p/-/p-1.0.0.tgz',
      'https://registry.npmjs.org@evil.example/p/-/p-1.0.0.tgz',
      'https://evil.example/registry.npmjs.org/p/-/p-1.0.0.tgz',
      'https://evil.example/?https://registry.npmjs.org/p/-/p-1.0.0.tgz',
      'https:\\\\registry.npmjs.org\\p\\-\\p-1.0.0.tgz',
      ' https://registry.npmjs.org/p/-/p-1.0.0.tgz',
      'https://registry.npmjs.org',
      'https://registry.yarnpkg.com/p/-/p-1.0.0.tgz',
      'https://npm.pkg.github.com/download/@acme/p/1.0.0/abc',
    ];
    const packages = Object.fromEntries(
      notPublic.map((resolved, i) => [`node_modules/p${i}`, { version: '1.0.0', resolved }]),
    );
    const result = parse(v3(packages));
    expect(result.packages).toEqual([]);
    expect(result.lockfile.notKept).toEqual(counted({ otherRegistry: notPublic.length }));

    const fine = parse(
      v3({
        'node_modules/p': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/p/-/p-1.0.0.tgz?x=1#y',
        },
      }),
    );
    expect(names(fine)).toEqual(['p@1.0.0']);
  });

  it('counts a registry entry with a name or version that is not a plain npm one as invalid', () => {
    const at = (key: string, entry: Record<string, unknown>): [string, Record<string, unknown>] => [
      key,
      { resolved: registry('x'), version: '1.0.0', ...entry },
    ];
    const invalid = Object.fromEntries([
      at('node_modules/..', {}),
      at('node_modules/.hidden', {}),
      at('node_modules/_underscore', {}),
      at('node_modules/has space', {}),
      at('node_modules/@scope', {}),
      at('node_modules/@/name', {}),
      at('node_modules/@scope/a/b', {}),
      at('node_modules/a%2fb', {}),
      at('node_modules/', {}),
      at(`node_modules/${'n'.repeat(215)}`, {}),
      at('node_modules/alias-a', { name: '../POISON_name' }),
      at('node_modules/alias-b', { name: 'POISON name' }),
      at('node_modules/v1', { version: '^1.0.0' }),
      at('node_modules/v2', { version: '1.0' }),
      at('node_modules/v3', { version: 'latest' }),
      at('node_modules/v4', { version: '1.0.0/../POISON_version' }),
      at('node_modules/v5', { version: `1.0.0-${'9'.repeat(60)}` }),
      at('node_modules/v6', { version: 1 }),
      at('node_modules/v7', { version: undefined }),
      at('node_modules/v8', { version: 'npm:POISON@1.0.0' }),
    ]);
    const result = parse(
      v3({
        ...invalid,
        'node_modules/not-an-object': 'POISON_string',
        'node_modules/null-entry': null,
        'node_modules/array-entry': [],
        // The longest name and version the patterns allow are kept.
        [`node_modules/${'n'.repeat(214)}`]: {
          version: `1.0.0-${'9'.repeat(58)}`,
          resolved: registry('x'),
        },
      }),
    );
    expect(result.lockfile.notKept).toEqual(counted({ invalid: Object.keys(invalid).length + 3 }));
    expect(names(result)).toEqual([`${'n'.repeat(214)}@1.0.0-${'9'.repeat(58)}`]);
    expect(JSON.stringify(result)).not.toContain('POISON');
    for (const item of result.packages) {
      expect(item.name).toMatch(LOCKED_PACKAGE_NAME_PATTERN);
      expect(item.version).toMatch(PACKAGE_VERSION_PATTERN);
    }
  });

  it('holds back the packages that match an exclude pattern, and counts them', () => {
    const lockfile = v3({
      'node_modules/@POISON-corp/billing': {
        version: '1.0.0',
        resolved: registry('@POISON-corp/billing'),
      },
      'node_modules/@poison-corp/Ledger': {
        version: '1.0.0',
        resolved: registry('@poison-corp/Ledger'),
      },
      'node_modules/POISON-internal-tool': {
        version: '1.0.0',
        resolved: registry('POISON-internal-tool'),
      },
      'node_modules/alias': {
        name: 'POISON-exact',
        version: '1.0.0',
        resolved: registry('POISON-exact'),
      },
      'node_modules/baip-kept': { version: '1.0.0', resolved: registry('baip-kept') },
      // Not from the public registry: counted under where it comes from, whatever the patterns say.
      'node_modules/@POISON-corp/mirror': {
        version: '1.0.0',
        resolved: 'https://npm.example.com/x.tgz',
      },
    });
    const exclude = excludeMatcher(['@poison-corp/*', '*-INTERNAL-*', 'poison-exact']);
    const result = parse(lockfile, {}, { exclude });
    expect(names(result)).toEqual(['baip-kept@1.0.0']);
    expect(result.lockfile.notKept).toEqual(counted({ excluded: 4, otherRegistry: 1 }));
    expect(JSON.stringify(result)).not.toMatch(/poison/i);
  });

  it('counts an entry that is both invalid and excluded as invalid: the reasons have an order', () => {
    const exclude = excludeMatcher(['@poison-corp/*', 'poison-*', '..*']);
    const result = parse(
      v3({
        // The name matches a pattern, the version is not an exact one.
        'node_modules/@poison-corp/billing': {
          version: '^1.0.0',
          resolved: registry('@poison-corp/billing'),
        },
        // A name that is not a plain npm one and matches a pattern all the same.
        'node_modules/alias': {
          name: '../POISON_name',
          version: '1.0.0',
          resolved: registry('x'),
        },
        'node_modules/poison-tool': { version: '1.0.0', resolved: registry('poison-tool') },
        // Where a package comes from is decided before both.
        'node_modules/poison-mirror': {
          version: '^1.0.0',
          resolved: 'https://npm.example.com/x.tgz',
        },
      }),
      {},
      { exclude },
    );
    expect(result.packages).toEqual([]);
    expect(result.lockfile.notKept).toEqual(counted({ invalid: 2, excluded: 1, otherRegistry: 1 }));
    // The same order in a version 1 tree.
    const legacy = parse(
      v1({
        'poison-range': { version: '^1.0.0', resolved: registry('poison-range') },
        'poison-tool': { version: '1.0.0', resolved: registry('poison-tool') },
      }),
      {},
      { exclude },
    );
    expect(legacy.lockfile.notKept).toEqual(counted({ invalid: 1, excluded: 1 }));
    expect(JSON.stringify([result, legacy])).not.toMatch(/poison/i);
  });

  it('gives up a lockfile with more packages than the budget, instead of cutting it', () => {
    const packages = Object.fromEntries(
      Array.from({ length: 6 }, (_, i) => [
        `node_modules/p${i}`,
        { version: '1.0.0', resolved: registry(`p${i}`) },
      ]),
    );
    // The same package twice is one package.
    packages['node_modules/x/node_modules/p0'] = { version: '1.0.0', resolved: registry('p0') };
    packages['node_modules/POISON-private'] = {
      version: '1.0.0',
      resolved: 'https://npm.example.com/x.tgz',
    };
    expect(parse(v3(packages), {}, { maxPackages: 6 }).lockfile).toMatchObject({
      status: 'read',
      kept: 6,
    });
    expect(parse(v3(packages), {}, { maxPackages: 5 })).toEqual({
      lockfile: {
        file: 'package-lock.json',
        kind: 'package-lock',
        lockfileVersion: 3,
        status: 'too-many-packages',
        kept: 0,
        notKept: emptyNotKept(),
      },
      packages: [],
    });
    expect(parse(v3({}), {}, { maxPackages: 0 }).lockfile.status).toBe('read');
    expect(MAX_PACKAGES).toBe(20_000);
  });

  it('gives the same result whatever the order of the entries', () => {
    const entries: [string, unknown][] = [
      ['node_modules/b', { version: '2.0.0', resolved: registry('b'), dev: true }],
      ['node_modules/a', { version: '10.0.0', resolved: registry('a') }],
      ['node_modules/x/node_modules/a', { version: '9.0.0', resolved: registry('a') }],
      ['node_modules/x/node_modules/b', { version: '2.0.0', resolved: registry('b') }],
      ['node_modules/B', { version: '1.0.0', resolved: registry('B') }],
      ['node_modules/c', { version: '1.0.0', resolved: 'git+https://example.org/c.git' }],
    ];
    const forward = parse(v3(Object.fromEntries(entries), { dependencies: { b: '^2' } }));
    const backward = parse(
      v3(Object.fromEntries([...entries].reverse()), { dependencies: { b: '^2' } }),
    );
    expect(backward).toEqual(forward);
    // Code point order: upper case first, and versions as text.
    expect(names(forward)).toEqual(['B@1.0.0', 'a@10.0.0', 'a@9.0.0', 'b@2.0.0']);
    expect(forward.packages[3]).toEqual({
      name: 'b',
      version: '2.0.0',
      direct: true,
      scope: 'prod',
    });
  });
});

describe('lockfile version 2 and the hidden lockfile', () => {
  it('reads `packages` of a version 2 lockfile and ignores its legacy tree', () => {
    const result = parse({
      ...v3({ 'node_modules/a': { version: '1.0.0', resolved: registry('a') } }),
      lockfileVersion: 2,
      dependencies: {
        a: { version: '1.0.0', resolved: registry('a') },
        'POISON-legacy-only': { version: '1.0.0', resolved: registry('POISON-legacy-only') },
      },
    });
    expect(result.lockfile).toMatchObject({ lockfileVersion: 2, status: 'read', kept: 1 });
    expect(names(result)).toEqual(['a@1.0.0']);
  });

  it('reads `packages` when the version is one it does not know, and records no version', () => {
    for (const lockfileVersion of [4, '3', undefined]) {
      const result = parse({
        ...v3({ 'node_modules/a': { version: '1.0.0', resolved: registry('a') } }),
        lockfileVersion,
      });
      expect(result.lockfile).toMatchObject({ lockfileVersion: null, status: 'read', kept: 1 });
    }
  });

  it('takes the direct names of a lockfile without a root entry from the root package.json', () => {
    const hidden = {
      name: 'POISON_lock_name',
      lockfileVersion: 3,
      requires: true,
      packages: {
        'node_modules/a': { version: '1.0.0', resolved: registry('a') },
        'node_modules/b': { version: '1.0.0', resolved: registry('b') },
        'node_modules/a/node_modules/c': { version: '1.0.0', resolved: registry('c') },
      },
    };
    const source: Partial<LockfileSource> = {
      file: 'node_modules/.package-lock.json',
      kind: 'hidden',
      rootDirectNames: new Set(['a', 'c']),
    };
    const result = parse(hidden, source);
    expect(result.lockfile).toMatchObject({
      file: 'node_modules/.package-lock.json',
      kind: 'hidden',
      status: 'read',
    });
    expect(result.packages.map((item) => [item.name, item.direct])).toEqual([
      ['a', true],
      ['b', false],
      ['c', false],
    ]);
    // Without that manifest nothing is known to be direct.
    expect(parse(hidden, { rootDirectNames: null }).packages.some((item) => item.direct)).toBe(
      false,
    );
  });

  it('prefers the root entry of the lockfile itself over the names it is handed', () => {
    const result = parse(
      v3(
        {
          'node_modules/a': { version: '1.0.0', resolved: registry('a') },
          'node_modules/b': { version: '1.0.0', resolved: registry('b') },
        },
        { dependencies: { a: '^1' } },
      ),
      { rootDirectNames: new Set(['b']) },
    );
    expect(result.packages.map((item) => [item.name, item.direct])).toEqual([
      ['a', true],
      ['b', false],
    ]);
  });
});

describe('lockfile version 1', () => {
  const tree = {
    'baip-server': {
      version: '2.4.1',
      resolved: registry('baip-server', '2.4.1'),
      integrity: 'sha512-POISON_integrity',
      requires: { POISON_requirement: '^1' },
      dependencies: {
        'baip-merge': {
          version: '3.10.1',
          resolved: registry('baip-merge', '3.10.1'),
          dependencies: {
            'baip-deep': { version: '0.0.1', resolved: registry('baip-deep', '0.0.1'), dev: true },
          },
        },
        'POISON-bundled': { version: '1.0.0', bundled: true, resolved: registry('POISON-bundled') },
      },
    },
    'baip-merge': { version: '4.17.20', resolved: registry('baip-merge', '4.17.20') },
    'my-alias': { version: 'npm:baip-queue@5.0.2', resolved: registry('baip-queue', '5.0.2') },
    'scoped-alias': {
      version: 'npm:@baip/odata@3.1.0',
      resolved: registry('@baip/odata', '3.1.0'),
    },
    'baip-dev': { version: '7.0.0', resolved: registry('baip-dev', '7.0.0'), dev: true },
    'baip-optional': { version: '2.3.3', resolved: registry('baip-optional'), optional: true },
    'POISON-local': { version: 'file:../POISON-local', requires: { ms: '2.1.3' } },
    'POISON-git': {
      version: 'git+ssh://git@github.com/acme/POISON-git.git#0123abc',
      from: 'POISON-git@git+ssh://git@github.com/acme/POISON-git.git',
    },
    'POISON-hosted': { version: 'github:acme/POISON-hosted#0123abc' },
    'POISON-scp': { version: 'git@github.com:acme/POISON-scp.git' },
    'POISON-tarball': { version: 'https://POISON.example.com/POISON-tarball-1.0.0.tgz' },
    'POISON-unresolved': { version: '1.0.0' },
    'POISON-mirror': {
      version: '1.0.0',
      resolved: 'https://npm.POISON.example.com/POISON-mirror/-/POISON-mirror-1.0.0.tgz',
    },
    'POISON-bad-alias': { version: 'npm:@POISON/no-version', resolved: registry('x') },
    'POISON-not-an-object': 'POISON',
  };

  it('walks the tree, reads aliases from the version, and classes the rest', () => {
    const result = parse(v1(tree), {
      rootDirectNames: new Set(['baip-server', 'my-alias', 'baip-dev', 'baip-deep']),
    });
    expect(result.lockfile).toEqual({
      file: 'package-lock.json',
      kind: 'package-lock',
      lockfileVersion: 1,
      status: 'read',
      kept: 8,
      notKept: counted({
        otherRegistry: 2,
        git: 3,
        file: 1,
        bundled: 1,
        unknown: 1,
        invalid: 2,
      }),
    });
    expect(result.packages).toEqual([
      { name: '@baip/odata', version: '3.1.0', direct: false, scope: 'prod' },
      // Listed by the root, but nested: not at the top level.
      { name: 'baip-deep', version: '0.0.1', direct: false, scope: 'dev' },
      { name: 'baip-dev', version: '7.0.0', direct: true, scope: 'dev' },
      { name: 'baip-merge', version: '3.10.1', direct: false, scope: 'prod' },
      { name: 'baip-merge', version: '4.17.20', direct: false, scope: 'prod' },
      { name: 'baip-optional', version: '2.3.3', direct: false, scope: 'optional' },
      { name: 'baip-queue', version: '5.0.2', direct: true, scope: 'prod' },
      { name: 'baip-server', version: '2.4.1', direct: true, scope: 'prod' },
    ]);
    expect(JSON.stringify(result)).not.toMatch(/POISON|sha512|registry\.npmjs/);
  });

  it('knows no direct package for a nested lockfile, whose manifest is not read', () => {
    const result = parse(v1(tree), { file: 'app/package-lock.json', rootDirectNames: null });
    expect(result.lockfile.file).toBe('app/package-lock.json');
    expect(result.packages.some((item) => item.direct)).toBe(false);
    expect(result.packages).toHaveLength(8);
  });

  it('reads a version 1 lockfile without a tree as a project without packages', () => {
    const bare: Record<string, unknown> = v1({});
    delete bare.dependencies;
    expect(parse(bare).lockfile).toMatchObject({ lockfileVersion: 1, status: 'read', kept: 0 });
    expect(parse(v1({})).lockfile).toMatchObject({ lockfileVersion: 1, status: 'read', kept: 0 });
  });

  it('gives up a tree with more packages than the budget, wherever in the tree they are', () => {
    const big = v1({
      a: {
        version: '1.0.0',
        resolved: registry('a'),
        dependencies: {
          b: { version: '1.0.0', resolved: registry('b') },
          c: { version: '1.0.0', resolved: registry('c') },
          e: { version: '1.0.0', resolved: registry('e') },
        },
      },
      d: { version: '1.0.0', resolved: registry('d') },
      'POISON-git': { version: 'github:acme/POISON-git' },
    });
    expect(parse(big, {}, { maxPackages: 5 }).lockfile).toMatchObject({ status: 'read', kept: 5 });
    expect(parse(big, {}, { maxPackages: 3 })).toEqual({
      lockfile: {
        file: 'package-lock.json',
        kind: 'package-lock',
        lockfileVersion: 1,
        status: 'too-many-packages',
        kept: 0,
        notKept: emptyNotKept(),
      },
      packages: [],
    });
  });

  it('walks a deep tree without recursion', () => {
    // 30 packages, each installed below the one before: 62 levels of JSON, under the limit of 64.
    let dependencies: Record<string, unknown> = {};
    for (let level = 29; level >= 0; level -= 1) {
      dependencies = {
        [`p${level}`]: { version: '1.0.0', resolved: registry(`p${level}`), dependencies },
      };
    }
    const result = parse(v1(dependencies), { rootDirectNames: new Set(['p0', 'p1']) });
    expect(result.lockfile).toMatchObject({ status: 'read', kept: 30 });
    expect(result.packages.filter((item) => item.direct).map((item) => item.name)).toEqual(['p0']);
  });
});

describe('a file that is not a lockfile this tool reads', () => {
  const unread = (status: string) => ({
    lockfile: {
      file: 'package-lock.json',
      kind: 'package-lock',
      lockfileVersion: null,
      status,
      kept: 0,
      notKept: emptyNotKept(),
    },
    packages: [],
  });

  it.each([
    ['text that is not JSON', '<<<<<<< HEAD\n{ "POISON": 1 }'],
    ['an empty file', ''],
    ['an array', '[]'],
    ['a string', '"POISON"'],
    ['null', 'null'],
    ['an object without a version and without packages', '{"name":"POISON"}'],
    ['a version 1 lockfile whose tree is not an object', '{"lockfileVersion":1,"dependencies":[]}'],
    ['a version 3 lockfile without packages', '{"lockfileVersion":3,"dependencies":{}}'],
    ['a version 3 lockfile whose packages are an array', '{"lockfileVersion":3,"packages":[]}'],
    ['a version it does not know', '{"lockfileVersion":4,"dependencies":{}}'],
    ['a version written as text', '{"lockfileVersion":"1","dependencies":{}}'],
    ['a yarn lockfile', '# yarn lockfile v1\n\nPOISON@^1.0.0:\n  version "1.0.0"\n'],
  ])('is unreadable: %s', (_name, text) => {
    expect(parse(text)).toEqual(unread('unreadable'));
  });

  it('is unreadable when it nests deeper than any lockfile does', () => {
    const deep = `{"lockfileVersion":3,"packages":${'{"a":'.repeat(LOCKFILE_SHAPE_LIMITS.maxDepth)}1${'}'.repeat(LOCKFILE_SHAPE_LIMITS.maxDepth)}}`;
    expect(parse(deep)).toEqual(unread('unreadable'));
  });

  it('is too large with more keys in one object, or more keys and values, than the limits allow', () => {
    const keys = (count: number) => {
      let text = '';
      for (let i = 0; i < count; i += 1) text += `${i === 0 ? '' : ','}"node_modules/p${i}":0`;
      return `{"lockfileVersion":3,"packages":{${text}}}`;
    };
    expect(parse(keys(LOCKFILE_SHAPE_LIMITS.maxMembers + 1))).toEqual(unread('too-large'));
    expect(parse(keys(LOCKFILE_SHAPE_LIMITS.maxMembers)).lockfile).toMatchObject({
      status: 'read',
      notKept: counted({ invalid: LOCKFILE_SHAPE_LIMITS.maxMembers }),
    });
    const items = `{"lockfileVersion":3,"packages":{"a":[${'0,'.repeat(LOCKFILE_SHAPE_LIMITS.maxItems)}0]}}`;
    expect(parse(items)).toEqual(unread('too-large'));
  }, 30_000);

  it('reads a lockfile that starts with a byte order mark', () => {
    const text = `\ufeff${JSON.stringify(v3({ 'node_modules/a': { version: '1.0.0', resolved: registry('a') } }))}`;
    expect(parse(text).lockfile).toMatchObject({ status: 'read', kept: 1 });
  });

  it('never throws, whatever the input', () => {
    for (const text of ['', '\0', '{', '{"packages":', '{"packages":{"":1}}', '\ufeff', 'null']) {
      expect(() => parse(text)).not.toThrow();
    }
  });
});

describe('hostile lockfiles', () => {
  it('copies no key of the file into a plain object', () => {
    const text = `{"lockfileVersion":3,"packages":{
      "":{"dependencies":{"__proto__":"1","constructor":"1","a":"1"}},
      "__proto__":{"version":"1.0.0","resolved":"${registry('x')}"},
      "node_modules/__proto__":{"version":"1.0.0","resolved":"${registry('__proto__')}"},
      "node_modules/constructor":{"version":"1.0.0","resolved":"${registry('constructor')}"},
      "node_modules/toString":{"version":"1.0.0","resolved":"${registry('toString')}"},
      "node_modules/a":{"version":"1.0.0","resolved":"${registry('a')}","__proto__":{"dev":true,"link":true}}
    }}`;
    const result = parse(text);
    expect(result.packages).toEqual([
      { name: 'a', version: '1.0.0', direct: true, scope: 'prod' },
      { name: 'constructor', version: '1.0.0', direct: true, scope: 'prod' },
      { name: 'toString', version: '1.0.0', direct: false, scope: 'prod' },
    ]);
    // `__proto__` starts with an underscore, which no package name may; outside node_modules it is a link.
    expect(result.lockfile.notKept).toEqual(counted({ invalid: 1, link: 1 }));
    expect(({} as Record<string, unknown>).dev).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, 'link')).toBe(false);
  });

  it('does not look at an address longer than any real one', () => {
    const result = parse(
      v3({
        'node_modules/a': {
          version: '1.0.0',
          resolved: `${REGISTRY}/a/-/a-1.0.0.tgz?${'x'.repeat(5000)}`,
        },
      }),
    );
    expect(result.lockfile.notKept).toEqual(counted({ unknown: 1 }));
  });

  it('parses a lockfile of 64 000 packages, about 32 MiB, within seconds', () => {
    const padding = 'x'.repeat(380);
    const entries: string[] = [];
    for (let i = 0; i < 64_000; i += 1) {
      entries.push(
        `"node_modules/p${i}":{"version":"1.0.${i}","resolved":"${REGISTRY}/p${i}/-/p${i}-1.0.${i}.tgz",` +
          `"integrity":"sha512-${padding}","license":"MIT","dependencies":{"q":"^1"}}`,
      );
    }
    const text = `{"name":"big","lockfileVersion":3,"requires":true,"packages":{"":{"name":"big"},${entries.join(',')}}}`;
    expect(text.length).toBeGreaterThan(31 * 1024 * 1024);
    const started = Date.now();
    const result = parse(text, {}, { maxPackages: 100_000 });
    const elapsed = Date.now() - started;
    expect(result.lockfile).toMatchObject({ status: 'read', kept: 64_000 });
    // Well under a second on a developer machine; the budget leaves room for a loaded CI runner.
    expect(elapsed).toBeLessThan(10_000);

    const againStarted = Date.now();
    expect(parse(text).lockfile.status).toBe('too-many-packages');
    expect(Date.now() - againStarted).toBeLessThan(10_000);
  }, 60_000);

  it('reads a wide and deep version 1 tree in time linear to its size', () => {
    const leaf = (i: number) =>
      `"q${i}":{"version":"1.0.0","resolved":"${REGISTRY}/q${i}/-/q${i}-1.0.0.tgz"}`;
    const leaves = Array.from({ length: 40 }, (_, i) => leaf(i)).join(',');
    const branches: string[] = [];
    for (let i = 0; i < 5_000; i += 1) {
      branches.push(
        `"p${i}":{"version":"1.0.0","resolved":"${REGISTRY}/p${i}/-/p${i}-1.0.0.tgz","dependencies":{${leaves}}}`,
      );
    }
    const text = `{"lockfileVersion":1,"dependencies":{${branches.join(',')}}}`;
    const started = Date.now();
    const result = parse(text);
    expect(result.lockfile).toMatchObject({ status: 'read', kept: 5_040 });
    expect(Date.now() - started).toBeLessThan(10_000);
  }, 60_000);
});

describe('exclude patterns', () => {
  it('match a whole name, with * for any run of characters, without regard to case', () => {
    const matches = (pattern: string, name: string) => excludeMatcher([pattern])(name);
    expect(matches('@acme/*', '@acme/billing')).toBe(true);
    expect(matches('@acme/*', '@ACME/Billing')).toBe(true);
    expect(matches('@ACME/*', '@acme/billing')).toBe(true);
    expect(matches('@acme/*', '@acme-other/billing')).toBe(false);
    expect(matches('@acme/*', 'acme')).toBe(false);
    expect(matches('acme-internal', 'acme-internal')).toBe(true);
    expect(matches('acme-internal', 'acme-internal-2')).toBe(false);
    expect(matches('acme-internal', 'my-acme-internal')).toBe(false);
    expect(matches('*-internal', 'acme-internal')).toBe(true);
    expect(matches('acme-*-tool', 'acme-billing-tool')).toBe(true);
    expect(matches('acme-*-tool', 'acme-tool')).toBe(false);
    expect(matches('a*b*c', 'abc')).toBe(true);
    expect(matches('a*b*c', 'a-b-c')).toBe(true);
    expect(matches('a*b*c', 'acb')).toBe(false);
    expect(matches('ab*b', 'ab')).toBe(false);
    expect(matches('*', 'anything')).toBe(true);
    expect(matches('**', '')).toBe(true);
  });

  it('take every character but * as itself, so no pattern is an expression', () => {
    const matches = (pattern: string, name: string) => excludeMatcher([pattern])(name);
    expect(matches('a.b', 'a.b')).toBe(true);
    expect(matches('a.b', 'axb')).toBe(false);
    expect(matches('a+', 'aaa')).toBe(false);
    expect(matches('(a|b)', 'a')).toBe(false);
    expect(matches('[ab]', 'a')).toBe(false);
    expect(matches('a?', 'ab')).toBe(false);
    expect(matches('^a$', 'a')).toBe(false);
    expect(matches('', 'a')).toBe(false);
    expect(excludeMatcher([])('a')).toBe(false);
    expect(excludeMatcher(['x', 'b*', 'y'])('baip')).toBe(true);
  });

  it('cannot be made slow by a pattern of many stars', () => {
    const pattern = `${'*a'.repeat(100)}*b`;
    const name = 'a'.repeat(214);
    const matcher = excludeMatcher(Array.from({ length: 100 }, () => pattern));
    const started = Date.now();
    for (let i = 0; i < 2_000; i += 1) expect(matcher(name)).toBe(false);
    expect(Date.now() - started).toBeLessThan(5_000);
  }, 30_000);

  it('have a shape the command line can check: names and scopes with *, at most 214 characters', () => {
    for (const pattern of ['@acme/*', 'acme-*', '*', 'a.b_c~d', 'A-Z']) {
      expect(pattern).toMatch(DEPENDENCY_EXCLUDE_PATTERN);
    }
    for (const pattern of ['', 'has space', 'a,b', 'a|b', '(a)', 'a\\b', 'a'.repeat(215)]) {
      expect(pattern).not.toMatch(DEPENDENCY_EXCLUDE_PATTERN);
    }
  });
});
