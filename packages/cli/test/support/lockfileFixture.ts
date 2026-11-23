/**
 * npm lockfiles for the tests, built in memory and written at test time: no
 * lockfile is committed, and every package name is invented (`baip-fixture-…`),
 * so nothing here names a real package or a real vulnerable version. The
 * planted names and fields (`poison-lock-…`, `POISON_lock_…`) are listed in
 * `POISON` (test/support/project.ts): none of them may reach a snapshot, a
 * report or the terminal.
 */

export const PUBLIC_REGISTRY = 'https://registry.npmjs.org';

/** What npm records for a package it resolved from the public registry. */
export interface RegistryEntryOptions {
  dev?: boolean;
  optional?: boolean;
  devOptional?: boolean;
  /** The real package name of an alias. */
  name?: string;
  /** The registry's deprecation message, which npm copies into the lockfile. */
  deprecated?: string;
}

/** `node_modules/<name>` as a version 2 or 3 lockfile holds it, resolved from the public npm registry. */
export function registryEntry(
  name: string,
  version: string,
  options: RegistryEntryOptions = {},
): Record<string, unknown> {
  const tarball = name.slice(name.lastIndexOf('/') + 1);
  return {
    ...(options.name === undefined ? {} : { name: options.name }),
    version,
    resolved: `${PUBLIC_REGISTRY}/${name}/-/${tarball}-${version}.tgz`,
    integrity: 'sha512-POISON_lock_integrity',
    license: 'POISON_lock_license',
    ...(options.deprecated === undefined ? {} : { deprecated: options.deprecated }),
    ...(options.dev ? { dev: true } : {}),
    ...(options.optional ? { optional: true } : {}),
    ...(options.devOptional ? { devOptional: true } : {}),
  };
}

export interface RootManifest {
  name: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

/** A `lockfileVersion` 3 lockfile as text: the root entry, then one entry per install location. */
export function lockfileV3(root: RootManifest, packages: Record<string, unknown>): string {
  const lockfile = {
    name: root.name,
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages: { '': { version: '1.0.0', ...root }, ...packages },
  };
  return `${JSON.stringify(lockfile, null, 2)}\n`;
}

/**
 * The packages of the acme-incidents lockfile that come from the public npm
 * registry, as the project record keeps them: sorted by name, then version.
 * Later slices script answers about some of them (a vulnerable version, a
 * deprecated one); here they are only read.
 */
export const ACME_PUBLIC_PACKAGES = [
  { name: '@baip-fixture/odata', version: '3.1.0', direct: true, scope: 'prod' },
  { name: 'baip-fixture-legacy-http', version: '1.9.3', direct: true, scope: 'prod' },
  { name: 'baip-fixture-merge', version: '3.10.1', direct: false, scope: 'prod' },
  { name: 'baip-fixture-merge', version: '4.17.20', direct: false, scope: 'prod' },
  { name: 'baip-fixture-mkdir', version: '0.5.1', direct: false, scope: 'dev' },
  { name: 'baip-fixture-queue', version: '5.0.2', direct: true, scope: 'prod' },
  { name: 'baip-fixture-server', version: '2.4.1', direct: true, scope: 'prod' },
  { name: 'baip-fixture-test-kit', version: '7.0.0', direct: true, scope: 'dev' },
  { name: 'baip-fixture-watcher', version: '2.3.3', direct: true, scope: 'optional' },
] as const;

/** What the acme-incidents lockfile holds besides the public packages, per reason it is not kept. */
export const ACME_NOT_KEPT = {
  otherRegistry: 1,
  git: 1,
  file: 1,
  link: 2,
  bundled: 1,
  unknown: 1,
  excluded: 0,
  invalid: 1,
} as const;

/**
 * The lockfile of the acme-incidents fixture: public packages (direct and
 * transitive, two versions of one package, an alias, a dev and an optional
 * one), and one entry of every kind that is counted and never named.
 */
export function acmeLockfile(): string {
  return lockfileV3(
    {
      name: 'acme-incidents',
      dependencies: {
        '@baip-fixture/odata': '^3.1.0',
        '@poison-scope/private': '^1.0.0',
        'baip-fixture-alias': 'npm:baip-fixture-queue@^5.0.0',
        'baip-fixture-legacy-http': '^1.9.0',
        'baip-fixture-server': '^2.4.0',
        'poison-lock-git': 'git+ssh://git@github.com/acme/POISON_lock_repo.git',
        'poison-lock-link': 'file:../poison-lock-folder',
        'poison-lock-tarball': 'file:vendor/poison-lock-tarball-1.0.0.tgz',
      },
      devDependencies: { 'baip-fixture-test-kit': '^7.0.0' },
      optionalDependencies: { 'baip-fixture-watcher': '^2.3.0' },
    },
    {
      // A linked folder: the link, and the folder it points at.
      '../poison-lock-folder': { version: '0.1.0' },
      'node_modules/@baip-fixture/odata': registryEntry('@baip-fixture/odata', '3.1.0'),
      // Another registry, with a token in the address.
      'node_modules/@poison-scope/private': {
        version: '1.0.0',
        resolved:
          'https://ci:POISON_lock_token@poison-internal.example.com/npm/@poison-scope/private/-/private-1.0.0.tgz',
        integrity: 'sha512-POISON_lock_integrity',
      },
      // An alias: installed under one name, the real package under `name`.
      'node_modules/baip-fixture-alias': registryEntry('baip-fixture-queue', '5.0.2', {
        name: 'baip-fixture-queue',
      }),
      'node_modules/baip-fixture-legacy-http': registryEntry('baip-fixture-legacy-http', '1.9.3', {
        deprecated: 'POISON_lock_deprecated: this package is no longer supported',
      }),
      'node_modules/baip-fixture-merge': registryEntry('baip-fixture-merge', '4.17.20'),
      'node_modules/baip-fixture-mkdir': registryEntry('baip-fixture-mkdir', '0.5.1', {
        dev: true,
      }),
      'node_modules/baip-fixture-server': registryEntry('baip-fixture-server', '2.4.1'),
      // A second version of one package, installed below the package that needs it.
      'node_modules/baip-fixture-server/node_modules/baip-fixture-merge': registryEntry(
        'baip-fixture-merge',
        '3.10.1',
      ),
      // Shipped inside the tarball of another package.
      'node_modules/baip-fixture-server/node_modules/poison-lock-bundled': {
        version: '1.0.0',
        inBundle: true,
      },
      'node_modules/baip-fixture-test-kit': registryEntry('baip-fixture-test-kit', '7.0.0', {
        dev: true,
      }),
      'node_modules/baip-fixture-watcher': registryEntry('baip-fixture-watcher', '2.3.3', {
        optional: true,
      }),
      'node_modules/poison-lock-git': {
        version: '1.4.0',
        resolved: 'git+ssh://git@github.com/acme/POISON_lock_repo.git#semver:^1.4.0',
      },
      // From the public registry, but with a version npm would not write.
      'node_modules/poison-lock-invalid': {
        version: '1.0.0 POISON_lock_version',
        resolved: `${PUBLIC_REGISTRY}/poison-lock-invalid/-/poison-lock-invalid-1.0.0.tgz`,
      },
      'node_modules/poison-lock-link': { resolved: '../poison-lock-folder', link: true },
      'node_modules/poison-lock-tarball': {
        version: '1.0.0',
        resolved: 'file:vendor/poison-lock-tarball-1.0.0.tgz',
      },
      // No `resolved` at all: where it came from is not known.
      'node_modules/poison-lock-unresolved': { version: '2.0.0' },
    },
  );
}

/** The packages of the clean-cap lockfile: every one from the public npm registry. */
export const CLEAN_PUBLIC_PACKAGES = [
  { name: '@baip-fixture/odata', version: '3.2.0', direct: true, scope: 'prod' },
  { name: 'baip-fixture-merge', version: '4.17.21', direct: false, scope: 'prod' },
  { name: 'baip-fixture-server', version: '2.5.0', direct: true, scope: 'prod' },
  { name: 'baip-fixture-test-kit', version: '7.1.0', direct: true, scope: 'dev' },
] as const;

/** The lockfile of the clean-cap fixture: public packages only, so nothing is left unchecked. */
export function cleanLockfile(): string {
  return lockfileV3(
    {
      name: 'clean-cap',
      dependencies: { '@baip-fixture/odata': '^3.2.0', 'baip-fixture-server': '^2.5.0' },
      devDependencies: { 'baip-fixture-test-kit': '^7.1.0' },
    },
    {
      'node_modules/@baip-fixture/odata': registryEntry('@baip-fixture/odata', '3.2.0'),
      'node_modules/baip-fixture-merge': registryEntry('baip-fixture-merge', '4.17.21'),
      'node_modules/baip-fixture-server': registryEntry('baip-fixture-server', '2.5.0'),
      'node_modules/baip-fixture-test-kit': registryEntry('baip-fixture-test-kit', '7.1.0', {
        dev: true,
      }),
    },
  );
}
