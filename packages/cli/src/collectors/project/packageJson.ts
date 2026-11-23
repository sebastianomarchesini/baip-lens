import {
  NON_REGISTRY_RANGE,
  PACKAGE_NAME_PATTERN,
  RANGE_PATTERN,
  type RawDependency,
  type RawPackageJson,
} from '../../model/raw.js';
import { isPlainObject, parseJson } from './read.js';

const MAX_DEPENDENCIES = 500;

/** The sections of a manifest whose keys are the packages it asks for itself. */
const DEPENDENCY_SECTIONS = [
  'dependencies',
  'devDependencies',
  'optionalDependencies',
  'peerDependencies',
] as const;

export interface PackageJsonResult {
  packageJson: RawPackageJson;
  /** The `cds` section, merged by cdsConfig.ts; nothing else of the file is kept. */
  cds: unknown;
  /**
   * Every name the manifest lists as a dependency of any kind, for telling
   * the direct packages of a lockfile from the transitive ones. Used while
   * the lockfiles are read and never stored: a name is kept only with the
   * lockfile entry it matches.
   */
  directNames: ReadonlySet<string>;
}

/**
 * The names a manifest lists under `dependencies`, `devDependencies`,
 * `optionalDependencies` and `peerDependencies`. The manifest is the root
 * `package.json`, or the root entry of a lockfile, which has the same shape.
 */
export function directNamesOf(manifest: unknown): Set<string> {
  const names = new Set<string>();
  if (!isPlainObject(manifest)) return names;
  for (const section of DEPENDENCY_SECTIONS) {
    const listed = manifest[section];
    if (!isPlainObject(listed)) continue;
    for (const name of Object.keys(listed)) names.add(name);
  }
  return names;
}

/** A registry range as written; a git URL, file path or alias becomes the placeholder. */
export function rangeOf(value: unknown): string {
  return typeof value === 'string' && RANGE_PATTERN.test(value) ? value : NON_REGISTRY_RANGE;
}

function dependenciesOf(value: unknown): RawDependency[] {
  if (!isPlainObject(value)) return [];
  return Object.entries(value)
    .filter(([name]) => PACKAGE_NAME_PATTERN.test(name))
    .slice(0, MAX_DEPENDENCIES)
    .map(([name, range]) => ({ name, range: rangeOf(range) }));
}

export function emptyPackageJson(): RawPackageJson {
  return { present: false, name: null, dependencies: [], devDependencies: [], nodeEngine: null };
}

/** Reads the allow-listed facts of a package.json; null when it is not a JSON object. */
export function parsePackageJson(text: string): PackageJsonResult | null {
  const json = parseJson(text);
  if (!isPlainObject(json)) return null;
  const engines = isPlainObject(json.engines) ? json.engines : {};
  return {
    packageJson: {
      present: true,
      name:
        typeof json.name === 'string' && PACKAGE_NAME_PATTERN.test(json.name) ? json.name : null,
      dependencies: dependenciesOf(json.dependencies),
      devDependencies: dependenciesOf(json.devDependencies),
      nodeEngine: engines.node === undefined ? null : rangeOf(engines.node),
    },
    cds: json.cds,
    directNames: directNamesOf(json),
  };
}
