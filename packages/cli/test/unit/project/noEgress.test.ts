import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/**
 * The project scan reads files and nothing else: no child process, no
 * network, no worker, no dynamic import that could load either. A static
 * guard over the source files, so a future change cannot add one quietly.
 *
 * The npm dependency checks look packages up on the network, but not from
 * here: the file-reading code, the rules and `src/project.ts` stay free of
 * any request. The lookup is handed to the project scan as a function by its
 * caller, so none of these files may import the HTTP client, a client built
 * on it, or the module that does the lookup.
 */
const SRC = fileURLToPath(new URL('../../../src/', import.meta.url));
const GUARDED = ['collectors/project', 'analyzers/project', 'analyzers/dependencies', 'project.ts'];

const FORBIDDEN_MODULES = [
  'node:child_process',
  'child_process',
  'node:http',
  'node:https',
  'node:net',
  'node:dns',
  'node:worker_threads',
];

/**
 * Modules of this repository that make requests, or that exist to make them
 * for the dependency checks, by the file name an import ends with. Some are
 * built by a later step; the guard names them so that they cannot be wired
 * in here once they exist.
 */
const FORBIDDEN_OWN_MODULES = [
  'httpClient',
  'cfClient',
  'logCacheClient',
  'auth',
  'osvClient',
  'npmRegistryClient',
  'osv',
  'deprecations',
  'dependencyCheck',
];

/** Every `.ts` file of an entry, sub-folders included. */
async function sourceFiles(entry: string): Promise<string[]> {
  const path = join(SRC, entry);
  if (entry.endsWith('.ts')) return [path];
  const names = await readdir(path, { recursive: true });
  return names.filter((name) => name.endsWith('.ts')).map((name) => join(path, name));
}

/** What a file imports, re-exports or requires: the module specifiers, as written. */
function importedModules(text: string): string[] {
  const specifiers: string[] = [];
  const patterns = [
    /\bfrom\s+['"]([^'"]+)['"]/g,
    /\bimport\s+['"]([^'"]+)['"]/g,
    /\brequire\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) specifiers.push(match[1] ?? '');
  }
  return specifiers;
}

/** The file name an import of this repository ends with, without its extension. */
function ownModuleName(specifier: string): string | null {
  if (!specifier.startsWith('.')) return null;
  return specifier.slice(specifier.lastIndexOf('/') + 1).replace(/\.[cm]?[jt]s$/, '');
}

function forbiddenImports(text: string): string[] {
  return importedModules(text).filter((specifier) => {
    const own = ownModuleName(specifier);
    return own !== null && FORBIDDEN_OWN_MODULES.includes(own);
  });
}

describe('project scan has no way out of the file system', () => {
  it('guards the collector, the analyzers and the command', async () => {
    const files = (await Promise.all(GUARDED.map(sourceFiles))).flat();
    expect(files.length).toBeGreaterThan(14);
    // The lockfile parser, the lockfile step and the dependency rules are among them: also the
    // rule that reads the answers of the lookup, and the two calculations it rests on.
    for (const guarded of [
      'collectors/project/lockfile.ts',
      'collectors/project/dependencies.ts',
      'analyzers/dependencies/index.ts',
      'analyzers/dependencies/lockfileMissing.ts',
      'analyzers/dependencies/notChecked.ts',
      'analyzers/dependencies/knownCve.ts',
      'analyzers/dependencies/cvss.ts',
      'analyzers/dependencies/semver.ts',
      'project.ts',
    ]) {
      expect(files, guarded).toContain(join(SRC, guarded));
    }
    for (const file of files) {
      const text = await readFile(file, 'utf8');
      for (const module of FORBIDDEN_MODULES) {
        expect(text, `${file} imports ${module}`).not.toMatch(
          new RegExp(`from\\s+['"]${module}['"]|require\\(['"]${module}['"]\\)`),
        );
      }
      expect(text, `${file} calls fetch`).not.toMatch(/\bfetch\(/);
      expect(text, `${file} uses a dynamic import`).not.toMatch(/\bimport\(/);
      expect(forbiddenImports(text), `${file} imports a module that makes requests`).toEqual([]);
    }
  });

  it('gets its network step from the command line alone: one module builds the lookup, one file imports it', async () => {
    const names = await readdir(SRC, { recursive: true });
    const sources = names
      .filter((name) => name.endsWith('.ts'))
      .map((name) => name.replaceAll('\\', '/'));
    // The modules that ask a public source about a package exist, outside the guarded files.
    const requesters = [
      'dependencyCheck.ts',
      'collectors/osv.ts',
      'http/osvClient.ts',
      'collectors/deprecations.ts',
      'http/npmRegistryClient.ts',
    ];
    for (const requester of requesters) expect(sources, requester).toContain(requester);
    const guarded = (await Promise.all(GUARDED.map(sourceFiles))).flat();
    for (const requester of requesters)
      expect(guarded, requester).not.toContain(join(SRC, requester));

    const importers = async (module: string): Promise<string[]> => {
      const found: string[] = [];
      for (const source of sources) {
        const imported = importedModules(await readFile(join(SRC, source), 'utf8'));
        if (imported.some((specifier) => ownModuleName(specifier) === module)) found.push(source);
      }
      return found.sort();
    };
    // Only `main.ts` builds a lookup; the scans are handed one and never make it themselves.
    expect(await importers('dependencyCheck')).toEqual(['main.ts']);
    expect(await importers('osv')).toEqual(['dependencyCheck.ts']);
    expect(await importers('osvClient')).toEqual(['collectors/osv.ts', 'dependencyCheck.ts']);
    // The same for the second source, the npm registry.
    expect(await importers('deprecations')).toEqual(['dependencyCheck.ts']);
    expect(await importers('npmRegistryClient')).toEqual([
      'collectors/deprecations.ts',
      'dependencyCheck.ts',
    ]);
    // What the two lookups share makes no request, and only they use it.
    expect(await importers('packageLookup')).toEqual([
      'collectors/deprecations.ts',
      'collectors/osv.ts',
    ]);
  });

  it('recognises an import of a module that makes requests, however it is written', () => {
    const cases = [
      "import { HttpClient } from '../../http/httpClient.js';",
      "import type { FetchLike } from './http/httpClient.js';",
      "import { OsvClient } from '../../http/osvClient.js';",
      "import { NpmRegistryClient } from '../../http/npmRegistryClient.js';",
      "import { collectAdvisories } from '../osv.js';",
      "import { collectDeprecations } from '../deprecations.js';",
      "import { createDependencyLookup } from './dependencyCheck.js';",
      "export { createDependencyLookup } from './dependencyCheck.js';",
      "import './dependencyCheck.js';",
      "const lookup = require('./dependencyCheck.js');",
      "import { CfClient } from './http/cfClient.js';",
      "import { resolveTokenProvider } from './http/auth.js';",
      "import { LogCacheClient } from '../../http/logCacheClient.ts';",
    ];
    for (const line of cases) expect(forbiddenImports(line), line).toHaveLength(1);
    // Errors and the model make no request, and a package from npm is not a module of this repository.
    const allowed = [
      "import { ConfigError } from '../../http/errors.js';",
      "import { analyze } from './analyzers/index.js';",
      "import { parseDocument } from 'yaml';",
      "import { z } from 'zod';",
      "import type { RawProject } from '../../model/raw.js';",
      "import { jsonShapeExcess } from '../../io/jsonShape.js';",
      "import { open } from 'node:fs/promises';",
    ];
    for (const line of allowed) expect(forbiddenImports(line), line).toEqual([]);
  });
});
