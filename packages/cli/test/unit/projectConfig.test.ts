import { describe, expect, it } from 'vitest';
import { type ProjectConfig, parseProjectConfig } from '../../src/config.js';
import { ConfigError } from '../../src/http/errors.js';

/* The options of `baip-lens project`, as commander hands them over. */

const BASE = { out: './reports', format: 'json', failOn: 'none', quiet: false };

const parse = (options: Record<string, unknown>): ProjectConfig =>
  parseProjectConfig({ ...BASE, ...options });

/** The message of the ConfigError the options are refused with. */
function refusal(options: Record<string, unknown>): string {
  try {
    parse(options);
  } catch (error) {
    if (error instanceof ConfigError) return error.message;
    throw error;
  }
  throw new Error('the options were accepted');
}

describe('project --cf options for a deployed project', () => {
  it('accepts --mta with --cf, trimmed, and keeps it out of a --path scan', () => {
    expect(parse({ cf: true, mta: ' acme.incidents ' })).toMatchObject({
      cf: true,
      mta: 'acme.incidents',
    });
    const local = parse({ path: '.' });
    expect(local.mta).toBeUndefined();
    expect(local.mtaNamespace).toBeUndefined();
  });

  it('refuses --mta together with --app', () => {
    expect(refusal({ cf: true, app: 'incidents-srv', mta: 'acme' })).toBe(
      'Use either --app (one app) or --mta (every app of a project), not both.',
    );
  });

  it('refuses --mta-namespace without --mta', () => {
    expect(refusal({ cf: true, mtaNamespace: 'blue' })).toBe(
      '--mta-namespace works only together with --mta',
    );
    expect(refusal({ cf: true, app: 'incidents-srv', mtaNamespace: '' })).toBe(
      '--mta-namespace works only together with --mta',
    );
  });

  it('refuses both without --cf, with the flags spelled as they are typed', () => {
    const message = refusal({ path: '.', mta: 'acme', mtaNamespace: 'blue' });
    expect(message.split('\n')).toEqual([
      '--mta works only together with --cf',
      '--mta-namespace works only together with --cf',
    ]);
    expect(message).not.toContain('mtaNamespace');
    expect(refusal({ path: '.', mtaNamespace: 'blue' }).split('\n')).toEqual([
      '--mta-namespace works only together with --cf',
      '--mta-namespace works only together with --mta',
    ]);
  });

  it.each(['acme incidents', 'acme/incidents', 'acme;rm', 'a'.repeat(129), '', '   ', 'acmé'])(
    'refuses the project id %j',
    (mta) => {
      expect(refusal({ cf: true, mta })).toBe(
        '--mta needs a project id (letters, digits, ".", "_" and "-")',
      );
    },
  );

  it('accepts a namespace, and the empty string for the deployment without one', () => {
    expect(parse({ cf: true, mta: 'acme', mtaNamespace: 'blue' }).mtaNamespace).toBe('blue');
    expect(parse({ cf: true, mta: 'acme', mtaNamespace: '' }).mtaNamespace).toBe('');
    expect(parse({ cf: true, mta: 'acme' }).mtaNamespace).toBeUndefined();
  });

  it.each(['blue green', ' blue', 'n'.repeat(37), 'blue/1'])(
    'refuses the namespace %j',
    (mtaNamespace) => {
      expect(refusal({ cf: true, mta: 'acme', mtaNamespace })).toBe(
        '--mta-namespace needs a namespace (at most 36 letters, digits, ".", "_" and "-"), or "" for the deployment without one',
      );
    },
  );

  it('still refuses the other --cf options without --cf', () => {
    expect(refusal({ path: '.', app: 'x', api: 'eu10', org: 'o', space: 's' }).split('\n')).toEqual(
      [
        '--app works only together with --cf',
        '--api works only together with --cf',
        '--org works only together with --cf',
        '--space works only together with --cf',
      ],
    );
  });
});

describe('project options for the dependency lookup', () => {
  const PATTERN_HELP =
    '--dependency-exclude needs package names or patterns such as @acme/*, separated by commas ' +
    '(letters, digits and "@", "/", ".", "_", "~", "-", "*"; at most 214 characters each)';

  it('looks packages up unless --no-dependency-check, for a folder and for deployed apps', () => {
    expect(parse({ path: '.' }).dependencyCheck).toBe(true);
    expect(parse({ cf: true }).dependencyCheck).toBe(true);
    // What commander hands over for the flag and for its absence.
    expect(parse({ path: '.', dependencyCheck: false }).dependencyCheck).toBe(false);
    expect(parse({ cf: true, dependencyCheck: false }).dependencyCheck).toBe(false);
    expect(parse({ path: '.', dependencyCheck: true }).dependencyCheck).toBe(true);
  });

  it('holds no package back unless --dependency-exclude names some', () => {
    expect(parse({ path: '.' }).dependencyExclude).toEqual([]);
    expect(parse({ cf: true }).dependencyExclude).toEqual([]);
  });

  it('splits --dependency-exclude on commas and trims each pattern, for both modes', () => {
    const list = ' @acme/* , acme-internal,*-private ,Acme.Tool_1~x ';
    const patterns = ['@acme/*', 'acme-internal', '*-private', 'Acme.Tool_1~x'];
    expect(parse({ path: '.', dependencyExclude: list }).dependencyExclude).toEqual(patterns);
    expect(parse({ cf: true, dependencyExclude: list }).dependencyExclude).toEqual(patterns);
    expect(parse({ path: '.', dependencyExclude: '*' }).dependencyExclude).toEqual(['*']);
  });

  it('works together with --no-dependency-check: the names are then not kept either', () => {
    expect(
      parse({ path: '.', dependencyCheck: false, dependencyExclude: '@acme/*' }),
    ).toMatchObject({ dependencyCheck: false, dependencyExclude: ['@acme/*'] });
  });

  it.each([
    ['an empty list', ''],
    ['blanks only', '   '],
    ['an empty item between two commas', '@acme/*,,acme-internal'],
    ['a comma at the end', '@acme/*,'],
    ['a comma at the start', ',@acme/*'],
    ['a blank inside a pattern', '@acme/internal tool'],
    ['a pattern that is an address', 'https://npm.acme.example/@acme'],
    ['a regular expression', '@acme/(a|b)'],
    ['a character outside ASCII', '@acmé/*'],
    ['a pattern of 215 characters', 'a'.repeat(215)],
    ['a quote', '"@acme/*"'],
  ])('refuses %s, and does not repeat what was typed', (_name, dependencyExclude) => {
    const message = refusal({ path: '.', dependencyExclude });
    expect(message).toBe(PATTERN_HELP);
    expect(refusal({ cf: true, dependencyExclude })).toBe(PATTERN_HELP);
  });

  it('never repeats a pattern in the refusal: it may name a private scope', () => {
    const message = refusal({ path: '.', dependencyExclude: '@acme-private/billing tool' });
    expect(message).not.toContain('acme-private');
  });

  it('takes 100 patterns and refuses 101', () => {
    const patterns = Array.from({ length: 101 }, (_, i) => `@acme-${i}/*`);
    expect(
      parse({ path: '.', dependencyExclude: patterns.slice(0, 100).join(',') }).dependencyExclude,
    ).toHaveLength(100);
    expect(refusal({ path: '.', dependencyExclude: patterns.join(',') })).toBe(
      '--dependency-exclude takes at most 100 patterns',
    );
  });

  it('takes a pattern of 214 characters, the longest a package name can be', () => {
    const longest = `@acme/${'a'.repeat(208)}`;
    expect(parse({ path: '.', dependencyExclude: longest }).dependencyExclude).toEqual([longest]);
  });
});
