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
