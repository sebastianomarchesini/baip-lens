import { describe, expect, it } from 'vitest';
import {
  type SemVer,
  compareSemVer,
  parseSemVer,
} from '../../../src/analyzers/dependencies/semver.js';

function parsed(text: string): SemVer {
  const version = parseSemVer(text);
  if (version === null) throw new Error(`not a version: ${text}`);
  return version;
}

/** -1, 0 or 1. */
function order(a: string, b: string): number {
  return Math.sign(compareSemVer(parsed(a), parsed(b)));
}

describe('parseSemVer', () => {
  it('takes a release version apart', () => {
    expect(parseSemVer('4.17.21')).toEqual({ release: ['4', '17', '21'], prerelease: [] });
    expect(parseSemVer('0.0.0')).toEqual({ release: ['0', '0', '0'], prerelease: [] });
  });

  it('keeps the prerelease identifiers, hyphens included', () => {
    expect(parseSemVer('1.0.0-alpha.1')).toEqual({
      release: ['1', '0', '0'],
      prerelease: ['alpha', '1'],
    });
    expect(parseSemVer('1.0.0-x-y-z.--')?.prerelease).toEqual(['x-y-z', '--']);
    expect(parseSemVer('8.0.0-alpha.0')?.prerelease).toEqual(['alpha', '0']);
  });

  it('drops build metadata, with or without a prerelease before it', () => {
    expect(parseSemVer('1.0.0+build.5')).toEqual(parseSemVer('1.0.0'));
    expect(parseSemVer('1.0.0-rc.1+sha-5114f85')).toEqual(parseSemVer('1.0.0-rc.1'));
    // A hyphen after the plus sign belongs to the build metadata.
    expect(parseSemVer('1.0.0+exp-sha')?.prerelease).toEqual([]);
  });

  it('reads numbers without their leading zeros, and of any length', () => {
    expect(parseSemVer('01.002.0003')?.release).toEqual(['1', '2', '3']);
    expect(parseSemVer('00.0.000')?.release).toEqual(['0', '0', '0']);
    const long = '9'.repeat(40);
    expect(parseSemVer(`${long}.0.0`)?.release[0]).toBe(long);
  });

  it.each([
    ['an empty text', ''],
    ['two numbers', '1.2'],
    ['four numbers', '1.2.3.4'],
    ['a `v` before it', 'v1.2.3'],
    ['a range', '^1.2.3'],
    ['a wildcard', '1.2.x'],
    ['a negative number', '1.-2.3'],
    ['a blank', '1.2.3 '],
    ['an empty prerelease', '1.2.3-'],
    ['an empty prerelease identifier', '1.2.3-a..b'],
    ['a prerelease that ends in a dot', '1.2.3-rc.'],
    ['empty build metadata', '1.2.3+'],
    ['two plus signs', '1.2.3+a+b'],
    ['a character no version has', '1.2.3-rc_1'],
    ['a tag', 'latest'],
    ['an alias', 'npm:baip-fixture-queue@5.0.2'],
  ])('gives null for %s', (_name, text) => {
    expect(parseSemVer(text)).toBeNull();
  });
});

describe('compareSemVer', () => {
  it('compares major, minor and patch as numbers, in that order', () => {
    expect(order('1.0.0', '2.0.0')).toBe(-1);
    expect(order('2.0.0', '2.1.0')).toBe(-1);
    expect(order('2.1.0', '2.1.1')).toBe(-1);
    expect(order('2.1.1', '2.1.1')).toBe(0);
    // As numbers, not as text.
    expect(order('1.9.0', '1.10.0')).toBe(-1);
    expect(order('4.17.9', '4.17.21')).toBe(-1);
    expect(order('10.0.0', '9.99.99')).toBe(1);
    expect(order('1.2.3', '1.02.3')).toBe(0);
  });

  it('compares numbers too large for arithmetic digit by digit', () => {
    const big = '9007199254740993';
    expect(order(`${big}.0.0`, '9007199254740992.0.0')).toBe(1);
    expect(order(`1.0.0-${big}`, '1.0.0-9007199254740992')).toBe(1);
    expect(order(`${'1'.repeat(30)}.0.0`, `${'9'.repeat(29)}.0.0`)).toBe(1);
  });

  it('puts a prerelease before its release, and after the release before it', () => {
    expect(order('1.0.0-alpha', '1.0.0')).toBe(-1);
    expect(order('1.0.0', '1.0.0-rc.1')).toBe(1);
    expect(order('1.0.0-rc.1', '0.9.9')).toBe(1);
    expect(order('4.17.21-rc.1', '4.17.21')).toBe(-1);
    expect(order('4.17.21-rc.1', '4.17.20')).toBe(1);
  });

  it('orders prereleases as the specification lists them', () => {
    // https://semver.org/#spec-item-11
    const ascending = [
      '1.0.0-alpha',
      '1.0.0-alpha.1',
      '1.0.0-alpha.beta',
      '1.0.0-beta',
      '1.0.0-beta.2',
      '1.0.0-beta.11',
      '1.0.0-rc.1',
      '1.0.0',
    ];
    for (const [at, lower] of ascending.entries()) {
      for (const higher of ascending.slice(at + 1)) {
        expect(order(lower, higher), `${lower} < ${higher}`).toBe(-1);
        expect(order(higher, lower), `${higher} > ${lower}`).toBe(1);
      }
      expect(order(lower, lower)).toBe(0);
    }
  });

  it('compares numeric identifiers as numbers and the others in ASCII order', () => {
    expect(order('1.0.0-2', '1.0.0-11')).toBe(-1);
    expect(order('1.0.0-rc.9', '1.0.0-rc.10')).toBe(-1);
    expect(order('1.0.0-007', '1.0.0-7')).toBe(0);
    // A number comes before any identifier with a letter or a hyphen.
    expect(order('1.0.0-999', '1.0.0-a')).toBe(-1);
    expect(order('1.0.0-1', '1.0.0--')).toBe(-1);
    // Upper case before lower case, digits before letters: ASCII.
    expect(order('1.0.0-Beta', '1.0.0-alpha')).toBe(-1);
    expect(order('1.0.0-alpha1', '1.0.0-alphaa')).toBe(-1);
    expect(order('1.0.0-rc-1', '1.0.0-rc.1')).toBe(1);
  });

  it('puts the prerelease with more identifiers after one that is its beginning', () => {
    expect(order('1.0.0-alpha', '1.0.0-alpha.0')).toBe(-1);
    expect(order('1.0.0-alpha.1.2', '1.0.0-alpha.1')).toBe(1);
  });

  it('ignores build metadata', () => {
    expect(order('1.0.0+a', '1.0.0+b')).toBe(0);
    expect(order('1.0.0+zzz', '1.0.0')).toBe(0);
    expect(order('1.0.0-rc.1+1', '1.0.0-rc.1+2')).toBe(0);
    expect(order('1.0.0+a', '1.0.1')).toBe(-1);
    expect(order('1.0.0-rc.1+build', '1.0.0+build')).toBe(-1);
  });

  it('is a total order: sorting gives the same list whatever the order before', () => {
    const versions = [
      '0.5.1',
      '1.0.0-alpha',
      '1.0.0-alpha.1',
      '1.0.0-beta.2',
      '1.0.0-beta.11',
      '1.0.0',
      '1.2.3',
      '1.10.0',
      '2.0.0-0',
      '2.0.0',
      '8.0.0-alpha.0',
      '8.0.0-alpha.4',
      '10.0.0',
    ];
    const sort = (list: string[]): string[] =>
      [...list].sort((a, b) => compareSemVer(parsed(a), parsed(b)));
    expect(sort([...versions].reverse())).toEqual(versions);
    expect(sort([...versions.slice(5), ...versions.slice(0, 5)])).toEqual(versions);
    for (const a of versions) {
      // Antisymmetric: what comes before one way comes after the other way.
      for (const b of versions) expect(order(a, b) + order(b, a), `${a} ${b}`).toBe(0);
    }
  });
});
