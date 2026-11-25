/*
 * Which of two versions is the later one, by the precedence rules of
 * Semantic Versioning 2.0.0 (https://semver.org/#spec-item-11). The rule
 * `DEP_KNOWN_CVE` needs it to say which fixed version of an advisory lies
 * above the installed one. Exact versions only: no ranges, no `v` prefix.
 */

/** A version taken apart. Numbers stay digit strings: a version may hold more digits than a number keeps. */
export interface SemVer {
  /** Major, minor and patch, without leading zeros. */
  release: readonly [string, string, string];
  /** The identifiers after `-`; empty for a release version. */
  prerelease: readonly string[];
}

const IDENTIFIERS = /^[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*$/;
const NUMERIC = /^\d+$/;
const CORE = /^(\d+)\.(\d+)\.(\d+)$/;

function withoutLeadingZeros(digits: string): string {
  return digits.replace(/^0+(?=\d)/, '');
}

/**
 * Takes a version apart, or returns null when the text is not one: three
 * numbers, then `-` and prerelease identifiers, then `+` and build metadata,
 * each part optional and never empty. Build metadata is checked and dropped:
 * it does not take part in precedence.
 */
export function parseSemVer(text: string): SemVer | null {
  const plus = text.indexOf('+');
  const build = plus === -1 ? undefined : text.slice(plus + 1);
  if (build !== undefined && !IDENTIFIERS.test(build)) return null;
  const versionAndPrerelease = plus === -1 ? text : text.slice(0, plus);
  const dash = versionAndPrerelease.indexOf('-');
  const prerelease = dash === -1 ? undefined : versionAndPrerelease.slice(dash + 1);
  if (prerelease !== undefined && !IDENTIFIERS.test(prerelease)) return null;
  const core = CORE.exec(dash === -1 ? versionAndPrerelease : versionAndPrerelease.slice(0, dash));
  if (core === null) return null;
  const [, major = '', minor = '', patch = ''] = core;
  return {
    release: [withoutLeadingZeros(major), withoutLeadingZeros(minor), withoutLeadingZeros(patch)],
    prerelease: prerelease === undefined ? [] : prerelease.split('.'),
  };
}

function compareText(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/** Two numbers written in digits, without leading zeros: the longer is the larger. */
function compareNumbers(a: string, b: string): number {
  return a.length - b.length || compareText(a, b);
}

/**
 * Two prerelease identifiers: numbers by value, and before any identifier
 * with a letter or a hyphen; those in ASCII order.
 */
function compareIdentifiers(a: string, b: string): number {
  const [aNumeric, bNumeric] = [NUMERIC.test(a), NUMERIC.test(b)];
  if (aNumeric && bNumeric) {
    return compareNumbers(withoutLeadingZeros(a), withoutLeadingZeros(b));
  }
  if (aNumeric !== bNumeric) return aNumeric ? -1 : 1;
  return compareText(a, b);
}

function comparePrerelease(a: readonly string[], b: readonly string[]): number {
  // A release version comes after every prerelease of it.
  if (a.length === 0 || b.length === 0) return (a.length === 0 ? 1 : 0) - (b.length === 0 ? 1 : 0);
  for (let at = 0; at < Math.min(a.length, b.length); at += 1) {
    const order = compareIdentifiers(a[at] ?? '', b[at] ?? '');
    if (order !== 0) return order;
  }
  // The same so far: the one with more identifiers is the later one.
  return a.length - b.length;
}

/** Negative when `a` comes before `b`, positive when after, 0 when they have the same precedence. */
export function compareSemVer(a: SemVer, b: SemVer): number {
  for (const part of [0, 1, 2] as const) {
    const order = compareNumbers(a.release[part], b.release[part]);
    if (order !== 0) return order;
  }
  return comparePrerelease(a.prerelease, b.prerelease);
}
