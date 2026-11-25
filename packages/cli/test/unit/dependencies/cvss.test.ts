import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { cvssV3BaseScore } from '../../../src/analyzers/dependencies/cvss.js';

/*
 * Vectors with the base score that is published for them: the worked
 * examples of the CVSS v3.1 specification (first.org/cvss/v3.1/examples) and
 * vectors the NVD publishes for many entries. None of them names a
 * vulnerability here: only the arithmetic is under test.
 */
const BASE = 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

/** [metrics, score], scope unchanged. */
const UNCHANGED: [string, number][] = [
  // Critical: 9.0 to 10.0.
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', 9.1],
  // High: 7.0 to 8.9.
  ['AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8],
  ['AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 8.8],
  ['AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 8.8],
  ['AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 8.1],
  ['AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 7.8],
  ['AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 7.8],
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5],
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5],
  ['AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N', 7.4],
  ['AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H', 7.4],
  ['AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', 7.2],
  // Medium: 4.0 to 6.9.
  ['AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 6.8],
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N', 6.5],
  ['AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N', 5.9],
  ['AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N', 5.5],
  ['AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 5.3],
  ['AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', 4.6],
  ['AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', 4.3],
  ['AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N', 4.3],
  ['AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L', 4.2],
  // Low: 0.1 to 3.9.
  ['AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N', 3.7],
  ['AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N', 3.3],
  ['AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N', 3.1],
  ['AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N', 2.7],
  ['AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N', 2.5],
  ['AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', 2.4],
];

/** [metrics, score], scope changed: another impact formula, other weights for PR, and the factor 1.08. */
const CHANGED: [string, number][] = [
  ['AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0],
  ['AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 9.9],
  ['AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H', 9.6],
  ['AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H', 9.3],
  ['AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H', 9.1],
  ['AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H', 9.0],
  ['AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H', 8.8],
  ['AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N', 8.6],
  ['AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N', 6.8],
  ['AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N', 6.4],
  ['AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
  ['AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N', 5.8],
  ['AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N', 5.8],
  ['AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', 5.4],
  ['AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N', 4.8],
  ['AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:N/A:N', 3.8],
];

describe('cvssV3BaseScore', () => {
  it.each(UNCHANGED)('scores %s as %f (scope unchanged)', (metrics, score) => {
    expect(cvssV3BaseScore(`CVSS:3.1/${metrics}`)).toBe(score);
  });

  it.each(CHANGED)('scores %s as %f (scope changed)', (metrics, score) => {
    expect(cvssV3BaseScore(`CVSS:3.1/${metrics}`)).toBe(score);
  });

  it('covers every severity band at least twice, and the changed scope in three of them', () => {
    const band = (score: number): string =>
      score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
    const count = (rows: [string, number][], name: string): number =>
      rows.filter(([, score]) => band(score) === name).length;
    for (const name of ['critical', 'high', 'medium', 'low']) {
      expect(count([...UNCHANGED, ...CHANGED], name), name).toBeGreaterThanOrEqual(2);
    }
    expect(CHANGED.length).toBeGreaterThanOrEqual(5);
    for (const name of ['critical', 'high', 'medium']) {
      expect(count(CHANGED, name), name).toBeGreaterThanOrEqual(2);
    }
  });

  it('gives a v3.0 vector the score of the same v3.1 vector: the base formulas are the same', () => {
    for (const [metrics, score] of [...UNCHANGED, ...CHANGED]) {
      expect(cvssV3BaseScore(`CVSS:3.0/${metrics}`), metrics).toBe(score);
    }
  });

  it('scores 0.0 when nothing is affected, whatever the way in', () => {
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N')).toBe(0);
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:N')).toBe(0);
    expect(cvssV3BaseScore('CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N')).toBe(0);
  });

  it('never goes above 10.0', () => {
    // 1.08 x (6.05 + 3.89) is 10.7 before the limit.
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H')).toBe(10);
  });

  it('weighs the privileges required differently when the scope changes', () => {
    // PR:L is 0.62 with an unchanged scope and 0.68 with a changed one.
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N')).toBe(5.4);
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')).toBe(6.4);
    // PR:H is 0.27 and 0.5.
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H')).toBe(7.2);
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H')).toBe(9.1);
  });

  it('reads the metrics in any order', () => {
    expect(cvssV3BaseScore('CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N')).toBe(9.8);
    expect(cvssV3BaseScore('CVSS:3.1/S:C/AV:N/C:L/AC:L/I:L/PR:N/A:N/UI:R')).toBe(6.1);
  });

  it('leaves temporal and environmental metrics aside: they do not change the base score', () => {
    expect(cvssV3BaseScore(`CVSS:3.1/${BASE}/E:U/RL:O/RC:C`)).toBe(9.8);
    expect(cvssV3BaseScore(`CVSS:3.1/${BASE}/E:X/RL:X/RC:X`)).toBe(9.8);
    expect(
      cvssV3BaseScore(
        `CVSS:3.1/${BASE}/E:P/RL:T/RC:R/CR:H/IR:M/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:N/MA:N`,
      ),
    ).toBe(9.8);
  });

  it('always gives a number from 0.0 to 10.0 with one decimal, the same for both versions', () => {
    const values = {
      AV: ['N', 'A', 'L', 'P'],
      AC: ['L', 'H'],
      PR: ['N', 'L', 'H'],
      UI: ['N', 'R'],
      S: ['U', 'C'],
      C: ['H', 'L', 'N'],
      I: ['H', 'L', 'N'],
      A: ['H', 'L', 'N'],
    };
    let vectors = [''];
    for (const [name, options] of Object.entries(values)) {
      vectors = vectors.flatMap((vector) => options.map((value) => `${vector}/${name}:${value}`));
    }
    expect(vectors).toHaveLength(2592);
    const scores = new Set<number>();
    for (const metrics of vectors) {
      const score = cvssV3BaseScore(`CVSS:3.1${metrics}`);
      expect(score, metrics).not.toBeNull();
      expect(cvssV3BaseScore(`CVSS:3.0${metrics}`), metrics).toBe(score);
      scores.add(score ?? -1);
    }
    for (const score of scores) {
      expect(score).toBeGreaterThanOrEqual(0);
      expect(score).toBeLessThanOrEqual(10);
      // One decimal, exactly: 4.0 and not 4.000000000000001.
      expect(Number(score.toFixed(1))).toBe(score);
    }
    expect(scores.has(0)).toBe(true);
    expect(scores.has(10)).toBe(true);
  });

  /*
   * Every combination of the eight base metrics, for both versions, against
   * an independent implementation: the Python library `cvss` 3.6 (Red Hat
   * Product Security) computed the same 2,592 scores per version on
   * 2026-11-25, and the digests below are those of its list as well. The
   * list is `<vector>=<score with one decimal>`, one vector per line, the
   * metrics in the order of the specification and each with its values in
   * the order given here. A weight or a rounding that changes for one vector
   * only changes the digest.
   */
  it.each([
    ['3.0', '05b8fc759c884b19aca554d540aeb815633aeaf8f8c925b1b3ad0189fe52f9f5'],
    ['3.1', 'acec74d9a4420dc631180a006db694cbc71b740a596bf4ddbb19e2e87fb4def4'],
  ])(
    'gives every base vector of CVSS %s the score an independent implementation gives',
    (version, digest) => {
      const metrics: [string, string[]][] = [
        ['AV', ['N', 'A', 'L', 'P']],
        ['AC', ['L', 'H']],
        ['PR', ['N', 'L', 'H']],
        ['UI', ['N', 'R']],
        ['S', ['U', 'C']],
        ['C', ['H', 'L', 'N']],
        ['I', ['H', 'L', 'N']],
        ['A', ['H', 'L', 'N']],
      ];
      let vectors = [`CVSS:${version}`];
      for (const [metric, values] of metrics) {
        vectors = vectors.flatMap((head) => values.map((value) => `${head}/${metric}:${value}`));
      }
      expect(vectors).toHaveLength(2592);
      expect(vectors[0]).toBe(`CVSS:${version}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`);
      const lines = vectors.map(
        (vector) => `${vector}=${(cvssV3BaseScore(vector) ?? NaN).toFixed(1)}`,
      );
      expect(createHash('sha256').update(lines.join('\n')).digest('hex')).toBe(digest);
    },
  );

  describe('gives null for a text that is not a CVSS v3 vector', () => {
    it.each([
      ['an empty text', ''],
      ['the prefix alone', 'CVSS:3.1'],
      ['the prefix and a slash', 'CVSS:3.1/'],
      ['no prefix', BASE],
      ['version 2', 'AV:N/AC:L/Au:N/C:P/I:P/A:P'],
      ['version 2 with a prefix', `CVSS:2.0/${BASE}`],
      ['version 4', 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
      ['a version 3 that does not exist', `CVSS:3.2/${BASE}`],
      ['a prefix in lower case', `cvss:3.1/${BASE}`],
      ['text before the prefix', `xCVSS:3.1/${BASE}`],
      ['text after the version', `CVSS:3.1x/${BASE}`],
      ['a blank before the prefix', ` CVSS:3.1/${BASE}`],
      ['a base metric that is missing', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H'],
      ['only temporal metrics', 'CVSS:3.1/E:U/RL:O/RC:C'],
      ['a metric named twice', `CVSS:3.1/${BASE}/AV:L`],
      ['a metric named twice with the same value', `CVSS:3.1/${BASE}/A:H`],
      ['a temporal metric named twice', `CVSS:3.1/${BASE}/E:U/E:U`],
      ['a value the metric cannot take', 'CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
      ['the value of another metric', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:R'],
      ['a value in lower case', 'CVSS:3.1/AV:n/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
      ['a metric in lower case', 'CVSS:3.1/av:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
      ['a metric that does not exist', `CVSS:3.1/${BASE}/XX:N`],
      ['a metric of version 4', `CVSS:3.1/${BASE}/AT:N`],
      ['a metric without a value', 'CVSS:3.1/AV:/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
      ['a value without a metric', 'CVSS:3.1/:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
      ['a part without a colon', 'CVSS:3.1/AVN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
      ['a part with two colons', 'CVSS:3.1/AV:N:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
      ['a slash at the end', `CVSS:3.1/${BASE}/`],
      ['two slashes', 'CVSS:3.1//AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
      ['a blank inside', 'CVSS:3.1/AV:N /AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
      ['a blank at the end', `CVSS:3.1/${BASE} `],
      ['a name every object has', `CVSS:3.1/${BASE}/constructor:N`],
      ['another name every object has', `CVSS:3.1/${BASE}/__proto__:N`],
    ])('%s', (_name, vector) => {
      expect(cvssV3BaseScore(vector)).toBeNull();
    });

    // No vector is longer than 117 characters: every metric of the three groups, once. A
    // longer text names a metric twice or one that does not exist, and ends there.
    it('a text far longer than a vector can be, quickly', () => {
      const long = `CVSS:3.1/${BASE}${'/E:U'.repeat(100_000)}`;
      const started = performance.now();
      expect(cvssV3BaseScore(long)).toBeNull();
      expect(cvssV3BaseScore(`CVSS:3.1/${BASE}/${'X'.repeat(1_000_000)}`)).toBeNull();
      expect(performance.now() - started).toBeLessThan(200);
    });

    it('the longest vector there is has a score', () => {
      const longest = `CVSS:3.1/${BASE}/E:P/RL:T/RC:R/CR:H/IR:M/AR:L/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:N/MA:N`;
      expect(longest).toHaveLength(117);
      expect(cvssV3BaseScore(longest)).toBe(9.8);
    });
  });
});
