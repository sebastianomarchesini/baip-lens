import { describe, expect, it } from 'vitest';
import { skippedPhrase } from '../../src/checks.js';
import type { CheckResult, SkipReasonCode } from '../../src/model/check.js';

/** One skipped check per reason code; `undefined` is a snapshot from before reason codes. */
const skipped = (...codes: (SkipReasonCode | undefined)[]): CheckResult[] =>
  codes.map((reasonCode, i) => ({
    id: `check.${i}`,
    title: `Check ${i}`,
    roles: ['SpaceAuditor'],
    status: 'skipped',
    reason: 'test',
    ...(reasonCode === undefined ? {} : { reasonCode }),
  }));

describe('skippedPhrase', () => {
  it('blames the role only when a missing role is all that stopped the checks', () => {
    expect(skippedPhrase(skipped('insufficient_role'))).toBe('could not run with your role');
    // A check that needs a forbidden one was stopped by the same role.
    expect(skippedPhrase(skipped('insufficient_role', 'dependency_skipped'))).toBe(
      'could not run with your role',
    );
    expect(skippedPhrase(skipped('dependency_skipped'))).toBe('did not run');
    expect(skippedPhrase(skipped('insufficient_role', 'unavailable'))).toBe('did not run');
  });

  it('says a check was turned off and never blames an absent service on the role', () => {
    expect(skippedPhrase(skipped('disabled'))).toBe('was turned off');
    expect(skippedPhrase(skipped('disabled', 'disabled'))).toBe('were turned off');
    expect(skippedPhrase(skipped('disabled', 'unavailable'))).toBe('did not run');
    expect(skippedPhrase(skipped('unavailable'))).toBe('did not run');
    expect(skippedPhrase(skipped('error'))).toBe('did not run');
    expect(skippedPhrase(skipped('requires_deep'))).toBe('did not run');
    expect(skippedPhrase(skipped(undefined))).toBe('did not run');
  });
});
