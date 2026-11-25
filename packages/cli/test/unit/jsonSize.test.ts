import { describe, expect, it } from 'vitest';
import { rawListBytes } from '../../src/io/jsonSize.js';

/** What the list really takes in a snapshot: the file with it, minus the file with an empty one. */
function writtenBytes(list: unknown[]): number {
  const size = (value: unknown[]) =>
    Buffer.byteLength(
      JSON.stringify({ schemaVersion: 1, raw: { before: 1, list: value } }, null, 2),
    );
  return size(list) - size([]) + 2;
}

describe('rawListBytes', () => {
  it.each([
    ['an empty list', []],
    ['one flat element', [{ id: 'GHSA-fake-0001-baip', label: null }]],
    [
      'elements with nested lists and objects',
      [
        { id: 'a', aliases: ['x', 'y'], summary: null, nested: { deep: [1, [2, 3], {}] } },
        { id: 'b', aliases: [], summary: 'two\nlines "quoted" \\ and a tab\t' },
        { name: 'baip-fixture-merge', advisories: [{ id: 'a', fixed: ['1.0.0', '2.0.0'] }] },
      ],
    ],
    ['text outside ASCII', [{ summary: 'Größe ≥ 4 ✓ \u{1f600}' }, { summary: '\u0001\u2028' }]],
    ['values that are not objects', ['text', 1, null, true, [], {}, [[]]]],
    ['a key that is left out', [{ kept: 1, dropped: undefined }]],
  ])('counts %s as a snapshot writes it', (_name, list) => {
    expect(rawListBytes(list)).toBe(writtenBytes(list));
  });

  it('counts many elements exactly', () => {
    const list = Array.from({ length: 2_500 }, (_, i) => ({
      id: `GHSA-fake-${String(i).padStart(4, '0')}-baip`,
      aliases: i % 3 === 0 ? [`CVE-2026-${i}`] : [],
      fixed: i % 2 === 0 ? ['1.0.1'] : [],
    }));
    expect(rawListBytes(list)).toBe(writtenBytes(list));
  });

  it('stops counting once it is above the bound it was given', () => {
    let read = 0;
    const element = {
      get id(): string {
        read += 1;
        return 'x'.repeat(100);
      },
    };
    const list = Array.from({ length: 1_000 }, () => element);
    const one = writtenBytes([element]);
    read = 0;
    const bytes = rawListBytes(list, 10 * one);
    expect(bytes).toBeGreaterThan(10 * one);
    expect(bytes).toBeLessThan(12 * one);
    expect(read).toBeLessThan(12);
    // Without a bound every element is read.
    read = 0;
    rawListBytes(list);
    expect(read).toBe(1_000);
  });
});
