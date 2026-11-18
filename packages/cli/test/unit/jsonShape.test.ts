import { describe, expect, it } from 'vitest';
import { jsonShapeExcess } from '../../src/io/jsonShape.js';

const LIMITS = { maxDepth: 4, maxValues: 10 };
const excess = (text: string) => jsonShapeExcess(Buffer.from(text, 'utf8'), LIMITS);

describe('jsonShapeExcess: nesting', () => {
  it('allows the maximum depth and refuses one level more', () => {
    expect(excess('[[[[1]]]]')).toBeUndefined();
    expect(excess('[[[[[1]]]]]')).toBe('depth');
    expect(excess('{"a":{"b":{"c":{"d":1}}}}')).toBeUndefined();
    expect(excess('{"a":{"b":{"c":{"d":{}}}}}')).toBe('depth');
  });

  it('counts the depth of the deepest branch, not of the whole document', () => {
    // Nine values, each branch four deep: closing a branch must give its depth back.
    expect(excess('[[[[1]]],[[[2]]]]')).toBeUndefined();
  });

  it('ignores brackets inside strings, escaped quotes included', () => {
    expect(excess('["[[[[[[[[", "]]]]]]"]')).toBeUndefined();
    expect(excess(String.raw`["\"[[[[[["]`)).toBeUndefined();
    // An escaped backslash does not escape the quote after it: the brackets count.
    expect(excess(String.raw`["\\",[[[[1]]]]]`)).toBe('depth');
  });

  it('reads multi-byte characters inside strings as text', () => {
    expect(excess('{"name":"Zürich ✓ 𝄞 [[[[[[","x":"\\u005b"}')).toBeUndefined();
  });
});

describe('jsonShapeExcess: values', () => {
  it('counts every value, containers included, and refuses one more than the limit', () => {
    // The list and nine numbers: ten values.
    expect(excess('[1,2,3,4,5,6,7,8,9]')).toBeUndefined();
    expect(excess('[1,2,3,4,5,6,7,8,9,10]')).toBe('values');
    // The outer list and nine empty lists, or nine empty objects.
    expect(excess('[[],[],[],[],[],[],[],[],[]]')).toBeUndefined();
    expect(excess('[[],[],[],[],[],[],[],[],[],[]]')).toBe('values');
    expect(excess('[{},{},{},{},{},{},{},{},{}]')).toBeUndefined();
    expect(excess('[{},{},{},{},{},{},{},{},{},{}]')).toBe('values');
  });

  it('does not count object keys as values', () => {
    expect(excess('{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9}')).toBeUndefined();
    expect(excess('{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9,"j":0}')).toBe('values');
  });

  it('ignores commas inside strings and whitespace between tokens', () => {
    expect(excess('[",,,,,,,,,,,,,,,,,,,,"]')).toBeUndefined();
    const pretty = JSON.stringify({ a: [1, 2, { b: null, c: 'x' }], d: true }, null, 2);
    expect(excess(pretty)).toBeUndefined();
  });

  it('accepts a single value at the top level', () => {
    expect(excess('"text"')).toBeUndefined();
    expect(excess(' 42 ')).toBeUndefined();
  });
});
