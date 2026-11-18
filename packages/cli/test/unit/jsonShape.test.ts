import { describe, expect, it } from 'vitest';
import { type JsonShapeLimits, jsonShapeExcess } from '../../src/io/jsonShape.js';

const LIMITS: JsonShapeLimits = { maxDepth: 4, maxItems: 10, maxMembers: 100 };
const excess = (text: string, limits = LIMITS) =>
  jsonShapeExcess(Buffer.from(text, 'utf8'), limits);

describe('jsonShapeExcess: nesting', () => {
  it('allows the maximum depth and refuses one level more', () => {
    expect(excess('[[[[1]]]]')).toBeUndefined();
    expect(excess('[[[[[1]]]]]')).toBe('depth');
    expect(excess('{"a":{"b":{"c":{}}}}')).toBeUndefined();
    expect(excess('{"a":{"b":{"c":{"d":{}}}}}')).toBe('depth');
  });

  it('counts the depth of the deepest branch, not of the whole document', () => {
    // Nine items, each branch four deep: closing a branch must give its depth back.
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

describe('jsonShapeExcess: items', () => {
  it('counts every value, arrays and objects included, and refuses one more than the limit', () => {
    // The list and nine numbers: ten items.
    expect(excess('[1,2,3,4,5,6,7,8,9]')).toBeUndefined();
    expect(excess('[1,2,3,4,5,6,7,8,9,10]')).toBe('items');
    // The outer list and nine empty lists, or nine empty objects.
    expect(excess('[[],[],[],[],[],[],[],[],[]]')).toBeUndefined();
    expect(excess('[[],[],[],[],[],[],[],[],[],[]]')).toBe('items');
    expect(excess('[{},{},{},{},{},{},{},{},{}]')).toBeUndefined();
    expect(excess('[{},{},{},{},{},{},{},{},{},{}]')).toBe('items');
  });

  it('counts object keys as items, since the parser builds each one', () => {
    // The object, four keys and four numbers: nine items.
    expect(excess('{"a":1,"b":2,"c":3,"d":4}')).toBeUndefined();
    expect(excess('{"a":1,"b":2,"c":3,"d":4,"e":5}')).toBe('items');
  });

  it('counts an empty array or object as one item, whatever whitespace it holds', () => {
    expect(excess('[[ ],[\t],[\n],[\r],{ },{\t},{\n},{\r\n},[  ]]')).toBeUndefined();
    expect(excess('[[ ],[\t],[\n],[\r],{ },{\t},{\n},{\r\n},[  ],{ }]')).toBe('items');
  });

  it('ignores commas inside strings and whitespace between tokens', () => {
    expect(excess('[",,,,,,,,,,,,,,,,,,,,"]')).toBeUndefined();
    const pretty = JSON.stringify({ a: [1, 2, { b: null }], d: true }, null, 2);
    expect(excess(pretty)).toBeUndefined();
  });

  it('accepts a single value at the top level', () => {
    expect(excess('"text"')).toBeUndefined();
    expect(excess(' 42 ')).toBeUndefined();
  });
});

describe('jsonShapeExcess: keys per object', () => {
  const few: JsonShapeLimits = { maxDepth: 4, maxItems: 100, maxMembers: 3 };

  it('allows the maximum number of keys in an object and refuses one more', () => {
    expect(excess('{"a":1,"b":2,"c":3}', few)).toBeUndefined();
    expect(excess('{"a":1,"b":2,"c":3,"d":4}', few)).toBe('members');
  });

  it('counts the keys of each object on its own, nested ones included', () => {
    expect(excess('{"a":{"x":1,"y":2,"z":3},"b":{"x":1,"y":2,"z":3},"c":3}', few)).toBeUndefined();
    expect(excess('{"a":{"x":1,"y":2,"z":3},"b":1,"c":2,"d":3}', few)).toBe('members');
  });

  it('does not limit the elements of an array', () => {
    expect(excess('[1,2,3,4,5,6,7]', few)).toBeUndefined();
  });
});
