/*
 * A look at JSON text before `JSON.parse` turns it into values. It reads the
 * bytes once, allocates almost nothing and stops at the first limit passed,
 * so a file that would cost far more memory parsed than it takes on disk
 * (millions of `{}` or of distinct keys in a few megabytes), or that nests
 * deeper than any code reading it can recurse, is refused before it is
 * parsed (docs/security-review.md SEC-21).
 *
 * It does not validate the JSON: text that is not JSON passes or fails here
 * like any other, and `JSON.parse` then reports it.
 */

export interface JsonShapeLimits {
  /** Deepest nesting of arrays and objects; a top-level array is 1 deep. Sizes two arrays of state per level. */
  maxDepth: number;
  /**
   * Most items the parser may build: every value (arrays and objects
   * included) and every object key. A key costs memory like a value: a
   * distinct one takes more than an empty object.
   */
  maxItems: number;
  /** Most keys one object may hold; a large object is far costlier per key. */
  maxMembers: number;
}

export type JsonShapeLimit = 'depth' | 'items' | 'members';

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const COMMA = 0x2c;
const OPEN_ARRAY = 0x5b;
const CLOSE_ARRAY = 0x5d;
const OPEN_OBJECT = 0x7b;
const CLOSE_OBJECT = 0x7d;

function isWhitespace(byte: number | undefined): boolean {
  return byte === 0x20 || byte === 0x0a || byte === 0x0d || byte === 0x09;
}

/**
 * The index of the quote that closes the string opened at `start`, or the end
 * of the input when nothing closes it. A quote is escaped when an odd number
 * of backslashes precedes it. Every byte of a multi-byte UTF-8 character is
 * 0x80 or above, so it can never be mistaken for a quote or a backslash.
 */
function endOfString(bytes: Uint8Array, start: number): number {
  let from = start + 1;
  for (;;) {
    const quote = bytes.indexOf(QUOTE, from);
    if (quote === -1) return bytes.length;
    let backslashes = 0;
    for (let i = quote - 1; i > start && bytes[i] === BACKSLASH; i--) backslashes++;
    if (backslashes % 2 === 0) return quote;
    from = quote + 1;
  }
}

/**
 * The first limit that `bytes`, read as JSON text, goes past, or undefined.
 * Items are counted as the parser builds them: the top-level value, then for
 * every member of an array one item, and of an object two (its key and its
 * value). A member is counted where it starts: at the first byte after `[`
 * or `{` that does not close it, and at every comma.
 */
export function jsonShapeExcess(
  bytes: Uint8Array,
  limits: JsonShapeLimits,
): JsonShapeLimit | undefined {
  // Per open array or object: whether it is an object, and its keys so far.
  const isObject = new Uint8Array(limits.maxDepth + 1);
  const members = new Uint32Array(limits.maxDepth + 1);
  let depth = 0;
  let items = 1;
  // The last byte that was not whitespace opened an array or an object.
  let opened = false;

  const member = (): JsonShapeLimit | undefined => {
    if (isObject[depth] === 1) {
      items += 2;
      const keys = (members[depth] ?? 0) + 1;
      members[depth] = keys;
      if (keys > limits.maxMembers) return 'members';
    } else {
      items += 1;
    }
    return items > limits.maxItems ? 'items' : undefined;
  };

  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (isWhitespace(byte)) continue;
    if (opened) {
      opened = false;
      if (byte !== CLOSE_ARRAY && byte !== CLOSE_OBJECT) {
        const excess = member();
        if (excess !== undefined) return excess;
      }
    }
    switch (byte) {
      case QUOTE:
        i = endOfString(bytes, i);
        break;
      case OPEN_ARRAY:
      case OPEN_OBJECT:
        if (++depth > limits.maxDepth) return 'depth';
        isObject[depth] = byte === OPEN_OBJECT ? 1 : 0;
        members[depth] = 0;
        opened = true;
        break;
      case CLOSE_ARRAY:
      case CLOSE_OBJECT:
        // Text that closes more than it opened is not JSON; the parser says so.
        if (depth > 0) depth--;
        break;
      case COMMA: {
        const excess = member();
        if (excess !== undefined) return excess;
        break;
      }
    }
  }
  return undefined;
}
