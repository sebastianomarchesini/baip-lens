/*
 * A look at JSON text before `JSON.parse` turns it into values. It reads the
 * bytes once, allocates nothing and stops at the first limit passed, so a
 * file that would cost far more memory parsed than it takes on disk (millions
 * of `{}` in a few megabytes) or that nests deeper than any code reading it
 * can recurse is refused before it is parsed (docs/security-review.md SEC-21).
 *
 * It does not validate the JSON: text that is not JSON passes or fails here
 * like any other, and `JSON.parse` then reports it.
 */

export interface JsonShapeLimits {
  /** Deepest nesting of arrays and objects; a top-level array is 1 deep. */
  maxDepth: number;
  /** Most values the parser may build, arrays and objects included; object keys do not count. */
  maxValues: number;
}

export type JsonShapeLimit = 'depth' | 'values';

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
 * Values are counted as the parser builds them: the top-level value, then
 * one for the first member of every array or object that is not empty and
 * one for every comma between members.
 */
export function jsonShapeExcess(
  bytes: Uint8Array,
  limits: JsonShapeLimits,
): JsonShapeLimit | undefined {
  let depth = 0;
  let values = 1;
  // The last byte that was not whitespace opened an array or an object.
  let opened = false;
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    if (isWhitespace(byte)) continue;
    if (opened) {
      opened = false;
      if (byte !== CLOSE_ARRAY && byte !== CLOSE_OBJECT && ++values > limits.maxValues) {
        return 'values';
      }
    }
    switch (byte) {
      case QUOTE:
        i = endOfString(bytes, i);
        break;
      case OPEN_ARRAY:
      case OPEN_OBJECT:
        if (++depth > limits.maxDepth) return 'depth';
        opened = true;
        break;
      case CLOSE_ARRAY:
      case CLOSE_OBJECT:
        depth--;
        break;
      case COMMA:
        if (++values > limits.maxValues) return 'values';
        break;
    }
  }
  return undefined;
}
