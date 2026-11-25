/*
 * How many bytes a list takes in a snapshot file, counted one element at a
 * time. A scan that is about to store what a public source answered needs
 * that number before it stores anything, and the text of the whole list,
 * built only to be measured, could itself be hundreds of megabytes.
 *
 * A snapshot is written with `JSON.stringify(snapshot, null, 2)`, and the
 * lists measured here are members of its `raw` object: their elements start
 * three levels deep (the snapshot, `raw`, the list).
 */

const INDENT = 2;
/** How deep the elements of a list under `raw` are written. */
const ELEMENT_DEPTH = 3;
const NEWLINE = '\n';

/** The bytes of one element, the indentation of its first line included. */
function elementBytes(element: unknown): number {
  const text = JSON.stringify(element, null, INDENT) ?? 'null';
  let lines = 1;
  for (let at = text.indexOf(NEWLINE); at !== -1; at = text.indexOf(NEWLINE, at + 1)) lines += 1;
  return Buffer.byteLength(text, 'utf8') + lines * ELEMENT_DEPTH * INDENT;
}

/**
 * The bytes the value of a list under `raw` takes as a snapshot is written,
 * from its `[` to its `]`. Counting stops once the sum is above `stopAbove`:
 * the result is then only known to be larger than that.
 */
export function rawListBytes(list: readonly unknown[], stopAbove = Infinity): number {
  if (list.length === 0) return 2;
  // `[`, and at the end a line break, the indentation of the list and `]`.
  let total = 1 + 1 + (ELEMENT_DEPTH - 1) * INDENT + 1;
  for (const [index, element] of list.entries()) {
    // A line break before each element, a comma after each but the last.
    total += 1 + elementBytes(element) + (index === list.length - 1 ? 0 : 1);
    if (total > stopAbove) return total;
  }
  return total;
}
