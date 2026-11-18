// Pins the relative links and images of the README that ships in the npm
// package to the release tag on GitHub, and lists any relative URL left.
//
// The README's relative URLs point at files in the repository root. On
// npmjs.com a relative link or image resolves under `repository.directory`
// (packages/cli) on the default branch, and a relative `srcset` against
// npmjs.com itself; neither has those files. Images (Markdown images and the
// HTML `src`, `srcset` and `poster` values) become raw file URLs and every
// other link a GitHub blob URL, both pinned to the version's tag.
//
// Code gets no special treatment: a relative URL in a code sample is pinned
// as well. Telling code from prose would need a full Markdown parser, and a
// mistake there would hide a real link from the pinning and from the check.

const REPOSITORY = 'sebastianomarchesini/BAIP-Lens';

/** A URL with a scheme (`https:`, `mailto:`), a protocol-relative URL (`//host`) or an anchor. */
const ABSOLUTE = /^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i;
/** An inline image, `![alt](url`, with one level of brackets in the alt text; group 1 is the destination. */
const INLINE_IMAGE = /!\[(?:[^[\]\\]|\\.|\[(?:[^[\]\\]|\\.)*\])*\]\(\s*(<[^>\n]*>|[^)\s]+)/dg;
/** An inline link or image destination, `](url`; group 1 is the destination. */
const INLINE_LINK = /\]\(\s*(<[^>\n]*>|[^)\s]+)/dg;
/**
 * A link reference definition, `[label]: url`: also in a block quote, in a
 * list item or on its marker line, with the label wrapped over lines (but not
 * over a blank line) and with the URL on the next line. Footnotes
 * (`[^1]: text`) are not definitions, and neither is a line where plain text
 * follows the URL. Group 1 is the destination.
 */
const REFERENCE =
  /^(?:[ \t]*(?:>|(?:[-+*]|\d{1,9}[.)])(?=[ \t])))*[ \t]*\[(?!\^)(?:[^[\]\\\n]|\\.|\n(?![ \t]*(?:>[ \t]*)*\r?\n))+\]:[ \t]*(?:\r?\n(?:[ \t]*>)*[ \t]*)?(<[^>\n]*>|[^\s<]\S*)(?=[ \t]*(?:$|["'(]))/dgm;
/** An HTML comment, whose content is not rendered. */
const COMMENT = /<!--[\s\S]*?-->/g;
/** An HTML start tag, with `>` allowed inside quoted attribute values. */
const TAG = /<[a-z][a-z0-9-]*(?:"[^"]*"|'[^']*'|[^>"'])*>/gi;
/**
 * A URL attribute, after whitespace, a quote or a slash as browsers accept;
 * group 2, 3 or 4 is its double-quoted, single-quoted or unquoted value.
 */
const URL_ATTRIBUTE =
  /(?<=[\s"'/])(src|srcset|href|poster)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/dgi;

/** @param {string} url */
const isRelative = (url) => url !== '' && !ABSOLUTE.test(url);

/**
 * @param {string} url a relative URL
 * @param {'raw' | 'blob'} kind
 * @param {string} version
 */
function pin(url, kind, version) {
  const path = url.replace(/^(?:\.\/|\/)+/, '');
  return kind === 'raw'
    ? `https://raw.githubusercontent.com/${REPOSITORY}/v${version}/${path}`
    : `https://github.com/${REPOSITORY}/blob/v${version}/${path}`;
}

/**
 * The candidate URLs of a `srcset` value, as offsets into it, following the
 * HTML parsing rules: a URL may contain commas, except at its end.
 * @param {string} value
 * @returns {{ start: number, end: number }[]}
 */
function srcsetUrls(value) {
  const urls = [];
  let i = 0;
  while (i < value.length) {
    while (i < value.length && /[\s,]/.test(value[i] ?? '')) i += 1;
    const start = i;
    while (i < value.length && !/\s/.test(value[i] ?? '')) i += 1;
    let end = i;
    while (end > start && value[end - 1] === ',') end -= 1;
    if (end > start) urls.push({ start, end });
    if (end < i) continue;
    // Descriptors such as `2x` or `480w` run to the next comma.
    let depth = 0;
    while (i < value.length && (value[i] !== ',' || depth > 0)) {
      if (value[i] === '(') depth += 1;
      else if (value[i] === ')') depth = Math.max(0, depth - 1);
      i += 1;
    }
  }
  return urls;
}

/**
 * @typedef {object} Occurrence
 * @property {number} start offset of the URL in the Markdown
 * @property {number} end
 * @property {string} url
 * @property {'raw' | 'blob'} kind
 * @property {boolean} pinnable false for reference definitions, which are only reported
 */

/**
 * Every URL in the Markdown: inline links and images, link reference
 * definitions outside HTML comments, and the `src`, `srcset`, `href` and
 * `poster` of HTML tags.
 * @param {string} markdown
 * @returns {Occurrence[]}
 */
function locate(markdown) {
  /** @type {Map<number, Occurrence>} */
  const found = new Map();
  /**
   * @param {[number, number] | undefined} range
   * @param {'raw' | 'blob'} kind
   * @param {boolean} pinnable
   */
  const add = (range, kind, pinnable) => {
    if (range === undefined || found.has(range[0])) return;
    let [start, end] = range;
    if (markdown[start] === '<' && markdown[end - 1] === '>') {
      start += 1;
      end -= 1;
    }
    found.set(range[0], { start, end, url: markdown.slice(start, end), kind, pinnable });
  };
  // Images first, so that their destinations are pinned as raw files.
  for (const match of markdown.matchAll(INLINE_IMAGE)) add(match.indices?.[1], 'raw', true);
  for (const match of markdown.matchAll(INLINE_LINK)) add(match.indices?.[1], 'blob', true);
  const uncommented = markdown.replace(COMMENT, (comment) => comment.replace(/[^\n]/g, ' '));
  for (const match of uncommented.matchAll(REFERENCE)) add(match.indices?.[1], 'blob', false);
  for (const tag of markdown.matchAll(TAG)) {
    for (const attribute of tag[0].matchAll(URL_ATTRIBUTE)) {
      const value = [2, 3, 4].map((group) => attribute.indices?.[group]).find(Boolean);
      if (value === undefined) continue;
      // Browsers strip ASCII whitespace around a URL attribute value.
      const text = tag[0].slice(value[0], value[1]);
      const start = tag.index + value[0] + (text.length - text.replace(/^[\t\n\f\r ]+/, '').length);
      const end = tag.index + value[1] - (text.length - text.replace(/[\t\n\f\r ]+$/, '').length);
      const name = (attribute[1] ?? '').toLowerCase();
      if (name === 'srcset') {
        for (const url of srcsetUrls(markdown.slice(start, end))) {
          add([start + url.start, start + url.end], 'raw', true);
        }
      } else if (end > start) {
        add([start, end], name === 'href' ? 'blob' : 'raw', true);
      }
    }
  }
  return [...found.values()].sort((a, b) => a.start - b.start);
}

/**
 * Rewrites the relative URLs of inline Markdown links and images and of the
 * HTML `src`, `srcset`, `href` and `poster` attributes to GitHub URLs pinned to
 * the tag `v<version>`. Absolute URLs and anchors stay as they are.
 * @param {string} markdown
 * @param {string} version
 */
export function pinReadmeLinks(markdown, version) {
  let out = '';
  let at = 0;
  for (const { start, end, url, kind, pinnable } of locate(markdown)) {
    if (!pinnable || !isRelative(url) || start < at) continue;
    out += markdown.slice(at, start) + pin(url, kind, version);
    at = end;
  }
  return out + markdown.slice(at);
}

/**
 * The relative URLs in the Markdown, with their 1-based line. After
 * `pinReadmeLinks` only what it cannot pin is left: the targets of link
 * reference definitions.
 * @param {string} markdown
 * @returns {{ line: number, url: string }[]}
 */
export function findRelativeUrls(markdown) {
  return locate(markdown)
    .filter(({ url }) => isRelative(url))
    .map(({ start, url }) => ({ line: markdown.slice(0, start).split('\n').length, url }));
}
