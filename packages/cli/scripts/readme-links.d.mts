/** A relative URL in the Markdown, with its 1-based line. */
export interface RelativeUrl {
  line: number;
  url: string;
}

/**
 * Rewrites the relative URLs of inline Markdown links and images and of the
 * HTML `src`, `srcset`, `href` and `poster` attributes to GitHub URLs pinned to
 * the tag `v<version>`. Absolute URLs and anchors stay as they are.
 */
export function pinReadmeLinks(markdown: string, version: string): string;

/**
 * The relative URLs in the Markdown. After `pinReadmeLinks` only what it
 * cannot pin is left: the targets of link reference definitions.
 */
export function findRelativeUrls(markdown: string): RelativeUrl[];
