import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { findRelativeUrls, pinReadmeLinks } from '../../scripts/readme-links.mjs';

const RAW = 'https://raw.githubusercontent.com/sebastianomarchesini/BAIP-Lens/v1.2.3/';
const BLOB = 'https://github.com/sebastianomarchesini/BAIP-Lens/blob/v1.2.3/';
const pin = (markdown: string): string => pinReadmeLinks(markdown, '1.2.3');

describe('pinReadmeLinks', () => {
  it('pins Markdown images to raw files and links to blob pages, keeping anchors', () => {
    expect(pin('![Overview](docs/images/a.png) see [rules](docs/rules.md#project-rules)')).toBe(
      `![Overview](${RAW}docs/images/a.png) see [rules](${BLOB}docs/rules.md#project-rules)`,
    );
  });

  it('pins the link around a badge but not the absolute badge image', () => {
    expect(pin('[![License](https://img.shields.io/badge/license-x)](LICENSE)')).toBe(
      `[![License](https://img.shields.io/badge/license-x)](${BLOB}LICENSE)`,
    );
  });

  it('pins HTML src, href and every srcset candidate, whatever the quoting', () => {
    const html = [
      '<picture>',
      '  <source media="(prefers-color-scheme: dark)" srcset="docs/a-dark.png">',
      "  <source srcset='docs/a.png 1x, ./docs/a@2x.png 2x'>",
      '  <img src=docs/a.png width="420" alt="a > b">',
      '</picture>',
      '<a href="SPONSORS.md"><img src="https://example.org/x.svg"></a>',
    ].join('\n');
    expect(pin(html)).toBe(
      [
        '<picture>',
        `  <source media="(prefers-color-scheme: dark)" srcset="${RAW}docs/a-dark.png">`,
        `  <source srcset='${RAW}docs/a.png 1x, ${RAW}docs/a@2x.png 2x'>`,
        `  <img src=${RAW}docs/a.png width="420" alt="a > b">`,
        '</picture>',
        `<a href="${BLOB}SPONSORS.md"><img src="https://example.org/x.svg"></a>`,
      ].join('\n'),
    );
  });

  it('keeps a data URL in srcset whole, commas included', () => {
    const html = '<img srcset="data:image/png;base64,AAA,BBB 1x, docs/b.png 2x">';
    expect(pin(html)).toBe(`<img srcset="data:image/png;base64,AAA,BBB 1x, ${RAW}docs/b.png 2x">`);
  });

  it('pins a srcset candidate without a descriptor before the next one', () => {
    expect(pin('<img srcset="docs/a.png, docs/a@2x.png 2x">')).toBe(
      `<img srcset="${RAW}docs/a.png, ${RAW}docs/a@2x.png 2x">`,
    );
  });

  it('pins attributes in any letter case, after a quoted ">", a quote or a slash', () => {
    const html = [
      '<IMG SRC=docs/a.png>',
      '<img alt="a > b" src="docs/b.png">',
      '<img width="420"src="docs/c.png">',
      '<img/src="docs/d.png">',
    ].join('\n');
    expect(pin(html)).toBe(
      [
        `<IMG SRC=${RAW}docs/a.png>`,
        `<img alt="a > b" src="${RAW}docs/b.png">`,
        `<img width="420"src="${RAW}docs/c.png">`,
        `<img/src="${RAW}docs/d.png">`,
      ].join('\n'),
    );
  });

  it('pins a destination after spaces or a line break', () => {
    expect(pin('[a]( docs/a.md) ![b](\ndocs/b.png)')).toBe(
      `[a]( ${BLOB}docs/a.md) ![b](\n${RAW}docs/b.png)`,
    );
  });

  it('pins an attribute value once even when it looks like a Markdown link', () => {
    expect(pin('<a href="docs/a.md](b.md)">x</a>')).toBe(`<a href="${BLOB}docs/a.md](b.md)">x</a>`);
  });

  it('leaves absolute URLs, protocol-relative URLs, anchors and mail links alone', () => {
    const markdown = [
      '[a](https://example.org/x) [b](HTTPS://EXAMPLE.ORG) [c](//example.org/y)',
      '[d](#privacy) [e](mailto:security@example.org) <a href="#top">top</a> [f]() [g](<>)',
    ].join('\n');
    expect(pin(markdown)).toBe(markdown);
  });

  it('pins ./ and / prefixed paths from the repository root', () => {
    expect(pin('[a](./CONTRIBUTING.md) [b](/docs/faq.md)')).toBe(
      `[a](${BLOB}CONTRIBUTING.md) [b](${BLOB}docs/faq.md)`,
    );
  });

  it('keeps link titles and angle-bracket destinations', () => {
    expect(pin('[a](docs/a.md "The A") [b](<docs/b c.md>)')).toBe(
      `[a](${BLOB}docs/a.md "The A") [b](<${BLOB}docs/b c.md>)`,
    );
  });

  it('pins relative URLs in code samples too, so that nothing hides from the check', () => {
    const markdown = [
      '```md',
      '[x](docs/x.md) <img src="x.png">',
      '```',
      'Use `![y](y.png)`.',
    ].join('\n');
    expect(pin(markdown)).toBe(
      [
        '```md',
        `[x](${BLOB}docs/x.md) <img src="${RAW}x.png">`,
        '```',
        `Use \`![y](${RAW}y.png)\`.`,
      ].join('\n'),
    );
  });

  it('pins an image whose alt text has brackets as a raw file', () => {
    expect(pin('![The [beta] report](docs/a.png) ![a \\] b](docs/b.png)')).toBe(
      `![The [beta] report](${RAW}docs/a.png) ![a \\] b](${RAW}docs/b.png)`,
    );
  });

  it('ignores the whitespace around an attribute value, as browsers do', () => {
    const html = '<img src=" https://example.org/a.png "> <img src=" docs/b.png ">';
    expect(pin(html)).toBe(
      `<img src=" https://example.org/a.png "> <img src=" ${RAW}docs/b.png ">`,
    );
  });

  it('pins a link whose text is a code span', () => {
    expect(pin('[`baip-lens project`](docs/rules.md#project-rules)')).toBe(
      `[\`baip-lens project\`](${BLOB}docs/rules.md#project-rules)`,
    );
  });
});

describe('findRelativeUrls', () => {
  it('reports what pinReadmeLinks cannot pin, with its line', () => {
    const markdown = 'Intro [rules][r]\n\n[r]: docs/rules.md\n[ok]: https://example.org\n';
    expect(findRelativeUrls(pin(markdown))).toEqual([{ line: 3, url: 'docs/rules.md' }]);
  });

  it('finds relative links, images and attributes anywhere, code included', () => {
    const markdown = [
      '![a](a.png) [b](b.md)',
      '<video poster="p.png" src="https://example.org/v.mp4"></video>',
      '`[c](c.md)`',
    ].join('\n');
    expect(findRelativeUrls(markdown)).toEqual([
      { line: 1, url: 'a.png' },
      { line: 1, url: 'b.md' },
      { line: 2, url: 'p.png' },
      { line: 3, url: 'c.md' },
    ]);
    expect(findRelativeUrls(pin(markdown))).toEqual([]);
  });

  it('finds link reference definitions in block quotes, in list items and split over two lines', () => {
    const markdown = [
      '> [q]: docs/q.md',
      '- item',
      '',
      '  [l]: docs/l.md',
      '[n]:',
      '  docs/n.md',
      '[t]: <docs/t.md> "Title"',
      '[ok]: https://example.org',
    ].join('\r\n');
    expect(findRelativeUrls(pin(markdown))).toEqual([
      { line: 1, url: 'docs/q.md' },
      { line: 4, url: 'docs/l.md' },
      { line: 6, url: 'docs/n.md' },
      { line: 7, url: 'docs/t.md' },
    ]);
  });

  it('finds link reference definitions on list marker lines, with a wrapped label and between comments', () => {
    const markdown = [
      '- [r]: docs/r.md',
      '1. [s]: docs/s.md',
      '> - [u]: docs/u.md',
      '[Wrapped',
      'label]: docs/w.md',
      '> [v]:',
      '> docs/v.md',
      '<!-- one -->',
      '[c]: docs/c.md',
      '<!-- two -->',
    ].join('\n');
    expect(findRelativeUrls(markdown)).toEqual([
      { line: 1, url: 'docs/r.md' },
      { line: 2, url: 'docs/s.md' },
      { line: 3, url: 'docs/u.md' },
      { line: 5, url: 'docs/w.md' },
      { line: 7, url: 'docs/v.md' },
      { line: 9, url: 'docs/c.md' },
    ]);
  });

  it('does not take footnotes, prose or commented-out definitions for link references', () => {
    const markdown = [
      '[^1]: The report embeds its fonts.',
      '[^2]: Trademarks.',
      '[Optional]: you can also pass --space.',
      '[Not',
      '',
      'a label]: docs/x.md',
      '<!--',
      '[old]: docs/old.md',
      '-->',
    ].join('\n');
    expect(findRelativeUrls(markdown)).toEqual([]);
  });
});

describe('the repository README', () => {
  const root = new URL('../../../../', import.meta.url);
  const load = async (): Promise<{ readme: string; version: string }> => {
    const pkg = JSON.parse(await readFile(new URL('packages/cli/package.json', root), 'utf8')) as {
      version: string;
    };
    return { readme: await readFile(new URL('README.md', root), 'utf8'), version: pkg.version };
  };

  it('has no relative URL left once pinned, which prepack requires to pack', async () => {
    const { readme, version } = await load();
    expect(findRelativeUrls(readme).length).toBeGreaterThan(0);
    expect(findRelativeUrls(pinReadmeLinks(readme, version))).toEqual([]);
  });

  it('pins both logos to raw files of the release tag', async () => {
    const { readme, version } = await load();
    const raw = `https://raw.githubusercontent.com/sebastianomarchesini/BAIP-Lens/v${version}`;
    const pinned = pinReadmeLinks(readme, version);
    expect(pinned).toContain(`srcset="${raw}/docs/assets/logo-dark.png"`);
    expect(pinned).toContain(`<img src="${raw}/docs/assets/logo.png"`);
  });

  it('pins only paths that exist in the repository', async () => {
    const { readme, version } = await load();
    const pinned = pinReadmeLinks(readme, version);
    const prefix = new RegExp(
      `https://(?:raw\\.githubusercontent\\.com/sebastianomarchesini/BAIP-Lens/v${version}` +
        `|github\\.com/sebastianomarchesini/BAIP-Lens/blob/v${version})/([^)"'\\s#?]+)`,
      'g',
    );
    const paths = [...pinned.matchAll(prefix)].map((match) => match[1] ?? '');
    expect(paths.length).toBe(findRelativeUrls(readme).length);
    expect(paths.filter((path) => !existsSync(new URL(path, root)))).toEqual([]);
  });
});
