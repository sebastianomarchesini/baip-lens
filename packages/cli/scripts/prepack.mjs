// Copies the repository README, LICENSE and NOTICE into the package before
// `npm pack` / `npm publish`, so the npm page and tarball carry them.
//
// The README's relative links and images point at files in the repository
// root, which npmjs.com cannot resolve, so they are pinned to this version's
// tag on GitHub (see readme-links.mjs). Packing fails if a relative URL is
// left that cannot be pinned, the target of a link reference definition,
// rather than publishing a README with a broken link.
import { copyFile, readFile, writeFile } from 'node:fs/promises';
import { findRelativeUrls, pinReadmeLinks } from './readme-links.mjs';

const root = new URL('../../../', import.meta.url);
const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));

const readme = pinReadmeLinks(await readFile(new URL('README.md', root), 'utf8'), pkg.version);
const left = findRelativeUrls(readme);
if (left.length > 0) {
  const lines = left.map(({ line, url }) => `  README.md:${line} ${url}`).join('\n');
  throw new Error(
    `README.md has relative URLs that npmjs.com cannot resolve and prepack cannot pin. ` +
      `Use an inline link, an inline image or a src, srcset or href attribute:\n${lines}`,
  );
}
await writeFile(new URL('../README.md', import.meta.url), readme);
for (const file of ['LICENSE', 'NOTICE']) {
  await copyFile(new URL(file, root), new URL(`../${file}`, import.meta.url));
}
// stderr, so `npm pack --json` output stays valid JSON.
console.error(
  `Copied README.md (links pinned to v${pkg.version}), LICENSE and NOTICE into the package`,
);
