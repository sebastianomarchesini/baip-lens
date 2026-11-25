import { redactSecrets, stripControlCharacters } from '../io/redact.js';

/**
 * Buildpack names can be git or HTTP URLs, and those URLs sometimes carry
 * credentials (https://user:token@host/repo) or tokens in the query string.
 * Keep only scheme, host and path.
 */
export function redactUrlCredentials(value: string): string {
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return value;
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    // Not parseable: drop anything that looks like userinfo.
    return value.replace(/\/\/[^/@]*@/, '//');
  }
}

/** Collapses whitespace and cuts free text (e.g. buildpack detect output). */
export function truncate(value: string | null | undefined, max = 200): string | null {
  if (value === null || value === undefined) return null;
  const clean = value.replace(/\s+/g, ' ').trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

/*
 * Text that people outside the scanned landscape wrote: the summary of an
 * advisory, later the deprecation message of a package. It ends up in the
 * snapshot and in every report, so before it is stored it is reduced to one
 * short line of visible text without anything that looks like a credential
 * or an e-mail address (docs/privacy.md).
 */

/** Separators and controls that end a line or move the cursor: they become a blank, so that words stay apart. */
const LINE_BREAKS = /[\t\n\v\f\r\u0085\u2028\u2029]/g;
/**
 * Characters that take no room but change what a reader sees or what a
 * program reads: the soft hyphen, the combining grapheme joiner, the Arabic
 * letter mark, the Mongolian vowel separator, zero-width characters and
 * direction marks, direction embeddings and overrides, the word joiner and
 * the invisible operators, direction isolates, the byte order mark, the
 * interlinear annotation marks and the tag characters.
 */
const INVISIBLE =
  /\u034f|[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\ufff9-\ufffb]|\udb40[\udc00-\udc7f]/g;
/** Half of a character outside the basic plane: a surrogate without its partner. */
const HALF_CHARACTER = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;
/** Any userinfo of a URL, up to the last `@` before the host ends. */
const URL_USERINFO = /([a-z][a-z0-9+.-]*:\/\/)[^\s/]*@/gi;
/** The query and the fragment of a URL: where a token travels when it is not in the userinfo. */
const URL_QUERY = /([a-z][a-z0-9+.-]*:\/\/[^\s?#]*)[?#]\S*/gi;
/**
 * `name=value` where the name is, or ends in, a word for a credential, however
 * the word is joined to what stands before it (`api_key=`, `NPM_TOKEN=`,
 * `authToken=`, `sessiontoken=`, `secret=`).
 */
const NAMED_SECRET =
  /([a-z0-9_-]*(?:token|secret|api[_-]?key|passwd))(\s*=\s*["']?)[^\s"'&,;)}]+/gi;
/** An address, with any further `@domain` glued to it. */
const EMAIL = /[\w.+-]+(?:@(?:[a-z0-9-]+\.)+[a-z]{2,})+/gi;
/** Two base64url segments after the JSON header `{"`: a token, also when its signature was cut off. */
const TOKEN = /eyJ[\w-]{8,}\.[\w-]{8,}(?:\.[\w-]*)?/g;
/** `bearer <token>` and `basic <base64>`, also glued to the word before. */
const AUTHORIZATION = /(bearer|basic)\s+[\w.~+/=-]{8,}/gi;
/** How much of the text is looked at, as a multiple of what is kept: the patterns above cost more than its length on a long word. */
const LOOKED_AT_FACTOR = 10;

/**
 * The start of `text` that is looked at. When the text is longer, the word
 * the cut went through is dropped as well: half an address or half a token
 * must not get past the patterns that would have matched it whole.
 */
function head(text: string, length: number): string {
  if (text.length <= length) return text;
  const cut = text.slice(0, length);
  return cut.slice(0, Math.max(0, cut.lastIndexOf(' ')));
}

/**
 * One line of external text, safe to store and to show: without control
 * characters, escape sequences, direction marks and invisible characters;
 * whitespace collapsed; cut to `max` characters. What can carry a credential
 * or name a person is taken out by its shape: the userinfo, the query and
 * the fragment of a URL that begins with a scheme (`https://…`) are removed;
 * a JWT, the value after `bearer` or `basic`, the value of a field whose
 * name is or ends in a word for a credential (`password: …`,
 * `client_secret: …`, `api_key=…`, `authToken=…`) and an e-mail address are
 * replaced. A key that stands in the text with nothing that names it is not
 * recognised, and neither is the query of an address written without a
 * scheme. The schema of the field the text is stored in bounds it again.
 *
 * The line that is returned is a string of its own. A part of a string
 * keeps the whole string in memory, and what is stored of megabytes of text
 * must not hold on to them.
 */
export function cleanExternalText(text: string, max = 200): string {
  const visible = stripControlCharacters(text.replace(LINE_BREAKS, ' '))
    .replace(INVISIBLE, '')
    .replace(HALF_CHARACTER, '')
    .replace(/\s+/g, ' ')
    .trim();
  const safe = redactSecrets(head(visible, max * LOOKED_AT_FACTOR))
    .replace(TOKEN, '[redacted-token]')
    .replace(AUTHORIZATION, '$1 [redacted]')
    .replace(NAMED_SECRET, '$1$2[redacted]')
    .replace(URL_USERINFO, '$1')
    .replace(URL_QUERY, '$1')
    .replace(EMAIL, '[e-mail]');
  // A cut can go through a character; what is left of it goes as well.
  const line = (truncate(safe, max) ?? '').replace(HALF_CHARACTER, '');
  // Copied: no half character is left, so the bytes give the same text back.
  return Buffer.from(line, 'utf8').toString('utf8');
}
