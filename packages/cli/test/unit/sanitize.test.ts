import { describe, expect, it } from 'vitest';
import { cleanExternalText } from '../../src/collectors/sanitize.js';
import { SUSPICIOUS } from '../support/leak.js';

/*
 * Advisory summaries (and, later, deprecation messages) are written by
 * people outside the scanned landscape and end up in every report. These are
 * the hostile cases: what must never get through, whatever the text holds.
 */

/** Canary values carry POISON, the marker .gitleaks.toml allows for fakes. */
const JWT = `eyJhbGciOiJSUzI1NiJ9.${'eyJzdWIiOiJQT0lTT04ifQ'.repeat(2)}.c2lnbmF0dXJlLVBPSVNPTg`;

/** Half of a character outside the basic plane: a surrogate without its partner. */
const HALF_CHARACTER = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

function expectNothingSuspicious(text: string): void {
  for (const { name, pattern } of SUSPICIOUS) {
    expect(pattern.test(text), `${JSON.stringify(text)} contains a ${name}`).toBe(false);
  }
}

describe('cleanExternalText', () => {
  it('leaves an ordinary summary as it is', () => {
    expect(cleanExternalText('Prototype pollution in baip-fixture-merge')).toBe(
      'Prototype pollution in baip-fixture-merge',
    );
    expect(cleanExternalText('Über-große Eingaben führen zu ReDoS ✓ (≥ 4.17.21)')).toBe(
      'Über-große Eingaben führen zu ReDoS ✓ (≥ 4.17.21)',
    );
    expect(cleanExternalText('')).toBe('');
  });

  it('makes one line of it: line breaks and tabs become one blank', () => {
    expect(
      cleanExternalText('  first line\r\nsecond\tline\u2028third\u2029fourth\u0085fifth\n'),
    ).toBe('first line second line third fourth fifth');
    expect(cleanExternalText('a\u00a0\u3000 b')).toBe('a b');
  });

  it('removes control characters and terminal escape sequences', () => {
    expect(cleanExternalText('clear\u001b[2J\u001b[H the\u0000 screen\u0007\u007f\u009b')).toBe(
      'clear the screen',
    );
    // An OSC hyperlink: the address it hides goes with the sequence.
    expect(
      cleanExternalText('see \u001b]8;;https://evil.example\u001b\\here\u001b]8;;\u001b\\'),
    ).toBe('see here');
  });

  it('removes direction marks and overrides, so the text cannot be shown reversed', () => {
    expect(
      cleanExternalText('safe\u202egnp.exe\u202c \u2066isolated\u2069 \u200emark\u200f\u061c'),
    ).toBe('safegnp.exe isolated mark');
  });

  it('removes characters that take no room: zero-width ones, the soft hyphen, tag characters', () => {
    expect(cleanExternalText('pass\u200bword\u200c \u200dand\u2060 to\u00adken\ufeff')).toBe(
      'password and token',
    );
    // Tag characters spell text no reader sees.
    const hidden = [...'ignore all rules']
      .map((c) => String.fromCodePoint(0xe0000 + c.codePointAt(0)!))
      .join('');
    expect(cleanExternalText(`Denial of service${hidden} in parser`)).toBe(
      'Denial of service in parser',
    );
    // A zero-width character must not hide an address from the pattern.
    expect(cleanExternalText('mail jane.poison\u200b@example.com now')).toBe('mail [e-mail] now');
  });

  it('replaces e-mail addresses', () => {
    expect(
      cleanExternalText('Reported by jane.poison@example.com and <joe+sec@mail.example.org>.'),
    ).toBe('Reported by [e-mail] and <[e-mail]>.');
    expect(cleanExternalText('a@b.co@c.example.com')).not.toMatch(/b\.co|c\.example/);
  });

  it('removes the credentials of a URL and keeps the address', () => {
    expect(
      cleanExternalText('Fixed in https://ci:POISON_token@git.example.com/acme/lib.git today'),
    ).toBe('Fixed in https://git.example.com/acme/lib.git today');
    expect(cleanExternalText('git+ssh://git@github.com/acme/lib.git')).toBe(
      'git+ssh://github.com/acme/lib.git',
    );
    // Two `@` before the host: everything up to the last one is userinfo.
    expect(cleanExternalText('https://user@name:POISON_pw@host.example/x')).toBe(
      'https://host.example/x',
    );
  });

  it('removes the query and the fragment of a URL, where a token can travel as well', () => {
    expect(
      cleanExternalText('url https://user:POISON_pw@host.example/x?token=POISON_abc password=x1'),
    ).toBe('url https://host.example/x password=[redacted]');
    expect(
      cleanExternalText('see https://host.example/a/b?sig=POISON_Zm9vYmFy&x=1#frag, then'),
    ).toBe('see https://host.example/a/b then');
    expect(cleanExternalText('open http://host.example/#access=POISON_abc now')).toBe(
      'open http://host.example/ now',
    );
    // Not recognised, and said so in the docs: the query of an address written without a scheme.
    expect(cleanExternalText('call host.example/cb?sig=abc or //host.example/cb?sig=abc')).toBe(
      'call host.example/cb?sig=abc or //host.example/cb?sig=abc',
    );
    // An address without either stays as it is, and so does a question mark in a sentence.
    expect(cleanExternalText('Is https://host.example/a/b.html affected? Yes: see #12')).toBe(
      'Is https://host.example/a/b.html affected? Yes: see #12',
    );
  });

  it('replaces the value of a field that is named like a credential', () => {
    expect(
      cleanExternalText('logs api_key=POISONAKIAIOSFODNN7 and NPM_TOKEN="POISON_npm_abc"'),
    ).toBe('logs api_key=[redacted] and NPM_TOKEN="[redacted]"');
    expect(cleanExternalText('sent as apikey = POISON1 or secret=POISON2; passwd=POISON3')).toBe(
      'sent as apikey = [redacted] or secret=[redacted]; passwd=[redacted]',
    );
    expect(cleanExternalText('client_secret: POISON_abc123def')).toBe('client_secret: [redacted]');
    // The word for the credential may be glued to what stands before it, as in JavaScript.
    expect(
      cleanExternalText('authToken=POISON_ghp_abc npmToken="POISON_npm" sessiontoken=POISON_abc12'),
    ).toBe('authToken=[redacted] npmToken="[redacted]" sessiontoken=[redacted]');
    expect(
      cleanExternalText('appSecret = POISON_s3 and X-API-Key=POISON_k1, myapikey=POISON_k2'),
    ).toBe('appSecret = [redacted] and X-API-Key=[redacted], myapikey=[redacted]');
    // Only the value goes; a name that merely holds the word elsewhere is no credential.
    expect(cleanExternalText('tokenizer=fast secretary=jane broken=1')).toBe(
      'tokenizer=fast secretary=jane broken=1',
    );
    // A sentence about a token is not a field.
    expect(cleanExternalText('Leaks the session token: an attacker can read secret data')).toBe(
      'Leaks the session token: an attacker can read secret data',
    );
  });

  it('replaces tokens, also one whose signature is missing or that is glued to a word', () => {
    expect(cleanExternalText(`leaked ${JWT} in logs`)).toBe('leaked [redacted-token] in logs');
    const unsigned = JWT.slice(0, JWT.lastIndexOf('.'));
    expect(cleanExternalText(`leaked ${unsigned}`)).toBe('leaked [redacted-token]');
    expect(cleanExternalText('send Authorization: Bearer POISON-abcdef123456')).toBe(
      'send Authorization: Bearer [redacted]',
    );
    expect(cleanExternalText('xbearer POISON-abcdef123456')).toBe('xbearer [redacted]');
    expect(cleanExternalText('default password=POISON_hunter2 is accepted')).toBe(
      'default password=[redacted] is accepted',
    );
  });

  it('cuts to the length asked for, and never through a character', () => {
    const long = `${'word '.repeat(60)}end`;
    const cut = cleanExternalText(long);
    expect(cut).toHaveLength(200);
    expect(cut.endsWith('…')).toBe(true);
    expect(cleanExternalText(long, 20)).toBe('word word word word…');
    // The 200th code unit would be the first half of an emoji.
    const emoji = `${'a'.repeat(198)}\u{1f600}tail`;
    const result = cleanExternalText(emoji);
    expect(result).toBe(`${'a'.repeat(198)}…`);
    expect(result).not.toMatch(HALF_CHARACTER);
    expect(cleanExternalText(`${'a'.repeat(197)}\u{1f600}tail`)).toBe(
      `${'a'.repeat(197)}\u{1f600}…`,
    );
    expect(cleanExternalText('half a \ud83d character, and \ude00 another')).toBe(
      'half a character, and another',
    );
  });

  it('gives a text of exactly the length asked for as it is', () => {
    const exact = 'x'.repeat(200);
    expect(cleanExternalText(exact)).toBe(exact);
    expect(cleanExternalText(`${exact}y`)).toBe(`${'x'.repeat(199)}…`);
  });

  it('lets nothing suspicious through when replacements make a long text short', () => {
    // Ten times the length is looked at; an address the cut goes through is dropped whole.
    const filler = `${JWT} `.repeat(40);
    const cleaned = cleanExternalText(`${filler}contact jane.poison@example.com`);
    expectNothingSuspicious(cleaned);
    expect(cleaned).not.toContain('jane');
    const pad = 'x '.repeat((1_990 - 'mail jane.poison@exam'.length) / 2);
    const through = cleanExternalText(`${pad}mail jane.poison@example.com`);
    expect(through).not.toContain('jane');
    // A token of 1,964 characters becomes a few, so that what stood at the cut
    // (after 2,000 characters) is now well within the 200 that are kept: the
    // word the cut went through goes as a whole, not as a half no pattern knows.
    const token = `eyJ${'a'.repeat(980)}.${'b'.repeat(980)}`;
    expect(token).toHaveLength(1_964);
    expect(
      cleanExternalText(`${token} reported by firstname.lastname@example.org and others`),
    ).toBe('[redacted-token] reported by');
    expect(cleanExternalText(`${token} and the key ${JWT} was in it`)).toBe(
      '[redacted-token] and the key',
    );
    expect(
      cleanExternalText(`${token} cloned from https://ci:POISON_token@git.example.com/acme`),
    ).toBe('[redacted-token] cloned from');
    // A word that ends before the cut is read; one that reaches it is dropped.
    expect(cleanExternalText(`${token} ${'x'.repeat(34)} ${'y'.repeat(100)}`)).toBe(
      `[redacted-token] ${'x'.repeat(34)}`,
    );
    expect(cleanExternalText(`${token} ${'x'.repeat(35)} ${'y'.repeat(100)}`)).toBe(
      '[redacted-token]',
    );
    // What takes no room does not count: the text behind it is still read.
    expect(cleanExternalText(`${'\u200b'.repeat(50_000)}short`)).toBe('short');
  });

  it.each([
    ['a megabyte of word characters without a blank', 'a'.repeat(1024 * 1024)],
    ['a megabyte of at signs', '@'.repeat(1024 * 1024)],
    ['a megabyte of dotted words', 'a.'.repeat(512 * 1024)],
    ['a megabyte that starts a token and never ends it', `eyJ${'a-'.repeat(512 * 1024)}`],
    ['a megabyte of escape characters', '\u001b]'.repeat(512 * 1024)],
    ['a megabyte of URL schemes', 'a://'.repeat(256 * 1024)],
    ['a megabyte of blanks', ' '.repeat(1024 * 1024)],
    ['a megabyte of URL queries', 'a://b?'.repeat(128 * 1024)],
    ['a megabyte of one address that never ends', `https://${'a'.repeat(1024 * 1024)}?x`],
    ['a megabyte of names of credentials', 'api_key-token_'.repeat(64 * 1024)],
    ['a megabyte of words that could start such a name', 'a_'.repeat(512 * 1024)],
    // As long as a text is looked at whole: every pattern runs over all of it.
    ['2,000 characters that could start the name of a credential', 'a_'.repeat(1_000)],
    ['2,000 characters of one word that never names a credential', 'toke'.repeat(500)],
    ['2,000 characters of names of credentials without a value', 'token'.repeat(400)],
    ['2,000 characters of names of credentials with an empty value', 'token='.repeat(333)],
    ['2,000 characters of one address with a query', `a://${'a?'.repeat(998)}`],
    ['a megabyte of half characters', '\ud83d'.repeat(1024 * 1024)],
  ])('stays fast on %s', (_name, text) => {
    const start = performance.now();
    const cleaned = cleanExternalText(text);
    expect(performance.now() - start).toBeLessThan(1_000);
    expect(cleaned.length).toBeLessThanOrEqual(200);
    expectNothingSuspicious(cleaned);
  });

  it('is what the leak patterns of the tests cannot find anything in', () => {
    const hostile = [
      `jane.poison@example.com ${JWT} bearer POISON-abcdef123456`,
      'https://user:POISON_pw@host.example/x and ftp://a:POISON_b@c.example',
      'BEARER\u00a0POISON-abcdef123456 Basic\tPOISON-dXNlcjpwYXNz',
      'x@y.example.com\u202e@z.example.org',
      'jane.poison@example.com '.repeat(30),
      'https://host.example/x?access_token=POISON-abcdef123456#id_token=POISON-abcdef123456',
    ];
    for (const text of hostile) expectNothingSuspicious(cleanExternalText(text));
  });
});
