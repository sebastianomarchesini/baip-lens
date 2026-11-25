import { describe, expect, it } from 'vitest';
import { HttpNetworkError } from '../../src/http/errors.js';
import { HttpClient } from '../../src/http/httpClient.js';
import { EgressPolicy } from '../../src/net/allowlist.js';
import { noSleep } from '../support/fakeFetch.js';

/*
 * The guard of test/support/noRealNetwork.ts is installed for every test
 * file by vitest.config.ts (`setupFiles`). Nothing else would notice if that
 * line were lost: the HTTP client falls back to the global fetch when a test
 * hands it none, and the suite would start to talk to real hosts. So this
 * file does not import the guard: it finds it in place, or fails.
 */

const QUERYBATCH = 'https://api.osv.dev/v1/querybatch';

/** What the guard remembers, looked at before `fetch` is called: without it no request is made here either. */
function reachedSoFar(): string[] {
  const guard = globalThis.fetch as typeof fetch & { takeReached?: () => string[] };
  expect(
    typeof guard.takeReached,
    'test/support/noRealNetwork.ts is not loaded: see setupFiles in vitest.config.ts',
  ).toBe('function');
  return guard.takeReached?.() ?? [];
}

describe('the global fetch in a test', () => {
  it('answers nothing, and remembers that it was reached', async () => {
    expect(reachedSoFar()).toEqual([]);
    await expect(fetch(QUERYBATCH)).rejects.toThrow('the real network must not be used in a test');
    await expect(fetch(new Request(QUERYBATCH, { method: 'POST' }))).rejects.toThrow(
      'the real network must not be used in a test',
    );
    // Taken here: left in place, it would fail this test, as it fails any other that reaches it.
    expect(reachedSoFar()).toEqual([QUERYBATCH, QUERYBATCH]);
    expect(reachedSoFar()).toEqual([]);
  });

  it('is what an HTTP client without a scripted fetch falls back to', async () => {
    expect(reachedSoFar()).toEqual([]);
    const http = new HttpClient({
      policy: new EgressPolicy(),
      userAgent: 'baip-lens/test',
      sleep: noSleep,
      maxRetries: 1,
    });
    const request = http.request({ url: new URL(QUERYBATCH), method: 'POST', body: '{}' });
    await expect(request).rejects.toBeInstanceOf(HttpNetworkError);
    expect(reachedSoFar()).toEqual([QUERYBATCH, QUERYBATCH]);
  });
});
