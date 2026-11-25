import { afterEach, expect, vi } from 'vitest';

/*
 * No test reaches a real host. Every request of the code under test goes
 * through a fetch the test scripts (`FakeFetch`); where a test forgets to
 * hand one in, the HTTP client would fall back to the global `fetch`. Here
 * that one is replaced for every test file: it answers nothing, and the test
 * that reached it fails, whatever the code under test made of the refusal.
 */

let reached: string[] = [];

/**
 * The addresses the global fetch was asked for since the last look, which
 * are then forgotten. It hangs on the replaced `fetch` itself, as
 * `fetch.takeReached`, for the one test that reaches it on purpose
 * (test/unit/noRealNetwork.test.ts): that test shows that this file is
 * loaded, so it must find the guard without importing it.
 */
function takeReached(): string[] {
  const requests = reached;
  reached = [];
  return requests;
}

function refuse(input: unknown): Promise<never> {
  reached.push(String(input instanceof Request ? input.url : input));
  return Promise.reject(new Error('the real network must not be used in a test'));
}

vi.stubGlobal('fetch', Object.assign(refuse, { takeReached }));

afterEach(() => {
  expect(takeReached(), 'a test reached the global fetch: hand it a scripted one').toEqual([]);
});
