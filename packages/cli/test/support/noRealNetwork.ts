import { afterEach, expect, vi } from 'vitest';

/*
 * No test reaches a real host. Every request of the code under test goes
 * through a fetch the test scripts (`FakeFetch`); where a test forgets to
 * hand one in, the HTTP client would fall back to the global `fetch`. Here
 * that one is replaced for every test file: it answers nothing, and the test
 * that reached it fails, whatever the code under test made of the refusal.
 */

let reached: string[] = [];

vi.stubGlobal('fetch', (input: unknown) => {
  reached.push(String(input instanceof Request ? input.url : input));
  return Promise.reject(new Error('the real network must not be used in a test'));
});

afterEach(() => {
  const requests = reached;
  reached = [];
  expect(requests, 'a test reached the global fetch: hand it a scripted one').toEqual([]);
});
