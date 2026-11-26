import { z } from 'zod';
import { type JsonShapeLimits, jsonShapeExcess } from '../io/jsonShape.js';
import { LOCKED_PACKAGE_NAME_PATTERN, PACKAGE_VERSION_PATTERN } from '../model/raw.js';
import { HttpBodyTooLargeError, HttpNetworkError } from './errors.js';
import type { HttpResponse, ReadOnlyHttp } from './httpClient.js';

/*
 * The client for the public npm registry (docs/data-sources.md §12.4):
 * whether a version of a package is deprecated, and what the registry calls
 * the latest version of that package. Two requests, both a GET of two path
 * segments: `/<package>/<version>` and `/<package>/latest`. They carry the
 * name and the version of a public npm package and nothing else: no
 * credential, no cookie, no query string, no identifier of the project the
 * package was found in. The client is typed against the read-only view of
 * the HTTP layer, so it has no way to send another method or a body; the
 * HTTP client repeats a request after a network error, a 429 or a 5xx
 * answer, and follows no redirect.
 *
 * An answer of the registry describes a whole release: its dependencies, its
 * files, and the people who maintain and published it, with their e-mail
 * addresses (`maintainers`, `_npmUser`, `author`, `contributors`). Of all
 * that two fields are read, `version` and `deprecated`; the schema drops
 * every other key before anything is handed on. The answer is treated as
 * hostile text until it is parsed: bounded in bytes, in nesting and in the
 * number of its values before `JSON.parse` sees it, and refused as a whole
 * when it is not about the version that was asked for.
 */

export const NPM_REGISTRY_HOST = 'registry.npmjs.org';
const NPM_REGISTRY_ORIGIN = `https://${NPM_REGISTRY_HOST}`;
/** The dist-tag every package has: the version `npm install <package>` takes. */
const LATEST = 'latest';

/**
 * A version document takes a few kilobytes; one with a very large `exports`
 * map about 110 KB (measured on 2026-11-25). The readme is not part of it.
 */
const ANSWER_MAX_BYTES = 1024 * 1024;
const MAX_PACKAGE_NAME_LENGTH = 214;
const MAX_PACKAGE_VERSION_LENGTH = 64;

/*
 * What an answer may cost to parse. A version document nests a few levels
 * (the conditions of an `exports` entry) and holds some thousand values; its
 * widest object is the `exports` map, with one key per entry point of the
 * package, thousands for some.
 */
const ANSWER_SHAPE: JsonShapeLimits = { maxDepth: 32, maxItems: 200_000, maxMembers: 50_000 };

/** Why a request to the registry gave no usable answer. */
export type NpmRegistryFailure = 'unreachable' | 'status' | 'unexpected';

/**
 * A request to the npm registry that gave no usable answer. The message is
 * one of three fixed sentences: it is recorded as the reason of a skipped
 * check and must never repeat what a server sent.
 */
export class NpmRegistryError extends Error {
  override readonly name = 'NpmRegistryError';

  constructor(
    readonly failure: NpmRegistryFailure,
    /** The HTTP status, for `status`. */
    readonly status?: number,
  ) {
    super(
      failure === 'unreachable'
        ? `${NPM_REGISTRY_HOST} could not be reached`
        : failure === 'status'
          ? `${NPM_REGISTRY_HOST} answered HTTP ${status ?? 0}`
          : `${NPM_REGISTRY_HOST} sent an unexpected answer`,
    );
  }
}

/** A version of a package as far as BAIP Lens reads it from the registry. */
export interface RegistryVersion {
  /** The version the answer is about, in the registry's words. */
  version: string;
  /**
   * The deprecation message, as it came: external text, to be cleaned and
   * cut before it is stored. Empty for a version that is deprecated without
   * a reason; null for one that is not deprecated.
   */
  deprecated: string | null;
}

/** Only these two keys are read; `z.object` drops every other one, the people behind the package included. */
const VersionSchema = z.object({ version: z.string(), deprecated: z.unknown().optional() });

function unexpected(): NpmRegistryError {
  return new NpmRegistryError('unexpected');
}

/** Thrown before anything is sent: a mistake of the caller, never an answer. */
function notRequestable(): Error {
  return new Error('not a package name and version that can be looked up');
}

function isPackageName(value: string): boolean {
  return value.length <= MAX_PACKAGE_NAME_LENGTH && LOCKED_PACKAGE_NAME_PATTERN.test(value);
}

function isPackageVersion(value: string): boolean {
  return value.length <= MAX_PACKAGE_VERSION_LENGTH && PACKAGE_VERSION_PATTERN.test(value);
}

/**
 * The version that is asked for: without its build metadata. `1.4.0+build.7`
 * is the release `1.4.0`, and a `+` has no place in the one path shape the
 * allow-list lets through.
 */
export function requestedVersion(version: string): string {
  const plus = version.indexOf('+');
  return plus === -1 ? version : version.slice(0, plus);
}

/**
 * The path segment of a package: its name, a scoped one with its slash
 * encoded (`@scope%2fname`). The registry answers both spellings of a scoped
 * name; this one keeps every request at two segments.
 */
function packageSegment(name: string): string {
  const slash = name.indexOf('/');
  return slash === -1 ? name : `${name.slice(0, slash)}%2f${name.slice(slash + 1)}`;
}

/**
 * Deprecated is a version whose `deprecated` is a text that is not empty, or
 * `true` (no reason given). An empty text is how a deprecation is taken
 * back, so it counts like no field at all, and so does every other value.
 */
function deprecationOf(value: unknown): string | null {
  if (typeof value === 'string') return value === '' ? null : value;
  return value === true ? '' : null;
}

/** The two fields of an answer, once its shape is within what parsing may cost. */
function parseVersion(text: string): RegistryVersion {
  if (jsonShapeExcess(Buffer.from(text, 'utf8'), ANSWER_SHAPE) !== undefined) throw unexpected();
  let json: unknown;
  try {
    json = JSON.parse(text) as unknown;
  } catch {
    // Not JSON: the page of a gateway, or an answer that was cut off.
    throw unexpected();
  }
  const answer = VersionSchema.safeParse(json);
  // A version document always names its version. An object without one is
  // not an answer of the registry to this request (a gateway or a portal can
  // answer 200 as well), and "not deprecated" must not be read into it.
  if (!answer.success) throw unexpected();
  return { version: answer.data.version, deprecated: deprecationOf(answer.data.deprecated) };
}

export class NpmRegistryClient {
  constructor(private readonly http: ReadOnlyHttp) {}

  /**
   * `GET /<package>/<version>`: what the registry says about that version,
   * or null when it does not know it (404): a version that was unpublished,
   * or a package that is not public after all. Any other answer than those
   * two is a failure, and so is a document about another version.
   */
  async version(name: string, version: string): Promise<RegistryVersion | null> {
    if (!isPackageName(name) || !isPackageVersion(version)) throw notRequestable();
    const asked = requestedVersion(version);
    const answer = await this.read(name, asked);
    if (answer !== null && requestedVersion(answer.version) !== asked) throw unexpected();
    return answer;
  }

  /**
   * `GET /<package>/latest`: the version the registry tags as the latest of
   * the package, or null when it names none (404). The version is handed on
   * as it came: whether it is one that can be stored is the caller's to say.
   */
  async latest(name: string): Promise<RegistryVersion | null> {
    if (!isPackageName(name)) throw notRequestable();
    return this.read(name, LATEST);
  }

  /** The document at `/<package>/<last>`; null for a 404, an `NpmRegistryError` for every other outcome. */
  private async read(name: string, last: string): Promise<RegistryVersion | null> {
    const path = `/${packageSegment(name)}/${last}`;
    const url = new URL(path, NPM_REGISTRY_ORIGIN);
    // The address must read as it was written: two segments, no query, nothing resolved away.
    if (url.pathname !== path || url.search !== '' || url.hash !== '') throw notRequestable();
    let response: HttpResponse;
    try {
      response = await this.http.get({ url, maxBytes: ANSWER_MAX_BYTES });
    } catch (error) {
      if (error instanceof HttpNetworkError) throw new NpmRegistryError('unreachable');
      if (error instanceof HttpBodyTooLargeError) throw unexpected();
      throw error;
    }
    if (response.status === 404) return null;
    if (response.status !== 200) throw new NpmRegistryError('status', response.status);
    return parseVersion(response.text);
  }
}
