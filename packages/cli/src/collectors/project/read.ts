import { constants } from 'node:fs';
import { type FileHandle, open } from 'node:fs/promises';
import { parseDocument } from 'yaml';
import { IDENTIFIER_PATTERN } from '../../model/raw.js';

/*
 * Safe file reads for the project collector. A file is opened without
 * following symlinks, checked with fstat to be a regular file within the size
 * limit, rejected when its first bytes look binary (before the rest is
 * read), and read up to the size fstat reported. Every failure is a reason
 * code, never a message: the collector records reasons, and messages from
 * Node or a parser could carry a path or file content.
 */

export const MAX_FILE_BYTES = 2 * 1024 * 1024;
/**
 * The size limit of an npm lockfile, which the caller passes as `maxBytes`:
 * a real lockfile is often larger than the 2 MiB every other file may have
 * (about 500 bytes per package, docs/data-sources.md §12.1).
 */
export const MAX_LOCKFILE_BYTES = 32 * 1024 * 1024;
/** A NUL byte in this many leading bytes marks a file as binary. */
export const NUL_SCAN_BYTES = 8 * 1024;

export type ReadFailure = 'too-large' | 'binary' | 'unreadable';

export type ReadResult =
  { ok: true; text: string; bytes: number } | { ok: false; reason: ReadFailure };

export interface ReadOptions {
  /** The size limit for this file; `MAX_FILE_BYTES` when absent. */
  maxBytes?: number;
}

/**
 * Reads the bytes from `start` up to `end` of the file into the buffer, at
 * the same offsets, and returns where it stopped. One read may return less
 * than it was asked for, so this reads until the range is full or the file
 * ends (a file that shrank since fstat).
 */
async function readRange(
  handle: FileHandle,
  buffer: Buffer,
  start: number,
  end: number,
): Promise<number> {
  let at = start;
  while (at < end) {
    const { bytesRead } = await handle.read(buffer, at, end - at, at);
    if (bytesRead <= 0) break;
    at += bytesRead;
  }
  return at;
}

export async function readProjectFile(
  path: string,
  options: ReadOptions = {},
): Promise<ReadResult> {
  const maxBytes = options.maxBytes ?? MAX_FILE_BYTES;
  // O_NOFOLLOW: a symlink planted at an allow-listed name is refused, not read
  // through. O_NONBLOCK: opening a FIFO for reading must not wait for a writer.
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);
  let handle;
  try {
    handle = await open(path, flags);
  } catch {
    return { ok: false, reason: 'unreadable' };
  }
  try {
    const stats = await handle.stat();
    if (!stats.isFile()) return { ok: false, reason: 'unreadable' };
    if (stats.size > maxBytes) return { ok: false, reason: 'too-large' };
    const buffer = Buffer.alloc(stats.size);
    // The head first: a binary file is given up before the rest of it is read.
    const headEnd = Math.min(buffer.length, NUL_SCAN_BYTES);
    let bytesRead = await readRange(handle, buffer, 0, headEnd);
    if (buffer.subarray(0, bytesRead).includes(0)) return { ok: false, reason: 'binary' };
    if (bytesRead === headEnd) bytesRead = await readRange(handle, buffer, headEnd, buffer.length);
    return { ok: true, text: buffer.toString('utf8', 0, bytesRead), bytes: bytesRead };
  } catch {
    return { ok: false, reason: 'unreadable' };
  } finally {
    await handle.close().catch(() => undefined);
  }
}

/** JSON.parse without its message: a syntax error echoes the source text. */
export function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * YAML with alias expansion bounded (billion laughs), duplicate keys
 * tolerated (last wins, as the cds and mta tools do), merge keys (`<<`)
 * applied as the MTA build tool does, and no source lines in errors. With `logLevel: 'silent'` the parser collects syntax errors instead
 * of throwing them; a document with any is rejected as a whole, and the
 * errors themselves (which quote the source) are dropped.
 */
export function parseYaml(text: string): unknown {
  try {
    const document = parseDocument(text, {
      prettyErrors: false,
      logLevel: 'silent',
      uniqueKeys: false,
      merge: true,
    });
    if (document.errors.length > 0) return undefined;
    return document.toJS({ maxAliasCount: 100 }) as unknown;
  } catch {
    return undefined;
  }
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The value when it is a string, else undefined. */
export function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

/** The value when it is an identifier-shaped string, else null (never an `other` bucket). */
export function identifierOrNull(value: unknown): string | null {
  return typeof value === 'string' && IDENTIFIER_PATTERN.test(value) ? value : null;
}

export function isIdentifier(value: unknown): value is string {
  return typeof value === 'string' && IDENTIFIER_PATTERN.test(value);
}

/** Identifier-shaped strings of an array, in order, up to a limit. */
export function identifiers(value: unknown, max: number): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter(isIdentifier).slice(0, max);
}

/** Plain-object items of an array, up to a limit. */
export function objectItems(value: unknown, max: number): Record<string, unknown>[] {
  if (!Array.isArray(value)) return [];
  return value.filter(isPlainObject).slice(0, max);
}
