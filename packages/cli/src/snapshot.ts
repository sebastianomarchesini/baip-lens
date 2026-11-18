import { open } from 'node:fs/promises';
import { join } from 'node:path';
import { ConfigError } from './http/errors.js';
import { describeFsError, ensurePrivateDir, writePrivateFile } from './io/files.js';
import { type JsonShapeLimit, jsonShapeExcess } from './io/jsonShape.js';
import { SNAPSHOT_SCHEMA_VERSION, type Snapshot, SnapshotSchema } from './model/snapshot.js';

/** snapshot-20260929T031500Z.json: sortable, one file per scan. */
export function snapshotFileName(scannedAt: string): string {
  const stamp = scannedAt.replace(/\.\d+/, '').replace(/[-:]/g, '');
  return `snapshot-${stamp}.json`;
}

/*
 * What a snapshot file may be, checked before it is parsed
 * (docs/security-review.md SEC-21). A snapshot from someone else is
 * untrusted: parsed, a few megabytes of `{}` would cost gigabytes. A scan
 * writes about 3.2 KB and 84 values per app, so these hold about 42,000 apps
 * (50,000 written without whitespace). Each list has its own limit as well
 * (`model/list.ts`).
 */
/** Larger files are refused before they are read in full. */
export const MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024;
/** A snapshot nests 11 levels at most (the roles of an entity in a project's service). */
export const MAX_SNAPSHOT_DEPTH = 64;
/**
 * One value per 32 bytes over the whole size limit. A scan writes one per 35
 * to 47 bytes; minified, one per 27, so a minified file meets this limit first.
 */
export const MAX_SNAPSHOT_VALUES = 4 * 1024 * 1024;
const CHUNK_BYTES = 1024 * 1024;

const SHAPE_REASONS: Record<JsonShapeLimit, string> = {
  depth: `it nests more than ${MAX_SNAPSHOT_DEPTH} levels deep`,
  values: `it holds more than ${MAX_SNAPSHOT_VALUES.toLocaleString('en-US')} values`,
};

export async function writeSnapshot(snapshot: Snapshot, outDir: string): Promise<string> {
  await ensurePrivateDir(outDir);
  const path = join(outDir, snapshotFileName(snapshot.scannedAt));
  await writePrivateFile(path, `${JSON.stringify(snapshot, null, 2)}\n`);
  return path;
}

/**
 * The file's bytes, refused once they pass `maxBytes`. The size a regular file
 * reports is checked first; the bytes are counted as they are read too, so a
 * pipe (`--previous <(...)`, /dev/stdin), whose size is not known up front,
 * cannot get past the limit either.
 */
async function readCapped(path: string, maxBytes: number): Promise<Buffer> {
  const handle = await open(path, 'r');
  try {
    const { size } = await handle.stat();
    if (size > maxBytes) throw new Error(`file is ${size} bytes, the limit is ${maxBytes}`);
    const chunks: Buffer[] = [];
    let total = 0;
    for (;;) {
      const buffer = Buffer.alloc(CHUNK_BYTES);
      const { bytesRead } = await handle.read(buffer, 0, CHUNK_BYTES, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maxBytes)
        throw new Error(`file is over ${maxBytes} bytes, the limit is ${maxBytes}`);
      chunks.push(buffer.subarray(0, bytesRead));
    }
    return Buffer.concat(chunks, total);
  } finally {
    await handle.close();
  }
}

/** The file's text, once its size and its JSON shape are within the limits. */
async function readText(path: string, maxBytes: number): Promise<string> {
  let bytes: Buffer;
  try {
    bytes = await readCapped(path, maxBytes);
  } catch (error) {
    throw new ConfigError(`Could not read snapshot ${path}: ${describeFsError(error)}.`);
  }
  const excess = jsonShapeExcess(bytes, {
    maxDepth: MAX_SNAPSHOT_DEPTH,
    maxValues: MAX_SNAPSHOT_VALUES,
  });
  if (excess !== undefined) {
    throw new ConfigError(`Snapshot ${path} is not valid: ${SHAPE_REASONS[excess]}.`);
  }
  // The bytes are not kept: only the text reaches the parser.
  return bytes.toString('utf8');
}

/**
 * Where the JSON broke, from the parser's message, digits only: the message
 * also quotes the start of the input, which may be a secret pasted by mistake.
 */
function jsonErrorLocation(error: SyntaxError): string {
  const lineColumn = /line (\d+) column (\d+)/.exec(error.message);
  if (lineColumn) return ` at line ${lineColumn[1]}, column ${lineColumn[2]}`;
  const position = /at position (\d+)/.exec(error.message);
  return position ? ` at position ${position[1]}` : '';
}

/** The file parsed as JSON; its text is not kept either. */
async function readJson(path: string, maxBytes: number): Promise<unknown> {
  const text = await readText(path, maxBytes);
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    const reason =
      error instanceof SyntaxError
        ? `the file is not valid JSON${jsonErrorLocation(error)}`
        : describeFsError(error);
    throw new ConfigError(`Could not read snapshot ${path}: ${reason}.`);
  }
}

/**
 * A snapshot from a file, for `report --from` and `scan --previous`. The file
 * may come from someone else, so whatever it holds, reading it ends quickly,
 * in a snapshot or in a `ConfigError` (exit code 2) that names what is wrong
 * without quoting the file (docs/security-review.md SEC-21).
 */
export async function readSnapshot(
  path: string,
  { maxBytes = MAX_SNAPSHOT_BYTES }: { maxBytes?: number } = {},
): Promise<Snapshot> {
  const json = await readJson(path, maxBytes);
  const version = (json as { schemaVersion?: unknown } | null)?.schemaVersion;
  if (version !== SNAPSHOT_SCHEMA_VERSION) {
    throw new ConfigError(
      `Snapshot ${path} has schema version ${String(version)}; this baip-lens reads version ${SNAPSHOT_SCHEMA_VERSION}.`,
    );
  }
  const parsed = SnapshotSchema.safeParse(json);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new ConfigError(
      `Snapshot ${path} is not valid: ${issue ? `${issue.path.join('.')}: ${issue.message}` : 'unknown error'}`,
    );
  }
  return parsed.data;
}
