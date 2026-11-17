import { open } from 'node:fs/promises';
import { join } from 'node:path';
import { ConfigError } from './http/errors.js';
import { describeFsError, ensurePrivateDir, writePrivateFile } from './io/files.js';
import { SNAPSHOT_SCHEMA_VERSION, type Snapshot, SnapshotSchema } from './model/snapshot.js';

/** snapshot-20260929T031500Z.json: sortable, one file per scan. */
export function snapshotFileName(scannedAt: string): string {
  const stamp = scannedAt.replace(/\.\d+/, '').replace(/[-:]/g, '');
  return `snapshot-${stamp}.json`;
}

/** Larger files are refused before parsing: a snapshot is never this big. */
export const MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024;
const CHUNK_BYTES = 1024 * 1024;

export async function writeSnapshot(snapshot: Snapshot, outDir: string): Promise<string> {
  await ensurePrivateDir(outDir);
  const path = join(outDir, snapshotFileName(snapshot.scannedAt));
  await writePrivateFile(path, `${JSON.stringify(snapshot, null, 2)}\n`);
  return path;
}

/**
 * The file's text, refused once it passes `maxBytes`. The size a regular file
 * reports is checked first; the bytes are counted as they are read too, so a
 * pipe (`--previous <(...)`, /dev/stdin), whose size is not known up front,
 * cannot get past the limit either.
 */
async function readCapped(path: string, maxBytes: number): Promise<string> {
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
    return Buffer.concat(chunks).toString('utf8');
  } finally {
    await handle.close();
  }
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

export async function readSnapshot(
  path: string,
  { maxBytes = MAX_SNAPSHOT_BYTES }: { maxBytes?: number } = {},
): Promise<Snapshot> {
  let json: unknown;
  try {
    json = JSON.parse(await readCapped(path, maxBytes));
  } catch (error) {
    const reason =
      error instanceof SyntaxError
        ? `the file is not valid JSON${jsonErrorLocation(error)}`
        : describeFsError(error);
    throw new ConfigError(`Could not read snapshot ${path}: ${reason}.`);
  }
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
