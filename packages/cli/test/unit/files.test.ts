import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { ConfigError } from '../../src/http/errors.js';
import { ensurePrivateDir, writePrivateFile } from '../../src/io/files.js';
import { MAX_SNAPSHOT_BYTES, readSnapshot } from '../../src/snapshot.js';
import { nested, readFixture, repeated, withJsonAt } from '../support/snapshotText.js';

const posix = process.platform !== 'win32';
const sample = readFixture('sample-snapshot.json');

const created: string[] = [];
afterAll(async () => {
  await Promise.all(created.map((dir) => rm(dir, { recursive: true, force: true })));
});

/** `text` in a file of its own, removed after the tests. */
async function written(name: string, text: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'baip-lens-read-'));
  created.push(dir);
  const path = join(dir, name);
  await writeFile(path, text);
  return path;
}

/** The error reading `path` ends in; it must be the one the CLI turns into exit code 2. */
async function refusal(path: string): Promise<ConfigError> {
  const error = await readSnapshot(path).then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(ConfigError);
  return error as ConfigError;
}

describe('private output files', () => {
  it.skipIf(!posix)('creates directories 0700 and files 0600', async () => {
    const base = await mkdtemp(join(tmpdir(), 'baip-lens-files-'));
    const dir = join(base, 'nested', 'reports');
    await ensurePrivateDir(dir);
    await writePrivateFile(join(dir, 'report.json'), '{}');
    expect((await stat(dir)).mode & 0o777).toBe(0o700);
    expect((await stat(join(dir, 'report.json'))).mode & 0o777).toBe(0o600);
  });
});

describe('private output files: symlinks and existing files', () => {
  it.skipIf(!posix)(
    'refuses to write through a symlink and tightens an existing file',
    async () => {
      const base = await mkdtemp(join(tmpdir(), 'baip-lens-files-'));
      const target = join(base, 'target.json');
      await writeFile(target, 'keep', { mode: 0o644 });
      const link = join(base, 'report.json');
      await symlink(target, link);
      await expect(writePrivateFile(link, '{}')).rejects.toThrow(/symbolic link/);
      expect(await readFile(target, 'utf8')).toBe('keep');
      await writePrivateFile(target, '{}');
      expect((await stat(target)).mode & 0o777).toBe(0o600);
    },
  );

  it('explains missing files and bad JSON in plain words', async () => {
    await expect(readSnapshot(join(tmpdir(), 'no-such-dir', 'snapshot.json'))).rejects.toThrow(
      /does not exist/,
    );
    const base = await mkdtemp(join(tmpdir(), 'baip-lens-json-'));
    const path = join(base, 'bad.json');
    await writeFile(path, '{not json');
    await expect(readSnapshot(path)).rejects.toThrow(
      /not valid JSON at (line 1, column 2|position 1)\./,
    );
    await expect(ensurePrivateDir(join(path, 'nested'))).rejects.toThrow(/not a folder/);
  });

  it('never quotes the content of a file that is not JSON', async () => {
    const base = await mkdtemp(join(tmpdir(), 'baip-lens-json-'));
    const path = join(base, 'token.txt');
    // A secret passed by mistake: the parser's own message would quote its start.
    // Marked POISON, like every planted secret, so the secret scan lets it through.
    await writeFile(path, 'sk_live_51HxQzK9-POISON');
    const error = await readSnapshot(path).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(String(error)).toMatch(/not valid JSON/);
    expect(String(error)).not.toContain('sk_live');
  });
});

describe('readSnapshot limits', () => {
  it('refuses a snapshot above the size cap without parsing it', async () => {
    const base = await mkdtemp(join(tmpdir(), 'baip-lens-big-'));
    const path = join(base, 'huge.json');
    // A sparse file: the size is what matters, not the content.
    const handle = await import('node:fs/promises').then((fs) => fs.open(path, 'w'));
    await handle.truncate(MAX_SNAPSHOT_BYTES + 1);
    await handle.close();
    await expect(readSnapshot(path)).rejects.toThrow(/the limit is/);
  });

  it.skipIf(!posix)('refuses a pipe that streams past the size cap', async () => {
    const base = await mkdtemp(join(tmpdir(), 'baip-lens-fifo-'));
    const fifo = join(base, 'snapshot.json');
    execFileSync('mkfifo', [fifo]);
    // A pipe reports no useful size up front, so the bytes are counted as read.
    const writing = writeFile(fifo, `"${'x'.repeat(64 * 1024)}"`).catch(() => undefined);
    await expect(readSnapshot(fifo, { maxBytes: 1024 })).rejects.toThrow(/the limit is 1024/);
    await writing;
  });

  it('refuses a snapshot nested deeper than 64 levels before parsing it', async () => {
    const path = await written(
      'deep.json',
      // Under a finding's evidence, which the schema keeps as it is: the
      // reporters would overflow the stack writing it out.
      withJsonAt(sample, ['findings', 0, 'evidence', 'deep'], nested('0', 10_000)),
    );
    expect((await refusal(path)).message).toMatch(
      /^Snapshot .*deep\.json is not valid: it nests more than 64 levels deep\.$/,
    );
  });

  it('refuses a snapshot with more than 4,194,304 keys and values before parsing it', async () => {
    const path = await written(
      'dense.json',
      withJsonAt(sample, ['scope', 'orgs'], repeated('0', 4_194_304)),
    );
    expect((await refusal(path)).message).toMatch(
      /^Snapshot .*dense\.json is not valid: it holds more than 4,194,304 keys and values\.$/,
    );
  });

  it('refuses an object with more than 1,000 keys before parsing it', async () => {
    const keys = Array.from({ length: 1_001 }, (_, i) => `"k${i}":0`).join(',');
    const path = await written(
      'wide.json',
      withJsonAt(sample, ['findings', 0, 'evidence'], `{${keys}}`),
    );
    expect((await refusal(path)).message).toMatch(
      /^Snapshot .*wide\.json is not valid: an object in it has more than 1,000 keys\.$/,
    );
  });

  it('rejects unknown schema versions with a clear message', async () => {
    const path = await written('old.json', JSON.stringify({ schemaVersion: 0 }));
    expect((await refusal(path)).message).toMatch(/has schema version 0; this baip-lens reads/);
  });

  it('never quotes a schema version that is not a number', async () => {
    // Marked POISON, like every planted secret, so the secret scan lets it through.
    const secret = await written('secret.json', '{"schemaVersion":"sk_live_51HxQzK9-POISON"}');
    const quoted = (await refusal(secret)).message;
    expect(quoted).toMatch(/has a schema version that is not a number/);
    expect(quoted).not.toContain('sk_live');
    const odd = await written('odd.json', '{"schemaVersion":{"toString":0}}');
    expect((await refusal(odd)).message).toMatch(/has a schema version that is not a number/);
    const none = await written('none.json', '[]');
    expect((await refusal(none)).message).toMatch(/has no schema version/);
  });
});
