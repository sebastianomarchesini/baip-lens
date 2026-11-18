import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ensurePrivateDir, writePrivateFile } from '../../src/io/files.js';
import { MAX_SNAPSHOT_BYTES, readSnapshot } from '../../src/snapshot.js';
import { nested, readFixture, repeated, withJsonAt } from '../support/snapshotText.js';

const posix = process.platform !== 'win32';
const sample = readFixture('sample-snapshot.json');

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
    const path = join(await mkdtemp(join(tmpdir(), 'baip-lens-deep-')), 'deep.json');
    // Under a finding's evidence, which the schema keeps as it is: the
    // reporters would overflow the stack writing it out.
    await writeFile(
      path,
      withJsonAt(sample, ['findings', 0, 'evidence', 'deep'], nested('0', 10_000)),
    );
    await expect(readSnapshot(path)).rejects.toThrow(
      /^Snapshot .*deep\.json is not valid: it nests more than 64 levels deep\.$/,
    );
  });

  it('refuses a snapshot with more than 4,194,304 values before parsing it', async () => {
    const path = join(await mkdtemp(join(tmpdir(), 'baip-lens-dense-')), 'dense.json');
    await writeFile(path, withJsonAt(sample, ['scope', 'orgs'], repeated('0', 4_194_304)));
    await expect(readSnapshot(path)).rejects.toThrow(
      /^Snapshot .*dense\.json is not valid: it holds more than 4,194,304 values\.$/,
    );
  });

  it('rejects unknown schema versions with a clear message', async () => {
    const base = await mkdtemp(join(tmpdir(), 'baip-lens-ver-'));
    const path = join(base, 'old.json');
    await writeFile(path, JSON.stringify({ schemaVersion: 0 }));
    await expect(readSnapshot(path)).rejects.toThrow(/schema version 0/);
  });
});
