import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { collectProjectTree } from '../../../src/collectors/project/index.js';
import {
  MAX_FILE_BYTES,
  MAX_LOCKFILE_BYTES,
  NUL_SCAN_BYTES,
} from '../../../src/collectors/project/read.js';
import {
  RemoteSessionError,
  Ssh2ReadOnlySftp,
  type SftpReadRequests,
  entryType,
} from '../../../src/remote/sftp.js';
import { APP_ROOT, SftpProjectTree } from '../../../src/remote/sftpTree.js';
import { lockfileV3, registryEntry } from '../../support/lockfileFixture.js';
import { MemorySftp } from '../../support/memorySftp.js';

const FILE = 0o100644;
const DIR = 0o040755;
const LINK = 0o120777;

type Callback = (error: (Error & { code?: number }) | undefined, ...values: unknown[]) => void;

/**
 * A stand-in for the ssh2 SFTP client: every method call is recorded, the
 * seven read requests are answered from `answers`, and anything else throws.
 * A Proxy, so that a call the wrapper should never make fails loudly.
 */
function fakeSftp(answers: Partial<Record<string, (...args: unknown[]) => void>>) {
  const calls: { method: string; args: unknown[] }[] = [];
  const sftp = new Proxy(
    {},
    {
      get(_target, method: string) {
        return (...args: unknown[]) => {
          calls.push({ method, args });
          const answer = answers[method];
          if (answer === undefined) throw new Error(`unexpected SFTP call: ${method}`);
          answer(...args);
        };
      },
    },
  ) as SftpReadRequests;
  return { sftp, calls };
}

const eof = Object.assign(new Error('End of file'), { code: 1 });

describe('Ssh2ReadOnlySftp', () => {
  it('maps POSIX file types; links and devices are `other`', () => {
    expect(entryType(FILE)).toBe('file');
    expect(entryType(DIR)).toBe('directory');
    expect(entryType(LINK)).toBe('other');
    expect(entryType(0o020666)).toBe('other');
    expect(entryType(undefined)).toBe('other');
  });

  it('lists a directory in batches until EOF and closes the handle', async () => {
    let batch = 0;
    const { sftp, calls } = fakeSftp({
      opendir: (_path, cb) => (cb as Callback)(undefined, Buffer.from('h1')),
      readdir: (_handle, cb) => {
        batch += 1;
        if (batch === 1) {
          (cb as Callback)(undefined, [
            { filename: 'b.cds', longname: '', attrs: { mode: FILE, size: 3, mtime: 7 } },
            { filename: 'srv', longname: '', attrs: { mode: DIR, size: 0, mtime: 7 } },
          ]);
        } else if (batch === 2) {
          (cb as Callback)(undefined, [
            { filename: 'a', longname: '', attrs: { mode: LINK, size: 9 } },
          ]);
        } else {
          (cb as Callback)(eof);
        }
      },
      close: (_handle, cb) => (cb as Callback)(undefined),
    });
    const reader = new Ssh2ReadOnlySftp(sftp, { isClosed: () => false });
    expect(await reader.list('/home/vcap/app', 100)).toEqual([
      { name: 'b.cds', type: 'file', size: 3, mtime: 7 },
      { name: 'srv', type: 'directory', size: 0, mtime: 7 },
      { name: 'a', type: 'other', size: 9, mtime: undefined },
    ]);
    expect(calls.map((c) => c.method)).toEqual([
      'opendir',
      'readdir',
      'readdir',
      'readdir',
      'close',
    ]);
  });

  it('stops reading a directory at the limit', async () => {
    const { sftp, calls } = fakeSftp({
      opendir: (_path, cb) => (cb as Callback)(undefined, Buffer.from('h1')),
      readdir: (_handle, cb) =>
        (cb as Callback)(
          undefined,
          ['a', 'b', 'c'].map((filename) => ({
            filename,
            longname: '',
            attrs: { mode: FILE, size: 1 },
          })),
        ),
      close: (_handle, cb) => (cb as Callback)(undefined),
    });
    const reader = new Ssh2ReadOnlySftp(sftp, { isClosed: () => false });
    expect((await reader.list('/d', 2)).map((e) => e.name)).toEqual(['a', 'b']);
    expect(calls.filter((c) => c.method === 'readdir')).toHaveLength(1);
  });

  it('opens files with the read flag only', async () => {
    const { sftp, calls } = fakeSftp({
      open: (_path, _flags, cb) => (cb as Callback)(undefined, Buffer.from('f1')),
      fstat: (_handle, cb) => (cb as Callback)(undefined, { mode: FILE, size: 2, mtime: 1 }),
      read: (_h, buffer, offset, _length, _position, cb) => {
        (buffer as Buffer).write('hi', offset as number);
        (cb as Callback)(undefined, 2);
      },
      close: (_handle, cb) => (cb as Callback)(undefined),
    });
    const reader = new Ssh2ReadOnlySftp(sftp, { isClosed: () => false });
    const file = await reader.openForReading('/home/vcap/app/package.json');
    expect(await file.stat()).toEqual({ type: 'file', size: 2, mtime: 1 });
    const buffer = Buffer.alloc(2);
    expect(await file.read(buffer, 0, 2, 0)).toBe(2);
    await file.close();
    await file.close();
    expect(calls.map((c) => c.method)).toEqual(['open', 'fstat', 'read', 'close']);
    expect(calls[0]?.args[1]).toBe('r');
  });

  it('sends nothing once the session is closed', async () => {
    const { sftp, calls } = fakeSftp({});
    const reader = new Ssh2ReadOnlySftp(sftp, { isClosed: () => true });
    await expect(reader.lstat('/x')).rejects.toBeInstanceOf(RemoteSessionError);
    await expect(reader.list('/x', 10)).rejects.toBeInstanceOf(RemoteSessionError);
    await expect(reader.openForReading('/x')).rejects.toBeInstanceOf(RemoteSessionError);
    expect(calls).toEqual([]);
  });

  it('treats a request without an answer, or a channel that closed under it, as a lost session', async () => {
    const silent = fakeSftp({ lstat: () => undefined });
    const reader = new Ssh2ReadOnlySftp(silent.sftp, { isClosed: () => false, timeoutMs: 20 });
    await expect(reader.lstat('/x')).rejects.toBeInstanceOf(RemoteSessionError);

    const dropped = fakeSftp({
      lstat: (_path, cb) => (cb as Callback)(new Error('No response from server')),
    });
    const reader2 = new Ssh2ReadOnlySftp(dropped.sftp, { isClosed: () => false });
    await expect(reader2.lstat('/x')).rejects.toBeInstanceOf(RemoteSessionError);
  });

  it('passes on an ordinary error (for example permission denied) as is', async () => {
    const { sftp } = fakeSftp({
      lstat: (_path, cb) =>
        (cb as Callback)(Object.assign(new Error('Permission denied'), { code: 3 })),
    });
    const reader = new Ssh2ReadOnlySftp(sftp, { isClosed: () => false });
    const error = await reader.lstat('/x').catch((e: unknown) => e);
    expect(error).not.toBeInstanceOf(RemoteSessionError);
  });
});

describe('the remote code has no write path', () => {
  const REMOTE = fileURLToPath(new URL('../../../src/remote/', import.meta.url));
  // SFTP and SSH client calls that write, change or run something.
  const FORBIDDEN = [
    /\.write\(/,
    /\.writeFile\(/,
    /\.appendFile\(/,
    /\.fastPut\(/,
    /\.fastGet\(/,
    /\.createWriteStream\(/,
    /\.createReadStream\(/,
    /\.unlink\(/,
    /\.rename\(/,
    /\.mkdir\(/,
    /\.rmdir\(/,
    /\.setstat\(/,
    /\.fsetstat\(/,
    /\.futimes\(/,
    /\.utimes\(/,
    /\.chmod\(/,
    /\.chown\(/,
    /\.symlink\(/,
    /\.ext_openssh/,
    /\.exec\(/,
    /\.shell\(/,
    /\.subsys\(/,
    /\.forwardIn\(/,
    /\.forwardOut\(/,
    /\.openssh_/,
  ];

  it('never calls a mutating SFTP or SSH method', async () => {
    const files = (await readdir(REMOTE)).filter((name) => name.endsWith('.ts'));
    expect(files.length).toBeGreaterThanOrEqual(6);
    for (const name of files) {
      const text = await readFile(join(REMOTE, name), 'utf8');
      for (const pattern of FORBIDDEN)
        expect(text, `${name} matches ${pattern}`).not.toMatch(pattern);
    }
  });

  it('opens files with the read flag and nothing else', async () => {
    const text = await readFile(join(REMOTE, 'sftp.ts'), 'utf8');
    expect(text.match(/this\.sftp\.open\(/g)).toHaveLength(1);
    expect(text).toContain("this.sftp.open(path, 'r', done)");
  });
});

const ZERO = {
  otherRegistry: 0,
  git: 0,
  file: 0,
  link: 0,
  bundled: 0,
  unknown: 0,
  excluded: 0,
  invalid: 0,
};

const app = (files: Record<string, string | { size: number }>) =>
  Object.fromEntries(Object.entries(files).map(([rel, v]) => [`${APP_ROOT}/${rel}`, v]));

describe('SftpProjectTree', () => {
  it('feeds the collector the same allow-list as a local folder and never opens the rest', async () => {
    const sftp = new MemorySftp(
      app({
        'package.json': JSON.stringify({ name: 'acme', cds: { requires: { auth: 'mocked' } } }),
        'xs-app.json': JSON.stringify({ routes: [{ source: '^/(.*)$', localDir: 'resources' }] }),
        'srv/service.cds': 'service S { entity E { key ID : Integer; } }',
        'default-env.json': '{"POISON":"secret"}',
        '.env': 'POISON=1',
        'node_modules/x/package.json': '{}',
        'srv/server.js': 'console.log(1)',
      }),
    );
    const tree = new SftpProjectTree(sftp, { rootName: 'acme-srv' });
    const project = await collectProjectTree(tree, { id: 'acme-srv' });
    expect(project.id).toBe('acme-srv');
    expect(project.files).toEqual(['package.json', 'srv/service.cds', 'xs-app.json']);
    expect(project.repository).toBe(false);
    expect(project.cds.effective.production.authKind).toBe('mocked');
    const opened = sftp.requests.filter((r) => r.startsWith('open '));
    expect(opened.sort()).toEqual([
      `open ${APP_ROOT}/package.json`,
      `open ${APP_ROOT}/srv/service.cds`,
      `open ${APP_ROOT}/xs-app.json`,
    ]);
    expect(sftp.requests.some((r) => r.includes('node_modules'))).toBe(false);
  });

  it('reads a file across short reads and keeps the read limits', async () => {
    const sftp = new MemorySftp(
      app({
        'package.json': '{"name":"acme-long-name"}',
        'app/index.html': 'abc\u0000def',
        'db/data/x-Big.csv': { size: MAX_FILE_BYTES + 1 },
      }),
    );
    const tree = new SftpProjectTree(sftp, { rootName: 'acme' });
    const project = await collectProjectTree(tree);
    expect(project.packageJson.name).toBe('acme-long-name');
    expect(project.unreadable).toEqual([
      { file: 'app/index.html', kind: 'binary' },
      { file: 'db/data/x-Big.csv', kind: 'too-large' },
    ]);
    expect(sftp.requests).not.toContain(`read ${APP_ROOT}/db/data/x-Big.csv`);
  });

  it('refuses a file that changed between the listing and the read (a swap for a link)', async () => {
    const sftp = new MemorySftp(app({ 'package.json': '{}', 'srv/a.cds': 'service A {}' }));
    sftp.swapped.add(`${APP_ROOT}/srv/a.cds`);
    const project = await collectProjectTree(new SftpProjectTree(sftp, { rootName: 'acme' }));
    // A refused read is recorded under the file's kind, exactly as for a local folder.
    expect(project.unreadable).toEqual([{ file: 'srv/a.cds', kind: 'cds' }]);
    expect(sftp.requests).not.toContain(`read ${APP_ROOT}/srv/a.cds`);
  });

  it('ends the collection when the session is lost, instead of reporting a half-read app', async () => {
    const sftp = new MemorySftp(app({ 'package.json': '{}', 'srv/a.cds': 'service A {}' }));
    const tree = new SftpProjectTree(sftp, { rootName: 'acme' });
    const listing = tree.list(APP_ROOT, 100);
    await listing;
    sftp.gone = true;
    await expect(collectProjectTree(tree)).rejects.toBeInstanceOf(RemoteSessionError);
  });

  it('reads ahead only what the collector will read, within the budgets', async () => {
    const sftp = new MemorySftp(
      app({
        'package.json': '{}',
        'a.mtar': { size: 10 },
        '.gitignore': '*.mtar',
        'big.html': { size: MAX_FILE_BYTES + 5 },
        'srv/server.js': 'x',
      }),
    );
    const tree = new SftpProjectTree(sftp, { rootName: 'acme' });
    await tree.list(APP_ROOT, 100);
    await new Promise((resolve) => setTimeout(resolve, 0));
    const opened = sftp.requests.filter((r) => r.startsWith('open ')).sort();
    expect(opened).toEqual([`open ${APP_ROOT}/package.json`]);
  });

  it('does not read lockfiles ahead: an npm lockfile only on request, a foreign one never', async () => {
    const sftp = new MemorySftp(
      app({
        'package.json': '{}',
        'package-lock.json': '{}',
        'npm-shrinkwrap.json': '{}',
        'yarn.lock': '# yarn',
        'pnpm-lock.yaml': 'lockfileVersion: 9',
        'srv/package-lock.json': '{}',
      }),
    );
    const tree = new SftpProjectTree(sftp, { rootName: 'acme' });
    await tree.list(APP_ROOT, 100);
    await tree.list(`${APP_ROOT}/srv`, 100);
    await new Promise((resolve) => setTimeout(resolve, 0));
    const opened = sftp.requests.filter((r) => r.startsWith('open ')).sort();
    expect(opened).toEqual([`open ${APP_ROOT}/package.json`]);
  });

  it('reads a file up to the size limit the caller names, not the one of an ordinary file', async () => {
    const sftp = new MemorySftp(
      app({
        'package.json': '{}',
        'package-lock.json': '0123456789',
        'app/package-lock.json': { size: MAX_FILE_BYTES + 1 },
        'srv/package-lock.json': { size: MAX_LOCKFILE_BYTES + 1 },
      }),
    );
    const tree = new SftpProjectTree(sftp, { rootName: 'acme' });
    const small = `${APP_ROOT}/package-lock.json`;
    expect(await tree.read(small, { maxBytes: 9 })).toEqual({ ok: false, reason: 'too-large' });
    expect(await tree.read(small, { maxBytes: 10 })).toEqual({
      ok: true,
      text: '0123456789',
      bytes: 10,
    });
    expect(await tree.read(small)).toEqual({ ok: true, text: '0123456789', bytes: 10 });

    // Over the limit of an ordinary file: refused by default, read with the limit of a lockfile.
    const medium = `${APP_ROOT}/app/package-lock.json`;
    expect(await tree.read(medium)).toEqual({ ok: false, reason: 'too-large' });
    expect(sftp.requests).not.toContain(`read ${medium}`);
    const result = await tree.read(medium, { maxBytes: MAX_LOCKFILE_BYTES });
    expect(result).not.toEqual({ ok: false, reason: 'too-large' });
    expect(sftp.requests).toContain(`read ${medium}`);

    // Over the limit of a lockfile: refused from its size, never read.
    const large = `${APP_ROOT}/srv/package-lock.json`;
    expect(await tree.read(large, { maxBytes: MAX_LOCKFILE_BYTES })).toEqual({
      ok: false,
      reason: 'too-large',
    });
    expect(sftp.requests).not.toContain(`read ${large}`);
  });

  it('reads the lockfiles of a deployed app through the same step as a local folder', async () => {
    const lockfile = lockfileV3(
      { name: 'acme', dependencies: { 'baip-server': '^2' } },
      {
        'node_modules/baip-server': registryEntry('baip-server', '2.4.1'),
        'node_modules/POISON-private': {
          version: '1.0.0',
          resolved: 'https://npm.POISON.example.com/POISON-private/-/POISON-private-1.0.0.tgz',
        },
      },
    );
    const sftp = new MemorySftp(
      app({
        'package.json': '{ "name": "acme", "dependencies": { "baip-server": "^2" } }',
        'package-lock.json': '{ the loser next to a shrinkwrap file is not opened',
        'npm-shrinkwrap.json': lockfile,
        'yarn.lock': '# POISON_yarn',
        '.npmrc': '//registry.npmjs.org/:_authToken=POISON_token',
        'node_modules/x/package-lock.json': '{}',
      }),
    );
    const project = await collectProjectTree(new SftpProjectTree(sftp, { rootName: 'acme' }));
    expect(project.dependencies).toEqual({
      lockfiles: [
        {
          file: 'npm-shrinkwrap.json',
          kind: 'shrinkwrap',
          lockfileVersion: 3,
          status: 'read',
          kept: 1,
          notKept: { ...ZERO, otherRegistry: 1 },
        },
        {
          file: 'yarn.lock',
          kind: 'yarn',
          lockfileVersion: null,
          status: 'unsupported',
          kept: 0,
          notKept: ZERO,
        },
      ],
      lockfilesNotRead: 0,
      packages: [
        {
          name: 'baip-server',
          version: '2.4.1',
          direct: true,
          scope: 'prod',
          lockfiles: ['npm-shrinkwrap.json'],
        },
      ],
    });
    expect(project.files).toEqual(['npm-shrinkwrap.json', 'package.json']);
    expect(project.filesOpened).toBe(2);
    const opened = sftp.requests.filter((r) => r.startsWith('open ')).sort();
    expect(opened).toEqual([
      `open ${APP_ROOT}/npm-shrinkwrap.json`,
      `open ${APP_ROOT}/package.json`,
    ]);
    expect(sftp.requests.some((r) => r.includes('node_modules'))).toBe(false);
    expect(JSON.stringify(project)).not.toContain('POISON');
  });

  it('gives up a binary file after its first 8 KiB instead of fetching all of it', async () => {
    const binary = `{"lockfileVersion":3,\u0000${'x'.repeat(100_000)}`;
    const sftp = new MemorySftp(
      app({
        'package.json': '{ "name": "acme", "dependencies": { "baip-server": "^2" } }',
        'package-lock.json': binary,
      }),
    );
    const location = `${APP_ROOT}/package-lock.json`;
    const tree = new SftpProjectTree(sftp, { rootName: 'acme' });
    expect(await tree.read(location, { maxBytes: MAX_LOCKFILE_BYTES })).toEqual({
      ok: false,
      reason: 'binary',
    });
    // The fake answers four bytes per request: the head and not one request more.
    const requests = () => sftp.requests.filter((r) => r === `read ${location}`).length;
    expect(requests()).toBe(NUL_SCAN_BYTES / 4);

    // And through the collector: the lockfile is recorded as one that could not be read.
    const project = await collectProjectTree(new SftpProjectTree(sftp, { rootName: 'acme' }));
    expect(requests()).toBe(2 * (NUL_SCAN_BYTES / 4));
    expect(project.dependencies?.lockfiles.map((l) => [l.file, l.status])).toEqual([
      ['package-lock.json', 'unreadable'],
    ]);
    expect(project.unreadable).toEqual([{ file: 'package-lock.json', kind: 'binary' }]);
  });

  it('records a lockfile the tree refuses to read as an unreadable lockfile', async () => {
    const sftp = new MemorySftp(
      app({
        'package.json': '{ "name": "acme", "dependencies": { "baip-server": "^2" } }',
        // Changed between the listing and the read: refused, as a file swapped for a link would be.
        'package-lock.json': lockfileV3(
          { name: 'acme' },
          { 'node_modules/POISON-swapped': registryEntry('POISON-swapped', '1.0.0') },
        ),
        'srv/package-lock.json': lockfileV3(
          { name: 'srv' },
          { 'node_modules/baip-server': registryEntry('baip-server', '2.4.1') },
        ),
      }),
    );
    sftp.swapped.add(`${APP_ROOT}/package-lock.json`);
    const project = await collectProjectTree(new SftpProjectTree(sftp, { rootName: 'acme' }));
    expect(project.dependencies).toEqual({
      lockfiles: [
        {
          file: 'package-lock.json',
          kind: 'package-lock',
          lockfileVersion: null,
          status: 'unreadable',
          kept: 0,
          notKept: ZERO,
        },
        {
          file: 'srv/package-lock.json',
          kind: 'package-lock',
          lockfileVersion: 3,
          status: 'read',
          kept: 1,
          notKept: ZERO,
        },
      ],
      lockfilesNotRead: 0,
      packages: [
        {
          name: 'baip-server',
          version: '2.4.1',
          direct: false,
          scope: 'prod',
          lockfiles: ['srv/package-lock.json'],
        },
      ],
    });
    // Under the reason of a file of its kind, like every other file that is refused.
    expect(project.unreadable).toEqual([{ file: 'package-lock.json', kind: 'json' }]);
    expect(project.files).toEqual(['package.json', 'srv/package-lock.json']);
    expect(project.filesOpened).toBe(project.files.length + project.unreadable.length);
    expect(sftp.requests).not.toContain(`read ${APP_ROOT}/package-lock.json`);
    expect(JSON.stringify(project)).not.toContain('POISON');
  });

  it('says a container is not a repository', async () => {
    const tree = new SftpProjectTree(new MemorySftp({}), { rootName: 'acme' });
    expect(await tree.repository()).toBeNull();
    expect(tree.root).toBe(APP_ROOT);
    expect(tree.join(APP_ROOT, 'x')).toBe(`${APP_ROOT}/x`);
  });
});
