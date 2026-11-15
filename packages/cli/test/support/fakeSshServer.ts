import { createHash } from 'node:crypto';
import { type FileHandle, lstat, open, readdir } from 'node:fs/promises';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import {
  type Attributes,
  type Connection,
  type ParsedKey,
  Server,
  type SFTPWrapper,
  utils,
} from 'ssh2';

/*
 * A real SSH server on 127.0.0.1 standing in for the platform's app SSH
 * proxy and one container: it serves a local folder at /home/vcap/app over
 * SFTP and records everything a client asks for: logins, channels and every
 * SFTP request. Only the read requests BAIP Lens is allowed to send are
 * implemented; anything else is answered "unsupported" and recorded, so a
 * test can prove that nothing but reads ever reached the container.
 */

export const CONTAINER_ROOT = '/home/vcap/app';

const STATUS = { OK: 0, EOF: 1, NO_SUCH_FILE: 2, FAILURE: 4, OP_UNSUPPORTED: 8 } as const;
/** pkg/sftp, which the Diego SSH daemon uses, answers a READ with at most 32 KiB. */
const MAX_READ = 32 * 1024;

const SFTP_REQUESTS = [
  'OPEN',
  'READ',
  'WRITE',
  'FSTAT',
  'FSETSTAT',
  'CLOSE',
  'OPENDIR',
  'READDIR',
  'LSTAT',
  'STAT',
  'REMOVE',
  'RMDIR',
  'REALPATH',
  'READLINK',
  'SETSTAT',
  'MKDIR',
  'RENAME',
  'SYMLINK',
  'EXTENDED',
] as const;
export const READ_REQUESTS = new Set([
  'OPEN',
  'READ',
  'FSTAT',
  'CLOSE',
  'OPENDIR',
  'READDIR',
  'LSTAT',
]);

export interface SftpRequest {
  type: string;
  /** The container path, for path requests and for requests on a handle opened from one. */
  path?: string;
  /** For OPEN: the flags as ssh2 spells them ('r', 'w', 'a+', ...). */
  flags?: string;
}

export interface FakeSshServer {
  host: string;
  port: number;
  /** `127.0.0.1:<port>`, as `links.app_ssh.href` would carry it. */
  href: string;
  /** SHA-256 base64 fingerprint of the host key, as the CF root publishes it. */
  fingerprint: string;
  connections: number;
  logins: { method: string; username: string; password?: string }[];
  /** Session channel requests: 'sftp', 'exec', 'shell', 'pty', 'env', 'tcpip', ... */
  channels: string[];
  requests: SftpRequest[];
  close(): Promise<void>;
}

export interface FakeSshOptions {
  /** The folder served at /home/vcap/app. */
  appDir: string;
  username: string;
  password: string;
}

/** The SHA-256 base64 fingerprint (43 characters) of a public key, OpenSSH style. */
export function sha256Fingerprint(publicKey: string): string {
  const parsed = utils.parseKey(publicKey) as ParsedKey;
  return createHash('sha256').update(parsed.getPublicSSH()).digest('base64').replace(/=+$/, '');
}

/** A fresh ed25519 key pair in OpenSSH format. */
export function newHostKey(): { private: string; public: string } {
  return utils.generateKeyPairSync('ed25519');
}

async function attrsOf(path: string): Promise<Attributes> {
  const stats = await lstat(path);
  return {
    mode: stats.mode,
    uid: stats.uid,
    gid: stats.gid,
    size: stats.size,
    atime: Math.floor(stats.atimeMs / 1000),
    mtime: Math.floor(stats.mtimeMs / 1000),
  };
}

function serveSftp(sftp: SFTPWrapper, appDir: string, record: (r: SftpRequest) => void): void {
  const files = new Map<string, { file: FileHandle; path: string }>();
  const dirs = new Map<string, { path: string; done: boolean }>();
  let next = 0;
  const newHandle = (): Buffer => Buffer.from(String((next += 1)));
  const local = (path: string): string | null => {
    if (path === CONTAINER_ROOT) return appDir;
    if (!path.startsWith(`${CONTAINER_ROOT}/`)) return null;
    const rel = path.slice(CONTAINER_ROOT.length + 1);
    if (rel.split('/').some((s) => s === '' || s === '.' || s === '..')) return null;
    return join(appDir, ...rel.split('/'));
  };

  for (const type of SFTP_REQUESTS) {
    if (READ_REQUESTS.has(type)) continue;
    sftp.on(type, (reqid: number) => {
      record({ type });
      sftp.status(reqid, STATUS.OP_UNSUPPORTED);
    });
  }

  sftp.on('OPEN', (reqid, filename, flags) => {
    const flagText = utils.sftp.flagsToString(flags) ?? String(flags);
    record({ type: 'OPEN', path: filename, flags: flagText });
    const path = local(filename);
    if (path === null || flagText !== 'r') return sftp.status(reqid, STATUS.FAILURE);
    open(path, 'r').then(
      (file) => {
        const handle = newHandle();
        files.set(handle.toString(), { file, path: filename });
        sftp.handle(reqid, handle);
      },
      () => sftp.status(reqid, STATUS.NO_SUCH_FILE),
    );
  });

  sftp.on('FSTAT', (reqid, handle) => {
    const entry = files.get(handle.toString());
    record({ type: 'FSTAT', path: entry?.path });
    if (entry === undefined) return sftp.status(reqid, STATUS.FAILURE);
    entry.file.stat().then(
      (stats) =>
        sftp.attrs(reqid, {
          mode: stats.mode,
          uid: stats.uid,
          gid: stats.gid,
          size: stats.size,
          atime: Math.floor(stats.atimeMs / 1000),
          mtime: Math.floor(stats.mtimeMs / 1000),
        }),
      () => sftp.status(reqid, STATUS.FAILURE),
    );
  });

  sftp.on('READ', (reqid, handle, offset, length) => {
    const entry = files.get(handle.toString());
    record({ type: 'READ', path: entry?.path });
    if (entry === undefined) return sftp.status(reqid, STATUS.FAILURE);
    const buffer = Buffer.alloc(Math.min(length, MAX_READ));
    entry.file.read(buffer, 0, buffer.length, offset).then(
      ({ bytesRead }) =>
        bytesRead === 0
          ? sftp.status(reqid, STATUS.EOF)
          : sftp.data(reqid, buffer.subarray(0, bytesRead)),
      () => sftp.status(reqid, STATUS.FAILURE),
    );
  });

  sftp.on('OPENDIR', (reqid, path) => {
    record({ type: 'OPENDIR', path });
    const dir = local(path);
    if (dir === null) return sftp.status(reqid, STATUS.NO_SUCH_FILE);
    lstat(dir).then(
      (stats) => {
        if (!stats.isDirectory()) return sftp.status(reqid, STATUS.FAILURE);
        const handle = newHandle();
        dirs.set(handle.toString(), { path, done: false });
        sftp.handle(reqid, handle);
      },
      () => sftp.status(reqid, STATUS.NO_SUCH_FILE),
    );
  });

  sftp.on('READDIR', (reqid, handle) => {
    const entry = dirs.get(handle.toString());
    record({ type: 'READDIR', path: entry?.path });
    if (entry === undefined) return sftp.status(reqid, STATUS.FAILURE);
    if (entry.done) return sftp.status(reqid, STATUS.EOF);
    entry.done = true;
    const dir = local(entry.path) ?? '';
    readdir(dir)
      .then((names) =>
        Promise.all(
          names.map(async (filename) => ({
            filename,
            longname: filename,
            attrs: await attrsOf(join(dir, filename)),
          })),
        ),
      )
      .then(
        (list) => (list.length === 0 ? sftp.status(reqid, STATUS.EOF) : sftp.name(reqid, list)),
        () => sftp.status(reqid, STATUS.FAILURE),
      );
  });

  sftp.on('LSTAT', (reqid, path) => {
    record({ type: 'LSTAT', path });
    const target = local(path);
    if (target === null) return sftp.status(reqid, STATUS.NO_SUCH_FILE);
    attrsOf(target).then(
      (attrs) => sftp.attrs(reqid, attrs),
      () => sftp.status(reqid, STATUS.NO_SUCH_FILE),
    );
  });

  sftp.on('CLOSE', (reqid, handle) => {
    const key = handle.toString();
    const file = files.get(key);
    record({ type: 'CLOSE', path: file?.path ?? dirs.get(key)?.path });
    files.delete(key);
    dirs.delete(key);
    if (file) void file.file.close().catch(() => undefined);
    sftp.status(reqid, STATUS.OK);
  });
}

export async function startFakeSsh(options: FakeSshOptions): Promise<FakeSshServer> {
  const key = newHostKey();
  const state: Omit<FakeSshServer, 'host' | 'port' | 'href' | 'close'> = {
    fingerprint: sha256Fingerprint(key.public),
    connections: 0,
    logins: [],
    channels: [],
    requests: [],
  };
  const clients = new Set<Connection>();
  const server = new Server({ hostKeys: [key.private] }, (client) => {
    state.connections += 1;
    clients.add(client);
    client.on('close', () => clients.delete(client));
    client.on('error', () => undefined);
    client.on('authentication', (ctx) => {
      const password = ctx.method === 'password' ? ctx.password : undefined;
      state.logins.push({ method: ctx.method, username: ctx.username, password });
      if (
        ctx.method === 'password' &&
        ctx.username === options.username &&
        ctx.password === options.password
      ) {
        ctx.accept();
      } else {
        ctx.reject(['password']);
      }
    });
    client.on('ready', () => {
      client.on('tcpip', (_accept, reject) => {
        state.channels.push('tcpip');
        reject();
      });
      client.on('request', (_accept, reject, name) => {
        state.channels.push(`request:${name}`);
        reject?.();
      });
      client.on('session', (accept) => {
        const session = accept();
        session.on('sftp', (acceptSftp) => {
          state.channels.push('sftp');
          serveSftp(acceptSftp(), options.appDir, (r) => state.requests.push(r));
        });
        for (const name of ['exec', 'shell', 'pty', 'env', 'subsystem', 'x11'] as const) {
          session.on(name as 'exec', (_accept: unknown, reject: () => void) => {
            state.channels.push(name);
            reject();
          });
        }
      });
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return Object.assign(state, {
    host: '127.0.0.1',
    port,
    href: `127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        for (const client of clients) client.end();
        server.close(() => resolve());
      }),
  });
}
