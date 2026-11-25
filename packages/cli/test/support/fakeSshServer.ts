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
 * proxy and the containers behind it: each SSH user (`cf:<process>/<index>`)
 * gets its own local folder served at /home/vcap/app over SFTP, and a
 * one-time code is accepted as the password once. Everything a client asks
 * for is recorded: logins, channels and every SFTP request with the user it
 * came from. Only the read requests BAIP Lens is allowed to send are
 * implemented; anything else is answered "unsupported" and recorded, so a
 * test can prove that nothing but reads ever reached a container.
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
  /** The SSH user of the session the request came on. */
  username: string;
  /** The container path, for path requests and for requests on a handle opened from one. */
  path?: string;
  /** For OPEN: the flags as ssh2 spells them ('r', 'w', 'a+', ...). */
  flags?: string;
  /** For READ: where in the file the bytes were asked for. */
  offset?: number;
  /** For READ: how many bytes were asked for. */
  length?: number;
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

/** One app: one SSH user, its folder, and the one password accepted (once). */
export interface FakeSshApp {
  /** The folder served at /home/vcap/app. */
  appDir: string;
  username: string;
  password: string;
}

/** Several apps behind one proxy. */
export interface FakeSshApps {
  /** The folder served at /home/vcap/app to each SSH user. */
  users: Record<string, string>;
  /** The one-time codes accepted as a password, each of them once, by any user. */
  codes: string[];
  /** Users whose connection is cut at their first OPEN request: a session lost mid-scan. */
  dropOnOpen?: string[];
  /**
   * Users whose connection is cut at the first READ request that asks for
   * bytes beyond the start of a file: a session lost while the ranges of a
   * large file are in flight, after its head was answered.
   */
  dropOnRead?: string[];
  /**
   * Every SFTP answer is held back this long, each on its own: a stand-in for
   * the round trip of a real network, where requests in flight wait together.
   */
  delayMs?: number;
}

export type FakeSshOptions = FakeSshApp | FakeSshApps;

function severalApps(options: FakeSshOptions): FakeSshApps {
  return 'users' in options
    ? options
    : { users: { [options.username]: options.appDir }, codes: [options.password] };
}

/** The SHA-256 base64 fingerprint (43 characters) of a public key, OpenSSH style. */
export function sha256Fingerprint(publicKey: string): string {
  const parsed = utils.parseKey(publicKey) as ParsedKey;
  return createHash('sha256').update(parsed.getPublicSSH()).digest('base64').replace(/=+$/, '');
}

/**
 * A fresh ed25519 key pair in OpenSSH format. About one key in 250 that ssh2
 * generates comes out a byte short (a key that starts with a zero byte) and
 * ssh2 cannot read it back, so a pair is only handed out when both halves parse.
 */
export function newHostKey(): { private: string; public: string } {
  for (;;) {
    const key = utils.generateKeyPairSync('ed25519');
    const readable = [key.public, key.private].every(
      (half) => !(utils.parseKey(half) instanceof Error),
    );
    if (readable) return key;
  }
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

/** The calls that answer an SFTP request. */
type SftpAnswers = Pick<SFTPWrapper, 'status' | 'handle' | 'attrs' | 'data' | 'name'>;

/** The answers of a session, each held back by `delayMs`; an answer to a session that is gone is dropped. */
function answersOf(sftp: SFTPWrapper, delayMs: number): SftpAnswers {
  if (delayMs <= 0) return sftp;
  const later =
    <A extends unknown[]>(send: (...args: A) => void) =>
    (...args: A): void => {
      setTimeout(() => {
        try {
          send(...args);
        } catch {
          // The client hung up while the answer was on its way.
        }
      }, delayMs);
    };
  return {
    status: later((...args: Parameters<SFTPWrapper['status']>) => sftp.status(...args)),
    handle: later((...args: Parameters<SFTPWrapper['handle']>) => sftp.handle(...args)),
    attrs: later((...args: Parameters<SFTPWrapper['attrs']>) => sftp.attrs(...args)),
    data: later((...args: Parameters<SFTPWrapper['data']>) => sftp.data(...args)),
    name: later((...args: Parameters<SFTPWrapper['name']>) => sftp.name(...args)),
  };
}

interface ServeOptions {
  /** Called at the first OPEN instead of answering it, when the session is to be lost there. */
  cut?: () => void;
  /** Called at a READ beyond the start of a file instead of answering it, when the session is to be lost there. */
  cutRead?: () => void;
  delayMs?: number;
}

function serveSftp(
  channel: SFTPWrapper,
  appDir: string,
  record: (r: Omit<SftpRequest, 'username'>) => void,
  { cut, cutRead, delayMs = 0 }: ServeOptions = {},
): void {
  const sftp = answersOf(channel, delayMs);
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
    channel.on(type, (reqid: number) => {
      record({ type });
      sftp.status(reqid, STATUS.OP_UNSUPPORTED);
    });
  }

  channel.on('OPEN', (reqid, filename, flags) => {
    const flagText = utils.sftp.flagsToString(flags) ?? String(flags);
    record({ type: 'OPEN', path: filename, flags: flagText });
    if (cut !== undefined) return cut();
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

  channel.on('FSTAT', (reqid, handle) => {
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

  channel.on('READ', (reqid, handle, offset, length) => {
    const entry = files.get(handle.toString());
    record({ type: 'READ', path: entry?.path, offset, length });
    if (cutRead !== undefined && offset > 0) return cutRead();
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

  channel.on('OPENDIR', (reqid, path) => {
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

  channel.on('READDIR', (reqid, handle) => {
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

  channel.on('LSTAT', (reqid, path) => {
    record({ type: 'LSTAT', path });
    const target = local(path);
    if (target === null) return sftp.status(reqid, STATUS.NO_SUCH_FILE);
    attrsOf(target).then(
      (attrs) => sftp.attrs(reqid, attrs),
      () => sftp.status(reqid, STATUS.NO_SUCH_FILE),
    );
  });

  channel.on('CLOSE', (reqid, handle) => {
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
  const apps = severalApps(options);
  const unusedCodes = new Set(apps.codes);
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
    // Many small answers in a row: without this, Nagle's algorithm holds them back and a read takes twice as long.
    (client as Connection & { setNoDelay?: (noDelay: boolean) => void }).setNoDelay?.(true);
    // Who signed in on this connection, and the folder that user is served.
    let login: { username: string; appDir: string } | undefined;
    client.on('close', () => clients.delete(client));
    client.on('error', () => undefined);
    client.on('authentication', (ctx) => {
      const password = ctx.method === 'password' ? ctx.password : undefined;
      state.logins.push({ method: ctx.method, username: ctx.username, password });
      const appDir = apps.users[ctx.username];
      // A code is spent by the login that presents it, as UAA's one-time codes are.
      if (ctx.method === 'password' && appDir !== undefined && unusedCodes.delete(ctx.password)) {
        login = { username: ctx.username, appDir };
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
          if (login === undefined) return;
          const { username, appDir } = login;
          serveSftp(acceptSftp(), appDir, (r) => state.requests.push({ ...r, username }), {
            cut: apps.dropOnOpen?.includes(username) ? () => client.end() : undefined,
            cutRead: apps.dropOnRead?.includes(username) ? () => client.end() : undefined,
            delayMs: apps.delayMs,
          });
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
