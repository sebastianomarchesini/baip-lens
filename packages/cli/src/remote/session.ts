import type { ConnectConfig } from 'ssh2';
import type { SshEndpoint } from '../net/allowlist.js';
import { hostKeyMatches } from './hostKey.js';
import { type ReadOnlySftp, Ssh2ReadOnlySftp } from './sftp.js';

/*
 * One SSH session to one app instance, through the platform's SSH proxy, as
 * `cf ssh` opens it (cloudfoundry/cli `util/clissh/ssh.go`): user
 * `cf:<process guid>/<instance index>`, the one-time code as the password,
 * and the proxy's host key checked against the fingerprint from the CF root.
 * Only password authentication is offered (no `none` probe, no agent, no
 * keys, no keyboard-interactive), and the only channel opened is the SFTP
 * subsystem: no shell, no command, no port forwarding. ssh2 is loaded only
 * here, so every other command runs without it.
 */

export interface SshTarget {
  endpoint: SshEndpoint;
  /** `cf:<process guid>/<index>`. */
  username: string;
  /** The one-time code; used once and never printed. */
  password: string;
}

export interface SshSession {
  readonly sftp: ReadOnlySftp;
  close(): void;
}

export type SshConnect = (target: SshTarget) => Promise<SshSession>;

/** Why a connection failed, as a fixed category: messages from the server or ssh2 are never shown. */
export type SshFailure = 'host-key' | 'auth' | 'unreachable' | 'timeout' | 'sftp-refused' | 'other';

export class SshConnectError extends Error {
  override readonly name = 'SshConnectError';

  constructor(
    readonly failure: SshFailure,
    /** Node error code of a socket failure (ECONNREFUSED, ENOTFOUND, …), when there is one. */
    readonly code?: string,
  ) {
    super(`SSH connection failed (${failure}${code ? `: ${code}` : ''})`);
  }
}

export const HANDSHAKE_TIMEOUT_MS = 30_000;

interface Ssh2Error extends Error {
  level?: string;
  code?: string;
}

/** Maps an ssh2 client error to a category; ssh2 tags errors with a `level`. */
export function classifySshError(error: Ssh2Error, hostKeyRejected: boolean): SshConnectError {
  if (hostKeyRejected) return new SshConnectError('host-key');
  const code = typeof error.code === 'string' ? error.code : undefined;
  switch (error.level) {
    case 'client-authentication':
      return new SshConnectError('auth');
    case 'client-timeout':
      return new SshConnectError('timeout');
    case 'client-socket':
    case 'client-dns':
      return new SshConnectError('unreachable', code);
    default:
      return new SshConnectError('other', code);
  }
}

export const connectSsh: SshConnect = async (target) => {
  const { Client } = await import('ssh2');
  return new Promise<SshSession>((resolve, reject) => {
    const client = new Client();
    let hostKeyRejected = false;
    let closed = false;
    let settled = false;
    const fail = (error: SshConnectError): void => {
      if (settled) return;
      settled = true;
      closed = true;
      client.end();
      reject(error);
    };
    client.on('error', (error: Ssh2Error) => fail(classifySshError(error, hostKeyRejected)));
    client.on('close', () => {
      closed = true;
      fail(new SshConnectError(hostKeyRejected ? 'host-key' : 'other'));
    });
    client.on('ready', () => {
      client.sftp((error, sftp) => {
        if (error) {
          fail(new SshConnectError('sftp-refused'));
          return;
        }
        settled = true;
        resolve({
          sftp: new Ssh2ReadOnlySftp(sftp, { isClosed: () => closed }),
          close: () => {
            closed = true;
            client.end();
          },
        });
      });
    });
    const config: ConnectConfig = {
      host: target.endpoint.host,
      port: target.endpoint.port,
      username: target.username,
      password: target.password,
      authHandler: ['password'],
      tryKeyboard: false,
      readyTimeout: HANDSHAKE_TIMEOUT_MS,
      hostVerifier: (key: Buffer): boolean => {
        const ok = hostKeyMatches(key, target.endpoint.hostKeyFingerprint);
        if (!ok) hostKeyRejected = true;
        return ok;
      },
    };
    client.connect(config);
    // Without its native add-on ssh2 writes a packet in pieces (length, payload, tag). With Nagle's
    // algorithm a later piece waits for the acknowledgement of the first, which the other side
    // delays: about 40 ms lost per SFTP request (measured, docs/data-sources.md §10.2).
    client.setNoDelay(true);
  });
};
