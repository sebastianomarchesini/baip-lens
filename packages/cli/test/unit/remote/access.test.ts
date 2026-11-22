import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { CfAuthError, ConfigError } from '../../../src/http/errors.js';
import { type HttpGetRequest, HttpClient } from '../../../src/http/httpClient.js';
import { cfTargetNames, tokenUser } from '../../../src/http/auth.js';
import {
  type CredentialKind,
  EgressPolicy,
  sshEndpointFromRoot,
  uaaRule,
  uaaSshCodeRule,
} from '../../../src/net/allowlist.js';
import { EgressDeniedError } from '../../../src/net/errors.js';
import {
  fingerprintFormat,
  hostKeyFingerprint,
  hostKeyMatches,
} from '../../../src/remote/hostKey.js';
import { codeFromLocation, requestSshCode, sshCodeUrl } from '../../../src/remote/sshCode.js';
import { FakeFetch } from '../../support/fakeFetch.js';

const uaa = new URL('https://uaa.cf.example.org');

describe('UAA rule for the one-time SSH code', () => {
  const policy = (): EgressPolicy => {
    const p = new EgressPolicy();
    p.add(uaaRule(uaa));
    p.add(uaaSshCodeRule(uaa));
    return p;
  };
  const allowed = (method: string, url: string, credential?: CredentialKind): boolean => {
    try {
      policy().authorize(new URL(url), method, credential);
      return true;
    } catch (error) {
      expect(error).toBeInstanceOf(EgressDeniedError);
      return false;
    }
  };
  const AUTHORIZE = 'https://uaa.cf.example.org/oauth/authorize?response_type=code';
  const TOKEN = 'https://uaa.cf.example.org/oauth/token';

  it('lets the CF token reach GET /oauth/authorize, as `cf ssh-code` sends it', () => {
    expect(allowed('GET', AUTHORIZE, 'bearer')).toBe(true);
  });

  it('keeps the token endpoint for the OAuth client (Basic) only', () => {
    expect(allowed('POST', TOKEN, 'basic')).toBe(true);
    expect(allowed('POST', TOKEN, 'bearer')).toBe(false);
  });

  it('refuses every other credential, method and path on UAA', () => {
    expect(allowed('GET', AUTHORIZE, 'basic')).toBe(false);
    expect(allowed('GET', AUTHORIZE, 'unknown')).toBe(false);
    expect(allowed('POST', 'https://uaa.cf.example.org/oauth/authorize', 'bearer')).toBe(false);
    expect(allowed('GET', TOKEN, 'bearer')).toBe(false);
    expect(allowed('GET', 'https://uaa.cf.example.org/Users', 'bearer')).toBe(false);
    expect(allowed('GET', 'https://uaa.cf.example.org/oauth/authorize/x', 'bearer')).toBe(false);
  });

  it('is not part of the policy unless the command adds it', () => {
    const p = new EgressPolicy();
    p.add(uaaRule(uaa));
    expect(() =>
      p.authorize(new URL('https://uaa.cf.example.org/oauth/authorize'), 'GET', 'bearer'),
    ).toThrow(EgressDeniedError);
  });
});

describe('app SSH endpoint from the CF root', () => {
  const fp = 'Y411oivJwZCUQnXHq83mdM5SKCK4ftyoSXI31RRe4Zs';

  it('reads host:port as the CF docs show it', () => {
    expect(sshEndpointFromRoot('ssh.cf.eu10.example.org:2222', fp)).toMatchObject({
      host: 'ssh.cf.eu10.example.org',
      port: 2222,
      hostKeyFingerprint: fp,
    });
    expect(sshEndpointFromRoot('SSH.Example.org:22', fp)?.host).toBe('ssh.example.org');
  });

  it.each([
    'ssh.example.org',
    'ssh://ssh.example.org:2222',
    'user@ssh.example.org:2222',
    'ssh.example.org:2222/path',
    'ssh.example.org:0',
    'ssh.example.org:70000',
    '[::1]:2222',
    'ssh_example.org:2222',
    '',
  ])('refuses %j', (href) => {
    expect(sshEndpointFromRoot(href, fp)).toBeNull();
  });

  it('refuses an endpoint without a fingerprint, so nothing unverifiable is dialled', () => {
    expect(sshEndpointFromRoot('ssh.example.org:2222', undefined)).toBeNull();
    expect(sshEndpointFromRoot('ssh.example.org:2222', '')).toBeNull();
    expect(sshEndpointFromRoot(undefined, fp)).toBeNull();
  });
});

describe('host key fingerprints (cf CLI formats)', () => {
  const key = Buffer.from('ssh-ed25519 public key blob for the test');
  const md5 = [...createHash('md5').update(key).digest()]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':');
  const sha1 = [...createHash('sha1').update(key).digest()]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':');
  const sha256hex = createHash('sha256').update(key).digest('hex');
  const sha256b64 = createHash('sha256').update(key).digest('base64').replace(/=+$/, '');

  it('tells the format by its length, as the cf CLI does', () => {
    expect(fingerprintFormat(md5)).toBe('md5-hex');
    expect(fingerprintFormat(sha1)).toBe('sha1-hex');
    expect(fingerprintFormat(sha256hex)).toBe('sha256-hex');
    expect(fingerprintFormat(sha256b64)).toBe('sha256-base64');
    expect(fingerprintFormat('')).toBeNull();
    expect(fingerprintFormat(`${sha256b64}=`)).toBeNull();
  });

  it('matches the received key in every format', () => {
    expect(md5).toHaveLength(47);
    expect(sha1).toHaveLength(59);
    expect(sha256b64).toHaveLength(43);
    for (const expected of [md5, sha1, sha256hex, sha256b64]) {
      expect(hostKeyMatches(key, expected), expected).toBe(true);
    }
    expect(hostKeyMatches(key, md5.toUpperCase())).toBe(true);
    expect(hostKeyFingerprint(key, 'sha256-base64')).toBe(sha256b64);
  });

  it('rejects another key, a changed digit and an unknown format', () => {
    const other = Buffer.from('another key');
    expect(hostKeyMatches(other, sha256b64)).toBe(false);
    const changed = `${sha256b64.slice(0, -1)}${sha256b64.endsWith('A') ? 'B' : 'A'}`;
    expect(hostKeyMatches(key, changed)).toBe(false);
    // base64 is case-sensitive, unlike hex.
    const swapped = [...sha256b64]
      .map((c) => (c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase()))
      .join('');
    expect(swapped).not.toBe(sha256b64);
    expect(hostKeyMatches(key, swapped)).toBe(false);
    expect(hostKeyMatches(key, '')).toBe(false);
    expect(hostKeyMatches(key, 'SHA256:abc')).toBe(false);
  });
});

describe('one-time SSH code', () => {
  const tokens = () => {
    let invalidated = 0;
    return {
      source: 'test',
      getToken: () => Promise.resolve(`token-${invalidated}`),
      invalidate: () => {
        invalidated += 1;
      },
      get invalidated() {
        return invalidated;
      },
    };
  };
  const http = (fake: FakeFetch): HttpClient => {
    const policy = new EgressPolicy();
    policy.add(uaaSshCodeRule(uaa));
    return new HttpClient({ policy, userAgent: 'test', fetch: fake.fetch, maxRetries: 0 });
  };
  const redirect = (location: string) => () =>
    new Response(null, { status: 302, headers: { location } });
  const AUTHORIZE = 'uaa.cf.example.org/oauth/authorize?client_id=ssh-proxy&response_type=code';

  it('asks UAA as `cf ssh-code` does and reads the code from the redirect it does not follow', async () => {
    const fake = new FakeFetch().on(
      'GET',
      AUTHORIZE,
      redirect('https://uaa.cf.example.org/login?code=abc-123'),
    );
    expect(await requestSshCode(http(fake), uaa, 'ssh-proxy', tokens())).toBe('abc-123');
    expect(fake.calls).toHaveLength(1);
    expect(fake.calls[0]?.headers.authorization).toBe('bearer token-0');
    expect(fake.calls[0]?.redirect).toBe('manual');
  });

  it('refreshes the token once after a 401', async () => {
    const t = tokens();
    const fake = new FakeFetch()
      .on('GET', AUTHORIZE, () => new Response('', { status: 401 }), 1)
      .on('GET', AUTHORIZE, redirect('/login?code=xyz'));
    expect(await requestSshCode(http(fake), uaa, 'ssh-proxy', t)).toBe('xyz');
    expect(t.invalidated).toBe(1);
    expect(fake.calls[1]?.headers.authorization).toBe('bearer token-1');
  });

  it('gives up after a second 401 with a login hint', async () => {
    const fake = new FakeFetch().on('GET', AUTHORIZE, () => new Response('', { status: 401 }));
    await expect(requestSshCode(http(fake), uaa, 'ssh-proxy', tokens())).rejects.toBeInstanceOf(
      CfAuthError,
    );
  });

  it('explains an answer without a code (for example a client-credentials token)', async () => {
    const fake = new FakeFetch().on(
      'GET',
      AUTHORIZE,
      () => new Response('<html>login</html>', { status: 200 }),
    );
    const error = await requestSshCode(http(fake), uaa, 'ssh-proxy', tokens()).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(ConfigError);
    expect((error as Error).message).toContain('needs a personal cf login');
  });

  it('accepts only plain codes and plain client ids', () => {
    const base = sshCodeUrl(uaa, 'ssh-proxy');
    expect(base.href).toBe(
      'https://uaa.cf.example.org/oauth/authorize?response_type=code&client_id=ssh-proxy',
    );
    expect(codeFromLocation('https://x/login?code=a%20b', base)).toBeNull();
    expect(codeFromLocation('https://x/login?error=access_denied', base)).toBeNull();
    expect(codeFromLocation(null, base)).toBeNull();
    expect(() => sshCodeUrl(uaa, 'ssh proxy&x=1')).toThrow(ConfigError);
  });

  it('keeps a path prefix of the UAA URL', () => {
    expect(sshCodeUrl(new URL('https://example.org/uaa/'), 'ssh-proxy').pathname).toBe(
      '/uaa/oauth/authorize',
    );
  });

  it('is a GET without a body', () => {
    const request: HttpGetRequest = { url: uaa };
    expect('method' in request).toBe(false);
  });
});

describe('cf CLI target and token claims', () => {
  it('reads the targeted org and space names leniently', () => {
    const base = {
      AccessToken: '',
      RefreshToken: '',
      Target: '',
      UAAOAuthClient: '',
      UAAOAuthClientSecret: '',
    };
    expect(
      cfTargetNames({
        ...base,
        OrganizationFields: { GUID: 'g', Name: 'acme' },
        SpaceFields: { Name: 'dev' },
      }),
    ).toEqual({ org: 'acme', space: 'dev' });
    expect(
      cfTargetNames({ ...base, OrganizationFields: { Name: '' }, SpaceFields: 'dev' }),
    ).toEqual({});
    expect(cfTargetNames(base)).toEqual({});
  });

  it('reads the user id and scopes of a JWT locally', () => {
    const payload = Buffer.from(JSON.stringify({ user_id: 'u-1', scope: ['a', 'b'] })).toString(
      'base64url',
    );
    expect(tokenUser(`bearer x.${payload}.y`)).toEqual({ userId: 'u-1', scopes: ['a', 'b'] });
    expect(tokenUser('not-a-jwt')).toEqual({ scopes: [] });
    const client = Buffer.from(JSON.stringify({ client_id: 'c', scope: ['uaa.none'] })).toString(
      'base64url',
    );
    expect(tokenUser(`x.${client}.y`)).toEqual({ scopes: ['uaa.none'] });
  });
});

describe('messages for an app that cannot be read', () => {
  it('tells the three reasons CF gives apart by their phrase, not by a name inside them', async () => {
    const { sshOffAdvice } = await import('../../../src/remote/scanApp.js');
    expect(sshOffAdvice('ssh is disabled globally', 'a', 'dev')).toContain('whole platform');
    expect(sshOffAdvice('Disabled globally', 'a', 'dev')).toContain('whole platform');
    expect(sshOffAdvice("ssh is disabled for space 'globally'", 'a', 'globally')).toContain(
      'cf allow-space-ssh globally',
    );
    expect(sshOffAdvice('ssh is disabled for app', 'my app', 'dev')).toContain(
      'cf enable-ssh "my app"',
    );
    expect(sshOffAdvice('', 'a', 'dev')).toBe('SSH is off for this app');
  });

  it('classifies ssh2 errors by level, never by their text', async () => {
    const { classifySshError } = await import('../../../src/remote/session.js');
    const error = (level: string, code?: string) =>
      Object.assign(new Error('server said: POISON'), { level, code });
    expect(classifySshError(error('client-authentication'), false).failure).toBe('auth');
    expect(classifySshError(error('client-timeout'), false).failure).toBe('timeout');
    expect(classifySshError(error('client-socket', 'ECONNREFUSED'), false)).toMatchObject({
      failure: 'unreachable',
      code: 'ECONNREFUSED',
    });
    expect(classifySshError(error('client-dns', 'ENOTFOUND'), false).failure).toBe('unreachable');
    expect(classifySshError(error('protocol'), false).failure).toBe('other');
    expect(classifySshError(error('client-authentication'), true).failure).toBe('host-key');
    expect(classifySshError(error('protocol'), false).message).not.toContain('POISON');
  });

  it('explains each SSH failure without server text', async () => {
    const { explainSshFailure } = await import('../../../src/remote/scanApp.js');
    const { SshConnectError } = await import('../../../src/remote/session.js');
    const ssh = { host: 'ssh.cf.example.org', port: 2222, hostKeyFingerprint: 'x', purpose: '' };
    expect(
      explainSshFailure(new SshConnectError('unreachable', 'ETIMEDOUT'), ssh, 'a', 'dev'),
    ).toContain(
      'ssh.cf.example.org:2222 could not be reached (ETIMEDOUT). Company networks often block SSH (port 2222)',
    );
    expect(explainSshFailure(new SshConnectError('sftp-refused'), ssh, 'a', 'dev')).toContain(
      'SFTP',
    );
    expect(explainSshFailure(new SshConnectError('timeout'), ssh, 'a', 'dev')).toContain('in time');
    expect(explainSshFailure(new SshConnectError('other'), ssh, 'a', 'dev')).toContain('--path');
  });
});
