import type { TokenProvider } from '../http/auth.js';
import { CfAuthError, ConfigError } from '../http/errors.js';
import type { ReadOnlyHttp } from '../http/httpClient.js';

/*
 * The one-time SSH code, obtained as `cf ssh-code` does (cloudfoundry/cli
 * `api/uaa/ssh.go` `GetSSHPasscode`): a GET to `{uaa}/oauth/authorize` with
 * `response_type=code` and the SSH proxy's OAuth client id, authorised by the
 * user's access token. UAA answers with a redirect whose `code` parameter is
 * the passcode; the redirect is never followed (the HTTP client never follows
 * one). The code is used once, as the SSH password, and is never printed.
 */

/** OAuth client ids are plain identifiers; the CF root default is `ssh-proxy`. */
const CLIENT_ID = /^[A-Za-z0-9._-]{1,128}$/;
/** UAA authorization codes are short URL-safe strings. */
const CODE = /^[A-Za-z0-9._~-]{1,512}$/;

export const DEFAULT_SSH_OAUTH_CLIENT = 'ssh-proxy';

export function sshCodeUrl(uaa: URL, oauthClient: string): URL {
  if (!CLIENT_ID.test(oauthClient)) {
    throw new ConfigError('The CF API advertised an SSH OAuth client id that is not a plain name.');
  }
  const url = new URL(`${uaa.pathname.replace(/\/+$/, '')}/oauth/authorize`, uaa.origin);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', oauthClient);
  return url;
}

/** The `code` parameter of the redirect target, or null when there is none or it looks wrong. */
export function codeFromLocation(location: string | null, base: URL): string | null {
  if (location === null) return null;
  let target: URL;
  try {
    target = new URL(location, base);
  } catch {
    return null;
  }
  const code = target.searchParams.get('code');
  return code !== null && CODE.test(code) ? code : null;
}

const NOT_A_USER_LOGIN =
  'Reading a deployed app needs a personal cf login (`cf login` or `cf login --sso`); ' +
  'a token from client credentials cannot open an SSH session.';

export async function requestSshCode(
  http: ReadOnlyHttp,
  uaa: URL,
  oauthClient: string,
  tokens: TokenProvider,
): Promise<string> {
  const url = sshCodeUrl(uaa, oauthClient);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const token = await tokens.getToken();
    const res = await http.get({
      url,
      headers: { authorization: `bearer ${token}` },
      retry: false,
      maxBytes: 64 * 1024,
    });
    if (res.status === 401 && attempt === 0) {
      tokens.invalidate();
      continue;
    }
    if (res.status === 401) {
      throw new CfAuthError(
        `${uaa.host} did not accept your cf login for SSH (HTTP 401). Run \`cf login\` and try again.`,
      );
    }
    if (res.status >= 300 && res.status < 400) {
      const code = codeFromLocation(res.headers.get('location'), url);
      if (code !== null) return code;
    }
    throw new ConfigError(
      `${uaa.host} did not hand out a one-time SSH code (HTTP ${res.status}). ${NOT_A_USER_LOGIN}`,
    );
  }
  throw new CfAuthError('Your cf login was not accepted for SSH. Run `cf login` and try again.');
}
