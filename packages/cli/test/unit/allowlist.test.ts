import { describe, expect, it } from 'vitest';
import {
  type CredentialKind,
  EgressPolicy,
  STATIC_EGRESS_RULES,
  cfApiRule,
  credentialKind,
  logCacheRule,
  requestCredential,
  uaaRule,
} from '../../src/net/allowlist.js';
import { EgressDeniedError } from '../../src/net/errors.js';

const api = new URL('https://api.cf.example.org');
const uaa = new URL('https://uaa.cf.example.org');

function policy(): EgressPolicy {
  const p = new EgressPolicy();
  p.add(cfApiRule(api));
  p.add(uaaRule(uaa));
  p.add(logCacheRule(new URL('https://log-cache.cf.example.org')));
  return p;
}

const allowed = (method: string, url: string, auth?: CredentialKind): boolean => {
  try {
    policy().authorize(new URL(url), method, auth);
    return true;
  } catch (error) {
    expect(error).toBeInstanceOf(EgressDeniedError);
    return false;
  }
};

describe('egress allow-list', () => {
  describe('CF API', () => {
    it('allows GET on / and /v3/**', () => {
      expect(allowed('GET', 'https://api.cf.example.org/')).toBe(true);
      expect(allowed('GET', 'https://api.cf.example.org/v3/apps?per_page=5000')).toBe(true);
      expect(allowed('GET', 'https://api.cf.example.org/v3/apps/abc/droplets/current')).toBe(true);
    });

    it.each(['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])('denies %s', (method) => {
      expect(allowed(method, 'https://api.cf.example.org/v3/apps', 'bearer')).toBe(false);
    });

    it('denies the v2 API and other paths', () => {
      expect(allowed('GET', 'https://api.cf.example.org/v2/apps')).toBe(false);
      expect(allowed('GET', 'https://api.cf.example.org/v3apps')).toBe(false);
      expect(allowed('GET', 'https://api.cf.example.org/networking/v1/external')).toBe(false);
    });

    it('honours a path prefix in the API URL', () => {
      const p = new EgressPolicy([cfApiRule(new URL('https://example.org/cf/'))]);
      expect(() =>
        p.authorize(new URL('https://example.org/cf/v3/apps'), 'GET', 'bearer'),
      ).not.toThrow();
      expect(() => p.authorize(new URL('https://example.org/v3/apps'), 'GET', 'bearer')).toThrow(
        EgressDeniedError,
      );
    });

    it('never reads endpoints that return credentials, even with GET', () => {
      const guid = '0a1b2c3d-0000-4000-8000-000000000042';
      for (const path of [
        `/v3/apps/${guid}/env`,
        `/v3/apps/${guid}/env/`,
        `/v3/apps/${guid}/ENV`,
        `/v3/apps/${guid}/%65nv`,
        `/v3/service_credential_bindings/${guid}/details`,
        `/v3/service_credential_bindings/${guid}/parameters`,
        `/v3/service_instances/${guid}/credentials`,
        `/v3/service_instances/${guid}/parameters`,
      ]) {
        expect(allowed('GET', `https://api.cf.example.org${path}`, 'bearer'), path).toBe(false);
      }
      // The names-only endpoint used by --deep stays allowed.
      expect(
        allowed(
          'GET',
          `https://api.cf.example.org/v3/apps/${guid}/environment_variables`,
          'bearer',
        ),
      ).toBe(true);
      expect(
        allowed(
          'GET',
          `https://api.cf.example.org/v3/service_credential_bindings?type=app`,
          'bearer',
        ),
      ).toBe(true);
    });

    it('allows sending the bearer token, and no other credential', () => {
      expect(allowed('GET', 'https://api.cf.example.org/v3/apps', 'bearer')).toBe(true);
      expect(allowed('GET', 'https://api.cf.example.org/v3/apps', 'basic')).toBe(false);
      expect(allowed('GET', 'https://api.cf.example.org/v3/apps', 'unknown')).toBe(false);
    });
  });

  describe('UAA', () => {
    it('allows only POST /oauth/token', () => {
      expect(allowed('POST', 'https://uaa.cf.example.org/oauth/token', 'basic')).toBe(true);
      expect(allowed('GET', 'https://uaa.cf.example.org/oauth/token')).toBe(false);
      expect(allowed('POST', 'https://uaa.cf.example.org/oauth/authorize')).toBe(false);
      expect(allowed('DELETE', 'https://uaa.cf.example.org/oauth/token')).toBe(false);
    });

    it('receives the client id and secret, never the CF token', () => {
      expect(allowed('POST', 'https://uaa.cf.example.org/oauth/token', 'bearer')).toBe(false);
    });
  });

  describe('log cache', () => {
    const app = '0a1b2c3d-0000-4000-8000-000000000042';

    it("allows GET of one app's envelopes, with the CF token", () => {
      expect(
        allowed('GET', `https://log-cache.cf.example.org/api/v1/read/${app}?limit=1000`, 'bearer'),
      ).toBe(true);
      expect(allowed('GET', `https://log-cache.cf.example.org/api/v1/read/${app}`, 'basic')).toBe(
        false,
      );
    });

    it('allows nothing else: no meta, info, PromQL, other methods or nested paths', () => {
      for (const path of [
        '/api/v1/meta',
        '/api/v1/info',
        '/api/v1/query',
        '/api/v1/query_range',
        `/api/v1/read/${app}/x`,
        '/api/v1/read/',
        '/v1/read/x',
      ]) {
        expect(allowed('GET', `https://log-cache.cf.example.org${path}`, 'bearer'), path).toBe(
          false,
        );
      }
      expect(allowed('POST', `https://log-cache.cf.example.org/api/v1/read/${app}`, 'bearer')).toBe(
        false,
      );
    });
  });

  describe('the CF token', () => {
    it('can be sent to the CF API and the log cache only, whatever else is on the list', () => {
      const p = new EgressPolicy();
      p.add(cfApiRule(api));
      p.add(uaaRule(uaa));
      p.add(uaaRule(new URL('https://login.cf.example.org')));
      p.add(logCacheRule(new URL('https://log-cache.cf.example.org')));
      const bearerHosts = p
        .list()
        .filter((rule) => rule.credentials.includes('bearer'))
        .map((rule) => rule.host);
      expect(bearerHosts).toEqual(['api.cf.example.org', 'log-cache.cf.example.org']);
      expect(STATIC_EGRESS_RULES.every((rule) => rule.credentials.length === 0)).toBe(true);
    });

    it('classifies the Authorization header by its scheme only', () => {
      expect(credentialKind(undefined)).toBeUndefined();
      expect(credentialKind('bearer abc')).toBe('bearer');
      expect(credentialKind('Bearer abc')).toBe('bearer');
      expect(credentialKind('Basic Y2Y6')).toBe('basic');
      expect(credentialKind('Token abc')).toBe('unknown');
      expect(credentialKind('bearerabc')).toBe('unknown');
    });

    it('reads the credential of a request from its headers: a cookie is one no host may receive', () => {
      expect(requestCredential({})).toBeUndefined();
      expect(requestCredential({ accept: 'application/json', 'user-agent': 'x' })).toBeUndefined();
      expect(requestCredential({ authorization: 'bearer abc' })).toBe('bearer');
      expect(requestCredential({ authorization: 'Basic Y2Y6' })).toBe('basic');
      expect(requestCredential({ cookie: 'session=abc' })).toBe('unknown');
      expect(requestCredential({ 'proxy-authorization': 'Basic Y2Y6' })).toBe('unknown');
      // Next to a token a host may receive, the cookie still decides.
      expect(requestCredential({ authorization: 'bearer abc', cookie: 'session=abc' })).toBe(
        'unknown',
      );
      expect(requestCredential({ cookie: '' })).toBe('unknown');
    });
  });

  describe('public data sources', () => {
    it('allows OSV batch queries and vulnerability details', () => {
      expect(allowed('POST', 'https://api.osv.dev/v1/querybatch')).toBe(true);
      expect(allowed('GET', 'https://api.osv.dev/v1/vulns/GHSA-xxxx-yyyy-zzzz')).toBe(true);
      expect(allowed('GET', 'https://api.osv.dev/v1/query')).toBe(false);
    });

    it('allows endoflife.date product lookups only', () => {
      expect(allowed('GET', 'https://endoflife.date/api/v1/products/nodejs')).toBe(true);
      expect(allowed('GET', 'https://endoflife.date/api/v1/products/sapmachine/')).toBe(true);
      expect(allowed('GET', 'https://endoflife.date/api/v1/categories')).toBe(false);
      expect(allowed('POST', 'https://endoflife.date/api/v1/products/nodejs')).toBe(false);
    });

    it('allows the UI5 version overview only', () => {
      expect(allowed('GET', 'https://ui5.sap.com/versionoverview.json')).toBe(true);
      expect(allowed('GET', 'https://ui5.sap.com/1.120.0/resources/sap-ui-core.js')).toBe(false);
    });

    it('never allows credentials to public hosts', () => {
      for (const kind of ['bearer', 'basic', 'unknown'] as const) {
        expect(allowed('POST', 'https://api.osv.dev/v1/querybatch', kind)).toBe(false);
        expect(allowed('GET', 'https://endoflife.date/api/v1/products/nodejs', kind)).toBe(false);
        expect(allowed('GET', 'https://ui5.sap.com/versionoverview.json', kind)).toBe(false);
        expect(allowed('GET', 'https://registry.npmjs.org/baip-fixture-merge/4.17.20', kind)).toBe(
          false,
        );
        expect(allowed('GET', 'https://registry.npmjs.org/baip-fixture-merge/latest', kind)).toBe(
          false,
        );
      }
    });

    it('has one rule for each public host', () => {
      const hosts = STATIC_EGRESS_RULES.map((rule) => rule.host);
      expect(hosts).toEqual(['api.osv.dev', 'endoflife.date', 'ui5.sap.com', 'registry.npmjs.org']);
      expect(new Set(hosts).size).toBe(hosts.length);
    });
  });

  /*
   * The npm registry (D10): one version of a public package, or its latest
   * one, and nothing else of the registry. The rule sees the address as the
   * request line will carry it: `URL` has resolved dot segments by then.
   */
  describe('the npm registry', () => {
    const REGISTRY = 'https://registry.npmjs.org';
    const get = (path: string): boolean => allowed('GET', `${REGISTRY}${path}`);
    const name214 = 'n'.repeat(214);
    const scoped214 = `@baip-fixture/${'n'.repeat(200)}`;

    it.each([
      ['a plain name and a version', '/baip-fixture-merge/4.17.20'],
      ['a scoped name with its slash encoded', '/@baip-fixture%2fodata/3.1.0'],
      ['the same escape in upper case', '/@baip-fixture%2Fodata/3.1.0'],
      ['a version with a prerelease', '/baip-fixture-merge/5.0.0-rc.1'],
      ['a prerelease with a hyphen in it', '/baip-fixture-merge/5.0.0-alpha-2.1'],
      ['the latest version of a plain name', '/baip-fixture-merge/latest'],
      ['the latest version of a scoped name', '/@baip-fixture%2fodata/latest'],
      ['a name with dots, tildes, underscores and capitals', '/Baip.Fixture_merge~2/1.0.0'],
      ['a name of one character', '/q/1.0.0'],
      ['a name that is a number', '/7/1.0.0'],
      ['a package that is called latest', '/latest/1.0.0'],
      // A name may be a hyphen: under the prefix of the registry's own endpoints a version of
      // that package is all that can be asked for.
      ['a package that is called -', '/-/0.0.1'],
      ['a version of many digits', '/baip-fixture-merge/2026.1125.100000'],
      ['a name of 214 characters', `/${name214}/1.0.0`],
      ['a scoped name of 214 characters', `/${scoped214.replace('/', '%2f')}/latest`],
      ['a version of 64 characters', `/baip-fixture-merge/1.0.0-${'9'.repeat(58)}`],
    ])('allows GET of %s', (_name, path) => {
      expect(scoped214).toHaveLength(214);
      expect(get(path), path).toBe(true);
    });

    it.each(['POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])(
      'denies %s, whatever the path',
      (method) => {
        expect(allowed(method, `${REGISTRY}/baip-fixture-merge/4.17.20`)).toBe(false);
        expect(allowed(method, `${REGISTRY}/baip-fixture-merge/latest`)).toBe(false);
        expect(allowed(method, `${REGISTRY}/-/user/org.couchdb.user:x`)).toBe(false);
      },
    );

    it.each([
      // Fewer segments: the whole history of a package, the root, a search.
      ['a package without a version', '/baip-fixture-merge'],
      ['a scoped package without a version', '/@baip-fixture%2fodata'],
      ['the root', '/'],
      ['a version without a package', '//4.17.20'],
      ['a package with an empty version', '/baip-fixture-merge/'],
      // More segments.
      ['a scoped name with a plain slash', '/@baip-fixture/odata/3.1.0'],
      ['a tarball', '/baip-fixture-merge/-/baip-fixture-merge-4.17.20.tgz'],
      ['a trailing slash', '/baip-fixture-merge/4.17.20/'],
      ['a third segment', '/baip-fixture-merge/4.17.20/x'],
      ['an endpoint of the registry itself', '/-/v1/search'],
      ['the sign-in of the registry', '/-/user/org.couchdb.user:x'],
      ['its who-am-I', '/-/whoami'],
      ['its ping', '/-/ping'],
      ['the tags of a package', '/-/package/baip-fixture-merge/dist-tags'],
      ['its audit endpoint', '/-/npm/v1/security/advisories/bulk'],
      // Steps in the path.
      ['two dots as the package', '/../4.17.20'],
      ['two dots as the version', '/baip-fixture-merge/..'],
      ['two dots, encoded', '/%2e%2e/4.17.20'],
      ['two dots after an encoded slash', '/..%2f..%2fetc/1.0.0'],
      ['two dots as the scope', '/@..%2fodata/3.1.0'],
      ['two dots as the name in a scope', '/@baip-fixture%2f../3.1.0'],
      ['one dot as the package', '/./4.17.20'],
      ['a name that starts with a dot', '/.hidden/1.0.0'],
      ['a name that starts with an underscore', '/_private/1.0.0'],
      // An encoded slash anywhere but after the scope.
      ['an encoded slash in a plain name', '/baip-fixture%2fmerge/4.17.20'],
      ['a second encoded slash', '/@baip-fixture%2fodata%2fx/3.1.0'],
      ['an encoded slash for the one between package and version', '/baip-fixture-merge%2f4.17.20'],
      ['an encoded slash in the version', '/baip-fixture-merge/4.17.20%2f..'],
      ['an encoded slash before the scope', '/%2f@baip-fixture%2fodata/3.1.0'],
      ['a scope without a name', '/@baip-fixture%2f/3.1.0'],
      ['a name without a scope before the slash', '/@%2fodata/3.1.0'],
      // Any other escape, in either case.
      ['an encoded at sign', '/%40baip-fixture%2fodata/3.1.0'],
      ['an encoded letter', '/baip-fixture-m%65rge/4.17.20'],
      ['an encoded letter in upper case', '/baip-fixture-m%45rge/4.17.20'],
      ['an encoded backslash', '/baip-fixture%5Cmerge/4.17.20'],
      ['an encoded blank', '/baip-fixture%20merge/4.17.20'],
      ['an encoded plus in the version', '/baip-fixture-merge/1.0.0%2Bbuild'],
      ['an encoded question mark', '/baip-fixture-merge/4.17.20%3Fwrite=true'],
      ['an encoded NUL', '/baip-fixture-merge%00/4.17.20'],
      ['a percent sign alone', '/baip-fixture-merge%/4.17.20'],
      // A version that is not an exact one without build metadata.
      ['a version with build metadata', '/baip-fixture-merge/4.17.20+build.5'],
      ['a prerelease with build metadata', '/baip-fixture-merge/5.0.0-rc.1+build'],
      ['a range', '/baip-fixture-merge/^4.17.0'],
      ['a range with a tilde', '/baip-fixture-merge/~4.17.0'],
      ['a wildcard', '/baip-fixture-merge/*'],
      ['two numbers', '/baip-fixture-merge/4.17'],
      ['a leading v', '/baip-fixture-merge/v4.17.20'],
      ['another tag', '/baip-fixture-merge/next'],
      ['the tag in upper case', '/baip-fixture-merge/LATEST'],
      ['the tag with more behind it', '/baip-fixture-merge/latest-1'],
      ['a version of 65 characters', `/baip-fixture-merge/1.0.0-${'9'.repeat(59)}`],
      // A name that is too long, or not one.
      ['a name of 215 characters', `/${'n'.repeat(215)}/1.0.0`],
      ['a scoped name of 215 characters', `/${`${scoped214}n`.replace('/', '%2f')}/1.0.0`],
      ['a name with a blank', '/baip fixture/1.0.0'],
      ['a name with a colon', '/baip:fixture/1.0.0'],
      ['a name with an exclamation mark', '/baip!fixture/1.0.0'],
      ['a name with a semicolon', '/baip-fixture;x=1/1.0.0'],
      ['a name with a backslash', '/baip-fixture\\merge/4.17.20'],
      ['a name with an umlaut', '/b\u00e4ip-fixture/1.0.0'],
      ['two at signs', '/@@baip-fixture%2fodata/3.1.0'],
    ])('denies GET of %s', (_name, path) => {
      expect(get(path), path).toBe(false);
    });

    it('denies a query string, whatever the path', () => {
      expect(get('/baip-fixture-merge/4.17.20?write=true')).toBe(false);
      expect(get('/baip-fixture-merge/latest?token=POISON-abcdef123456')).toBe(false);
      expect(get('/@baip-fixture%2fodata/3.1.0?x')).toBe(false);
      // The bare mark of an empty one as well; what follows a `#` is never sent.
      expect(get('/baip-fixture-merge/4.17.20?')).toBe(false);
      expect(get('/baip-fixture-merge/4.17.20#readme?x=1')).toBe(true);
      expect(() =>
        policy().authorize(
          new URL(`${REGISTRY}/baip-fixture-merge/4.17.20?token=POISON-abcdef123456`),
          'GET',
          undefined,
        ),
      ).toThrow(
        'Egress denied: GET https://registry.npmjs.org/baip-fixture-merge/4.17.20 ' +
          '(a query string is not allowed for this host)',
      );
      // The other hosts are asked with one where they need it.
      expect(allowed('GET', 'https://api.cf.example.org/v3/apps?per_page=5000', 'bearer')).toBe(
        true,
      );
    });

    it('denies any other address of the host: another scheme, a port, a user, a name next to it', () => {
      for (const url of [
        'http://registry.npmjs.org/baip-fixture-merge/4.17.20',
        'https://registry.npmjs.org:8443/baip-fixture-merge/4.17.20',
        'https://user@registry.npmjs.org/baip-fixture-merge/4.17.20',
        'https://user:POISON-pw@registry.npmjs.org/baip-fixture-merge/4.17.20',
        'https://registry.npmjs.org.evil.example/baip-fixture-merge/4.17.20',
        'https://evil.registry.npmjs.org/baip-fixture-merge/4.17.20',
        'https://registry.npmjs.com/baip-fixture-merge/4.17.20',
        'https://registry.yarnpkg.com/baip-fixture-merge/4.17.20',
        'https://www.npmjs.com/package/baip-fixture-merge',
      ]) {
        expect(allowed('GET', url), url).toBe(false);
      }
    });

    it('no longer has the rule it replaces: a whole package document is not readable', () => {
      // D1 allowed `GET /@sap%2F{cds,approuter,xssec,xsenv}`: every version of the package at once.
      for (const path of ['/@sap%2Fcds', '/@sap/approuter', '/@sap/xssec', '/@sap%2fxsenv']) {
        expect(get(path), path).toBe(false);
      }
      // What it allows instead is the same for every public package.
      expect(get('/@sap%2fcds/9.0.0')).toBe(true);
      expect(get('/@sap%2fcds/latest')).toBe(true);
    });
  });

  describe('general rules', () => {
    it('denies unknown hosts', () => {
      expect(allowed('GET', 'https://example.com/')).toBe(false);
      expect(allowed('GET', 'https://evil.api.cf.example.org/v3/apps')).toBe(false);
    });

    it('denies plain http and other schemes', () => {
      expect(allowed('GET', 'http://api.cf.example.org/v3/apps')).toBe(false);
      expect(allowed('GET', 'file:///etc/passwd')).toBe(false);
    });

    it('denies credentials embedded in the URL', () => {
      expect(allowed('GET', 'https://user:pass@api.cf.example.org/v3/apps')).toBe(false);
    });

    it('denies a different port', () => {
      expect(allowed('GET', 'https://api.cf.example.org:8443/v3/apps')).toBe(false);
    });

    it('names the reason in the error without the query string', () => {
      expect(() =>
        policy().authorize(new URL('https://example.com/x?token=secret'), 'GET', undefined),
      ).toThrow(/Egress denied: GET https:\/\/example\.com\/x \(host is not on the allow-list\)/);
      try {
        policy().authorize(new URL('https://example.com/x?token=secret'), 'GET', undefined);
      } catch (error) {
        expect(String(error)).not.toContain('secret');
      }
    });
  });
});
