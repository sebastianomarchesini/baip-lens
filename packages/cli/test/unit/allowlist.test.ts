import { describe, expect, it } from 'vitest';
import {
  type CredentialKind,
  EgressPolicy,
  STATIC_EGRESS_RULES,
  cfApiRule,
  credentialKind,
  logCacheRule,
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

    it('allows the four @sap packages on the npm registry only', () => {
      expect(allowed('GET', 'https://registry.npmjs.org/@sap%2Fcds')).toBe(true);
      expect(allowed('GET', 'https://registry.npmjs.org/@sap/approuter')).toBe(true);
      expect(allowed('GET', 'https://registry.npmjs.org/@sap/xssec')).toBe(true);
      expect(allowed('GET', 'https://registry.npmjs.org/@sap/xsenv')).toBe(true);
      expect(allowed('GET', 'https://registry.npmjs.org/lodash')).toBe(false);
      expect(allowed('GET', 'https://registry.npmjs.org/@sap/cds-dk')).toBe(false);
    });

    it('never allows credentials to public hosts', () => {
      for (const kind of ['bearer', 'basic', 'unknown'] as const) {
        expect(allowed('POST', 'https://api.osv.dev/v1/querybatch', kind)).toBe(false);
        expect(allowed('GET', 'https://endoflife.date/api/v1/products/nodejs', kind)).toBe(false);
        expect(allowed('GET', 'https://ui5.sap.com/versionoverview.json', kind)).toBe(false);
      }
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
