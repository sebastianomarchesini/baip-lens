/**
 * The egress allow-list: the ONLY place that decides which hosts BAIP Lens may
 * contact, with which HTTP methods and paths, and whether credentials may be
 * sent. Every request goes through `EgressPolicy.authorize` before `fetch`
 * runs. See docs/data-sources.md §6.
 */
import { EgressDeniedError } from './errors.js';

/**
 * The only methods the HTTP layer can issue at all. Each rule below decides
 * which host and path may use which one: the customer's CF API and log cache
 * allow GET only, and POST is allowed on exactly two paths, the UAA token
 * endpoint (`/oauth/token`, the sign-in, as `cf login` does) and OSV.dev's
 * `/v1/querybatch` (public package names, never credentials). The CF client
 * cannot even ask for POST: it only sees `ReadOnlyHttp` (`http/httpClient.ts`).
 */
export type HttpMethod = 'GET' | 'POST';

/**
 * What an Authorization header carries. `bearer` is the CF access token, which
 * only the CF API and its log cache may receive; `basic` is the OAuth client
 * id and secret, which only the UAA token endpoint may receive. Any other
 * scheme is `unknown` and no host may receive it.
 */
export type CredentialKind = 'bearer' | 'basic' | 'unknown';

/** Classifies an Authorization header value without keeping it. */
export function credentialKind(headerValue: string | undefined): CredentialKind | undefined {
  if (headerValue === undefined) return undefined;
  if (/^bearer\s/i.test(headerValue)) return 'bearer';
  if (/^basic\s/i.test(headerValue)) return 'basic';
  return 'unknown';
}

export interface EgressRule {
  host: string;
  /** Explicit port, when the rule's base URL had one. */
  port?: string;
  /** Allowed path pattern per method. A method with no entry is denied. */
  allow: Partial<Record<HttpMethod, RegExp>>;
  /**
   * Paths denied for every method even when `allow` matches, tested against
   * the raw and the percent-decoded path. Used for endpoints that return
   * credentials, so that no future collector can reach them by accident.
   */
  deny?: RegExp;
  /** The credentials this host may receive in an Authorization header; empty: none. */
  credentials: readonly Exclude<CredentialKind, 'unknown'>[];
  /** Why the host is allowed; shown in errors and docs. */
  purpose: string;
}

/** Fixed public data sources. No customer data is ever sent to them. */
export const STATIC_EGRESS_RULES: readonly EgressRule[] = [
  {
    host: 'api.osv.dev',
    allow: { POST: /^\/v1\/querybatch$/, GET: /^\/v1\/vulns\/[A-Za-z0-9._:-]+$/ },
    credentials: [],
    purpose: 'Known-vulnerability lookups for SBOM packages (DEP_KNOWN_CVE)',
  },
  {
    host: 'endoflife.date',
    allow: { GET: /^\/api\/v1\/products\/[a-z0-9-]+\/?$/ },
    credentials: [],
    purpose: 'Runtime end-of-life dates (RUNTIME_NODE_EOL, RUNTIME_JAVA_EOL)',
  },
  {
    host: 'ui5.sap.com',
    allow: { GET: /^\/versionoverview\.json$/ },
    credentials: [],
    purpose: 'SAPUI5 maintenance status (UI5_OUT_OF_MAINTENANCE)',
  },
  {
    host: 'registry.npmjs.org',
    allow: { GET: /^\/@sap(?:\/|%2[fF])(?:cds|approuter|xssec|xsenv)$/ },
    credentials: [],
    purpose: 'Current major versions of @sap/* packages (SAP_PKG_OUTDATED)',
  },
];

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Path prefix of a base URL without trailing slash ("" for the root). */
function basePath(base: URL): string {
  return base.pathname.replace(/\/+$/, '');
}

function ruleFor(base: URL, rule: Omit<EgressRule, 'host' | 'port'>): EgressRule {
  return { ...rule, host: base.hostname.toLowerCase(), port: base.port || undefined };
}

/**
 * CF v3 endpoints that return secrets. BAIP Lens never needs them: `/env`
 * includes VCAP_SERVICES credentials and `/details` is the binding's
 * credentials. Environment variable *names* come from
 * `/environment_variables`, which stays allowed for `--deep`.
 */
const CREDENTIAL_ENDPOINTS = [
  'apps/[^/]+/env',
  'service_credential_bindings/[^/]+/details',
  'service_credential_bindings/[^/]+/parameters',
  'service_instances/[^/]+/credentials',
  'service_instances/[^/]+/parameters',
].join('|');

/** The customer's Cloud Foundry API: GET only, `/` and `/v3/**`, minus credential endpoints. */
export function cfApiRule(apiUrl: URL): EgressRule {
  const prefix = escapeRegExp(basePath(apiUrl));
  return ruleFor(apiUrl, {
    allow: { GET: new RegExp(`^${prefix}(?:/|/v3(?:/.*)?)?$`) },
    deny: new RegExp(`^${prefix}/v3/(?:${CREDENTIAL_ENDPOINTS})/*$`, 'i'),
    credentials: ['bearer'],
    purpose: 'Cloud Foundry API (read-only)',
  });
}

/**
 * UAA or login server discovered from the CF root: token endpoint only. It
 * receives the OAuth client id and secret (Basic), never the CF token.
 */
export function uaaRule(uaaUrl: URL): EgressRule {
  const prefix = escapeRegExp(basePath(uaaUrl));
  return ruleFor(uaaUrl, {
    allow: { POST: new RegExp(`^${prefix}/oauth/token$`) },
    credentials: ['basic'],
    purpose: 'OAuth token endpoint (UAA)',
  });
}

/**
 * Log cache discovered from the CF root (`links.log_cache`, never derived from
 * the API host name): one app's envelopes, GET only. Besides the CF API it is
 * the only host that may receive the CF token, which it needs to ask Cloud
 * Controller whether the caller may read the app (docs/data-sources.md §9.5).
 * `/api/v1/meta`, `/api/v1/info` and the PromQL endpoints are not reachable.
 */
export function logCacheRule(logCacheUrl: URL): EgressRule {
  const prefix = escapeRegExp(basePath(logCacheUrl));
  return ruleFor(logCacheUrl, {
    allow: { GET: new RegExp(`^${prefix}/api/v1/read/[A-Za-z0-9-]{1,64}$`) },
    credentials: ['bearer'],
    purpose: 'Log cache (read-only, router access log timestamps)',
  });
}

/** The path as sent plus its percent-decoded form, so encoding cannot bypass `deny`. */
function pathVariants(pathname: string): string[] {
  try {
    const decoded = decodeURIComponent(pathname);
    return decoded === pathname ? [pathname] : [pathname, decoded];
  } catch {
    return [pathname];
  }
}

export class EgressPolicy {
  private readonly rules: EgressRule[];

  constructor(rules: readonly EgressRule[] = STATIC_EGRESS_RULES) {
    this.rules = [...rules];
  }

  add(rule: EgressRule): void {
    this.rules.push(rule);
  }

  list(): readonly EgressRule[] {
    return this.rules;
  }

  /**
   * Returns the matching rule, or throws EgressDeniedError. Checks, in order:
   * https only, no userinfo, known host and port, allowed method and path,
   * and no credentials unless the rule allows that kind. `authorization` is
   * the kind of Authorization header the request carries (see `credentialKind`),
   * `undefined` for none. It is required so that no caller can forget it and
   * send a credential the host may not receive.
   */
  authorize(url: URL, method: string, authorization: CredentialKind | undefined): EgressRule {
    const deny = (reason: string): never => {
      throw new EgressDeniedError(method, url, reason);
    };
    if (url.protocol !== 'https:') deny('only https is allowed');
    if (url.username !== '' || url.password !== '') deny('credentials in URL are not allowed');

    const host = url.hostname.toLowerCase();
    const candidates = this.rules.filter(
      (rule) => rule.host === host && (rule.port ?? '') === url.port,
    );
    if (candidates.length === 0) deny('host is not on the allow-list');

    const methodRules = candidates.filter((rule) => rule.allow[method as HttpMethod] !== undefined);
    if (methodRules.length === 0) deny(`method ${method} is not allowed for this host`);

    const match = methodRules.find((rule) => rule.allow[method as HttpMethod]?.test(url.pathname));
    if (match === undefined) return deny(`path is not allowed for ${method}`);

    if (match.deny !== undefined) {
      for (const path of pathVariants(url.pathname)) {
        if (match.deny.test(path)) deny('endpoint returns credentials and is never read');
      }
    }

    if (authorization !== undefined) {
      const allowed: readonly CredentialKind[] = match.credentials;
      if (!allowed.includes(authorization)) {
        deny(`${authorization} credentials may not be sent to this host`);
      }
    }
    return match;
  }
}
