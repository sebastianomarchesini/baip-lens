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

/** Headers besides Authorization that carry a credential. No client sets one, and no host may receive one. */
const CREDENTIAL_HEADERS = ['cookie', 'proxy-authorization'];

/**
 * What the headers of a request carry as a credential, without keeping it:
 * the kind of their Authorization header, or `unknown`, which no host may
 * receive, when a cookie or a proxy credential is among them. Header names
 * are expected in lower case.
 */
export function requestCredential(
  headers: Readonly<Record<string, string>>,
): CredentialKind | undefined {
  if (CREDENTIAL_HEADERS.some((name) => headers[name] !== undefined)) return 'unknown';
  return credentialKind(headers.authorization);
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
  /**
   * False: a request to this host carries no query string. `allow` tests the
   * path alone, so a source that is asked by its path and nothing else says
   * so here, and nothing can travel next to the path.
   */
  query?: boolean;
  /** The credentials this host may receive in an Authorization header; empty: none. */
  credentials: readonly Exclude<CredentialKind, 'unknown'>[];
  /** Why the host is allowed; shown in errors and docs. */
  purpose: string;
}

/*
 * The one path shape of the npm registry rule (docs/data-sources.md §7, D10):
 * `/<package>/<version>` or `/<package>/latest`, two segments and nothing
 * else. The package is a plain name, or a scoped one written with its slash
 * encoded (`@scope%2fname`), in the alphabet of names read from a lockfile
 * (`LOCKED_PACKAGE_NAME_PATTERN`, at most 214 characters): no part of it can
 * begin with a dot, so none is a step in the path, and `%` stands nowhere but
 * in that one escape. The version is an exact one (`PACKAGE_VERSION_PATTERN`,
 * at most 64 characters) without build metadata, which the client cuts off.
 * No query string goes along (`query: false`). The patterns are repeated here
 * on purpose: this file decides alone, and a pattern that is loosened
 * elsewhere must not loosen what may be asked for.
 */
const NPM_NAME = '[A-Za-z0-9~-][A-Za-z0-9._~-]*';
const NPM_PACKAGE = `(?:(?=[^/]{1,216}/)@${NPM_NAME}%2[fF]${NPM_NAME}|(?=[^/]{1,214}/)${NPM_NAME})`;
const NPM_VERSION = '(?=[^/]{1,64}$)\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.-]*)?';
const NPM_REGISTRY_PATH = new RegExp(`^/${NPM_PACKAGE}/(?:latest|${NPM_VERSION})$`);

/** Fixed public data sources. No customer data is ever sent to them. */
export const STATIC_EGRESS_RULES: readonly EgressRule[] = [
  {
    host: 'api.osv.dev',
    allow: { POST: /^\/v1\/querybatch$/, GET: /^\/v1\/vulns\/[A-Za-z0-9._:-]+$/ },
    credentials: [],
    purpose: 'Known vulnerabilities of public npm packages from lockfiles (DEP_KNOWN_CVE)',
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
    allow: { GET: NPM_REGISTRY_PATH },
    query: false,
    credentials: [],
    purpose: 'Deprecation of public npm packages from lockfiles (DEP_DEPRECATED)',
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
 * The UAA authorize endpoint, GET only, for `baip-lens project --cf`: it
 * hands out the one-time SSH code, as `cf ssh-code` asks for it (the cf CLI
 * sends `GET {uaa}/oauth/authorize?response_type=code&client_id=<ssh client>`
 * with the access token and reads the code from the redirect it does not
 * follow). Added to the policy by that command only; `scan` never needs it.
 */
export function uaaSshCodeRule(uaaUrl: URL): EgressRule {
  const prefix = escapeRegExp(basePath(uaaUrl));
  return ruleFor(uaaUrl, {
    allow: { GET: new RegExp(`^${prefix}/oauth/authorize$`) },
    // The CF access token, as `cf ssh-code` sends it; UAA issued it in the first place.
    credentials: ['bearer'],
    purpose: 'One-time SSH code for reading a deployed app (UAA, as `cf ssh-code`)',
  });
}

/**
 * The app SSH proxy the CF root advertises in `links.app_ssh`, the only
 * non-HTTP destination BAIP Lens connects to, and only for
 * `baip-lens project --cf`. The connection opens the SFTP subsystem and
 * nothing else (no shell, no command, no port forwarding), and only read
 * operations are sent on it (`remote/sftp.ts`). The host key must match the
 * fingerprint published next to the address.
 */
export interface SshEndpoint {
  host: string;
  port: number;
  /** The proxy's host key fingerprint, exactly as `links.app_ssh.meta.host_key_fingerprint` gives it. */
  hostKeyFingerprint: string;
  purpose: string;
}

const DNS_NAME =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/**
 * Reads `links.app_ssh.href` (`host:port`, no scheme, as the CF docs and the
 * cf CLI use it). Null for anything else: a scheme, user info, a path, an IP
 * literal in brackets, a missing or out-of-range port, or a missing
 * fingerprint, so that nothing unverifiable is ever dialled.
 */
export function sshEndpointFromRoot(
  href: string | undefined,
  hostKeyFingerprint: string | undefined,
): SshEndpoint | null {
  if (href === undefined || !hostKeyFingerprint) return null;
  const match = /^([^:/@\s[\]]+):(\d{1,5})$/.exec(href.trim());
  if (match === null) return null;
  const host = (match[1] ?? '').toLowerCase();
  const port = Number(match[2]);
  if (!DNS_NAME.test(host) || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return {
    host,
    port,
    hostKeyFingerprint,
    purpose: 'App SSH proxy: SFTP read operations on one app instance (`project --cf`)',
  };
}

/**
 * Log cache discovered from the CF root (`links.log_cache`, never derived from
 * the API host name): one app's envelopes, GET only. Besides the CF API (and,
 * for `project --cf` only, the UAA authorize endpoint above) it is the only
 * host that may receive the CF token, which it needs to ask Cloud Controller
 * whether the caller may read the app (docs/data-sources.md §9.5).
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

/** Whether the request line would carry a `?`: a query, or the bare mark of an empty one. */
function hasQuery(url: URL): boolean {
  const sent = url.hash === '' ? url.href : url.href.slice(0, url.href.indexOf('#'));
  return url.search !== '' || sent.includes('?');
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
   * https only, no userinfo, known host and port, allowed method and path, no
   * query string where the rule allows none, and no credentials unless the
   * rule allows that kind. `authorization` is the kind of credential the
   * request carries in its headers (see `requestCredential`), `undefined` for
   * none. It is required so that no caller can forget it and send a
   * credential the host may not receive.
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

    if (match.query === false && hasQuery(url)) deny('a query string is not allowed for this host');

    if (authorization !== undefined) {
      const allowed: readonly CredentialKind[] = match.credentials;
      if (!allowed.includes(authorization)) {
        deny(`${authorization} credentials may not be sent to this host`);
      }
    }
    return match;
  }
}
