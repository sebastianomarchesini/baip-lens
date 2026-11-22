# Data sources

This file records every external data source BAIP Lens reads, what was **confirmed** against primary documentation, and what could **not** be confirmed and is therefore implemented defensively.

- **Verified on:** 2026-09-29
- **CF v3 API source of truth:** the Markdown sources of the official docs site (`v3-apidocs.cloudfoundry.org`), read from [`cloudfoundry/cloud_controller_ng` `docs/v3/source`](https://github.com/cloudfoundry/cloud_controller_ng/tree/main/docs/v3/source) at commit `8383175b` (2026-09-28). Defaults were read from `config/cloud_controller.yml` and `middleware/` in the same repository.

Legend: ✅ confirmed in primary docs or source · 🟡 confirmed second-hand (third-party code or search snippet) · ⚠️ not confirmed, implemented defensively

---

## 1. Cross-cutting CF v3 behaviour

### 1.1 Authentication ✅
- Every call sends `Authorization: bearer <token>` (UAA OAuth 2).
- Discovery: `GET /` (the global root, **no auth required**) returns `links.uaa.href`, `links.login.href` and `links.log_cache.href`. The `log_cache` link is omitted when log cache is not configured, so the code must handle its absence. BAIP Lens discovers these endpoints from the root and **never hard-codes** BTP region URLs.
- Token source 1: the cf CLI config at `$CF_HOME/.cf/config.json` (default `~/.cf/config.json`). Confirmed fields from `cloudfoundry/cli` `util/configv3/json_config.go`: `AccessToken` (already prefixed with `bearer `), `RefreshToken`, `Target`, `UaaEndpoint`, `AuthorizationEndpoint`, `UAAOAuthClient` (default `cf`), `UAAOAuthClientSecret`, `SSLDisabled`, `OrganizationFields`, `SpaceFields`.
  - If `AccessToken` has expired (read `exp` from the JWT payload locally, **without** any network call), refresh it with a `POST {UaaEndpoint}/oauth/token` using `grant_type=refresh_token`. This is the only permitted non-GET call. The refreshed token is held in memory and is **never written back** to `config.json`.
  - If `Target` differs from `--api`, fail with exit code 2 and a clear message.
- Token source 2: client credentials from `BAIP_LENS_CLIENT_ID` / `BAIP_LENS_CLIENT_SECRET`, sent as a `POST {uaa}/oauth/token` with `grant_type=client_credentials`.
- Token source 3 (guided mode, verified 2026-09-30 against `cloudfoundry/cli` `main`): what `cf login --sso` does. `command/v7/login_command.go` `authenticateSSO()` prompts for a passcode and calls `Authenticate({"passcode": <code>}, "", GrantTypePassword)`; `api/uaa/auth.go` `Authenticate()` posts `grant_type=password&passcode=<code>` (form-encoded) to `/oauth/token` with HTTP Basic auth of the CLI's OAuth client (`UAAOAuthClient`, default `cf`, and its secret, default empty). The response carries `access_token` and `refresh_token`; later refreshes use `grant_type=refresh_token`. The passcode page is `{login}/passcode` on the login server from `GET /` (`links.login`); the exact prompt text comes from `GET {login}/login` (`prompts.passcode`), which BAIP Lens does not need. Username and password use the same grant with `username` and `password` fields. BAIP Lens implements this in `UaaSessionTokenProvider`; the passcode or password is sent once and then dropped from memory.
- ✅ Region list for the wizard (`packages/cli/src/guided/regions.ts`), verified 2026-10-10 against the source of the SAP help page (`github.com/SAP-docs/btp-cloud-platform`, docs/10-concepts/regions-and-api-endpoints-available-for-the-cloud-foundry-environment-f344a57.md). It includes the extension landscapes (`eu10-002` to `eu10-005`, `us10-001`, `us10-002`, `eu20-001`, `eu20-002`) and the China regions on `platform.sapcloud.cn`. Wherever an API endpoint is accepted (wizard, `--api`), a region id (`eu10-004`, or `eu10.004` with a dot), a technical key (`cf-eu10-004`) or the region domain (`us10-001.hana.ondemand.com`) is turned into `https://api.cf.<region>.<domain>`. The list stays a convenience: the wizard asks for the region as text (no numbered menu), prints the list on `list` (as does `baip-lens regions`), tries an id that is not listed, verifies the endpoint with `GET /`, and a pasted cockpit URL wins.
- ⚠️ On SAP BTP, a technical user with client credentials needs a UAA client that CF role assignments can target. That setup is platform-specific, so the docs recommend `cf login` with a named user holding **Space Auditor** for v0.1.

### 1.2 Pagination ✅
- List responses contain `pagination.{total_results,total_pages,first,last,next,previous}` and `resources[]`.
- Follow `pagination.next.href` until it is `null`. Never build page URLs by hand.
- `per_page` is valid from 1 to **5000** on every v3 list endpoint used here. BAIP Lens uses `per_page=5000`.
- `include=space.organization` on `/v3/apps` returns parent spaces and orgs under `included.{spaces,organizations}`, which saves N+1 calls.
- Security guard: `next.href` must point to the same origin as `--api`. Otherwise stop paging and record an error. This prevents a token leak through a crafted `next` link.

### 1.3 Errors ✅
Error body: `{"errors":[{"code":int,"title":"CF-…","detail":"…"}]}`. Code on `code`/`title`, never on `detail`.

| HTTP | Title | BAIP Lens behaviour |
|---|---|---|
| 400 | `CF-BadQueryParameter` (10005) | Tool bug. Record the check as `error`; the scan continues. |
| 401 | `CF-InvalidAuthToken` (1000) / `CF-NotAuthenticated` (10002) | Refresh once, then abort with exit code 2. |
| 403 | `CF-NotAuthorized` (10003) | Record the check as `skipped: insufficient role`; the scan continues. |
| 404 | `CF-ResourceNotFound` (10010) | Also returned when **the user cannot read** the resource. Treat as "not visible", not as an error. |
| 429 | `CF-UaaRateLimited` (20008) or CC rate limiter | Honour `Retry-After` (seconds), then retry. |
| 5xx | `UnknownError` (10001), 502, 503 | Exponential backoff with jitter, max 3 retries, then record the check as `error`. |

### 1.4 Rate limits
- ✅ The Cloud Controller rate limiter (`middleware/base_rate_limiter.rb`) sets `X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset` (optionally with a suffix, e.g. `-V2-API`). On 429 it adds `Retry-After`. Open-source CF ships with it **disabled** by default, so the headers may be absent.
- 🟡 SAP BTP: according to *SAP BTP-Specific Configurations* (help.sap.com), the CC API limit is "in the range of a few 10k requests per hour per user on average", with a separate concurrency limit on service-related endpoints. help.sap.com is not reachable from the build environment, so this comes from a search snippet.
- Policy: concurrency of 5 (configurable). When `X-RateLimit-Remaining` drops below 5% of `-Limit`, pause until `-Reset`.

### 1.5 Roles ✅
The CF docs list per-endpoint *Permitted roles*. "All Roles" means the endpoint is callable by anyone, but results are **filtered to what the user can see**. An org-scoped list run by a Space Auditor therefore returns only that user's spaces, which is correct behaviour and not an error.

Global Auditor (a platform scope) can read everything except env vars and service binding details. It is rarely granted on BTP, but we support it.

### 1.6 Event retention: a design constraint ✅
Open-source CF defaults (`config/cloud_controller.yml`):

```yaml
app_usage_events: { cutoff_age_in_days: 31 }
audit_events:     { cutoff_age_in_days: 31 }
```

⚠️ The SAP BTP retention value is not published. **Assume 31 days.** Consequence: "no usage events in 180 days" cannot be proven from events, so `APP_IDLE` reads no events at all; it uses routes, processes and router access logs instead (§4, §9).

---

## 2. CF v3 endpoints used by collectors

All endpoints are **GET**. "SA" = Space Auditor; "SD" = Space Developer.

**Status:** the bootstrap calls, `apps.ts` and `droplets.ts` (since 0.1.0) and `routes.ts` and `processes.ts` (for `APP_IDLE`, §9) are implemented and are the only CF calls the scan makes. The other rows are verified endpoints for the collectors of the next releases; nothing calls them yet.

| Collector | Endpoint | Key fields used | Min. role | SA? | Notes |
|---|---|---|---|---|---|
| (bootstrap) | `GET /` | `links.uaa`, `links.login`, `links.log_cache` | none | ✅ | Unauthenticated. |
| (bootstrap) | `GET /v3/organizations?names=<org>` | `guid`, `name` | any role | ✅ | 0 results means "org not found or not visible", exit code 2. |
| (bootstrap) | `GET /v3/spaces?organization_guids=<g>[&names=<space>]` | `guid`, `name`, `relationships.organization` | any role | ✅ | Filtered to visible spaces. |
| `apps.ts` | `GET /v3/apps?organization_guids=<org>&per_page=5000` (`space_guids=<space>` with `--space`) | `guid`, `name`, `state` (`STARTED`/`STOPPED`), `created_at`, `updated_at`, `lifecycle.type` (`buildpack`/`cnb`/`docker`), `lifecycle.data.buildpacks[]`, `lifecycle.data.stack`, `relationships.space`, `relationships.current_droplet` | any role | ✅ | `lifecycle.data.buildpacks` may be `[]` and `stack` may be `null` for old records. |
| `droplets.ts` | `GET /v3/droplets?organization_guids=<org>&current=true&per_page=5000` (`space_guids=<space>` with `--space`) | `guid`, `state`, `created_at`, `updated_at`, `lifecycle.type`, `buildpacks[].{name,buildpack_name,version,detect_output}` (top-level on droplets, unlike apps), `stack`, `image`, `relationships.app` | any role | ✅ | One call instead of N× `/v3/apps/:guid/droplets/current`. `GET /v3/droplets/:guid` notes "some fields are redacted" for SA. ⚠️ The exact redacted fields are not documented; we do not rely on `execution_metadata` or `process_types`. Docker droplets have `image` and no buildpacks. |
| `processes.ts` | `GET /v3/processes?types=web&per_page=5000` with `organization_guids=<org>` (`space_guids=<space>` with `--space`) | `type`, `instances`, `health_check.type`, `updated_at`, `relationships.app` | any role | ✅ | Implemented (§9.2). `command` is never read. The legacy health check type `none` is read as `process`, as Cloud Controller's own manifest code does. |
| `processes.ts` | `GET /v3/processes/:guid/stats` | `state` (`RUNNING`/`CRASHED`/`STARTING`/`STOPPING`/`DOWN`), `uptime`, `usage.{cpu,mem,disk}`, `mem_quota` | SA (redacted) | ✅ | "Some fields are redacted" for SA. ⚠️ Treat `host`, `instance_internal_ip` and `instance_ports` as possibly missing. **Never** written to reports (infrastructure detail). Only called for `STARTED` apps. |
| `buildpacks.ts` | `GET /v3/buildpacks?per_page=5000` | `name`, `stack`, `state`, `enabled`, `position`, `filename`, `lifecycle`, `updated_at` | any role | ✅ | ⚠️ **There is no `version` field.** The platform's current version must be parsed from `filename` (e.g. `nodejs_buildpack-cflinuxfs4-v1.8.40.zip`). If parsing fails, `BUILDPACK_OUTDATED` falls back to comparing the droplet's `created_at` with the buildpack's `updated_at`, at lower confidence. |
| `stacks.ts` | `GET /v3/stacks?per_page=5000` | `name`, `state` (`ACTIVE`/`RESTRICTED`/`DEPRECATED`/`DISABLED`), `state_reason`, `default`, `description` | any role | ✅ | Use `state` as the primary signal. ⚠️ The `state` field is newer, so older CC versions may omit it. Fall back to a built-in list (`cflinuxfs3` deprecated) and flag the result as "static list". |
| `routes.ts` | `GET /v3/routes?space_guids=…&include=domain&per_page=5000`, 50 space GUIDs per request | `protocol` (`http`/`tcp`), `destinations[].app.guid`, `relationships.{space,domain}`, `included.domains[].internal` | any role | ✅ | Implemented (§9.1). By space, not org, so routes shared into a scanned space count. `url`, `host`, `path` and `port` are not read yet; the UI5 probe (§3.3) will need the URL. |
| `serviceBindings.ts` | `GET /v3/service_credential_bindings?type=app&app_guids=…&per_page=5000` | `name`, `type`, `relationships.app`, `relationships.service_instance`, `last_operation.state` | SA | ✅ | Metadata only. `GET …/:guid/details` (the credentials) is **SD-only and never called**. |
| `usageEvents.ts` | `GET /v3/app_usage_events?created_ats[gt]=<now-31d>&order_by=-created_at&per_page=5000` | `created_at`, `state.{current,previous}`, `app.guid`, `space.guid`, `instance_count` | "All Roles" | ✅ / ⚠️ | ⚠️ Listed as "All Roles", but the doc does not say how results are filtered for space-scoped users. On BTP it may return 403 or an empty list for SA. Treat both as `skipped` and fall back to audit events. Ignore `app.name`/`task.name` beyond matching. |
| `auditEvents.ts` | `GET /v3/audit_events?space_guids=…&types=audit.app.start,audit.app.stop,audit.app.restage,audit.app.droplet.create,audit.app.build.staged,audit.app.process.crash,app.crash&created_ats[gt]=<now-31d>&per_page=5000` | `type`, `created_at`, `target.guid` | **Org Auditor** or SA | ✅ | 🔒 Contains `actor.guid`, `actor.name` and `actor.type` (user identity). The collector **drops `actor.*` and `data` at parse time**; the zod schema strips them before anything reaches the snapshot. |
| `secretsInEnv.ts` (`--deep`) | `GET /v3/apps/:guid/environment_variables` | keys of `var` only | **SD** or Space Supporter | ❌ | Returns **only user-provided env vars**, not `VCAP_SERVICES`. Service bindings are therefore excluded by construction, which is exactly what `ENV_SECRET_PLAINTEXT` needs. Values are discarded in the collector and only keys are kept. ⚠️ Calling it creates an `audit.app.environment_variables.show` audit event in the customer's landscape; this is documented in `privacy.md`. |
| (not used) | `GET /v3/apps/:guid/env` | — | SD | ❌ | **Deliberately not used**: it returns `VCAP_SERVICES` credentials. |
| `project --cf` (§10) | `GET /v3/roles?types=space_developer&space_guids=<space>&user_guids=<user>` | `type` | any role | ✅ | "All Roles", filtered to what the user may see; the user's own roles are visible to them. Asked before any SSH attempt, so that a user without Space Developer is stopped before a refused login is recorded. |
| `project --cf` (§10) | `GET /v3/apps?space_guids=<space>&order_by=name&per_page=5000` | `guid`, `name`, `state`, `lifecycle.type` | any role | ✅ | The app list the user picks from. |
| `project --cf` (§10) | `GET /v3/apps/:guid/ssh_enabled` | `enabled`, `reason` | SA | ✅ | Permitted: Admin, Admin Read-Only, Global Auditor, Org Manager, Space Auditor, Space Developer, Space Manager, Space Supporter. `reason` is `ssh is disabled globally`, `ssh is disabled for space '<name>'` or `ssh is disabled for app` (`app/presenters/v3/app_ssh_status_presenter.rb`); only the three cases are told apart, the text is never shown. |
| `project --cf` (§10) | `GET /v3/apps/:guid/processes/web` | `guid` | any role | ✅ | The SSH user is `cf:<process guid>/<index>` (cloudfoundry/cli `actor/v7action/ssh.go`). |
| `project --cf` (§10) | `GET /v3/processes/:guid/stats` | `index`, `state` | SA (redacted) | ✅ | Only `index` and `state` are read, to pick the lowest `RUNNING` instance; `host` and ports are never read or kept. |

### 2.1 Role summary (input to `docs/permissions.md`)

| Check | Needs | Default |
|---|---|---|
| Inventory, droplets, processes, stats, buildpacks, stacks, routes, bindings metadata, audit events | Space Auditor (or Org Auditor for org-level audit events) | on |
| App usage events | ⚠️ unconfirmed on BTP | on, skips on 403 |
| `ENV_SECRET_PLAINTEXT` | Space Developer **or Space Supporter** | `--deep` only |
| `collect.project` and the project rules (§8) | **no CF role**: local files only, no network | on, for `baip-lens project` only |
| `collect.project` with `baip-lens project --cf` (§10) | **Space Developer**: Cloud Foundry allows SSH into an app only to users who may update it (`ProcessModelAccess#update?`, `app.space.has_developer?`); Space Auditor and Space Supporter cannot | on, for `project --cf` only |

> **Least-privilege finding:** Space Supporter can also read `/environment_variables`, and on paper it is a narrower role than Space Developer (it cannot push apps or manage services). However, Space Supporter can restart and scale apps, so it is **not** read-only either. We document both and recommend neither for routine scans.

---

## 3. Non-CF sources

### 3.1 endoflife.date ✅
- API v1 base: `https://endoflife.date/api/v1`. The OpenAPI spec is in [`endoflife-date/endoflife.date` `api_v1/openapi.yml`](https://github.com/endoflife-date/endoflife.date/blob/master/api_v1/openapi.yml).
- `GET /products/{product}` returns all release cycles. Release fields used: `name`, `releaseDate`, `isLts`, `isEol`, `eolFrom`, `isEoas`, `eoasFrom`, `latest`. Responses: 200, 304 (conditional), 404 (unknown product) and 429.
- Products: `nodejs`, `eclipse-temurin` and **`sapmachine`**. SapMachine is the JDK shipped by SAP's Java buildpack, so it is the correct EOL source for most BTP Java apps. It exists on endoflife.date (confirmed in `products/sapmachine.md`).
- The runtime version comes from the droplet's `buildpacks[].detect_output` / `version`, or the process start command. ⚠️ The format differs by buildpack and is not standardized. The parser has unit tests per known buildpack, and anything unparseable becomes `unknown`, never a guess.
- Offline mode: responses are cached in the snapshot, so `report --from` never calls the network.

### 3.2 OSV.dev ✅
- `POST https://api.osv.dev/v1/querybatch`. Docs: [`google/osv.dev` `docs/api`](https://github.com/google/osv.dev/tree/master/docs/api).
- It returns **only `id` and `modified`** per query, with the result order matching the input order. Severity needs `GET /v1/vulns/{id}` (fields `severity[]` with CVSS vectors, `database_specific.severity`, `affected[]`, `aliases`), cached per id.
- Pagination: a per-query `next_page_token` appears when one query has more than 1,000 vulns or the batch has more than 3,000. Re-send only the paginated queries with `page_token`.
- There is no documented rate limit. Responses are capped at 32 MiB over HTTP/1.1.
- ⚠️ **This is a POST.** The GET-only rule in constraint #1 applies to the CF API. The HTTP client therefore enforces a **per-host method allow-list**: CF API → GET only; UAA → POST to `/oauth/token` only; `api.osv.dev` → POST `/v1/querybatch` plus GET `/v1/vulns/*`; everything else → GET only. The request body contains only `{ecosystem, name, version}` of public packages, with no customer identifiers.

### 3.3 SAPUI5 version overview 🟡
- `GET https://ui5.sap.com/versionoverview.json`. ⚠️ ui5.sap.com is blocked from the build environment. The structure is confirmed through the open-source parser [`DevEpos/ui5-version-check`](https://github.com/DevEpos/ui5-version-check):
  - `versions[]`: `{ version: "1.120.*", support: "Maintenance" | "Out of maintenance", lts: boolean, eom: string, eocp: "Q1/2027" }`
  - `patches[]`: `{ version: "1.120.17", eocp: "Q3/2026", removed?: boolean, hidden?: boolean }`
  - `eocp` has **quarter precision**. End of Maintenance (EOM) and End of Cloud Provisioning (EOCP) are different milestones and must not be called "EOL".
- The zod schema is lenient (`passthrough`, optional fields). If the feed shape is not recognised, the check is `skipped: unrecognised UI5 feed`.
- Version detection: `GET https://<route>/resources/sap-ui-version.json` returns `{ name, version, buildTimestamp, libraries[] }` (⚠️ structure is well known but not verified first-hand here). Only `version` is read.

**Safety rules for the app probe:**

1. Send **no `Authorization` header**, because the CF token must never reach an app.
2. Use `redirect: 'manual'`. A 302 to XSUAA or IAS login means the app is protected and the result is `unknown (protected)`. Never follow the redirect.
3. Use a 5 s timeout and a max body of 256 KB.
4. Probe only `http` routes that are mapped to the app, one per app.
5. The probed hosts are added to the allow-list **at runtime**, taken only from routes that the CF API returned for the scanned org.

⚠️ Many BTP apps bootstrap UI5 from the CDN (`ui5.sap.com/<version>/resources/...`), so the file is 404 on the app route. That case becomes `unknown` in v0.1. Parsing `index.html` for the bootstrap `src` is a candidate for v0.2.

### 3.4 Log cache
Discovered via `GET /` → `links.log_cache`, never derived from the API host name. Read by the traffic check of `APP_IDLE` (`packages/cli/src/collectors/traffic.ts`); the endpoint, its parameters, the response shape, the roles it accepts and what it retains are verified in [§9](#9-traffic-and-route-signals-for-app_idle).

---

## 4. Consequences for the v0.1 rules

| Rule | Data | Constraint found | Decision |
|---|---|---|---|
| `RUNTIME_NODE_EOL` / `RUNTIME_JAVA_EOL` | droplet `buildpacks[]` + endoflife.date | Version format varies by buildpack | Parse per buildpack; otherwise `unknown`. Java → `sapmachine` if `sap_java_buildpack`, else `eclipse-temurin`. |
| `BUILDPACK_OUTDATED` | droplet `buildpacks[].version` vs `/v3/buildpacks` `filename` | No `version` field on buildpacks | Parse from `filename`; fall back to date comparison, flagged as lower confidence in evidence. |
| `STACK_DEPRECATED` | app `lifecycle.data.stack` or droplet `stack` + `/v3/stacks` `state` | `state` may be absent on old CCs | `state` ∈ {`DEPRECATED`,`RESTRICTED`,`DISABLED`} → finding; otherwise use the static list. |
| `APP_IDLE` | app `state`/`updated_at`, routes, `web` processes, router access logs in Log Cache (§9) | Events are kept ~31 days, so they are not used; Log Cache holds **hours, not days** (§9.6) | Stopped > 90 days: `state=STOPPED` and `updated_at` older than 90 days (`updated_at` is the last change, so the app has been stopped at least that long). Started with an instanced `web` process and no route: idle, high confidence. An external HTTP route and no router access log in the window Log Cache holds: idle, medium confidence only when the droplet and the `web` processes are unchanged for 180 days; a window shorter than `--min-traffic-window` is `unknown`. Workers are never judged by routes or traffic (D7), TCP and internal routes are `unknown` (D6). Evidence states the window. With `scan --previous`, 3 or more scans in a row without a request over 30 days or more give high confidence at low severity (D8, D9). |
| `APP_NO_RECENT_DEPLOY` | current droplet `created_at` | — | Direct. |
| `UI5_OUT_OF_MAINTENANCE` | app route probe + versionoverview | Protected or CDN-bootstrapped apps are not detectable | `unknown` is reported in inventory, not as a finding. |
| `SAP_PKG_OUTDATED` | local SBOM (`sbom` command) + npm registry | ⚠️ **The npm registry is not in the allow-list** | See decision D1. |
| `DEP_KNOWN_CVE` | SBOM + OSV | POST | Per-host method allow-list (§3.2). |
| `ENV_SECRET_PLAINTEXT` | `/environment_variables` keys | SD or Space Supporter only | `--deep`, keys only. |

---

## 5. HTML report (React + UI5 Web Components) constraints

Confirmed from the npm registry (2026-09-29):

| Package | Version | License |
|---|---|---|
| `@ui5/webcomponents-react` | 2.27.1 (peer: react ^18 \|\| ^19, `@ui5/webcomponents*` ~2.27.0) | Apache-2.0 |
| `@ui5/webcomponents-react-charts` | 2.27.1 | Apache-2.0 |
| `@ui5/webcomponents`, `-fiori`, `-icons`, `-base`, `-theming` | 2.27.2 | Apache-2.0 |
| `@sap-theming/theming-base-content` (contains the "72" font files) | 11.36.x | Apache-2.0 (LICENSE.txt covers the whole package, including the fonts) |
| `vite-plugin-singlefile` | 2.3.3 | MIT |

⚠️ **Offline blocker found:** by default, UI5 Web Components v2 load the "72" fonts from `https://cdn.jsdelivr.net/npm/@sap-theming/theming-base-content@…/fonts/*.woff2`, and CLDR locale data from `cdn.jsdelivr.net/npm/@openui5/sap.ui.core@…/cldr/*.json`. In report mode this would:

- (a) fail offline, and
- (b) contact a host that is not on the allow-list.

Mitigation for report mode:

1. Set `defaultFontLoading: false` via `<script data-ui5-config>`.
2. Inline the needed 72 `woff2` files as `data:` URIs in our own `@font-face`.
3. Import only the English locale and CLDR assets statically.
4. Add a Playwright test that opens the file with **all network requests blocked** and fails on any request other than `file://` or `data:`.

---

## 6. Allow-list (`packages/cli/src/net/allowlist.ts`)

| Host | Methods | Credentials it may receive | Source |
|---|---|---|---|
| `--api` host | GET | the CF token | user flag |
| `links.uaa` host | POST `/oauth/token` only | the OAuth client id and secret (Basic), never the CF token | CF root |
| `links.log_cache` host | GET `/api/v1/read/<app-guid>` only (no meta, info or PromQL) | the CF token | CF root |
| mapped app route hosts in the scanned org | GET `/resources/sap-ui-version.json` only, no redirects (planned; not called yet) | none | CF routes |
| `api.osv.dev` | POST `/v1/querybatch`, GET `/v1/vulns/*` | none | fixed |
| `endoflife.date` | GET `/api/v1/products/*` | none | fixed |
| `ui5.sap.com` | GET `/versionoverview.json` | none | fixed |
| `registry.npmjs.org` | GET `/@sap%2F{cds,approuter,xssec,xsenv}` only | none | fixed (D1) |
| `registry.npmjs.org` (planned, D10, replaces D1) | GET `/<package>/<version>` and `/<package>/latest`, only for packages the lockfile resolved from this registry (§12) | none | fixed |
| `links.uaa` host | GET `/oauth/authorize` only (the one-time SSH code); added by `project --cf` only | the CF token, as `cf ssh-code` sends it | CF root |
| `links.app_ssh` `host:port` | SSH: password authentication with the one-time code, the SFTP subsystem only, read requests only (§10); `project --cf` only | the one-time SSH code, as the SSH password; never the CF token | CF root |

Every rule lists the kinds of `Authorization` header it may receive (`credentials`): `bearer` for the CF API and the log cache (and, added by `project --cf` only, the UAA authorize endpoint), `basic` for the UAA token endpoint, none for the others. A header of any other kind is refused everywhere. Any other host, any other method, or a credential a host may not receive throws `EgressDeniedError` before `fetch` runs. Unit tests cover each refused combination through the HTTP client, with nothing reaching `fetch`, and a scan test asserts that the CF token went to the CF API and the log cache only.

---

## 7. Decisions (resolved 2026-09-29)

- **D1: npm registry allowed.** `registry.npmjs.org` is on the allow-list for GET `/<pkg>` only, restricted to `@sap/cds`, `@sap/approuter`, `@sap/xssec` and `@sap/xsenv`. It is used by `SAP_PKG_OUTDATED` for the current `dist-tags.latest`.
- **D10 (2026-11-22): package names leave the machine only for public npm packages.** Finding vulnerable (OSV.dev) and deprecated (npm registry) libraries needs the name and version of each package. Only packages whose lockfile `resolved` URL is on `https://registry.npmjs.org/` are sent; a package from any other registry, git, a file or a link is never sent and is counted as "not checked". The registry rule widens from the four `@sap/*` packages of D1 to `GET /<package>/<version>` and `/<package>/latest` for those packages, with no `Authorization` header (§12). Decided by the maintainer; not implemented yet.
- **D2: both roles documented for `--deep`.** Space Developer or Space Supporter can read `/environment_variables`. `permissions.md` notes that Supporter is narrower but can still restart and scale apps.
- **D3: route probe on by default.** One unauthenticated GET per app, 5 s timeout, no redirects. `--no-probe-routes` turns it off.
- **D4: dedicated repository.** BAIP Lens lives at the root of [`sebastianomarchesini/BAIP-Lens`](https://github.com/sebastianomarchesini/BAIP-Lens) as an npm-workspaces monorepo (`packages/cli`, `packages/ui`).
- **D5 (2026-11-13): `--min-traffic-window` defaults to 12 hours**, not 24. §9.6 found that one probed SAP BTP Log Cache node had been up 16.2 h and that an app's own metrics and log volume shrink its window further, so a 24-hour minimum would make `unknown` the answer for almost every app. 12 h keeps the guard against judging an app on a few minutes of history while still letting a normal scan say something. The flag remains configurable and the observed window is always in the evidence.
- **D6 (2026-11-13): apps reachable only over TCP or an internal domain are `unknown`**, with no separate signal value. §9.3 confirmed that neither traffic class produces a router access log at all (`cf-tcp-router` emits none, and container-to-container traffic bypasses gorouter), so their traffic is not measurable in principle. They share the `unknown` state of apps with no data rather than carrying a third label, because one state fewer is one state less to explain. An `unknown` app has no finding; its reason (`traffic_not_measurable`) is in the inventory, which the report's Usage column and the apps CSV show.
- **D7 (2026-11-15): a started app whose `web` process has the `process` health check is a worker, and `APP_IDLE` never flags it for a missing route or missing traffic.** Cloud Foundry documents that health check type for an app that "does not support TCP connections. An example of such an app is a worker" (`healthchecks.html#types`), and Cloud Controller maps the legacy `none` to it. This extends the spec's "apps with no web process (workers, jobs) are never flagged" to workers pushed as `web` with `no-route`, which would otherwise all be reported as unused with high confidence. Confirmed by the owner. A worker **stopped** for more than 90 days is still flagged as stopped, like any app: a stopped app serves nothing, so whether it would have listened for requests does not matter.
- **D8 (2026-11-16): a scan counts in the traffic history of `scan --previous` only when it could have reported `no_traffic` on its own.** A window of at least `--min-traffic-window` without a request extends the run of scans without traffic, and a request ends it; a shorter window, an empty cache or no read at all leaves the history as it was. Otherwise a short window seen scan after scan would add up to high confidence for an app whose logs Log Cache never keeps for long: a chatty app can fill its 100 000-envelope cap in seconds (§9.6). Confirmed by the owner. Applied to the inventory as well (review of 2026-11-17): an app the scan cannot see — outside `--space`, in a space none of whose apps is visible this time, or any app when the inventory could not be read in full — is "no read", so its entry is kept unchanged. Only an app missing from a space whose apps the scan read is dropped, since app visibility in Cloud Foundry is granted per space.
- **D9 (2026-11-16): high confidence from the history keeps severity `low`**, like `no_route`, which is high confidence too: an unused app is waste and attack surface, not a vulnerability, and `--fail-on medium` should not fail on it. Confirmed by the owner.

---

## 8. Local project files (`baip-lens project`)

`baip-lens project --path <dir>` is a second scan target: a local CAP or MTA project directory, read from the file system only. The collector (`packages/cli/src/collectors/project/`) makes **no network request**, starts **no child process** and never runs `git`; a static test (`test/unit/project/noEgress.test.ts`) fails if any file under the collector, the project rules or `src/project.ts` imports `child_process`, `http`, `https`, `net`, `dns` or `worker_threads`, or contains `fetch(` or a dynamic `import(`. The rules are listed in [rules.md](rules.md#project-rules). Verified 2026-10-29 against the sources named below.

### 8.1 The root

- `--path` is resolved with `realpath` and must be a directory that contains at least one of `package.json`, `mta.yaml`, `mta.yml`, `.cdsrc.json` or `.cdsrc.yaml`; otherwise the command stops with exit code 2. Every error about the root repeats the user's own `--path` argument and a fixed sentence per error code (`does not exist`, `is not a folder`, `cannot be read: permission denied`, `is a symbolic link loop`, `cannot be read`); the real path and the system message are never printed.
- After the root check no error escapes: a file that cannot be read or parsed becomes an `unreadable: { file, kind }` entry (`json`, `yaml`, `csv`, `cds`, `html`, `binary`, `too-large`) and the scan continues. A YAML document with syntax errors counts as unreadable (`yaml` is run with `prettyErrors: false`, `logLevel: 'silent'`, `maxAliasCount: 100`, `uniqueKeys: false`, `merge: true` (merge keys `<<` are applied, as the MTA build tool does) through `parseDocument`, and a document with errors is dropped, because with a silent log level `YAML.parse` would return a best-effort value instead of throwing). Check reasons therefore never carry a path, a line number or file content.

### 8.2 The walk

- `lstat` only; only regular files and directories are visited. Symbolic links, FIFOs, sockets and devices are skipped and never listed.
- Skipped directories: `node_modules`, `.git`, `gen`, `dist`, `dist-report`, `target`, `build`, `coverage`, `.vscode`, `.idea`, every directory whose name starts with `.` (except the root), and the resolved `--out` directory.
- Limits: depth 12; 20 000 directory entries visited; 2 000 files opened; 64 MiB read in total; 500 file names listed in `files[]`; 200 unreadable entries. Beyond a limit the walk stops and `filesTruncated` is `true`; `filesOpened` counts every file inside the project the collector opened (listed or unreadable), whatever the listing cap, and is the count the terminal prints.
- A cds configuration source (`.cdsrc.json`, `.cdsrc.yaml`, `package.json#cds`) nested deeper than 32 levels is recorded as unreadable (`json` / `yaml`) instead of being merged: the merge and the profile resolution recurse one level per object, and are themselves capped at that depth.
- Paths are stored relative to the root with `/` separators and must pass `isSafeRelativePath` (`packages/cli/src/model/paths.ts`: 1–512 characters, no `\`, NUL, CR or LF, not rooted, no `.`, `..` or empty segment); anything else is dropped.

### 8.3 Files read (allow-list) and never read (deny-list)

| Read | How |
| --- | --- |
| Root `package.json` | `name`, `dependencies` and `devDependencies` (names and version ranges; a range that is not a registry range becomes `[non-registry]`), `engines.node`, and the `cds` block as a configuration source. Nothing else (`author`, `repository`, `scripts`, …). |
| Root `.cdsrc.json`, root `.cdsrc.yaml` | as configuration sources (§8.4). |
| Root `mta.yaml` / `mta.yml` | `ID`, `modules[].{name,type,path,requires[].name,parameters.buildpack}` (a buildpack name of at most 100 characters `[A-Za-z0-9_.-]`, or an http(s)/git URL reduced to scheme, host and path; anything else, such as a local path, becomes null; merge keys `<<` are applied), `resources[].{name,type,parameters.service,parameters.service-plan}`, and for resources with `parameters.service: xsuaa` the `parameters.config.scopes[].{name,granted-apps,grant-as-authority-to-apps}` and `role-templates[].{name,scope-references}` as a security descriptor with source `mta.yaml`. Never: `properties`, `build-parameters`, `hooks`, `provides`, `service-key`, destinations, any other `config.*`. |
| Any `xs-security.json` | `scopes[].{name,granted-apps,grant-as-authority-to-apps}`, `role-templates[].{name,scope-references}`, `attributes[].name`. Never: `description`, `oauth2-configuration`, `foreign-scope-references`, `authorities`, `xsappname`, `tenant-mode`. |
| Any `xs-app.json` | `authenticationMethod`, `logout.logoutPage` (only to flag the logout route), `routes[].{source,authenticationType,csrfProtection}` and which of `destination` / `service` / `localDir` is present, plus a hint computed from the destination or service name (`ui5-cdn`, `html5-repo`, `api`, `other`); the name itself is not stored. Never: `target`, `scope`, `httpMethods`, `cacheControl`, `identityProvider`, … |
| `*.cds` | after stripping comments and string literals: `using … as` aliases, `service`, `entity` (with element names, `Association to` / `Composition of` targets, `as projection on` targets), `action` / `function` and `annotate` statements; of the annotations only the string values of `requires` and of `to` inside `restrict`, and the presence of `@readonly`, `@protocol: 'none'`, `@cds.external` and `@PersonalData`. Never: `where`, `grant`, `@title`, `@assert.*`, `@Common.*`, i18n keys, element types, defaults. Caps per file: 500 services, 2 000 entities, 200 elements per entity, 2 000 annotates; the regexes have no nested quantifiers (a ReDoS test runs a 2 MiB hostile file under 2 s). |
| `*.csv` under a directory named `data` or `csv`, and `test/data` | the header (accepted only when every field is identifier-shaped and there are at most 200 fields, else `headerRejected`) and the first 200 data rows, checked value by value for the sensitive column patterns of `SEED_DATA_SENSITIVE`; only the 1-based positions of the matching columns, the kind and the match counts are kept, never a cell value or a header name (a header-less file whose first row is identifier-shaped would otherwise turn a cell value into a column name). |
| `*.html` | the `<script>` tags with `id="sap-ui-bootstrap"` or a `src` ending in `sap-ui-core.js` (a simple attribute tokenizer; every `<script` tag is examined and the scan resumes after each tag; a start tag is read up to 16 KiB; at most 200 bootstraps, not tags, per file and per project). The `src` of an http(s) URL is reduced to origin and path (at most 200 characters; user info, query and fragment dropped), a relative `src` to its file name (never a path, which could be absolute or climb out of the project); other schemes become `[non-http]`; `integrity` is recorded as present or absent, never its value. |
| Root `.gitignore` and the `.gitignore` files on the path of a `*.mtar` (opened only when an archive exists; listed in `files[]`, or under `unreadable`, like any other file read), and the `.gitignore` files of the directories between the repository root (where `.git` was found) and the project root (outside the project: read for the decision only; never listed in `files[]`, counted or recorded as unreadable) | only to decide whether an archive is ignored: comments, blank lines, `!` negation, leading `/`, trailing `/`, `*`, `?`, `**`, character classes, patterns without `/` at any depth, last match wins. A glob-to-table matcher, not generated regexes (a hostile pattern cannot stall the scan); patterns over 1 024 characters and beyond 2 000 rules per file are ignored. `.git/info/exclude` and global excludes are not read. |
| `*.mtar` | `lstat` only (name and size); never opened. |
| `.git` in the root and in each ancestor up to the file-system root (at most 64 levels) | `lstat` only, to set `repository` and to find the repository root for the `.gitignore` files above the project; never read. |

**Never opened and never listed** (checked before the allow-list, with a unit test): `.cdsrc-private.json`, `.cdsrc.js`, `default-env.json`, `.env` and every name starting with `.env`, `*.mtaext`, `*-key.json`, `*.pem`, `*.key`, `*.http`, `manifest.json`, `*.md`, and every other file name.

**Read:** `fs.open` with `O_RDONLY | O_NOFOLLOW`, `fstat` must report a regular file of at most 2 MiB (else `unreadable: too-large`), at most 2 MiB are read, and a NUL byte in the first 8 KiB marks the file `binary`.

### 8.4 cds configuration sources ✅

Verified from the "Sources for cds.env" table of `node.js/cds-env.md` in the `cap-js/docs` GitHub mirror (`cap.cloud.sap` does not resolve from the build environment), lowest priority first:

| Order | Source | BAIP Lens |
| --- | --- | --- |
| 1 | `@sap/cds` defaults | not needed: `null` means "the default" and every rule treats it as such (production auth defaults to `jwt`) |
| 2 | `~/.cdsrc.json` | never read (outside the project) |
| 3 | `./.cdsrc.yaml`, `./.cdsrc.json`, `./.cdsrc.js` | `.cdsrc.yaml` then `.cdsrc.json` are read; `.cdsrc.js` is code and is never read |
| 4 | `./package.json#cds` | read |
| 5 | `./.cdsrc-private.json` | never read (credentials) |
| 6 | `default-env.json` (deprecated) | never read (credentials) |
| 7 | `.env`, `.<profile>.env` | never read (credentials) |
| 8 | `CDS_CONFIG`, `CDS_*` process environment | never read |
| 9 | `VCAP_SERVICES`, `~/.cds-services.json` | never read |

The three sources read are deep-merged in that order (a string under `requires` merged with an object is treated as cds' `{ kind }` shorthand), then for each of the two views `development` and `production` the `[view]` blocks are applied at every nesting level, followed by the `[view!]` blocks; other profiles are ignored. Of the merged result only `requires.auth` (string or `.kind`), the number of keys of `requires.auth.users` and how many of them have a `password` key, `requires.auth.restrict_all_services` and `requires['audit-log']` (string or `.kind`, and whether it is present) are kept; unknown strategy and kind strings become `other`; the legacy spellings `mocked-auth`, `basic-auth` and `dummy-auth` are normalised. `sourcesRead` records which of the three files were read and parsed and carried a cds configuration (`package.json` only when it has a `cds` key); a file that exists but is unreadable or malformed is listed under `unreadable` instead and does not appear. Consequence for every rule: the findings reflect the committed configuration; the higher-priority sources can change the effective value at runtime, and each rule says so in its limits.

### 8.5 Other sources verified for the project rules

- CAP authentication strategies, the pre-defined mock users and `restrict_all_services` (`node.js/authentication.md`), `@requires` / `@restrict`, the implicit `authenticated-user` requirement and the propagation of restrictions to projections (`guides/security/authorization.md`), the XSUAA role mapping and the merge of the inline `mta.yaml` config with `xs-security.json` (`guides/security/cap-users.md`), `@PersonalData` and the audit-logging plugin (`guides/security/dpp-annotations.md`, `guides/security/dpp-audit-logging.md`), initial data folders (`guides/databases/initial-data.md`): all from the `cap-js/docs` GitHub mirror. The former `guides/data-privacy/*` paths no longer exist there.
- `@cap-js/audit-logging` binding resolution (`vcap.label: auditlog` for restv2, binding name `auditlog-ng` for alsng; `[production]` defaults to restv2) from the `cap-js/audit-logging` repository; what `cds add audit-logging`, `cds add approuter`, `cds add app-frontend`, `cds add html5-repo` and `cds add workzone-standard` write from the `@sap/cds-dk` 10.2.0 tarball on the npm registry (`lib/init/template/*`); `@sap/cds` loads plugins from `devDependencies` only while `NODE_ENV` is not `production` (`lib/plugins.js`).
- Application router `authenticationType`, `authenticationMethod`, `csrfProtection` (default `true`, applied to every method other than `GET` and `HEAD` on non-public routes) and the logout route from the `SAP-docs/btp-cloud-platform` mirror (`docs/30-development/routes-666eb55.md`, `routing-configuration-file-c103fb4.md`, `application-router-configuration-c19f165.md`, `authenticationmethod-ff58bb0.md`, `logout-2296b4d.md`); the security descriptor syntax (`$XSAPPNAME` prefix, `scope-references`, `granted-apps`, `grant-as-authority-to-apps`, `authorities`) from `application-security-descriptor-configuration-syntax-517895a.md`; MTA archives from `multitarget-applications-in-the-cloud-foundry-environment-d04fc0e.md`; the Audit Log service name and plan from `audit-log-write-api-for-customers-64e99bb.md`.
- SAPUI5 CDN URL forms (specific, evergreen, unversioned) and the CDN removal one year after end of maintenance (SAP Note 3001696) from the `SAP-docs/sapui5` mirror (`docs/04_Essentials/variant-for-bootstrapping-from-content-delivery-network-2d3eb2f.md`, `bootstrapping-loading-and-initializing-a04b0d1.md`).
- The Cloud MTA Build Tool defaults (`mta_archives/`, module folder as build result, `build-parameters.ignore`) from the `SAP/cloud-mta-build-tool` mirror (`docs/docs/usage.md`, `configuration.md`); `gitignore(5)` from the `git/git` mirror (`Documentation/gitignore.adoc`).
- **OWASP Top 10 (2025):** the category names and the URL pattern `https://owasp.org/Top10/2025/<id>_2025-<Title_with_underscores>/` were verified from `2025/mkdocs.yml` in the `OWASP/Top10` GitHub repository (`site_url` and the `nav` entries, for example `A07 Authentication Failures: en/A07_2025-Authentication_Failures.md`); `packages/cli/src/model/owasp.ts` holds the map and builds every link from that one pattern. The 2025 edition merged "Vulnerable and Outdated Components" into A03 Software Supply Chain Failures.

---

## 9. Traffic and route signals for `APP_IDLE`

What `APP_IDLE` needs beyond §2: which apps have a route, which have a `web` process, and when a router last served a request for them. This section records what was confirmed **before** the collectors were written; §9.7 says how the code (`collectors/routes.ts`, `collectors/processes.ts`, `collectors/traffic.ts`, `http/logCacheClient.ts`, `analyzers/idleApps.ts`) follows it.

- **Verified on:** 2026-11-13.
- **Log Cache source of truth:** [`cloudfoundry/log-cache-release`](https://github.com/cloudfoundry/log-cache-release) at tag **`v3.2.17`**, the version SAP BTP reports (below). Its API documentation is [`src/README.md`](https://github.com/cloudfoundry/log-cache-release/blob/v3.2.17/src/README.md); `docs.cloudfoundry.org` has no Log Cache API reference of its own and points there. Behaviour was read from `src/internal/auth/cf_auth_middleware.go`, `src/internal/cache/log_cache.go`, `src/internal/cache/store/store.go` and `src/internal/syslog/server.go`.
- **Router side:** [`cloudfoundry/routing-release`](https://github.com/cloudfoundry/routing-release) (`src/code.cloudfoundry.org/gorouter/accesslog/*`, `jobs/gorouter/templates/gorouter.yml.erb`) and [`cloudfoundry/loggregator-agent-release`](https://github.com/cloudfoundry/loggregator-agent-release) (`src/pkg/egress/syslog/rfc5424.go`, `src/pkg/egress/syslog/log_source.go`, `jobs/loggr-syslog-agent/spec`). `cf-deployment` v60.11.0 pins **routing-release 0.397.0** and **loggregator-agent-release 8.3.31**; ⚠️ the files above were read on the moving `develop` and `main` branches, which matched those releases on the points used here.
- **CF v3 source of truth:** as §1, re-read at `cloud_controller_ng` commit `d8e6494c` (= capi-release 1.250.0 = **CC API 3.235.0**, the version SAP BTP reports) and at `main` (`5a849387`, API 3.238.0). The routes, destinations, domains, processes and apps docs are identical in both, and unchanged since the commit named in §1.
- **Platform version observed** (unauthenticated `GET /`, `GET /v3/info`, `GET /api/v1/info` on `eu10` and `us10-001`, 2026-11-12): CC API **3.235.0**, `/v3/info` `build v60.11.0` of `cf-deployment`, Log Cache **3.2.17**. Upstream [`cf-deployment` v60.11.0](https://github.com/cloudfoundry/cf-deployment/blob/v60.11.0/cf-deployment.yml) pins capi-release 1.250.0 and log-cache 3.2.17, so the sources above are the ones running there — unless SAP patches them, which SAP does not document.

Legend as in §1: ✅ confirmed in primary docs or source · 🟡 confirmed second-hand · ⚠️ not confirmed, implemented defensively.

### 9.1 Routes and destinations (item 1) ✅

**One call covers the whole route side:** `GET /v3/routes?space_guids=<spaces>&per_page=5000&include=domain`, following `pagination.next`.

- **Destinations are embedded in every route object of a list response** ✅. The list renders each resource with the same presenter, which always builds `destinations` from the route's mappings. Each destination carries `guid`, `app.guid`, `app.process.type`, `weight` (deprecated, nullable), `port`, `protocol`, `created_at`, `updated_at`. A route holds at most 100 destinations, and `destinations[].created_at` is when that mapping was made.
- **Route fields** ✅: `guid`, `created_at`, `updated_at`, `protocol`, `host`, `path`, `port` (nullable), `url` (no scheme), `destinations`, `relationships.{space,domain}`, `options` (**the key is omitted when unset**), `metadata`, `links`.
- **`include`** accepts `domain`, `space`, `space.organization` and `route_policies`; `per_page` is 1–5000 ✅. `include=domain` returns the domain objects under `included.domains` with `name`, **`internal`**, `supported_protocols` and `router_group`.
- **Scope filters** ✅: `organization_guids` matches the **owning** space's org; `space_guids` matches routes owned by *or shared into* those spaces; `app_guids` matches routes with a destination for those apps. Filters combine with AND. The collector filters by `space_guids`, as `apps.ts` does, so a route shared in from another org is not missed and does not become a false `no_route`.
- **Protocol** ✅: the route `protocol` is `http` or `tcp` and is derived from the domain, not stored on the route. ⚠️ **A route on an internal domain still reports `protocol: "http"`**, so an internal route is recognised only by `domain.internal === true`. A TCP route has `protocol: "tcp"` and a non-null `port`.
- **Roles** ✅: `GET /v3/routes`, `/v3/processes` and `/v3/domains` are "All Roles" with results filtered by role; `GET /v3/routes/:guid` and `/v3/routes/:guid/destinations` name Space Auditor and Org Auditor; `GET /v3/apps/:guid/routes` names Space Auditor but **not** Org Auditor.
- **A missing role is never a 403 here** ✅. List endpoints answer 200 with a filtered, possibly empty list; single-resource reads answer 404. 403 appears only when the token lacks the read scope. The `insufficient_role` path of `CheckRecorder` therefore cannot fire for these endpoints, exactly as §2.1 already notes for apps and droplets.
- ⚠️ **Shared routes:** with the experimental `route_sharing` feature flag a route can be shared across spaces and orgs, and the presenter renders every mapping with **no permission check**, so `destinations[].app.guid` can name an app in a space the scanning user cannot read (while `GET /v3/routes/:guid` answers 404 for that same route). The collector ignores destinations whose app is not in the scanned inventory and never writes their GUIDs anywhere. Whether the flag is on in SAP BTP is undocumented; SAP's cockpit documentation says a route maps to an app in the same space.

### 9.2 Processes ✅

`GET /v3/processes?space_guids=<spaces>&types=web&per_page=5000` ("All Roles", `per_page` 1–5000) gives `type`, `instances`, `updated_at` and `relationships.app`.

- `instances` is the **desired** count, and the process object has **no state**; whether the app runs comes from the app's `state`. Both are desired state, so a `STARTED` app whose instances are all crashed still counts as started ✅.
- ⚠️ **An app can have more than one `web` process**: a rolling or canary deployment creates a second one. The analyzer takes the maximum over the app's `web` processes.
- **Redaction** ✅: for a Space Auditor only `command` is redacted (`[PRIVATE DATA HIDDEN IN LISTS]` in every list response, for every caller). Nothing `APP_IDLE` needs is affected, and BAIP Lens does not read `command` at all (§2, privacy.md).
- **Running a `web` process with no route is a supported configuration** ✅ (the manifest's `no-route`), which is why `no_route` is a low-severity signal and not an error. The process's `health_check.type` (`port`, `http` or `process`; default `port`) goes into the evidence, because `process` plus no route is far more likely a worker than a forgotten app.
- ⚠️ **`updated_at` triggers are undocumented.** The docs define `updated_at` only as "the time with zone when the object was last updated"; the start, stop, restart, scale, destination and droplet endpoints say nothing about it. From the model code: starting or stopping an app changes `app.updated_at` only when the desired state really changes (restarting an already-started app does **not**); scaling a process always changes `process.updated_at`; mapping or unmapping a route explicitly sets `updated_at` on each targeted process but leaves `route.updated_at` alone; assigning a current droplet (the end of a restage) always changes `app.updated_at`. Every rule that reads these timestamps treats them as an **upper bound** on the last change, as §4 already does for the "stopped > 90 days" branch.

### 9.3 Log Cache: reading an app's envelopes (item 2) ✅

The host comes **only** from `links.log_cache` of `GET /` (§1.1); it is absent when log cache is not deployed. It is the one host besides the CF API that `scan` sends the CF token to (§9.7); `project --cf` also sends it to the UAA authorize endpoint (§10.1).

`GET /api/v1/read/<source-id>` — GET only, bound as `get "/api/v1/read/{source_id=**}"`. For an app the source id is its **GUID** (the API docs also accept an app name or a component name).

| Parameter | Type and unit | Default | Notes |
| --- | --- | --- | --- |
| `start_time` | int64, UNIX **nanoseconds** | start of the cache | **inclusive** |
| `end_time` | int64, UNIX **nanoseconds** | current time of the cache | **exclusive** — the docs write the range as `[starttime..endtime)` |
| `envelope_types` | enum, repeatable | all types | `LOG`, `COUNTER`, `GAUGE`, `TIMER`, `EVENT`; **repeat the parameter** for several types. A comma-separated list is parsed as one value and fails; names must be upper case |
| `limit` | int64, envelopes | **100** | **maximum 1000** |
| `descending` | bool | **false = ascending** | |
| `name_filter` | Go regexp | — | in the proto and enforced by the store, **not** in the API docs. It matches counter, gauge and timer *names* only, so setting it removes every `LOG` envelope |

Consequences, all confirmed in the store and gateway code:

- **`descending=true` must always be sent.** The default walks *upwards* from the oldest envelope, so a default read returns the **oldest** envelopes held, not the newest ✅.
- **`limit` above 1000 is rejected, not clamped**, and the error is a plain Go error: gRPC turns it into `Unknown`, which the gateway maps to **HTTP 500** with a `google.rpc.Status` body — not 400 ✅. An unparsable parameter (non-integer `limit`, unknown envelope type, non-boolean `descending`) is `InvalidArgument` = **400**. Unknown query parameters are ignored.
- **Response shape** ✅: `{"envelopes":{"batch":[...]}}` plus a newline. The gateway marshals with `UseProtoNames: true, EmitUnpopulated: true`, so envelope keys are **snake_case** (`source_id`, not `sourceId`) and empty values are emitted (`deprecated_tags: {}`). Per envelope: `timestamp`, `source_id`, `instance_id`, `tags` (string → string), `deprecated_tags`, and at most one of `log`, `counter`, `gauge`, `timer`, `event`.
- **`timestamp` is a JSON string of decimal int64 nanoseconds** (about 1.7e18, far beyond `Number.MAX_SAFE_INTEGER`) ✅. It must be parsed with a digits-only schema and handled as `BigInt`, never round-tripped through `Number`.
- **`log.payload` is base64** (a proto `bytes` field) and `log.type` is `"OUT"` or `"ERR"` ✅. The payload is **never decoded, stored or logged**: only the timestamp and `tags.source_type` are read (§9.7).
- **protojson output is explicitly not byte-stable**, so responses are parsed as JSON and never matched as text ✅.
- **Paging backwards has no cursor** ✅: `ReadResponse` has one field. The next older page is the same request with `end_time` set to the timestamp of the oldest envelope of the current page; because `end_time` is exclusive, that envelope is not returned twice.
- ⚠️ **Several envelopes of one source can share a timestamp**, and the store deliberately returns **more than `limit`** rather than split such a group. The collector must not assert `batch.length <= limit` and must not de-duplicate by timestamp.
- **A page with fewer than `limit` envelopes means the stored range was exhausted** ✅: the type filter runs inside the store traversal, non-matching envelopes do not count towards `limit`, and the walk continues until `limit` matches are collected or the source's range ends. That is the honest stop condition for "nothing older is held".
- ⚠️ **An empty batch is not proof of silence.** Each source lives on exactly one node (replication factor 1); when the owning node is unreachable the read returns a **successful empty batch**. Empty therefore means `unknown`, never `idle`.
- ⚠️ **429 is not rate limiting, and its origin is not settled.** Log Cache has no request rate limiter, no concurrency limit and no response compression on the read path, and nothing in its source writes a 429. One reading is that it arises from the gRPC mapping: nodes talk to each other with a 50 MiB receive limit, and `ResourceExhausted` maps to HTTP 429. The other is that a 429 can only come from a layer in front of Log Cache (a platform limiter). Either way the cf CLI treats it as "response too large" and halves its limit, up to ten times, down to 1 — which is the behaviour to copy, rather than waiting as for a CF API 429.
- **Other statuses** ✅: `Unavailable` → 503 (no node found), gateway unreachable from the auth proxy → 502, `DeadlineExceeded` → 504. The gateway and proxy set only a 2 s read-header timeout; the proxy's CAPI and UAA clients time out after 20 s. ⚠️ The cf CLI replaces go-log-cache's 5 s default with a client that has **no** overall deadline, which is why `cf logs` can hang; BAIP Lens keeps its own bounded timeout, as for the CF API.

**Cross-check against the reference clients** ✅. cf CLI v8 (v8.19.1, pinning `go-log-cache` v2.0.7) implements `cf logs --recent` as **exactly one** read:

```
GET /api/v1/read/<app-guid>?descending=true&envelope_types=LOG&limit=1000&start_time=<nanos>
```

preceded by one unauthenticated `GET /api/v1/info`, which the library uses only to choose `/api/v1` over the legacy `/v1`. Three lessons:

- **No client pages backwards.** `go-log-cache`'s `Walk` only moves *forward* (`Start = last.Timestamp + 1`). The backward walk this rule needs exists nowhere upstream and is built here from `descending=true` plus a moving `end_time`.
- **`start_time` is omitted.** The library always sends it, and for a zero `time.Time` that becomes the nonsense value `-6795364578871345152`; the API documents the default as the start of the cache, so leaving it out is both cleaner and safe from the server's `start_time > end_time` check.
- **The version probe is skipped** (BTP reports 3.2.17, so the `/api/v1` prefix is fixed). `/api/v1/info` needs **no token**, so it can never double as an authorization or reachability check for an app.

⚠️ The `log-cache-cli` plugin derives the host with `strings.Replace(apiEndpoint, "api", "log-cache", 1)`. That heuristic is **explicitly rejected** here: the host comes only from `links.log_cache` of `GET /`, as the cf CLI itself does.

**How a router access log is identified** ✅ — the expectation holds, and the chain was read end to end:

1. gorouter's `DropsondeLogSender.SendAppLog` sets `sourceType := "RTR"`, `messageType = LogMessage_OUT` and `AppId = <app guid>`, with the access-log line as the message. Emission is **not** an operator property: `jobs/gorouter/templates/gorouter.yml.erb` hardcodes `'loggregator_enabled' => true`.
2. **Only requests that reached an app instance are logged under the app's source id** ✅: `SendLog` passes `AccessLogRecord.ApplicationID()`, which is `""` when no `RouteEndpoint` was selected; `LogMessage()` returns `""` for an empty app id, and `SendAppLog` drops a record with an empty app id. A request that got a 404 because no route matched, or that failed before a backend was chosen, produces **no** envelope under any app. An `RTR` envelope is therefore evidence that a request was really dispatched to an instance of that app, not merely that something hit the route.
3. The syslog agent's RFC 5424 converter puts `tags["source_type"]` into the **PROCID** *and* passes **every** tag into the `tags@47450` structured-data element (`buildTagsStructuredData` applies no filter). `default_drain_metadata` defaults to **true** in `jobs/loggr-syslog-agent/spec`, and the Log Cache aggregate drain of `cf-deployment` v60.11.0 (`syslog-tls://log-cache.service.cf.internal:6067?include-metrics-deprecated=true&ssl-strict-internal=true`) does not turn it off.
4. Log Cache's syslog server builds the envelope with `source_id` = syslog APP-NAME (the app GUID), `timestamp` from the syslog timestamp (the **emitter's** time, not arrival), `instance_id` from the **last** `/`-separated token of PROCID, and copies the `tags@47450` parameters into `envelope.tags`.

So a router access log is **a `LOG` envelope whose `tags.source_type` is `RTR`**, and the match is on that tag alone. ⚠️ If an operator set `drain-metadata=false` on the Log Cache drain, `source_type` would survive only inside PROCID, which Log Cache reduces to `instance_id`; the tag would then be missing from *every* envelope, which the collector reports as `unknown` rather than guessing. `instance_id` is dropped: it is not needed and is infrastructure detail.

⚠️ On an `RTR` envelope `instance_id` is the **gorouter's** own index, not the app instance (gorouter sets `SourceInstance` to its own index). One more reason the collector keeps no instance.

**Other source types share an app's source id** ✅ (`log_source.go`, documented in the upstream "streaming logs" format reference): `API`, `STG`, `RTR`, `LGR`, `APP` (as `APP/PROC/WEB`), `SSH`, `CELL`, and in newer releases `PROXY`, `HEALTH`, `STATS`. A page of `LOG` envelopes can therefore be mostly application output, which is why the read filters on `envelope_types=LOG` and then on the tag, and why a page cap exists at all.

**Which traffic produces no `RTR` envelope at all** ✅ — this decides which apps the rule can judge:

| Traffic | App-scoped envelope? |
| --- | --- |
| HTTP request routed to an app instance | **yes** — the only case |
| Request to an unmatched route (404 at the router) | no — no `RouteEndpoint`, so no app id |
| gorouter's load-balancer health check | no |
| The route-service leg | no — it deliberately uses an empty `route.Endpoint` with no `ApplicationId` |
| **TCP routes** | **no** — `cf-tcp-router` has no app-log emission code at all |
| **Internal domains (container-to-container)** | **no** — that traffic bypasses gorouter entirely |

⚠️ So an app whose only routes are TCP or internal-domain routes **can never be judged by access logs**, however busy it is. Such apps are `unknown`, never idle — which is why §9.1 classifies every route from `domain.internal` and `protocol` before the traffic check runs. ⚠️ Whether a websocket's envelope is emitted at upgrade or at close was not established.

🟡 **A payload-free alternative exists but is worse for privacy.** Because the Log Cache drain carries `include-metrics-deprecated=true` (`DrainData=ALL`), gorouter's `HttpStartStop` events are forwarded as **`TIMER` envelopes named `http`**, and Log Cache's syslog server does reconstruct them. Reading `envelope_types=TIMER` would give a last-request time with no log line to discard — but their tags carry `uri`, `remote_address`, `user_agent` and the `X-Forwarded-For` chain, i.e. *more* personal data than the access log the collector refuses to keep. ⚠️ Whether SAP BTP's drains forward timers is unknown. Not used in v0.2; recorded so the choice is deliberate.

### 9.4 Log Cache: `/api/v1/meta` (item 3) ✅, but not used

`/api/v1/meta` does report the oldest timestamp held per source, and a non-admin user may call it — but it is the wrong tool here.

- **Response** ✅: one object under `meta`, keyed by source id, each with `count`, `expired`, `oldestTimestamp`, `newestTimestamp`. The API docs' own field list says `expired` is there only "if present", that is, when envelopes have been pruned.
- ⚠️ **Two different JSON conventions on the same host.** `/api/v1/meta` is built by the auth proxy with **default** protojson options, so its keys are **lowerCamelCase** and zero values are **omitted**; an empty result is `{}` with **no `meta` key at all**. `/api/v1/read` goes through the gateway with `UseProtoNames`/`EmitUnpopulated`, so it is snake_case and emits zeros. All four meta values are int64 **as JSON strings**. Neither endpoint sets `Content-Type`, so a client must not require `application/json`.
- **Semantics** ✅: the four values cover **all envelope types** of the source (one AVL tree per source id; the envelope type is not considered). Both pruning paths remove the smallest timestamp key first, so pruning is strictly **oldest-first** and every envelope at or after `oldestTimestamp` is still held — which is what would make `oldestTimestamp` a sound window start.
- **Non-admin callers are served** ✅: a caller counts as admin only with the `doppler.firehose` or `logs.admin` scope; everyone else gets the **intersection** with the source ids they may see.
- ⚠️ **But the visible-source lookup is expensive and silently fallible.** For a non-admin the proxy calls `GET /v3/apps?per_page=5000` and then `GET /v3/service_instances?per_page=5000` **with the caller's own token**, following every page, with **no caching** (its 60 s cache holds only per-source `read` authorizations). The lookup has **no org or space filter**, so it covers every app the user can see in the whole landscape, not only the scanned org. If any page fails — transport error, timeout, 429 from the CF rate limiter, any non-200 — the proxy answers **200 with an empty result**, indistinguishable from "no visible sources".
- ⚠️ **Version 3.2.17 — the one SAP BTP reports — has a race in `Store.Meta()`**: it re-loads each source in a second pass and type-asserts the result unchecked, so a source deleted by the truncation loop between the passes makes the call **panic**. Fixed in v3.2.18 (released 2026-11-04); no `cf-deployment` release pins 3.2.18 yet. Each uncached meta call reaches this code (the meta cache holds one second).
- **Aggregation can be partial without saying so** ✅: meta is merged across nodes by the Log Cache node, and a node whose call fails is logged and skipped; only if *every* node fails does the caller see 502.

**Decision:** `/api/v1/meta` is **not** called. The window start comes from the app's own data: when the newest-first walk ends without a router log, one extra **ascending** read with `limit=1` and no type filter returns the oldest envelope Log Cache holds for that app — the same number meta would report, at the cost of one read instead of two Cloud Controller calls, and without touching the 3.2.17 panic. If that read is empty, `windowStart` is `null` and the app is `unknown`.

### 9.5 Which roles Log Cache accepts (item 4) ✅ upstream, ⚠️ on SAP BTP

**The API documentation states the authorization model** ✅:

> The scopes `doppler.firehose` and `logs.admin` are authorized as `admin` […] For more limited scopes, Cloud Controller is consulted to establish app permissions.

and, decisively for the collector:

> Please note that in case of missing or insufficient authorization, an http status code of 404 (not found) will be returned to discourage malicious actors. Don't expect 401 or 403.

**The code agrees** ✅ (`cf_auth_middleware.go` at v3.2.17). On `/api/v1/read/{sourceID}` it writes `StatusNotFound` for an empty source id, a missing `Authorization` header, a token it cannot read, and a non-admin caller that `IsAuthorized` rejects; there is no 401 or 403 on the path. For a non-admin the authorizer calls **`GET /v3/apps/<source-id>`** with the caller's own header and, if that is not 200, `GET /v3/service_instances/<source-id>`; a 200 authorizes and is cached per token and source id for 60 s. Any other outcome — a CAPI error, a timeout, a 429 — counts as "not authorized".

So **the role question reduces to "may this user `GET /v3/apps/:guid`?"**, which §2 already answers. The official Cloud Foundry roles table confirms it from the other side: in `_oss_roles_table.html.md.erb` the row **"View app logs" is Yes for Space Developer, Space Auditor, Space Manager, Space Supporter, Org Manager, Global Auditor, Admin and Admin Read-Only**, and blank for Org Auditor, Org Billing Manager and Org User.

| Role | Log Cache read for an app in that space | Why |
| --- | --- | --- |
| **Space Auditor** | yes ✅ | may `GET /v3/apps/:guid`; "View app logs" = Yes |
| Space Developer, Space Manager, Space Supporter | yes ✅ | same |
| Org Manager | yes ✅ | same |
| Org Auditor only | **no** ✅ | cannot read the app; "View app logs" blank |
| Global Auditor, Admin Read-Only | yes ✅ | global read |
| `doppler.firehose` / `logs.admin` scope | yes, everything ✅ | admin path; never used by BAIP Lens |

**Declared role: Space Auditor**, as §2.1.

⚠️ **SAP BTP does not document this.** A code search of the SAP BTP documentation source (`SAP-docs/btp-cloud-platform`, 2 076 Markdown pages) for "log cache" and "log-cache" returns **0 hits**, and so does "log-cache" across the whole `SAP-docs` organisation. SAP's own roles page describes Space Auditor as "Provides read-only access to a space" and Space Supporter as "Allows you to troubleshoot and debug applications and service bindings in a space", mentions logs nowhere, and defers to `docs.cloudfoundry.org/concepts/roles.html` — exactly the table quoted above. It lists the same space and org roles as upstream, with Space Supporter present and unrenamed, but omits upstream's Org Billing Manager. SAP's Help page "Using Application Logs" states no role, no log count and no retention. The Regions page publishes the API endpoint, domain and cockpit URL but **no log-cache host**, so `GET /` stays the only way to learn it.

🟡 **A developers.sap.com tutorial does name "Space Developer, Space Auditor, Space Supporter"**, but it is about the **cockpit's Logs page**, not about the Log Cache API, and it lists a narrower set of three space roles than the upstream table's eight. SAP documents Log Cache itself only in two developers.sap.com tutorials ("enabled by default in SAP BTP Cloud Foundry", reachable "using the log cache API or the log cache plugin", and explicitly "not a solution for storing logs of production applications"). So SAP endorses using this API but states no roles for it; the upstream chain above is the only basis, and what a Space Auditor token really receives on SAP BTP has **not** been observed. The 404 path below is what makes this safe either way.

**No audit event** ✅: a Log Cache read makes Cloud Controller serve `GET /v3/apps/:guid`, which has **no audit type**, so unlike the `--deep` env-var read (§2, which does create `audit.app.environment_variables.show`) the traffic check leaves no trace in the customer's audit log. privacy.md records this.

⚠️ **The skip condition is 404, not 403.** This differs from every other check in `checks.ts`, which detects a missing role by a 403. 404 from Log Cache is **ambiguous** — no access, an invalid or expired token, a failed or rate-limited Cloud Controller lookup, or a missing route all look identical — so it is recorded as `skipped` with a reason that says exactly that, and never as "no traffic".

**Side effect on the CF API budget** ✅: each `read` for a new (token, source) pair costs the scanning user one Cloud Controller request (two when the app lookup is not 200). The proxy sends it to `cc.public_tls.port` (9024), the same endpoint set as public API traffic, with the user's own token, so the CF rate limiter counts it against **that user**, keyed on the user GUID.

What the limits actually are ✅, which also corrects §1.4:

- `/v3/info`'s `rate_limits.general_limit` is rendered from `per_process_general_limit`: **per Cloud Controller process, per user, per 30 minutes** (690 on `us10-001`, 334 on `eu10`). It is *not* the user's budget.
- The real per-user budget is a separate `global_general_limit`, which `/v3/info` never exposes. A client learns it only from the **`X-RateLimit-Limit`** response header.
- ⚠️ **`X-RateLimit-Remaining` is quantized**: it is the per-instance fraction rounded down to the nearest 10 %, multiplied by the global maximum, and CF's own documentation warns it can read **0 while requests still succeed**. The pacing in `http/httpClient.ts` must therefore not treat 0 as exhausted — it currently pauses below 5 % of the limit, which is safe, but a 0 is not proof and must never abort a scan.
- 🟡 SAP states the CF API limit only as "a range of a few 10k requests per hour per user on average", with 429 and `Retry-After`.

The collector therefore reads all pages of one app back to back (inside the 60 s cache), keeps Log Cache concurrency low, and counts one CF request per scanned app.

### 9.6 Retention: how far back the window reaches (item 5) ⚠️

- **In-memory only** ✅, and the release says so plainly: "all logs and metrics will always be lost upon crashes or re-deploys". The replication factor is hardcoded to **1** and source ids are mapped to nodes by xxhash plus a jump-consistent hash over the node list, so a node restart, redeploy or rescale loses that node's slice outright — and moves sources between nodes.
- **There is no age-based expiry at all** ✅: nothing in the v3.2.17 job spec or store code ever drops an envelope for being old. Only two things bound retention: the per-source item cap and heap-memory pressure.
- **Per-source cap** ✅: `max_per_source` defaults to **100 000 envelopes**, counting logs, gauges, counters, timers and events **together**; the oldest is evicted on insert once the cap is reached. Independently, truncation runs every `truncation_interval` (default 1 s) once heap use passes `memory_limit_percent` (default 50).
- **Pruning is strictly oldest-first within a source** ✅ (both paths take the leftmost node of the AVL tree), which is what lets a single ascending read establish the window start.
- ⚠️ **Memory pressure is biased against exactly the apps this rule is about.** Under pressure the store builds a heap of *every* source's oldest timestamp and repeatedly removes the **globally oldest** envelope, so all sources on a node converge to one time floor and the sources holding the oldest data — which is precisely what an idle app has — bleed first. An idle app's window is therefore systematically *shorter* than a busy app's, in the direction that produces `unknown` rather than a false finding.
- **The release itself promises no retention** ✅: its scaling section opens with "Numerous variables affect the retention of Log Cache" and lists instance count, max per source id, memory per instance and CPU. 🟡 The official operator target is far smaller than the cap suggests: `docs.cloudfoundry.org` tells operators to keep **"at least 15 minutes"** available, and the release's own `indicators.yml` warns at **30 seconds**.
- ⚠️ **Order of magnitude, as an estimate, not a promise:** with Diego's 15-second container-metrics tick (3 to 6 envelopes per instance per tick), the 100 000-envelope cap works out to roughly **2.9 to 5.8 days** for a one-instance silent app — but node uptime and memory pressure almost always bind first, and every additional instance divides it.
- ⚠️ **A chatty app evicts its own history in under a minute.** SAP publishes a log rate limit of **4 000 logs per second per app instance**, which is enough to refill a source's entire 100 000-envelope cap in **25 seconds**. For a verbose app, `windowStart` can therefore be seconds old, and the check will correctly report `unknown` instead of claiming anything.
- ⚠️ **Metrics compete with logs for the same cap.** The Log Cache drain in `cf-deployment` v60.11.0 carries `include-metrics-deprecated=true`, and Diego emits container metrics for every app instance every 15 s, each gauge value stored as its own envelope. For a quiet app the cap is filled by its own metrics, and the window shrinks as instances are added.
- ⚠️ **Observed, unauthenticated:** the Log Cache VM answering `/api/v1/info` reported `vm_uptime` **140 111 s (38.9 h)** on `us10-001` and **58 415 s (16.2 h)** on `eu10` on 2026-11-12. `vm_uptime` is the OS uptime of the VM running the answering gateway, an **upper bound** on the age of that node's cache; it says nothing about the other nodes, one of which may own a given app.
- ⚠️ **SAP BTP publishes no Log Cache retention, per-source cap or rate limit** (the 0-hit code search above). The "SAP BTP-Specific Configurations" page covers the CF API rate limit, a logging rate limit and audit-event retention, but not Log Cache. 🟡 SAP's own tutorial states that the log cache is enabled by default, recommends the `cf log-meta` plugin, points at the upstream API, and warns that it is **not** a solution for storing production logs.

**Stated assumption:** the window is **hours, not days**, and it is never assumed. Every finding names `windowStart` and the window length, and an observed window shorter than `--min-traffic-window` (default 12 h, D5) yields **no finding** and an `unknown` inventory value. Given 16.2 h on one probed node, `unknown` is expected to be the *common* outcome of a single scan. The cross-scan history (`scan --previous`) builds a longer view out of scans that each saw at least the minimum window; it never adds up short windows (D8).

⚠️ SAP documents **14 days** of retention for Cloud Foundry audit events, while §1.6 assumes the open-source default of 31 days. The event branch of `APP_IDLE` inherits the shorter figure; §1.6 is corrected when the event collectors are built.

### 9.7 Consequences for the design, as implemented

⚠️ **On trial accounts the platform stops apps by itself.** SAP documents that in trial accounts "applications stop automatically on a daily basis", at midnight relative to the region, alongside a quota of 10 routes and 4 GB of app memory. Both `APP_IDLE` branches are affected: `STOPPED` says nothing about abandonment there, and an app that was stopped overnight has no traffic for reasons of its own. Worse, ⚠️ **trial-ness cannot be inferred from the API hostname** — SAP lists `api.cf.us10.hana.ondemand.com` as the trial endpoint for `us10` while `us10-001` appears under enterprise regions, and the regions concept page says subaccounts are auto-assigned to an indexed or non-indexed instance. The scan therefore cannot detect a trial landscape reliably; the finding text and docs/rules.md must name this limitation instead of pretending otherwise. (The 0.1.0 sample scan in this repository ran against `us10-001`.)

| Assumed | Confirmed reality | What the code does |
| --- | --- | --- |
| "a 403 records the check as skipped" | Log Cache **never** answers 401 or 403; missing access, a bad token and a failed CAPI lookup are all **404** | skip on **404**, with a reason naming the three causes; 403 handling stays for the CF API |
| `/api/v1/meta` gives `windowStart` | true, but it costs two uncached CF calls, reaches beyond the scanned org, can answer empty on failure, and hits a panic race in the deployed 3.2.17 | meta is **not called**; one ascending `limit=1` read per app instead |
| read newest-first | the default is **ascending** | `descending=true` on every read |
| page backwards | no cursor; `end_time` is exclusive | `end_time` = oldest timestamp of the previous page, as the raw string |
| `limit` | maximum **1000**; above it is **HTTP 500**, not a clamp | `limit` ≤ 1000; a 429 ("too large") or a body above 16 MiB halves it and reads again; only 502–504 are retried |
| timestamps | int64 **nanoseconds as JSON strings** | digits-only schema, `BigInt` arithmetic, never `Number` |
| "no route" means idle | internal-domain routes report `protocol: "http"`; TCP and internal traffic may not produce router logs at all | route class from `domain.internal` and `protocol`; only external HTTP routes are candidates for the traffic check |
| one `web` process | a rolling deployment creates a second | maximum over the app's `web` processes |
| window ≥ 24 h | one probed node had been up 16.2 h, and metrics share the 100 000-envelope cap | `--min-traffic-window` defaults to 12 h (D5); a shorter window gives **`unknown`**, never a finding |
| every log envelope carries `source_type` | drain metadata can be turned off, and then the tags are gone (§9.3) | if no examined `LOG` envelope of an app carries a `source_type` tag, the check is skipped as an error: silence that cannot be told apart is not evidence |
| one failure means the check failed | the first read decides whether Log Cache can be read at all | a 404 on the first app skips the check (`insufficient_role`), no answer or 502–504 skips it as `unavailable`, any other status as `error`; after that a failing app stays `unknown`, and after 3 failures in a row the rest are left unread |
| "stopped > 90 days" means abandoned | trial accounts stop **every** app nightly, and trial-ness is not detectable from the endpoint | keep the branch, name the trial caveat in the finding and in docs/rules.md |
| a `TIMER` signal would avoid log payloads | router timers are forwarded upstream, but their tags carry `uri`, `remote_address` and `user_agent` | not used; `LOG` + `source_type` stays the signal |

**Allow-list (§6), as implemented.** The log cache rule allows `GET` on `/api/v1/read/<app-guid>` only (**not** `/api/v1/info`, `/api/v1/meta` or the PromQL endpoints), for the host taken **only** from `links.log_cache`, and lists `bearer` as the one kind of credential it may receive. It is the second and last host that may receive the CF token: every rule lists the credential kinds it accepts, and unit tests assert that the token reaches no other host.

**Privacy (privacy.md) changes for slice 2.** Logs are read for the first time. Kept per app: `lastRequestAt`, `windowStart`, `envelopesExamined`. Dropped at parse time: `log.payload` (the access-log line, which carries the client IP, the request path and query, the user agent and tracing headers), `instance_id`, and every tag except `source_type`. The one envelope of any type read for the window start (a gauge, or a router `http` timer with `uri`, `remote_address` and `user_agent` tags) is reduced to its timestamp the same way. ⚠️ Envelope **tags** carry identifying data too — the router sets the route endpoint's tags (app, space and org metadata), and router timer envelopes carry `uri`, `remote_address` and `user_agent` — so the tag map is read for one key and then discarded.

### 9.8 Open questions (only an authenticated call settles these)

1. What a **Space Auditor** token really gets from `GET /api/v1/read/<app-guid>` on SAP BTP: 200 for an app in its space, 404 for an app elsewhere, 404 for an Org-Auditor-only user.
2. Which envelope types SAP BTP stores under an app GUID — container metrics, and router `TIMER` envelopes named `http`. The latter would be a usage signal *without* a log payload, but their tags carry `uri`, `remote_address` and `user_agent`: better for the signal, worse for privacy.
3. The real window: the oldest stored envelope for a quiet single-instance app, a multi-instance app and a busy app, that is SAP's effective `max_per_source` and memory limit, and whether the 12-hour minimum (D5) is regularly reached.
4. Whether the auth proxy's Cloud Controller lookups really consume the scanning user's CF API budget on SAP BTP, and what the effective per-user limit is, given that `general_limit` is per process.
5. Whether a websocket's `RTR` envelope is emitted at the upgrade or only when the connection closes, which changes what `lastRequestAt` means for long-lived connections.
6. Whether SAP's 3.2.17 is unmodified upstream (so the `Store.Meta()` race is present), and when SAP moves to 3.2.18 or later.
7. The exact bytes of one real SAP BTP `RTR` envelope, for an anonymized fixture: timestamp precision, the tag set, and whether `deprecated_tags` and `instance_id` are populated.

---

## 10. Deployed apps (`baip-lens project --cf`)

`baip-lens project --cf` runs the project collector and rules of §8 on a **deployed app**, reading its files live from a running instance over the platform's SSH proxy, the way `cf ssh` reaches a container, but opening only the SFTP subsystem and sending only read requests. The droplet is never downloaded and nothing is written to disk except the reports. Verified 2026-11-15 against `cloudfoundry/cli` at `5b69b945` (2026-11-12), `cloudfoundry/cloud_controller_ng` at `37a35fa` and `cloudfoundry/diego-ssh` at `c056e57`.

### 10.1 Flow ✅

1. **Login and target.** The API endpoint, token and targeted org and space come from the cf CLI config (`Target`, `AccessToken`, `RefreshToken`, `OrganizationFields.Name`, `SpaceFields.Name`, from `util/configv3/json_config.go`); `--api`, `--org` and `--space` override them, and `BAIP_LENS_ACCESS_TOKEN` works as for `scan`. The target org and space are used only when the config targets the same API.
2. **Discovery.** `GET /` gives `links.uaa` and `links.app_ssh` (`{"href": "ssh.example.org:2222", "meta": {"host_key_fingerprint": "…", "oauth_client": "ssh-proxy"}}`, `docs/v3/source/includes/api_resources/_root.erb`). An `href` that is not a plain `host:port`, or a missing fingerprint, stops the command: nothing unverifiable is dialled.
3. **Role check.** The user id is read from the token's `user_id` claim (locally, never sent anywhere); `GET /v3/roles?types=space_developer&space_guids=…&user_guids=…` must return a role, or the command stops before any SSH attempt. A token with `cloud_controller.admin` skips the check; if the list cannot be read, the command goes on and the SSH login decides.
4. **Picking the app.** `GET /v3/apps?space_guids=…`; for every started buildpack app `GET /v3/apps/:guid/ssh_enabled`. Stopped apps, Docker apps and apps with SSH off are listed as "not readable right now", with the cf command that would change that (`cf start`, `cf enable-ssh` then `cf restart`, `cf allow-space-ssh` for a Space Manager); BAIP Lens never runs them. `--app <name>` skips the question.
5. **Instance.** `GET /v3/apps/:guid/processes/web`, then `GET /v3/processes/:guid/stats`: the lowest index in state `RUNNING`.
6. **One-time code.** `GET {links.uaa}/oauth/authorize?response_type=code&client_id=<oauth_client>` with `Authorization: bearer <token>`; UAA answers with a redirect whose `code` query parameter is the passcode (`api/uaa/ssh.go` `GetSSHPasscode`; the cf CLI's UAA connection does not follow redirects, `api/uaa/uaa_connection.go`). The redirect is not followed here either. The code is used once as the SSH password and is never printed or stored. A client-credentials token gets no code, and the command says that a personal `cf login` is needed.
7. **SSH.** Connect to `links.app_ssh` as `cf:<process guid>/<index>` (the user format the Diego SSH proxy accepts: `authenticators/cf_authenticator.go` `CFUserRegex`) with password authentication only (ssh2 would otherwise try `none` first). The host key is checked before authentication as the cf CLI checks it (`util/clissh/ssh.go` `fingerprintCallback`): the format is told by the length of the published fingerprint (64: SHA-256 hex, 43: SHA-256 unpadded base64, 59: SHA-1 hex with colons, 47: MD5 hex with colons) and compared with the same digest of the received key. Unlike the cf CLI, an empty or unknown fingerprint is refused.
8. **SFTP.** The only channel opened is the `sftp` subsystem, which the Diego SSH daemon serves with `github.com/pkg/sftp` (`handlers/session_channel_handler.go`). The client sends only `OPENDIR`, `READDIR`, `CLOSE`, `LSTAT`, `OPEN` (flag `r` only), `FSTAT` and `READ` (`packages/cli/src/remote/sftp.ts`, typed against that subset of the ssh2 client; a test with a real SSH server on 127.0.0.1 records every request and fails on anything else).
9. **Walk and read.** `/home/vcap/app` is walked and read through the same collector as a local folder (§8.2–§8.5): the same allow-list and deny-list, skipped directories, depth and entry limits, 2 MiB per file, 2 000 files, 64 MiB in total, NUL check, parsers and reason codes. The root must hold `package.json`, `mta.yaml`, `mta.yml`, `.cdsrc.json` or `.cdsrc.yaml`. Contents stay in memory until the parsers have reduced them to names and counts; at most eight files are fetched ahead while the walk goes on, within the same budgets. The session is closed at the end.

### 10.2 Differences from a local folder

- ⚠️ **No `O_NOFOLLOW` in SFTP.** `OPEN` follows links on the server. The walk lists only entries whose `lstat` type (READDIR attributes, which pkg/sftp takes from `os.File.Readdir`, lstat semantics) is a regular file, and a file is read only when, once opened, `FSTAT` reports the size and modification time the listing showed; otherwise it is recorded as unreadable. A process inside the container that swaps a file for a link in that window, with the same size and time, could still make BAIP Lens parse another file of the same container; the parsers keep only names and counts.
- **No repository.** `cf push` never uploads `.git` or `.gitignore` (`DefaultIgnoreLines` in cloudfoundry/cli `actor/sharedaction/resource.go`), so `repository` is `false`, `gitIgnore.present` is usually `false`, and `DEPLOY_ARTIFACT_IN_REPO` can only report an archive pushed with the app.
- **A lost session stops the scan.** Every request has a 60 s timeout and nothing is sent after the session closes; a dropped connection ends the command with exit code 2 and writes nothing, instead of reporting a half-read app.
- **Audit trail.** Cloud Foundry records `audit.app.ssh-authorized` (or `audit.app.ssh-unauthorized`) with the user and the instance index for every session (`app/repositories/app_event_repository.rb`, `event_types.rb`). The command says so before it starts.

### 10.3 What a deployed app contains

What the rules can see is what was pushed. A CAP service built with `cds build` usually ships the compiled model (`srv/csn.json`, not read) instead of the `.cds` sources, and an MTA deployment does not put `mta.yaml` or `xs-security.json` into the app, so the CDS-model and security-descriptor rules (`CAP_SERVICE_NO_RESTRICTION`, `CAP_PERSONAL_DATA_UNANNOTATED`, `CAP_ROLE_NOT_IN_XSUAA`, `XSUAA_SCOPE_UNUSED`, …) find less than on the repository. The configuration in `package.json` and `.cdsrc.*` (`CAP_MOCKED_AUTH_IN_PROD`, `CAP_MOCKED_USER_PASSWORD`, `CAP_AUDITLOG_*`), the approuter's `xs-app.json` (`APPROUTER_*`), seed data shipped with a deployer app and HTML pages served by an approuter are read as in a local folder. Java apps and Docker images have none of the marker files and are refused with a message.

### 10.4 Network

SSH does not go through an HTTPS proxy, and company networks often block outbound port 2222. When `links.app_ssh` cannot be reached the command says so and suggests another network or `--path`. The SSH library (`ssh2`, MIT) is loaded only by `project --cf`; every other command runs without it.

### 10.5 Tried on SAP BTP (2026-11-22)

A first run against an SAP BTP Cloud Foundry landscape, with a Space Developer user and the cf CLI session from `cf login`, confirmed:

- `GET /` advertises `links.app_ssh` as `host:port` with a host key fingerprint in one of the cf CLI formats: the host key check passed and the session opened.
- UAA answers `GET /oauth/authorize?response_type=code&client_id=<oauth_client>`, sent with the access token and `Accept: application/json`, with a redirect that carries the code, and the SSH proxy accepts that code as the password of `cf:<process guid>/<index>`.
- The SSH proxy serves the SFTP subsystem, and `OPENDIR`, `READDIR`, `LSTAT`, `OPEN` (read), `FSTAT` and `READ` behave as `pkg/sftp` implements them.
- For an app with SSH turned off, `GET /v3/apps/:guid/ssh_enabled` gave the app-level reason, and the command stopped before connecting, with the `cf enable-ssh` advice. The role check (`GET /v3/roles`) did not stop the Space Developer.
- A CAP service deployed from a `cds build` output held only `package.json` among the allow-listed files (no `.cds` sources, `.cdsrc.*` or `xs-app.json`), as §10.3 expects. The one finding it produced was confirmed as correct by the app's maintainer.
- ⚠️ Not yet seen on SAP BTP: a refused login (missing role), an unreachable port 2222, a session that drops mid-scan, and which of the four fingerprint formats the platform publishes.

---

## 11. Deployed MTA projects (`project --cf` picker) — design, not implemented yet

The picker of `project --cf` will group the apps of a space by the multi-target application (MTA) they were deployed from, so that one choice reads every module of a project (approuter, service, deployer) into one report. Verified 2026-11-22 against `cloudfoundry/multiapps-controller` at `a4501d6` (2026-11-16), the deploy service behind `cf deploy`, and `cloudfoundry/cloud_controller_ng` at `c6d269b`.

### 11.1 What the deploy service writes on each app ✅

`MtaMetadataBuilder` and `ApplicationMetadataBuilder` (`multiapps-controller-core/…/cf/v2/`) set, on every app of an MTA:

| Kind | Key | Value |
| --- | --- | --- |
| label | `mta_id` | the MD5 hex digest of the MTA ID (`MtaMetadataUtil.getHashedLabel`) |
| label | `mta_namespace` | the MD5 of the namespace, only when deployed with one |
| annotation | `mta_id` | the MTA ID in clear |
| annotation | `mta_version` | the MTA version |
| annotation | `mta_namespace` | the namespace in clear, only when set |
| annotation | `mta_module` | JSON `{"name": "<module name>"}` (`MtaMetadataParser.parseDeployedMtaApplication` reads `name`) |

`mta_module_provided_dependencies` and `mta_bound_services` are written too and are **not** read. The app resource of the CF v3 API carries them as `metadata.labels` and `metadata.annotations` (`docs/v3/source/includes/resources/apps/_object.md.erb`), so the `GET /v3/apps?space_guids=…` the picker already makes (any role) is enough: no new endpoint, no new role.

### 11.2 How BAIP Lens will use it

- Only these keys are read; every other label and annotation is dropped at parse time, because annotations can hold personal data (the acme fixture plants a contact e-mail there).
- An app belongs to a project when its annotation `mta_id` matches `^[A-Za-z0-9_.-]{1,128}$` and its label `mta_id` is the MD5 of that annotation, as the deploy service writes them; an app whose two values disagree is listed on its own. Two deployments of one MTA in different namespaces are two projects. The module name must match the same pattern; the version is kept when it is at most 64 characters of `[0-9A-Za-z.+-]`.
- The picker lists projects first (`<mta id> <version> · N apps: <app> (<module>), …`), then the apps not deployed as an MTA. A project can be chosen when at least one of its apps can be read; the others are named with the reason, as today.
- Reading a project opens one SSH session per app, one after the other (so one `audit.app.ssh-authorized` event per app), and writes one snapshot and one report with one project per app. An app that cannot be read (stopped, SSH off, no project files, refused) is recorded as a skipped check with its reason and the other apps are still read; only when none can be read does the command stop with exit code 2.
- `--mta <id>` chooses a project without the picker, as `--app` chooses one app.
- Kept in the snapshot per project: the app name, and the MTA ID, version and module name when present (identifiers only).

---

## 12. npm dependencies: known vulnerabilities and deprecations — design, not implemented yet

`project --path` and `project --cf` will check every npm package of the project, direct and transitive, for known vulnerabilities (OSV.dev, `DEP_KNOWN_CVE`) and for deprecation (npm registry, new rule `DEP_DEPRECATED`). Verified 2026-11-22 against `npm/cli` at `787f152` (`docs/lib/content/configuring-npm/package-lock-json.md`), `cloudfoundry/nodejs-buildpack` at `523ff82`, `google/osv.dev` at `5da6b90`, `ossf/osv-schema` at `091feab` and `npm/registry` at `ae49abf`.

### 12.1 Where the versions come from ✅

- **Lockfile formats.** `lockfileVersion` 1 (npm 5–6: a nested `dependencies` tree), 2 (npm 7–8: `packages` plus the legacy `dependencies`) and 3 (npm 9+: `packages` only). `packages` maps an install location (`""` for the root, `node_modules/a`, `node_modules/a/node_modules/b`) to `version`, `resolved`, `integrity`, `link`, `dev`, `optional`, `devOptional`, `inBundle` and more. `npm-shrinkwrap.json` has the same format and wins over `package-lock.json`.
- **`--path`:** the root `npm-shrinkwrap.json`, else the root `package-lock.json`. yarn and pnpm lockfiles are not read and are reported as "not supported".
- **`--cf`:** `node_modules/.package-lock.json`, the hidden lockfile (always `lockfileVersion` 3) that npm 7+ writes after an install. The Node.js buildpack runs `npm install --unsafe-perm --userconfig <app>/.npmrc` (or `npm rebuild` then `npm install` for a pushed `node_modules`, `src/nodejs/npm/npm.go`) with `NODE_ENV=production` and `NPM_CONFIG_PRODUCTION=true` (`src/nodejs/supply/supply.go`), so the hidden lockfile lists the production tree actually installed. Without it, the root `npm-shrinkwrap.json` or `package-lock.json` is read and its `dev` entries are left out. The walk still never enters `node_modules`: only this one file is opened there, and `.npmrc` (which can hold registry tokens) is never opened.
- ⚠️ npm uses the hidden lockfile only when it was written by the last change to the tree; a later manual change inside `node_modules` is not detected by BAIP Lens.
- **Limits:** a lockfile of at most 32 MiB (the 2 MiB limit of other project files would refuse real ones), its shape checked before parsing (nesting, number of keys) with the bounded parser that snapshots already use (`io/jsonShape.ts`), and at most 20 000 packages.
- **Kept per package:** name (`PACKAGE_NAME_PATTERN`), version (semver, at most 64 characters), whether it is a direct dependency of the root, `prod`, `dev` or `optional`, and the source as a class: `npm` (resolved from `https://registry.npmjs.org/`), `other-registry`, `git`, `file`, `link` or `unknown`. The `resolved` URL itself is never kept (it can name an internal host or carry a token), nor `integrity`.

### 12.2 What leaves the machine (D10) ✅ decided

Only packages of source class `npm` are sent to OSV.dev and the npm registry; every other package is counted as "not checked" with its source class, so the report says how much was not looked at. ⚠️ A package published as private on npmjs.com also resolves from `registry.npmjs.org`, so its name would reach OSV.dev; a later `--dependency-exclude <@scope>` can keep a scope at home. `--no-dependency-check` will turn the network part off.

### 12.3 OSV.dev ✅

- `POST https://api.osv.dev/v1/querybatch` with `{"queries": [{"package": {"ecosystem": "npm", "name": …}, "version": …}, …]}`; results come back in the order of the queries with each vulnerability's `id` and `modified` only (`docs/api/post-v1-querybatch.md`).
- At most 1 000 queries per request: the server answers "too many queries" beyond `maxBatchQueries` (`go/internal/api/query_affected.go`), with a 35 s timeout per batch.
- A query whose result carries `next_page_token` is asked again with `page_token`; that happens above 1 000 vulnerabilities for one query or 3 000 for the batch.
- No rate limit, and a 32 MiB response limit over HTTP/1.1 (`docs/api/index.md`).
- `GET https://api.osv.dev/v1/vulns/{id}` once per distinct id, for `summary`, `aliases` (CVE ids), `severity[]` (`CVSS_V3` or `CVSS_V4` vectors, `docs/schema.md`), `database_specific.severity` (GitHub advisories for npm: `LOW`, `MODERATE`, `HIGH`, `CRITICAL`), `affected[].ranges[].events` (`introduced` / `fixed`, for the fixed version) and `withdrawn` (a withdrawn advisory is ignored). OSV.dev also lists malicious npm packages (`MAL-` ids).
- The allow-list rule for `api.osv.dev` already exists (§6) and does not change. Nothing but public package names and versions is sent; no credential.

### 12.4 npm registry ✅

- `GET https://registry.npmjs.org/{package}/{version}` returns that version's document (`docs/REGISTRY-API.md`); it holds `deprecated`, the deprecation message, when the version is deprecated (the abbreviated version object lists it, and the full one contains every abbreviated field, `docs/responses/package-metadata.md`). Only `deprecated` is read; the rest (author and maintainer e-mails, readme) is dropped at parse time and never stored.
- For a deprecated version, `GET /{package}/latest` tells whether a newer version is not deprecated (upgrade) or the whole package is (replace it).
- Scoped names are sent as `@scope%2fname`. No `Authorization` header, no redirects, at most 4 MiB per response (a readme can be large), concurrency 5 as for every request.

### 12.5 Rules and offline reports

- **`DEP_KNOWN_CVE`** (as already described in [rules.md](rules.md#dep_known_cve)): one finding per package and version, with all its advisory ids and aliases and the fixed version when known. Severity from the CVSS v3 base score computed from the vector (critical ≥ 9.0, high ≥ 7.0, medium ≥ 4.0, else low); without a v3 vector, from the advisory's own `database_specific.severity`; `medium` when there is neither; `critical` for a malicious package.
- **`DEP_DEPRECATED`** (new): the installed version is deprecated on the npm registry. `medium` when the latest version is deprecated too (the package is abandoned; replace it), `low` when a newer version is not (upgrade). The deprecation message is kept, at most 200 characters.
- Evidence of both: name, version, direct or transitive, `prod` / `dev` / `optional`. Findings name the package, never a path inside `node_modules`.
- The answers of OSV.dev and of the registry are stored in the snapshot, so `report --from` re-runs both rules offline, as for every other source. Advisory summaries and deprecation messages are external text: sanitized, length-capped, and shown as text only.
- Checks: `collect.dependencies` (the lockfile; no role for `--path`, Space Developer for `--cf` as the rest of that scan), `collect.osv` and `collect.npm-deprecations` (skipped with `--no-dependency-check` or when the host cannot be reached; a skipped check means "not checked", never "no findings").

### 12.6 Not covered

- yarn and pnpm lockfiles, Java (`pom.xml`) and other ecosystems.
- A project without a lockfile: `package.json` holds ranges, not versions, so nothing is checked and the check says why.
- A company mirror of the public registry (Artifactory, Nexus): its packages resolve from the mirror's host, so nothing is sent and they count as not checked. Allowing named mirror hosts is a possible later option.
