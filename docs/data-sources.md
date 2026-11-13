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
- ✅ Region list for the wizard (`packages/cli/src/guided/regions.ts`), verified 2026-10-10 against the source of the SAP help page (`github.com/SAP-docs/btp-cloud-platform`, docs/10-concepts/regions-and-api-endpoints-available-for-the-cloud-foundry-environment-f344a57.md). It includes the extension landscapes (`eu10-002` to `eu10-005`, `us10-001`, `us10-002`, `eu20-001`, `eu20-002`) and the China regions on `platform.sapcloud.cn`. Wherever an API endpoint is accepted (wizard, `--api`), a region id (`eu10-004`), a technical key (`cf-eu10-004`) or the region domain (`us10-001.hana.ondemand.com`) is turned into `https://api.cf.<region>.<domain>`. The list stays a convenience: the wizard verifies the endpoint with `GET /` and a pasted cockpit URL wins.
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

⚠️ The SAP BTP retention value is not published. **Assume 31 days.** Consequence: "no usage events in 180 days" cannot be proven from events (see `APP_IDLE` in §4).

---

## 2. CF v3 endpoints used by collectors

All endpoints are **GET**. "SA" = Space Auditor; "SD" = Space Developer.

**Status in 0.1.0:** the bootstrap calls, `apps.ts` and `droplets.ts` are implemented and are the only CF calls the scan makes. The other rows are verified endpoints for the collectors of the next releases; nothing calls them yet.

| Collector | Endpoint | Key fields used | Min. role | SA? | Notes |
|---|---|---|---|---|---|
| (bootstrap) | `GET /` | `links.uaa`, `links.login`, `links.log_cache` | none | ✅ | Unauthenticated. |
| (bootstrap) | `GET /v3/organizations?names=<org>` | `guid`, `name` | any role | ✅ | 0 results means "org not found or not visible", exit code 2. |
| (bootstrap) | `GET /v3/spaces?organization_guids=<g>[&names=<space>]` | `guid`, `name`, `relationships.organization` | any role | ✅ | Filtered to visible spaces. |
| `apps.ts` | `GET /v3/apps?organization_guids=<org>&per_page=5000` (`space_guids=<space>` with `--space`) | `guid`, `name`, `state` (`STARTED`/`STOPPED`), `created_at`, `updated_at`, `lifecycle.type` (`buildpack`/`cnb`/`docker`), `lifecycle.data.buildpacks[]`, `lifecycle.data.stack`, `relationships.space`, `relationships.current_droplet` | any role | ✅ | `lifecycle.data.buildpacks` may be `[]` and `stack` may be `null` for old records. |
| `droplets.ts` | `GET /v3/droplets?organization_guids=<org>&current=true&per_page=5000` (`space_guids=<space>` with `--space`) | `guid`, `state`, `created_at`, `updated_at`, `lifecycle.type`, `buildpacks[].{name,buildpack_name,version,detect_output}` (top-level on droplets, unlike apps), `stack`, `image`, `relationships.app` | any role | ✅ | One call instead of N× `/v3/apps/:guid/droplets/current`. `GET /v3/droplets/:guid` notes "some fields are redacted" for SA. ⚠️ The exact redacted fields are not documented; we do not rely on `execution_metadata` or `process_types`. Docker droplets have `image` and no buildpacks. |
| `processes.ts` | `GET /v3/processes?space_guids=…&per_page=5000` | `type`, `instances`, `memory_in_mb`, `disk_in_mb`, `health_check.type`, `updated_at`, `relationships.app` | any role | ✅ | |
| `processes.ts` | `GET /v3/processes/:guid/stats` | `state` (`RUNNING`/`CRASHED`/`STARTING`/`STOPPING`/`DOWN`), `uptime`, `usage.{cpu,mem,disk}`, `mem_quota` | SA (redacted) | ✅ | "Some fields are redacted" for SA. ⚠️ Treat `host`, `instance_internal_ip` and `instance_ports` as possibly missing. **Never** written to reports (infrastructure detail). Only called for `STARTED` apps. |
| `buildpacks.ts` | `GET /v3/buildpacks?per_page=5000` | `name`, `stack`, `state`, `enabled`, `position`, `filename`, `lifecycle`, `updated_at` | any role | ✅ | ⚠️ **There is no `version` field.** The platform's current version must be parsed from `filename` (e.g. `nodejs_buildpack-cflinuxfs4-v1.8.40.zip`). If parsing fails, `BUILDPACK_OUTDATED` falls back to comparing the droplet's `created_at` with the buildpack's `updated_at`, at lower confidence. |
| `stacks.ts` | `GET /v3/stacks?per_page=5000` | `name`, `state` (`ACTIVE`/`RESTRICTED`/`DEPRECATED`/`DISABLED`), `state_reason`, `default`, `description` | any role | ✅ | Use `state` as the primary signal. ⚠️ The `state` field is newer, so older CC versions may omit it. Fall back to a built-in list (`cflinuxfs3` deprecated) and flag the result as "static list". |
| `routes.ts` | `GET /v3/routes?space_guids=…&per_page=5000` | `url`, `protocol` (`http`/`tcp`), `host`, `path`, `destinations[].app.guid` | any role | ✅ | Feeds the UI5 probe (§3.3). `/v3/apps/:guid/routes` (SA allowed) is the per-app fallback. |
| `serviceBindings.ts` | `GET /v3/service_credential_bindings?type=app&app_guids=…&per_page=5000` | `name`, `type`, `relationships.app`, `relationships.service_instance`, `last_operation.state` | SA | ✅ | Metadata only. `GET …/:guid/details` (the credentials) is **SD-only and never called**. |
| `usageEvents.ts` | `GET /v3/app_usage_events?created_ats[gt]=<now-31d>&order_by=-created_at&per_page=5000` | `created_at`, `state.{current,previous}`, `app.guid`, `space.guid`, `instance_count` | "All Roles" | ✅ / ⚠️ | ⚠️ Listed as "All Roles", but the doc does not say how results are filtered for space-scoped users. On BTP it may return 403 or an empty list for SA. Treat both as `skipped` and fall back to audit events. Ignore `app.name`/`task.name` beyond matching. |
| `auditEvents.ts` | `GET /v3/audit_events?space_guids=…&types=audit.app.start,audit.app.stop,audit.app.restage,audit.app.droplet.create,audit.app.build.staged,audit.app.process.crash,app.crash&created_ats[gt]=<now-31d>&per_page=5000` | `type`, `created_at`, `target.guid` | **Org Auditor** or SA | ✅ | 🔒 Contains `actor.guid`, `actor.name` and `actor.type` (user identity). The collector **drops `actor.*` and `data` at parse time**; the zod schema strips them before anything reaches the snapshot. |
| `secretsInEnv.ts` (`--deep`) | `GET /v3/apps/:guid/environment_variables` | keys of `var` only | **SD** or Space Supporter | ❌ | Returns **only user-provided env vars**, not `VCAP_SERVICES`. Service bindings are therefore excluded by construction, which is exactly what `ENV_SECRET_PLAINTEXT` needs. Values are discarded in the collector and only keys are kept. ⚠️ Calling it creates an `audit.app.environment_variables.show` audit event in the customer's landscape; this is documented in `privacy.md`. |
| (not used) | `GET /v3/apps/:guid/env` | — | SD | ❌ | **Deliberately not used**: it returns `VCAP_SERVICES` credentials. |

### 2.1 Role summary (input to `docs/permissions.md`)

| Check | Needs | Default |
|---|---|---|
| Inventory, droplets, processes, stats, buildpacks, stacks, routes, bindings metadata, audit events | Space Auditor (or Org Auditor for org-level audit events) | on |
| App usage events | ⚠️ unconfirmed on BTP | on, skips on 403 |
| `ENV_SECRET_PLAINTEXT` | Space Developer **or Space Supporter** | `--deep` only |
| `collect.project` and the project rules (§8) | **no CF role**: local files only, no network | on, for `baip-lens project` only |

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
Discovered via `GET /` → `links.log_cache`. The endpoints, roles and retention behind the `APP_IDLE` traffic check are recorded in [§9](#9-traffic-evidence-for-app_idle-routes-and-log-cache).

---

## 4. Consequences for the v0.1 rules

| Rule | Data | Constraint found | Decision |
|---|---|---|---|
| `RUNTIME_NODE_EOL` / `RUNTIME_JAVA_EOL` | droplet `buildpacks[]` + endoflife.date | Version format varies by buildpack | Parse per buildpack; otherwise `unknown`. Java → `sapmachine` if `sap_java_buildpack`, else `eclipse-temurin`. |
| `BUILDPACK_OUTDATED` | droplet `buildpacks[].version` vs `/v3/buildpacks` `filename` | No `version` field on buildpacks | Parse from `filename`; fall back to date comparison, flagged as lower confidence in evidence. |
| `STACK_DEPRECATED` | app `lifecycle.data.stack` or droplet `stack` + `/v3/stacks` `state` | `state` may be absent on old CCs | `state` ∈ {`DEPRECATED`,`RESTRICTED`,`DISABLED`} → finding; otherwise use the static list. |
| `APP_IDLE` | app `state`/`updated_at`, audit and usage events | **Events are kept ~31 days** | "Stopped > 90 days": `state=STOPPED` and `app.updated_at` older than 90 days (`updated_at` is an upper bound on the last change). "Running, no activity in 180 days": droplet `created_at` and process `updated_at` older than 180 days **and** no events in the retention window. Evidence states the window used. |
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

## 6. Allow-list (to become `packages/cli/src/net/allowlist.ts`)

| Host | Methods | Source |
|---|---|---|
| `--api` host | GET | user flag |
| `links.uaa` host | POST `/oauth/token` only | CF root |
| `links.log_cache` host | GET (v0.2) | CF root |
| mapped app route hosts in the scanned org | GET `/resources/sap-ui-version.json` only, no auth header, no redirects (planned; not called in 0.1.0) | CF routes |
| `api.osv.dev` | POST `/v1/querybatch`, GET `/v1/vulns/*` | fixed |
| `endoflife.date` | GET `/api/v1/products/*` | fixed |
| `ui5.sap.com` | GET `/versionoverview.json` | fixed |
| `registry.npmjs.org` | GET `/@sap%2F{cds,approuter,xssec,xsenv}` only | fixed (D1) |

Any other host, or any other method, throws `EgressDeniedError` before `fetch` runs. This is covered by a unit test.

---

## 7. Decisions (resolved 2026-09-29)

- **D1: npm registry allowed.** `registry.npmjs.org` is on the allow-list for GET `/<pkg>` only, restricted to `@sap/cds`, `@sap/approuter`, `@sap/xssec` and `@sap/xsenv`. It is used by `SAP_PKG_OUTDATED` for the current `dist-tags.latest`.
- **D2: both roles documented for `--deep`.** Space Developer or Space Supporter can read `/environment_variables`. `permissions.md` notes that Supporter is narrower but can still restart and scale apps.
- **D3: route probe on by default.** One unauthenticated GET per app, 5 s timeout, no redirects. `--no-probe-routes` turns it off.
- **D4: dedicated repository.** BAIP Lens lives at the root of [`sebastianomarchesini/BAIP-Lens`](https://github.com/sebastianomarchesini/BAIP-Lens) as an npm-workspaces monorepo (`packages/cli`, `packages/ui`).

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

## 9. Traffic evidence for `APP_IDLE`: routes and Log Cache

What `APP_IDLE` needs to tell "running and unused" from "running": which apps have a route, and when the router last logged a request for each of them. Nothing in this section is implemented yet; it is the verification that comes before the routes, processes and Log Cache collectors.

- **Verified on:** 2026-11-13
- **Sources read** (GitHub, at the commit named; `v3-apidocs.cloudfoundry.org`, `docs.cloudfoundry.org`, `help.sap.com` and `developers.sap.com` are not reachable from the build environment):
  - CF v3 API docs: `cloudfoundry/cloud_controller_ng` `docs/v3/source/includes/resources/{routes,domains,processes,apps}` at `5a849387`.
  - Log Cache: `cloudfoundry/log-cache-release` at `2d51b365` (2026-11-12): `src/README.md`, `src/internal/auth/{cf_auth_middleware,capi_client,uaa_client}.go`, `src/internal/routing/local_store_reader.go`, `src/internal/cache/store/store.go`, `src/internal/gateway/gateway.go`, `src/internal/syslog/server.go`, `src/cmd/log-cache/config.go`, `jobs/log-cache/spec`.
  - Envelope format: `cloudfoundry/loggregator-api` `v2/envelope.proto` at `0c5d39c`; `cloudfoundry/go-loggregator` `conversion/tov2.go` at `fef98d7`; `cloudfoundry/loggregator-agent-release` `src/pkg/egress/syslog/rfc5424.go` at `d0f2c39`.
  - Router: `cloudfoundry/routing-release` `src/code.cloudfoundry.org/gorouter/accesslog/{dropsonde_logsender.go,schema/access_log_record.go}` at `ecb3db30`.
  - Roles: `cloudfoundry/docs-cloudfoundry-concepts` `_oss_roles_table.html.md.erb` at `97e0d0b`.
  - SAP: `SAP-docs/btp-cloud-platform` `docs/10-concepts/sap-btp-specific-configurations-9809fa4.md` at `e8f7960`; `sap-tutorials/Tutorials` `tutorials/cp-cf-application-logs-overview` at `c4ef42b`.

| # | Question | Status |
| --- | --- | --- |
| 1 | `GET /v3/routes`: routes and destinations of every app in one paged call, minimum role | ✅ confirmed |
| 2 | Log Cache `GET /api/v1/read/<app-guid>`: parameters, response shape, router access log, base64 payload | ✅ confirmed (upstream source) |
| 3 | Log Cache `GET /api/v1/meta`: oldest timestamp per source, callable by a non-admin | ✅ confirmed (upstream source) |
| 4 | Roles Log Cache accepts for an app's logs | ✅ confirmed upstream · ⚠️ unconfirmed for SAP BTP |
| 5 | Retention | ✅ mechanism confirmed upstream · ⚠️ SAP BTP values unpublished, assumption stated |

"Upstream" means the open-source code. Whether SAP BTP runs it unchanged cannot be confirmed from public sources, so every upstream fact below is implemented defensively.

### 9.1 Routes and destinations ✅

- **One call for the whole scan:** `GET /v3/routes?organization_guids=<org>&per_page=5000&include=domain` (`space_guids=<space>` with `--space`). Every route object carries its `destinations[]` inline, so there is no call per app and no call per route. Filters confirmed: `app_guids`, `space_guids`, `organization_guids`, `domain_guids`, `hosts`, `paths`, `ports`; `per_page` 1 to 5000; `include` accepts `domain`, `space`, `space.organization`, `route_policies`.
- **Fields used:** `guid`, `protocol` (`http` or `tcp`), `relationships.domain.data.guid`, `destinations[].app.guid`, `destinations[].app.process.type`; from `included.domains[]`: `guid` and `internal` ("whether the domain is used for internal (container-to-container) traffic").
- **Fields not kept:** `host`, `path`, `url`, `port`, `options`, `metadata`. No rule in this task needs them; the UI5 route probe (§3.3) will add what it needs when it is built.
- **Minimum role:** the list is "All Roles", filtered to what the user can see, so **Space Auditor** is enough. The per-app fallback `GET /v3/apps/:guid/routes` names Space Auditor explicitly (with Admin, Admin Read-Only, Global Auditor, Org Manager, Space Developer, Space Manager, Space Supporter); it is not needed.
- **Processes** (needed for "has a `web` process with at least one instance"): `GET /v3/processes?organization_guids=<org>&types=web&per_page=5000` (`space_guids` with `--space`). "All Roles". Fields used: `guid`, `type`, `instances`, `created_at`, `updated_at`, `relationships.app.data.guid`. The `types`, `app_guids`, `space_guids` and `organization_guids` filters are confirmed. `command` is never read (it can contain secrets).

### 9.2 Log Cache: `GET /api/v1/read/<source-id>` ✅

The host is `links.log_cache.href` from `GET /` (§1.1). For an app, the source id is the app GUID.

| Parameter | Confirmed behaviour |
| --- | --- |
| `start_time` | UNIX time in **nanoseconds**, inclusive. Default 0 (start of the cache). |
| `end_time` | UNIX time in nanoseconds, **exclusive**. Default: the cache's current time. A `start_time` after `end_time` is an error. |
| `envelope_types` | `LOG`, `COUNTER`, `GAUGE`, `TIMER`, `EVENT`; may be repeated. BAIP Lens sends `LOG` only. |
| `descending` | `true` returns newest first. Default ascending. |
| `limit` | Default **100**, maximum **1000**; above 1000 the request fails. |
| `name_filter` | A regular expression on metric names. Not used. |

- **Response:** `{"envelopes":{"batch":[ … ]}}`. An app the cache holds nothing for answers `200` with an empty `batch`. The gateway marshals with proto field names and emits unset fields, so an envelope looks like `{"timestamp":"1524081739994226961","source_id":"<app-guid>","instance_id":"0","deprecated_tags":{},"tags":{"source_type":"RTR", …},"log":{"payload":"<base64>","type":"OUT"}}`.
  - `timestamp` is an int64 in nanoseconds, **serialised as a JSON string**.
  - `log.payload` is a protobuf `bytes` field, so it is **base64** in JSON.
- **Router access log:** a `LOG` envelope whose `tags.source_type` is `RTR`. The router sets `SourceType = "RTR"` and the app GUID on every access log it sends to Loggregator, and only for requests it matched to an app instance; the v1-to-v2 conversion writes it as the `source_type` tag, the syslog agent carries tags in the `tags@47450` structured data and the Log Cache syslog server restores them into `tags`. Defensive: `deprecated_tags.source_type.text` is accepted too, for platforms that convert without preferred tags.
- **There is no server-side filter on `source_type`.** The app's own stdout and stderr lines are `LOG` envelopes as well, so the collector has to read `LOG` envelopes newest first and look for the first `RTR` one. The store applies the type filter while it walks the source's tree, so a page of 1000 is the newest 1000 *log* envelopes, however many metrics lie between them.
- **Paging backwards:** repeat the call with `end_time` set to the oldest `timestamp` of the previous page (exclusive, so no envelope is read twice). A page shorter than `limit` means the cache holds no older log envelope for that app.
- **What the payload contains** (router `access_log_record.go`): request host, method, URI with path and query, status, referer, user agent, client address, `x_forwarded_for`, request id, backend address and timings. That is personal data. The collector's schema reads `timestamp` and `source_type` only and never decodes `payload`; the response body lives in memory until it is parsed and is never logged or stored.
- **Authentication:** `Authorization: bearer <token>` with the same UAA token as the CF API (a `bearer ` prefix is accepted and optional).

### 9.3 Log Cache: `GET /api/v1/meta` ✅

- **Response:** `{"meta":{"<source-id>":{"count":"100000","expired":"129452","oldestTimestamp":"1524071322998223702","newestTimestamp":"1524081739994226961"}, …}}`. Timestamps are nanoseconds as JSON strings. `count` is the number of envelopes held for the source, of every type; `expired` is how many were pruned and is absent when zero.
- **It does give the oldest timestamp held per source** (`oldestTimestamp`), which is the start of the observable window for that app.
- **A non-admin can call it.** The auth proxy answers any valid token; for a token without `doppler.firehose` or `logs.admin` it returns only the sources that are also in the user's own `GET /v3/apps` and `GET /v3/service_instances` lists, which the proxy fetches from the Cloud Controller with the user's token (`per_page=5000`, all pages).
- **Consequences:** one meta call per scan, never one per app (each call makes the proxy list all the user's apps and service instances, which counts against the user's CF API rate limit). There is no filter parameter over HTTP, so the response covers every visible source; only the scanned app GUIDs are kept. `502` means the proxy could not reach the cache nodes: the scan then falls back to the timestamps of the envelopes it examined.
- **Field names:** the auth proxy marshals this response itself with JSON names (`oldestTimestamp`); the gateway behind it would use proto names (`oldest_timestamp`). The schema accepts both and treats every field as optional.

### 9.4 Roles ✅ upstream · ⚠️ SAP BTP

- **Upstream, confirmed from the auth proxy source:** Log Cache has no role list of its own. For a non-admin token it calls `GET /v3/apps/<source-id>` on the Cloud Controller with that token and authorises the read when the answer is `200` (then `GET /v3/service_instances/<source-id>`), caching a positive answer for about a minute. Whoever can read the app can read its logs. The CF docs list for `GET /v3/apps/:guid`: Admin, Admin Read-Only, Global Auditor, Org Manager, **Space Auditor**, Space Developer, Space Manager, Space Supporter; the "View app logs" row of the CF roles table lists the same roles. Org Auditor is not among them.
- **SAP BTP, not confirmed:** the SAP tutorial on logs in the cockpit names Space Developer, Space Auditor and Space Supporter. 🟡 That page (`developers.sap.com`) is not reachable from the build environment and its source was not found in the public `sap-tutorials/Tutorials` repository, so this is known from a search snippet only, and it describes the cockpit, not the Log Cache API. It agrees with the upstream behaviour (Space Manager and Org Manager are simply not mentioned), but nothing public states that SAP BTP runs the upstream auth proxy unchanged.
- **Decision:** the check declares **Space Auditor** and relies on the denied path.
- ⚠️ **The denied path is `404`, not `403`.** Upstream Log Cache answers `404` for a missing or invalid token, for a source the user may not read and when its own call to the Cloud Controller fails, "to discourage malicious actors. Don't expect 401 or 403" (`src/README.md`, and every branch of `cf_auth_middleware.go`). The collector therefore treats `401`, `403` and `404` from `/api/v1/read` and `/api/v1/meta` the same way: not authorised. The apps it asks about were all just returned by `GET /v3/apps` for the same token, so a `404` cannot mean "no such app".

### 9.5 Retention ✅ mechanism · ⚠️ SAP BTP values

Confirmed upstream:

- **In memory only.** "All logs and metrics will always be lost upon crashes or re-deploys of log-cache." Each source lives on one node.
- **Capped per source:** `max_per_source`, default **100 000 envelopes**. The cap counts every envelope type of the source together: app logs, router access logs, container metrics and the router's per-request `http` timers. When a source is full, each new envelope evicts that source's oldest one.
- **Capped by memory:** every `truncation_interval` (default 1 s) the node checks whether it uses more than `memory_limit_percent` (default 50) of system memory and, if so, evicts the oldest envelopes across all sources.
- **No time-based expiry.** Nothing is dropped because of its age alone.
- Both evictions remove the oldest envelope first, so what the cache holds for one app is everything it received since that app's `oldestTimestamp`. "No router log since `oldestTimestamp`" is therefore a sound reading, within the two limits below.
- **Limits of the evidence:** the pipeline in front of the cache is lossy by design (the README names ingress drops between nodes; the platform also drops logs above its rate limit), and the window differs per app: minutes for a busy app, days at most for a quiet one (its own container metrics keep filling the cap), and close to zero after a node restart.

SAP BTP:

- ⚠️ **Not published.** SAP's "SAP BTP-Specific Configurations" page documents a log rate limit (4000 logs per second per app instance by default) and an audit event retention of 14 days, but no Log Cache value: not `max_per_source`, not the memory limit, not the number of nodes. SAP's own tutorial says the log cache is enabled by default on SAP BTP and "is not a solution for storing logs of production applications".
- **Assumption:** at best the upstream defaults, possibly less. BAIP Lens never assumes a window. It measures the window per app on every scan (from `meta`, else from the oldest envelope it examined), reports it in the evidence, and produces no finding when the window is shorter than `--min-traffic-window`.
- Side finding: the 14 days above are shorter than the 31 days §1.6 assumes for audit events on SAP BTP. No collector reads events yet; §1.6 has to be corrected when one does.

### 9.6 Consequences for the collector and the rule

1. **Not authorised is `401`, `403` or `404`** (§9.4). If the first app read or the meta call is refused, the check is recorded as skipped (`insufficient role: needs SpaceAuditor`) and no further read is sent. A refusal for a single app later in the scan (the proxy also answers `404` when its Cloud Controller lookup fails) leaves that app as "unknown".
2. **Log Cache not advertised or unreachable** (`links.log_cache` absent, network error, `5xx` after retries): the check is skipped with that reason; the "no route" results stand.
3. **Only external HTTP routes are observable.** The router logs requests that pass through it. A route on an internal domain (`included.domains[].internal = true`) never does, and ⚠️ it is not confirmed that the TCP router writes `RTR` logs for `tcp` routes. An app whose routes are all internal or `tcp` therefore gets "unknown", never a finding. "No route" means no route of any kind.
4. **`windowStart`:** when the collector reached the end of the app's log envelopes (a short page) without an `RTR` line, the window starts at `meta.oldestTimestamp`; without meta, at the oldest envelope examined. When it stopped at the page cap, the window starts at the oldest envelope examined, whatever meta says. No envelope and no meta entry means a window of zero: "unknown".
5. **Chatty apps shrink the window, they do not cause findings.** An app that writes many log lines of its own can push its last request beyond the page cap (5 pages × 1000 envelopes by default). The window then starts at the oldest line examined and is usually shorter than `--min-traffic-window`.
6. **A request is not a user.** Uptime monitors, crawlers and scanners produce `RTR` lines too, and telling them apart would need the payload, which is never read. "Request seen" means only that. 🟡 Container health checks are run by Diego against the container itself and do not pass through the router (CF architecture; not re-verified against source for this section).
7. **Cost:** one meta call per scan, and one to five reads per started app with an observable route. The auth proxy makes one `GET /v3/apps/:guid` per app on the user's behalf, so a scan of N such apps costs about N extra requests against the CF API rate limit (§1.4).
8. **No side effect:** these are `GET` requests; nothing in Log Cache or the auth proxy creates a CF audit event. The auth proxy can write a platform-side access log of the request path, which the customer does not see.
9. ⚠️ **Not used, noted for later:** the router also emits one `TIMER` envelope named `http` per request with the app as source, so `envelope_types=TIMER&descending=true&limit=1` would return the last request in a single small call, unaffected by the app's own log volume. The emission can be switched off in the router (`send_http_start_stop_server_event`), whether SAP BTP forwards these envelopes is unknown, and its tags carry the same personal data. It needs a check against a live SAP BTP org before it can replace or complement the `RTR` read.

### 9.7 Allow-list entry (replaces the v0.2 placeholder in §6 when the collector is built)

| Host | Methods | Source |
| --- | --- | --- |
| `links.log_cache` host | GET `/api/v1/read/<guid>` and GET `/api/v1/meta` only; `/api/v1/query` and `/api/v1/query_range` (PromQL) stay denied | CF root |

It is the only host besides the CF API that may receive the CF bearer token. The UAA token endpoint receives client credentials or a refresh token, never the access token.
