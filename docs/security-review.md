# Security review: BAIP Lens

Three parts. **Part 1** (2026-09-29) is the design and repository review written before any code existed. **Part 2** (2026-09-30) is the code review of slice 1 against Part 1's checklist, with what was fixed in the same change and what stays open. **Part 3** (2026-11-15) reviews `project --cf`, the first feature that leaves HTTP. Read Part 2 first if you want the state of the core, then Part 3.

---

# Part 3: `project --cf` (deployed apps over SSH), 2026-11-15

**Scope.** `packages/cli/src/remote/` (role check, one-time code, host key check, SSH session, read-only SFTP wrapper, SFTP project tree), the `ProjectTree` refactor of the project collector, the allow-list additions and the `ssh2` dependency. Design and verified sources: [data-sources.md §10](data-sources.md#10-deployed-apps-baip-lens-project---cf). Updated 2026-11-23 for the project picker, which reads every app of a deployed MTA project in one run (`remote/mta.ts`, `remote/selectApps.ts`, [§11](data-sources.md#11-deployed-mta-projects-project---cf-picker)): SEC-31 and SEC-32 revised, SEC-35 added.

| Id | Sev | Concern | Status |
|---|---|---|---|
| **SEC-28** | High | SSH can do far more than read (shell, commands, uploads, port forwarding). | 🔧 Only the `sftp` subsystem is requested; the SFTP wrapper is typed against the seven read requests (`SftpReadRequests`) and opens files with `'r'` only; a static test forbids every mutating ssh2 call in `src/remote/`; the end-to-end test runs a real SSH server that records every login, channel and SFTP request and fails on anything but a password login, the `sftp` channel and read requests |
| **SEC-29** | High | The one-time code is a credential and must only reach the genuine proxy. | 🔧 The host key is checked against `links.app_ssh.meta.host_key_fingerprint` before authentication (cf CLI formats); a missing or unknown fingerprint is refused, unlike the cf CLI; a test proves no login is attempted when the key differs. The code is used once, never retried, never printed (leak test) |
| **SEC-30** | Medium | SFTP `OPEN` follows links; a link in the app folder could make the scanner read container files such as `/proc/self/environ`. | 🔧 Only `lstat` regular files are listed; a file is read only if `FSTAT` after `OPEN` matches the listed size and time. ⚠️ Residual: a live process swapping a file in that window with the same size and time; the parsers keep names and counts only |
| **SEC-31** | Medium | A refused SSH login is recorded as `audit.app.ssh-unauthorized`, which security teams alert on. | 🔧 The user's Space Developer role is checked with `GET /v3/roles` before the code is requested; without it the command stops and connects to nothing (tested). Reading a project opens one session per app: when the role could not be told beforehand and the first login of the run is refused, the run stops there, so a missing role is one refused attempt and not one per app (tested). A login refused after another app's login was accepted is about that app: it is recorded as skipped and the next app is read. A CF API or UAA that cannot be reached stops the run instead of being asked again for every app (tested for UAA) |
| **SEC-32** | Medium | A dropped connection could leave a half-read app that looks clean. | 🔧 Every request times out after 60 s and nothing is sent after the session closes. In a run of one app a lost session ends the command with exit code 2 without writing a report (tested). In a project run the app is recorded as a skipped check (`collect.project.<project id>`, reason code `error`), nothing of it is kept, and the report names it as not read (tested) |
| **SEC-33** | Low | Supply chain: `ssh2` brings four packages and an install script that tries `node-gyp` for an optional native crypto add-on (it always exits 0 and falls back to pure JavaScript). | ⏳ Accepted for now: CI installs with `--ignore-scripts` and all tests pass without the add-on; `ssh2` is imported only by `project --cf`. Option for later: bundle `ssh2` into `dist` so that installing BAIP Lens runs no third-party install script |
| **SEC-34** | Info | The local project collector now reads through `ProjectTree`. | ✅ `LocalProjectTree` keeps `O_NOFOLLOW`, `lstat`-only walk, the same limits and the `.git` lookup; all existing collector tests pass unchanged, and the no-egress guard still covers `collectors/project`, `analyzers/project` and `project.ts` |
| **SEC-35** | Medium | The MTA labels and annotations that group apps into projects (added with the project picker) are user-controlled: a Space Developer can set them on any app with `PATCH /v3/apps/:guid`, and annotations are free text of up to 5 000 characters that often holds e-mail addresses. | 🔧 Only six keys are read and every other one is dropped at parse time; a value is used only when it matches a strict pattern (hex digests, identifiers of bounded length, a small JSON object for the module), so no free text reaches the terminal, the snapshot or a report, and a malformed value can never drop an app from the list (tested with `null`, wrong types, control characters, a 6 000-character value, `__proto__` and a planted e-mail). The MD5 link between label and annotation is what the deploy service writes; it is a display aid for grouping, not a trust boundary, and nothing is decided by it except which apps one choice reads. A namespace key whose value cannot be used makes the app an app on its own, never a part of the deployment without a namespace (tested). App and space names are user-controlled too and may hold any printable character: a cf command the terminal suggests quotes such a name so that a shell expands nothing in it (tested against a POSIX shell with `$(…)`, backticks, quotes and backslashes), and the reason of a skipped check, which is written to the snapshot and the reports, is a fixed sentence that repeats no name and no command (tested). ⚠️ Residual: a Space Developer can make an app of their space appear as part of another project of the same space, or hide it from one; every app read is still named in the report, and reading needs the same role either way ([data-sources.md §11](data-sources.md#11-deployed-mta-projects-project---cf-picker)) |

---

# Part 2: code review of slice 1, 2026-09-30

**Scope.** Everything under `packages/cli/src` and `packages/ui/src` as merged by PR #2 (GET-only CF client, egress allow-list, credentials, collectors for orgs, spaces, apps and droplets, `APP_NO_RECENT_DEPLOY`, JSON/CSV/SARIF/HTML reporters, the React + UI5 report), the CI workflows, `package.json` manifests and the repository settings. Method: read every file on the request, credential and output paths line by line against the §7 checklist below; run the test suite; grep the sources and the built bundle for TLS-disable, `eval` and raw-HTML patterns; verify the pinned GitHub Action SHAs against the upstream tags with `git ls-remote`; check the npm registry and the GitHub repository settings.

Verdicts: **✅ verified** (present in code and covered by a test), **🔧 fixed now** (was missing; implemented in this change with a test), **⏳ open** (not yet applicable or deferred, with the reason), **👤 owner** (only the repository owner can do it).

## 2.1 Checklist results

| Item | Verdict | Where |
|---|---|---|
| GET-only to the CF API; every other method and every unknown host refused before `fetch` (constraint 1) | ✅ | `net/allowlist.ts` `EgressPolicy.authorize`, `test/unit/allowlist.test.ts`, `cfClient.test.ts` |
| SEC-02 token bound to host: `Authorization` allowed only where the rule says so | ✅ | `credentials` per rule: `bearer` (the CF token) for the CF API and the log cache, `basic` for the UAA token endpoint, none elsewhere; the client throws before `fetch` on a credential the host may not receive and on any other kind of `Authorization` header (`test/unit/httpClient.test.ts`, `allowlist.test.ts`) |
| SEC-03 no redirects on any request | ✅ | `redirect: 'manual'` in `httpClient.ts`; a 3xx from CF is an error ("redirect not followed") |
| SEC-09 discovered links must be `https:` | ✅ | `authorize` denies any non-https URL, so a `http:` UAA link can never be called |
| SEC-13 `report --from` is offline | ✅ | `runReport` never constructs an `HttpClient`; `cli.test.ts` injects a fetch that rejects |
| SEC-01 TLS verification never disabled, `SSLDisabled` ignored | ✅ | grep of `packages/` for `rejectUnauthorized`, `NODE_TLS_REJECT_UNAUTHORIZED`, `SSLDisabled`: no hits; `CfCliConfigSchema` does not read the field |
| SEC-04 redaction on every log and error path | 🔧 | `io/redact.ts`: every `stdout`/`stderr` write in `main.ts` strips ANSI/OSC/C0/C1 sequences and redacts JWT shapes, `bearer …`, and `refresh_token`/`access_token`/`client_secret`/`password`/`passcode` fields. `redact.test.ts`, `cli.test.ts` |
| SEC-17 terminal escape injection through app, org and space names | 🔧 | same filter; test with an OSC title-setting sequence in an org name |
| SEC-06 no token, config path or operator name in outputs | ✅ | strict zod schemas for `raw`, `apps`, `findings`; `leak.test.ts` plants poison values and scans all six output files for them, e-mails, JWTs, bearer tokens and credential URLs |
| SEC-07 JWT `exp` read locally, nothing else trusted | ✅ | `jwtExpiryMs` reads `exp` only; malformed → refresh |
| SEC-05 no secret as a CLI flag; `_FILE` variant | ✅ / ⏳ | No flag exists. `BAIP_LENS_CLIENT_SECRET_FILE` is not implemented yet (v0.2, CI use case) |
| `/v3/apps/:guid/env` and binding `details` refused even for GET | 🔧 | `cfApiRule` gained a `deny` pattern (also `parameters`, `credentials`), tested raw and percent-decoded; `/environment_variables` stays allowed for `--deep` |
| SEC-08 route probe SSRF guards | ⏳ | The probe is not implemented yet (`--no-probe-routes` exists but no collector reads routes). The §2.2 requirements apply unchanged when it lands; the flag should be documented as "reserved" until then |
| SEC-10 OSV disclosure, `--no-osv`, `--osv-exclude` | ✅ | Built with the lookup of `baip-lens project` (2026-11-25), under other names than proposed below: `--no-dependency-check` and `--dependency-exclude <list>`. The design goes further than the recommendation: only a package that a lockfile resolved from `https://registry.npmjs.org/` is kept by name at all, so a package of a company registry, of git or of a local folder cannot be sent whatever the flags say (decision D10, [data-sources.md §12.1 and §12.2](data-sources.md#122-what-leaves-the-machine-d10-)). One line before the first request says how many package names go to `api.osv.dev` and names both flags (`dependencyCheck.ts`). The lookup has an HTTP client of its own whose allow-list does not hold the CF API, so no credential can go along, and redirects are not followed. `docs/privacy.md` says what is sent in plain words. End-to-end tests look at every request: host, method, headers and body, with a private package name, a registry token and the CF login planted (`e2e/project-dependencies.test.ts`, `e2e/project-cf.test.ts`). ⚠️ Residual: a private package published on npmjs.com resolves from the public registry and is sent unless a pattern holds it back; `--quiet` silences the line, not the lookup. Nothing is sent to the npm registry: that lookup is not built |
| SEC-11 fixed `User-Agent` | ✅ | `baip-lens/<version>`, no OS or Node details |
| SEC-12 caps on `Retry-After` and body size | ✅ | 120 s cap; 64 MB default body cap, streamed and cut off; `httpClient.test.ts` |
| SEC-15 HTML injection | ✅ / 🔧 | JSON embedded with `\u003c`/`\u003e`/`\u0026`/U+2028/U+2029 escaping (`reporters/html.ts`); no `dangerouslySetInnerHTML` anywhere; evidence rendered as text. **Fixed now:** a Content Security Policy in the built report (`default-src 'none'; script-src 'sha256-…'; connect-src 'none'; base-uri 'none'`) and an http(s)-only guard on reference links. `e2e/offline-report.spec.ts` asserts the policy and that an injected inline script does not run |
| SEC-16 CSV formula injection | ✅ | `csvCell` prefixes `= + - @ TAB CR` with `'`; `reporters.test.ts` |
| SEC-18 no file names from CF names | ✅ | `snapshot-<timestamp>.json` and fixed report names |
| SEC-19 SBOM parsing | ⏳ | `sbom` command not implemented yet |
| SEC-20 SARIF without local paths | ✅ | pseudo-URIs `cf/<org>/<space>/<app>`, percent-encoded |
| SEC-21 snapshot input validated and size-capped | ✅ / 🔧 | zod parse with a schema version check. Unknown keys are **dropped, not rejected** (a deviation from the recommendation below): an older or newer snapshot stays readable, and nothing unknown reaches a report or the next snapshot (`leak.test.ts` plants unknown fields in a `--previous` file). A file that is not JSON is reported with its line and column only, never with an excerpt, and a schema version that is not a number is not quoted either (`snapshot.ts`, `files.test.ts`). **Bounded parsing (2026-11-18):** a few megabytes of `{}` in a list used to cost 1.1 to 2.1 GB and end in an out-of-memory abort, because zod builds one issue per invalid element and nested lists multiply; 42 MB of distinct keys in one finding's evidence loaded after 8 s and 1.1 GB. Four limits now apply, each refusing with exit code 2. (1) **128 MB** cap, lower than the 256 MB recommended below, also counted while reading, so it holds for a pipe such as `--previous <(...)`; a pipe that hands over a few kilobytes at a time no longer keeps a megabyte buffer per read. (2) Before `JSON.parse`, one pass over the bytes (`io/jsonShape.ts`) refuses nesting deeper than **64** levels (a snapshot nests 11), more than **4,194,304** keys and values together, and an object with more than **1,000** keys (a snapshot's objects hold 19 at most). Keys count because the parser builds each one, and a distinct key costs more than an empty object; this keeps the parser's memory bounded and the reporters' `JSON.stringify` from overflowing the stack. (3) Every list has a limit (`model/list.ts`, above what a real snapshot holds within 1 and 2), and zod 4.6.7 refuses a longer list before reading its elements. (4) A list stops at its first invalid element (`list()`), so a snapshot yields at most one element's issues per list. `snapshotSchemaShape.test.ts` walks `SnapshotSchema` and fails on any other collection that checks its members one by one (a plain array, set, map, tuple, record with checked values, or an object that keeps unknown keys); ESLint also refuses `z.array` in `src/model`. A scan writes about 157 keys and values per app (3,190 bytes pretty-printed), so about 26,000 apps load, however the file is formatted (`snapshotCapacity.test.ts`). In `craftedSnapshot.test.ts` every crafted file is refused, or loaded when it is valid, within 1.5 s on a laptop; across the whole run the process's peak memory grows by about 530 MB, the costliest read alone about 400 MB. **Write guard (2026-11-25):** `baip-lens project` checks the text of its snapshot against limits 1 and 2 before it writes anything; a result that does not pass ends the command with exit code 2, a message that names the limit and what to do, and no file (`loadableSnapshotText` in `snapshot.ts`, `snapshotWriteGuard.test.ts`). The answers of the lookup on OSV.dev are bounded before that (16 MiB for both tables), and a project scan at the limits of its lockfiles and of that lookup, with a finding for each of 20,000 packages, loads again (`snapshotCapacity.test.ts`). **Residual:** `scan` does not check its own snapshot against these limits, so an org of more than about 26,000 apps would write one that `report --from` refuses. A crafted but *valid* project record can still keep `report --from` busy, because some project rules compare names in nested loops: `effectiveEntities` and `annotatedEntities` in `analyzers/project/cdsModel.ts` take time in the cube of the number of annotates, service entities and database entities, and `effectiveServices` in services × members × annotates. Measured: 3 s for a 123 KB file and 24 s for a 216 KB one, so hours for a file of a megabyte or two, with memory still bounded. Not fixed here: those rules need their names indexed |
| SEC-22 private output modes and warning | 🔧 | `io/files.ts`: directories `0700`, files `0600` (`files.test.ts`); guided mode prints the sharing warning. `scan` and `report` print the sharing warning (added 2026-10-03) |
| SEC-23 `report --redact` | ⏳ | not implemented; needed before testers share screenshots (campaign Phase 0) |
| Fixture linter (no e-mails, tokens, real hosts, IPs) | ⏳ | Fixtures use `example.org` and synthetic GUIDs, and `leak.test.ts` covers outputs, but there is no test that lints the fixture files themselves |
| SC-01 provenance publishing from CI | 👤 / ⏳ | no release workflow yet |
| SC-02 actions pinned by SHA | ✅ / 🔧 | `security.yml` already pinned; all seven SHAs re-verified against upstream tags today. **Fixed now:** `ci.yml` was on floating `@v7` tags and is pinned; the new `pages.yml` is pinned |
| SC-03 `npm ci --ignore-scripts`, tiny runtime dependency list | 🔧 / ✅ | CI and Pages install with `--ignore-scripts` (build and tests verified to pass that way). Runtime dependencies: `commander`, `zod` only |
| SC-04 `files` whitelist | ✅ | `packages/cli/package.json` ships `dist`, `README.md`, `LICENSE`, `NOTICE`. CI and the release workflow run `npm pack --dry-run` and fail on any other file or a missing one (2026-11-18) |
| SC-05 bundled licences | ✅ | `THIRD_PARTY_LICENSES.md` generated and embedded in the report as a leading comment |

## 2.2 Findings not in Part 1

| Id | Sev | Finding | Status |
|---|---|---|---|
| **SEC-24** | Medium | Guided mode introduces two new credential inputs (one-time passcode, password). Risk: echo to the terminal, reuse, or persistence. | 🔧 Input is hidden (`TerminalPrompter` mutes the echo), the grant is sent once and the field cleared from memory (`UaaSessionTokenProvider`), the session lives in memory only, and tests assert the code never appears in the transcript or the snapshot. The grant matches `cf login --sso` exactly (data-sources §1.1) |
| **SEC-25** | Low | Opening the report and the passcode page uses an OS opener. Risk: shell injection through the path. | 🔧 `spawn` with an argument array, never a shell string; both paths are built by BAIP Lens, not from CF data |
| **SEC-26** | Low | `--no-probe-routes` and the `probeRoutes` snapshot option exist but nothing probes yet; a reader could believe the guard is active. | ⏳ Document as reserved until the collector lands |
| **SEC-27** | Info | `HttpNetworkError` embeds the undici cause message. Today these are safe (`fetch failed`, `ENOTFOUND`); the redaction filter now covers the case where a future cause carries a URL with credentials. | ✅ covered by SEC-04 fix |

## 2.3 Repository state re-checked on 2026-09-30

| Check | Result |
|---|---|
| Branch protection on `main` | **Still none** (`protected: false` for all three branches). Owner action §6.2 stands |
| Collaborators | owner only |
| Open pull requests | none; PR #1 and #2 merged |
| npm `baip-lens` | **Still unclaimed** (`npm view` → 404). Reserve it before any public post |
| Pinned action SHAs (`security.yml`) | all seven match the upstream tags (`git ls-remote`) |
| Secrets in the new commits | none; `gitleaks` runs on push |

## 2.4 What to run before tagging 0.1.0 (delta to §7)

- [ ] SEC-08 route probe guards when the collector lands (private ranges, `.internal`, https only, DNS pin, 5 s, 256 KB, JSON only)
- [x] SEC-10 OSV disclosure and flags when the OSV client lands (landed 2026-11-25 as `--no-dependency-check` and `--dependency-exclude`, see 2.1)
- [ ] SEC-19 SBOM parsing guards when `sbom` lands
- [ ] SEC-23 `report --redact`
- [ ] SEC-05 `BAIP_LENS_CLIENT_SECRET_FILE`
- [ ] Fixture linter test; `npm pack --dry-run` in CI; release workflow with provenance (SC-01, SC-04)
- [ ] Owner: protect `main`, enable secret scanning + push protection, reserve the npm name, enable Pages and Sponsors

---

# Part 1: design and repository review, 2026-09-29

**Scope.** At the time of this review the repository contains the build spec (`CLAUDE.md`), the verified data-source notes (`docs/data-sources.md`), the README, the licence and `.gitignore`. There is no application code yet, so this is a **design review plus a repository-hygiene review**. Every design finding below is written as a requirement that the implementation must meet and, where possible, as a unit test to add. Re-run the "Code checklist" section against the code once the first slices land.

**Method.** Threat model of the read-only scanner (§1), line-by-line review of the constraints in `CLAUDE.md` and of every data flow in `docs/data-sources.md` (§2), review of the GitHub repository settings and git history (§3), and supply-chain review of the planned toolchain (§4). §5 lists what this change already fixes, §6 what only the repository owner can do, and §7 is the checklist to run against the code.

Severity scale: **High** = could expose a customer credential or run attacker-controlled code on the operator's machine; **Medium** = leaks customer-internal information or degrades the tool's trust story; **Low** = hardening.

---

## 1. Threat model

| Asset | Where it lives | Who wants it |
|---|---|---|
| CF/UAA bearer token and refresh token | `~/.cf/config.json`, process memory, `BAIP_LENS_CLIENT_SECRET` | Anyone who can read logs, crash output, reports, or a proxied request |
| The landscape picture (app names, routes, versions, CVEs, findings) | snapshot JSON, HTML/CSV/SARIF reports, terminal output | Attackers doing reconnaissance; also accidental leaks through screenshots and shared files |
| Customer-internal package names | SBOM, OSV query bodies | Competitors, attackers targeting private packages |
| The operator's machine and network | wherever the CLI runs (laptop, CI runner, jump host) | A tenant of the scanned org who controls app names, routes or responses |
| The project's trust story ("read-only, nothing leaves the machine") | code, docs, CI, npm package | Typosquatters, compromised dependencies, a compromised maintainer account |

**Attackers considered.** (A) A developer with Space Developer in the scanned org who controls app names, route hosts, buildpack detect output, env var names and the HTTP responses of the app routes. (B) A network attacker between the operator and the CF API (mitigated by TLS if never disabled). (C) A supply-chain attacker: npm dependency, GitHub Action, or the npm package name itself. (D) A curious reader of the produced reports (auditor, manager, community member who receives a screenshot).

Attacker (A) is the important one: **every string the scanner reads from CF or from an app route is attacker-controlled input**, and it ends up in the terminal, in a CSV opened in Excel, and in an HTML file opened in a browser.

---

## 2. Design findings

### 2.1 Credentials

| Id | Sev | Finding | Requirement |
|---|---|---|---|
| **SEC-01** | High | `docs/data-sources.md` §1.1 lists `SSLDisabled` among the cf CLI config fields but does not say what to do with it. The cf CLI honours it (`--skip-ssl-validation`). If BAIP Lens honoured it too, a token could be sent over an unverified TLS connection. | Ignore `SSLDisabled`. Never set `rejectUnauthorized: false`, never read `NODE_TLS_REJECT_UNAUTHORIZED`. If the certificate is invalid, exit 2 with "certificate not trusted; add your corporate CA with `NODE_EXTRA_CA_CERTS`". Unit test: the HTTP client has no code path that disables TLS verification (grep the built bundle). |
| **SEC-02** | High | The token is attached to requests by the client, but the spec does not bind the token to a host. A bug, or a redirect, could send the CF bearer token to `api.osv.dev`, `endoflife.date`, `ui5.sap.com` or an app route. | Bind credentials to hosts inside the client: `Authorization` is added **only** when the request host equals the `--api` host or the discovered `log_cache` host. Callers cannot pass headers. Unit test: a request to every other allow-listed host is asserted to carry no `Authorization` header. |
| **SEC-03** | High | Redirects. `fetch` follows redirects by default; a CF API or an app route answering 3xx to another host would move the request (and possibly the token) off the allow-list. `data-sources.md` sets `redirect: 'manual'` for the route probe only. | `redirect: 'manual'` (or `'error'`) for **all** requests. A 3xx from the CF API is recorded as `error` for that check. Unit test with a mocked 302. |
| **SEC-04** | High | Secrets in error paths. UAA and CF errors are printed to the terminal; stack traces and `--verbose` output can include request objects with headers, and `POST /oauth/token` bodies contain the refresh token or client secret. | A single redaction function wraps every log, error and verbose line: it removes `Authorization` headers, any `bearer …`/`eyJ…` token shape, `refresh_token`, `client_secret` and `password` fields, and the contents of `config.json`. Never log the body of `/oauth/token` requests or responses. Unit test: feed a fake token through each error path and assert the output never contains it. |
| **SEC-05** | Medium | Client credentials are read from `BAIP_LENS_CLIENT_ID` / `BAIP_LENS_CLIENT_SECRET` only. A `--client-secret` flag (if ever added) would land in shell history and `ps` output. | Never accept secrets as CLI flags. Add `BAIP_LENS_CLIENT_SECRET_FILE` for CI and secret managers. Zero the in-memory copy after the token exchange. |
| **SEC-06** | Medium | The refreshed token is "held in memory" and "never written back". Good. Missing: the snapshot must never contain the token, the config file path, or the operator's user name (`~/.cf/config.json` contains the user's name and GUID). | The snapshot schema is `.strict()` and has no field where a token could land. The privacy test in the definition of done must scan **all** outputs for the JWT shape (`eyJ` + two dots), for `bearer `, for the operator's email/user name from `config.json`, and for `refresh_token`. |
| **SEC-07** | Low | The JWT `exp` is decoded locally. Fine, as long as nothing else in the payload is trusted. | Decode base64url payload only, read `exp`, treat anything malformed as "expired" and refresh. Never verify or trust `sub`, `scope` etc. locally; the CF API decides. |

### 2.2 Outbound requests and the allow-list

| Id | Sev | Finding | Requirement |
|---|---|---|---|
| **SEC-08** | High | **Route probe reaches internal networks.** The UI5 probe GETs `https://<route host>/resources/sap-ui-version.json` for every mapped route. Route hosts are attacker (A) controlled and can be internal domains (`apps.internal`, private DNS names) or names that resolve to private, loopback or link-local addresses. When the scan runs on a CI runner or a jump host this becomes a server-side request forgery primitive: e.g. `169.254.169.254` (cloud metadata) or `10.x` services. | Before connecting, resolve the host and refuse RFC 1918, loopback, link-local (`169.254.0.0/16`, `fe80::/10`), unique-local (`fc00::/7`), multicast and unspecified addresses; refuse `*.internal` and single-label hosts; connect only with `https:`; pin the resolved address for the request to avoid DNS rebinding (resolve once, connect to that IP with the `Host`/SNI set to the name). Cap: one probe per app, 5 s, 256 KB body, `Content-Type` must be JSON. Unit tests for each refused class. |
| **SEC-09** | Medium | `GET /` discovery returns `links.uaa`, `links.login`, `links.log_cache`. They are trusted because they come over TLS from `--api`, but the spec does not require them to be `https:`. | Validate scheme `https:` for every discovered link; otherwise exit 2. The `next.href` same-origin guard in §1.2 stays. |
| **SEC-10** | Medium | **Private package names leak to OSV.** `POST api.osv.dev/v1/querybatch` sends `{ecosystem, name, version}` for every SBOM entry, including scoped internal packages such as `@customer/billing-core`. That is customer-internal information leaving the machine, contradicting the "no data leaves the machine" pitch as users will read it. | Document it in `docs/privacy.md` in plain words. Add `--osv-exclude <glob>` (default: none) and `--no-osv`. Print, before the first OSV call, one line: "Sending N package names and versions to api.osv.dev (public packages only is recommended; use --osv-exclude '@yourorg/*')". |
| **SEC-11** | Low | Third-party services receive a default Node `User-Agent` that reveals the Node version. | Send `User-Agent: baip-lens/<version> (+https://github.com/sebastianomarchesini/BAIP-Lens)` to every host and nothing about the OS. |
| **SEC-12** | Low | `Retry-After` is honoured without a cap; a misbehaving server can stall the scan for hours. Unbounded response bodies can exhaust memory. | Cap `Retry-After` at 120 s. Cap every response body (64 MB for CF list pages, 256 KB for probes, 8 MB for OSV, 1 MB for endoflife/UI5/npm) and record `error` when exceeded. |
| **SEC-13** | Low | `report --from snapshot.json` must be offline, but nothing enforces it. | The allow-list has an "offline" mode that throws `EgressDeniedError` for every host. `report` always runs in that mode. Unit test. |
| **SEC-14** | Low | Corporate proxies. Not a vulnerability, but users will be tempted to disable TLS checks when a TLS-inspecting proxy is in the way. | Honour `HTTPS_PROXY`/`NO_PROXY` (undici `EnvHttpProxyAgent`) and document `NODE_EXTRA_CA_CERTS`. This removes the main reason people reach for `--skip-ssl-validation`. |

### 2.3 Attacker-controlled strings in outputs

| Id | Sev | Finding | Requirement |
|---|---|---|---|
| **SEC-15** | High | **HTML report injection.** The single-file report embeds the snapshot JSON and renders app names, routes, buildpack names, `detect_output`, env var names and OSV advisory text (`summary`, `details`, which is Markdown from a third party). If any of it is inserted as HTML, attacker (A) gets script execution in the reader's browser. On `file://` the impact is limited, but the same UI is planned for **server mode behind XSUAA (v0.3)**, where it becomes session theft. | Embed the snapshot as `<script type="application/json">` with `<`, `>`, `&`, U+2028 and U+2029 escaped as `\uXXXX`. Never use `dangerouslySetInnerHTML`; render OSV `details` as plain text, never as Markdown/HTML. Accept reference links only with `http:`/`https:` schemes. Add a CSP meta tag to the report: `default-src 'none'; script-src 'sha256-<hash of the inline bundle>'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'`. Tests: an app named `</script><script>alert(1)</script>` and a reference `javascript:alert(1)` in a fixture must render inert (React Testing Library), and the Playwright offline test must also assert `connect-src 'none'` and zero network requests. |
| **SEC-16** | High | **CSV injection.** A cell starting with `=`, `+`, `-`, `@`, tab or carriage return is executed as a formula by Excel and LibreOffice (DDE / `=cmd|…`). App names and remediation text end up in the CSV. | In `csv.ts`, prefix such cells with a single quote and escape quotes per RFC 4180 (OWASP CSV injection guidance). Unit test with `=cmd|' /C calc'!A0`. |
| **SEC-17** | Medium | **Terminal escape injection.** App and route names printed to the console can contain ANSI/OSC escape sequences that hide text, move the cursor, or (in some terminals) set the clipboard or title. | Strip C0/C1 control characters and ESC sequences from every string before it reaches `stdout`/`stderr`. Unit test. |
| **SEC-18** | Medium | **Path traversal through names.** File names like `snapshot-<org>-<date>.json` or per-app files would let an org/space/app name containing `/`, `\` or `..` write outside `--out`. | Never build file names from CF names. Use `snapshot-<date>-<8 hex of random>.json`. If a user-supplied name is ever used, allow `[A-Za-z0-9._-]` only. |
| **SEC-19** | Medium | **SBOM inputs.** `baip-lens sbom --path` reads `package-lock.json`, `pom.xml`, `mta.yaml` and `.mtar` (a ZIP). Risks: zip-slip (entry names with `..`), decompression bombs, symlinked entries, XML external entities and entity expansion in `pom.xml`. | Never extract `.mtar` to disk; read entries in memory, reject entry names that normalise outside the root, cap total uncompressed size (e.g. 512 MB) and ratio (100:1). Parse XML with entity processing **off** (`processEntities: false`, no DOCTYPE). Parse YAML with a safe loader only. Cap input file sizes. Unit tests with a crafted zip and a `pom.xml` containing `<!DOCTYPE … <!ENTITY …>>`. |
| **SEC-20** | Medium | **SARIF and local paths.** SARIF `artifactLocation.uri` and messages may contain absolute local paths of the SBOM source (`/Users/<name>/…` reveals the operator's user name). | Use paths relative to `--path` and `uriBaseId`. Extend the privacy test to fail on `/Users/`, `/home/`, `C:\Users\`. |
| **SEC-21** | Low | Snapshot input trust. `report --from` parses a JSON file the user may have received from someone else. | Validate with the strict zod schema before use; cap file size (256 MB); do not deep-merge parsed objects with defaults (prototype pollution); reject unknown keys. |
| **SEC-22** | Low | Report files contain the landscape picture but are written with the default umask, often world-readable on shared hosts. | Create `--out` with mode `0o700` and files with `0o600`. Print once: "Reports contain internal details of your landscape. Do not commit them; add `reports/` to `.gitignore`." |
| **SEC-23** | Low | Users will share screenshots and files of the report in the community (this is also what the marketing plan asks them to do). Real org, space, app and route names would leak. | Add `report --redact`: replaces org, space, app and route names with stable per-scan hashes (`app-3f2a`), keeps versions, findings and counts. Ship it in v0.1 because the campaign relies on shared reports. |

### 2.4 Privacy checks that are already right

- Audit events: `actor.*` and `data` are dropped at parse time (`data-sources.md` §2). Keep the zod `strip` behaviour and add a fixture containing `actor` to prove it never reaches the snapshot.
- Process stats: `host`, `instance_internal_ip`, `instance_ports` are never written. Add the same fixture proof.
- `GET /v3/apps/:guid/env` (returns `VCAP_SERVICES` credentials) is deliberately not used; `/environment_variables` returns keys only. Keep the GET-only test **and** add a test that the path `/env` is refused by the client even with GET.
- `--deep` creates an `audit.app.environment_variables.show` event in the customer landscape. Keep the disclosure in `privacy.md` and print it once when `--deep` is used.

---

## 3. Repository review (as of 2026-09-29)

Checked with the GitHub API and `git`:

| Check | Result | Action |
|---|---|---|
| Secrets in git history (all commits, all blobs; AWS, private keys, Slack, GitHub, JWT, `client_secret`, `password` patterns) | **Clean** | Keep it that way: `gitleaks` on every push (added, §5). |
| Binary or large blobs in history | None | — |
| Collaborators | 1 admin (owner) | Fine for now. When a second maintainer joins, require 2FA and use CODEOWNERS (added). |
| Branch protection on `main` | **None** (`protected: false`) | Owner action (§6): require PR, required status checks, no force-push, linear history. |
| `SECURITY.md` / disclosure policy | Missing | Added (§5). |
| Dependabot / dependency updates | Missing | Added `.github/dependabot.yml` for npm and GitHub Actions. |
| Secret scanning and push protection | Not verifiable from here | Owner action (§6): enable in Settings → Code security. |
| OpenSSF Scorecard | Not running | Added workflow; publish the badge once green. |
| CodeQL | Not running (no code yet) | Workflow added; the job skips itself until TypeScript sources exist. |
| GitHub Actions token permissions | Repository default | Workflows added here declare `permissions: read-all` at top level and elevate per job only. Owner action: set the repository default to read-only. |
| Issue templates | Missing | Added, with a "do not paste tokens or `config.json`" warning, because bug reports are the most likely place for a token to leak. |
| `.gitignore` | Covers build output and `reports/` | Recommend adding (in the development branch, not done here to avoid conflicts): `.env`, `.env.*`, `*.pem`, `*.key`, `.cf/`, `*.mtar`, `snapshot*.json`, `*.sarif`, `.DS_Store`. |
| Test fixtures | None yet | Add a fixture linter test that fails on e-mail addresses, `eyJ` tokens, `bearer `, real BTP hostnames (`*.hana.ondemand.com`, `*.cfapps.*`) and IP addresses. Fixtures must use `example.com`/`.invalid` hosts and made-up GUIDs. |
| npm package name `baip-lens` | **Unclaimed** on 2026-11-07 (also `baiplens`, `@baip-lens/cli`, `create-baip-lens` are free) | Owner action, **urgent before any marketing post**: publish `baip-lens@0.0.1` as a placeholder that prints "not released yet" so the name cannot be squatted. |

---

## 4. Supply chain and release

| Id | Sev | Requirement |
|---|---|---|
| **SC-01** | High | Publish from GitHub Actions with **npm trusted publishing (OIDC) and `--provenance`**, never from a laptop token. Enable 2FA on the npm account and on GitHub. |
| **SC-02** | High | Pin every GitHub Action to a full commit SHA (done in the workflows added here) and let Dependabot bump them. |
| **SC-03** | Medium | Commit the lockfile, install with `npm ci --ignore-scripts` in CI, and keep the runtime dependency list tiny (`commander`, `zod`, an XML and a YAML parser; nothing else at runtime). Review every new dependency's install scripts. |
| **SC-04** | Medium | `package.json` `files` whitelist (`dist/`, `README.md`, `LICENSE`, `NOTICE`) so fixtures and tests never ship. Verify with `npm pack --dry-run` in CI. |
| **SC-05** | Medium | The UI bundle inlines fonts and locale data from `@sap-theming/theming-base-content` and `@openui5/sap.ui.core`. Record their licences in `NOTICE` and add a CI check that the built HTML has no `http://`/`https://` `src`/`href` attributes except in visible reference links. |
| **SC-06** | Low | Add an OpenSSF Scorecard badge and a `SECURITY.md` link in the README once the workflows are green; both are trust signals the marketing plan uses. |

---

## 5. Fixed in this change

- `SECURITY.md`: private disclosure via GitHub Security Advisories, 72-hour acknowledgement, 90-day coordinated disclosure, safe-harbour statement, what is in and out of scope.
- `.github/dependabot.yml`: weekly npm (root and both workspaces) and GitHub Actions updates, grouped, with a 5-PR cap.
- `.github/workflows/security.yml`: `gitleaks` on push and PR (full history), Dependency Review on PRs, CodeQL for JavaScript/TypeScript that skips until sources exist, and OpenSSF Scorecard on `main` weekly. Every action pinned by SHA; `permissions: read-all` by default.
- `.github/CODEOWNERS`: the owner reviews everything under `packages/cli/src/http/`, `packages/cli/src/net/`, `packages/cli/src/reporters/`, `.github/` and `SECURITY.md`.
- `.github/ISSUE_TEMPLATE/`: bug and feature templates with the token warning, and a config that routes security reports to the advisory form.
- `.github/PULL_REQUEST_TEMPLATE.md`: a short security checklist (GET-only, no new hosts, no secrets in fixtures, outputs escaped).

Nothing in `CLAUDE.md`, `README.md`, `.gitignore` or under `packages/` was touched, because development is in progress on another branch. §7 is the list to hand to whoever is writing the code.

---

## 6. Owner actions (cannot be done from a branch)

1. **Reserve `baip-lens` on npm today** (placeholder 0.0.1 with a clear "not released" message). Then set up trusted publishing for the repository.
2. GitHub → Settings → Branches: protect `main` (require a PR, require `ci` and `security` checks, block force-push and deletion). Settings → Actions → General: workflow permissions "Read repository contents", and require approval for first-time contributors.
3. Settings → Code security: enable Dependabot alerts, secret scanning **and push protection**, private vulnerability reporting.
4. Enable 2FA on GitHub and npm; add a second maintainer only with 2FA.
5. Enable GitHub Sponsors on the account (the `FUNDING.yml` added by the marketing kit only works once you are enrolled).

---

## 7. Code checklist (run before tagging v0.1.0)

Copy this list into the development session. Each line is a test or a grep.

- [ ] HTTP client refuses every method except GET on the CF API host, and every non-allow-listed host (existing constraint #1), **plus** SEC-02 (token bound to host), SEC-03 (no redirects), SEC-09 (https only), SEC-13 (offline mode for `report`).
- [ ] No code path disables TLS verification; `SSLDisabled` from `config.json` is ignored (SEC-01).
- [ ] Redaction wrapper on every log/error/verbose path; token never appears in any output (SEC-04, SEC-06).
- [ ] No secret accepted as a CLI flag; `BAIP_LENS_CLIENT_SECRET_FILE` supported (SEC-05).
- [ ] Route probe: private/loopback/link-local/`.internal` refused, https only, DNS pinned, 5 s, 256 KB, JSON only (SEC-08).
- [ ] OSV: `--no-osv`, `--osv-exclude`, the one-line disclosure before the first call (SEC-10).
- [ ] Fixed `User-Agent`, capped `Retry-After`, capped body sizes (SEC-11, SEC-12).
- [ ] HTML: JSON embedded with `\u003c` escaping, no `dangerouslySetInnerHTML`, OSV text as plain text, `http(s):` links only, CSP meta with `connect-src 'none'`, XSS fixture test (SEC-15).
- [ ] CSV: formula-prefix escaping with test (SEC-16).
- [ ] Terminal output stripped of control characters (SEC-17).
- [ ] No file name derived from CF names (SEC-18).
- [ ] SBOM: in-memory zip reading, path normalisation, size and ratio caps, XML entities off, safe YAML (SEC-19).
- [ ] SARIF uses relative URIs; privacy test fails on home-directory paths (SEC-20).
- [ ] Snapshot input validated strictly and size-capped (SEC-21).
- [ ] `--out` created `0o700`, files `0o600`, warning printed (SEC-22).
- [ ] `report --redact` implemented (SEC-23).
- [ ] Fixture linter test (no e-mails, tokens, real hosts, IPs).
- [ ] `package.json` `files` whitelist, `npm pack --dry-run` check, provenance publish workflow (SC-01, SC-04).
