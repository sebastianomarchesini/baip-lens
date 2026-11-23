# Changelog

## Unreleased

### Security

- **A crafted snapshot can no longer exhaust memory** in `report --from` and `scan --previous`. 0.3.1 said this was still open. A few megabytes of `{}` in one of a snapshot's lists made zod build millions of validation issues: 1.1 to 2.1 GB of memory, then an out-of-memory abort instead of exit code 2. A nested project list overflowed the stack, evidence nested a million levels deep loaded and then broke the reporters, and 42 MB of distinct keys in one finding's evidence took 8 seconds and 1.1 GB to load. Such a file is now refused within a second or two, with exit code 2 and a message that names the limit:
  - The file may be at most **128 MB** (was 256 MB).
  - Before it is parsed, it may nest at most **64** levels, hold at most **4,194,304** keys and values together, and no object in it may have more than **1,000** keys.
  - Every list has a limit (for example 100,000 apps), and a list stops at its first invalid element, so a snapshot yields at most one element's issues per list.
  - A schema version that is not a number is no longer quoted in the error message, which could repeat a secret pasted by mistake.
  - These limits are set above any real landscape: a snapshot of about 26,000 apps still loads, however it is formatted, and so do the recorded snapshots, the 0.1.0 one included ([docs/security-review.md](docs/security-review.md) SEC-21).
  - Not fixed yet: a crafted but valid project record can still keep `report --from` busy for hours, because some project rules compare names in nested loops. Memory stays bounded.

### Added

- **`baip-lens project --cf`:** the project rules on a **deployed app**, read live. It reuses the cf CLI login and target, lists the apps of the space (saying why a stopped app, a Docker app or an app with SSH off cannot be read, with the `cf` command that would change it), and reads the app you pick (or name with `--app`) from one running instance over the platform's SSH proxy, as `cf ssh` reaches it: the one-time code from UAA (as `cf ssh-code`), password authentication only, the proxy's host key checked against the fingerprint the CF root publishes (an empty or unknown fingerprint is refused), the SFTP subsystem only (no shell, command or port forwarding), and only listing and read requests, with files opened read-only. The droplet is not downloaded and nothing is written to disk but the reports. The same allow-list, deny-list, limits and parsers as for a local folder apply; a file that changed between listing and reading is refused, and a lost session stops the command with exit code 2. It needs **Space Developer**: the command says so first, checks the user's roles before any SSH attempt, and notes the `audit.app.ssh-authorized` event Cloud Foundry records ([docs/data-sources.md §10](docs/data-sources.md#10-deployed-apps-baip-lens-project---cf), [docs/permissions.md](docs/permissions.md#baip-lens-project---cf)). Tried on an SAP BTP landscape before release (§10.5).

### Changed

- **`project --cf` can turn SSH on for you.** An app with SSH off for the app can now be picked: after a yes (or `--enable-ssh` in a script) BAIP Lens runs, with your cf CLI, `cf enable-ssh <app>` and `cf restart <app> --strategy rolling`, reads the app, and then runs `cf disable-ssh <app>`, also when the scan fails or is interrupted. It refuses when the cf CLI targets another org or space. Without Space Developer, a Space or Org Manager is offered `cf set-space-role` for themselves; anyone else gets the command for a manager. The Space Developer note is shown only when the role is missing. The app list groups the apps that cannot be read by reason, and an only readable app is picked without asking. The cf commands are limited to these four shapes (`remote/cfCli.ts`); the HTTP client stays GET-only ([docs/permissions.md](docs/permissions.md#baip-lens-project---cf)).
- The project collector reads through a `ProjectTree` interface (`collectors/project/tree.ts`); a local folder (`localTree.ts`) keeps exactly the previous behaviour, and the deployed app (`remote/sftpTree.ts`) is the second implementation.
- The CLI depends on `ssh2` (MIT) for `project --cf` only; it is loaded on demand, so every other command runs without it. Its install script tries to build an optional native crypto add-on and falls back to pure JavaScript; CI keeps installing with `--ignore-scripts`, and the tests pass that way.
- The egress allow-list gains `GET /oauth/authorize` on UAA and the `links.app_ssh` endpoint, both added to the policy by `project --cf` only.

## 0.3.1 (2026-11-18)

### Security

- **zod 4.6.7** (was 4.6.5), with the fix for [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5): zod checked an array's `.max()` limit only after parsing every element, building one validation issue per bad element first. In a snapshot only the lists inside a project record have such a limit, so `report --from` and `scan --previous` now reject one of them at once when it is over its limit. This does not stop a crafted snapshot from exhausting memory: the list of projects and the other lists have no limit, and the nested limits multiply. The package now requires `zod@^4.6.7`, so npm can no longer satisfy it with an older copy already installed in a project.

### Fixed

- **The logo on the npm page** was a broken image: the prepack step pinned the README's Markdown links and images to the release tag but not its HTML attributes, so npmjs.com looked for the logo under `packages/cli` on the default branch and left the dark variant's `srcset` relative to npmjs.com. Prepack now pins the `src`, `srcset`, `href` and `poster` of HTML tags too, and fails when it finds a relative URL it cannot pin (the target of a link reference definition) instead of packing a README with a broken link. CI now runs `npm pack --dry-run` on every pull request, so this check and the release workflow's file check run before a release, and the file check now also requires the `README.md`, `LICENSE` and `NOTICE` that prepack copies in.
- **The npm description** no longer promises runtime health and outdated-library checks, which are still planned. It names what ships (app inventory, idle apps, stale deployments, the OWASP-based project checks and the report formats) and says that the project is not affiliated with SAP. The keyword `sbom` is replaced by `cap` and `sarif`.

## 0.3.0 (2026-11-17)

### Added

- **`APP_IDLE` history across scans: `scan --previous <snapshot.json>`** carries each app's traffic history forward from an earlier snapshot of the same org, matched by app GUID: the newest request ever seen, when the current run of scans without a request began, and how many scans it has ([docs/rules.md](docs/rules.md#history-across-scans-scan---previous)). From the second scan without a request the finding states the span ("No requests seen across 6 scans over 42 days"); 3 or more scans over 30 days or more raise the confidence to `high`, with severity still `low` (D9). A request in any window ends a run; a scan without one counts only when it read at least `--min-traffic-window`, and a scan that cannot tell leaves the history as it was (D8). An app this scan cannot see (outside `--space`, in a space not visible this time, or when the app inventory could not be read) keeps its history unchanged; only an app missing from a space whose apps were read is dropped. A file that is not a valid snapshot, a project scan, another API endpoint or a snapshot that is not older stops the scan with exit code 2 before any request; another org stops it right after the org lookup. The history is stored in the snapshot (`raw.history`, `options.previousScannedAt`), so `report --from` gives the same result offline, and the report's summary names the earlier scan.
- **`APP_IDLE`: apps that nothing seems to use**, with three signals ([docs/rules.md](docs/rules.md#app_idle)):
  - `no_route`: started, a `web` process with instances, and no route at all (`low`, confidence `high`).
  - `no_traffic`: started, an HTTP route, and no router access log in the window Log Cache held; `low` with confidence `medium` when the droplet and the `web` processes are unchanged for more than 180 days, else `info` with confidence `low`. A window shorter than `--min-traffic-window` (default 12 hours) gives no finding but `unknown`, and every finding names the window it saw.
  - `stopped`: stopped for more than 90 days (`low`, confidence `high`).
  - Started workers are never flagged: no `web` process, `web` scaled to 0, or a `web` process with the `process` health check, which Cloud Foundry documents for workers (the legacy `none` counts as `process`, decision D7). Stopped for more than 90 days, a worker is flagged as `stopped` like any app. Apps reachable only over TCP or an internal domain are `unknown` (D6).
  - When the routes or processes cannot be read, no app is called idle: started apps and apps stopped for more than 90 days are `unknown`, and the traffic check is skipped (`dependency_skipped`). When no Log Cache envelope of an app carries a `source_type` tag (drain metadata turned off), router logs cannot be recognised, so the traffic check is skipped instead of calling every app silent.
- **Three collectors**, all Space Auditor: `collect.routes` (`GET /v3/routes?space_guids=…&include=domain`, by space so that shared routes count, 50 spaces per request), `collect.processes` (`GET /v3/processes?types=web`) and `collect.traffic`, which reads Log Cache (`GET /api/v1/read/<app-guid>`, host only from the CF root's `links.log_cache`) newest first for apps with an HTTP route, keeps three values per app (`lastRequestAt`, `windowStart`, `envelopesExamined`) and drops the log lines, tags and instance as it reads them.
- **`scan` options:** `--no-traffic-check`, `--min-traffic-window <hours>` (default 12) and `--traffic-pages <n>` (default 5). They are recorded in the snapshot, so `report --from` gives the same result offline.
- **Usage per app** in the inventory: `idle`, `active` (with the last request), `unknown` (the rule would judge the app but the data cannot tell) or `not_assessed` (a worker, or stopped recently), with a signal and confidence or a reason code. The HTML report shows it in a new Usage column of the Apps table, where `unknown` has its own icon and never looks like "no finding", and the Idle apps key figure names each signal with its confidence and the number of unknown apps.
- `docs/data-sources.md`: §9, the verified research behind the traffic evidence (routes, the Log Cache read and meta endpoints, the roles Log Cache accepts, retention); decisions D5 to D9 in §7; and the credential each host may receive in the §6 allow-list table.

### Changed

- **Guided mode, Step 1: type the region instead of picking a number.** The numbered menu of about fifty regions is gone. The prompt shows an example (`eu10`, `us10` or `us10-001`) and takes a region id or the pasted API endpoint; `list` (or `help`, `?`) prints every region and asks again. The check line names the region (`Checking api.cf.eu10.hana.ondemand.com (Europe (Frankfurt), AWS) …`), an id that is not in the list is still tried with a note, and an unreachable address can be retyped up to three times. New command `baip-lens regions` prints the same list. Wherever an endpoint is accepted, `us10.001` now means `us10-001`.
- **The egress allow-list names the credential each host may receive:** the CF token for the CF API and its log cache only, the OAuth client id and secret (Basic) for the token endpoint only, nothing for the public data sources. The log cache rule allows `GET /api/v1/read/<app-guid>` only; `/api/v1/meta`, `/api/v1/info` and the PromQL endpoints are unreachable.
- **A check can be skipped with its own reason.** Log Cache answers 404, never 403, for a missing role, an expired token or a failed permission lookup; the traffic check says so instead of the generic "insufficient role". A new skip reason code, `unavailable`, covers a log cache that is absent or does not answer.
- **Skipped checks are no longer all blamed on the role.** Guided mode and the report's "Start here" summary say a check "could not run with your role" only when a missing role is what stopped it, "was turned off" after `--no-traffic-check`, and "did not run" otherwise, for example when the log cache is down.
- **Snapshot (schema version unchanged, older snapshots still load):** `raw.routes`, `raw.processes`, `raw.traffic`, `raw.history`, the three traffic options, `options.previousScannedAt` and `usage` on inventory items, all with defaults when missing.
- **CSV:** the apps file ends with five new trailing columns `usage`, `usage_signal`, `usage_confidence`, `usage_reason`, `usage_last_request_at`; existing columns keep their order.
- **HTML report:** the Apps table's fixed columns are sized to their content to make room for the Usage column; long buildpack names are cut short with "…" at desktop width.
- `btp-lens-reports/`, the default output folder before the rename, is git-ignored again.
- **Reading a snapshot (`report --from`, `scan --previous`):** the 256 MB limit now holds for a pipe too (`--previous <(...)`, `/dev/stdin`), since the bytes are counted as they are read, and a file that is not JSON is reported with its line and column only, never with the start of its content, which could be a secret passed by mistake.

## 0.2.0 (2026-11-07)

### Changed

- **The project is now BAIP Lens.** The npm package is `baip-lens` (the command is `npx baip-lens`), the UI workspace is `@baip-lens/ui`, the environment variables are `BAIP_LENS_ACCESS_TOKEN`, `BAIP_LENS_CLIENT_ID`, `BAIP_LENS_CLIENT_SECRET`, `BAIP_LENS_DATA` and `BAIP_LENS_DEBUG`, the default output folder is `baip-lens-reports/`, the report file is `baip-lens-report.html`, snapshots record `tool.name` as `baip-lens`, and SARIF fingerprints are keyed `baipLensFinding/v1`. The repository moves to `sebastianomarchesini/BAIP-Lens`. Snapshots written by `btp-lens` 0.1.0 still load with `report --from`. The `btp-lens` package on npm is deprecated and points here. The name follows the SAP Business AI Platform (BAIP), which SAP announced in 2026 as the umbrella for SAP BTP; the tool is still not affiliated with SAP.

### Added

- **`baip-lens project --path <dir>`:** a second scan target, a local CAP or MTA project directory, read from the file system only (no network, no child process, no `git`). It writes the same snapshot and reports as `scan`, `report --from` works on its snapshots, and `--fail-on` applies. The collector opens an allow-list of files (`package.json`, `.cdsrc.json`, `.cdsrc.yaml`, `mta.yaml`, `xs-security.json`, `xs-app.json`, `*.cds`, seed `*.csv`, `*.html`, and the `.gitignore` files consulted when a `*.mtar` is present; `*.mtar` is only stat'ed) and never opens `.cdsrc-private.json`, `.cdsrc.js`, `default-env.json`, `.env*`, `*.mtaext`, keys, `*.http` or `*.md`; it keeps identifiers, counts and booleans, never file contents, CSV values, mocked user names, passwords or absolute paths ([docs/data-sources.md §8](docs/data-sources.md#8-local-project-files-baip-lens-project), [docs/privacy.md](docs/privacy.md#project-scans)).
- **Thirteen project rules**, derived from the OWASP Top 10 (2025) patterns of the public SAP TechEd 2026 workshop XP261: `CAP_MOCKED_AUTH_IN_PROD`, `CAP_MOCKED_USER_PASSWORD`, `CAP_AUDITLOG_MISSING`, `CAP_AUDITLOG_NOT_BOUND`, `CAP_PERSONAL_DATA_UNANNOTATED`, `CAP_SERVICE_NO_RESTRICTION`, `CAP_ROLE_NOT_IN_XSUAA`, `XSUAA_SCOPE_UNUSED`, `APPROUTER_ROUTE_NO_AUTH`, `APPROUTER_CSRF_DISABLED`, `DEPLOY_ARTIFACT_IN_REPO`, `SEED_DATA_SENSITIVE`, `UI5_BOOTSTRAP_EXTERNAL`. Each is documented in [docs/rules.md](docs/rules.md#project-rules) with its data, trigger, severity, evidence, remediation, verified references and limits.
- **OWASP Top 10 (2025) tags** on every rule (`owasp` in the rule metadata, `owasp/<id>` tags in SARIF, shown per rule in the HTML report), and a **criticality matrix** (impact × ease of attack → severity, `packages/cli/src/model/criticality.ts`) that the new rules use; findings record the two inputs as `impact` and `easeOfAttack` in their evidence.
- **Findings with a file location:** project findings carry `location: { file, line? }`; SARIF emits it as a `physicalLocation` with `uriBaseId: PROJECTROOT` (and a region when the line is known), the HTML report shows `file:line` under the finding, and the findings CSV gains `file` and `line` columns.
- **HTML report for project scans:** "Projects scanned", "Services open to all users" and "Personal data without annotations" key figures, a Projects tab instead of Apps, the OWASP category in each rule panel, and a "Start here" summary for the project.
- `npm run sample` also renders the project sample report (`reports/sample-project/`), and a Playwright check opens it from disk with networking disabled.
- `docs/due-diligence.md`: answers to the questions that managers and security, legal and procurement teams ask before a first run, each pointing to the code, test or document behind it.

### Changed

- **Snapshot (schema version unchanged, older snapshots still load):** `scope.projects`, `raw.projects`, `kind` (`app` or `project`) on inventory items, `state`, `createdAt` and `updatedAt` nullable for projects, `owasp` on rule metadata, `location` on findings, and `summary.projects` next to `summary.apps` in the report data. A test loads the 0.1.0 sample snapshot and checks that it re-analyses to the same findings.
- **CSV:** the findings file ends with three new trailing columns `owasp`, `file`, `line`, and the apps file with `kind`; existing columns keep their order.
- **SARIF:** rule tags gain `owasp/<id>`; fingerprints of Cloud Foundry findings are unchanged, and project findings add the file and subject to theirs so that two findings of one rule on one project stay distinct.
- The Cloud Foundry client is typed against `ReadOnlyHttp`, a view of the HTTP layer with a single `get` method whose request has no method and no body field, so its code cannot ask for anything but `GET`. A type-level test fails CI if the client is ever given more. The allow-list still refuses every other method for the CF API host, as before.
- The CLI depends on `yaml` (ISC) in addition to `commander` and `zod`, to read `mta.yaml` and `.cdsrc.yaml`.

## 0.1.0 (2026-10-10)

First public release. It covers guided mode, the app inventory, the `APP_NO_RECENT_DEPLOY` rule and every report format. The other rules in [docs/rules.md](docs/rules.md) (runtime and stack end of life, buildpack age, idle apps, SAPUI5 maintenance, `@sap/*` packages, known CVEs and plain-text secrets) and the `sbom` command arrive in the next releases.

### Fixed (pre-release audit, 2026-10-11)

- **HTML report:** grouping the Apps table by org or space no longer blanks the whole report; a page that fails now shows a message and the other sections keep working. The theme menu (Light, Dark, Same as system) is now visible and usable; it rendered with no size before. A scan limited with `--space` now says so in the headline, the title bar and the summary.
- **Guided mode:** org names and error texts from the CF API now pass through the same escape-sequence and token filter as the rest of the CLI. Ctrl+C now stops the wizard while it is connecting, signing in or scanning, as the banner promises. The login URL from the CF root is validated as plain https before it is shown or opened. "The report was opened in your browser" is only printed when the opener succeeded.
- **Windows:** files and URLs are opened through PowerShell with a literal argument instead of `cmd /c start`, so `&`, `%` and `|` in a path or URL cannot run anything.
- **Connection errors:** the real cause behind Node's `fetch failed` (DNS, refused connection, TLS interception, proxy 407) is kept, so `doctor` and guided mode now give the right advice; TLS interception was previously reported as a proxy problem. The proxy advice (`NODE_USE_ENV_PROXY=1`) is only given on Node.js 22.21 or 24 and newer, where it exists; older versions are told to upgrade.
- **Scan:** a user who can see the org but none of its spaces now gets a clear message and exit code 2 instead of an empty report with every check "ran" (the CF list endpoints filter by visibility instead of answering 403). `--org` and `--space` are matched exactly; a comma in a name no longer widens the filter. A `401` on the unauthenticated root call is no longer reported as a rejected token.
- **Output files:** reports are never written through a symbolic link, an existing report file is tightened to `0600`, and file-system errors are explained in plain words.
- **Terminal filter:** `Basic` credentials and the cf CLI config field names (`AccessToken`, `RefreshToken`, `UAAOAuthClientSecret`) are redacted too.
- `--no-probe-routes` is hidden from `--help` and the snapshot records `probeRoutes: false`, because no route probe exists yet. `--fail-on` no longer prints its default twice. `baip-lens guided` in a script (no terminal) prints the usage hint and exits 2 instead of writing escape codes to the pipe.
- **CSV:** the files start with a UTF-8 byte-order mark, so Excel opens non-ASCII org, space and app names correctly, and control characters are dropped from cells.
- **Report accessibility:** the document title names the section (`Apps · BAIP Lens report`), every section has a page heading, and focus moves to the page on navigation so screen readers announce it.
- **Licenses:** the report and `THIRD_PARTY_LICENSES.md` now carry the Unicode CLDR notice (locale data) and the Preact MIT notice (vendored by UI5 Web Components).
- **Docs:** README, privacy, FAQ, permissions, data sources, security policy and the landing page describe what 0.1.0 does rather than what is planned; the CLA text now exists (`docs/CLA.md`); links to GitHub Discussions were replaced by issues.
- **Release workflow:** runs the same gates as CI (coverage, sample report, offline Playwright check); CI also runs on version tags; the README shipped to npm has its links pinned to the release tag.
- `baip-lens doctor` no longer tells you to run `baip-lens doctor` when the API check fails. A `401`, `403` or `407` from the API root is now explained as a proxy or firewall block, with the fix.

### Added

- **Logo and app icon:** a cloud-and-magnifier mark. It is the report's ShellBar logo and favicon (inlined, so the report stays one offline file), and the README, landing page and social card use it. Light and dark variants of the horizontal logo live in `docs/assets/`.
- **Guided mode:** `baip-lens` with no arguments asks four questions (region or API endpoint, sign-in, org, confirm) and opens the report. Sign-in works like `cf login --sso` with a one-time code from the company login, or with username and password; the session is held in memory only. Reports go to `./baip-lens-reports/<date-time>/`.
- **`baip-lens doctor`:** checks Node.js, API reachability, TLS trust, the cf CLI login and the output folder, with a one-sentence fix per failure.
- **"Start here" panel** on the report's Overview: three or four plain-language sentences computed from the scan.
- **Hardening:** a Content Security Policy in the HTML report (`connect-src 'none'`, hashed scripts); terminal output stripped of escape sequences and token shapes; report folders `0700` and files `0600`; a 256 MB cap on `report --from`; the allow-list refuses the CF endpoints that return credentials even for `GET`; CI actions pinned by commit SHA and installed with `--ignore-scripts`.
- `scan` and `report` end with a one-line reminder that reports describe your landscape and should not be committed.
- **Docs for non-developers:** `docs/getting-started-no-terminal.md`, `docs/faq.md`, and text to send to an administrator in `docs/permissions.md`.
- **`baip-lens scan`:** a read-only scan of one CF org, or one space, that writes a snapshot and reports.
- **`baip-lens report --from`:** offline re-analysis of a snapshot.
- **`baip-lens version`**, and exit codes 0, 1 and 2 with `--fail-on`.
- **HTTP layer:** an egress allow-list with per-host methods and paths; a GET-only CF client with same-origin pagination; retry with backoff; `Retry-After` and `X-RateLimit-*` handling; and a concurrency limit.
- **Credentials:** the cf CLI session (refreshed in memory), `BAIP_LENS_ACCESS_TOKEN`, or client credentials.
- **Collectors:** orgs, spaces, apps and current droplets. A 403 skips the check without failing the scan.
- **Rule `APP_NO_RECENT_DEPLOY`.**
- **Reports:** JSON, CSV (with formula-injection guard), SARIF 2.1.0, and a single-file offline HTML report. The HTML report uses React and UI5 Web Components for React with the Horizon light and dark themes. It has Overview, Apps and Findings screens and embeds the third-party licenses.
- **Documentation:** verified data sources, rules, permissions, privacy and security policy.
