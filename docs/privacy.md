# Privacy

BAIP Lens runs on your machine and writes files to your disk. This page lists what it reads, what it keeps, and where requests go.

## Principles

1. **Read-only.** The HTTP client allows only `GET` to the CF API. This is enforced per host by the egress allow-list in `packages/cli/src/net/allowlist.ts`, and unit tests prove it. A project scan of a folder (`baip-lens project --path`) only reads files and makes no request at all; a project scan of a deployed app (`--cf`) sends only SFTP read requests over its SSH session.
2. **No data leaves the machine.** The allow-list is the only way out, and redirects are never followed. There is no telemetry.
3. **No personal data** in any output.
4. **No secret values** in any output.

## Where requests go

**Only the first three rows, and the last two with `project --cf`, are used today.** The other hosts are already in the allow-list for the rules of the next releases, so that adding a rule can never add a destination unnoticed, but nothing contacts them yet.

| Host | Why | What is sent | Status |
| --- | --- | --- | --- |
| Your CF API (`--api`) | inventory | `GET` only, with your token | 0.1.0 |
| Your UAA or login server (from the CF root) | sign-in, token refresh or client credentials | `POST /oauth/token` only | 0.1.0 |
| Your log cache (from the CF root, never guessed from the API host) | when each app last served a request (`APP_IDLE`) | `GET /api/v1/read/<app-guid>` only, with your token, for apps with an HTTP route | 0.3.0; `--no-traffic-check` turns it off |
| `api.osv.dev` | known vulnerabilities | public package names and versions from your SBOM | planned |
| `endoflife.date` | runtime end-of-life dates | product names such as `nodejs` | planned |
| `ui5.sap.com` | UI5 maintenance status | a request for `/versionoverview.json` | planned |
| `registry.npmjs.org` | current `@sap/*` versions | four fixed package names | planned |
| Your app routes | the UI5 version served | one unauthenticated `GET /resources/sap-ui-version.json` per app, with no redirects; `--no-probe-routes` will turn it off | planned; 0.1.0 makes no request to app routes |
| Your UAA server (from the CF root) | the one-time SSH code, for `project --cf` only | `GET /oauth/authorize` with your token, as `cf ssh-code` does | `project --cf` |
| Your app SSH proxy (`links.app_ssh` from the CF root) | the files of the app you picked, or of each app of the project you picked, for `project --cf` only | one new one-time code per app as SSH password; then SFTP listing and read requests only | `project --cf` |

Your CF token is sent to the CF API and its log cache only, and with `project --cf` also to the UAA authorize endpoint, which hands out the one-time SSH code (as `cf ssh-code` asks for it). The allow-list knows which credential each host may receive: the CF token for those, the OAuth client id and secret for the token endpoint (never the CF token), and nothing for any other host. The SSH proxy receives the one-time code as the SSH password, never the CF token. Unit tests check that no other host receives it, and that a credential a host may not receive is refused before anything is sent.

## What is kept

The snapshot and reports contain only allow-listed fields. The parsers drop everything else before it is stored.

- **Orgs and spaces:** GUID and name.
- **Apps:**
  - GUID, name, space, state, created and updated times, lifecycle type, and requested buildpacks.
  - Credentials in buildpack URLs are removed.
- **Current droplets:**
  - GUID, app, state, timestamps, stack, and the detected buildpack names and versions.
  - Detect output is cut to 200 characters.
  - For Docker droplets, the image reference with credentials removed.
- **Routes:** GUID, owning space, kind (`http`, `tcp`, `internal` or `unknown`) and the GUIDs of the destination apps, limited to the apps of the scanned inventory. Host, path, port and URL are not kept, nor annotations and labels. A destination that points to an app outside the inventory (possible with shared routes) is dropped, and a route with no destination left is not kept at all.
- **Web processes:** GUID, app, desired instance count, health check type and updated time. Never the start command.
- **App usage (`APP_IDLE`):** per app, a state (`idle`, `active`, `unknown` or `not_assessed`) with a signal and confidence, a reason code, or, for `active`, the time of the last request. All are fixed values except that one timestamp. The reports carry the same values: the Apps table, the `usage*` columns of the apps CSV and the JSON report.
- **Traffic history (`raw.history`):** per app, its GUID and its space's GUID, when the newest request any scan saw was written, when the current run of scans without a request began, and how many scans that run has. The list is in the snapshot only, but a `no_traffic` finding repeats these values (`scansWithoutTraffic`, `firstScanWithoutTraffic`, `silentSpanDays`, `lastRequestEverSeen`) in its evidence, so every report format carries them for that app. With `scan --previous`, the earlier snapshot is read from disk and validated, unknown fields are dropped, and only two things reach the new snapshot: these history values and the earlier scan's time (`options.previousScannedAt`, which the JSON and HTML reports carry too). An entry carries forward for an app still in the inventory, or unchanged for an app this scan could not see; it is dropped once a scan reads the app's space without the app. Nothing else of the earlier snapshot, such as its app names or findings, is carried.
- **Traffic (`raw.traffic`, snapshot only):** per app with an HTTP route, three values read from Log Cache: `lastRequestAt` (when the newest router access log was written, nothing about the request), `windowStart` (the oldest envelope Log Cache held for the app) and `envelopesExamined` (a count). A `no_traffic` finding repeats the window start and length in its evidence.
- **Findings:** rule id, severity, app reference, evidence (facts such as dates and versions), remediation and links.

## What is never kept

- **User identities:**
  - User names, emails and IDs are never stored.
  - Audit-event `actor` fields are dropped when the events are read.
  - App annotations and labels (which often hold owner emails) are not collected. The one exception is `project --cf`, which reads the six keys the deploy service writes to mark an app as part of a project and drops every other one (see [Deployed-app scans](#deployed-app-scans)).
- **Secrets:**
  - Tokens, refresh tokens and client secrets.
  - Environment variable **values**; with `--deep`, only variable names are kept.
  - Service credentials and service keys.
  - Droplet `execution_metadata` and start commands, and process commands (all of which can contain passwords).
- **Log lines.** The traffic check of `APP_IDLE` reads an app's log envelopes from Log Cache, and of each envelope it parses two things only: its timestamp and its `source_type` tag, which is checked for being `RTR` (and for being there at all) and then dropped. The access-log line (client address, request path and query, user agent, `X-Forwarded-For`, request id), the lines of every other log, every other tag (app, space and org names, addresses) and the instance are never parsed and never kept. Per app, only `lastRequestAt`, `windowStart` and `envelopesExamined` reach the snapshot. The same holds for the one envelope of any type read to find where the window starts, such as a router `http` timer whose tags carry the request's address, path and user agent. The leak test plants a client address, a request path, a query, a user agent and a request id in a router log (in its payload and in its tags) and in such a timer, plus app-log lines and tags on app logs, and fails if any of them reaches the snapshot, a report or what the scan prints while it runs.

A test scans the snapshot, every report format and the scan's progress output for planted secrets, emails, JWTs and credential URLs (`packages/cli/test/e2e/leak.test.ts`).

## Project scans

`baip-lens project --path <dir>` reads files of a local CAP or MTA project. It makes **no network request at all**, starts no child process and never runs `git`; the only outbound connection of such a scan is none. The allow-list of files it opens, and the files it never opens, are in [data-sources.md §8](data-sources.md#8-local-project-files-baip-lens-project).

What a project scan keeps:

- The relative file names of the recognised files it opened (`package.json`, `.cdsrc.json`, `.cdsrc.yaml`, `mta.yaml`, `xs-security.json`, `xs-app.json`, `*.cds`, seed `*.csv`, `*.html`, and the `.gitignore` files consulted for `*.mtar` archives), the names and sizes of `*.mtar` archives, and for unreadable files the name and a reason code.
- Identifiers: the project id (the MTA id, else the package name without its scope, else the folder name), package names and version ranges of dependencies (a non-registry range such as a git or file URL is replaced by `[non-registry]`), module, resource, service, plan and buildpack names from `mta.yaml` (a buildpack is kept only as a name or as an http(s)/git URL reduced to scheme, host and path; a local path is dropped), scope, role-template and attribute names from the security descriptor, route source patterns from `xs-app.json`, and service, entity, element, action and role names from the CDS model.
- Counts and booleans: how many mocked users exist and how many carry a password, whether `restrict_all_services` or `audit-log` is configured, which authentication kind is set (as an enum, unknown strings become `other`), whether a route sets `csrfProtection`, whether an archive is git-ignored (also by the `.gitignore` files between the repository root and the project root, which are read but never stored), whether a `.git` entry exists in the project root or one of its ancestors, how many files were opened, and for seed CSV files the number of rows checked and, per sensitive column, its position in the header and the number of values that match a card, IBAN or secret check.
- From HTML pages: the line of the SAPUI5 bootstrap and its `src` reduced to origin and path for an http(s) URL (user info, query and fragment are dropped) or to the file name for a relative one, whether it is external, whether an `integrity` attribute exists (never its value) and the version form.

What a project scan never keeps:

- File contents, comments or doc strings, CSV cell values and CSV headers (only the positions of the columns that matched a sensitive pattern are kept, never a name), element types, defaults, titles and every annotation other than the recognised `@requires`, `@restrict.to`, `@readonly`, `@protocol`, `@cds.external` and `@PersonalData` markers.
- Mocked user names, passwords, roles and attributes (`cds.requires.auth.users` is only counted), destination names (only a hint such as `api` or `ui5-cdn` is derived from them), `description` fields, `oauth2-configuration`, `authorities`, `xsappname`, service keys, `properties`, `hooks`, `build-parameters` and `provides` of `mta.yaml`, and `VCAP_SERVICES`-shaped data.
- Absolute paths: every stored path is relative to the project root, the real path of the root is never written, the log prints counts and the project id only, and a collector error becomes a reason code rather than a message that could carry a path or file content.
- URLs with credentials: user info is removed from buildpack URLs and bootstrap sources.
- Files that typically hold credentials are never opened: `.cdsrc-private.json`, `.cdsrc.js`, `default-env.json`, `.env*`, `*.mtaext`, `*-key.json`, `*.pem`, `*.key`, `*.http`, `manifest.json`, `*.md`, and everything under `node_modules`, `.git`, `gen`, `dist`, `target`, `build`, `coverage` or any dot-directory.

The acme-incidents fixture plants a poison value in every one of those places, and `packages/cli/test/e2e/project.test.ts` fails if any of them, an absolute path or the temporary folder name reaches the snapshot, a report or the terminal.

## Deployed-app scans

`baip-lens project --cf` applies the project scan above to a deployed app, or to every app of a deployed MTA project: the same files are opened (and the same ones never are), the same values are kept, and the same ones never are. The difference is where the files come from: they are read live from one running instance of each app over SSH, with the SFTP file channel and read requests only ([data-sources.md §10](data-sources.md#10-deployed-apps-baip-lens-project---cf) and [§11](data-sources.md#11-deployed-mta-projects-project---cf-picker)).

- **Nothing is downloaded to disk.** File contents are held in memory until the parsers have reduced them to names and counts; only the snapshot and the reports are written.
- **The one-time SSH code** is used once as the password and never printed or stored; each app of a project gets a new one. Your CF token goes to the CF API and to the UAA authorize endpoint only; `project --cf` does not read Log Cache.
- **The paths are relative** to the app folder (`/home/vcap/app`), as for a local project; the container path is never written to a report, and no reason of a skipped check names it.
- **Which app it was.** Per app read, the snapshot keeps the app name and, when the app was deployed as part of an MTA project, the MTA ID, version, module name and namespace (`raw.projects[].deployment`). The reports name the app by its project id: the app name, or an id derived from it when the name has characters an id cannot have.
- **Labels and annotations.** Of each app in the list, only six keys are read: the labels `mta_id` and `mta_namespace` and the annotations `mta_id`, `mta_version`, `mta_namespace` and `mta_module`. Every other label and annotation is dropped when the list is parsed, and a value is used only when it matches a strict pattern (identifiers, no free text), because anyone who may update an app can write these values. A test plants an e-mail address in another annotation and fails if it reaches the terminal, the snapshot or a report.
- **The app list** shown in the terminal (app and project names, and why some apps cannot be read) is not written anywhere, with one exception: when you read a project, each of its apps that was not read is recorded as a skipped check, with the app name in its title and a fixed reason (for example that it is stopped), so that the report says what it does not cover. The reason repeats no name and no cf command: the space name and the advice on what to do (`cf start <app>`, `cf allow-space-ssh <space>`) stay in the terminal.

## Side effects in your landscape

`GET` requests do not change anything. Two kinds of read are audited by Cloud Foundry:

- With `--deep`, reading an app's environment variables creates an `audit.app.environment_variables.show` event for that app.
- `project --cf` opens an SSH session to the app you pick, or one session to each readable app of the project you pick, one after the other. Cloud Foundry records each as `audit.app.ssh-authorized` (a refused login as `audit.app.ssh-unauthorized`, which BAIP Lens avoids by checking your role first, and by stopping a project run when the first login is refused instead of trying every app).

Tell your security team before you run `--deep` or `project --cf` scans.

Reading Log Cache creates no audit event, but it is not free: for each app, Log Cache asks Cloud Controller, with your token, whether you may read the app (`GET /v3/apps/<guid>`), which counts once per app against your CF API rate limit.

## User-level usage (v0.2)

Usage per user is not collected in v0.1. When it arrives in v0.2, it will be opt-in. User identifiers will be hashed with a random salt created for each scan and never stored, and only aggregated counts will be reported.

## Retention

Snapshots and reports are ordinary files in your `--out` folder. Delete them when you no longer need them. BAIP Lens keeps no other copy.
