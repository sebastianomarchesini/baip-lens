# Permissions

BAIP Lens follows least privilege. Every check declares which Cloud Foundry roles are enough to run it, and any one of the listed roles works. The roles come from the Cloud Controller v3 docs (see [data-sources.md](data-sources.md) §2).

## Recommended setup

Give the scanning user **Space Auditor** in every space you want to scan:

```sh
cf set-space-role scanner@example.com my-org my-space SpaceAuditor
```

Space Auditor can read apps, droplets, processes, routes and service binding *metadata*. It cannot read environment variables or service credentials, and it cannot change anything.

## Asking for the role

Most people who want to run BAIP Lens cannot grant themselves a role. Copy this to your administrator (the person who manages your subaccount or Cloud Foundry org):

> Hi, could you give my user **<your e-mail>** the **Space Auditor** role on the spaces **<space names>** in the Cloud Foundry org **<org name>**? Space Auditor is read-only: it lets me see apps and their settings, but not change anything, read credentials or restart anything. I need it to run a read-only health report (BAIP Lens, an open-source tool, https://github.com/sebastianomarchesini/BAIP-Lens). Thank you!

In the BTP cockpit the administrator does this under **Cloud Foundry Environment → Spaces → <space> → Members → Add Members**, choosing the **Space Auditor** role. With the cf CLI: `cf set-space-role <your e-mail> <org> <space> SpaceAuditor`.

## Roles per check

| Check id | What it reads | Roles | Default |
| --- | --- | --- | --- |
| `collect.apps` | `GET /v3/apps` | Space Auditor | on |
| `collect.droplets` | `GET /v3/droplets?current=true` | Space Auditor | on |
| `rule.APP_NO_RECENT_DEPLOY` | droplets (above) | Space Auditor | on |
| `collect.routes` | `GET /v3/routes?space_guids=…&include=domain` (destinations and the domain's `internal` flag only) | Space Auditor | on |
| `collect.processes` | `GET /v3/processes?types=web` (instances and health check type only) | Space Auditor | on |
| `collect.traffic` | Log Cache `GET /api/v1/read/<app-guid>` for apps with an HTTP route: router log timestamps only | Space Auditor (Log Cache asks Cloud Controller whether you may read the app) | on; `--no-traffic-check` turns it off |
| `rule.APP_IDLE` | apps, droplets, routes, processes and traffic (above) | Space Auditor | on |
| planned: stacks, buildpacks, binding metadata | `GET /v3/...` | Space Auditor | on |
| planned: audit events | `GET /v3/audit_events` | Space Auditor or Org Auditor | on |
| planned: app usage events | `GET /v3/app_usage_events` | not documented for BTP; skipped on 403 | on |
| planned: `ENV_SECRET_PLAINTEXT` | `GET /v3/apps/:guid/environment_variables` (names only) | Space Developer or Space Supporter | `--deep` |
| `collect.project` and the thirteen `rule.CAP_*`, `rule.XSUAA_*`, `rule.APPROUTER_*`, `rule.DEPLOY_*`, `rule.SEED_*`, `rule.UI5_BOOTSTRAP_*` checks | local project files (`baip-lens project --path <dir>`), see [data-sources.md §8](data-sources.md#8-local-project-files-baip-lens-project) | **no CF role**: no login, no network | on, for `project` only |
| `collect.project` and the same thirteen rules, on a deployed app or on every app of a deployed MTA project (an app of a project that was not read is the skipped check `collect.project.<project id>`) | the apps' files, read over SSH with read-only SFTP (`baip-lens project --cf`), see [data-sources.md §10](data-sources.md#10-deployed-apps-baip-lens-project---cf) and [§11](data-sources.md#11-deployed-mta-projects-project---cf-picker) | **Space Developer** | on, for `project --cf` only |
| `collect.dependencies`, `collect.osv` and the rules `rule.DEP_KNOWN_CVE`, `rule.DEP_LOCKFILE_MISSING`, `rule.DEP_NOT_CHECKED` | the npm lockfiles of the project or of the deployed app, and a lookup of the public packages they pin on `api.osv.dev` (`POST /v1/querybatch`, `GET /v1/vulns/<id>`; no credential), see [data-sources.md §12](data-sources.md#12-npm-dependencies-known-vulnerabilities-and-deprecations) | **no CF role** for the lookup; the lockfiles are read like the other files of the scan (no role with `--path`, Space Developer with `--cf`) | on, for `project`; `--no-dependency-check` turns the lookup off |

## `baip-lens project`

A project scan reads a local CAP or MTA project directory and needs **no Cloud Foundry role and no BTP login**. Its only network requests go to `api.osv.dev`, without any credential: the names and versions of the project's public npm packages are looked up for known vulnerabilities, and `--no-dependency-check` turns that off ([privacy.md](privacy.md#project-scans)). It only needs read permission on the project files; a file it cannot read is recorded as unreadable with a reason code, and the scan continues. The output folder (`--out`) is skipped by the file walk, so a report written into the project is never scanned.

## `baip-lens project --cf`

Reading a **deployed** app needs the **Space Developer** role in its space. Cloud Foundry lets a user open an SSH session to an app only when the user may update it, so Space Auditor and Space Supporter are not enough. BAIP Lens says so before it starts, and it checks your roles (`GET /v3/roles`, your own space roles only) before any SSH attempt: without Space Developer it stops with this message and connects to nothing, because a refused SSH login is recorded as a failed attempt.

Even with that role, BAIP Lens only **reads**: it opens the SFTP file channel and nothing else (no shell, no command, no port forwarding), sends only listing and read requests, opens files read-only, and never changes, restarts or restages the app. Cloud Foundry still records every session as an `audit.app.ssh-authorized` event; tell your security team before you scan production spaces.

**Reading a project.** The app list groups the apps of the space by the MTA project they were deployed from (read from the labels and annotations the deploy service writes; no extra request and no extra role). Choosing a project, or naming it with `--mta <id>`, reads every readable app of it: **one SSH session per app**, one after the other, so Cloud Foundry records one `audit.app.ssh-authorized` event per app. The command says how many sessions it will open before the first one, and one run reads at most 50 apps. An app of the project that cannot be read (stopped, SSH off, no project files, a refused session) is recorded in the report as a skipped check with its reason, and the other apps are still read. If the very first SSH login is refused, the run stops there: it does not try the other apps, so a missing role costs one refused attempt, not one per app. `--app <name>` reads one app only, as before.

SSH must also be on, for the platform, the space and the app. BAIP Lens never turns it on; the app list shows the command for each app it cannot read:

- for one app: `cf enable-ssh <app>`, then `cf restart <app>` (Space Developer);
- for a space: `cf allow-space-ssh <space>` (Space Manager);
- for the whole platform: only its operator can.

To ask for the role:

> Hi, could you give my user **<your e-mail>** the **Space Developer** role on the space **<space name>** in the Cloud Foundry org **<org name>**? I need it to run a read-only check of the deployed app **<app name>** with BAIP Lens (open source, https://github.com/sebastianomarchesini/BAIP-Lens). It opens a read-only file session like `cf ssh` and changes nothing. Thank you!

When the role is not possible, scan the project folder instead: `baip-lens project --path <dir>` needs no role at all.

**Not used at all:** `GET /v3/apps/:guid/env` (it returns service credentials) and `GET /v3/service_credential_bindings/:guid/details`.

## `--deep`

Reading environment variables needs **Space Developer** or **Space Supporter**. Space Supporter is the narrower of the two: it cannot push apps or manage services. It is still **not read-only**, though, because it can restart and scale apps. Use `--deep` only when you accept giving the scanning user that access, and consider a separate, short-lived user for it.

## When a role is missing

- The v3 **list** endpoints BAIP Lens uses (`/v3/spaces`, `/v3/apps`, `/v3/droplets`, `/v3/routes`, `/v3/processes`) do not answer 403 to a user without a space role: they return only what the user may see, which can be nothing. BAIP Lens therefore stops with exit code 2 and the text to send to your administrator when the org is visible but none of its spaces is. The number of visible spaces is printed while the scan runs and the spaces are listed in the snapshot (`raw.spaces`).
- A call that returns **403** records the check as `skipped` with reason `insufficient role: needs <roles>`, and the scan continues.
- **Log Cache never answers 403.** A missing role, an expired token and a failed permission lookup all come back as **404**, so a 404 on the first app records `collect.traffic` as skipped (`insufficient_role`) with a reason that names all three; no answer records it as `unavailable`. Either way the rest of the scan, and the no-route and stopped signals of `APP_IDLE`, stand. Without the app inventory, the routes or the processes (a 403 or an error there), the traffic check does not run at all (`dependency_skipped`), since those decide which apps to read.
- `scan --previous` reads an earlier snapshot from disk: it needs no role and sends nothing itself. A file that is not a valid snapshot, a project scan, a snapshot of another API endpoint or one that is not older stops the scan with exit code 2 before any request. A snapshot of another org stops it with exit code 2 right after the org lookup (the CF root, a token request when one is needed, and `GET /v3/organizations`), before anything about spaces or apps is read.
- Rules that depend on a skipped collector are skipped too.
- Skipped checks appear in every report: on the HTML overview, in the JSON `checks`, and as SARIF notifications. Missing data is therefore never mistaken for "no findings".
- Only a **401** after a token refresh, or a configuration error, stops the scan (exit code 2).
