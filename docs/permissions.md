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
| `collect.project` and the same thirteen rules, on a deployed app | the app's files, read over SSH with read-only SFTP (`baip-lens project --cf`), see [data-sources.md §10](data-sources.md#10-deployed-apps-baip-lens-project---cf) | **Space Developer** | on, for `project --cf` only |

## `baip-lens project`

A project scan reads a local CAP or MTA project directory and needs **no Cloud Foundry role and no BTP login**: it makes no network request. It only needs read permission on the project files; a file it cannot read is recorded as unreadable with a reason code, and the scan continues. The output folder (`--out`) is skipped by the file walk, so a report written into the project is never scanned.

## `baip-lens project --cf`

Reading a **deployed** app needs the **Space Developer** role in its space. Cloud Foundry lets a user open an SSH session to an app only when the user may update it, so Space Auditor and Space Supporter are not enough. BAIP Lens checks your roles (`GET /v3/roles`, your own roles only) before any SSH attempt, because a refused SSH login is recorded as a failed attempt. Without Space Developer it stops and connects to nothing:

- if you are a **Space Manager** of the space or an **Org Manager** of the org, it offers to give you the role: after a yes it runs `cf set-space-role <you> <org> <space> SpaceDeveloper` with your cf CLI;
- otherwise it prints that command for a manager to run.

The SSH session itself only **reads**: it opens the SFTP file channel and nothing else (no shell, no command, no port forwarding), sends only listing and read requests and opens files read-only. Cloud Foundry still records every session as an `audit.app.ssh-authorized` event; tell your security team before you scan production spaces.

SSH must also be on, for the platform, the space and the app:

- **for one app**, BAIP Lens can turn it on, but only after a yes at the terminal (or `--enable-ssh` in a script). It then runs, with your cf CLI and its current target: `cf enable-ssh <app>`, `cf restart <app> --strategy rolling` (Cloud Foundry starts the new instances before stopping the old ones, and runs the app's start command again), and after the scan, whether it succeeded or not, `cf disable-ssh <app>`, which takes effect at once without a restart (the SSH proxy asks Cloud Controller at every login whether SSH is on). It refuses to run them when the cf CLI targets another org or space than the scan, so they can never act on another app of the same name;
- for a space: `cf allow-space-ssh <space>` (Space Manager), shown in the app list;
- for the whole platform: only its operator can.

These are the only cf commands BAIP Lens can run (`packages/cli/src/remote/cfCli.ts` refuses any other command line before it starts the cf CLI); its own HTTP client sends nothing but `GET`.

To ask for the role:

> Hi, could you give my user **<your e-mail>** the **Space Developer** role on the space **<space name>** in the Cloud Foundry org **<org name>**? I need it to run a read-only check of the deployed app **<app name>** with BAIP Lens (open source, https://github.com/sebastianomarchesini/BAIP-Lens). It opens a read-only file session like `cf ssh`. Thank you!

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
