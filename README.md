# webMethods Observability Hub (prototype)

An Optimize-style monitoring console for a fleet of webMethods servers that the dashboard **cannot reach**.
A small agent on each host reads the product's log files, host metrics and a health probe, and pushes
them **outbound over HTTPS** to one collector. The collector stores everything, evaluates alert rules and
notifies by **email** and **Microsoft Teams**.

```
 webMethods host (isolated)                     central
 ┌───────────────────────────┐   HTTPS POST   ┌──────────────────────────────────────────────┐
 │ server.log, wrapper.log … │   (outbound    │ collector  ─►  SQLite store ─► alert engine  │─► SMTP
 │        │                  │    only)       │     ▲                              │         │─► Teams webhook
 │  wm_agent.py ── spool ────┼───────────────►│     │                              ▼         │
 │  (tail, parse, redact)    │  gzip + token  │  dashboard (browser)          alerts, ack,   │
 └───────────────────────────┘                │                               maintenance    │
                                              └──────────────────────────────────────────────┘
```

Full design: see the *webMethods Observability Hub — High-Level Design* document delivered with this package.
How this build maps to that design, item by item: [docs/GAP_CHECKLIST.md](docs/GAP_CHECKLIST.md).

> **Prototype.** This is not production-ready. See [Known limits](#known-limits-of-the-prototype) and the
> production gaps in the checklist before using it anywhere but a lab.

## Try it in two minutes

Requires Python 3.9+ on one machine. No packages to install.

```bash
python sim/run_demo.py                      # collector + the 75-host estate from the server list
# open http://127.0.0.1:8080
python sim/run_demo.py --run-seconds 180    # stops by itself; useful for a scripted check
```

The simulated estate follows `sim/inventory.demo.json` (generated from Server List.xlsx, with host names
replaced by placeholders; a real list saved as `sim/inventory.local.json` is used instead when present and
is gitignored): six landscapes
(Dev, Test, PROD, CN1, PSS, DR) with their clusters. Five hosts run a real agent and carry the scenario; the
other hosts send light simulated heartbeats through the same ingest API and per-host tokens (pass
`--all-real-agents` to run a real agent everywhere, about 20 MB of memory each). One DR host never reports,
so you can see the "No data" state. The demo injects an error burst, an out-of-memory event, a log rotation,
a dead agent, a failing probe and the PROD /wMShared NAS filling to 91% (one alert, not one per server).
Simulated hosts report the file systems of a real Dev IS host: the local /opt* and /var* mounts plus the
/wMNfs and /wMShared NAS mounts.
Watch alerts fire, escalate and resolve. Emails and Teams cards are written to `<run folder>/data/outbox`
(dry-run mode) instead of being sent.

**The demo never deletes anything.** Each run creates a new folder `./demo_runs/<timestamp>` (relative to
where you start it) holding the database, agent spools and outbox. `--dir <folder>` names the folder
instead, and the demo stops with a message if that folder already exists. Remove old run folders yourself
when you no longer need them. Every demo service listens on 127.0.0.1 only, each simulated server gets
its own agent token, and the dashboard is anonymous only because it is loopback-bound.

Run the tests (66, about 20 seconds): `python -m unittest discover -s tests -v`

## What is in the box

| Path | What it is |
|---|---|
| `agent/wm_agent.py` | The agent. One file, standard library only, Python 3.8+. |
| `agent/agent.example.json` | Annotated sample configuration. |
| `agent/deploy/wm-agent.service` | Hardened systemd unit. |
| `collector/run_collector.py`, `collector/hub/` | Collector: ingest API, store, alert engine, notifiers, dashboard API. |
| `collector/web/index.html` | The dashboard (one file, no external libraries). |
| `collector/rules.json` | The default alert catalogue (21 rules). Edit and commit it; it hot-reloads. |
| `collector/collector.example.json` | Sample collector configuration with email and Teams routing. |
| `collector/Dockerfile`, `collector/deploy/wm-hub.service` | Container image and systemd unit. |
| `sim/` | Simulated estate and the one-command demo. |
| `tests/` | Unit tests: agent parsing, redaction, rotation and restart; alert engine; real SMTP and webhook delivery against local sinks. |

## Health check view: landscapes, clusters and shared storage

The overview page is a health check: every landscape with its clusters and a status per node, a
**Needs attention** list (down, critical, warning and listed-but-silent hosts, plus full NAS shares), and
**Shared storage**, where a NAS share mounted on many servers is shown and alerted once instead of on
every server. **Problems only** hides everything healthy, the page refreshes every minute, and
**Export CSV** downloads `api/report.csv` (add `?problems=1` for problems only; the dashboard login applies).

Grouping comes from a server list on the collector, not from each agent, so a host that is listed but
never reported still shows up. Create it from the team's spreadsheet and point `inventory_file` in
collector.json at it (it reloads when the file changes):

```bash
python collector/import_inventory.py "Server List.xlsx" -o collector/inventory.json \
       --shared "PROD wMNfs=/wMNfs@PROD" --shared "PROD wMShared=/wMShared@PROD"   # one per NAS share and landscape
```

The importer reads the current layout (landscape rows, then role / host rows; standard library only). The
spreadsheet has no cluster column, so clusters are derived from role names (Broker1 + Broker2 -> Broker,
PRD_UM1..3 -> UM); put an explicit cluster in column C to override, and review the generated JSON. Servers
are matched by server name or host name, with or without the domain. A shared path is recognised by the
agent's `disk_used_pct:<path>` metric. Which file systems an agent measures is set by `disk_mounts`:
mount-point patterns matched against the host's mount table, by default in the example
`["/opt*", "/var*", "/wMNfs", "/wMShared"]`; `/`, tmpfs and other pseudo file systems are skipped, and a
NAS that stops answering is reported as unreadable after 5 s instead of stalling the agent. Two checks matter
for each file system: **is it mounted** (`mount_present:<path>`, rule WM-018, critical when a listed mount
point such as /wMNfs is missing or a volume seen earlier disappears) and **is it under 75% used** (rule
WM-008: 75% and above is a warning, 90% and above critical). The /opt* file systems have per-landscape
limits: 90% for Dev (CON, CN1) in WM-019, 85% for UAT (Test, PSS) in WM-020, and 75% for PROD, DR and any other
landscape in WM-021. A rule's `scope.environment` matches the landscape in the server list as well as the
environment the agent reports; the dashboard judges each disk against the same limit as the alerts. Without a
server list, servers are grouped by the environment their agent reports.

## Deploying for real

### 1. Collector

```bash
cd collector
cp collector.example.json /etc/wm-hub/collector.json     # edit listen, tls, routes
python run_collector.py --new-agent-token IS-PRD-01      # prints a token once + the config entry to paste
python run_collector.py --hash-password                  # for dashboard users
python run_collector.py --config /etc/wm-hub/collector.json --check-config   # tokens scoped? dashboard protected?
python run_collector.py --config /etc/wm-hub/collector.json --check-rules
python run_collector.py --config /etc/wm-hub/collector.json
```

* The collector listens on `127.0.0.1` unless `listen.host` says otherwise. It **refuses to start** with an
  anonymous dashboard (`ui_auth.mode: none`) on any non-loopback address; set `ui_auth.mode` to `basic`
  and add users. (An `insecure_allow_anonymous_remote` override exists for isolated labs only and logs a warning.)
* Every `agents` entry must list the `servers` its token may report as; an entry without that list is rejected.

* Set `tls.cert` / `tls.key`, or terminate TLS at a reverse proxy. Without either, the collector warns and serves plain HTTP.
* Tokens are stored only as SHA-256 hashes. Each token lists the server names it may report as (`"servers": ["IS-PRD-*"]`).
* Secrets stay out of the file: `password_env` for SMTP, and Teams routes may name an environment variable that holds the webhook URL.
* Notifications stay in dry-run (`.eml`/`.json` files in the outbox) until you set `notifications.dry_run`
  to `false`. Test routes against a test mailbox and Teams channel first.
* Teams webhook URLs are credentials: name an environment variable in the route. If a route holds a URL
  directly, the notification log shows only its host.
* `sqlite_synchronous` is `NORMAL` (the design's choice) or `FULL`; see "Points where this build departs
  from the design" below.

### 2. Agent (per webMethods host)

```bash
python wm_agent.py --config agent.json --check                       # files found? collector reachable? token accepted?
python wm_agent.py --config agent.json --dry-run --once --from-beginning   # shows exactly how YOUR logs parse
WM_AGENT_TOKEN=wmh_... python wm_agent.py --config agent.json        # run it
```

* Linux: copy `agent/deploy/wm-agent.service`, create the `wmagent` user, give it read access to the logs, put the token in `/etc/wm-agent/agent.env`.
* Windows: run it as a service with NSSM (`nssm install WmHubAgent python.exe "C:\wm-agent\wm_agent.py --config C:\wm-agent\agent.json"`, then `nssm set WmHubAgent AppEnvironmentExtra WM_AGENT_TOKEN=...`) or as a Task Scheduler task at start-up. The Windows path has not been exercised in this prototype.
* **Validate the log patterns first.** The built-in profiles (`is_server`, `wrapper`, `generic`) are starting points based on the documented Integration Server layout `time_stamp time-zone [product_code.logging_facility.message_number.log_level] message_text` (the level is one letter: C, E, W, I, D or T; the profile accepts it with or without the dot before it). Use `--dry-run` against real files from each product version and add your own profile under `"profiles"` where needed.

### Agent behaviour worth knowing

* **First start** reads from the end of each file (`first_run: "end"`); use `"beginning"` to backfill history.
* **At-least-once delivery.** Batches are written to a local spool before offsets advance, and each event has a deterministic id, so the collector drops duplicates after a crash or retry. Checked in this build: a collector outage with agent restarts (automated test), a hard agent kill followed by a restart and a live rename rotation on Windows (demo run: 13,220 simulated lines, none missing, none duplicated), and copy-truncate rotation (unit test only).
* **Spool cap** (`spool_max_mb`, default 200): during a very long outage the oldest batches are discarded and counted in the `agent_events_dropped` metric, which has an alert rule.
* **Redaction happens on the host.** Passwords, tokens, bearer/basic credentials and Luhn-valid card numbers are masked before anything is sent. Add patterns under `"redact"`.
* **Volume control.** Every source ships all levels by default. Add `"min_level": "WARN"` to a source in `agent.json` to send only warnings and above; this is the biggest lever on storage and alert-engine cost for informational logs.
* **Rejected batches.** A batch the collector refuses as malformed (400/413/415/422) is moved to
  `<spool_dir>/rejected` so it cannot block the queue. Its count is reported as `agent_batches_rejected`
  and rule WM-017 raises a warning, so the loss is visible rather than silent.
* **Windows hosts.** Memory use is read through `GlobalMemoryStatusEx`; Windows has no load average, so
  `load_per_cpu` (and rule WM-012) does not apply there. `Ctrl-C`/service stop on Windows ends the process
  without the 10-second final flush; the spool and saved offsets make the next start deliver the rest.
* **Extra metrics.** Any script can write a flat `{"name": number}` JSON file; point `extra_metrics_file` at it and the values ride along with every heartbeat and can be alerted on.

## Alert rules

`collector/rules.json` ships with these types; each rule can have `scope` (environment, server glob, tags), `levels` (warning then critical), `repeat_s`, `escalate_after_s`, `runbook`, and a `title` template.

| Type | Fires when |
|---|---|
| `event_count` | at least N matching events in a window, grouped per server, per error pattern, or fleet-wide |
| `metric_threshold` | a heartbeat metric crosses a threshold, optionally for a sustained period |
| `heartbeat_missing` | an agent stops reporting |
| `new_error` | an error pattern is seen for the first time anywhere in the fleet |

Alerts are de-duplicated (one open alert per rule and key), can be acknowledged from the dashboard, and resolve automatically when the condition stays clear. Servers in a **maintenance window** are not evaluated and send nothing.

## Security model in one paragraph

Agents only make outbound HTTPS calls and authenticate with a per-agent bearer token that is limited to the server names it owns. The collector stores token hashes, caps request and decompressed sizes, validates every field, and sends security headers. Dashboard users sign in with HTTP Basic (PBKDF2-hashed passwords) in the prototype; state-changing calls also require a custom header as CSRF protection.

**Before any shared use:** `ui_auth.mode` defaults to `none` (anonymous), so set it to `basic` and add users. When `tls.client_ca` is set the collector verifies a client certificate if one is presented but does not require one; enforce mutual TLS at a reverse proxy if you need it. There are no per-user roles and no per-agent rate limit. For production put SSO (OIDC/SAML) in front; see the design document.

## Points where this build departs from the design

These are deliberate and worth a decision by whoever owns the design:

1. **Anonymous dashboard.** The design says the default UI mode is no authentication. Combined with the
   old default listen address `0.0.0.0`, that exposed an unauthenticated dashboard (logs, acknowledge,
   maintenance) on every interface. This build defaults to `127.0.0.1` and refuses `mode: none` on other
   addresses.
2. **Token scope default.** An `agents` entry without `servers` used to mean "may report as any server",
   which undoes the per-host token principle. It now means "no server", and configuration validation
   rejects it.
3. **Durability setting.** The design keeps `synchronous=NORMAL`. Since the agent deletes a batch once the
   collector acknowledges it, a host power loss can lose acknowledged events with no replay. That conflicts
   with the "no silent loss" goal, so I would choose `FULL` once its ingest cost has been measured. The
   setting is now configurable; the default is unchanged.
4. **Rule WM-017** (agent quarantined batches) is added to the 16-rule catalogue so rejected batches are
   not silently lost.
5. **Manual resolve** of an alert whose condition still holds is followed by a new alert at the next
   evaluation (about 15 s). That is consistent with "one alert per problem" but may surprise operators;
   acknowledging is the right action for a problem that is still present.

## Known limits of the prototype

* SQLite is a single-node store. The storage layer is isolated in `hub/store.py` so PostgreSQL/TimescaleDB or OpenSearch can replace it.
* The collector is a single process; it is not highly available as shipped.
* Figures from the original prototype run (one machine, synthetic data; **not re-measured in this build**, so treat them as environment-specific estimates): about 20,000 events/s ingest into a small store and 6,700 events/s into a store holding 2 million events; about 260 bytes per event on disk; overview page about 40 ms at 2 million events. Free-text search of a rare word scans the table (about 4 s at 2 million events), and message-matching alert rules read every event in their window (an evaluation took about 1.4 s at 500 events/s fleet-wide and about 4 s at 2,000 events/s). Plan for roughly 500 events/s as the upper end for this build; the design document has the sizing table and the production path.
* The Dockerfile and systemd units have not been run in the environment where the prototype was built.
* Only log files, host metrics and probes are collected. Business-process analytics and the Integration Server audit database are on the roadmap, not in this build.
* Log paths and line layouts must be confirmed against your installed product versions.
* The dashboard re-sorts tables on its 5-second refresh, so a row can move under the pointer just as you
  click a button; switch off auto-refresh while working through a list.
* Production gaps: single sign-on and access roles, enforced mutual TLS, per-agent rate limits and token
  expiry, encryption at rest, high availability, and an independent security review are not done.
* The Windows agent ran here only as a plain process in the demo (no NSSM or Task Scheduler service). Email and Teams delivery are unit-tested against local SMTP and HTTP sinks (payload shape, routing, retry, failure logging); STARTTLS/authentication against Office 365 and the live Teams Workflows endpoint still need a test in your tenant.
