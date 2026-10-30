# Requirements-to-code gap checklist

Compares the *webMethods Observability Hub — High-Level Design* (29 Oct 2026) with this repository.
Status: **OK** = implemented and covered by a test or the demo run; **Fixed** = gap closed in this
change; **Open** = still missing (production work or out of scope). Verified on Windows 11 with
Python 3.14 and 3.12; Python 3.8/3.9 compatibility was checked by parsing with the 3.8/3.9 grammar
and avoiding newer APIs, not by running those interpreters.

## Agent (`agent/wm_agent.py`)

| Requirement (HLD) | Status | Where / evidence |
|---|---|---|
| One file, standard library only, Python 3.8+ | OK, **Fixed** (version guard) | `main()` refuses < 3.8 |
| Config-driven sources: glob + parser profile; profiles overridable | OK | `BUILTIN_PROFILES`, `"profiles"` in config |
| `is_server`, `wrapper`, `generic` profiles; IS level letters C/E/W/I/D/T | OK | `test_agent.Parsing` |
| Time zones (GMT±hh:mm, UTC, offsets, abbreviation table, `default_tz`); events leave in UTC | OK | `test_timezone_forms`, `test_documented_sample_line` |
| Multi-line events joined; 3 s timeout; commit offset = start of pending event | OK | `test_stack_trace_is_one_event`, `test_pending_event_is_not_committed_until_complete` |
| Rename and copy-truncate rotation; restart mid-rotation | OK | `test_agent.Rotation`; demo rotates IS-PRD-01 live on Windows |
| Spool write (tmp, fsync, rename) **before** offsets saved | OK | `Agent.run`, `test_http.AgentOutage` |
| Stable event ids (agent, source, inode, offset) | OK | `test_event_ids_are_stable_across_reads` |
| Redaction on host before spool (key=value, JSON, Bearer/Basic, Luhn cards, custom) | OK | `test_secrets_are_masked_before_leaving_the_host`; outage test checks the store |
| 200 delete / 4xx quarantine / 401-403 retry / other retry with backoff, jitter, Retry-After | OK | `_sender_loop`; `test_rejected_batch_is_quarantined_and_counted` |
| Quarantined batches visible, not silent | **Fixed** | new metric `agent_batches_rejected` + rule WM-017 |
| Spool cap 200 MB, oldest dropped, `agent_events_dropped` | OK | `Spool._enforce_cap`; rule WM-015 |
| Heartbeat every 30 s: host metrics, log health, probes, custom metrics, own health | OK | `Agent.metrics` |
| Memory metric on Windows | **Fixed** | `_windows_memory()` (ctypes). Load average has no Windows equivalent and is not reported there |
| `--check`, `--dry-run --once --from-beginning` | OK | CLI |
| Graceful-stop flush (10 s) | OK on Linux | On Windows `terminate()` is a hard kill; replay covers it (demo drain step) |
| Outage: spool, restart, replay, no loss or duplicates | OK | `test_outage_then_recovery_loses_and_duplicates_nothing`; demo verification |

## Collector ingest and storage (`collector/hub/server.py`, `store.py`)

| Requirement | Status | Where / evidence |
|---|---|---|
| Python 3.9+, standard library only | OK, **Fixed** (version guard) | `run_collector.py` |
| `POST /api/v1/ingest`, bearer token, gzip | OK | `test_http.Ingest` |
| Unsupported `Content-Encoding` → 415 | **Fixed** | `test_malformed_and_oversized_requests` |
| `GET /healthz` without auth | OK | `test_healthz_needs_no_auth` |
| Limits: 8 MB body, 4× decompressed (413), 5,000 events, 4,000/12,000 chars | OK, **Fixed** (limits now config values) | `test_malformed_and_oversized_requests`, `test_long_fields_are_cut` |
| Non-object body, bad heartbeat, bad Content-Length, bad query params → 4xx not 500 | **Fixed** | same tests; `test_bad_query_parameters_are_400_not_500` |
| Event id format validated | **Fixed** | `EID_RX` |
| Token-to-server authorization | **Fixed** | a token entry without `servers` used to default to `*` (report as anyone); now reports as nobody and config validation rejects it. `test_auth_and_token_to_server_scoping` |
| Duplicate events ignored (`INSERT OR IGNORE` on eid) | OK | `test_gzip_batch_is_stored_with_event_time_and_duplicates_ignored` |
| Event time in UTC, separate from receive time; >1 day future clamped | OK | same test, `test_far_future_event_time_is_clamped_to_arrival` |
| Clock-skew metric from heartbeat | OK | `test_heartbeat_metrics_and_clock_skew`; rule WM-016 |
| SQLite WAL, parameterised SQL only | OK | `Store.conn`; all SQL in `store.py` |
| `synchronous` durability choice | **Fixed** (configurable `sqlite_synchronous`, default NORMAL as designed) | see "Disagreements" in the README |
| Retention purge by event time | OK, **Fixed** (first purge 60 s after start instead of 1 h) | `Hub._janitor`, `test_recurring_error_is_not_renewed_by_retention_purge` |
| Error fingerprints, per-minute rollups | OK | `test_fingerprint_ignores_ids_and_numbers`, rollup tests |
| Store releases its files on close (Windows) | **Fixed** | `Store.close()`; baseline tests failed on Windows without it |

## Alerts and notifications (`alerts.py`, `notify.py`, `rules.json`)

| Requirement | Status | Where / evidence |
|---|---|---|
| Four rule types, scope, levels, title templates, runbook | OK | `rules.json`, `test_collector.Engine_` |
| 16 shipped rules (WM-001…016) | OK + WM-017 added | `--check-rules`: 17 OK |
| One alert per rule+key; escalation in place; ack stops reminders; auto-resolve; reminders; time escalation | OK | `test_severity_levels_escalate_in_place_and_dedupe`, `test_auto_resolve_after_condition_clears`; demo |
| Maintenance suppression | OK | `test_heartbeat_missing_and_maintenance_suppression` |
| Hot reload; bad rule dropped and named; bad file keeps previous rules | OK | `Engine.load_rules` |
| Email (text+HTML, threading headers, STARTTLS/SSL/none, password from env) | OK | `test_email_and_teams_are_really_sent_and_routed` (local SMTP sink) |
| Teams Adaptive Card; route names env var or URL | OK | same test (local HTTP sink) |
| Webhook URL not written to the notification log | **Fixed** | `hook_label()`, `test_teams_webhook_url_is_not_logged` |
| 3 retries, every attempt recorded | OK | `test_failed_delivery_is_recorded_not_raised` |
| Dry-run writes .eml / .json to outbox | OK | demo outbox |
| Dry-run by default in examples | **Fixed** | `collector.example.json` had `dry_run: false` |

## Dashboard (`collector/web/index.html`)

| Requirement | Status | Evidence |
|---|---|---|
| Overview, server, alerts (+detail, ack/reopen/resolve), events, rules (+error banner), maintenance, notifications | OK | demo run in a browser |
| No external assets; CSP, nosniff, frame deny, no-referrer, no-store | OK | `test_security_headers_on_the_dashboard_page` |
| Basic auth with PBKDF2; CSRF header on changes; audit table | OK | `test_basic_auth_csrf_header_and_audit` |
| Unauthenticated dashboard never on a non-loopback interface | **Fixed** | default listen is now 127.0.0.1; startup refuses `ui_auth.mode=none` on other addresses unless `insecure_allow_anonymous_remote` is set on purpose (`--check-config`, `ConfigGuards`) |
| Request socket timeout | **Fixed** | `Handler.timeout = 30` |

## Demo and simulator (`sim/`)

| Requirement | Status | Evidence |
|---|---|---|
| Demo never deletes; fresh folder by default; refuses an existing folder | **Fixed** (was `shutil.rmtree(--dir)`) | `test_http.DemoSafety` |
| Loopback only | OK | collector, probes and agents bind/target 127.0.0.1 |
| One token per simulated server | **Fixed** (was one `*` token) | `run_demo.py` |
| Rotation scenario works on Windows | **Fixed** (write lock + rename retry) | demo run |
| End-of-run drain via agent restart; loss/duplicate check | **Fixed** | `simulate.py drain()`; verification script result in the README |

## Open (production work, not in this prototype)

SSO (OIDC/SAML) and access roles; enforced mutual TLS (verify-if-offered only); per-agent rate limits
and token expiry/rotation tooling; encryption at rest (spool and SQLite rely on file permissions and
disk encryption); high availability (single process, single SQLite file); independent security review
and penetration test; Windows service packaging (NSSM/Task Scheduler not exercised); Dockerfile and
systemd units not built or run; real Office 365 SMTP and Teams Workflows endpoints not tested;
log paths and layouts not validated against real installations. Out of scope by design:
business-process analytics, payload inspection, IS audit-database reading, automated remediation.
