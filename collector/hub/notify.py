"""Notification channels: SMTP email and Microsoft Teams (Workflows webhook, Adaptive Card).

Routing: every route whose `match` fits the alert contributes its recipients (union, de-duplicated).
In dry_run mode nothing leaves the box; .eml / .json files are written to outbox_dir instead.
"""
from __future__ import annotations

import fnmatch
import html
import json
import logging
import os
import queue
import smtplib
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from . import config as cfgmod

log = logging.getLogger("hub.notify")

KIND_LABEL = {"firing": "FIRING", "resolved": "RESOLVED", "escalation": "ESCALATION", "severity_change": "SEVERITY CHANGED",
              "reminder": "REMINDER"}
SEV_COLOR = {"critical": "attention", "warning": "warning", "info": "accent"}
SEV_HEX = {"critical": "#C62828", "warning": "#B26A00", "info": "#1565C0"}


def _fmt_ts(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "-"


def hook_label(hook: str) -> str:
    """What the notification log may show for a Teams target. A webhook URL is itself a credential,
    so only its host is kept; an environment-variable name is shown as is."""
    if "://" in hook:
        return f"{urllib.parse.urlsplit(hook).hostname or 'webhook'}/... (URL hidden)"
    return hook


def route_matches(match: dict, alert: dict, kind: str) -> bool:
    if not match:
        return True
    if match.get("severity") and alert["severity"] not in match["severity"]:
        return False
    if match.get("environment") and (alert.get("environment") or "") not in match["environment"]:
        return False
    if match.get("server") and not fnmatch.fnmatch(alert["server"], match["server"]):
        return False
    if match.get("rule") and not any(fnmatch.fnmatch(alert["rule_id"], p) for p in match["rule"]):
        return False
    if match.get("kinds") and kind not in match["kinds"]:
        return False
    return True


class Notifier:
    def __init__(self, cfg: dict, store):
        self.cfg = cfg["notifications"]
        self.store = store
        self.q: "queue.Queue" = queue.Queue(maxsize=1000)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name="notifier")
        if self.cfg.get("dry_run") and self.cfg.get("outbox_dir"):
            os.makedirs(self.cfg["outbox_dir"], exist_ok=True)

    def start(self):
        self.thread.start()

    def submit(self, kind: str, alert: dict):
        try:
            self.q.put_nowait((kind, dict(alert)))
        except queue.Full:
            log.error("notification queue full - dropping %s for alert %s", kind, alert.get("id"))

    # -- worker ---------------------------------------------------------------
    def _run(self):
        while not self.stop.is_set():
            try:
                kind, alert = self.q.get(timeout=1)
            except queue.Empty:
                continue
            try:
                self._dispatch(kind, alert)
            except Exception:  # noqa: BLE001
                log.exception("dispatch failed")

    def recipients(self, alert, kind):
        email, teams = [], []
        for r in self.cfg.get("routes", []):
            if route_matches(r.get("match", {}), alert, kind):
                email += [x for x in r.get("email", []) if x not in email]
                teams += [x for x in r.get("teams", []) if x not in teams]
        return email, teams

    def _dispatch(self, kind, alert):
        email_to, teams_hooks = self.recipients(alert, kind)
        e_cfg, t_cfg = self.cfg.get("email", {}), self.cfg.get("teams", {})
        if e_cfg.get("enabled") and email_to:
            self._with_retry(alert, kind, "email", ",".join(email_to), lambda: self._send_email(alert, kind, email_to, e_cfg))
        for hook in teams_hooks if t_cfg.get("enabled") else []:
            self._with_retry(alert, kind, "teams", hook_label(hook), lambda h=hook: self._send_teams(alert, kind, h, t_cfg))

    def _with_retry(self, alert, kind, channel, target, fn, attempts=3):
        last = ""
        for i in range(attempts):
            try:
                detail = fn()
                self.store.record_notification(alert["id"], kind, channel, target, "dry-run" if self.cfg.get("dry_run") else "sent", detail or "")
                return
            except Exception as exc:  # noqa: BLE001
                last = f"{type(exc).__name__}: {exc}"
                log.warning("%s notification attempt %d/%d failed: %s", channel, i + 1, attempts, last)
                time.sleep(2 ** i)
        self.store.record_notification(alert["id"], kind, channel, target, "failed", last)

    # -- content ----------------------------------------------------------------
    def _link(self, alert):
        base = (self.cfg.get("dashboard_url") or "").rstrip("/")
        return f"{base}/#/alerts/{alert['id']}" if base else ""

    def subject(self, alert, kind):
        tag = KIND_LABEL.get(kind, kind.upper())
        return f"[{tag}][{alert['severity'].upper()}][{alert.get('environment') or '-'}] {alert['server']} - {alert['title']}"[:240]

    def facts(self, alert):
        return [("Server", alert["server"]), ("Environment", alert.get("environment") or "-"), ("Severity", alert["severity"]),
                ("Rule", f"{alert['rule_name']} ({alert['rule_id']})"), ("First seen", _fmt_ts(alert["first_seen"])),
                ("Last seen", _fmt_ts(alert["last_seen"])), ("Alert id", str(alert["id"]))]

    def _send_email(self, alert, kind, to, e):
        msg = EmailMessage()
        msg["Subject"] = self.subject(alert, kind)
        msg["From"] = e.get("from", "wm-hub@localhost")
        msg["To"] = ", ".join(to)
        msg["Date"] = formatdate(localtime=False)
        thread_id = f"<wmhub-alert-{alert['id']}@{(e.get('from', 'wm-hub@localhost').split('@')[-1])}>"
        if kind == "firing":  # later mails for the same alert reply to this one, so mail clients thread them
            msg["Message-ID"] = thread_id
        else:
            msg["Message-ID"] = make_msgid(domain="wm-hub")
            msg["In-Reply-To"] = thread_id
            msg["References"] = thread_id
        facts = self.facts(alert)
        link = self._link(alert)
        text = [self.subject(alert, kind), "", alert["title"], ""] + [f"{k}: {v}" for k, v in facts]
        text += ["", (alert.get("detail") or "")[:3000]]
        if alert.get("runbook"):
            text += ["", f"Runbook: {alert['runbook']}"]
        if link:
            text += ["", f"Open in the Hub: {link}"]
        msg.set_content("\n".join(text))
        rows = "".join(f"<tr><td style='padding:2px 12px 2px 0;color:#555'>{html.escape(k)}</td><td>{html.escape(v)}</td></tr>" for k, v in facts)
        color = SEV_HEX.get(alert["severity"], "#444")
        body = (f"<div style='font-family:Segoe UI,Arial,sans-serif;font-size:14px'>"
                f"<div style='border-left:5px solid {color};padding:4px 12px'><b>{html.escape(KIND_LABEL.get(kind, kind))}</b> - "
                f"{html.escape(alert['title'])}</div><table style='margin:12px 0'>{rows}</table>"
                f"<pre style='background:#f4f4f4;padding:8px;white-space:pre-wrap'>{html.escape((alert.get('detail') or '')[:3000])}</pre>"
                + (f"<p><a href='{html.escape(alert['runbook'])}'>Runbook</a></p>" if alert.get("runbook") else "")
                + (f"<p><a href='{html.escape(link)}'>Open in the Hub</a></p>" if link else "") + "</div>")
        msg.add_alternative(body, subtype="html")
        if self.cfg.get("dry_run"):
            path = os.path.join(self.cfg["outbox_dir"], f"{int(time.time() * 1000)}_alert{alert['id']}_{kind}.eml")
            with open(path, "wb") as fh:
                fh.write(bytes(msg))
            return os.path.basename(path)
        host, port = e["smtp_host"], int(e.get("smtp_port", 587))
        mode = e.get("security", "starttls")  # starttls | ssl | none
        if mode == "ssl":
            smtp = smtplib.SMTP_SSL(host, port, timeout=20, context=ssl.create_default_context())
        else:
            smtp = smtplib.SMTP(host, port, timeout=20)
        with smtp:
            smtp.ehlo()
            if mode == "starttls":
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
            user = e.get("username")
            if user:
                smtp.login(user, cfgmod.secret(e, "password"))
            smtp.send_message(msg)
        return ""

    def teams_payload(self, alert, kind):
        label = KIND_LABEL.get(kind, kind.upper())
        link = self._link(alert)
        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
            "body": [
                {"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": True,
                 "color": "Good" if kind == "resolved" else SEV_COLOR.get(alert["severity"], "Default").capitalize(),
                 "text": f"{label}: {alert['title']}"},
                {"type": "FactSet", "facts": [{"title": k, "value": v} for k, v in self.facts(alert)]},
                {"type": "TextBlock", "wrap": True, "isSubtle": True, "fontType": "Monospace",
                 "text": (alert.get("detail") or "")[:1200] or "-"},
            ],
            "actions": ([{"type": "Action.OpenUrl", "title": "Open in the Hub", "url": link}] if link else [])
            + ([{"type": "Action.OpenUrl", "title": "Runbook", "url": alert["runbook"]}] if alert.get("runbook") else []),
        }
        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None, "content": card}]}

    def _send_teams(self, alert, kind, hook, t):
        payload = self.teams_payload(alert, kind)
        if self.cfg.get("dry_run"):
            path = os.path.join(self.cfg["outbox_dir"], f"{int(time.time() * 1000)}_alert{alert['id']}_{kind}_teams.json")
            with open(path, "w") as fh:
                json.dump(payload, fh, indent=2)
            return os.path.basename(path)
        url = os.environ.get(hook) or (hook if hook.startswith("https://") else "")  # a route may hold an env-var name or a URL
        if not url:
            raise RuntimeError(f"Teams webhook '{hook_label(hook)}' is not an https URL and no such environment variable is set")
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            if r.status not in (200, 202):
                raise RuntimeError(f"Teams webhook returned HTTP {r.status}")
        return ""
