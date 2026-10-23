"""Slack notifier - posts the client exposure report to an incoming webhook.

Incoming webhooks can post messages but not upload files, so the report goes out as a
Block Kit summary of the same FleetReport the markdown/HTML renderers use.
"""
from __future__ import annotations

import logging

import requests

from ..cve.base import CVEFinding
from ..report import FleetReport
from .base import Digest, Notifier

logger = logging.getLogger(__name__)

# Slack rejects messages over 50 blocks or with section text over 3000 characters.
MAX_CLIENTS = 20
MAX_RISKS_PER_CLIENT = 5
MAX_INDEX_ROWS = 10

STATUS_EMOJI = {
    "act now": ":rotating_light:",
    "action needed": ":warning:",
    "review": ":mag:",
    "clear": ":white_check_mark:",
    "below filter": ":white_check_mark:",
    "unknown": ":grey_question:",
}


def _esc(value) -> str:
    """Escape the three characters Slack mrkdwn treats as control syntax."""
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _section(text: str) -> dict:
    return {"type": "section", "text": {"type": "mrkdwn", "text": text[:3000]}}


def render_report_blocks(report: FleetReport) -> list[dict]:
    """The report as Block Kit blocks, capped to stay inside Slack's message limits."""
    stamp = report.generated_at.strftime("%Y-%m-%d %H:%M UTC")
    meta = f"Generated {stamp} | latest stable *{_esc(report.latest_stable or 'unknown')}*"
    if report.latest_lts_patch:
        meta += f" | latest LTS patch *{_esc(report.latest_lts_patch)}*"
    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"Client exposure report - {report.repo}"[:150]}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": meta}]},
        _section(
            f"{len(report.clients)} client(s) checked against {report.total_cves} CVE(s). "
            f"*{report.act_now_total}* need acting on now; "
            f"*{report.clients_needing_action}* client(s) affected in total."
        ),
        {"type": "divider"},
    ]

    for entry in report.clients[:MAX_CLIENTS]:
        emoji = STATUS_EMOJI.get(entry.status, "")
        running = entry.client.raw_version or "not recorded"
        lines = [f"{emoji} *{_esc(entry.client.name)}* - {_esc(running)} - _{entry.status}_"]
        verdict = f"{entry.cleared} CVE(s) ruled out"
        if entry.affected:
            verdict += f", {len(entry.affected)} affected"
        if entry.unknown:
            verdict += f", {len(entry.unknown)} need review"
        if entry.filtered:
            verdict += f", {entry.filtered} below the priority filter"
        if entry.upgrade_to:
            verdict += f". Upgrade to *{_esc(entry.upgrade_to)}* clears {entry.upgrade_clears} of {len(entry.affected)}"
        lines.append(verdict + ".")
        for item in entry.affected[:MAX_RISKS_PER_CLIENT]:
            fix = f" -> {_esc(item.recommended_version)}" if item.recommended_version else ""
            lines.append(f"• `{item.priority.label.upper()}` *{_esc(item.cve_id)}*{fix} - {_esc(item.assessment.summary)}")
        if len(entry.affected) > MAX_RISKS_PER_CLIENT:
            lines.append(f"• +{len(entry.affected) - MAX_RISKS_PER_CLIENT} more affected")
        for item in entry.unknown[:MAX_RISKS_PER_CLIENT]:
            lines.append(f"• `REVIEW` *{_esc(item.cve_id)}* - {_esc(item.assessment.summary)}")
        if len(entry.unknown) > MAX_RISKS_PER_CLIENT:
            lines.append(f"• +{len(entry.unknown) - MAX_RISKS_PER_CLIENT} more to review")
        blocks.append(_section("\n".join(lines)))
    if len(report.clients) > MAX_CLIENTS:
        blocks.append(_section(f"+{len(report.clients) - MAX_CLIENTS} more client(s) - see the full report."))

    index = report.cve_index
    if index:
        rows = [
            f"• *{_esc(cve)}* - {len(names)} client(s), fixed in {_esc(', '.join(fixes) or '-')}"
            for cve, names, fixes in index[:MAX_INDEX_ROWS]
        ]
        if len(index) > MAX_INDEX_ROWS:
            rows.append(f"• +{len(index) - MAX_INDEX_ROWS} more")
        blocks += [{"type": "divider"}, _section("*CVEs by blast radius*\n" + "\n".join(rows))]
    return blocks


class SlackNotifier(Notifier):
    """Posts to a Slack incoming webhook. Only the fleet report is implemented so far."""

    name = "slack"

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send_report(self, report: FleetReport) -> None:
        """Post the fleet report; raises requests.RequestException if Slack refuses it."""
        payload = {
            # Fallback text for notifications and clients that can't render blocks.
            "text": f"Client exposure report - {report.repo}: {report.act_now_total} to act on now, "
            f"{report.clients_needing_action} client(s) affected",
            "blocks": render_report_blocks(report),
        }
        response = requests.post(self.webhook_url, json=payload, timeout=30)
        response.raise_for_status()
        logger.info("Posted the %s report to Slack", report.repo)

    def send_digest(self, digest: Digest) -> None:
        raise NotImplementedError("SlackNotifier only delivers reports so far.")

    def send_urgent(self, finding: CVEFinding) -> None:
        raise NotImplementedError("SlackNotifier only delivers reports so far.")
