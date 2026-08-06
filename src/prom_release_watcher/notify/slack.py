"""Slack notifier - STUB (needs an incoming webhook URL)."""
from __future__ import annotations

from ..cve.base import CVEFinding
from .base import Digest, Notifier


class SlackNotifier(Notifier):
    """NOT IMPLEMENTED: would POST to a Slack incoming webhook."""

    name = "slack"

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send_digest(self, digest: Digest) -> None:
        raise NotImplementedError("SlackNotifier is a stub.")

    def send_urgent(self, finding: CVEFinding) -> None:
        raise NotImplementedError("SlackNotifier is a stub.")
