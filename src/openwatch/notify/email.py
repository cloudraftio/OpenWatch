"""Email notifier - STUB (needs SMTP credentials)."""
from __future__ import annotations

from ..cve.base import CVEFinding
from .base import Digest, Notifier


class EmailNotifier(Notifier):
    """NOT IMPLEMENTED: would send the digest over SMTP via smtplib."""

    name = "email"

    def __init__(self, host: str, port: int, username: str, password: str, recipients: list[str]):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.recipients = recipients

    def send_digest(self, digest: Digest) -> None:
        raise NotImplementedError("EmailNotifier is a stub.")

    def send_urgent(self, finding: CVEFinding) -> None:
        raise NotImplementedError("EmailNotifier is a stub.")
