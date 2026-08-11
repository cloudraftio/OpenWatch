"""Notifier interface and the shared Digest payload."""
from __future__ import annotations

import abc
from dataclasses import dataclass, field

from ..changelog.base import ChangelogSummary
from ..cve.base import CVEFinding
from ..lts import LTSEntry
from ..risk import ClientDigest


@dataclass
class Digest:
    """Everything a notification pass might report."""

    repo: str = ""  # The watched "owner/name", so a channel can say which project it's reporting on.
    new_releases: list[str] = field(default_factory=list)
    batched_cves: list[CVEFinding] = field(default_factory=list)
    lts_eol_reminders: list[LTSEntry] = field(default_factory=list)
    latest_stable: str | None = None
    latest_lts_patch: str | None = None
    changelogs: list[ChangelogSummary] = field(default_factory=list)  # Parallel to new_releases.
    client_digests: list[ClientDigest] = field(default_factory=list)  # Empty in broadcast mode.


class Notifier(abc.ABC):
    """A delivery channel: send_urgent for immediate single items, send_digest for the batch."""

    @abc.abstractmethod
    def send_digest(self, digest: Digest) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def send_urgent(self, finding: CVEFinding) -> None:
        raise NotImplementedError

    def send_client_digest(self, client_digest: ClientDigest) -> None:
        """Deliver one client's targeted risk report; no-op for channels that only broadcast."""
