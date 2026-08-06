"""Common CVE finding shape and source interface."""
from __future__ import annotations

import abc
from dataclasses import dataclass


@dataclass(frozen=True)
class CVEFinding:
    """A single CVE affecting the watched project, normalised across all sources."""

    cve_id: str
    source: str
    summary: str = ""
    severity: str | None = None
    affected_component: str | None = None
    url: str | None = None
    fix_versions: tuple[str, ...] = ()  # Every release tag that shipped a fix, including LTS backports.


class CVESource(abc.ABC):
    """Common interface every CVE feed implements, so the pipeline can treat them uniformly."""

    name: str

    @abc.abstractmethod
    def collect(self) -> list[CVEFinding]:
        """Return all currently known findings from this source."""
        raise NotImplementedError
