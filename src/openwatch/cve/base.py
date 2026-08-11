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
    severity: str | None = None  # low | moderate | high | critical, as published upstream.
    affected_component: str | None = None
    url: str | None = None
    fix_versions: tuple[str, ...] = ()  # Every release tag that shipped a fix, including LTS backports.
    cvss_score: float | None = None
    cvss_vector: str | None = None  # e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
    kev: bool = False  # Listed in CISA's Known Exploited Vulnerabilities catalogue.
    epss: float | None = None  # Probability of exploitation in the next 30 days (0-1).

    def merge(self, other: "CVEFinding") -> "CVEFinding":
        """Combine two sources' views of the same CVE, preferring whichever knows more."""
        return CVEFinding(
            cve_id=self.cve_id,
            source=f"{self.source}+{other.source}" if other.source not in self.source else self.source,
            summary=self.summary or other.summary,
            severity=self.severity or other.severity,
            affected_component=self.affected_component or other.affected_component,
            url=self.url or other.url,
            fix_versions=tuple(dict.fromkeys(self.fix_versions + other.fix_versions)),
            cvss_score=self.cvss_score if self.cvss_score is not None else other.cvss_score,
            cvss_vector=self.cvss_vector or other.cvss_vector,
            kev=self.kev or other.kev,
            epss=self.epss if self.epss is not None else other.epss,
        )


class CVESource(abc.ABC):
    """Common interface every CVE feed implements, so the pipeline can treat them uniformly."""

    name: str

    @abc.abstractmethod
    def collect(self) -> list[CVEFinding]:
        """Return all currently known findings from this source."""
        raise NotImplementedError
