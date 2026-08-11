"""Priority scoring: turn "N CVEs" into "these three, today".

The model is deliberately three independent questions rather than one blended number,
because they fail differently and a single score hides which one fired:

  1. How bad is it?        severity / CVSS base score
  2. Is it being used?     CISA KEV, then EPSS probability
  3. Can it reach us?      CVSS attack vector, and whether this client's version is affected

A blended 0-100 would let a high severity quietly outvote "not exploitable from the
network", which is exactly the judgement call a human needs to see.
"""
from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field

from .risk import Exposure

SEVERITY_RANK = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1}

# Thresholds. EPSS is a probability, so 0.1 means "1 in 10 chance of exploitation
# in the next 30 days" - high for a metric whose median sits near 0.0005.
EPSS_ACTIVE = 0.10
EPSS_NOTABLE = 0.01

_VECTOR_RE = re.compile(r"\b(AV|AC|PR|UI):([NLHAPR])\b")


class Priority(enum.IntEnum):
    """Ordered so sorting puts the most urgent first."""

    ACT_NOW = 1
    PATCH_SOON = 2
    SCHEDULE = 3
    REVIEW = 4  # Exposure could not be established; needs a human.
    INFORMATIONAL = 5

    @property
    def label(self) -> str:
        return {
            Priority.ACT_NOW: "act now",
            Priority.PATCH_SOON: "patch soon",
            Priority.SCHEDULE: "schedule",
            Priority.REVIEW: "review",
            Priority.INFORMATIONAL: "informational",
        }[self]


@dataclass
class Assessment:
    """A priority verdict plus the specific signals that produced it."""

    priority: Priority
    reasons: list[str] = field(default_factory=list)
    severity: str | None = None
    cvss_score: float | None = None
    kev: bool = False
    epss: float | None = None
    remotely_exploitable: bool = False

    @property
    def summary(self) -> str:
        return "; ".join(self.reasons) if self.reasons else "no exploitation signals available"


def parse_vector(vector: str | None) -> dict[str, str]:
    """Pull the exploitability metrics out of a CVSS vector string."""
    return dict(_VECTOR_RE.findall(vector or ""))


def is_remotely_exploitable(vector: str | None) -> bool:
    """Network-reachable, no credentials, no user interaction - the pre-auth RCE shape.

    Absent a vector this is False, which keeps an unscored CVE out of ACT_NOW rather
    than assuming the worst and drowning the list.
    """
    metrics = parse_vector(vector)
    if not metrics:
        return False
    return metrics.get("AV") == "N" and metrics.get("PR") == "N" and metrics.get("UI") == "N"


def assess(finding, exposure: Exposure = Exposure.AFFECTED) -> Assessment:
    """Rank one finding for one client, given whether their version is actually affected."""
    severity = (finding.severity or "").lower() or None
    rank = SEVERITY_RANK.get(severity or "", 0)
    remote = is_remotely_exploitable(finding.cvss_vector)
    result = Assessment(
        priority=Priority.SCHEDULE,
        severity=severity,
        cvss_score=finding.cvss_score,
        kev=bool(finding.kev),
        epss=finding.epss,
        remotely_exploitable=remote,
    )

    if severity:
        score = f" (CVSS {finding.cvss_score})" if finding.cvss_score else ""
        result.reasons.append(f"{severity}{score}")
    if finding.kev:
        result.reasons.append("listed in CISA KEV - exploited in the wild")
    if finding.epss is not None and finding.epss >= EPSS_NOTABLE:
        result.reasons.append(f"EPSS {finding.epss:.1%} chance of exploitation in 30 days")
    if remote:
        result.reasons.append("network-reachable with no credentials or user interaction")

    # Exposure gates everything: an unaffected version doesn't become urgent because
    # the CVE is famous, and an unresolved one is a question, not a verdict.
    if exposure is Exposure.NOT_AFFECTED:
        result.priority = Priority.INFORMATIONAL
        return result
    if exposure is Exposure.UNKNOWN:
        result.priority = Priority.REVIEW
        return result

    active = finding.kev or (finding.epss is not None and finding.epss >= EPSS_ACTIVE)
    if active or (rank >= 3 and remote):
        result.priority = Priority.ACT_NOW
    elif rank >= 3 or (finding.epss is not None and finding.epss >= EPSS_NOTABLE):
        result.priority = Priority.PATCH_SOON
    else:
        result.priority = Priority.SCHEDULE
    return result
