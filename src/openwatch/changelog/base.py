"""Changelog parser interface."""
from __future__ import annotations

import abc
from dataclasses import dataclass, field

# Categories Prometheus-style release notes tag every bullet with; other projects
# are handled by the keyword fallback in changelog/release_notes.py.
CATEGORIES = ("FEATURE", "ENHANCEMENT", "PERF", "BUGFIX", "SECURITY", "CHANGE")

# Non-security categories, batched into the digest instead of pushed immediately.
HIGHLIGHT_CATEGORIES = ("FEATURE", "ENHANCEMENT", "PERF", "CHANGE", "BUGFIX")


@dataclass(frozen=True)
class ChangelogEntry:
    """A single categorised bullet from a release's changelog."""

    category: str
    text: str
    cve_ids: list[str] = field(default_factory=list)
    ghsa_ids: list[str] = field(default_factory=list)
    go_ids: list[str] = field(default_factory=list)  # GO-YYYY-NNNN, also used by govulncheck.
    pr_number: int | None = None


@dataclass(frozen=True)
class ChangelogSummary:
    tag: str
    highlights: list[str]
    security_fixes: list[str]
    entries: list[ChangelogEntry] = field(default_factory=list)


class ChangelogParser(abc.ABC):
    """Turns a raw GitHub release body into a structured summary."""

    @abc.abstractmethod
    def parse(self, tag: str, raw_body: str) -> ChangelogSummary:
        raise NotImplementedError
