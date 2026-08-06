"""Whole-body CVE regex scanner, catching mentions outside categorised bullets."""
from __future__ import annotations

import re
from dataclasses import dataclass

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass(frozen=True)
class CVEMention:
    cve_id: str
    release_tag: str


def extract_cve_ids(text: str) -> list[str]:
    """Pull every CVE identifier mentioned in a block of text, deduplicated and upper-cased."""
    seen: list[str] = []
    for match in _CVE_RE.findall(text):
        normalised = match.upper()
        if normalised not in seen:
            seen.append(normalised)
    return seen


def extract_from_releases(releases) -> list[CVEMention]:
    """Scan every release's changelog body for CVE mentions."""
    mentions = []
    for release in releases:
        for cve_id in extract_cve_ids(release.body):
            mentions.append(CVEMention(cve_id=cve_id, release_tag=release.tag))
    return mentions
