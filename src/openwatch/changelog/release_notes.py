"""Deterministic changelog parsing - exact string parsing, no LLM/search API needed."""
from __future__ import annotations

import re

from .base import CATEGORIES, HIGHLIGHT_CATEGORIES, ChangelogEntry, ChangelogParser, ChangelogSummary

_BULLET_RE = re.compile(
    r"^\s*[-*]\s*\[(?P<category>" + "|".join(CATEGORIES) + r")\]\s*(?P<text>.+)$",
    re.IGNORECASE,
)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)
_GO_VULN_RE = re.compile(r"GO-\d{4}-\d{4,}", re.IGNORECASE)
_PR_RE = re.compile(r"#(\d+)")

# --- Fallback parsing, for projects that don't tag their bullets ---
_PLAIN_BULLET_RE = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+(?P<text>.+)$")
_SECURITY_HINT_RE = re.compile(
    r"\b(security|vulnerabilit(?:y|ies)|CVE-|GHSA-|XSS|CSRF|SSRF|RCE|"
    r"privilege escalation|denial of service|path traversal)\b",
    re.IGNORECASE,
)
MAX_FALLBACK_ENTRIES = 50  # Keeps an untagged 500-line changelog from swamping the digest.


def _unique(matches: list[str], upper: bool = True) -> list[str]:
    seen: list[str] = []
    for match in matches:
        value = match.upper() if upper else match
        if value not in seen:
            seen.append(value)
    return seen


def _fallback_entries(raw_body: str) -> list[tuple[str, list[str]]]:
    """Categorise plain, untagged bullets by keyword - used for projects outside the
    Prometheus convention, where every bullet would otherwise be dropped.

    Only the SECURITY verdict matters downstream (it drives the CVE mapping), so
    everything else is filed as CHANGE rather than guessed at.
    """
    entries: list[tuple[str, list[str]]] = []
    for line in raw_body.splitlines():
        match = _PLAIN_BULLET_RE.match(line)
        if not match:
            continue
        text = match.group("text").strip()
        if not text:
            continue
        category = "SECURITY" if _SECURITY_HINT_RE.search(text) else "CHANGE"
        entries.append((category, [text]))
        if len(entries) >= MAX_FALLBACK_ENTRIES:
            break
    return entries


class ReleaseNotesParser(ChangelogParser):
    """Parses categorised release-note bullets, folding wrapped continuation lines.

    Prometheus-style `* [SECURITY] ...` bullets are parsed exactly; a body with none
    falls back to keyword categorisation so any project produces a usable summary.
    """

    def parse(self, tag: str, raw_body: str) -> ChangelogSummary:
        raw_entries: list[tuple[str, list[str]]] = []
        for line in raw_body.splitlines():
            match = _BULLET_RE.match(line)
            if match:
                raw_entries.append((match.group("category").upper(), [match.group("text").strip()]))
                continue
            # Fold wrapped continuation lines into the entry above.
            if raw_entries and line.strip() and line[:1].isspace():
                raw_entries[-1][1].append(line.strip())

        if not raw_entries:
            raw_entries = _fallback_entries(raw_body)

        entries = []
        for category, parts in raw_entries:
            text = " ".join(parts).strip()
            pr_match = _PR_RE.search(text)
            entries.append(
                ChangelogEntry(
                    category=category,
                    text=text,
                    cve_ids=_unique(_CVE_RE.findall(text)),
                    ghsa_ids=_unique(_GHSA_RE.findall(text)),
                    go_ids=_unique(_GO_VULN_RE.findall(text)),
                    pr_number=int(pr_match.group(1)) if pr_match else None,
                )
            )

        return ChangelogSummary(
            tag=tag,
            highlights=[e.text for e in entries if e.category in HIGHLIGHT_CATEGORIES],
            security_fixes=[e.text for e in entries if e.category == "SECURITY"],
            entries=entries,
        )
