"""LTS lifecycle tracking, parsed from a project's "List of LTS releases" markdown table.

Prometheus publishes one in prometheus/docs; most projects publish none at all, so
fetching is best-effort and an absent table simply means no LTS tracking.
"""
from __future__ import annotations

import enum
import logging
import re
from dataclasses import dataclass
from datetime import date, datetime

import requests

logger = logging.getLogger(__name__)

RAW_DOCS_URL = "https://raw.githubusercontent.com/{repo}/{branch}/{path}"
DOC_BRANCHES = ("main", "master")  # Tried in order; projects differ on the default branch name.

_SECTION_HEADING = re.compile(r"^##\s+List of LTS releases", re.IGNORECASE)
_ROW_RE = re.compile(
    r"^\|\s*(?P<release>.+?)\s*\|\s*(?P<date>.+?)\s*\|\s*(?P<eos>.+?)\s*\|\s*(?P<status>.+?)\s*\|\s*$"
)
_RELEASE_VERSION_RE = re.compile(r"(\d+)\.(\d+)")


class LTSStatus(enum.Enum):
    SUPPORTED = "supported"
    END_OF_LIFE = "end of life"
    UPCOMING = "upcoming"


@dataclass(frozen=True)
class LTSEntry:
    label: str
    branch: tuple[int, int] | None  # None for not-yet-numbered rows, e.g. "TBD".
    release_date: date | None
    end_of_support: date | None
    status: LTSStatus


def _strip_markdown(text: str) -> str:
    return text.replace("**", "").strip()


def _parse_date(text: str) -> date | None:
    text = _strip_markdown(text)
    for fmt in ("%Y-%m-%d", "%Y-%m"):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def _parse_status(text: str) -> LTSStatus:
    text = _strip_markdown(text).lower()
    for status in LTSStatus:
        if status.value in text:
            return status
    raise ValueError(f"Unrecognised LTS status: {text!r}")


def parse_lts_table(markdown_text: str) -> list[LTSEntry]:
    """Parse the "List of LTS releases" table out of the release-cycle doc page."""
    lines = markdown_text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if _SECTION_HEADING.match(line.strip()):
            start = i
            break
    if start is None:
        raise ValueError('Could not find a "List of LTS releases" section in the given document.')

    entries: list[LTSEntry] = []
    header_seen = False
    for line in lines[start + 1 :]:
        stripped = line.strip()
        if stripped.startswith("##"):
            break  # Next section.
        match = _ROW_RE.match(stripped)
        if not match:
            continue
        release_cell = _strip_markdown(match.group("release"))

        if set(release_cell) <= {"-", ":"}:
            continue  # Markdown table separator row, e.g. |---|---|.
        if not header_seen:
            header_seen = True
            if release_cell.lower() == "release":
                continue  # Header row.

        version_match = _RELEASE_VERSION_RE.search(release_cell)
        branch = (int(version_match.group(1)), int(version_match.group(2))) if version_match else None

        entries.append(
            LTSEntry(
                label=release_cell,
                branch=branch,
                release_date=_parse_date(match.group("date")),
                end_of_support=_parse_date(match.group("eos")),
                status=_parse_status(match.group("status")),
            )
        )
    return entries


def fetch_lts_table(repo: str | None, path: str | None) -> list[LTSEntry]:
    """Fetch and parse a project's LTS lifecycle table from its docs repo.

    Best-effort by design: a project with no table, a moved file, or a network blip
    returns an empty list and logs why, rather than failing the whole run.
    """
    if not repo or not path:
        return []
    last_error: Exception | None = None
    for branch in DOC_BRANCHES:
        url = RAW_DOCS_URL.format(repo=repo, branch=branch, path=path)
        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 404:
                last_error = FileNotFoundError(url)
                continue  # Try the other default-branch name before giving up.
            response.raise_for_status()
            return parse_lts_table(response.text)
        except ValueError as exc:  # Document fetched, but it has no LTS section.
            logger.info("No LTS table in %s: %s", url, exc)
            return []
        except requests.RequestException as exc:
            last_error = exc
    logger.info("No LTS lifecycle data for %s (%s); continuing without it.", repo, last_error)
    return []


def active_lts_branches(entries: list[LTSEntry]) -> list[LTSEntry]:
    """All currently-supported LTS branches (there can be more than one during a handover)."""
    return [e for e in entries if e.status == LTSStatus.SUPPORTED and e.branch is not None]


def latest_lts_branch(entries: list[LTSEntry]) -> LTSEntry | None:
    """The newest currently-supported LTS branch; use active_lts_branches() for all of them."""
    active = active_lts_branches(entries)
    if not active:
        return None
    return max(active, key=lambda e: e.branch)


def eol_reminders(entries: list[LTSEntry], today: date, days_before: int = 90) -> list[LTSEntry]:
    """LTS branches whose end-of-support falls within `days_before` days of `today`."""
    due = []
    for entry in entries:
        if entry.status != LTSStatus.SUPPORTED or entry.end_of_support is None:
            continue
        days_left = (entry.end_of_support - today).days
        if 0 <= days_left <= days_before:
            due.append(entry)
    return due
