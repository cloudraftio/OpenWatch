"""Per-repository knowledge that cannot be discovered from the GitHub API.

Everything the watcher needs is read from the repo's releases, except the LTS
lifecycle table - projects that publish one put it in an arbitrary markdown
file in an arbitrary docs repo. Repos without an entry here still work; they
simply run without LTS tracking.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

DEFAULT_REPO = "prometheus/prometheus"


@dataclass(frozen=True)
class RepoProfile:
    """Optional extras known about one upstream project."""

    repo: str
    lts_docs_repo: str | None = None
    lts_doc_path: str | None = None

    @property
    def has_lts_source(self) -> bool:
        return bool(self.lts_docs_repo and self.lts_doc_path)

    @property
    def slug(self) -> str:
        """Filesystem-safe form of the repo name, e.g. "grafana-grafana"."""
        return self.repo.replace("/", "-")


# Keyed by lowercased "owner/name". Add an entry for any project that publishes
# a "List of LTS releases" markdown table; anything else needs no entry.
PROFILES: dict[str, RepoProfile] = {
    DEFAULT_REPO: RepoProfile(
        repo=DEFAULT_REPO,
        lts_docs_repo="prometheus/docs",
        lts_doc_path="docs/introduction/release-cycle.md",
    ),
}


def normalise_repo(value: str) -> str:
    """Accept a GitHub URL, an "owner/name" pair, or either with stray whitespace.

    Raises ValueError on anything that isn't resolvable to "owner/name", so a typo
    fails immediately instead of turning into a 404 halfway through a run.
    """
    repo = value.strip()
    if not repo:
        raise ValueError("No repository given.")
    repo = re.sub(r"^(https?://)?(www\.)?github\.com/", "", repo)
    repo = repo.removesuffix(".git").strip("/")
    if not _REPO_RE.match(repo):
        raise ValueError(f"{value!r} is not a GitHub repository; use the owner/name form, e.g. grafana/grafana.")
    return repo


def get_profile(repo: str) -> RepoProfile:
    """Return the known profile for a repo, or a bare one that skips LTS tracking."""
    return PROFILES.get(repo.lower(), RepoProfile(repo=repo))
