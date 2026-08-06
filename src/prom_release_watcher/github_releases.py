"""GitHub REST API client for tags and releases (pipeline stage 1)."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterator

import requests

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"


class RepoNotFound(Exception):
    """The watched repo doesn't exist, was renamed, or is private to this token."""


@dataclass(frozen=True)
class Release:
    tag: str
    name: str
    body: str
    published_at: str | None
    draft: bool
    prerelease: bool
    html_url: str


class GitHubReleasesClient:
    """Thin wrapper around the GitHub REST API for tags and releases; token is optional."""

    def __init__(self, repo: str, token: str | None = None, session: requests.Session | None = None):
        self.repo = repo
        self._session = session or requests.Session()
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._session.headers.update(headers)

    def _paginate(self, path: str, params: dict | None = None, limit: int = 0) -> Iterator[dict]:
        """Walk a paginated endpoint, stopping after `limit` items (0 means no cap)."""
        url = f"{GITHUB_API}{path}"
        params = dict(params or {})
        params.setdefault("per_page", 100)
        yielded = 0
        while url:
            response = self._session.get(url, params=params)
            if response.status_code == 404:
                raise RepoNotFound(
                    f"{self.repo} was not found on GitHub. Check the owner/name spelling, "
                    "and set GITHUB_TOKEN if the repo is private."
                )
            response.raise_for_status()
            for entry in response.json():
                yield entry
                yielded += 1
                if limit and yielded >= limit:
                    return
            url = response.links.get("next", {}).get("url")
            params = None  # The `next` URL already carries the query string.

    def repo_exists(self) -> bool:
        """Cheap single-request check, used to fail fast on a mistyped repo name."""
        response = self._session.get(f"{GITHUB_API}/repos/{self.repo}")
        if response.status_code == 404:
            return False
        response.raise_for_status()
        return True

    def list_tags(self, limit: int = 0) -> list[str]:
        """Return git tag names for the repo, in GitHub's own order (not by version)."""
        return [entry["name"] for entry in self._paginate(f"/repos/{self.repo}/tags", limit=limit)]

    def list_releases(self, limit: int = 0) -> list[Release]:
        """Return GitHub Releases (tag + changelog body), newest first."""
        releases = []
        for entry in self._paginate(f"/repos/{self.repo}/releases", limit=limit):
            releases.append(
                Release(
                    tag=entry["tag_name"],
                    name=entry.get("name") or entry["tag_name"],
                    body=entry.get("body") or "",
                    published_at=entry.get("published_at"),
                    draft=entry.get("draft", False),
                    prerelease=entry.get("prerelease", False),
                    html_url=entry.get("html_url", ""),
                )
            )
        return releases
