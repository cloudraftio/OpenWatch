"""GitHub Security Advisories source - STUB."""
from __future__ import annotations

from .base import CVEFinding, CVESource


class GitHubAdvisoriesSource(CVESource):
    """NOT IMPLEMENTED: would query the GraphQL securityVulnerabilities field for the watched repo."""

    name = "github_advisories"

    def __init__(self, repo: str, token: str | None = None):
        self.repo = repo
        self.token = token

    def collect(self) -> list[CVEFinding]:
        raise NotImplementedError("GitHubAdvisoriesSource is a stub.")
