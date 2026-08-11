"""GitHub Security Advisories source - the project's own published advisories.

One authenticated call per repo returns severity, CVSS vector and patched versions,
which is everything the release-note regex cannot know.
"""
from __future__ import annotations

import logging
import re

import requests

from .base import CVEFinding, CVESource

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
# Patched versions arrive as free text ("3.5.3 and 3.11.3", "9.3.4, 9.2.10"), so pull
# out anything version-shaped rather than trying to parse the sentence.
_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.\-]+)?")


class GitHubAdvisoriesSource(CVESource):
    """Reads /repos/{repo}/security-advisories, the advisories the project itself published."""

    name = "github_advisories"

    def __init__(self, repo: str, token: str | None = None):
        self.repo = repo
        self.token = token

    def collect(self) -> list[CVEFinding]:
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        url = f"{GITHUB_API}/repos/{self.repo}/security-advisories"
        try:
            response = requests.get(url, headers=headers, params={"per_page": 100}, timeout=30)
            response.raise_for_status()
            advisories = response.json()
        except requests.RequestException as exc:
            logger.warning("Could not read %s advisories: %s", self.repo, exc)
            return []
        if not isinstance(advisories, list):
            return []

        findings = []
        for advisory in advisories:
            cve_id = advisory.get("cve_id")
            if not cve_id:
                continue  # Draft or withdrawn advisories carry no CVE to key on.
            cvss = advisory.get("cvss") or {}
            fixes: list[str] = []
            for vulnerable in advisory.get("vulnerabilities") or []:
                for match in _VERSION_RE.findall(vulnerable.get("patched_versions") or ""):
                    if match not in fixes:
                        fixes.append(match)
            findings.append(
                CVEFinding(
                    cve_id=cve_id,
                    source=self.name,
                    summary=advisory.get("summary") or "",
                    severity=(advisory.get("severity") or None),
                    url=advisory.get("html_url"),
                    fix_versions=tuple(fixes),
                    cvss_score=cvss.get("score"),
                    cvss_vector=cvss.get("vector_string"),
                )
            )
        logger.info("Read %d advisories with severity from %s", len(findings), self.repo)
        return findings
