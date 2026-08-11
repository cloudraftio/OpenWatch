"""Pipeline orchestrator."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date

from . import clients, exploit, lts, release_notes_cves, risk, semver
from .changelog.base import ChangelogParser
from .changelog.release_notes import ReleaseNotesParser
from .config import Config
from .cve.base import CVEFinding, CVESource
from .github_releases import GitHubReleasesClient, Release
from .notify.base import Digest, Notifier
from .storage.base import Storage

logger = logging.getLogger(__name__)


def _sort_tags(tags) -> list[str]:
    """Order release tags by SemVer precedence, dropping anything unparseable."""
    parsed = [(semver.parse(tag), tag) for tag in tags]
    return [tag for version, tag in sorted((p for p in parsed if p[0]), key=lambda p: p[0])]


def _guard_state_repo(config: Config, storage: Storage) -> None:
    """Refuse to reuse another repo's state, where identical tags would look already-seen.

    Only applies to backends that hold one repo per store; where every row already
    records its repo, there is nothing to collide and nothing to stamp.
    """
    if storage.scopes_by_repo:
        return
    recorded = storage.get_pointer("repo")
    if recorded and recorded.lower() != config.repo.lower():
        raise SystemExit(
            f"This state store already tracks {recorded}, not {config.repo}.\n"
            "A local state file holds one repo; point WATCHER_STATE_FILE at its own file\n"
            "(or use Google Sheets, where each row records the repo it belongs to)."
        )
    storage.set_pointer("repo", config.repo)


TAG_FETCH_CAP = 2000  # Safety valve for repos with a very long tag history.


def _fetch_releases(client: GitHubReleasesClient, limit: int) -> list:
    """Fetch GitHub Releases, falling back to bare tags for projects that only tag."""
    releases = client.list_releases(limit=limit)
    if releases:
        return releases

    # The tags endpoint isn't ordered by version, so cap only after sorting - otherwise
    # a limited run would report whichever ancient tags happened to come back first.
    tags = client.list_tags(limit=TAG_FETCH_CAP)
    if not tags:
        return []
    parsed = [(semver.parse(tag), tag) for tag in tags]
    ordered = [tag for version, tag in sorted((p for p in parsed if p[0]), key=lambda p: p[0], reverse=True)]
    ordered += [tag for version, tag in parsed if version is None]  # Unparseable tags last, never dropped.
    if limit:
        ordered = ordered[:limit]
    logger.info("No GitHub Releases published; falling back to %d git tag(s) with no changelog.", len(ordered))
    return [
        Release(tag=tag, name=tag, body="", published_at=None, draft=False, prerelease=False, html_url="")
        for tag in ordered
    ]


def _load_clients(config: Config, storage: Storage):
    """Load the client registry, degrading to broadcast mode rather than failing the run."""
    try:
        registry = clients.load_clients_file(config.clients_file)
        return registry or clients.parse_clients(storage.list_clients())
    except Exception as exc:  # A malformed registry must never take the whole run down.
        logger.warning("Could not load client registry, falling back to broadcast: %s", exc)
        return []


@dataclass
class Analysis:
    """Everything one pass learns about a repo, before any of it is persisted or delivered.

    Kept separate from Digest because a digest is "what changed since last time" while
    this is "what is true right now" - reporting needs the latter.
    """

    repo: str
    releases: list[Release] = field(default_factory=list)
    latest_stable: object | None = None
    latest_lts_patch: object | None = None
    lts_entries: list = field(default_factory=list)
    reminders: list = field(default_factory=list)
    summaries: dict = field(default_factory=dict)
    findings: list[CVEFinding] = field(default_factory=list)


def analyse(
    config: Config,
    cve_sources: list[CVESource] | None = None,
    releases_client: GitHubReleasesClient | None = None,
    changelog_parser: ChangelogParser | None = None,
    today: date | None = None,
) -> Analysis:
    """Fetch and evaluate the upstream project. Reads only - never touches storage.

    Both the watcher run and the client report go through here, so the two can never
    disagree about which CVEs exist or which releases fixed them.
    """
    today = today or date.today()
    client = releases_client or GitHubReleasesClient(repo=config.repo, token=config.github_token)
    parser = changelog_parser or ReleaseNotesParser()

    # --- Fetch GitHub Releases ---
    releases = _fetch_releases(client, config.max_releases)
    logger.info("Fetched %d releases from %s", len(releases), config.repo)
    if not releases:
        logger.warning("%s has no releases or tags; nothing to report.", config.repo)

    # --- Compute Current Version State (SemVer, not publish date) ---
    versions = semver.parse_all([r.tag for r in releases])
    latest_stable = semver.resolve_latest_stable(versions)

    # --- Refresh LTS Metadata (only for projects that publish a lifecycle table) ---
    lts_entries = lts.fetch_lts_table(repo=config.docs_repo, path=config.lts_doc_path)
    active_branch = lts.latest_lts_branch(lts_entries)
    latest_lts_patch = (
        semver.resolve_branch_latest_patch(versions, active_branch.branch) if active_branch else None
    )
    reminders = lts.eol_reminders(lts_entries, today=today, days_before=config.eol_reminder_days)

    # --- Parse Release Changelog ---
    summaries = {release.tag: parser.parse(release.tag, release.body) for release in releases}

    # --- Collect Security Data: categorised [SECURITY] bullets ---
    # One CVE can be fixed in several releases (LTS backports), and per-client risk
    # mapping needs all of them, so collect every fixing tag rather than just the first.
    fix_tags: dict[str, set[str]] = {}
    cve_summaries: dict[str, str] = {}
    for tag, summary in summaries.items():
        for entry in summary.entries:
            if entry.category != "SECURITY":
                continue
            for cve_id in entry.cve_ids:
                fix_tags.setdefault(cve_id, set()).add(tag)
                cve_summaries.setdefault(cve_id, entry.text)

    # --- Collect Security Data: whole-body regex catch-all ---
    for mention in release_notes_cves.extract_from_releases(releases):
        fix_tags.setdefault(mention.cve_id, set()).add(mention.release_tag)
        cve_summaries.setdefault(mention.cve_id, f"Mentioned in {mention.release_tag}")

    findings = []
    for cve_id, tags in fix_tags.items():
        ordered = _sort_tags(tags)
        findings.append(
            CVEFinding(
                cve_id=cve_id,
                source="release_notes",
                summary=cve_summaries.get(cve_id, ""),
                affected_component=ordered[0] if ordered else None,
                fix_versions=tuple(ordered),
            )
        )

    # --- Collect Security Data: pluggable sources (GH advisories/govulncheck/Trivy) ---
    # Sources overlap heavily - release notes and the project's own advisories describe
    # the same CVEs - so merge per ID rather than reporting each flaw several times.
    by_id = {finding.cve_id: finding for finding in findings}
    for source in cve_sources or []:
        try:
            for finding in source.collect():
                existing = by_id.get(finding.cve_id)
                by_id[finding.cve_id] = finding.merge(existing) if existing else finding
        except NotImplementedError as exc:
            logger.warning("Skipping CVE source %r: %s", source.name, exc)
    findings = list(by_id.values())

    # --- Real-world exploitation signals (KEV / EPSS) ---
    if config.enrich_exploit_signals:
        findings = exploit.enrich(findings)

    return Analysis(
        repo=config.repo,
        releases=releases,
        latest_stable=latest_stable,
        latest_lts_patch=latest_lts_patch,
        lts_entries=lts_entries,
        reminders=reminders,
        summaries=summaries,
        findings=findings,
    )


def run_once(
    config: Config,
    storage: Storage,
    notifiers: list[Notifier],
    cve_sources: list[CVESource] | None = None,
    releases_client: GitHubReleasesClient | None = None,
    changelog_parser: ChangelogParser | None = None,
    today: date | None = None,
) -> Digest:
    """Execute one pipeline pass: fetch, resolve versions, refresh LTS, scan CVEs, persist, notify."""
    _guard_state_repo(config, storage)
    analysis = analyse(config, cve_sources, releases_client, changelog_parser, today)
    releases = analysis.releases
    summaries = analysis.summaries
    findings = analysis.findings
    latest_stable = analysis.latest_stable
    latest_lts_patch = analysis.latest_lts_patch
    reminders = analysis.reminders

    # --- Persist + idempotency check (section 7) ---
    new_release_tags = []
    for release in releases:
        if not storage.has_seen("release", release.tag):
            new_release_tags.append(release.tag)
            storage.mark_seen("release", release.tag)

    new_findings = []
    for finding in findings:
        if not storage.has_seen("advisory", finding.cve_id):
            new_findings.append(finding)
            storage.mark_seen("advisory", finding.cve_id)

    if latest_stable:
        storage.set_pointer("latest_stable", latest_stable.raw)
    if latest_lts_patch:
        storage.set_pointer("latest_lts_patch", latest_lts_patch.raw)

    # --- Per-client risk mapping (falls back to broadcast when no clients are recorded) ---
    registry = _load_clients(config, storage)
    client_digests = risk.build_client_digests(registry, findings, storage, repo=config.repo) if registry else []
    if registry:
        logger.info("Mapped %d advisories across %d client(s)", len(findings), len(registry))

    # Persist before notifying, so a storage failure can't leave us having notified without recording it.
    storage.flush()

    # --- Generate Notifications (section 8) ---
    digest = Digest(
        repo=config.repo,
        new_releases=new_release_tags,
        batched_cves=new_findings,
        lts_eol_reminders=reminders,
        latest_stable=latest_stable.raw if latest_stable else None,
        latest_lts_patch=latest_lts_patch.raw if latest_lts_patch else None,
        changelogs=[summaries[tag] for tag in new_release_tags],
        client_digests=client_digests,
    )

    for notifier in notifiers:
        notifier.send_digest(digest)
        for finding in new_findings:
            if finding.severity and finding.severity.lower() == "critical":
                notifier.send_urgent(finding)

    # Targeted delivery: each client hears only about their own exposure.
    for client_digest in client_digests:
        if not client_digest.has_content:
            continue
        for notifier in notifiers:
            notifier.send_client_digest(client_digest)

    return digest
