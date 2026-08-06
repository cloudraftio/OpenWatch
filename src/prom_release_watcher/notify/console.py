"""Console notifier - always available, no configuration needed."""
from __future__ import annotations

from ..cve.base import CVEFinding
from .base import Digest, Notifier

MAX_LISTED_RELEASES = 10  # Caps output on a first run, where every historical release is "new".


class ConsoleNotifier(Notifier):
    """Logs the digest instead of delivering it anywhere; always available, no config needed."""

    def send_digest(self, digest: Digest) -> None:
        lines = [f"Release & Security Watcher - digest for {digest.repo or 'the watched repo'}"]
        if digest.latest_stable:
            lines.append(f"  Latest stable:    {digest.latest_stable}")
        if digest.latest_lts_patch:
            lines.append(f"  Latest LTS patch: {digest.latest_lts_patch}")
        if digest.new_releases:
            shown = digest.new_releases[:MAX_LISTED_RELEASES]
            suffix = "" if len(digest.new_releases) <= MAX_LISTED_RELEASES else (
                f", +{len(digest.new_releases) - MAX_LISTED_RELEASES} more"
            )
            lines.append(f"  New releases ({len(digest.new_releases)}): {', '.join(shown)}{suffix}")
        for summary in digest.changelogs[:MAX_LISTED_RELEASES]:
            if not summary.security_fixes and not summary.highlights:
                continue
            lines.append(f"    {summary.tag}:")
            for fix in summary.security_fixes:
                lines.append(f"      [SECURITY] {fix}")
            for highlight in summary.highlights[:3]:
                lines.append(f"      {highlight}")
        if digest.batched_cves:
            lines.append(f"  CVEs this cycle ({len(digest.batched_cves)}):")
            for finding in digest.batched_cves:
                lines.append(f"    - {finding.cve_id} [{finding.source}]")
        if digest.lts_eol_reminders:
            lines.append(f"  LTS branches nearing EOL ({len(digest.lts_eol_reminders)}):")
            for entry in digest.lts_eol_reminders:
                lines.append(f"    - {entry.label}: end of support {entry.end_of_support}")
        if len(lines) == 1:
            lines.append("  Nothing new.")
        print("\n".join(lines))

    def send_urgent(self, finding: CVEFinding) -> None:
        print(f"[URGENT] {finding.cve_id} ({finding.source}): {finding.summary or 'see source for details'}")

    def send_client_digest(self, client_digest) -> None:
        client = client_digest.client
        recorded = client.raw_version or "not recorded"
        project = client_digest.repo.split("/")[-1] if client_digest.repo else "version"
        lines = [f"\n--- Client: {client.name} ({project} {recorded}) ---"]
        if client.contact:
            lines.append(f"  Contact: {client.contact}")
        if client_digest.affected:
            lines.append(f"  AFFECTED ({len(client_digest.affected)}):")
            for item in client_digest.affected:
                upgrade = f" -> upgrade to {item.recommended_version}" if item.recommended_version else ""
                lines.append(f"    - {item.cve_id}{upgrade}")
                lines.append(f"        {item.reason}")
        if client_digest.unknown:
            lines.append(f"  NEEDS REVIEW ({len(client_digest.unknown)}):")
            for item in client_digest.unknown:
                lines.append(f"    - {item.cve_id}")
                lines.append(f"        {item.reason}")
        print("\n".join(lines))
