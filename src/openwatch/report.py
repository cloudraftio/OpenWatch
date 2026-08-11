"""Fleet-wide client exposure report.

The digest answers "what changed since last run"; this answers "where does every client
stand right now". It deliberately ignores the notified-risk ledger, so a report is
complete every time rather than emptying out once a CVE has been announced.
"""
from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import risk, scoring, semver
from .clients import Client
from .cve.base import CVEFinding
from .risk import ClientRisk, Exposure
from .scoring import Assessment, Priority
from .semver import Version


@dataclass
class ScoredRisk:
    """One client's exposure to one CVE, ranked by how urgently it needs acting on."""

    risk: ClientRisk
    finding: CVEFinding
    assessment: Assessment

    # Passthroughs so renderers don't have to know where each piece lives.
    @property
    def cve_id(self) -> str:
        return self.risk.cve_id

    @property
    def reason(self) -> str:
        return self.risk.reason

    @property
    def recommended_version(self):
        return self.risk.recommended_version

    @property
    def priority(self) -> Priority:
        return self.assessment.priority

    @property
    def sort_key(self):
        # Highest CVSS first within a priority, then by ID so runs are reproducible.
        return (self.assessment.priority, -(self.assessment.cvss_score or 0), self.risk.cve_id)


@dataclass
class ClientReport:
    """One client's full standing against every known CVE."""

    client: Client
    affected: list[ScoredRisk] = field(default_factory=list)
    unknown: list[ScoredRisk] = field(default_factory=list)
    cleared: int = 0  # CVEs checked and ruled out - the evidence that silence means "checked".
    filtered: int = 0  # Applicable, but below the requested priority floor.
    upgrade_to: Version | None = None
    upgrade_clears: int = 0

    @property
    def status(self) -> str:
        if self.client.version is None:
            return "unknown"
        if self.act_now:
            return "act now"
        if self.affected:
            return "action needed"
        if self.unknown:
            return "review"
        # "clear" must mean nothing applies, not "nothing survived the filter".
        return "below filter" if self.filtered else "clear"

    @property
    def act_now(self) -> list[ScoredRisk]:
        """The subset that is both applicable and being exploited - the real short list."""
        return [item for item in self.affected if item.priority is Priority.ACT_NOW]


@dataclass
class FleetReport:
    """Every client's exposure for one repo, plus the cross-client view of each CVE."""

    repo: str
    generated_at: datetime
    latest_stable: str | None = None
    latest_lts_patch: str | None = None
    total_cves: int = 0
    clients: list[ClientReport] = field(default_factory=list)

    @property
    def cve_index(self) -> list[tuple[str, list[str], list[str]]]:
        """(cve_id, affected client names, fix versions), worst blast radius first."""
        index: dict[str, tuple[list[str], list[str]]] = {}
        for report in self.clients:
            for item in report.affected:
                names, fixes = index.setdefault(item.cve_id, ([], []))
                names.append(report.client.name)
                if item.recommended_version and str(item.recommended_version) not in fixes:
                    fixes.append(str(item.recommended_version))
        rows = [(cve, names, fixes) for cve, (names, fixes) in index.items()]
        rows.sort(key=lambda row: (-len(row[1]), row[0]))
        return rows

    @property
    def clients_needing_action(self) -> int:
        return sum(1 for report in self.clients if report.affected)

    @property
    def act_now_total(self) -> int:
        return sum(len(report.act_now) for report in self.clients)


def _recommended_upgrade(affected: list[ScoredRisk]) -> tuple[Version | None, int]:
    """The single lowest version that clears the most CVEs on the client's own branch.

    Taking the highest recommended patch works because every fix below it on the same
    branch is already included in it - one upgrade, not one per CVE.
    """
    targets = [item.recommended_version for item in affected if item.recommended_version]
    if not targets:
        return None, 0
    best = max(targets)
    return best, sum(1 for item in affected if item.recommended_version and item.recommended_version <= best)


def build(
    repo: str,
    registry: list[Client],
    findings,
    latest_stable=None,
    latest_lts_patch=None,
    min_priority: Priority = Priority.REVIEW,
) -> FleetReport:
    """Evaluate every client against every finding, keeping the ruled-out ones as a count.

    min_priority drops anything less urgent from the listings - the counts still reflect
    everything evaluated, so filtering never silently shrinks the denominator.
    """
    report = FleetReport(
        repo=repo,
        generated_at=datetime.now(timezone.utc),
        latest_stable=str(latest_stable) if latest_stable else None,
        latest_lts_patch=str(latest_lts_patch) if latest_lts_patch else None,
        total_cves=len(findings),
    )
    for client in registry:
        entry = ClientReport(client=client)
        for finding in findings:
            fixes = [v for v in (semver.parse(tag) for tag in finding.fix_versions) if v is not None]
            item = risk.evaluate(client, finding.cve_id, fixes)
            scored = ScoredRisk(item, finding, scoring.assess(finding, item.exposure))
            if item.exposure is Exposure.NOT_AFFECTED:
                entry.cleared += 1
            elif scored.priority > min_priority:
                entry.filtered += 1
            elif item.exposure is Exposure.AFFECTED:
                entry.affected.append(scored)
            else:
                entry.unknown.append(scored)
        entry.affected.sort(key=lambda item: item.sort_key)
        entry.unknown.sort(key=lambda item: item.sort_key)
        entry.upgrade_to, entry.upgrade_clears = _recommended_upgrade(entry.affected)
        report.clients.append(entry)
    report.clients.sort(key=lambda entry: (-len(entry.affected), -len(entry.unknown), entry.client.name))
    return report


# --- Rendering -------------------------------------------------------

SEVERITY_CAVEAT = (
    "Priority combines three independent signals: published severity/CVSS, real-world "
    "exploitation (CISA KEV and EPSS), and whether this client's version is actually "
    "affected. CVEs with no published advisory carry no severity and are ranked on "
    "applicability alone. Nothing here knows your deployment - a flaw in a component "
    "you do not run, or one unreachable from your network, still shows as affected."
)


def render_markdown(report: FleetReport) -> str:
    """Plain-text report, for a terminal, an email body, or a repo checkin."""
    stamp = report.generated_at.strftime("%Y-%m-%d %H:%M UTC")
    out = [
        f"# Client exposure report - {report.repo}",
        "",
        f"Generated {stamp} | latest stable {report.latest_stable or 'unknown'}"
        + (f" | latest LTS patch {report.latest_lts_patch}" if report.latest_lts_patch else ""),
        "",
        f"{len(report.clients)} client(s) checked against {report.total_cves} CVE(s). "
        f"{report.act_now_total} need acting on now; {report.clients_needing_action} client(s) affected in total.",
        "",
        "| Client | Version | Status | Affected | Review | Upgrade to |",
        "|---|---|---|---|---|---|",
    ]
    for entry in report.clients:
        target = str(entry.upgrade_to) if entry.upgrade_to else "-"
        out.append(
            f"| {entry.client.name} | {entry.client.raw_version or '(not recorded)'} | {entry.status} "
            f"| {len(entry.affected)} | {len(entry.unknown)} | {target} |"
        )

    for entry in report.clients:
        out += ["", f"## {entry.client.name}", ""]
        running = entry.client.raw_version or "not recorded"
        line = f"Running **{running}**. {entry.cleared} CVE(s) checked and ruled out."
        if entry.filtered:
            line += f" {entry.filtered} more apply but rank below the priority filter."
        if entry.upgrade_to:
            line += f" Upgrading to **{entry.upgrade_to}** clears {entry.upgrade_clears} of {len(entry.affected)}."
        out.append(line)
        if entry.client.contact:
            out.append(f"Contact: {entry.client.contact}")
        if entry.affected:
            out += ["", f"### Affected ({len(entry.affected)})", ""]
            for item in entry.affected:
                fix = f" -> upgrade to {item.recommended_version}" if item.recommended_version else ""
                out.append(
                    f"- [{item.priority.label.upper()}] **{item.cve_id}**{fix}  \n"
                    f"  {item.assessment.summary}  \n  {item.reason}"
                )
        if entry.unknown:
            out += ["", f"### Needs review ({len(entry.unknown)})", ""]
            for item in entry.unknown:
                out.append(f"- **{item.cve_id}** - {item.assessment.summary}  \n  {item.reason}")
        if not entry.affected and not entry.unknown:
            out += ["", "No known exposure."]

    index = report.cve_index
    if index:
        out += ["", "## CVEs by blast radius", "", "| CVE | Clients affected | Who | Fixed in |", "|---|---|---|---|"]
        for cve_id, names, fixes in index:
            out.append(f"| {cve_id} | {len(names)} | {', '.join(names)} | {', '.join(fixes) or '-'} |")

    out += ["", "---", "", SEVERITY_CAVEAT]
    return "\n".join(out) + "\n"


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


REPORT_CSS = """
:root {
  --ground: #f5f6f8; --surface: #ffffff; --line: #dde2e9; --line-strong: #c3ccd8;
  --ink: #171b22; --muted: #5c6672; --accent: #12505f;
  --action: #b23a2f; --review: #a86a12; --clear: #2f6b4f;
  --action-bg: #fbeae7; --review-bg: #fbf2e2; --clear-bg: #e8f2ec;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ground: #0f1318; --surface: #161b22; --line: #262d38; --line-strong: #38414f;
    --ink: #e6eaf0; --muted: #98a3b1; --accent: #63b3c2;
    --action: #e88275; --review: #e0ac4d; --clear: #6cbd93;
    --action-bg: #2a1a18; --review-bg: #2a2216; --clear-bg: #17241d;
  }
}
:root[data-theme="dark"] {
  --ground: #0f1318; --surface: #161b22; --line: #262d38; --line-strong: #38414f;
  --ink: #e6eaf0; --muted: #98a3b1; --accent: #63b3c2;
  --action: #e88275; --review: #e0ac4d; --clear: #6cbd93;
  --action-bg: #2a1a18; --review-bg: #2a2216; --clear-bg: #17241d;
}
:root[data-theme="light"] {
  --ground: #f5f6f8; --surface: #ffffff; --line: #dde2e9; --line-strong: #c3ccd8;
  --ink: #171b22; --muted: #5c6672; --accent: #12505f;
  --action: #b23a2f; --review: #a86a12; --clear: #2f6b4f;
  --action-bg: #fbeae7; --review-bg: #fbf2e2; --clear-bg: #e8f2ec;
}
body { background: var(--ground); color: var(--ink); margin: 0;
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  font-size: 16px; line-height: 1.55; }
.report { max-width: 62rem; margin: 0 auto; padding: 3rem 1.5rem 4rem;
  display: flex; flex-direction: column; gap: 2.75rem; }
.masthead { display: flex; flex-direction: column; gap: .4rem;
  border-bottom: 2px solid var(--line-strong); padding-bottom: 1.25rem; }
.eyebrow { margin: 0; font-size: .75rem; letter-spacing: .14em; text-transform: uppercase;
  color: var(--accent); font-weight: 600; }
h1 { margin: 0; font-family: ui-serif, "Iowan Old Style", Georgia, serif; font-weight: 600;
  font-size: clamp(1.75rem, 4vw, 2.5rem); line-height: 1.1; text-wrap: balance;
  font-variant-ligatures: none; }
h2 { margin: 0; font-family: ui-serif, "Iowan Old Style", Georgia, serif;
  font-size: 1.35rem; font-weight: 600; text-wrap: balance; }
h3 { margin: 0; font-size: .78rem; letter-spacing: .1em; text-transform: uppercase;
  color: var(--muted); font-weight: 700; }
.meta { margin: 0; color: var(--muted); font-size: .92rem; }
.meta code { font-family: ui-monospace, "SF Mono", "Cascadia Code", Menlo, monospace;
  color: var(--ink); font-size: .88em; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr)); gap: 1px;
  background: var(--line); border: 1px solid var(--line); }
.stat { background: var(--surface); padding: 1rem 1.1rem; display: flex; flex-direction: column; gap: .2rem; }
.stat b { font-size: 2rem; font-weight: 600; line-height: 1; font-variant-numeric: tabular-nums;
  font-family: ui-serif, "Iowan Old Style", Georgia, serif; }
.stat span { font-size: .78rem; letter-spacing: .06em; text-transform: uppercase; color: var(--muted); }
.stat.is-action b { color: var(--action); }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: .93rem; }
th { text-align: left; font-size: .72rem; letter-spacing: .09em; text-transform: uppercase;
  color: var(--muted); font-weight: 700; padding: .5rem .75rem; border-bottom: 1px solid var(--line-strong);
  white-space: nowrap; }
td { padding: .6rem .75rem; border-bottom: 1px solid var(--line); vertical-align: baseline; }
td.num { font-variant-numeric: tabular-nums; text-align: right; }
.mono, code { font-family: ui-monospace, "SF Mono", "Cascadia Code", Menlo, monospace; font-size: .88em; }
.pill { display: inline-block; padding: .1rem .5rem; border-radius: 999px; font-size: .72rem;
  font-weight: 700; letter-spacing: .04em; text-transform: uppercase; white-space: nowrap; }
.pill--action { background: var(--action-bg); color: var(--action); }
.pill--review { background: var(--review-bg); color: var(--review); }
.pill--clear  { background: var(--clear-bg);  color: var(--clear); }
.pill--unknown{ background: var(--line); color: var(--muted); }
.client { display: flex; flex-direction: column; gap: 1rem;
  border-top: 1px solid var(--line-strong); padding-top: 1.4rem; }
.client-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: .6rem 1rem; }
.client-head .running { color: var(--muted); font-size: .93rem; }
.verdict { margin: 0; color: var(--muted); font-size: .93rem; }
.verdict strong { color: var(--ink); }
.risks { display: flex; flex-direction: column; gap: .1rem; margin: 0; padding: 0; list-style: none; }
.risk { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: .2rem 1rem;
  padding: .55rem 0; border-bottom: 1px solid var(--line); }
.risk .id { font-family: ui-monospace, "SF Mono", "Cascadia Code", Menlo, monospace;
  font-size: .9rem; font-weight: 600; }
.risk .fix { font-size: .8rem; color: var(--accent); font-weight: 600; white-space: nowrap; }
.risk .signals { grid-column: 1 / -1; color: var(--ink); font-size: .83rem; }
.risk .why { grid-column: 1 / -1; color: var(--muted); font-size: .87rem; }
.pill--action.pill { letter-spacing: .05em; }
.group { display: flex; flex-direction: column; gap: .5rem; }
footer { border-top: 1px solid var(--line); padding-top: 1.25rem; color: var(--muted); font-size: .85rem; }
@media print {
  body { background: #fff; }
  .report { padding: 0; gap: 1.75rem; }
  .client { break-inside: avoid; }
}
"""


def _pill(entry: ClientReport) -> str:
    kind = {"act now": "action", "action needed": "action", "review": "review", "clear": "clear"}.get(
        entry.status, "unknown"
    )
    return f'<span class="pill pill--{kind}">{_esc(entry.status)}</span>'


PRIORITY_CLASS = {
    Priority.ACT_NOW: "action",
    Priority.PATCH_SOON: "review",
    Priority.SCHEDULE: "clear",
    Priority.REVIEW: "unknown",
    Priority.INFORMATIONAL: "unknown",
}


def _risk_items(items: list[ScoredRisk]) -> str:
    rows = []
    for item in items:
        fix = (
            f'<span class="fix">&rarr; {_esc(item.recommended_version)}</span>'
            if item.recommended_version
            else '<span class="fix">&nbsp;</span>'
        )
        badge = (
            f'<span class="pill pill--{PRIORITY_CLASS[item.priority]}">{_esc(item.priority.label)}</span>'
        )
        signals = f'<span class="signals">{_esc(item.assessment.summary)}</span>'
        rows.append(
            f'<li class="risk"><span class="id">{badge} {_esc(item.cve_id)}</span>{fix}'
            f'{signals}<span class="why">{_esc(item.reason)}</span></li>'
        )
    return f'<ul class="risks">{"".join(rows)}</ul>'


def render_html(report: FleetReport, standalone: bool = True) -> str:
    """Self-contained HTML report - no external assets, readable in both themes, printable."""
    stamp = report.generated_at.strftime("%d %B %Y, %H:%M UTC")
    meta = f"Generated {_esc(stamp)} &middot; latest stable <code>{_esc(report.latest_stable or 'unknown')}</code>"
    if report.latest_lts_patch:
        meta += f" &middot; latest LTS patch <code>{_esc(report.latest_lts_patch)}</code>"

    total_affected = sum(len(entry.affected) for entry in report.clients)
    total_review = sum(len(entry.unknown) for entry in report.clients)
    stats = [
        ("", len(report.clients), "clients checked"),
        ("", report.total_cves, "CVEs evaluated"),
        ("is-action" if report.act_now_total else "", report.act_now_total, "act now"),
        ("", total_affected, "affected"),
        ("", total_review, "need review"),
    ]
    stat_html = "".join(
        f'<div class="stat {cls}"><b>{value}</b><span>{label}</span></div>' for cls, value, label in stats
    )

    fleet_rows = "".join(
        f"<tr><td>{_esc(entry.client.name)}</td>"
        f'<td class="mono">{_esc(entry.client.raw_version or "not recorded")}</td>'
        f"<td>{_pill(entry)}</td>"
        f'<td class="num">{len(entry.affected)}</td>'
        f'<td class="num">{len(entry.unknown)}</td>'
        f'<td class="num">{entry.cleared}</td>'
        f'<td class="mono">{_esc(entry.upgrade_to) if entry.upgrade_to else "&mdash;"}</td></tr>'
        for entry in report.clients
    )

    sections = []
    for entry in report.clients:
        running = entry.client.raw_version or "not recorded"
        verdict = f"{entry.cleared} CVE(s) checked and ruled out for this version."
        if entry.filtered:
            verdict += f" {entry.filtered} more apply but rank below the priority filter."
        if entry.upgrade_to:
            verdict = (
                f"Upgrading to <strong>{_esc(entry.upgrade_to)}</strong> clears "
                f"{entry.upgrade_clears} of {len(entry.affected)} affected. " + verdict
            )
        contact = (
            f' &middot; <span class="running">{_esc(entry.client.contact)}</span>' if entry.client.contact else ""
        )
        blocks = ""
        if entry.affected:
            blocks += (
                f'<div class="group"><h3>Affected ({len(entry.affected)})</h3>'
                f"{_risk_items(entry.affected)}</div>"
            )
        if entry.unknown:
            blocks += (
                f'<div class="group"><h3>Needs review ({len(entry.unknown)})</h3>'
                f"{_risk_items(entry.unknown)}</div>"
            )
        if not blocks:
            blocks = '<p class="verdict">No known exposure.</p>'
        sections.append(
            f'<section class="client"><div class="client-head"><h2>{_esc(entry.client.name)}</h2>'
            f'{_pill(entry)}<span class="running">running <span class="mono">{_esc(running)}</span>'
            f"{contact}</span></div>"
            f'<p class="verdict">{verdict}</p>{blocks}</section>'
        )

    radius = ""
    index = report.cve_index
    if index:
        rows = "".join(
            f'<tr><td class="mono">{_esc(cve_id)}</td><td class="num">{len(names)}</td>'
            f'<td>{_esc(", ".join(names))}</td><td class="mono">{_esc(", ".join(fixes)) or "&mdash;"}</td></tr>'
            for cve_id, names, fixes in index
        )
        radius = (
            '<section class="group"><h2>CVEs by blast radius</h2><div class="scroll"><table>'
            "<thead><tr><th>CVE</th><th>Clients</th><th>Who</th><th>Fixed in</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div></section>"
        )

    body = (
        '<article class="report">'
        f'<header class="masthead"><p class="eyebrow">Client exposure report</p>'
        f'<h1>{_esc(report.repo)}</h1><p class="meta">{meta}</p></header>'
        f'<section class="stats">{stat_html}</section>'
        '<section class="group"><h2>Fleet</h2><div class="scroll"><table>'
        "<thead><tr><th>Client</th><th>Version</th><th>Status</th><th>Affected</th>"
        "<th>Review</th><th>Cleared</th><th>Upgrade to</th></tr></thead>"
        f"<tbody>{fleet_rows}</tbody></table></div></section>"
        f'{"".join(sections)}{radius}'
        f"<footer>{_esc(SEVERITY_CAVEAT)}</footer>"
        "</article>"
    )
    page = f"<style>{REPORT_CSS}</style>{body}"
    if not standalone:
        return page  # Embedded in a host page that supplies its own document shell.
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f"<title>Client exposure report - {_esc(report.repo)}</title>\n"
        f"</head>\n<body>\n{page}\n</body>\n</html>\n"
    )
