"""Per-client risk mapping - evaluates each advisory against each client's recorded version."""
from __future__ import annotations

import enum
from dataclasses import dataclass, field

from . import semver
from .clients import Client
from .semver import Version


class Exposure(enum.Enum):
    """Whether a client's recorded version is exposed to a given CVE."""

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ClientRisk:
    """One client's exposure to one CVE, with the reasoning behind the verdict."""

    client: Client
    cve_id: str
    exposure: Exposure
    reason: str
    recommended_version: Version | None = None


@dataclass
class ClientDigest:
    """The newly-determined risks for a single client, for targeted delivery."""

    client: Client
    repo: str = ""  # The project these risks are about, for channels that report several.
    affected: list[ClientRisk] = field(default_factory=list)
    unknown: list[ClientRisk] = field(default_factory=list)

    @property
    def has_content(self) -> bool:
        return bool(self.affected or self.unknown)


def evaluate(client: Client, cve_id: str, fix_versions: list[Version]) -> ClientRisk:
    """Decide whether one client is exposed to one CVE, given every release that fixed it."""
    if client.version is None:
        detail = f"no version recorded" if not client.raw_version else f"unparseable version {client.raw_version!r}"
        return ClientRisk(client, cve_id, Exposure.UNKNOWN, f"Cannot assess: {detail}.")

    stable = sorted(v for v in fix_versions if not v.is_prerelease)
    if not stable:
        return ClientRisk(client, cve_id, Exposure.UNKNOWN, "No released version is recorded as fixing this CVE.")

    # A fix on the client's own branch is the only fully reliable signal.
    same_branch = [v for v in stable if v.minor_branch == client.version.minor_branch]
    if same_branch:
        fix = min(same_branch)
        if client.version >= fix:
            return ClientRisk(
                client, cve_id, Exposure.NOT_AFFECTED, f"Running {client.version}; fixed on this branch in {fix}."
            )
        return ClientRisk(
            client, cve_id, Exposure.AFFECTED, f"Running {client.version}; fixed on this branch in {fix}.", fix
        )

    newest = max(stable)
    if client.version >= newest:
        return ClientRisk(
            client, cve_id, Exposure.NOT_AFFECTED, f"Running {client.version}, at or above the newest fix {newest}."
        )

    # Release notes record where a flaw was fixed, never where it was introduced, so
    # inferring across branches without a same-branch fix would be a guess.
    fixed_in = ", ".join(str(v) for v in stable)
    branch = f"{client.version.major}.{client.version.minor}"
    return ClientRisk(
        client,
        cve_id,
        Exposure.UNKNOWN,
        f"Running {client.version}; fixed in {fixed_in} but no patch was released for the {branch} branch, "
        "and the introducing version is not recorded.",
        newest,
    )


def build_client_digests(clients: list[Client], findings, storage=None, repo: str = "") -> list[ClientDigest]:
    """Map every finding onto every client, keeping only risks not already notified."""
    digests = []
    for client in clients:
        digest = ClientDigest(client=client, repo=repo)
        for finding in findings:
            fix_versions = [v for v in (semver.parse(tag) for tag in finding.fix_versions) if v is not None]
            risk = evaluate(client, finding.cve_id, fix_versions)
            if risk.exposure is Exposure.NOT_AFFECTED:
                continue
            if storage is not None:
                key = f"{client.name}:{finding.cve_id}"
                if storage.has_seen("client_risk", key):
                    continue
                storage.mark_seen("client_risk", key)
            (digest.affected if risk.exposure is Exposure.AFFECTED else digest.unknown).append(risk)
        digests.append(digest)
    return digests
