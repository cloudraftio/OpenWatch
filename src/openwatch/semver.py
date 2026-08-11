"""SemVer parsing and version resolution - ordering by precedence, never by publish date."""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

# SemVer 2.0.0 regex (semver.org), with an optional leading "v" for git tags.
_SEMVER_RE = re.compile(
    r"""^
    v?
    (?P<major>0|[1-9]\d*)\.
    (?P<minor>0|[1-9]\d*)\.
    (?P<patch>0|[1-9]\d*)
    (?:-(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?
    (?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?
    $""",
    re.VERBOSE,
)


@total_ordering
@dataclass(frozen=True)
class Version:
    """A parsed SemVer version, as used for git release tags."""

    major: int
    minor: int
    patch: int
    prerelease: str | None
    raw: str

    @property
    def is_prerelease(self) -> bool:
        return self.prerelease is not None

    @property
    def minor_branch(self) -> tuple[int, int]:
        """The (major, minor) release branch this version belongs to."""
        return (self.major, self.minor)

    def _sort_key(self):
        # A prerelease tag sorts below the same major.minor.patch without one.
        if self.prerelease is None:
            prerelease_key: tuple = (1,)
        else:
            parts = []
            for part in self.prerelease.split("."):
                parts.append((0, int(part)) if part.isdigit() else (1, part))
            prerelease_key = (0, tuple(parts))
        return (self.major, self.minor, self.patch, prerelease_key)

    def __eq__(self, other):
        if not isinstance(other, Version):
            return NotImplemented
        return self._sort_key() == other._sort_key()

    def __lt__(self, other):
        if not isinstance(other, Version):
            return NotImplemented
        return self._sort_key() < other._sort_key()

    def __hash__(self):
        return hash(self.raw)

    def __str__(self):
        return self.raw


def parse(tag: str) -> Version | None:
    """Parse a git tag into a Version, or return None if it isn't valid SemVer."""
    match = _SEMVER_RE.match(tag.strip())
    if not match:
        return None
    return Version(
        major=int(match.group("major")),
        minor=int(match.group("minor")),
        patch=int(match.group("patch")),
        prerelease=match.group("prerelease"),
        raw=tag,
    )


def parse_all(tags: list[str]) -> list[Version]:
    """Parse a list of tags, silently dropping anything that isn't valid SemVer."""
    versions = []
    for tag in tags:
        version = parse(tag)
        if version is not None:
            versions.append(version)
    return versions


def resolve_latest_stable(versions: list[Version]) -> Version | None:
    """Return the highest non-prerelease version - the "Latest Stable" pointer."""
    stable = [v for v in versions if not v.is_prerelease]
    if not stable:
        return None
    return max(stable)


def resolve_branch_latest_patch(versions: list[Version], branch: tuple[int, int]) -> Version | None:
    """Return the highest non-prerelease patch on a given (major, minor) branch."""
    on_branch = [v for v in versions if not v.is_prerelease and v.minor_branch == branch]
    if not on_branch:
        return None
    return max(on_branch)
