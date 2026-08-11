"""Storage interface shared by every backend."""
from __future__ import annotations

import abc


class Storage(abc.ABC):
    """Persistence + idempotency tracking, keyed by a stable identifier per category."""

    # True when every record carries the repo it belongs to, so one store can hold
    # several projects. False means the store holds exactly one repo's data.
    scopes_by_repo = False

    @abc.abstractmethod
    def has_seen(self, category: str, identifier: str) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def mark_seen(self, category: str, identifier: str) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def get_pointer(self, name: str) -> str | None:
        """Read back a named state pointer, e.g. "latest_stable" or "latest_lts_patch"."""
        raise NotImplementedError

    @abc.abstractmethod
    def set_pointer(self, name: str, value: str) -> None:
        raise NotImplementedError

    def flush(self) -> None:
        """Persist any buffered writes; a no-op for backends that write eagerly."""

    def list_clients(self) -> list[dict[str, str]]:
        """Return manually-recorded client rows; empty means broadcast mode, never an error."""
        return []

    def add_client(self, name: str, version: str, contact: str = "") -> None:
        """Record a client so advisories can be mapped against their version."""
        raise NotImplementedError(f"{type(self).__name__} cannot record clients.")

    def remove_client(self, name: str) -> int:
        """Drop every recorded row matching this name, returning how many were removed."""
        raise NotImplementedError(f"{type(self).__name__} cannot remove clients.")
