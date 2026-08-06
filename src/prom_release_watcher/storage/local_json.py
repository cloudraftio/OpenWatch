"""Local JSON-file storage backend - the credential-free default."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .base import Storage


class LocalJSONStorage(Storage):
    """A single JSON file used as the structured store; the credential-free default backend."""

    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        self._data = self._load()

    def _load(self) -> dict:
        if not self.path.exists():
            return {"seen": {}, "pointers": {}}
        with self.path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Write atomically so a crash mid-write can't corrupt existing state.
        fd, tmp_path = tempfile.mkstemp(dir=self.path.parent, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, sort_keys=True)
            os.replace(tmp_path, self.path)
        except BaseException:
            os.unlink(tmp_path)
            raise

    def has_seen(self, category: str, identifier: str) -> bool:
        return identifier in self._data["seen"].get(category, [])

    def mark_seen(self, category: str, identifier: str) -> None:
        bucket = self._data["seen"].setdefault(category, [])
        if identifier not in bucket:
            bucket.append(identifier)
            self._save()

    def get_pointer(self, name: str) -> str | None:
        return self._data["pointers"].get(name)

    def set_pointer(self, name: str, value: str) -> None:
        self._data["pointers"][name] = value
        self._save()

    def list_clients(self) -> list[dict[str, str]]:
        """Read an optional "clients" list from the state file."""
        return self._data.get("clients", [])

    def add_client(self, name: str, version: str, contact: str = "") -> None:
        self._data.setdefault("clients", []).append({"name": name, "version": version, "contact": contact})
        self._save()

    def remove_client(self, name: str) -> int:
        recorded = self._data.get("clients", [])
        target = name.strip().lower()
        keep = [c for c in recorded if str(c.get("name", "")).strip().lower() != target]
        removed = len(recorded) - len(keep)
        if removed:
            self._data["clients"] = keep
            self._save()
        return removed
