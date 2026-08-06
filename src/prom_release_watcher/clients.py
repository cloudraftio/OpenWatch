"""Client registry - manually recorded upstream versions, used for targeted risk mapping."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Iterable, Mapping

from . import semver
from .semver import Version


@dataclass(frozen=True)
class Client:
    """A client and the version of the watched project they are recorded as running."""

    name: str
    raw_version: str
    version: Version | None
    contact: str | None = None


def parse_clients(records: Iterable[Mapping[str, str]]) -> list[Client]:
    """Build Clients from raw registry rows, tolerating missing or unparseable versions."""
    clients = []
    for record in records:
        name = str(record.get("name") or "").strip()
        if not name:
            continue  # A row without a name isn't a usable client record.
        raw_version = str(record.get("version") or "").strip()
        contact = str(record.get("contact") or "").strip() or None
        clients.append(
            Client(
                name=name,
                raw_version=raw_version,
                version=semver.parse(raw_version) if raw_version else None,
                contact=contact,
            )
        )
    return clients


def load_clients_file(path: str) -> list[Client]:
    """Load clients from a standalone JSON file - a list of {name, version, contact} objects."""
    if not path or not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return parse_clients(json.load(f))
