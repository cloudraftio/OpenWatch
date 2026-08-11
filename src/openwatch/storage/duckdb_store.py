"""DuckDB storage backend - the default.

The database is either a local file or a MotherDuck connection string ("md:openwatch"),
which is the same client either way - only the string passed to `duckdb.connect` differs.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from .base import Storage

logger = logging.getLogger(__name__)

# DuckDB rounds a database file up to whole blocks, so its default 256KB block costs
# ~500KB for the handful of rows a watcher stores. 16KB blocks bring that to ~45KB,
# which matters because CI commits this file back on every run. Only settable at
# creation - passing it for an existing file whose blocks differ is an error.
BLOCK_SIZE = 16384

# Every table leads with the repo the row belongs to, so one database can track several
# projects and every row says which one it is about - the same layout the Sheets backend uses.
SCHEMA = """
CREATE TABLE IF NOT EXISTS seen (
    repo        VARCHAR     NOT NULL,
    category    VARCHAR     NOT NULL,
    identifier  VARCHAR     NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (repo, category, identifier)
);
CREATE TABLE IF NOT EXISTS pointers (
    repo   VARCHAR NOT NULL,
    "key"  VARCHAR NOT NULL,
    "value" VARCHAR,
    PRIMARY KEY (repo, "key")
);
CREATE TABLE IF NOT EXISTS clients (
    repo     VARCHAR NOT NULL,
    name     VARCHAR NOT NULL,
    version  VARCHAR,
    contact  VARCHAR
);
"""

CLIENT_COLUMNS = ("repo", "name", "version", "contact")


class DuckDBStorage(Storage):
    """DuckDB-backed store, scoped to one repo.

    Reads ignore other projects' rows and writes stamp the repo, so several watchers can
    share a database without reading each other's state. Writes land immediately - DuckDB
    is transactional, so there is nothing to batch for quota reasons the way Sheets needs.
    """

    scopes_by_repo = True

    def __init__(self, database: str, repo: str = ""):
        try:
            import duckdb
        except ModuleNotFoundError as exc:  # A core dependency, so this means a broken install.
            raise SystemExit(
                "DuckDB storage needs the duckdb package:\n"
                "    pip install -e .\n"
                "(or set WATCHER_STATE_FILE to use the local JSON file instead)"
            ) from exc

        self.database = database
        self.repo = repo
        self._conn = self._connect(duckdb, database)
        self._conn.execute(SCHEMA)
        # This repo's seen identifiers, read once so a run of N findings costs one query
        # rather than N - which matters when the database is remote (MotherDuck).
        self._seen: dict[str, set[str]] | None = None

    # --- Internals ----------------------------------------------------

    @staticmethod
    def _connect(duckdb, database: str):
        """Open the database, giving a newly created file small blocks to keep it compact.

        MotherDuck and in-memory databases take neither the ATTACH detour nor BLOCK_SIZE.
        """
        if database.startswith("md:") or database == ":memory:":
            return duckdb.connect(database)
        conn = duckdb.connect()
        # ATTACH takes no bound parameters, so the path goes in as an escaped literal.
        literal = database.replace("'", "''")
        options = f" (BLOCK_SIZE {BLOCK_SIZE})" if not os.path.exists(database) else ""
        conn.execute(f"ATTACH '{literal}' AS openwatch{options}")
        conn.execute("USE openwatch")
        return conn

    def _load_seen(self) -> dict[str, set[str]]:
        if self._seen is None:
            self._seen = {}
            rows = self._conn.execute(
                "SELECT category, identifier FROM seen WHERE lower(repo) = lower(?)", [self.repo]
            ).fetchall()
            for category, identifier in rows:
                self._seen.setdefault(category, set()).add(identifier)
        return self._seen

    # --- Storage interface --------------------------------------------

    def has_seen(self, category: str, identifier: str) -> bool:
        return identifier in self._load_seen().get(category, set())

    def mark_seen(self, category: str, identifier: str) -> None:
        if self.has_seen(category, identifier):
            return
        self._load_seen().setdefault(category, set()).add(identifier)
        # ON CONFLICT DO NOTHING keeps the original first_seen if another watcher raced us.
        self._conn.execute(
            "INSERT INTO seen (repo, category, identifier, first_seen) VALUES (?, ?, ?, ?) "
            "ON CONFLICT DO NOTHING",
            [self.repo, category, identifier, datetime.now(timezone.utc)],
        )

    def get_pointer(self, name: str) -> str | None:
        row = self._conn.execute(
            'SELECT "value" FROM pointers WHERE lower(repo) = lower(?) AND "key" = ?', [self.repo, name]
        ).fetchone()
        return row[0] if row else None

    def set_pointer(self, name: str, value: str) -> None:
        self._conn.execute(
            'INSERT INTO pointers (repo, "key", "value") VALUES (?, ?, ?) '
            'ON CONFLICT (repo, "key") DO UPDATE SET "value" = excluded."value"',
            [self.repo, name, value],
        )

    def list_clients(self) -> list[dict[str, str]]:
        rows = self._conn.execute(
            "SELECT repo, name, version, contact FROM clients WHERE lower(repo) = lower(?) ORDER BY name",
            [self.repo],
        ).fetchall()
        return [dict(zip(CLIENT_COLUMNS, ["" if cell is None else str(cell) for cell in row])) for row in rows]

    def add_client(self, name: str, version: str, contact: str = "") -> None:
        self._conn.execute(
            "INSERT INTO clients (repo, name, version, contact) VALUES (?, ?, ?, ?)",
            [self.repo, name, version, contact],
        )

    def remove_client(self, name: str) -> int:
        """Remove matching rows for this repo only; another project's client of the same name stays."""
        removed = self._conn.execute(
            "SELECT count(*) FROM clients WHERE lower(repo) = lower(?) AND lower(trim(name)) = ?",
            [self.repo, name.strip().lower()],
        ).fetchone()[0]
        if removed:
            self._conn.execute(
                "DELETE FROM clients WHERE lower(repo) = lower(?) AND lower(trim(name)) = ?",
                [self.repo, name.strip().lower()],
            )
        return removed

    def flush(self) -> None:
        """Checkpoint the write-ahead log so the database file on disk is complete and standalone.

        Writes are already committed; without this the WAL is only folded in when the
        connection closes, which leaves a stray .wal beside a file CI is about to upload.
        """
        try:
            self._conn.execute("CHECKPOINT")
        except Exception:  # MotherDuck and read-only attachments reject CHECKPOINT; harmless.
            logger.debug("CHECKPOINT skipped for %s", self.database, exc_info=True)

    def close(self) -> None:
        self._conn.close()
