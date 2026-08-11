"""Google Sheets storage backend; needs a service account and `pip install -e ".[sheets]"`."""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

from .base import Storage

logger = logging.getLogger(__name__)

SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]
CATEGORY_WORKSHEETS = {"release": "Releases", "advisory": "Advisories", "client_risk": "NotifiedRisks"}
POINTER_WORKSHEET = "State"
CLIENT_WORKSHEET = "Clients"

# Every worksheet leads with the repo it belongs to, so one spreadsheet can track
# several projects and every row says which one it is about.
REPO_COLUMN = "repo"
HEADERS = {
    "Releases": [REPO_COLUMN, "tag", "first_seen"],
    "Advisories": [REPO_COLUMN, "cve_id", "first_seen"],
    "NotifiedRisks": [REPO_COLUMN, "client_and_cve", "first_seen"],
    POINTER_WORKSHEET: [REPO_COLUMN, "key", "value"],
    CLIENT_WORKSHEET: [REPO_COLUMN, "name", "version", "contact"],
}


def _credentials(raw: str):
    """Build service-account credentials from either a raw JSON blob or a path to the key file."""
    from google.oauth2.service_account import Credentials

    if os.path.exists(raw):
        with open(raw, encoding="utf-8") as f:
            info = json.load(f)
    else:
        info = json.loads(raw)
    return Credentials.from_service_account_info(info, scopes=SCOPES)


class GoogleSheetsStorage(Storage):
    """Sheets-backed store that reads once into memory and buffers writes to stay inside API quota.

    Scoped to one repo: reads ignore other projects' rows and writes stamp the repo, so
    several watchers can share a spreadsheet without reading each other's state.
    """

    scopes_by_repo = True

    def __init__(self, service_account_json: str, spreadsheet_id: str, repo: str = ""):
        try:
            import gspread
        except ModuleNotFoundError as exc:  # The Sheets deps are an opt-in extra.
            raise SystemExit(
                "Google Sheets storage needs the 'sheets' extra:\n"
                '    pip install -e ".[sheets]"\n'
                "(or unset GOOGLE_SPREADSHEET_ID to use the local JSON file instead)"
            ) from exc

        self._gspread = gspread
        self._sheet = gspread.authorize(_credentials(service_account_json)).open_by_key(spreadsheet_id)
        self.repo = repo
        self._pending: dict[str, list[list[str]]] = {}
        self._seen: dict[str, set[str]] = {}
        self._pointers: dict[str, str] = {}
        self._other_pointers: list[list[str]] = []  # Other repos' State rows, preserved on rewrite.
        self._pointers_dirty = False
        self._loaded = False
        self._legacy_repo: str | None = None

    # --- Sheet access -------------------------------------------------

    def _worksheet(self, title: str):
        """Return the named worksheet, creating it with its header row if it doesn't exist yet."""
        try:
            return self._sheet.worksheet(title)
        except self._gspread.WorksheetNotFound:
            worksheet = self._sheet.add_worksheet(title=title, rows=1000, cols=len(HEADERS[title]))
            worksheet.append_row(HEADERS[title], value_input_option="RAW")
            return worksheet

    def _rows(self, title: str) -> list[list[str]]:
        """All rows of a worksheet including the header, migrating a pre-repo-column sheet first."""
        worksheet = self._worksheet(title)
        values = worksheet.get_all_values()
        if not values:
            worksheet.append_row(HEADERS[title], value_input_option="RAW")
            return [HEADERS[title]]
        if values[0] and values[0][0].strip().lower() == REPO_COLUMN:
            return values
        return self._add_repo_column(worksheet, title, values)

    def _add_repo_column(self, worksheet, title: str, values: list[list[str]]) -> list[list[str]]:
        """One-time upgrade of a spreadsheet written before rows carried a repo."""
        owner = self._legacy_owner()
        rows = [HEADERS[title]] + [[owner] + row for row in values[1:] if any(cell.strip() for cell in row)]
        worksheet.clear()
        worksheet.batch_update([{"range": "A1", "values": rows}])
        logger.info("Added a %r column to %s; %d existing row(s) credited to %s.", REPO_COLUMN, title, len(rows) - 1, owner)
        return rows

    def _legacy_owner(self) -> str:
        """Which repo the pre-upgrade rows belong to, per the old unscoped "repo" pointer."""
        if self._legacy_repo is not None:
            return self._legacy_repo
        self._legacy_repo = self.repo  # Fallback: a sheet only this run has ever written.
        for row in self._worksheet(POINTER_WORKSHEET).get_all_values()[1:]:
            cells = [cell.strip() for cell in row]
            if len(cells) >= 2 and cells[0] == "repo" and cells[1]:
                self._legacy_repo = cells[1]
                break
        return self._legacy_repo

    def _mine(self, row: list[str]) -> bool:
        return bool(row) and row[0].strip().lower() == self.repo.lower()

    def _ensure_loaded(self) -> None:
        """Read this repo's seen-sets and pointers once, and only when something needs them.

        Client-registry commands never touch these worksheets, so deferring keeps their
        cost to a single read instead of one per worksheet.
        """
        if self._loaded:
            return
        self._loaded = True  # Set first so a failure mid-load can't trigger an infinite retry.
        for category, title in CATEGORY_WORKSHEETS.items():
            rows = self._rows(title)[1:]
            self._seen[category] = {row[1] for row in rows if len(row) >= 2 and self._mine(row)}
        for row in self._rows(POINTER_WORKSHEET)[1:]:
            if len(row) < 3 or not row[1].strip():
                continue
            if self._mine(row):
                self._pointers[row[1]] = row[2]
            else:
                self._other_pointers.append(row[:3])

    # --- Storage interface --------------------------------------------

    def has_seen(self, category: str, identifier: str) -> bool:
        self._ensure_loaded()
        return identifier in self._seen.get(category, set())

    def mark_seen(self, category: str, identifier: str) -> None:
        if self.has_seen(category, identifier):
            return
        self._seen.setdefault(category, set()).add(identifier)
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._pending.setdefault(category, []).append([self.repo, identifier, stamp])

    def get_pointer(self, name: str) -> str | None:
        self._ensure_loaded()
        return self._pointers.get(name)

    def set_pointer(self, name: str, value: str) -> None:
        self._ensure_loaded()
        if self._pointers.get(name) != value:
            self._pointers[name] = value
            self._pointers_dirty = True

    def list_clients(self) -> list[dict[str, str]]:
        """Read this repo's rows from the Clients worksheet, mapping the header onto each."""
        rows = self._rows(CLIENT_WORKSHEET)
        header = [cell.strip().lower() for cell in rows[0]]
        return [dict(zip(header, row)) for row in rows[1:] if self._mine(row)]

    def add_client(self, name: str, version: str, contact: str = "") -> None:
        self._rows(CLIENT_WORKSHEET)  # Ensures the repo column exists before appending to it.
        self._worksheet(CLIENT_WORKSHEET).append_row(
            [self.repo, name, version, contact], value_input_option="RAW"
        )

    def remove_client(self, name: str) -> int:
        """Remove matching rows for this repo only; another project's client of the same name stays."""
        rows = self._rows(CLIENT_WORKSHEET)
        target = name.strip().lower()
        matches = [
            i
            for i, row in enumerate(rows[1:], start=2)
            if len(row) >= 2 and self._mine(row) and row[1].strip().lower() == target
        ]
        worksheet = self._worksheet(CLIENT_WORKSHEET)
        for index in reversed(matches):  # Delete bottom-up so the earlier indices stay valid.
            worksheet.delete_rows(index)
        return len(matches)

    def flush(self) -> None:
        """Write everything buffered so far - one API call per worksheet actually touched."""
        for category, rows in self._pending.items():
            if rows:
                self._worksheet(CATEGORY_WORKSHEETS[category]).append_rows(rows, value_input_option="RAW")
        self._pending.clear()
        if self._pointers_dirty:
            # Sorted so each project's pointers sit together rather than interleaved.
            mine = [[self.repo, key, value] for key, value in self._pointers.items()]
            body = sorted(self._other_pointers + mine, key=lambda row: (row[0].lower(), row[1]))
            worksheet = self._worksheet(POINTER_WORKSHEET)
            worksheet.clear()
            worksheet.batch_update([{"range": "A1", "values": [HEADERS[POINTER_WORKSHEET]] + body}])
            self._pointers_dirty = False
