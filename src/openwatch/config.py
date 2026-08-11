"""Runtime configuration loaded from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .profiles import DEFAULT_REPO, get_profile, normalise_repo

DEFAULT_DUCKDB = "openwatch.duckdb"  # One database for every watched repo; rows carry the repo.


@dataclass
class Config:
    """Watcher run configuration; every field defaults from an env var."""

    repo: str = field(default_factory=lambda: os.environ.get("WATCH_REPO", DEFAULT_REPO))
    # LTS lifecycle source. Derived from the repo profile unless the env vars pin it.
    docs_repo: str | None = field(default_factory=lambda: os.environ.get("LTS_DOCS_REPO") or None)
    lts_doc_path: str | None = field(default_factory=lambda: os.environ.get("LTS_DOC_PATH") or None)
    github_token: str | None = field(default_factory=lambda: os.environ.get("GITHUB_TOKEN"))
    # Opt into the JSON backend by naming a file; blank leaves storage to DuckDB.
    # One file holds one repo, so watching several needs one path each.
    state_file: str = field(default_factory=lambda: os.environ.get("WATCHER_STATE_FILE", ""))
    eol_reminder_days: int = 90
    # Newest-first cap on how many releases to fetch; 0 fetches every one. Large repos
    # (kubernetes, grafana) have thousands, which is a lot of unauthenticated API calls.
    max_releases: int = field(default_factory=lambda: int(os.environ.get("MAX_RELEASES", "0")))
    # Fetch CISA KEV + EPSS to rank findings by real-world exploitation. Off makes runs
    # fully offline-ish (GitHub only) at the cost of priority accuracy.
    enrich_exploit_signals: bool = field(
        default_factory=lambda: os.environ.get("ENRICH_EXPLOIT_SIGNALS", "1") not in ("0", "false", "no")
    )
    # Optional JSON client registry; takes precedence over the storage backend's Clients table.
    clients_file: str = field(default_factory=lambda: os.environ.get("CLIENTS_FILE", ""))
    # DuckDB database to store state in - a file path, or a MotherDuck connection string
    # ("md:openwatch"). Blank means the default database; see duckdb_path().
    duckdb_database: str = field(default_factory=lambda: os.environ.get("OPENWATCH_DUCKDB", ""))

    # Backs the still-stubbed integrations (see the corresponding modules).
    exa_api_key: str | None = field(default_factory=lambda: os.environ.get("EXA_API_KEY"))
    parallel_api_key: str | None = field(default_factory=lambda: os.environ.get("PARALLEL_API_KEY"))
    slack_webhook_url: str | None = field(default_factory=lambda: os.environ.get("SLACK_WEBHOOK_URL"))
    smtp_host: str | None = field(default_factory=lambda: os.environ.get("SMTP_HOST"))
    google_service_account_json: str | None = field(
        default_factory=lambda: os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON")
    )
    google_spreadsheet_id: str | None = field(default_factory=lambda: os.environ.get("GOOGLE_SPREADSHEET_ID"))

    def __post_init__(self) -> None:
        # Remembered so switching repos re-derives the LTS source instead of keeping
        # the previous repo's, while an explicit env override still wins every time.
        self._lts_overrides = (self.docs_repo, self.lts_doc_path)
        self.set_repo(self.repo)

    def set_repo(self, repo: str) -> None:
        """Point the run at a repo, filling in whatever its profile knows.

        Raises ValueError if the name isn't in owner/name form.
        """
        self.repo = normalise_repo(repo)
        profile = get_profile(self.repo)
        docs_repo, doc_path = self._lts_overrides
        self.docs_repo = docs_repo or profile.lts_docs_repo
        self.lts_doc_path = doc_path or profile.lts_doc_path

    @property
    def tracks_lts(self) -> bool:
        return bool(self.docs_repo and self.lts_doc_path)

    @property
    def project_name(self) -> str:
        """Short, human-facing name for the watched project, e.g. "prometheus"."""
        return self.repo.split("/")[-1]

    def duckdb_path(self) -> str:
        """Which DuckDB database to use - one shared file unless an env var points elsewhere.

        Unlike the JSON file there is no per-repo path, because every row records the
        repo it belongs to and each run reads back only its own.
        """
        return self.duckdb_database or DEFAULT_DUCKDB

    @classmethod
    def from_env(cls) -> "Config":
        return cls()
