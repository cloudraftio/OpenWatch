"""CLI entrypoint (`promwatch`)."""
from __future__ import annotations

import argparse
import logging
import os
import sys

from . import clients as clients_mod
from . import semver
from .config import Config
from .github_releases import GitHubReleasesClient, RepoNotFound
from .notify.base import Notifier
from .notify.console import ConsoleNotifier
from .pipeline import run_once
from .profiles import DEFAULT_REPO, normalise_repo
from .storage.base import Storage
from .storage.local_json import LocalJSONStorage

logger = logging.getLogger(__name__)


def build_notifiers(config: Config) -> list[Notifier]:
    notifiers: list[Notifier] = [ConsoleNotifier()]
    # Slack/Email notifiers are stubs - append here once implemented.
    return notifiers


def build_storage(config: Config) -> Storage:
    """Use Google Sheets when both its env vars are set, otherwise the local JSON file."""
    # Half-configured Sheets is nearly always a shell that never sourced .env, so say
    # so rather than quietly writing to a local file the user won't think to look in.
    if bool(config.google_service_account_json) != bool(config.google_spreadsheet_id):
        missing = "GOOGLE_SERVICE_ACCOUNT_JSON" if config.google_spreadsheet_id else "GOOGLE_SPREADSHEET_ID"
        logger.warning("%s is not set, so Google Sheets is skipped and state stays local.", missing)
    if config.google_service_account_json and config.google_spreadsheet_id:
        from .storage.google_sheets import GoogleSheetsStorage  # Imported lazily; gspread is an extra.

        logger.info("Using Google Sheets storage (spreadsheet %s)", config.google_spreadsheet_id)
        return GoogleSheetsStorage(
            config.google_service_account_json, config.google_spreadsheet_id, repo=config.repo
        )
    path = config.state_file_path()
    logger.info("Using local JSON storage (%s)", path)
    return LocalJSONStorage(path)


def _prompt(label: str, required: bool) -> str:
    """Ask for one field, re-prompting only while a required answer is blank."""
    while True:
        try:
            value = input(label).strip()
        except EOFError:
            return ""  # Non-interactive stdin; treat as "not provided" rather than crashing.
        if value or not required:
            return value
        print("  A client name is required.")


def resolve_repo(config: Config, requested: str | None) -> None:
    """Settle which repository this run watches, asking interactively when nothing was given.

    Order of precedence: --repo, then WATCH_REPO, then an interactive prompt, then the
    built-in default. Automation never reaches the prompt, so it can't hang.
    """
    explicit = requested or os.environ.get("WATCH_REPO")
    if explicit:
        config.set_repo(explicit)  # ValueError here is caught in main() and reported.
        return
    if not sys.stdin.isatty():
        return  # cron/CI keeps the default rather than waiting on an answer.

    print("Which open-source repo do you want to watch?")
    print(f"Give it as owner/name or a GitHub URL. Press Enter for {DEFAULT_REPO}.\n")
    while True:
        answer = _prompt(f"  Repository [{DEFAULT_REPO}]: ", required=False)
        if not answer:
            print(f"  Watching {config.repo}.\n")
            return
        try:
            repo = normalise_repo(answer)
        except ValueError as exc:
            print(f"  {exc}")
            continue
        if not _repo_exists(repo, config.github_token):
            print(f"  {repo} was not found on GitHub. Check the spelling, or set GITHUB_TOKEN for a private repo.")
            continue
        config.set_repo(repo)
        extra = "" if config.tracks_lts else " (no LTS lifecycle table known, so that section is skipped)"
        print(f"  Watching {config.repo}{extra}.\n")
        return


def _repo_exists(repo: str, token: str | None) -> bool:
    """Check a typed repo name against GitHub, treating an API outage as "probably fine"."""
    try:
        return GitHubReleasesClient(repo=repo, token=token).repo_exists()
    except Exception as exc:  # Rate limit or network trouble shouldn't block a valid answer.
        logger.debug("Could not verify %s: %s", repo, exc)
        return True


def prompt_for_clients_if_empty(config: Config, storage: Storage) -> None:
    """On an interactive run with nothing recorded, offer to record clients; never blocks automation."""
    if config.clients_file:
        return  # The registry comes from a file; recording here wouldn't be used.
    if not sys.stdin.isatty():
        return  # cron/CI has no one to answer, so stay silent and fall back to broadcast.
    if storage.list_clients():
        return
    print("No clients recorded yet, so advisories would go out as one common digest.")
    print("Add clients to get per-version risk mapping, or press Enter to skip.\n")
    while True:
        name = _prompt("  Client name (blank to skip): ", required=False)
        if not name:
            print()
            return
        version = _prompt(f"  {config.project_name} version (blank if unknown): ", required=False)
        contact = _prompt("  Contact (optional): ", required=False)
        if version and semver.parse(version) is None:
            print(f"  Warning: {version!r} is not a recognisable version; it will need manual review.")
        storage.add_client(name=name, version=version, contact=contact)
        print(f"  Recorded {name!r} on version {version or '(unknown)'}.\n")


def cmd_add_client(config: Config, storage: Storage, args) -> int:
    """Record one client, prompting for anything not supplied as a flag."""
    name = args.name or _prompt("Client name: ", required=True)
    if not name:
        print("No client name given; nothing recorded.")
        return 1
    version = (
        args.version
        if args.version is not None
        else _prompt(f"{config.project_name} version (blank if unknown): ", False)
    )
    contact = args.contact if args.contact is not None else _prompt("Contact (optional): ", False)

    if version and semver.parse(version) is None:
        # Recorded anyway - the risk mapper reports it as "needs review" rather than dropping the client.
        print(
            f"Warning: {version!r} is not a full version, so advisories cannot be mapped against it.\n"
            f"         Use MAJOR.MINOR.PATCH (e.g. {version}.0 rather than {version})."
            if version.count(".") == 1
            else f"Warning: {version!r} is not a recognisable version; advisories cannot be mapped against it.\n"
            "         Use MAJOR.MINOR.PATCH, e.g. 3.4.0."
        )
    if not version:
        print("Warning: no version recorded; this client's advisories will all need manual review.")

    existing = {str(row.get("name", "")).strip().lower() for row in storage.list_clients()}
    if name.strip().lower() in existing:
        print(f"Warning: a client named {name!r} is already recorded; adding another row.")

    storage.add_client(name=name, version=version, contact=contact)
    storage.flush()
    print(f"Recorded client {name!r} on {config.project_name} version {version or '(unknown)'}.")
    if config.clients_file:
        print(f"Note: CLIENTS_FILE={config.clients_file} is set and takes precedence over stored clients.")
    return 0


def cmd_remove_client(storage: Storage, args) -> int:
    """Drop every row recorded under a client name."""
    removed = storage.remove_client(args.name)
    storage.flush()
    if not removed:
        print(f"No client named {args.name!r} is recorded.")
        return 1
    print(f"Removed {removed} row(s) for {args.name!r}.")
    return 0


def cmd_list_clients(config: Config, storage: Storage) -> int:
    """Show the registry the risk mapper will actually use."""
    registry = clients_mod.load_clients_file(config.clients_file)
    source = f"CLIENTS_FILE ({config.clients_file})" if registry else type(storage).__name__
    if not registry:
        registry = clients_mod.parse_clients(storage.list_clients())
    if not registry:
        print("No clients recorded - the watcher will send one common broadcast digest.")
        return 0
    print(f"{len(registry)} client(s) from {source}:")
    for client in registry:
        state = str(client.version) if client.version else f"{client.raw_version or '(none)'} - unusable"
        print(f"  {client.name:<24} {state:<22} {client.contact or ''}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="promwatch", description="Release & Security Watcher for any open-source GitHub repo"
    )
    parser.add_argument(
        "--repo",
        default=None,
        help=f"GitHub repo to watch, as owner/name or a URL. Asked for interactively if omitted "
        f"(default: {DEFAULT_REPO})",
    )
    parser.add_argument("--state-file", default=None, help="Path to the local JSON state store")
    parser.add_argument(
        "--max-releases", type=int, default=None, help="Only fetch the N newest releases (0 = all)"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run", help="Run the watcher pipeline (default)")
    add = sub.add_parser("add-client", help="Record a client name and the version they run")
    add.add_argument("--name", default=None, help="Client name; prompted for if omitted")
    add.add_argument("--version", default=None, help="The version they run; prompted for if omitted")
    add.add_argument("--contact", default=None, help="Email/channel to target; prompted for if omitted")
    remove = sub.add_parser("remove-client", help="Remove every row recorded under a client name")
    remove.add_argument("--name", required=True, help="Client name to remove")
    sub.add_parser("list-clients", help="Show the recorded clients")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(message)s")

    config = Config.from_env()
    if args.state_file:
        config.state_file = args.state_file
    if args.max_releases is not None:
        config.max_releases = args.max_releases
    try:
        resolve_repo(config, args.repo)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    try:
        storage = build_storage(config)
    except Exception as exc:
        if "429" in str(exc) or "Quota exceeded" in str(exc):
            raise SystemExit(
                "Google Sheets read quota exceeded (60 requests/minute). Wait a minute and retry."
            ) from exc
        raise

    if args.command == "add-client":
        return cmd_add_client(config, storage, args)
    if args.command == "remove-client":
        return cmd_remove_client(storage, args)
    if args.command == "list-clients":
        return cmd_list_clients(config, storage)

    prompt_for_clients_if_empty(config, storage)
    try:
        run_once(config=config, storage=storage, notifiers=build_notifiers(config))
    except RepoNotFound as exc:
        raise SystemExit(str(exc)) from exc
    return 0


if __name__ == "__main__":
    sys.exit(main())
