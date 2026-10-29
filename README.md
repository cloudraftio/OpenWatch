# Release & Security Watcher

POC. This proof of concept keeps an eye on an open-source GitHub project for new releases, security advisories, CVEs, and LTS (Long-Term Support) updates. Instead of sending every client the same generic update, it checks which version each client is running and only reports the changes that are actually relevant to them.

Any public GitHub repository works — Prometheus is just the default.

## How to run

```bash
python -m venv .venv && source .venv/bin/activate

pip install -e .

openwatch run
```

An interactive run starts by asking which repo to watch:

```text
Which open-source repo do you want to watch?
Give it as owner/name or a GitHub URL. Press Enter for prometheus/prometheus.

  Repository [prometheus/prometheus]: grafana/grafana
```

The answer is checked against GitHub before the run starts, so a typo is
caught immediately rather than 404-ing mid-run. To skip the question, name
the repo up front — this is also how scheduled runs pick their target, since
nothing is ever prompted when stdin isn't a terminal:

```bash
openwatch --repo grafana/grafana run       # owner/name or a full GitHub URL
WATCH_REPO=hashicorp/vault openwatch run   # same thing, via the environment
```

### What differs per repo

| | Behaviour |
|---|---|
| Releases and tags | Read from the GitHub API. Repos that publish no Releases fall back to their git tags (no changelog text). |
| Changelogs | Prometheus-style `* [SECURITY] ...` bullets are parsed exactly. Projects that don't tag their bullets fall back to keyword categorisation, so security items are still picked out. |
| CVEs | Any `CVE-…` mentioned anywhere in a release body is collected, for every project. |
| LTS lifecycle | Only for projects known to publish a "List of LTS releases" markdown table. Prometheus ships with one out of the box; see [profiles.py](src/openwatch/profiles.py) to add another, or set `LTS_DOCS_REPO` / `LTS_DOC_PATH`. Other repos simply run without that section. |

### Reports

`openwatch report` shows where every client stands right now — unlike the digest, it
ignores what has already been notified, so it is complete every time.

```bash
openwatch report                              # markdown to stdout
openwatch report -o report.html               # self-contained HTML, printable
openwatch report --priority act-now           # only what needs acting on today
```

Each CVE is ranked from three independent signals, so you can see which one fired:

| Signal | Source | Answers |
|---|---|---|
| Severity / CVSS | the project's own GitHub Security Advisories | how bad is it |
| CISA KEV | `known_exploited_vulnerabilities.json` | is it being exploited right now |
| EPSS | FIRST.org | how likely is exploitation in the next 30 days |
| Applicability | the client's recorded version vs. the fixing releases | can it reach *this* client |

Priorities are `act now` (applicable **and** exploited in the wild, or high severity and
reachable pre-auth), `patch soon`, `schedule`, and `review` (exposure unresolved).
`--priority` sets the floor for what gets listed; the counts always cover everything
evaluated, and a client whose findings were all filtered out reads "below filter"
rather than "clear".

Set `ENRICH_EXPLOIT_SIGNALS=0` to skip the KEV and EPSS fetches.

Set `SLACK_WEBHOOK_URL` to an [incoming webhook](https://api.slack.com/messaging/webhooks)
and every `openwatch report` also posts a summary to that channel: each client's status,
its most urgent CVEs, the upgrade that clears them, and the CVEs by blast radius. Webhooks
can't carry files, so the full HTML/markdown report stays wherever `-o` wrote it. A failed
post makes the command exit non-zero, so a broken webhook doesn't go unnoticed.

### Clients

The first interactive run asks for client names and the version each one
runs, so advisories can be mapped per client. Press Enter at the name prompt
to skip and get one common digest instead. Manage them later with:

```bash
openwatch add-client --name "<name>" --version <version> --contact <email>
openwatch list-clients
openwatch remove-client --name "<name>"
```

Clients are recorded per repo, since a version number only means something
against the project it belongs to.

## Watching more than one repo

**Google Sheets:** one spreadsheet holds as many projects as you like. Every
worksheet leads with a `repo` column naming the project each row belongs to,
so nothing is ambiguous:

| repo | tag | first_seen |
|------|-----|------------|
| prometheus/prometheus | v3.13.2 | 2026-07-31T08:18:01+00:00 |
| grafana/grafana | v13.1.2 | 2026-08-06T06:55:37+00:00 |

Each run reads and writes only its own repo's rows, so watchers can't see or
overwrite each other's state. Clients are scoped the same way — "Acme Corp" on
Prometheus 3.5.2 and "Acme Corp" on Grafana 12.4.0 are separate records. To
read one project at a time in the browser, sort or filter by the `repo` column.

Spreadsheets written before this column existed are upgraded automatically on
the next run, with every existing row credited to the repo that wrote it.

**DuckDB:** one database holds as many projects as you like, scoped the same way
— every table leads with a `repo` column and each run reads and writes only its
own rows.

**Local JSON:** a file holds one project, so watching several means one
`WATCHER_STATE_FILE` path each. A run that finds another repo's data in its file
stops rather than mixing the two.

## Running it on a schedule

[`scripts/watch.sh`](scripts/watch.sh) does one full scheduled run, and the
host's own cron runs it. Put the settings in a `.env` file at the repo root
(cron starts with an almost empty environment, so the script loads it itself),
with `WATCH_REPOS` listing the projects to track, space separated:

```bash
WATCH_REPOS="prometheus/prometheus cloudnative-pg/cloudnative-pg"
GITHUB_TOKEN=<token>
SLACK_WEBHOOK_URL=<webhook>   # optional
```

Then add it to your crontab (`crontab -e`) — this runs daily at 06:00 and keeps
a log:

```cron
0 6 * * * /path/to/OpenWatch/scripts/watch.sh >> /path/to/OpenWatch/watch.log 2>&1
```

Run `scripts/watch.sh` by hand once first to check it works. It uses the
`.venv` (or `venv`) entry point when there is one, since cron's `PATH` won't
include it; set `OPENWATCH_BIN` to use a different one.

Each run watches every listed repo in turn, then renders a client exposure
report per repo into `reports/<owner>-<name>.md`. State stays in the local
database, so the machine running cron is the one that keeps it — or point
`OPENWATCH_DUCKDB` at MotherDuck to keep it off the machine.

Repos are processed sequentially, because DuckDB takes one writer at a time.
For the same reason a run that starts while another is still going skips
itself rather than failing midway.

Clients are read from whatever is already recorded, so `add-client` is a one-off
setup step per repo — the schedule picks them up from then on. A repo with no
clients still gets watched, it just has no fleet to report on, and the run says
so instead of failing.

## Storing data in DuckDB

DuckDB is the default backend and needs no configuration — `openwatch run`
creates `openwatch.duckdb` in the working directory and stores everything there.
`OPENWATCH_DUCKDB` (or `--duckdb <database>` for a single run) points it
somewhere else. The first line of the output confirms which backend is in use:

```text
Using DuckDB storage (openwatch.duckdb)
```

The database is created on first use with three tables:

| Table | Columns |
|-------|---------|
| `seen` | `repo`, `category`, `identifier`, `first_seen` |
| `pointers` | `repo`, `key`, `value` |
| `clients` | `repo`, `name`, `version`, `contact` |

`category` is `release`, `advisory`, or `client_risk` — the three worksheets
the Sheets backend keeps separate, folded into one table. Query it with any
DuckDB client:

```sql
SELECT repo, identifier AS cve, first_seen
FROM seen WHERE category = 'advisory' ORDER BY first_seen DESC LIMIT 10;
```

DuckDB is a single-writer embedded database, so run one watcher at a time
against a given file. To share one database between machines, point `OPENWATCH_DUCKDB` at a
[MotherDuck](https://motherduck.com) database instead — the connection string is
the only difference:

```bash
export MOTHERDUCK_TOKEN=<token>
export OPENWATCH_DUCKDB=md:openwatch
```

New database files are created with 16KB blocks rather than DuckDB's 256KB
default, which keeps a watcher's worth of state at roughly 45KB instead of
500KB, which matters when the database is committed to the repo.

### Which backend a run uses

The first match wins:

1. `OPENWATCH_DUCKDB` or `--duckdb` — DuckDB at that database.
2. `GOOGLE_SERVICE_ACCOUNT_JSON` **and** `GOOGLE_SPREADSHEET_ID` — Google Sheets.
3. `WATCHER_STATE_FILE` or `--state-file` — the JSON file at that path.
4. Nothing set — DuckDB at `openwatch.duckdb`.

Switching backends does not carry state across. A backend that has never seen a
repo treats every existing release and CVE as new on its first run.

## Storing data in Google Sheets

Sheets is the backend to pick when people other than the watcher need to read or
edit the data by hand — the `Clients` worksheet especially. Install the optional
Sheets support and set the following environment variables before running the
watcher:

```bash
pip install -e ".[sheets]"

export GOOGLE_SERVICE_ACCOUNT_JSON=/path/to/service-account.json
export GOOGLE_SPREADSHEET_ID=<spreadsheet ID from the URL>

openwatch run
```

Both environment variables are required. If either one is missing, the watcher falls back to DuckDB, and says so rather than doing it silently. You can confirm which storage backend is being used by checking the first line of the output:

```text
Using Google Sheets storage
```

`GOOGLE_SERVICE_ACCOUNT_JSON` can point to the downloaded service account JSON file, or you can provide the JSON contents directly. This is especially useful in CI/CD systems where credentials are stored as secrets.

Since `export` only applies to the current terminal session, a convenient approach is to place these variables in a gitignored `.env` file and run:

```bash
source .env
```

before starting the watcher.

### Setting up Google Sheets access

To create the required service account:

1. Open the Google Cloud Console.
2. Enable the **Google Sheets API** for your project.
3. Go to **IAM & Admin → Service Accounts** and create a new service account.
4. Under **Keys**, create and download a JSON key.

Open the downloaded JSON file and copy the `client_email` value. Share your spreadsheet with that email address and give it **Editor** access. That's all the watcher needs—there's no need to sign in with your personal Google account.

On the first run, the watcher automatically creates five worksheets, each with
a leading `repo` column identifying the project the row belongs to:

| Worksheet | Columns |
|-----------|---------|
| `Releases` | `repo`, `tag`, `first_seen` |
| `Advisories` | `repo`, `cve_id`, `first_seen` |
| `State` | `repo`, `key`, `value` |
| `Clients` | `repo`, `name`, `version`, `contact` |
| `NotifiedRisks` | `repo`, `client_and_cve`, `first_seen` |

### Other environment variables

| Variable | Purpose |
|----------|---------|
| `WATCH_REPO` | Repo to watch, as `owner/name`. Skips the interactive question. Defaults to `prometheus/prometheus`. |
| `GITHUB_TOKEN` | Optional. Increases the GitHub API rate limit from **60 requests/hour** to **5,000 requests/hour**. Worth setting for large repos. |
| `WATCHER_STATE_FILE` | Opts into the JSON backend, storing state at this path. One repo per file. |
| `OPENWATCH_DUCKDB` | DuckDB database to store state in — a file path, or `md:<name>` for MotherDuck. Defaults to `openwatch.duckdb`. |
| `MAX_RELEASES` | Only fetch the N newest releases (`0`, the default, fetches all). Useful for repos with thousands of them. |
| `LTS_DOCS_REPO` / `LTS_DOC_PATH` | Point LTS tracking at a project's release-cycle markdown file, e.g. `prometheus/docs` + `docs/introduction/release-cycle.md`. |
| `CLIENTS_FILE` | Path to a JSON client registry. If provided, it takes precedence over the `Clients` worksheet. |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook. When set, `openwatch report` also posts the report to that channel. |

## Running the watcher multiple times

The watcher is designed to be idempotent, so running it repeatedly won't create duplicate records.

- Releases are tracked by their Git tag.
- Security advisories are tracked by CVE ID.
- Client notifications are tracked using the client and CVE combination.

If a run doesn't find anything new, it simply doesn't write any new rows. An unchanged database usually means the watcher is already up to date—not that something went wrong.
## License

OpenWatch is released under the [MIT License](LICENSE).
