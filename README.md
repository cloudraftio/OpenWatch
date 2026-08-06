# Open Source Governance

POC. This proof of concept keeps an eye on an open-source GitHub project for new releases, security advisories, CVEs, and LTS (Long-Term Support) updates. Instead of sending every client the same generic update, it checks which version each client is running and only reports the changes that are actually relevant to them.

Any public GitHub repository works — Prometheus is just the default.

## How to run

```bash
python -m venv .venv && source .venv/bin/activate

pip install -e .

promwatch run
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
promwatch --repo grafana/grafana run       # owner/name or a full GitHub URL
WATCH_REPO=hashicorp/vault promwatch run   # same thing, via the environment
```

### What differs per repo

| | Behaviour |
|---|---|
| Releases and tags | Read from the GitHub API. Repos that publish no Releases fall back to their git tags (no changelog text). |
| Changelogs | Prometheus-style `* [SECURITY] ...` bullets are parsed exactly. Projects that don't tag their bullets fall back to keyword categorisation, so security items are still picked out. |
| CVEs | Any `CVE-…` mentioned anywhere in a release body is collected, for every project. |
| LTS lifecycle | Only for projects known to publish a "List of LTS releases" markdown table. Prometheus ships with one out of the box; see [profiles.py](src/prom_release_watcher/profiles.py) to add another, or set `LTS_DOCS_REPO` / `LTS_DOC_PATH`. Other repos simply run without that section. |

### Clients

The first interactive run asks for client names and the version each one
runs, so advisories can be mapped per client. Press Enter at the name prompt
to skip and get one common digest instead. Manage them later with:

```bash
promwatch add-client --name "<name>" --version <version> --contact <email>
promwatch list-clients
promwatch remove-client --name "<name>"
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

**Local JSON:** each repo gets its own file — `watcher_state-<owner>-<name>.json`,
or `watcher_state.json` for Prometheus. A file holds one project, and a run
that finds another repo's data in it stops rather than mixing the two.

## Storing data in Google Sheets

By default, the watcher stores everything locally in a per-repo JSON file. If you'd rather keep the data in Google Sheets, install the optional Sheets support and set the following environment variables before running the watcher:

```bash
pip install -e ".[sheets]"

export GOOGLE_SERVICE_ACCOUNT_JSON=/path/to/service-account.json
export GOOGLE_SPREADSHEET_ID=<spreadsheet ID from the URL>

promwatch run
```

Both environment variables are required. If either one is missing, the watcher automatically falls back to using the local JSON state file. You can confirm which storage backend is being used by checking the first line of the output:

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

## Running the watcher multiple times

The watcher is designed to be idempotent, so running it repeatedly won't create duplicate records.

- Releases are tracked by their Git tag.
- Security advisories are tracked by CVE ID.
- Client notifications are tracked using the client and CVE combination.

If a run doesn't find anything new, it simply doesn't write any new rows. An unchanged spreadsheet usually means the watcher is already up to date—not that something went wrong.
