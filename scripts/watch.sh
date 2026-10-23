#!/usr/bin/env bash
# Scheduled watcher run: watch every repo in WATCH_REPOS, then build a client
# exposure report per repo into reports/<owner>-<name>.md. Meant to be run from
# cron (see "Running it on a schedule" in the README), but works by hand too.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root" || exit 1

# cron starts with an almost empty environment, so secrets and settings
# (GITHUB_TOKEN, SLACK_WEBHOOK_URL, OPENWATCH_DUCKDB, ...) come from .env.
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

# Space-separated list of repos to watch. One database holds all of them, so
# adding a repo here is the only step needed to start tracking it.
WATCH_REPOS="${WATCH_REPOS:-${WATCH_REPO:-prometheus/prometheus}}"

# cron's PATH won't include the virtualenv, so prefer its entry point.
openwatch="${OPENWATCH_BIN:-}"
if [ -z "$openwatch" ]; then
  for candidate in .venv/bin/openwatch venv/bin/openwatch; do
    [ -x "$candidate" ] && openwatch="$root/$candidate" && break
  done
fi
openwatch="${openwatch:-openwatch}"

# A manual run overlapping the scheduled one would have two writers on DuckDB,
# which takes one at a time, so the second run skips instead of failing midway.
exec 9>"$root/.watch.lock"
if ! flock -n 9; then
  echo "Another watcher run is in progress - skipping this one."
  exit 0
fi

status=0
echo "=== $(date -u +%Y-%m-%dT%H:%M:%SZ) watching: $WATCH_REPOS"

# Sequential, not parallel: DuckDB takes one writer at a time.
for repo in $WATCH_REPOS; do
  echo "--- $repo"
  "$openwatch" --repo "$repo" run || status=1
done

mkdir -p reports
for repo in $WATCH_REPOS; do
  slug="${repo//\//-}"
  # A repo with no clients recorded yet exits non-zero; that is not a failure,
  # it just means there is no fleet to report on for that project.
  if "$openwatch" --repo "$repo" report -o "reports/$slug.md"; then
    echo "Report for $repo written to reports/$slug.md"
  else
    echo "No report for $repo (no clients recorded, or the Slack post failed)."
  fi
done

exit "$status"
