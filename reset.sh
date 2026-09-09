#!/usr/bin/env bash
#
# Wipe local state: scan history, findings, artifacts, HTB boxes and flags.
#
#   ./reset.sh              # ask first
#   ./reset.sh --yes        # don't ask
#   ./reset.sh --keep-templates   # leave the downloaded detection content alone
#
# Use this before recording a demo, before handing the machine to someone else,
# or when a database has got into a state you would rather not debug.
#
# None of this is in git — the database lives in a Docker volume and
# .sentinel-data/ is ignored — so this is about your machine, not the
# repository. Nothing here touches your code or your commits.

set -euo pipefail
cd "$(dirname "$0")"

trap 'status=$?; if [ "$status" -ne 0 ]; then
        printf "\n  \033[31m✗\033[0m reset.sh stopped at line %s (exit %s).\n" \
          "$LINENO" "$status"
      fi' ERR

ok()   { printf "  \033[32m✓\033[0m %s\n" "$1"; }
warn() { printf "  \033[33m!\033[0m %s\n" "$1"; }
info() { printf "  \033[2m%s\033[0m\n" "$1"; }

ASSUME_YES=0
KEEP_TEMPLATES=0
for arg in "$@"; do
  case "$arg" in
    --yes|-y)         ASSUME_YES=1 ;;
    --keep-templates) KEEP_TEMPLATES=1 ;;
    *) echo "unknown option: $arg"; exit 2 ;;
  esac
done

printf "\033[1mReset local state\033[0m\n"
echo "  This deletes, on this machine only:"
echo "    · every scan, finding, engagement and submission queue entry"
echo "    · every Hack The Box box you have added, and any flags saved with it"
echo "    · CTF challenges and their notes"
echo "    · captured artifacts and evidence blocks"
if [ "$KEEP_TEMPLATES" -eq 1 ]; then
  echo "  Detection templates and privesc knowledge are kept."
else
  echo "    · downloaded templates and privesc knowledge (re-downloaded on next run)"
fi
echo

if [ "$ASSUME_YES" -ne 1 ]; then
  printf "  Type 'reset' to confirm: "
  read -r reply
  if [ "$reply" != "reset" ]; then
    warn "Cancelled — nothing was deleted."
    exit 0
  fi
fi

if command -v docker >/dev/null 2>&1 && docker compose ps >/dev/null 2>&1; then
  info "stopping containers…"
  docker compose down >/dev/null 2>&1 || true

  if [ "$KEEP_TEMPLATES" -eq 1 ]; then
    # Templates live in their own volume (nuclei-templates), so keeping them
    # only means not dropping that one. The database is in app-data; empty it
    # from a throwaway container rather than removing the volume, so the mount
    # stays intact.
    #
    # Compose prefixes volume names with the project name, which defaults to the
    # directory name lowercased with non-alphanumerics stripped — "Bug Bounty
    # Webapp" becomes "bugbountywebapp". Ask compose rather than reconstructing
    # it, because getting this wrong makes the command silently no-op.
    info "emptying the database volume, keeping templates…"
    vol=$(docker compose config --format json 2>/dev/null \
          | python3 -c 'import json,sys;d=json.load(sys.stdin);print(next((v.get("name","") for k,v in (d.get("volumes") or {}).items() if k=="app-data"), ""))' 2>/dev/null || true)
    if [ -z "${vol:-}" ]; then
      vol="$(docker volume ls -q | grep -E 'app-data$' | head -1 || true)"
    fi
    if [ -n "${vol:-}" ]; then
      docker run --rm -v "${vol}:/data" alpine:3 \
        sh -c 'rm -f /data/sentinel.db /data/sentinel.db-wal /data/sentinel.db-shm /data/update-state.json;
               rm -rf /data/artifacts /data/htb-knowledge' >/dev/null 2>&1 \
        && ok "database and artifacts removed, templates kept" \
        || warn "could not write to volume $vol"
    else
      warn "no app-data volume found — nothing to empty yet"
    fi
  else
    info "removing the data volumes…"
    docker compose down -v >/dev/null 2>&1 || true
  fi
  ok "container state cleared"
else
  warn "Docker isn't running — clearing local files only"
fi

# The non-Docker path: config.py falls back to .sentinel-data/ when /data is
# not writable, which is what happens when you run the backend directly.
if [ -d .sentinel-data ]; then
  if [ "$KEEP_TEMPLATES" -eq 1 ]; then
    rm -f .sentinel-data/sentinel.db .sentinel-data/sentinel.db-wal \
          .sentinel-data/sentinel.db-shm
    rm -rf .sentinel-data/artifacts
  else
    rm -rf .sentinel-data
  fi
  ok "local .sentinel-data cleared"
fi

echo
ok "Done. Run ./start.sh to come back up with an empty database."
