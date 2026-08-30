#!/usr/bin/env bash
#
# Run the pipeline against deliberately vulnerable targets and assert what it
# should find.
#
#   ./run-lab-tests.sh          fast checks (~1 min)
#   ./run-lab-tests.sh --slow   include the nuclei stage (~15 min)
#   ./run-lab-tests.sh --keep   leave the lab containers running afterwards
#
# The targets sit on an internal Docker network: no host ports, no internet
# route, unreachable from your LAN. They are intentionally insecure — that is
# the point — so they are never started by a normal `docker compose up`.

set -uo pipefail
cd "$(dirname "$0")"

SLOW=0
KEEP=0
for arg in "$@"; do
  case "$arg" in
    --slow) SLOW=1 ;;
    --keep) KEEP=1 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

bold() { printf "\033[1m%s\033[0m\n" "$1"; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$1"; }
warn() { printf "  \033[33m!\033[0m %s\n" "$1"; }
die()  { printf "  \033[31m✗\033[0m %s\n" "$1"; exit 1; }

cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    warn "leaving lab containers running (--keep)"
    return
  fi
  bold "Stopping lab targets…"
  docker compose --profile lab stop juiceshop dvwa >/dev/null 2>&1
  docker compose --profile lab rm -f juiceshop dvwa >/dev/null 2>&1
  ok "lab torn down"
}
trap cleanup EXIT

bold "Bug Bounty Webapp — lab integration tests"

docker info >/dev/null 2>&1 || die "Docker isn't running."

# ---------- 1. unit tests first: no point testing integration on broken parts ----------
bold "Unit tests…"
if ! docker compose run --rm --no-deps -T backend python -m pytest tests -q; then
  die "Unit tests failed — fix those before running integration tests."
fi
ok "unit tests passed"

# ---------- 2. bring up the vulnerable targets ----------
bold "Starting lab targets (Juice Shop, DVWA)…"
docker compose --profile lab up -d juiceshop dvwa || die "Could not start lab containers."

printf "  waiting for Juice Shop"
READY=0
for _ in $(seq 1 60); do
  if docker compose exec -T backend sh -c \
      'curl -sS -o /dev/null --max-time 3 http://juiceshop.test:3000/' 2>/dev/null; then
    READY=1; break
  fi
  printf "."; sleep 3
done
echo
[ "$READY" -eq 1 ] || die "Juice Shop never became reachable. Check: docker compose logs juiceshop"
ok "lab reachable from the backend container"

# ---------- 3. integration tests ----------
MARK='integration and not slow'
[ "$SLOW" -eq 1 ] && MARK='integration'

bold "Integration tests${SLOW:+ (including slow)}…"
docker compose exec -T backend python -m pytest tests/integration \
    -m "$MARK" -q -p no:cacheprovider
RESULT=$?

echo
if [ $RESULT -eq 0 ]; then
  ok "pipeline verified against a known-vulnerable target"
else
  warn "integration tests failed — that means the scanner itself is broken,"
  warn "not just a parser. Read the assertion above; it names the stage."
fi
exit $RESULT
