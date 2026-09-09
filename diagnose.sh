#!/usr/bin/env bash
# Collect everything needed to diagnose a backend problem in one shot.
#   ./diagnose.sh

cd "$(dirname "$0")"
line() { printf "\n\033[1m=== %s ===\033[0m\n" "$1"; }

line "is the running container older than your code?"
# The commonest cause of "it stopped working" after an update: `docker compose
# up -d` without --build reuses the existing image, so the container runs code
# from before the change. Nothing errors — it just behaves like the old version.
CREATED=$(docker inspect -f '{{.Created}}' bbwebapp-backend 2>/dev/null)
if [ -n "$CREATED" ]; then
  CREATED_TS=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${CREATED%%.*}" +%s 2>/dev/null \
               || date -d "${CREATED%%.*}" +%s 2>/dev/null || echo 0)
  NEWEST=$(find backend/app backend/requirements.txt -type f -newermt "@$CREATED_TS" 2>/dev/null | head -5)
  if [ -n "$NEWEST" ] && [ "$CREATED_TS" != "0" ]; then
    printf "  \033[33mSTALE\033[0m — these changed after the container was built:\n"
    echo "$NEWEST" | sed 's/^/      /'
    printf "  Rebuild with:  \033[1mdocker compose up -d --build\033[0m\n"
  else
    echo "  container is current with the source"
  fi
else
  echo "  backend container does not exist — run ./start.sh"
fi

line "container status"
docker compose ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}' 2>&1

line "restart count (a climbing number means a crash loop)"
for c in bbwebapp-backend bbwebapp-frontend; do
  printf "%s: %s restarts, exit code %s\n" "$c" \
    "$(docker inspect -f '{{.RestartCount}}' "$c" 2>/dev/null || echo '?')" \
    "$(docker inspect -f '{{.State.ExitCode}}' "$c" 2>/dev/null || echo '?')"
done

line "backend log (last 60 lines)"
docker compose logs --tail=60 --no-color backend 2>&1

line "can the API be reached?"
curl -sS -m 5 -o /dev/null -w "health -> HTTP %{http_code} in %{time_total}s\n" \
  http://127.0.0.1:8000/api/health 2>&1

line "are the scanners actually present?"
for t in subfinder dnsx httpx naabu nmap tlsx ffuf katana nuclei; do
  printf "  %-10s %s\n" "$t" \
    "$(docker compose exec -T backend sh -c "command -v $t >/dev/null && echo present || echo MISSING" 2>/dev/null || echo 'container not running')"
done

line "disk inside the container"
docker compose exec -T backend df -h /data 2>&1 | tail -2

echo
echo "Copy everything above into the chat."
