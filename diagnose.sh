#!/usr/bin/env bash
# Collect everything needed to diagnose a backend problem in one shot.
#   ./diagnose.sh

cd "$(dirname "$0")"
line() { printf "\n\033[1m=== %s ===\033[0m\n" "$1"; }

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
