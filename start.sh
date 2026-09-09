#!/usr/bin/env bash
#
# One command to bring the whole thing up:
#   ./start.sh
#
# Checks Docker, starts Ollama if it isn't already, pulls the model if it's
# missing, then brings up the stack and opens the browser.

set -euo pipefail
cd "$(dirname "$0")"

# `set -e` exits on any unhandled non-zero status, and by default it does so
# in complete silence — which is how this script came to print "checking
# Docker…" and then just return you to the prompt with no explanation.
#
# This trap makes that impossible: any unexpected exit now says which line
# died and what it returned. A startup script whose failure mode is "nothing
# happens" is worse than one that crashes loudly.
trap 'status=$?; if [ "$status" -ne 0 ]; then
        printf "\n  \033[31m✗\033[0m start.sh stopped unexpectedly at line %s (exit %s).\n" \
          "$LINENO" "$status"
        printf "     This is a bug in the script, not in your setup — please report it.\n"
      fi' ERR

# Sized to the machine at run time. A 14b model on 8 GB of RAM does not fail
# cleanly — it swaps, the box crawls, and triage takes minutes per finding,
# which reads as "the app is broken". Override with OLLAMA_MODEL if you know
# better than this guess.
total_ram_gb() {
  if [ "$(uname -s)" = "Darwin" ]; then
    echo $(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824 ))
  elif [ -r /proc/meminfo ]; then
    echo $(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1048576 ))
  else
    echo 0
  fi
}

pick_model() {
  ram=$(total_ram_gb)
  # Apple Silicon shares RAM with the GPU, so usable headroom is smaller than
  # the number suggests — hence the conservative steps.
  if   [ "$ram" -ge 32 ]; then echo "qwen2.5:14b"
  elif [ "$ram" -ge 16 ]; then echo "qwen2.5:7b"
  elif [ "$ram" -ge 8 ];  then echo "qwen2.5:3b"
  elif [ "$ram" -gt 0 ];  then echo "qwen2.5:1.5b"
  else                         echo "qwen2.5:7b"
  fi
}

MODEL="${OLLAMA_MODEL:-$(pick_model)}"
UI="http://127.0.0.1:5173"
API="http://127.0.0.1:8000"

bold() { printf "\033[1m%s\033[0m\n" "$1"; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$1"; }
warn() { printf "  \033[33m!\033[0m %s\n" "$1"; }
info() { printf "  \033[2m%s\033[0m\n" "$1"; }
die()  { printf "  \033[31m✗\033[0m %s\n" "$1"; exit 1; }

# macOS has no GNU `timeout`, and a wedged Docker daemon makes `docker info`
# block forever — which looks like the script has frozen. Run it in the
# background and give up after N seconds.
run_timeout() {
  local secs="$1"; shift
  "$@" >/dev/null 2>&1 &
  local pid=$!
  local waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$secs" ]; then
      kill -9 "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 124
    fi
    sleep 1
    waited=$((waited + 1))
  done
  wait "$pid" 2>/dev/null
}

bold "Bug Bounty Webapp"

# ---------- 1. Docker ----------
command -v docker >/dev/null 2>&1 || die "Docker isn't installed. Get Docker Desktop from docker.com."

info "checking Docker…"

# Captured with `|| docker_status=$?` rather than run bare and read via `$?`.
# Under `set -e` a bare failing command exits the script *before* the next line
# runs, so the whole "Docker isn't running — start Docker Desktop" branch below
# was unreachable: with Docker stopped, the script printed "checking Docker…"
# and vanished. `||` marks the command as tested, which exempts it from `set -e`.
docker_status=0
run_timeout 15 docker info || docker_status=$?
case $docker_status in
  0) ok "Docker is running" ;;
  124)
    die "The Docker daemon is not responding (it hung for 15s).

     This usually means Docker Desktop is wedged — often after an interrupted
     prune or a disk error. Fix it with:

       1. Quit Docker Desktop completely (menu bar whale → Quit)
       2. Reopen it and wait for the whale to stop animating
       3. Rerun ./start.sh

     If it hangs again, the virtual disk is likely corrupt:
       Docker Desktop → Settings → Troubleshoot → Clean / Purge data"
    ;;
  *)
    warn "Docker isn't running — starting Docker Desktop…"
    open -a Docker 2>/dev/null || die "Couldn't launch Docker Desktop. Open it manually, then rerun."
    printf "  waiting for Docker"
    for _ in $(seq 1 60); do
      run_timeout 5 docker info && break
      printf "."; sleep 2
    done
    echo
    run_timeout 10 docker info || die "Docker didn't come up in two minutes. Open it manually and rerun."
    ok "Docker is running"
    ;;
esac

# Docker Desktop keeps its own virtual disk. When it fills, builds fail with
# "input/output error" writing to buildkit — which looks like corruption but is
# just a full disk.
if run_timeout 10 docker system df; then
  USED=$(docker system df 2>/dev/null | awk '/Build Cache/ {print $3}' || true)
  # An `if` block rather than `[ ... ] && info ...`. The `&&` form is actually
  # safe here — a failing command inside an `&&` list is exempt from `set -e` —
  # but it stops being safe the moment such a line ends up last in a function or
  # last in the script, where the test's status becomes the caller's. Not worth
  # the footgun for one line.
  if [ -n "${USED:-}" ]; then
    info "build cache: $USED"
  fi
fi

# ---------- 2. Ollama (optional — the app works without it) ----------
if command -v ollama >/dev/null 2>&1; then
  if ! curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    warn "Ollama isn't running — starting it in the background…"
    # nohup so it survives this script exiting; log kept for debugging
    nohup ollama serve >/tmp/ollama.log 2>&1 &
    for _ in $(seq 1 20); do
      curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1 && break
      sleep 1
    done
  fi

  if curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    ok "Ollama is running"
    if [ -z "${OLLAMA_MODEL:-}" ]; then
      info "$(total_ram_gb) GB RAM detected — using $MODEL (set OLLAMA_MODEL to override)"
    fi
    if ! ollama list 2>/dev/null | awk 'NR>1 {print $1}' | grep -q "^${MODEL}$"; then
      warn "Model '$MODEL' not downloaded yet. Pulling it now (this is several GB)…"
      ollama pull "$MODEL" || warn "Pull failed — continuing without AI triage."
    else
      ok "Model $MODEL ready"
    fi
  else
    warn "Ollama wouldn't start. Continuing without AI triage (see /tmp/ollama.log)."
  fi
else
  # Offer to install rather than just reporting the absence: "one command and
  # everything happens" is the point of this script.
  warn "Ollama isn't installed — it powers AI triage and JS analysis."
  if [ "${SENTINEL_AUTO_INSTALL:-1}" = "1" ] && [ "$(uname -s)" = "Darwin" ] \
     && command -v brew >/dev/null 2>&1; then
    info "installing via Homebrew (ctrl-C to skip)…"
    if brew install ollama >/dev/null 2>&1; then
      ok "Ollama installed"
      nohup ollama serve >/tmp/ollama.log 2>&1 &
      sleep 3
      info "pulling $MODEL in the background — the app works before it finishes"
      nohup ollama pull "$MODEL" >/tmp/ollama-pull.log 2>&1 &
    else
      warn "Homebrew install failed. Get it from ollama.com; the app runs without it."
    fi
  elif [ "${SENTINEL_AUTO_INSTALL:-1}" = "1" ] && [ "$(uname -s)" = "Linux" ]; then
    info "installing via the official script (ctrl-C to skip)…"
    if curl -fsSL https://ollama.com/install.sh | sh >/tmp/ollama-install.log 2>&1; then
      ok "Ollama installed"
      nohup ollama serve >/tmp/ollama.log 2>&1 &
      sleep 3
      nohup ollama pull "$MODEL" >/tmp/ollama-pull.log 2>&1 &
    else
      warn "Install failed (see /tmp/ollama-install.log). The app runs without it."
    fi
  else
    warn "Skipping — install from ollama.com to enable AI triage."
  fi
fi

# ---------- 3. The stack ----------
# The backend gets its model name from compose, which has its own default.
# Without exporting, a machine sized down to a 3b model would pull 3b and then
# ask Ollama for 14b — and get "model not found" on every triage call.
export OLLAMA_MODEL="$MODEL"

bold "Starting containers…"
# Same reasoning as the build-cache check above: an `if` block, for the same
# "cannot become a footgun later" reason rather than because the `&&` form was
# failing here.
if [ "${INSTALL_MODE:-binary}" = "source" ]; then
  warn "INSTALL_MODE=source — compiling the toolchain, this takes a few minutes"
fi
if ! docker compose up --build -d; then
  echo
  warn "Build failed. If the error mentioned 'input/output error' or 'no space left',"
  warn "Docker's virtual disk is full. Reclaim it with:"
  echo "      docker system prune -af --volumes"
  warn "Then raise the disk limit in Docker Desktop → Settings → Resources."
  exit 1
fi

printf "  waiting for the backend"
for _ in $(seq 1 90); do
  if curl -sf "$API/api/health" >/dev/null 2>&1; then break; fi
  printf "."; sleep 2
done
echo

if ! curl -sf "$API/api/health" >/dev/null 2>&1; then
  printf "  \033[31m✗\033[0m Backend never answered. Last 40 log lines:\n\n"
  docker compose logs --tail=40 --no-color backend 2>&1 | sed 's/^/      /'
  echo
  warn "Still stuck? Follow it live with:  docker compose logs -f backend"
  exit 1
fi
ok "Backend healthy"

# Templates download in the background inside the container (see
# backend/entrypoint.sh) — no need to block startup on them here.
if docker compose logs --no-color backend 2>/dev/null | grep -q "\[templates\] ready"; then
  ok "Detection templates current"
else
  info "detection templates downloading in the background — first scan may lag"
fi

echo
bold "Ready → $UI"
echo "  Stop with:  docker compose down"
echo "  Logs with:  docker compose logs -f backend"
echo
sleep 1
open "$UI" 2>/dev/null || true
