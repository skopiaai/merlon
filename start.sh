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
    # Also correct under WSL, which presents a normal /proc.
    echo $(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1048576 ))
  elif command -v powershell.exe >/dev/null 2>&1; then
    # Git Bash on Windows: no /proc, so ask Windows itself.
    powershell.exe -NoProfile -Command \
      "[math]::Floor((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB)" \
      2>/dev/null | tr -d '\r' || echo 0
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

# ---------- 0. which machine are we on ----------
#
# Everything below that touches the system — installing Docker, starting the
# daemon, opening a browser — differs per platform. Work it out once here
# rather than sprinkling `uname` tests through the script.
#
# WSL is deliberately its own case rather than "Linux": Docker Desktop for
# Windows integrates with WSL, so the daemon is usually already provided from
# the Windows side and installing docker-ce *inside* the distro is the wrong
# fix for "docker: command not found".
case "$(uname -s)" in
  Darwin) PLATFORM="macos" ;;
  Linux)
    if grep -qiE "microsoft|wsl" /proc/version 2>/dev/null; then
      PLATFORM="wsl"
    else
      PLATFORM="linux"
    fi
    ;;
  MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
  *)                    PLATFORM="unknown" ;;
esac

# Root already, or a sudo we can reach. Empty means "cannot elevate", which is
# a refusal to guess rather than an error — the caller decides what to do.
SUDO=""
if [ "$(id -u 2>/dev/null || echo 0)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 && SUDO="sudo"
fi

open_url() {
  case "$PLATFORM" in
    macos)   open "$1" >/dev/null 2>&1 || true ;;
    linux)   xdg-open "$1" >/dev/null 2>&1 || true ;;
    wsl)     wslview "$1" >/dev/null 2>&1 \
               || powershell.exe -NoProfile -Command "Start-Process '$1'" >/dev/null 2>&1 \
               || true ;;
    windows) start "" "$1" >/dev/null 2>&1 || true ;;
    *)       true ;;
  esac
}

# Ask before changing the machine. Non-interactive runs (CI, piped input) must
# not hang waiting for a keystroke, so no TTY means "don't install".
confirm() {
  [ "${MERLON_AUTO_INSTALL:-1}" = "1" ] || return 1
  [ -t 0 ] || return 1
  printf "  \033[33m?\033[0m %s [y/N] " "$1"
  read -r reply </dev/tty 2>/dev/null || return 1
  case "$reply" in [yY]*) return 0 ;; *) return 1 ;; esac
}

bold "Merlon · by Skopia AI"

# ---------- 1. Docker ----------
#
# Docker is the one hard requirement — everything the scanner runs lives in the
# image. If it is missing we offer to install it rather than printing a URL and
# quitting, because "one command and everything happens" is the whole point of
# this script.
install_docker() {
  case "$PLATFORM" in
    macos)
      if ! command -v brew >/dev/null 2>&1; then
        warn "Homebrew isn't installed, so this can't be automated."
        info "Install Docker Desktop from https://docker.com/products/docker-desktop"
        info "or install Homebrew first: https://brew.sh"
        return 1
      fi
      confirm "Install Docker Desktop with Homebrew? (a few GB)" || return 1
      info "installing Docker Desktop — this takes a few minutes…"
      brew install --cask docker || return 1
      ok "Docker Desktop installed"
      ;;

    linux)
      warn "This installs Docker Engine from Docker's official script and needs root."
      info "The script is https://get.docker.com — read it first if you would rather."
      [ -n "$SUDO" ] || { warn "No sudo available. Install Docker as root, then rerun."; return 1; }
      confirm "Install Docker Engine now?" || return 1
      info "installing (you may be asked for your password)…"
      curl -fsSL https://get.docker.com -o /tmp/get-docker.sh || return 1
      $SUDO sh /tmp/get-docker.sh || return 1
      rm -f /tmp/get-docker.sh
      $SUDO systemctl enable --now docker >/dev/null 2>&1 || true
      # Without this every later docker call needs sudo, which then writes
      # root-owned files into the project directory.
      if [ -n "${USER:-}" ] && ! id -nG "$USER" 2>/dev/null | grep -qw docker; then
        $SUDO usermod -aG docker "$USER" >/dev/null 2>&1 || true
        warn "Added $USER to the 'docker' group — log out and back in for it to apply."
        info "Until then, docker commands need sudo."
      fi
      ok "Docker Engine installed"
      ;;

    wsl)
      warn "Inside WSL, Docker normally comes from Docker Desktop on Windows."
      info "Install Docker Desktop on Windows, then enable this distro under"
      info "Settings → Resources → WSL integration. That is the supported path."
      info "Alternatively install Docker Engine inside this distro with:"
      info "  curl -fsSL https://get.docker.com | sudo sh"
      return 1
      ;;

    windows)
      warn "Automated install isn't available from Git Bash."
      info "Run this in PowerShell:  winget install -e --id Docker.DockerDesktop"
      info "or download it from https://docker.com/products/docker-desktop"
      info "Then reopen this shell and rerun ./start.sh"
      info "(On Windows, start.ps1 in PowerShell does all of this for you.)"
      return 1
      ;;

    *)
      info "Install Docker from https://docker.com, then rerun."
      return 1
      ;;
  esac
}

if ! command -v docker >/dev/null 2>&1; then
  warn "Docker isn't installed — it is required, everything runs in containers."
  install_docker || die "Docker is still missing. Install it, then rerun ./start.sh"
  command -v docker >/dev/null 2>&1 \
    || die "Docker was installed but isn't on PATH yet. Open a new terminal and rerun."
fi

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
    # How you start the daemon is entirely platform-specific: a desktop app on
    # macOS and Windows, a system service on Linux, and on WSL something that
    # lives on the Windows side and cannot be started from in here at all.
    warn "Docker isn't running — starting it…"
    case "$PLATFORM" in
      macos)
        open -a Docker 2>/dev/null \
          || die "Couldn't launch Docker Desktop. Open it manually, then rerun."
        ;;
      linux)
        if command -v systemctl >/dev/null 2>&1 && [ -n "$SUDO" ]; then
          $SUDO systemctl start docker \
            || die "Couldn't start the docker service. Try: sudo systemctl start docker"
        elif command -v service >/dev/null 2>&1 && [ -n "$SUDO" ]; then
          $SUDO service docker start || die "Couldn't start Docker. Start it, then rerun."
        else
          die "Docker isn't running and it can't be started automatically.
     Start it with:  sudo systemctl start docker"
        fi
        ;;
      wsl)
        die "Docker isn't reachable from WSL.

     Start Docker Desktop on Windows, then check that this distro is enabled
     under Settings → Resources → WSL integration. Rerun once it is running."
        ;;
      windows)
        powershell.exe -NoProfile -Command "Start-Process 'Docker Desktop'" >/dev/null 2>&1 \
          || die "Couldn't launch Docker Desktop. Open it from the Start menu, then rerun."
        ;;
      *)
        die "Docker isn't running. Start it, then rerun."
        ;;
    esac
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
  if [ "${MERLON_AUTO_INSTALL:-1}" = "1" ] && [ "$PLATFORM" = "macos" ] \
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
  elif [ "${MERLON_AUTO_INSTALL:-1}" = "1" ] \
       && { [ "$PLATFORM" = "linux" ] || [ "$PLATFORM" = "wsl" ]; }; then
    info "installing via the official script (ctrl-C to skip)…"
    if curl -fsSL https://ollama.com/install.sh | sh >/tmp/ollama-install.log 2>&1; then
      ok "Ollama installed"
      nohup ollama serve >/tmp/ollama.log 2>&1 &
      sleep 3
      nohup ollama pull "$MODEL" >/tmp/ollama-pull.log 2>&1 &
    else
      warn "Install failed (see /tmp/ollama-install.log). The app runs without it."
    fi
  elif [ "${MERLON_AUTO_INSTALL:-1}" = "1" ] && [ "$PLATFORM" = "windows" ] \
       && command -v winget.exe >/dev/null 2>&1; then
    info "installing via winget (ctrl-C to skip)…"
    if winget.exe install -e --id Ollama.Ollama --accept-source-agreements \
         --accept-package-agreements >/dev/null 2>&1; then
      ok "Ollama installed — it starts with Windows; rerun to use AI triage"
    else
      warn "winget install failed. Get it from ollama.com; the app runs without it."
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

# ---------- 2b. clear containers left by the pre-rename project ----------
#
# `container_name:` is a global Docker name, not a project-scoped one. Pinning
# `name: merlon` in compose created a new project that still wanted the same
# container names, so the first upgrade run died with:
#
#   Conflict. The container name "/bbwebapp-backend" is already in use
#
# Renaming the containers fixes the collision but not the real problem: the old
# ones are still running and still holding ports 8000 and 5173, so the new ones
# would fail to bind instead. They have to go.
#
# Only containers this project created are touched, by exact name. Nothing
# matches a pattern, because a pattern eventually matches something of yours.
# Every name this project has shipped under, newest first. Two renames now, so
# this is a list rather than a single generation — the parapet-* containers are
# the ones actually running on any machine that upgraded last time, and missing
# them would reproduce the exact conflict this block exists to prevent.
LEGACY_CONTAINERS="parapet-backend parapet-frontend parapet-lab-juiceshop parapet-lab-dvwa \
bbwebapp-backend bbwebapp-frontend bbwebapp-lab-juiceshop bbwebapp-lab-dvwa"

clear_legacy_containers() {
  local found=""
  for c in $LEGACY_CONTAINERS; do
    if docker container inspect "$c" >/dev/null 2>&1; then
      found="$found $c"
    fi
  done
  [ -z "$found" ] && return 0

  warn "removing containers from the previous name:$found"
  info "(their data lives in the volume, which is copied across below)"
  # shellcheck disable=SC2086
  docker rm -f $found >/dev/null 2>&1 \
    && ok "old containers removed" \
    || warn "could not remove them — run: docker rm -f$found"
}

# ---------- 2c. one-time volume migration ----------
#
# docker-compose.yml now pins `name: merlon`, so the data volume is
# `merlon_app-data`. Before that, Compose derived the project name from the
# checkout directory — "Bug Bounty Webapp" became `bugbountywebapp_app-data`.
#
# Without this, `docker compose up` would create a fresh empty volume and every
# scan, finding and HTB box would appear to have been deleted by the upgrade,
# while the real data sat untouched in a volume nothing mounts any more. Copy
# rather than rename: if anything goes wrong the original is still there.
migrate_volume() {
  local target="merlon_app-data"
  docker volume inspect "$target" >/dev/null 2>&1 && return 0   # already done

  local old
  old="$(docker volume ls -q 2>/dev/null | grep -E '_app-data$' | grep -v '^merlon_' | head -1 || true)"
  [ -z "${old:-}" ] && return 0

  warn "found data from a previous install ($old) — copying it across…"
  docker volume create "$target" >/dev/null 2>&1 || true
  if docker run --rm -v "${old}:/from:ro" -v "${target}:/to" alpine:3 \
       sh -c 'cp -a /from/. /to/ 2>/dev/null || true' >/dev/null 2>&1; then
    ok "previous scans and Hack The Box boxes carried over"
    info "the old volume ($old) was left in place — remove it once you are happy"
  else
    warn "could not copy $old. Your old data is still in that volume; the app"
    warn "will start with an empty database until it is moved across."
  fi
}

if command -v docker >/dev/null 2>&1; then
  # Order matters: the old containers must be gone before the volume is copied,
  # or the copy reads a database that is still being written to.
  clear_legacy_containers || true
  migrate_volume || true
fi

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
open_url "$UI"
