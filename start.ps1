#Requires -Version 5.1
<#
    Merlon · by Skopia AI — Windows launcher

        .\start.ps1

    The PowerShell counterpart to start.sh. It does the same job in the same
    order: make sure Docker exists and is running, install and start Ollama if
    it is missing, bring the stack up, wait for the backend, open the UI.

    Windows users can equally run start.sh inside WSL. This script exists so
    that installing WSL first is not a prerequisite for trying the tool.
#>

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$UI  = 'http://127.0.0.1:5173'
$API = 'http://127.0.0.1:8000'

function Write-Bold  { param($m) Write-Host $m -ForegroundColor White }
function Write-Ok    { param($m) Write-Host "  + $m" -ForegroundColor Green }
function Write-Warn  { param($m) Write-Host "  ! $m" -ForegroundColor Yellow }
function Write-Info  { param($m) Write-Host "  $m"   -ForegroundColor DarkGray }
function Write-Die   { param($m) Write-Host "  x $m" -ForegroundColor Red; exit 1 }

function Test-Command { param($n) [bool](Get-Command $n -ErrorAction SilentlyContinue) }

# Ask before changing the machine. A non-interactive host must not block on
# input, so treat "no console" as "don't install" rather than hanging.
function Confirm-Action {
    param($Message)
    if ($env:MERLON_AUTO_INSTALL -eq '0') { return $false }
    if ([Console]::IsInputRedirected) { return $false }
    $reply = Read-Host "  ? $Message [y/N]"
    return $reply -match '^[yY]'
}

# Sized to the machine, for the same reason as start.sh: a 14b model on 8 GB
# swaps rather than failing, and that reads as "the app is broken".
function Get-ModelForRam {
    $gb = 0
    try {
        $gb = [math]::Floor((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    } catch { $gb = 0 }
    if     ($gb -ge 32) { return 'qwen2.5:14b' }
    elseif ($gb -ge 16) { return 'qwen2.5:7b'  }
    elseif ($gb -ge 8)  { return 'qwen2.5:3b'  }
    elseif ($gb -gt 0)  { return 'qwen2.5:1.5b'}
    else                { return 'qwen2.5:7b'  }
}

function Test-Endpoint {
    param($Url, $TimeoutSec = 3)
    try {
        Invoke-WebRequest -Uri $Url -TimeoutSec $TimeoutSec -UseBasicParsing | Out-Null
        return $true
    } catch { return $false }
}

$MODEL = if ($env:OLLAMA_MODEL) { $env:OLLAMA_MODEL } else { Get-ModelForRam }

Write-Bold 'Merlon - by Skopia AI'

# ---------- 1. Docker ----------
if (-not (Test-Command 'docker')) {
    Write-Warn "Docker isn't installed - it is required, everything runs in containers."
    if (Test-Command 'winget') {
        if (Confirm-Action 'Install Docker Desktop with winget? (a few GB)') {
            Write-Info 'installing Docker Desktop - this takes a few minutes...'
            winget install -e --id Docker.DockerDesktop `
                --accept-source-agreements --accept-package-agreements
            if ($LASTEXITCODE -ne 0) { Write-Die 'winget install failed. Install Docker Desktop manually, then rerun.' }
            Write-Ok 'Docker Desktop installed'
            Write-Warn 'Windows needs a sign-out (sometimes a reboot) before Docker works.'
            Write-Info 'Sign out, sign back in, then rerun .\start.ps1'
            exit 0
        } else {
            Write-Die 'Docker is required. Install it, then rerun .\start.ps1'
        }
    } else {
        Write-Info 'Install Docker Desktop from https://docker.com/products/docker-desktop'
        Write-Die  'Docker is required. Install it, then rerun .\start.ps1'
    }
}

Write-Info 'checking Docker...'
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Warn "Docker isn't running - starting Docker Desktop..."
    $exe = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
    if (Test-Path $exe) { Start-Process $exe } else { Start-Process 'Docker Desktop' -ErrorAction SilentlyContinue }

    Write-Host '  waiting for Docker' -NoNewline
    $up = $false
    foreach ($i in 1..60) {
        docker info *> $null
        if ($LASTEXITCODE -eq 0) { $up = $true; break }
        Write-Host '.' -NoNewline
        Start-Sleep -Seconds 2
    }
    Write-Host ''
    if (-not $up) {
        Write-Die "Docker didn't come up in two minutes. Open Docker Desktop manually and rerun."
    }
}
Write-Ok 'Docker is running'

# ---------- 2. Ollama (optional - the app works without it) ----------
if (Test-Command 'ollama') {
    if (-not (Test-Endpoint "http://127.0.0.1:11434/api/tags")) {
        Write-Warn "Ollama isn't running - starting it in the background..."
        Start-Process 'ollama' -ArgumentList 'serve' -WindowStyle Hidden -ErrorAction SilentlyContinue
        foreach ($i in 1..20) {
            if (Test-Endpoint "http://127.0.0.1:11434/api/tags" 2) { break }
            Start-Sleep -Seconds 1
        }
    }

    if (Test-Endpoint "http://127.0.0.1:11434/api/tags") {
        Write-Ok 'Ollama is running'
        if (-not $env:OLLAMA_MODEL) { Write-Info "using $MODEL (set OLLAMA_MODEL to override)" }
        $have = (& ollama list 2>$null | Select-Object -Skip 1) -match "^$([regex]::Escape($MODEL))\s"
        if (-not $have) {
            Write-Warn "Model '$MODEL' not downloaded yet. Pulling it now (this is several GB)..."
            & ollama pull $MODEL
            if ($LASTEXITCODE -ne 0) { Write-Warn 'Pull failed - continuing without AI triage.' }
        } else {
            Write-Ok "Model $MODEL ready"
        }
    } else {
        Write-Warn "Ollama wouldn't start. Continuing without AI triage."
    }
} else {
    Write-Warn "Ollama isn't installed - it powers AI triage and JS analysis."
    if ((Test-Command 'winget') -and (Confirm-Action 'Install Ollama with winget?')) {
        winget install -e --id Ollama.Ollama `
            --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -eq 0) {
            Write-Ok 'Ollama installed'
            Start-Process 'ollama' -ArgumentList 'serve' -WindowStyle Hidden -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
            Write-Info "pulling $MODEL in the background - the app works before it finishes"
            Start-Process 'ollama' -ArgumentList "pull $MODEL" -WindowStyle Hidden -ErrorAction SilentlyContinue
        } else {
            Write-Warn 'Install failed. Get it from ollama.com; the app runs without it.'
        }
    } else {
        Write-Warn 'Skipping - install from ollama.com to enable AI triage.'
    }
}

# ---------- 3. The stack ----------
# The backend reads the model name from compose, which has its own default.
# Without this, a machine sized down to 3b would pull 3b and then ask Ollama
# for 14b, getting "model not found" on every triage call.
$env:OLLAMA_MODEL = $MODEL

# Containers from the two previous names of this project hold ports 8000 and
# 5173, so the new ones fail to bind rather than conflict by name. Removed by
# exact name only - a pattern eventually matches something of yours.
$legacy = @(
    'parapet-backend','parapet-frontend','parapet-lab-juiceshop','parapet-lab-dvwa',
    'bbwebapp-backend','bbwebapp-frontend','bbwebapp-lab-juiceshop','bbwebapp-lab-dvwa'
)
$found = @()
foreach ($c in $legacy) {
    docker container inspect $c *> $null
    if ($LASTEXITCODE -eq 0) { $found += $c }
}
if ($found.Count -gt 0) {
    Write-Warn "removing containers from the previous name: $($found -join ' ')"
    docker rm -f @found *> $null
}

# Compose now pins `name: merlon`, so the volume is merlon_app-data. Before
# that it was derived from the folder name. Without copying it across, an
# upgrade looks like every scan and box was deleted.
docker volume inspect 'merlon_app-data' *> $null
if ($LASTEXITCODE -ne 0) {
    $old = (docker volume ls -q 2>$null | Where-Object { $_ -match '_app-data$' -and $_ -notmatch '^merlon_' } | Select-Object -First 1)
    if ($old) {
        Write-Warn "found data from a previous install ($old) - copying it across..."
        docker volume create 'merlon_app-data' *> $null
        docker run --rm -v "${old}:/from:ro" -v 'merlon_app-data:/to' alpine:3 `
            sh -c 'cp -a /from/. /to/ 2>/dev/null || true' *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Ok 'previous scans and Hack The Box boxes carried over'
            Write-Info "the old volume ($old) was left in place - remove it once you are happy"
        } else {
            Write-Warn "could not copy $old. The app will start with an empty database."
        }
    }
}

Write-Bold 'Starting containers...'
docker compose up --build -d
if ($LASTEXITCODE -ne 0) {
    Write-Host ''
    Write-Warn "Build failed. If the error mentioned 'no space left', Docker's disk is full:"
    Write-Host '      docker system prune -af --volumes'
    Write-Warn 'Then raise the disk limit in Docker Desktop -> Settings -> Resources.'
    exit 1
}

Write-Host '  waiting for the backend' -NoNewline
$healthy = $false
foreach ($i in 1..90) {
    if (Test-Endpoint "$API/api/health" 2) { $healthy = $true; break }
    Write-Host '.' -NoNewline
    Start-Sleep -Seconds 2
}
Write-Host ''

if (-not $healthy) {
    Write-Host '  x Backend never answered. Last 40 log lines:' -ForegroundColor Red
    Write-Host ''
    docker compose logs --tail=40 --no-color backend 2>&1 | ForEach-Object { "      $_" }
    Write-Host ''
    Write-Warn 'Still stuck? Follow it live with:  docker compose logs -f backend'
    exit 1
}
Write-Ok 'Backend healthy'

if ((docker compose logs --no-color backend 2>$null) -match '\[templates\] ready') {
    Write-Ok 'Detection templates current'
} else {
    Write-Info 'detection templates downloading in the background - first scan may lag'
}

Write-Host ''
Write-Bold "Ready -> $UI"
Write-Host '  Stop with:  docker compose down'
Write-Host '  Logs with:  docker compose logs -f backend'
Write-Host ''
Start-Sleep -Seconds 1
Start-Process $UI
