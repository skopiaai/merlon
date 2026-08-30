# syntax=docker/dockerfile:1
#
# Full scanner toolchain. Two ways to get the Go tools, chosen with INSTALL_MODE:
#
#   binary (default) — download official release builds. ~1 min.
#   source           — compile with Go. ~8 min, several GB of module cache.
#                      Only worth it to patch a tool or track unreleased commits.
#
#   INSTALL_MODE=source ./start.sh

ARG INSTALL_MODE=binary

# ======================= option A: release binaries ========================

FROM debian:bookworm-slim AS tools-binary

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip tar ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH

# --- ProjectDiscovery suite (uniform release naming, so one loop covers them) ---
# subfinder  passive subdomain enumeration
# dnsx       DNS resolution, CNAME chains (feeds takeover detection)
# httpx      live HTTP probing + fingerprinting
# naabu      port discovery
# katana     crawler
# nuclei     template-driven detection engine
# tlsx       TLS/certificate inspection
# cdncheck   flags CDN/WAF-fronted hosts so you don't waste a scan on them
# asnmap     ASN → netblock lookups
RUN set -eux; \
    mkdir -p /out; \
    for repo in subfinder dnsx httpx naabu katana nuclei tlsx cdncheck asnmap alterx; do \
      api="https://api.github.com/repos/projectdiscovery/${repo}/releases/latest"; \
      url="$(curl -fsSL --retry 3 --retry-delay 2 "$api" \
             | grep -o '"browser_download_url": *"[^"]*"' \
             | cut -d'"' -f4 | grep -i "linux_${TARGETARCH}\.zip$" | head -1)"; \
      if [ -z "$url" ]; then \
        echo "ERROR: no linux_${TARGETARCH} asset for ${repo}" >&2; exit 1; \
      fi; \
      echo ">> ${repo}: ${url}"; \
      curl -fsSL --retry 3 --retry-delay 2 "$url" -o /tmp/t.zip; \
      unzip -o -j /tmp/t.zip "${repo}" -d /out; \
      rm -f /tmp/t.zip; chmod +x "/out/${repo}"; \
    done

# --- ffuf: content discovery (tar.gz, different naming) ---
RUN set -eux; \
    url="$(curl -fsSL https://api.github.com/repos/ffuf/ffuf/releases/latest \
           | grep -o '"browser_download_url": *"[^"]*"' | cut -d'"' -f4 \
           | grep -i "linux_${TARGETARCH}\.tar\.gz$" | head -1)"; \
    [ -n "$url" ] || { echo "ERROR: no ffuf asset" >&2; exit 1; }; \
    curl -fsSL --retry 3 "$url" -o /tmp/ffuf.tgz; \
    tar -xzf /tmp/ffuf.tgz -C /out ffuf; chmod +x /out/ffuf; rm /tmp/ffuf.tgz

# --- gitleaks: secret detection in git history ---
RUN set -eux; \
    arch="$TARGETARCH"; [ "$arch" = "amd64" ] && arch="x64"; \
    url="$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
           | grep -o '"browser_download_url": *"[^"]*"' | cut -d'"' -f4 \
           | grep -iE "linux_${arch}\.tar\.gz$" | head -1)"; \
    if [ -n "$url" ]; then \
      curl -fsSL --retry 3 "$url" -o /tmp/gl.tgz; \
      tar -xzf /tmp/gl.tgz -C /out gitleaks; chmod +x /out/gitleaks; rm /tmp/gl.tgz; \
    else echo "WARN: gitleaks asset not found, skipping" >&2; fi

# ========================== option B: from source ==========================

FROM golang:1.25-bookworm AS tools-source

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# GOTOOLCHAIN=auto: the golang images default to `local`, which hard-fails when
# a tool's go.mod requires a newer Go than the base image ships.
ENV GOBIN=/out CGO_ENABLED=1 GOTOOLCHAIN=auto

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    set -eux; \
    for m in \
      github.com/projectdiscovery/subfinder/v2/cmd/subfinder \
      github.com/projectdiscovery/dnsx/cmd/dnsx \
      github.com/projectdiscovery/httpx/cmd/httpx \
      github.com/projectdiscovery/naabu/v2/cmd/naabu \
      github.com/projectdiscovery/katana/cmd/katana \
      github.com/projectdiscovery/nuclei/v3/cmd/nuclei \
      github.com/projectdiscovery/tlsx/cmd/tlsx \
      github.com/projectdiscovery/cdncheck/cmd/cdncheck \
      github.com/projectdiscovery/asnmap/cmd/asnmap \
      github.com/projectdiscovery/alterx/cmd/alterx \
      github.com/ffuf/ffuf/v2 \
      github.com/zricethezav/gitleaks/v8 \
    ; do go install -v "${m}@latest"; done

# ===========================================================================

FROM tools-${INSTALL_MODE} AS tools

# Fail here, loudly, rather than at runtime with a confusing error.
RUN set -eux; for t in subfinder dnsx httpx naabu katana nuclei tlsx ffuf; do \
      test -x "/out/$t" || { echo "MISSING: $t" >&2; exit 1; }; done

# ================================ runtime ==================================

FROM python:3.12-slim-bookworm

# --- scanning core ---
# nmap        service/version detection and NSE scripts
# testssl.sh  deep TLS auditing beyond what tlsx reports
# libpcap0.8  runtime dependency of naabu
# git         needed by gitleaks and for cloning repos to scan
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap testssl.sh libpcap0.8 git \
        ca-certificates dnsutils whois curl unzip \
    && rm -rf /var/lib/apt/lists/*

# --- CTF toolchain ---
# The competition spans six categories and the venue network can't be relied
# on, so everything needed offline is baked in. Split across several layers:
# a single missing package shouldn't fail the whole build.
#
# Binary/reversing: binutils gdb ltrace strace radare2 upx xxd patchelf
# Forensics:        exiftool binwalk foremost steghide pngcheck sleuthkit
# Network/ICS:      tshark tcpdump netcat socat
# Crypto:           openssl john
ENV DEBIAN_FRONTEND=noninteractive

# Installed one package at a time on purpose. Debian's arm64 archive doesn't
# carry everything the amd64 one does — ltrace and upx-ucl in particular are
# absent on arm64 — and in a single apt-get line one missing package aborts the
# whole layer. Here a gap costs you that one tool and nothing else.
RUN set -eux; \
    apt-get update; \
    for pkg in \
        binutils gdb strace ltrace xxd patchelf upx-ucl upx \
        openssl john \
        libimage-exiftool-perl binwalk foremost pngcheck steghide \
        sleuthkit testdisk p7zip-full \
        tshark tcpdump netcat-openbsd socat \
        radare2 jq less \
    ; do \
        apt-get install -y --no-install-recommends "$pkg" \
          || echo "WARN: package '$pkg' unavailable on $(dpkg --print-architecture) — skipping"; \
    done; \
    rm -rf /var/lib/apt/lists/*

# Report what actually made it in, so the build log answers "do I have X?".
RUN set +e; \
    echo "--- CTF toolchain present ---"; \
    for t in gdb strace ltrace objdump readelf xxd upx r2 radare2 \
             john openssl exiftool binwalk foremost pngcheck steghide \
             fls tshark tcpdump nc socat jq; do \
        command -v "$t" >/dev/null && echo "  ok      $t" || echo "  MISSING $t"; \
    done; true

# Pure-Python and reliably-wheeled packages: these should always install, so a
# failure here is a real problem worth failing the build over.
RUN pip install --no-cache-dir \
        pycryptodome sympy scapy pymodbus pymavlink \
    && python3 -c "import Crypto, sympy, scapy, pymavlink, pymodbus; print('crypto/net/telemetry ok')"

# Everything below has native dependencies or large binary wheels that don't
# exist for every architecture. Installed individually and tolerantly.
RUN for pkg in semgrep wafw00f pwntools volatility3 gmpy2; do \
        pip install --no-cache-dir "$pkg" || echo "WARN: '$pkg' unavailable — skipping"; \
    done; true

RUN set +e; \
    echo "--- python toolchain present ---"; \
    for m in Crypto sympy scapy pymavlink pymodbus pwn volatility3 semgrep gmpy2; do \
        python3 -c "import $m" 2>/dev/null && echo "  ok      $m" || echo "  MISSING $m"; \
    done; true

# rockyou for crypto/password challenges — the standard CTF wordlist.
RUN set -eux; \
    mkdir -p /opt/wordlists; \
    curl -fsSL --retry 3 \
      https://raw.githubusercontent.com/praetorian-inc/Hob0Rules/master/wordlists/rockyou.txt.gz \
      -o /tmp/rockyou.gz \
      && gunzip -c /tmp/rockyou.gz > /opt/wordlists/rockyou.txt \
      && rm /tmp/rockyou.gz \
      || echo "WARN: rockyou download failed"

COPY --from=tools /out/ /usr/local/bin/
RUN chmod +x /usr/local/bin/* || true

# Wordlists for ffuf. SecLists is large but it's the standard, and content
# discovery is only as good as its list.
RUN set -eux; \
    mkdir -p /opt/wordlists; \
    curl -fsSL --retry 3 https://codeload.github.com/danielmiessler/SecLists/tar.gz/refs/heads/master \
      -o /tmp/sl.tgz \
      && tar -xzf /tmp/sl.tgz -C /opt/wordlists --strip-components=1 \
           SecLists-master/Discovery/Web-Content \
           SecLists-master/Discovery/DNS \
      && rm /tmp/sl.tgz \
      || echo "WARN: SecLists download failed; ffuf will need a wordlist supplied"

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8000

# Templates download in the BACKGROUND — the first fetch is ~200 MB and would
# otherwise hold the API down for minutes while the UI looks broken.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
CMD ["/usr/local/bin/entrypoint.sh"]
