"""Deeper service-level auditing: testssl.sh and nmap NSE.

tlsx tells you the certificate is valid. testssl.sh tells you the cipher suites
are weak, the server is vulnerable to a downgrade, or renegotiation is enabled
— the things an auditor asks about.

nmap NSE goes past "port 445 is open" to "SMB signing is not required", which
is the difference between an observation and a finding.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile

from ..models import Severity
from ..normalize import make_dedupe_key
from .registry import EngineSpec, register

# testssl severity strings -> ours.
_TESTSSL_SEV = {
    "CRITICAL": Severity.critical,
    "HIGH": Severity.high,
    "MEDIUM": Severity.medium,
    "LOW": Severity.low,
    "WARN": Severity.low,
    "INFO": Severity.info,
    "OK": None,      # passing checks aren't findings
    "DEBUG": None,
}

# Checks that are informational noise rather than findings.
_TESTSSL_SKIP = {
    "service", "cert_numbers", "cert", "intermediate_cert", "clientAuth",
    "scanTime", "engine_problem", "optimal_proto", "protocol_negotiated",
    "cipher_negotiated", "cert_chain_of_trust", "cert_commonName",
    "cert_subjectAltName", "cert_caIssuers", "cert_certificatePolicies_EV",
}


async def testssl(host: str, port: int = 443, *, log=None) -> list[dict]:
    """Run testssl.sh and convert its JSON output into findings."""
    if not shutil.which("testssl.sh"):
        return []

    fd, out_path = tempfile.mkstemp(prefix="testssl_", suffix=".json")
    os.close(fd)
    os.unlink(out_path)  # testssl refuses to overwrite

    argv = [
        "testssl.sh", "--jsonfile", out_path, "--quiet", "--color", "0",
        "--severity", "LOW",      # skip OK/INFO noise at source
        "--protocols", "--ciphers", "--vulnerable", "--headers",
        "--sneaky",               # less conspicuous user agent
        "--connect-timeout", "10", "--openssl-timeout", "10",
        f"{host}:{port}",
    ]
    if log:
        await log("info", f"[testssl] deep TLS audit of {host}:{port}", "tlsdeep")

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await asyncio.wait_for(proc.wait(), timeout=900)
    except (asyncio.TimeoutError, OSError):
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
        if log:
            await log("warn", f"[testssl] timed out on {host}", "tlsdeep")
        return []

    if not os.path.exists(out_path):
        return []
    try:
        with open(out_path) as fh:
            records = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass

    if isinstance(records, dict):
        records = records.get("scanResult") or []

    findings = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        rid = rec.get("id", "")
        if rid in _TESTSSL_SKIP:
            continue
        sev = _TESTSSL_SEV.get(str(rec.get("severity", "")).upper())
        if sev is None:
            continue
        finding_text = str(rec.get("finding", "")).strip()
        if not finding_text:
            continue

        url = f"https://{host}:{port}"
        findings.append({
            "engine": "testssl",
            "rule_id": f"testssl-{rid}",
            "name": f"TLS: {rid.replace('_', ' ')}",
            "severity": sev,
            "host": host,
            "url": url,
            "matched_at": url,
            "description": finding_text,
            "evidence": json.dumps(rec, indent=2)[:2000],
            "remediation": (
                "Review the TLS configuration against the Mozilla SSL Configuration "
                "Generator for your server software. Most findings here resolve by "
                "adopting the 'intermediate' profile: TLS 1.2+ only, modern cipher "
                "suites, and no renegotiation or compression."
            ),
            "references": ["https://ssl-config.mozilla.org/",
                           "https://testssl.sh/"],
            "tags": ["tls", "crypto"],
            "cve": [c for c in (rec.get("cve", "") or "").split() if c.startswith("CVE-")],
            "cwe": [rec["cwe"]] if rec.get("cwe") else [],
            "cvss_score": None,
            "dedupe_key": make_dedupe_key("testssl", rid, host, url),
            "raw": rec,
        })
    return findings


# ------------------------------------------------------------------ nmap NSE

# Safe, non-intrusive scripts that turn an open port into an actual finding.
NSE_SCRIPTS = ",".join([
    "smb-security-mode", "smb2-security-mode",   # SMB signing
    "ssl-enum-ciphers",                          # cipher strength
    "ssh2-enum-algos", "ssh-auth-methods",       # SSH config
    "rdp-ntlm-info",                             # RDP exposure detail
    "snmp-info",                                 # SNMP community exposure
    "ftp-anon",                                  # anonymous FTP
    "mongodb-info", "redis-info",                # unauthenticated datastores
    "http-methods",                              # dangerous verbs
])

# script id -> (severity, title, description, fix)
_NSE_RULES = {
    "ftp-anon": (
        Severity.high, "Anonymous FTP login permitted",
        "The FTP service accepts anonymous logins. Anyone can connect and list — often "
        "download, sometimes upload — files without credentials.",
        "Disable anonymous access in the FTP server configuration, or replace FTP with "
        "SFTP entirely.",
    ),
    "smb-security-mode": (
        Severity.medium, "SMB message signing not required",
        "SMB signing isn't enforced, which permits relay attacks: an attacker on the "
        "network can capture an authentication attempt and replay it against another host.",
        "Require SMB signing on both clients and servers.",
    ),
    "smb2-security-mode": (
        Severity.medium, "SMB2 message signing not required",
        "SMB2 signing isn't enforced, permitting authentication relay attacks.",
        "Set 'Require SMB signing' in group policy or the Samba configuration.",
    ),
    "snmp-info": (
        Severity.high, "SNMP responding to default community string",
        "The SNMP service answered a query using a default community string. SNMP exposes "
        "detailed system, network and sometimes credential information, and 'public' is "
        "the first thing any scanner tries.",
        "Change the community string, restrict SNMP to management networks, or move to "
        "SNMPv3 with authentication.",
    ),
    "mongodb-info": (
        Severity.critical, "MongoDB responding without authentication",
        "The MongoDB instance answered an information query without credentials. If reads "
        "are unauthenticated, the entire database is readable by anyone who can reach the port.",
        "Enable authentication, bind to a private interface, and firewall the port. Then "
        "check the logs for connections you don't recognise.",
    ),
    "redis-info": (
        Severity.critical, "Redis responding without authentication",
        "Redis answered without credentials. Unauthenticated Redis is routinely used to "
        "read application data and, in many configurations, to achieve remote code execution.",
        "Set requirepass, bind to localhost, and firewall the port immediately.",
    ),
}


async def nmap_nse(hosts: list[str], *, log=None) -> list[dict]:
    """Run safe NSE scripts and turn notable results into findings."""
    if not hosts or not shutil.which("nmap"):
        return []

    fd, out_path = tempfile.mkstemp(prefix="nse_", suffix=".xml")
    os.close(fd)

    argv = [
        "nmap", "-sV", "--script", NSE_SCRIPTS, "--script-timeout", "60",
        "-T3", "--open", "-Pn", "-n", "--top-ports", "200",
        "-oX", out_path, *hosts,
    ]
    if log:
        await log("info", f"[nse] service-level checks on {len(hosts)} host(s)", "nse")

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await asyncio.wait_for(proc.wait(), timeout=2400)
    except (asyncio.TimeoutError, OSError):
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
        return []

    import xml.etree.ElementTree as ET

    findings = []
    try:
        root = ET.parse(out_path).getroot()
    except (ET.ParseError, OSError):
        return []
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass

    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        ip = addr_el.get("addr", "") if addr_el is not None else ""
        names = [h.get("name", "") for h in host_el.findall("hostnames/hostname")]
        hostname = (names[0] if names else ip).lower()

        for port_el in host_el.findall("ports/port"):
            port = port_el.get("portid", "")
            for script in port_el.findall("script"):
                sid = script.get("id", "")
                output = (script.get("output") or "").strip()
                rule = _NSE_RULES.get(sid)
                if not rule or not output:
                    continue

                # Only flag when the output actually indicates the weak state.
                low = output.lower()
                if sid in ("smb-security-mode", "smb2-security-mode") and \
                        "not required" not in low and "disabled" not in low:
                    continue
                if sid == "ftp-anon" and "anonymous ftp login allowed" not in low:
                    continue

                sev, title, desc, fix = rule
                url = f"{hostname}:{port}"
                findings.append({
                    "engine": "nmap-nse",
                    "rule_id": f"nse-{sid}",
                    "name": f"{title} (port {port})",
                    "severity": sev,
                    "host": hostname,
                    "url": url,
                    "matched_at": url,
                    "description": desc,
                    "evidence": output[:2000],
                    "remediation": fix,
                    "references": [f"https://nmap.org/nsedoc/scripts/{sid}.html"],
                    "tags": ["network", "service", sid],
                    "cve": [], "cwe": [], "cvss_score": None,
                    "dedupe_key": make_dedupe_key("nmap-nse", sid, hostname, url),
                    "raw": {"script": sid, "output": output},
                })
    return findings


@register(EngineSpec(
    name="tlsdeep",
    label="Deep TLS audit",
    description="testssl.sh: protocol versions, cipher suites and known TLS "
                "vulnerabilities, well beyond certificate validity.",
    phase="post_http",
    takes="hosts",
    weight=12,
    limit=6,
    skip_cdn=True,
    default_in=("deep",),
))
async def _tlsdeep(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    out: list[dict] = []
    for i in range(0, len(targets), 3):
        import asyncio as _a
        batch = targets[i:i + 3]
        for r in await _a.gather(*(testssl(h, log=log) for h in batch),
                                 return_exceptions=True):
            if not isinstance(r, Exception):
                out += r
    return out


@register(EngineSpec(
    name="nse",
    label="Service-level configuration checks",
    description="nmap NSE scripts that turn an open port into a finding: SMB "
                "signing, SNMP community strings, anonymous FTP, unauthenticated "
                "datastores.",
    phase="post_http",
    takes="hosts",
    weight=14,
    limit=20,
    skip_cdn=True,
    default_in=("deep",),
))
async def _nse(targets: list[str], ctx: dict) -> list[dict]:
    return await nmap_nse(targets, log=ctx.get("log"))
