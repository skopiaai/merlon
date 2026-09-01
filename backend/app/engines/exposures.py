"""Files that were never meant to be served.

Version control directories, environment files, editor leftovers, database
dumps, backups made before a risky change and never removed. These are the
findings that turn into an incident report rather than a hardening ticket,
because they usually contain credentials rather than pointing at them.

`.git` deserves its own note. A web root with a `.git` directory in it is not
"source code disclosure" in the abstract — the repository contains the full
history, and history routinely holds the API key that was committed once and
removed in the next commit. The removal is what makes people believe it's gone.

The single most important thing this engine does is **confirm content**. A
single-page application answers HTTP 200 with its shell for every path,
including `/.env`, and a scanner that trusts status codes reports every one of
these against every SPA on the internet. So each path carries a signature of
what the real file looks like, and nothing is reported without it.

Read-only: files are fetched, never modified, and only the first few hundred
bytes are kept as evidence — with anything credential-shaped redacted, because
a vulnerability report shouldn't be the second copy of the leak.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register

# path -> (signature regex, severity, what it is)
TARGETS: dict[str, tuple[str, Severity, str]] = {
    "/.git/config": (r"\[core\]|repositoryformatversion", Severity.critical,
                     "a Git configuration file — the repository is being served, "
                     "and its full history can be reconstructed"),
    "/.git/HEAD": (r"^ref:\s*refs/", Severity.critical,
                   "a Git HEAD reference — the repository is being served"),
    "/.git/logs/HEAD": (r"[0-9a-f]{40}", Severity.critical,
                        "the Git reflog, which lists every commit including "
                        "rewritten ones"),
    "/.svn/entries": (r"^\d+|dir\b", Severity.high, "a Subversion working copy"),
    "/.hg/requires": (r"revlog|dotencode|store", Severity.high, "a Mercurial repository"),
    "/.bzr/branch-format": (r"Bazaar", Severity.high, "a Bazaar branch"),

    "/.env": (r"^[A-Z_]{3,}=|APP_KEY|DB_PASSWORD|SECRET", Severity.critical,
              "an environment file — these hold database passwords and API keys "
              "by convention"),
    "/.env.local": (r"^[A-Z_]{3,}=", Severity.critical, "a local environment file"),
    "/.env.production": (r"^[A-Z_]{3,}=", Severity.critical,
                         "the production environment file"),
    "/.env.bak": (r"^[A-Z_]{3,}=", Severity.critical, "a backup environment file"),

    "/.aws/credentials": (r"aws_access_key_id", Severity.critical,
                          "AWS credentials"),
    "/.ssh/id_rsa": (r"BEGIN [A-Z ]*PRIVATE KEY", Severity.critical,
                     "an SSH private key"),
    "/id_rsa": (r"BEGIN [A-Z ]*PRIVATE KEY", Severity.critical, "an SSH private key"),
    "/.npmrc": (r"_authToken|registry=", Severity.high, "npm registry credentials"),
    "/.netrc": (r"machine\s+\S+\s+login", Severity.critical, "netrc credentials"),
    "/.dockercfg": (r"\"auth\"", Severity.high, "Docker registry credentials"),

    "/web.config": (r"<configuration|<system\.web", Severity.high,
                    "an IIS configuration file, often containing connection strings"),
    "/.htaccess": (r"RewriteEngine|<Files|AuthType", Severity.medium,
                   "an Apache access file, which reveals rewrite rules and "
                   "protected paths"),
    "/.htpasswd": (r"^\S+:\$?[\w./$]+$", Severity.critical,
                   "an htpasswd file — password hashes, offline-crackable"),
    "/docker-compose.yml": (r"services:|version:\s*['\"]?\d", Severity.high,
                            "a compose file, which names internal services and "
                            "often embeds passwords"),
    "/Dockerfile": (r"^FROM\s+\S+", Severity.medium,
                    "a Dockerfile, revealing the build and base image"),
    "/.gitlab-ci.yml": (r"stages:|script:", Severity.medium, "a CI pipeline definition"),
    "/.travis.yml": (r"language:|script:", Severity.low, "a CI configuration"),
    "/.circleci/config.yml": (r"jobs:|workflows:", Severity.medium, "a CI configuration"),

    "/config.php.bak": (r"<\?php|define\(", Severity.critical,
                        "a PHP config backup — served as text rather than executed, "
                        "so its credentials are readable"),
    "/config.php~": (r"<\?php", Severity.critical, "an editor backup of a PHP config"),
    "/wp-config.php.bak": (r"DB_PASSWORD|<\?php", Severity.critical,
                           "a WordPress config backup, containing the database password"),
    "/config.json": (r"^\s*\{", Severity.medium, "an application configuration file"),
    "/settings.py": (r"SECRET_KEY|INSTALLED_APPS", Severity.critical,
                     "Django settings, including SECRET_KEY"),
    "/application.properties": (r"spring\.|datasource", Severity.critical,
                                "Spring configuration, usually with datasource credentials"),
    "/appsettings.json": (r"ConnectionStrings|Logging", Severity.critical,
                          ".NET settings, usually with connection strings"),

    "/backup.zip": (r"^PK\x03\x04", Severity.critical, "a site backup archive"),
    "/backup.sql": (r"CREATE TABLE|INSERT INTO|DROP TABLE", Severity.critical,
                    "a database dump"),
    "/dump.sql": (r"CREATE TABLE|INSERT INTO", Severity.critical, "a database dump"),
    "/db.sql": (r"CREATE TABLE|INSERT INTO", Severity.critical, "a database dump"),
    "/database.sql": (r"CREATE TABLE|INSERT INTO", Severity.critical, "a database dump"),

    "/.DS_Store": (r"Bud1|\x00\x00\x00\x01Bud1", Severity.low,
                   "a macOS folder index, which lists filenames in this directory "
                   "including ones that aren't linked"),
    "/.idea/workspace.xml": (r"<project|<component", Severity.low,
                             "JetBrains project files, revealing local paths and structure"),
    "/.vscode/settings.json": (r"^\s*\{", Severity.low, "editor settings"),
    "/.bash_history": (r"\b(cd|ls|sudo|ssh|mysql|curl)\b", Severity.high,
                       "a shell history file, which frequently contains passwords "
                       "typed on the command line"),

    "/phpinfo.php": (r"phpinfo\(\)|PHP Version", Severity.high,
                     "a phpinfo page — full environment, paths, loaded modules and "
                     "often environment variables"),
    "/info.php": (r"phpinfo\(\)|PHP Version", Severity.high, "a phpinfo page"),
    "/test.php": (r"phpinfo\(\)|PHP Version", Severity.medium, "a leftover test script"),
    "/composer.json": (r"\"require\"", Severity.low,
                       "a dependency manifest, naming exact library versions to "
                       "check against known vulnerabilities"),
    "/package.json": (r"\"dependencies\"|\"devDependencies\"", Severity.info,
                      "a dependency manifest"),
    "/yarn.lock": (r"^# yarn lockfile", Severity.info, "a dependency lockfile"),
    "/.well-known/apple-app-site-association": (r"applinks|appID", Severity.info,
                                                "app association config"),
    "/crossdomain.xml": (r"<cross-domain-policy", Severity.low,
                         "a Flash cross-domain policy — a wildcard here still "
                         "affects some legacy clients"),
    "/server.key": (r"BEGIN [A-Z ]*PRIVATE KEY", Severity.critical,
                    "a TLS private key"),
    "/privkey.pem": (r"BEGIN [A-Z ]*PRIVATE KEY", Severity.critical,
                     "a TLS private key"),
}

# Anything that looks like a credential is masked before it enters the report.
REDACT = [
    re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key|access[_-]?key"
               r"|private[_-]?key|auth)\w*\s*[=:]\s*)(\S+)"),
    re.compile(r"(AKIA[0-9A-Z]{16})"),
    re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]+"),
]


def redact(text: str) -> str:
    out = text
    for pattern in REDACT:
        if pattern.groups >= 2:
            out = pattern.sub(lambda m: m.group(1) + "[redacted]", out)
        else:
            out = pattern.sub("[redacted]", out)
    return out


def confirms(path: str, body: str, status: int) -> bool:
    """Is this actually the file, or the application's 200-for-everything page?"""
    if status != 200 or not body:
        return False
    signature = TARGETS.get(path, (None,))[0]
    if not signature:
        return False
    # A framework's HTML shell is the classic false positive.
    head = body[:300].lstrip().lower()
    if head.startswith(("<!doctype html", "<html")) and path != "/phpinfo.php" \
            and path != "/info.php" and path != "/test.php":
        return False
    try:
        return re.search(signature, body[:4000], re.I | re.M) is not None
    except re.error:
        return signature in body[:4000]


@register(EngineSpec(
    name="exposures",
    label="Probing for exposed files",
    description="Version control directories, environment files, backups, dumps and "
                "editor leftovers. Every hit is confirmed by content signature, not "
                "status code, so a catch-all 200 doesn't produce 40 false positives.",
    phase="post_http",
    takes="urls",
    produces="findings",
    weight=7,
    limit=15,
    default_in=("standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []

    for origin in fetch.origins(targets)[:10]:
        host = (urlparse(origin).hostname or "").lower()

        # Establish the catch-all behaviour first: if a path that cannot exist
        # returns 200, status codes carry no information on this host.
        control = await fetch.request(
            urljoin(origin, "/zzz-does-not-exist-9182736455"), timeout=10, ctx=ctx)
        catch_all = control.status == 200

        async def probe(path: str, origin=origin):
            resp = await fetch.request(urljoin(origin, path), timeout=10, ctx=ctx)
            return path, resp

        for path, resp in [r for r in await fetch.gather_limited(
                [probe(p) for p in TARGETS], limit=8) if r]:
            if not confirms(path, resp.body, resp.status):
                continue
            signature, sev, what = TARGETS[path]
            url = urljoin(origin, path)

            findings.append({
                "engine": "exposures", "rule_id": f"exposed{path.replace('/', '-')}",
                "name": f"Exposed file: {path}",
                "severity": sev,
                "host": host, "url": url, "matched_at": url,
                "description": (
                    f"`{path}` is downloadable without authentication. It is {what}.\n\n"
                    + ("The whole repository is likely retrievable from here, not "
                       "just the current files — Git history keeps deleted content, "
                       "so a credential that was committed and later removed is "
                       "still in there. Assume anything ever committed to this "
                       "repository is public.\n\n"
                       if path.startswith("/.git") else "")
                    + ("Treat every credential in this file as disclosed and rotate "
                       "it. You cannot tell from the outside who has already "
                       "fetched it, and files like this are collected "
                       "automatically at internet scale.\n\n"
                       if sev is Severity.critical else "")
                    + "Confirmed by content, not by status code"
                    + (" — note this host returns 200 for paths that don't exist, "
                       "so status alone would have proved nothing." if catch_all
                       else ".")),
                "evidence": f"GET {url} → HTTP {resp.status}, "
                            f"{len(resp.body)} bytes\n\n"
                            + redact(resp.body[:400]),
                "remediation": (
                    "Immediate: remove the file from the web root, or block it at "
                    "the server.\n\n"
                    "  nginx:  location ~ /\\.(git|env|svn|hg|ssh) { deny all; return 404; }\n"
                    "  Apache: <FilesMatch \"^\\.\"> Require all denied </FilesMatch>\n\n"
                    "Then the part that actually matters: rotate every secret the "
                    "file contained. Blocking the URL does not un-disclose what was "
                    "already served.\n\n"
                    "Structural fix: deploy build artefacts rather than a working "
                    "copy, so `.git` and `.env` never reach the server in the first "
                    "place. Add a CI check that fails the build if a deploy bundle "
                    "contains a dotfile."),
                "references": [
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    "https://cwe.mitre.org/data/definitions/530.html",
                ],
                "tags": ["exposure", "backup", "config"], "cve": [],
                "cwe": ["CWE-530", "CWE-538", "CWE-200"], "cvss_score": None,
                "dedupe_key": make_dedupe_key("exposures", f"exposed{path}", host, origin),
                "raw": {"path": path, "catch_all_host": catch_all},
            })

    if log:
        crit = [f for f in findings if f["severity"] is Severity.critical]
        await log("info", f"[exposures] {len(findings)} exposed file(s)", "exposures")
        if crit:
            await log("error",
                      f"[exposures] {len(crit)} file(s) contain credentials directly "
                      f"— rotate them, don't just block the path: "
                      f"{', '.join(f['raw']['path'] for f in crit)}", "exposures")
    return findings
