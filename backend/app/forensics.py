"""Web server log forensics.

The honest scope of this module, stated plainly because it matters:

**From outside a website you cannot identify who compromised it.** No external
scan reveals the attacker's IP, device or identity. That evidence exists in one
place — the web server's own access and error logs — and only the people who
run the server can give you those.

What this does is analyse those logs once you have them, legitimately, from the
system owner. Given an Apache or Nginx access log it reconstructs:

  * when the compromise started (first request to an injected path)
  * which IPs interacted with injected files, and how
  * webshell behaviour — POSTs to files that should never receive them
  * the upload or exploit request that preceded the first spam hit
  * whether the attacker returned, and from where

That is genuine incident response, and it produces the timeline a university
IT department needs to actually fix the problem rather than just delete pages.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime

# Apache/Nginx "combined" format, which is the default for both.
COMBINED = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^"]*?) (?P<proto>HTTP/[\d.]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)

TS_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# Paths that should never receive a POST on a normal content site. A POST here
# is close to definitive webshell behaviour.
SUSPICIOUS_POST = re.compile(
    r"\.(?:php|phtml|php5|php7|asp|aspx|jsp|jspx|cgi|pl)$"
    r"|/(?:upload|uploads|images|img|assets|static|media|cache|tmp|temp|files)/",
    re.I)

# Filenames commonly used by webshells and droppers.
SHELL_NAMES = re.compile(
    r"\b(?:shell|c99|r57|wso|b374k|alfa|adminer|indoxploit|mini|cmd|bypass|"
    r"up|upl|uploader|filemanager|xmlrpc|wp-conflg|wp-cache-?\w{0,6}|"
    r"radio|error_log|lock360|class\.api|inputs|content-?\w{0,4})\.(?:php|asp|jsp)\b",
    re.I)

# Tooling user agents. Not proof of anything, but a strong signal in context.
TOOL_UA = re.compile(
    r"sqlmap|nikto|acunetix|nessus|wpscan|havij|python-requests|curl/|wget|"
    r"go-http-client|zgrab|masscan|nmap|libwww|httrack|scrapy|okhttp",
    re.I)

CRAWLER_UA = re.compile(r"googlebot|bingbot|yandex|duckduckbot|baiduspider|slurp", re.I)


@dataclass
class Entry:
    ip: str
    ts: datetime | None
    method: str
    path: str
    status: int
    size: int
    referer: str
    ua: str
    raw: str


@dataclass
class LogReport:
    lines_total: int = 0
    lines_parsed: int = 0
    window: tuple[str, str] = ("", "")
    findings: list[dict] = field(default_factory=list)
    suspects: list[dict] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    spam_paths: list[dict] = field(default_factory=list)
    summary: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "lines_total": self.lines_total, "lines_parsed": self.lines_parsed,
            "window": list(self.window), "findings": self.findings,
            "suspects": self.suspects, "timeline": self.timeline,
            "spam_paths": self.spam_paths, "summary": self.summary,
        }


def parse_line(line: str) -> Entry | None:
    m = COMBINED.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    try:
        ts = datetime.strptime(d["ts"], TS_FORMAT)
    except (ValueError, TypeError):
        ts = None
    try:
        size = int(d["size"]) if d["size"].isdigit() else 0
    except (AttributeError, ValueError):
        size = 0
    return Entry(
        ip=d["ip"], ts=ts, method=d["method"], path=d["path"] or "",
        status=int(d["status"]), size=size,
        referer=d.get("referer") or "", ua=d.get("ua") or "", raw=line.strip(),
    )


def _iso(ts: datetime | None) -> str:
    return ts.isoformat() if ts else ""


def analyse(text: str, spam_terms: list[str] | None = None) -> LogReport:
    """Reconstruct what happened from an access log."""
    from .engines.seospam import SPAM_PATH_HINTS, SPAM_TERMS

    terms = [t.lower() for t in (spam_terms or SPAM_TERMS)]
    report = LogReport()

    entries: list[Entry] = []
    for line in text.splitlines():
        report.lines_total += 1
        entry = parse_line(line)
        if entry:
            entries.append(entry)
    report.lines_parsed = len(entries)

    if not entries:
        report.summary.append(
            "No lines matched the Apache/Nginx combined log format. If this is a "
            "different format, the log needs converting before analysis.")
        return report

    stamped = [e for e in entries if e.ts]
    if stamped:
        report.window = (_iso(min(e.ts for e in stamped)),
                         _iso(max(e.ts for e in stamped)))

    # ---------- 1. requests to spam paths ----------
    spam_hits: dict[str, list[Entry]] = defaultdict(list)
    for e in entries:
        low = e.path.lower()
        if any(h in low for h in SPAM_PATH_HINTS) or any(t in low for t in terms):
            spam_hits[e.path.split("?")[0]].append(e)

    for path, hits in sorted(spam_hits.items(), key=lambda kv: -len(kv[1]))[:40]:
        stamped_hits = [h for h in hits if h.ts]
        first = min((h.ts for h in stamped_hits), default=None)
        crawlers = sum(1 for h in hits if CRAWLER_UA.search(h.ua))
        report.spam_paths.append({
            "path": path,
            "requests": len(hits),
            "first_seen": _iso(first),
            "crawler_requests": crawlers,
            "distinct_ips": len({h.ip for h in hits}),
        })

    # ---------- 2. earliest evidence — when did this start ----------
    first_spam = None
    if spam_hits:
        all_stamped = [h for hits in spam_hits.values() for h in hits if h.ts]
        if all_stamped:
            first_spam = min(all_stamped, key=lambda h: h.ts)
            report.findings.append({
                "title": "Approximate start of the compromise",
                "severity": "high",
                "detail": f"The earliest request to an injected path in this log is "
                          f"{_iso(first_spam.ts)} for {first_spam.path}. The injection "
                          f"happened at or before that moment — check whether the log "
                          f"actually reaches further back, or whether an earlier file "
                          f"was rotated away.",
                "evidence": first_spam.raw[:400],
            })

    # ---------- 3. webshell behaviour: POSTs where they don't belong ----------
    posts: dict[str, list[Entry]] = defaultdict(list)
    for e in entries:
        if e.method != "POST":
            continue
        clean = e.path.split("?")[0]
        if SHELL_NAMES.search(clean) or SUSPICIOUS_POST.search(clean):
            posts[clean].append(e)

    for path, hits in sorted(posts.items(), key=lambda kv: -len(kv[1]))[:20]:
        ips = Counter(h.ip for h in hits)
        named_shell = bool(SHELL_NAMES.search(path))
        report.findings.append({
            "title": f"POST requests to {path}",
            "severity": "critical" if named_shell else "high",
            "detail": (
                f"{len(hits)} POST request(s) from {len(ips)} IP(s). "
                + ("The filename matches known webshell naming. " if named_shell else "")
                + "A content site should not accept POSTs to this path. This is the "
                  "most likely command channel — treat the file as hostile, preserve "
                  "it, then remove it."),
            "evidence": "\n".join(h.raw[:300] for h in hits[:5]),
            "ips": [{"ip": ip, "requests": n} for ip, n in ips.most_common(10)],
        })

    # ---------- 4. suspects: who touched the injected content ----------
    actor_score: dict[str, dict] = defaultdict(
        lambda: {"requests": 0, "spam": 0, "posts": 0, "tool_ua": False,
                 "uas": Counter(), "first": None, "last": None, "paths": Counter()})

    for e in entries:
        a = actor_score[e.ip]
        a["requests"] += 1
        a["uas"][e.ua[:120]] += 1
        a["paths"][e.path.split("?")[0][:120]] += 1
        if e.ts:
            a["first"] = e.ts if a["first"] is None else min(a["first"], e.ts)
            a["last"] = e.ts if a["last"] is None else max(a["last"], e.ts)
        low = e.path.lower()
        if any(h in low for h in SPAM_PATH_HINTS) or any(t in low for t in terms):
            a["spam"] += 1
        if e.method == "POST" and (SHELL_NAMES.search(low) or SUSPICIOUS_POST.search(low)):
            a["posts"] += 1
        if TOOL_UA.search(e.ua):
            a["tool_ua"] = True

    for ip, a in actor_score.items():
        # Crawlers request spam paths too — they're victims of the cloaking,
        # not perpetrators. Exclude them or the suspect list is meaningless.
        if all(CRAWLER_UA.search(ua) for ua in a["uas"] if ua):
            continue
        score = a["posts"] * 10 + a["spam"] * 2 + (5 if a["tool_ua"] else 0)
        if score < 4:
            continue
        reasons = []
        if a["posts"]:
            reasons.append(f"{a['posts']} POST(s) to suspicious paths")
        if a["spam"]:
            reasons.append(f"{a['spam']} request(s) to injected paths")
        if a["tool_ua"]:
            reasons.append("automated tooling user-agent")
        report.suspects.append({
            "ip": ip,
            "score": score,
            "requests": a["requests"],
            "first_seen": _iso(a["first"]),
            "last_seen": _iso(a["last"]),
            "user_agents": [u for u, _ in a["uas"].most_common(3)],
            "top_paths": [p for p, _ in a["paths"].most_common(5)],
            "why": "; ".join(reasons),
        })
    report.suspects.sort(key=lambda s: -s["score"])
    report.suspects = report.suspects[:25]

    # ---------- 5. what happened just before the first spam request ----------
    if first_spam and first_spam.ts:
        prior = sorted(
            (e for e in entries if e.ts and e.ts <= first_spam.ts),
            key=lambda e: e.ts)[-40:]
        report.timeline = [{
            "ts": _iso(e.ts), "ip": e.ip, "method": e.method,
            "path": e.path[:160], "status": e.status, "ua": e.ua[:100],
        } for e in prior]
        report.findings.append({
            "title": "Requests immediately before the first spam hit",
            "severity": "info",
            "detail": "The entry vector is usually visible here — a POST to an upload "
                      "endpoint, a request with a traversal or injection payload, or a "
                      "successful admin login. Read this window line by line.",
            "evidence": "",
        })

    # ---------- 6. tooling ----------
    scanners = {e.ip for e in entries if TOOL_UA.search(e.ua)}
    if scanners:
        report.findings.append({
            "title": f"{len(scanners)} IP(s) using automated tooling",
            "severity": "medium",
            "detail": "Requests with scanner or scripting user-agents. On its own this "
                      "is background noise on any public site — it matters only if the "
                      "same IP also appears in the suspects list.",
            "evidence": ", ".join(sorted(scanners)[:20]),
        })

    # ---------- summary ----------
    if report.spam_paths:
        total = sum(p["requests"] for p in report.spam_paths)
        crawler = sum(p["crawler_requests"] for p in report.spam_paths)
        report.summary.append(
            f"{len(report.spam_paths)} injected path(s), {total} request(s) total; "
            f"{crawler} came from search engine crawlers — that is the indexing you "
            f"see in Google results.")
    if posts:
        report.summary.append(
            f"{len(posts)} path(s) receiving POSTs that shouldn't. Start here: this is "
            f"most likely the attacker's control channel.")
    if report.suspects:
        top = report.suspects[0]
        report.summary.append(
            f"Highest-scoring source is {top['ip']} ({top['why']}), active "
            f"{top['first_seen'][:10]} to {top['last_seen'][:10]}.")
    if not report.findings:
        report.summary.append(
            "Nothing matching a known compromise pattern in this log. That doesn't "
            "clear the server — the relevant window may have been rotated away, or the "
            "injection may predate this file.")
    report.summary.append(
        "An IP is a starting point, not an identity. Attribution needs the ISP or "
        "hosting provider to act on a lawful request — that is the university's and "
        "law enforcement's job, not yours.")
    return report
