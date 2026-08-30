"""Log forensics tests.

Built on a synthetic access log shaped like a real SEO-spam compromise: an
upload of a webshell, POSTs to it, then Googlebot indexing the injected
gambling pages for weeks afterwards.
"""

import pytest

from app import forensics

LOG = """\
203.0.113.9 - - [01/Jul/2026:02:14:03 +0530] "GET /wp-login.php HTTP/1.1" 200 4021 "-" "python-requests/2.31.0"
203.0.113.9 - - [01/Jul/2026:02:14:44 +0530] "POST /wp-login.php HTTP/1.1" 302 0 "-" "python-requests/2.31.0"
203.0.113.9 - - [01/Jul/2026:02:15:10 +0530] "POST /wp-admin/admin-ajax.php HTTP/1.1" 200 32 "-" "python-requests/2.31.0"
203.0.113.9 - - [01/Jul/2026:02:16:02 +0530] "POST /wp-content/uploads/2026/07/wso.php HTTP/1.1" 200 1580 "-" "Mozilla/5.0"
203.0.113.9 - - [01/Jul/2026:02:18:31 +0530] "POST /wp-content/uploads/2026/07/wso.php HTTP/1.1" 200 940 "-" "Mozilla/5.0"
198.51.100.4 - - [03/Jul/2026:11:02:00 +0530] "GET /metric_523 HTTP/1.1" 200 18400 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
198.51.100.4 - - [03/Jul/2026:11:02:40 +0530] "GET /course-list/slot-888 HTTP/1.1" 200 17300 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
198.51.100.4 - - [04/Jul/2026:09:31:00 +0530] "GET /metric_523 HTTP/1.1" 200 18400 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
192.0.2.77 - - [05/Jul/2026:19:44:12 +0530] "GET /admissions HTTP/1.1" 200 8800 "-" "Mozilla/5.0 (Macintosh)"
192.0.2.77 - - [05/Jul/2026:19:45:01 +0530] "GET /courses HTTP/1.1" 200 7200 "-" "Mozilla/5.0 (Macintosh)"
203.0.113.9 - - [09/Jul/2026:04:02:00 +0530] "POST /wp-content/uploads/2026/07/wso.php HTTP/1.1" 200 220 "-" "Mozilla/5.0"
"""


@pytest.fixture
def report():
    return forensics.analyse(LOG)


# --------------------------------------------------------------- parsing

def test_all_lines_parse():
    r = forensics.analyse(LOG)
    assert r.lines_parsed == r.lines_total == 11


def test_parse_line_extracts_fields():
    e = forensics.parse_line(LOG.splitlines()[0])
    assert e.ip == "203.0.113.9"
    assert e.method == "GET"
    assert e.status == 200
    assert "python-requests" in e.ua
    assert e.ts and e.ts.year == 2026


def test_unparseable_input_is_reported_not_crashed():
    r = forensics.analyse("this is not a log file\nnor is this\n")
    assert r.lines_parsed == 0
    assert any("combined log format" in s for s in r.summary)


def test_empty_input():
    assert forensics.analyse("").lines_parsed == 0


def test_time_window_is_reported(report):
    assert report.window[0].startswith("2026-07-01")
    assert report.window[1].startswith("2026-07-09")


# ------------------------------------------------------- webshell detection

def test_webshell_posts_flagged_critical(report):
    shell = [f for f in report.findings if "wso.php" in f["title"]]
    assert shell, "POSTs to a known webshell filename must be flagged"
    assert shell[0]["severity"] == "critical"
    assert shell[0]["ips"][0]["ip"] == "203.0.113.9"


def test_webshell_finding_counts_requests(report):
    shell = next(f for f in report.findings if "wso.php" in f["title"])
    assert "3 POST request(s)" in shell["detail"]


# ------------------------------------------------------------ spam paths

def test_injected_paths_identified(report):
    paths = {p["path"] for p in report.spam_paths}
    assert "/course-list/slot-888" in paths


def test_crawler_requests_counted(report):
    slot = next(p for p in report.spam_paths if "slot" in p["path"])
    assert slot["crawler_requests"] >= 1


def test_compromise_start_estimated(report):
    start = [f for f in report.findings if "start of the compromise" in f["title"]]
    assert start
    assert "2026-07-03" in start[0]["detail"]


# --------------------------------------------------------------- suspects

def test_attacker_ip_is_top_suspect(report):
    assert report.suspects
    assert report.suspects[0]["ip"] == "203.0.113.9"
    assert "POST" in report.suspects[0]["why"]


def test_googlebot_is_not_listed_as_a_suspect(report):
    """The crawler requests spam paths because it's the victim of the cloaking."""
    assert "198.51.100.4" not in {s["ip"] for s in report.suspects}


def test_ordinary_visitor_is_not_a_suspect(report):
    assert "192.0.2.77" not in {s["ip"] for s in report.suspects}


def test_suspect_records_activity_window(report):
    top = report.suspects[0]
    assert top["first_seen"].startswith("2026-07-01")
    assert top["last_seen"].startswith("2026-07-09")


def test_tooling_user_agent_noted(report):
    top = report.suspects[0]
    assert any("python-requests" in ua for ua in top["user_agents"])


# --------------------------------------------------------------- timeline

def test_timeline_shows_events_before_first_spam_hit(report):
    assert report.timeline
    paths = [t["path"] for t in report.timeline]
    assert any("wp-login.php" in p for p in paths), \
        "the entry vector should appear in the pre-compromise window"


# ---------------------------------------------------------------- summary

def test_summary_is_actionable(report):
    joined = " ".join(report.summary)
    assert "control channel" in joined
    assert "crawlers" in joined


def test_summary_states_the_limit_of_attribution(report):
    """An IP is not an identity — the report must say so."""
    assert any("not an identity" in s for s in report.summary)


def test_clean_log_produces_no_alarm():
    clean = """\
192.0.2.5 - - [01/Jul/2026:10:00:00 +0530] "GET / HTTP/1.1" 200 5000 "-" "Mozilla/5.0"
192.0.2.5 - - [01/Jul/2026:10:00:05 +0530] "GET /about HTTP/1.1" 200 4000 "-" "Mozilla/5.0"
"""
    r = forensics.analyse(clean)
    assert r.suspects == []
    assert any("Nothing matching a known compromise pattern" in s for s in r.summary)
