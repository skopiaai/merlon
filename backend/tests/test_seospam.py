"""Cloaking and SEO-spam detection tests.

Modelled on the campaign currently hitting .edu domains: Thai gambling pages
served to Googlebot from university subdomains, with the real page shown to
anyone browsing normally.
"""

import pytest

from app.engines import seospam

THAI_SPAM = """<html><head><title>ปั่นสล็อตทดลอง สายปั่นห้ามพลาด แตกหนักโบนัส PRAGMATIC</title></head>
<body><h1>สล็อต ทดลองฟรี</h1>
<p>เว็บตรง ไม่ผ่านเอเย่นต์ ฝากถอน ออโต้ โบนัส 100% บาคาร่า คาสิโน</p>
<p>ทดลองเล่นสล็อต สายปั่นห้ามพลาด เครดิตฟรี แทงบอล หวย</p>
</body></html>"""

REAL_PAGE = """<html><head><title>Example University — Admissions</title></head>
<body><h1>Welcome to the University</h1>
<p>Explore our undergraduate and postgraduate programmes in engineering,
management and law. Applications for the autumn intake are now open.</p>
</body></html>"""


# ------------------------------------------------------- spam vocabulary

def test_thai_gambling_terms_detected():
    found = seospam._spam_terms_in(THAI_SPAM)
    assert "สล็อต" in found
    assert len(found) >= 3


def test_legitimate_page_has_no_spam_terms():
    assert seospam._spam_terms_in(REAL_PAGE) == []


@pytest.mark.parametrize("term", [
    # one from each campaign language we claim to cover
    "カジノ", "카지노", "judi", "slot gacor", "pragmatic play", "老虎机",
    "nhà cái", "казино", "bahis", "apostas", "सट्टा", "viagra",
    "replica watches", "write my essay",
])
def test_other_language_campaigns_covered(term):
    # Terms overlap by design ("slot gacor" also matches "gacor"), so assert
    # membership rather than an exact match.
    assert term in seospam._spam_terms_in(f"<p>{term}</p>")


# ----------------------------------------------------------- script check

def test_thai_script_detected():
    found, label = seospam._has_foreign_script(THAI_SPAM * 6)
    assert found
    assert "THAI" in label


def test_english_page_not_flagged_as_foreign():
    assert seospam._has_foreign_script(REAL_PAGE)[0] is False


def test_a_few_foreign_characters_are_tolerated():
    """A name or a quotation shouldn't trip the detector."""
    page = REAL_PAGE + "<p>Prof. 田中 visited campus.</p>"
    assert seospam._has_foreign_script(page)[0] is False


# -------------------------------------------------------- spam redirects

@pytest.mark.parametrize("url", [
    "https://evil.example/slot-online",
    "http://pgslot88.test/x",
    "https://cdn.test/redirect?to=ufabet",
    "https://togel-site.test/",
])
def test_spam_destinations_matched(url):
    assert seospam.SPAM_DESTINATION.search(url)


def test_ordinary_url_not_matched():
    assert not seospam.SPAM_DESTINATION.search("https://example.edu/admissions")


def test_js_redirect_extracted():
    html = '<script>window.location.href="https://pgslot.test/go";</script>'
    m = seospam.JS_REDIRECT.search(html)
    assert m
    assert "pgslot.test" in (m.group(1) or m.group(2))


def test_location_replace_form_extracted():
    html = '<script>location.replace("https://slot-x.test/a")</script>'
    m = seospam.JS_REDIRECT.search(html)
    assert m and "slot-x.test" in (m.group(1) or m.group(2))


# --------------------------------------------------- normalisation / diff

def test_normalise_removes_volatile_content():
    a = seospam._normalise("<p>hi</p><!-- nonce a1b2c3d4e5f60718 --> 2026-08-10T10:00:00")
    b = seospam._normalise("<p>hi</p><!-- nonce 9f8e7d6c5b4a3021 --> 2026-08-11T11:00:00")
    assert a == b, "identical pages must not look different because of nonces"


def test_normalise_keeps_real_differences():
    assert seospam._normalise(REAL_PAGE) != seospam._normalise(THAI_SPAM)


def test_title_extraction():
    assert "Admissions" in seospam._title(REAL_PAGE)
    assert "สล็อต" in seospam._title(THAI_SPAM)


# ------------------------------------------------------ end-to-end verdict

@pytest.mark.parametrize("persona", ["googlebot", "from_google"])
def test_cloaking_is_detected_and_rated_critical(monkeypatch, persona):
    """The real shape of the attack: crawler gets spam, browser gets the site."""
    async def fake_fetch(url, headers, timeout=20):
        ua = headers.get("User-Agent", "")
        ref = headers.get("Referer", "")
        is_bot = "Googlebot" in ua
        from_google = "google.com" in ref
        target = is_bot if persona == "googlebot" else from_google
        return (200, url, THAI_SPAM if target else REAL_PAGE)

    monkeypatch.setattr(seospam, "_fetch", fake_fetch)
    findings = _run(seospam.audit_url("https://campus.example.edu/"))

    cloak = [f for f in findings if f["rule_id"].startswith("seo-cloaking")]
    assert cloak, f"cloaking not detected for {persona}"
    assert cloak[0]["severity"].value == "critical"
    assert "compromised" in cloak[0]["description"]
    assert "Search Console" in cloak[0]["remediation"]


def test_clean_site_produces_no_findings(monkeypatch):
    async def fake_fetch(url, headers, timeout=20):
        return (200, url, REAL_PAGE)

    monkeypatch.setattr(seospam, "_fetch", fake_fetch)
    assert _run(seospam.audit_url("https://example.edu/")) == []


def test_spam_visible_to_everyone_is_high(monkeypatch):
    async def fake_fetch(url, headers, timeout=20):
        return (200, url, THAI_SPAM)

    monkeypatch.setattr(seospam, "_fetch", fake_fetch)
    findings = _run(seospam.audit_url("https://example.edu/x"))
    direct = [f for f in findings if f["rule_id"] == "seo-spam-content"]
    assert direct and direct[0]["severity"].value == "high"


def test_offdomain_gambling_redirect_is_critical(monkeypatch):
    async def fake_fetch(url, headers, timeout=20):
        return (200, "https://pgslot99.test/landing", THAI_SPAM)

    monkeypatch.setattr(seospam, "_fetch", fake_fetch)
    findings = _run(seospam.audit_url("https://example.edu/go"))
    assert any(f["rule_id"] == "malicious-redirect" and f["severity"].value == "critical"
               for f in findings)


def test_unreachable_host_is_not_an_error(monkeypatch):
    async def fake_fetch(url, headers, timeout=20):
        return (0, url, "")

    monkeypatch.setattr(seospam, "_fetch", fake_fetch)
    assert _run(seospam.audit_url("https://down.example/")) == []


def _run(coro):
    from .conftest import run_coroutine
    return run_coroutine(coro)
