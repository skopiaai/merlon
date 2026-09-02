"""SEO spam and cloaking detection.

The attack this catches: someone gains write access to a site — usually via a
vulnerable CMS plugin, an exposed admin panel, or a file upload flaw — and
plants pages that show gambling or pharmacy spam to Googlebot while showing
normal content to everyone else. The university's own staff see nothing wrong;
Google indexes hundreds of spam pages under their domain; visitors who click
through from search get redirected to a gambling site.

It is one of the most under-reported findings on institutional domains, because
nobody looks at what their site serves to a crawler. It is also unambiguous
evidence of compromise rather than a configuration weakness — so it outranks
almost anything else a scanner finds.

Detection is entirely passive: fetch the same URL as different clients and
compare. Nothing is modified.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import unicodedata

from ..models import Severity
from ..normalize import make_dedupe_key
from .registry import EngineSpec, register

# Personas. Cloaking works by branching on these, so requesting the same URL
# several ways and diffing is the whole technique.
PERSONAS = {
    "browser": {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    },
    "googlebot": {
        "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; "
                      "+http://www.google.com/bot.html)",
    },
    "from_google": {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                      "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile Safari/604.1",
        "Referer": "https://www.google.com/",
    },
}

# Gambling / pharma / adult spam vocabulary across the languages these
# campaigns actually use. Thai and Japanese dominate the current wave.
SPAM_TERMS = [
    # --- Thai: the campaign currently hitting Indian .edu domains ---
    "สล็อต", "บาคาร่า", "คาสิโน", "แทงบอล", "หวย", "เว็บตรง", "ฝากถอน",
    "โบนัส", "เครดิตฟรี", "ปั่นสล็อต", "ทดลองเล่น", "สล็อตเว็บตรง",
    "ไม่ผ่านเอเย่นต์", "ถอนออโต้", "ฟรีสปิน", "แจกเครดิต", "พนันออนไลน์",
    "เดิมพัน", "ยิงปลา", "ไฮโล", "รูเล็ต", "เกมสล็อต", "สมัครสมาชิก",
    "แตกหนัก", "ลิขสิทธิ์แท้", "เว็บหลัก", "ทางเข้า", "โปรโมชั่น",
    # --- Japanese ---
    "カジノ", "オンラインカジノ", "スロット", "バカラ", "ブックメーカー",
    "パチンコ", "賭博", "ギャンブル", "入金不要", "ボーナス",
    # --- Chinese ---
    "老虎机", "百家乐", "在线赌场", "博彩", "娱乐城", "赌场", "彩票",
    "六合彩", "时时彩", "网上赌博", "真人娱乐",
    # --- Korean ---
    "카지노", "바카라", "슬롯", "토토", "먹튀", "온라인카지노", "도박",
    "안전놀이터", "사설토토",
    # --- Indonesian / Malay ---
    "judi", "judi online", "slot gacor", "togel", "situs slot", "maxwin",
    "bandar", "poker online", "agen bola", "slot terpercaya", "rtp slot",
    # --- Vietnamese ---
    "nhà cái", "cá cược", "casino truc tuyen", "đánh bài", "lô đề",
    # --- Hindi / Bengali (targets Indian institutional domains) ---
    "सट्टा", "जुआ", "कैसीनो", "लॉटरी", "मटका",
    # --- Russian ---
    "казино", "букмекер", "ставки на спорт", "игровые автоматы",
    # --- Turkish ---
    "bahis", "casino siteleri", "bonus veren", "güvenilir bahis",
    # --- Portuguese / Spanish ---
    "apostas", "cassino online", "casa de apostas", "apuestas", "tragamonedas",
    # --- English gambling ---
    "pragmatic play", "slot online", "free spins", "casino bonus", "sportsbook",
    "betting site", "online casino", "no deposit bonus", "jackpot slot",
    "live baccarat", "toto site", "gacor", "situs judi",
    # --- Pharmacy spam ---
    # The "pharma hack" is the oldest variant and still circulating. Same
    # entry points and same cloaking as the gambling campaigns; only the
    # keywords differ.
    "viagra", "cialis", "levitra", "tadalafil", "sildenafil", "kamagra",
    "buy pills online", "no prescription", "cheap meds", "canadian pharmacy",
    "online pharmacy", "buy tramadol", "oxycodone", "ambien", "xanax online",
    "バイアグラ", "виагра", "сиалис", "دواء",

    # --- Counterfeit luxury goods: the Japanese keyword hack's real payload ---
    # This variant was the single most frequently detected website malware in
    # Sucuri's threat reporting — roughly one in ten infected sites. It turns a
    # legitimate domain into a doorway page for fake Louis Vuitton, Rolex,
    # Gucci, Nike and Supreme aimed at Japanese-speaking buyers, which is why
    # the vocabulary is mostly Japanese retail language rather than obscenity.
    "ブランドコピー", "スーパーコピー", "コピー品", "偽物", "激安", "通販",
    "n級品", "ルイヴィトン", "ロレックス", "グッチ", "シャネル", "エルメス",
    "プラダ", "腕時計 コピー", "財布 コピー", "バッグ 激安", "最安値",
    "送料無料", "正規品", "新作", "人気商品", "口コミ",
    "명품 레플리카", "레플리카", "이미테이션",
    "奢侈品", "高仿", "复刻表", "代购",
    "replica watches", "replica handbags", "fake rolex", "designer replica",
    "cheap jordans", "wholesale nike", "yeezy replica", "aaa replica",

    # --- Essay mills, piracy, other classic injections ---
    "essay writing service", "write my essay", "assignment help online",
    "dissertation writing", "escort service", "porn video",
    "streaming gratis", "crack download", "nulled script", "keygen serial",
    "free robux", "hack tool", "generator no survey", "mod apk download",
    "iptv gratuit", "смотреть онлайн бесплатно",
]

# Content the visitor cannot see but a crawler indexes. Research on these
# campaigns is consistent on this point: the injected block is "frequently
# invisible to site visitors and administrators", which is precisely why an
# owner can look at their own page, see nothing wrong, and still be delisted.
#
# So this looks for the CSS that hides it rather than for the words alone.
HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    r"|font-size\s*:\s*0(?:px|pt|em)?\b"
    r"|opacity\s*:\s*0(?:\.0+)?\s*[;\"'}]"
    r"|text-indent\s*:\s*-\s*\d{3,}"
    r"|(?:left|top|margin-left|margin-top)\s*:\s*-\s*\d{4,}"
    r"|height\s*:\s*(?:0|1)px\s*;\s*overflow\s*:\s*hidden"
    r"|clip\s*:\s*rect\(\s*0",
    re.I)

# An element carrying one of those styles, with its content.
HIDDEN_BLOCK = re.compile(
    r"<(div|span|p|ul|ol|section|a)\b[^>]*"
    r"(?:style\s*=\s*[\"'][^\"']*"
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|"
    r"text-indent\s*:\s*-\s*\d{3,}|opacity\s*:\s*0)"
    r"[^\"']*[\"'])[^>]*>(.{0,3000}?)</\1>",
    re.I | re.S)

# Paths these campaigns plant. Seeing several of these 200-OK on a site is
# itself strong evidence, independent of content.
SPAM_PATH_HINTS = [
    "/slot", "/casino", "/judi", "/togel", "/bet", "/gacor", "/situs",
    "/sbobet", "/pgslot", "/pragmatic", "/สล็อต", "/카지노", "/wp-includes/js/",
    "/metric_", "/course-list/slot", "/.well-known/slot",
]

# Affiliate / campaign identifiers in redirect URLs. Extracting these lets you
# link the same operator across many victim domains — real threat intel for a
# disclosure report.
AFFILIATE_ID = re.compile(
    r"[?&](?:aff|affid|aff_id|ref|refer|referral|utm_source|utm_campaign|"
    r"partner|pid|clickid|sub_id|campaign)=([A-Za-z0-9_\-]{3,60})", re.I)

# Domains and TLDs these campaigns redirect into.
SPAM_DESTINATION = re.compile(
    r"https?://[^\s\"'<>]*?("
    r"slot|casino|judi|togel|bet\d|gacor|bacc?ara|188bet|w88|ufabet|pgslot"
    r")[^\s\"'<>]*", re.I)

# JS redirect patterns used to bounce the visitor after the page renders.
JS_REDIRECT = re.compile(
    r"(?:window\.)?location(?:\.href)?\s*=\s*[\"']([^\"']+)[\"']"
    r"|location\.replace\(\s*[\"']([^\"']+)[\"']", re.I)


def hidden_spam(html: str) -> list[tuple[str, list[str]]]:
    """Spam inside elements the visitor cannot see.

    Returns (excerpt, matched_terms) for each hidden block that contains spam
    vocabulary. Hidden text alone is not reported — sites legitimately hide
    things: screen-reader labels, tab panels, print-only blocks, cookie
    banners. Hidden text that is *also* selling counterfeit handbags is not
    ambiguous.

    This catches the case the site owner cannot: they load their own page, see
    their own content, and have no idea why Google delisted them.
    """
    found: list[tuple[str, list[str]]] = []
    for match in HIDDEN_BLOCK.finditer(html or ""):
        inner = match.group(2) or ""
        text = re.sub(r"<[^>]+>", " ", inner)
        terms = _spam_terms_in(text)
        if terms:
            excerpt = " ".join(text.split())[:220]
            found.append((excerpt, terms))
    return found


def link_stuffing(html: str, threshold: int = 15) -> list[str]:
    """Off-domain links inside hidden blocks — the point of the injection.

    Doorway pages exist to pass link equity. A hidden block holding a dozen
    external links is a link farm regardless of what the anchor text says, and
    counting them separates a genuine injection from a page that happens to use
    one hidden div.
    """
    links: list[str] = []
    for match in HIDDEN_BLOCK.finditer(html or ""):
        for href in re.findall(r"href\s*=\s*[\"']([^\"']+)[\"']",
                               match.group(2) or "", re.I):
            if href.startswith("http"):
                links.append(href)
    return links if len(links) >= threshold else []


def spam_in_sitemap(body: str) -> list[str]:
    """Spam URLs listed in a sitemap.

    A compromised site usually gets a sitemap of its doorway pages, because the
    attacker needs them indexed and cannot rely on the site linking to them.
    That makes the sitemap the most reliable single place to see the scale of a
    compromise: it is the attacker's own inventory of what they planted.
    """
    urls = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body or "", re.I)
    return [u for u in urls
            if _spam_terms_in(u) or SPAM_DESTINATION.search(u)][:50]


def _has_foreign_script(text: str) -> tuple[bool, str]:
    """Detect CJK/Thai/Cyrillic/Arabic text on a page that shouldn't have it."""
    counts: dict[str, int] = {}
    for ch in text[:200_000]:
        if ch.isspace() or ch.isascii():
            continue
        try:
            block = unicodedata.name(ch).split()[0]
        except ValueError:
            continue
        if block in ("THAI", "CJK", "HIRAGANA", "KATAKANA", "HANGUL",
                     "CYRILLIC", "ARABIC"):
            counts[block] = counts.get(block, 0) + 1
    if not counts:
        return False, ""
    script, n = max(counts.items(), key=lambda kv: kv[1])
    # A handful of characters is normal (a name, a quote). Hundreds is not.
    return (n > 80), f"{script} ({n} characters)"


def _spam_terms_in(text: str) -> list[str]:
    low = text.lower()
    return [t for t in SPAM_TERMS if t.lower() in low][:12]


def _normalise(html: str) -> str:
    """Strip volatile content so two fetches of an honest page look identical."""
    html = re.sub(r"<!--.*?-->", "", html, flags=re.S)
    html = re.sub(r"\b[0-9a-f]{16,}\b", "", html, flags=re.I)   # nonces, hashes
    html = re.sub(r"\d{4}-\d{2}-\d{2}[T ][\d:]+", "", html)      # timestamps
    html = re.sub(r"\s+", " ", html)
    return html.strip()


def _title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""


async def _fetch(url: str, headers: dict, timeout: int = 20) -> tuple[int, str, str]:
    """Fetch with curl — already in the image, and easy to control precisely.

    Returns (status, final_url, body). Redirects are followed so we can see
    where a visitor actually lands.
    """
    argv = ["curl", "-sS", "-L", "--max-time", str(timeout),
            "--max-redirs", "5", "-w", "\n---META---\n%{http_code}\n%{url_effective}"]
    for k, v in headers.items():
        argv += ["-H", f"{k}: {v}"]
    argv.append(url)
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 10)
    except (asyncio.TimeoutError, OSError):
        return 0, url, ""
    text = out.decode("utf-8", "replace")
    if "\n---META---\n" not in text:
        return 0, url, text
    body, meta = text.rsplit("\n---META---\n", 1)
    parts = meta.strip().splitlines()
    status = int(parts[0]) if parts and parts[0].isdigit() else 0
    final = parts[1] if len(parts) > 1 else url
    return status, final, body


def _finding(rule_id, name, sev, host, url, desc, fix, evidence="", tags=None):
    return {
        "engine": "seospam",
        "rule_id": rule_id,
        "name": name,
        "severity": sev,
        "host": host,
        "url": url,
        "matched_at": url,
        "description": desc,
        "evidence": evidence[:6000],
        "remediation": fix,
        "references": [
            "https://developers.google.com/search/docs/monitor-debug/security/hacked-content",
            "https://developers.google.com/search/docs/essentials/spam-policies#cloaking",
        ],
        "tags": ["seo-spam", "compromise"] + (tags or []),
        "cve": [], "cwe": ["CWE-506"], "cvss_score": None,
        "dedupe_key": make_dedupe_key("seospam", rule_id, host, url),
        "raw": {},
    }


REMEDIATION = (
    "Treat this as a compromise, not a misconfiguration — someone has write "
    "access to the site.\n\n"
    "1. Preserve evidence first: snapshot the files and web/access logs before "
    "changing anything.\n"
    "2. Find the injected content — commonly a modified index/header template, "
    "a rogue plugin or theme, or PHP files with recent modification times. "
    "Compare against a known-good backup or the upstream release.\n"
    "3. Find the entry point: check for a webshell (files accepting a "
    "parameter and calling eval/system), unpatched CMS or plugin versions, and "
    "an exposed or brute-forced admin login.\n"
    "4. Rotate every credential — CMS admins, database, FTP/SSH, API keys.\n"
    "5. Patch the entry vector, then remove the spam content.\n"
    "6. In Google Search Console, review the Security Issues report, remove "
    "the spam URLs, and request a review. Until then the domain keeps ranking "
    "for gambling terms.\n"
    "7. Add file integrity monitoring so the next injection is noticed in days "
    "rather than months."
)


async def audit_url(url: str, *, log=None) -> list[dict]:
    """Fetch one URL as three different clients and compare."""
    from urllib.parse import urlparse
    host = (urlparse(url).hostname or url).lower()
    findings: list[dict] = []

    results = await asyncio.gather(
        *(_fetch(url, h) for h in PERSONAS.values()), return_exceptions=True)
    pages: dict[str, tuple[int, str, str]] = {}
    for persona, res in zip(PERSONAS, results, strict=True):
        if isinstance(res, Exception) or not isinstance(res, tuple):
            continue
        pages[persona] = res

    if "browser" not in pages or not pages["browser"][2]:
        return findings

    _, browser_final, browser_body = pages["browser"]
    browser_norm = _normalise(browser_body)
    browser_hash = hashlib.sha256(browser_norm.encode()).hexdigest()

    # ---- 1. cloaking: does the crawler get a different page? ----
    for persona in ("googlebot", "from_google"):
        if persona not in pages:
            continue
        _, final, body = pages[persona]
        if not body:
            continue
        norm = _normalise(body)
        if hashlib.sha256(norm.encode()).hexdigest() == browser_hash:
            continue

        # Ignore trivial differences — personalisation, A/B tests, ads.
        ratio = abs(len(norm) - len(browser_norm)) / max(len(browser_norm), 1)
        t_browser, t_other = _title(browser_body), _title(body)
        spam_in_other = _spam_terms_in(body)
        foreign, script = _has_foreign_script(body)

        if spam_in_other or (foreign and not _has_foreign_script(browser_body)[0]):
            label = "search engine crawler" if persona == "googlebot" \
                else "visitor arriving from Google"
            findings.append(_finding(
                f"seo-cloaking-{persona}",
                f"Cloaked spam content served to {label}",
                Severity.critical, host, url,
                f"This URL returns different content depending on who asks. As a "
                f"{label} it serves spam"
                f"{' containing ' + ', '.join(spam_in_other[:4]) if spam_in_other else ''}"
                f"{'; the page is in ' + script if foreign else ''}, while a normal "
                f"browser sees the legitimate page. This is deliberate cloaking, "
                f"which means the site is compromised — an attacker has write access "
                f"and is monetising the domain's search reputation. Staff viewing the "
                f"site normally will see nothing wrong.",
                REMEDIATION,
                evidence=(f"Title as browser:   {t_browser!r}\n"
                          f"Title as {persona}: {t_other!r}\n"
                          f"Body size differs by {ratio:.0%}\n"
                          f"Spam terms found: {', '.join(spam_in_other) or 'none'}\n"
                          f"Foreign script: {script or 'none'}\n\n"
                          f"--- first 1500 chars served to {persona} ---\n{body[:1500]}"),
                tags=["cloaking", "critical-compromise"],
            ))
        elif ratio > 0.4 or (t_browser and t_other and t_browser != t_other):
            findings.append(_finding(
                "seo-content-differs",
                f"Page content differs substantially for {persona}",
                Severity.medium, host, url,
                "The response changes noticeably based on the User-Agent or Referer. "
                "That can be legitimate (mobile rendering, localisation) but it is "
                "also how cloaking works, so it is worth confirming by hand.",
                "Compare the two responses manually. If the difference isn't explained "
                "by a deliberate feature, investigate as a possible injection.",
                evidence=(f"Title as browser:   {t_browser!r}\n"
                          f"Title as {persona}: {t_other!r}\n"
                          f"Body size differs by {ratio:.0%}"),
                tags=["cloaking"],
            ))

    # ---- 2. spam content visible to everyone ----
    spam_now = _spam_terms_in(browser_body)
    foreign_now, script_now = _has_foreign_script(browser_body)
    if spam_now:
        findings.append(_finding(
            "seo-spam-content", "Gambling or pharmacy spam content on the page",
            Severity.high, host, url,
            f"The page contains spam vocabulary ({', '.join(spam_now[:6])})"
            f"{' and is largely in ' + script_now if foreign_now else ''}. On a "
            f"legitimate institutional site this is injected content, indicating "
            f"someone has write access.",
            REMEDIATION,
            evidence=f"Terms: {', '.join(spam_now)}\nScript: {script_now or 'none'}\n"
                     f"Title: {_title(browser_body)!r}",
            tags=["injection"],
        ))
    elif foreign_now:
        findings.append(_finding(
            "unexpected-language", f"Page is largely in an unexpected script: {script_now}",
            Severity.medium, host, url,
            f"A substantial amount of {script_now} text appears on this page. If the "
            f"site isn't meant to serve that language, it's likely injected content.",
            "Confirm whether this language is expected. If not, treat it as an "
            "injection and follow the compromise checklist.",
            evidence=f"Title: {_title(browser_body)!r}",
            tags=["injection"],
        ))

    # ---- 3. redirect off-domain to a spam destination ----
    for persona, (_status, final, body) in pages.items():
        from urllib.parse import urlparse as up
        final_host = (up(final).hostname or "").lower()
        if final_host and final_host != host and not final_host.endswith("." + host):
            if SPAM_DESTINATION.search(final) or _spam_terms_in(body):
                findings.append(_finding(
                    "malicious-redirect",
                    f"Redirects {persona} to an external gambling site",
                    Severity.critical, host, url,
                    f"Requesting this URL as a {persona} ends up at {final}, which is "
                    f"off-domain and matches known gambling-spam patterns. Visitors "
                    f"clicking this result from a search engine are sent straight to "
                    f"the attacker's site.",
                    REMEDIATION,
                    evidence=f"{url}\n  → {final}",
                    tags=["redirect", "critical-compromise"],
                ))
                break

        # ---- hidden injected content ----
        # Checked on the browser response specifically. This is the variant an
        # owner cannot see by looking: the spam is in the page they are served,
        # inside an element CSS has made invisible.
        if persona == "browser":
            for excerpt, terms in hidden_spam(body)[:3]:
                findings.append(_finding(
                    "seo-hidden-injection",
                    "Hidden spam content injected into the page",
                    Severity.critical, host, url,
                    f"This page contains text that is hidden from visitors by CSS "
                    f"but is fully visible to search engines, and that hidden text "
                    f"matches known spam vocabulary "
                    f"({', '.join(terms[:6])}).\n\n"
                    f"This is the form of compromise an owner cannot find by "
                    f"looking at their own site — you load the page, everything "
                    f"appears normal, and meanwhile the page is ranking for "
                    f"counterfeit goods or gambling terms. It usually surfaces "
                    f"only when Google flags the domain or traffic collapses.\n\n"
                    f"Hidden text on its own is legitimate — screen-reader "
                    f"labels, tab panels, print styles. Hidden text selling "
                    f"replica watches is not.",
                    REMEDIATION,
                    evidence=f"Hidden block on {url}:\n{excerpt}",
                    tags=["compromise", "cloaking", "critical-compromise"],
                ))

            stuffed = link_stuffing(body)
            if stuffed:
                findings.append(_finding(
                    "seo-link-farm",
                    f"{len(stuffed)} hidden outbound links — doorway page",
                    Severity.critical, host, url,
                    f"A block hidden from visitors contains {len(stuffed)} links "
                    f"to external sites. That is a link farm: the page exists to "
                    f"pass your domain's reputation to the attacker's sites.\n\n"
                    f"The damage here is to the domain itself. Search engines "
                    f"penalise the host of the links, so the cost lands on you "
                    f"rather than on whoever planted them.",
                    REMEDIATION,
                    evidence="Hidden outbound links:\n"
                             + "\n".join(f"  {u}" for u in stuffed[:12]),
                    tags=["compromise", "cloaking", "critical-compromise"],
                ))

        for m in JS_REDIRECT.finditer(body or ""):
            dest = m.group(1) or m.group(2) or ""
            if SPAM_DESTINATION.search(dest):
                findings.append(_finding(
                    "js-spam-redirect", "JavaScript redirect to a gambling site",
                    Severity.critical, host, url,
                    f"The page contains script that sends the visitor to {dest} after "
                    f"it loads. Because the redirect happens client-side, server-side "
                    f"checks and most monitoring miss it entirely.",
                    REMEDIATION,
                    evidence=f"Redirect target: {dest}",
                    tags=["redirect", "critical-compromise"],
                ))
                break

    if log and findings:
        await log("warn", f"[seospam] {len(findings)} issue(s) on {url}", "seospam")
    return findings


async def audit(urls: list[str], *, limit: int = 25, log=None) -> list[dict]:
    """Check the most representative URLs. Cloaking is usually site-wide, so a
    sample is enough to establish it."""
    if not urls:
        return []
    if log:
        await log("info", f"[seospam] checking {min(len(urls), limit)} URL(s) for "
                          f"cloaking and injected spam", "seospam")

    out: list[dict] = []
    sem = asyncio.Semaphore(5)

    async def one(u: str):
        async with sem:
            try:
                return await audit_url(u, log=log)
            except Exception:  # noqa: BLE001
                return []

    for batch in await asyncio.gather(*(one(u) for u in urls[:limit])):
        out += batch
    return out


@register(EngineSpec(
    name="seospam",
    label="Checking for cloaking and injected spam",
    description="Fetches each URL as a browser, as Googlebot, and as a visitor from "
                "Google, then diffs. Detects cloaked SEO spam — evidence of "
                "compromise rather than misconfiguration.",
    phase="post_http",
    takes="urls",
    weight=6,
    limit=25,
    default_in=("quick", "standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    return await audit(targets, limit=25, log=ctx.get("log"))
