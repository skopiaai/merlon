"""Subdomain takeover detection.

The setup is always the same. Someone points `docs.company.com` at a hosting
service with a CNAME, the service account is later cancelled or the project
deleted, and the CNAME stays. Now anyone can register that name on the service
and serve whatever they like from a hostname the organisation's users trust.

That's the whole attack, and it is worth more than it looks. A takeover on any
subdomain of a site that sets domain-wide cookies is session theft. On a domain
whose OAuth configuration allows subdomain redirect URIs it is account
takeover. On a university or government domain it is a phishing page with a
legitimate certificate on a legitimate name.

Two properties of this engine matter:

**A dangling CNAME alone is not a finding.** Plenty of CNAMEs point at services
that don't allow claiming an arbitrary name — pointing at them is untidy, not
exploitable. Reporting every dangling CNAME as a takeover is how researchers
lose credibility with triage teams.

**Nothing is claimed.** Detection stops at reading the error page the service
returns for an unclaimed name. Actually registering the name to prove it would
be seizing control of someone else's hostname, which is the attack, not the
test. The report says what to check and how to fix it.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

from ..models import Severity
from ..normalize import make_dedupe_key
from . import fetch
from .registry import EngineSpec, register


@dataclass(frozen=True)
class Service:
    name: str
    cnames: tuple[str, ...]       # CNAME suffixes that point at this service
    fingerprint: str              # text the service serves for an unclaimed name
    claimable: bool = True        # can anyone register the name?
    note: str = ""


# Derived from the community "can I take over xyz" research. `claimable=False`
# entries are deliberately kept: they suppress false positives that a naive
# dangling-CNAME check would report, which is most of the value.
SERVICES: tuple[Service, ...] = (
    Service("GitHub Pages", (".github.io",),
            "There isn't a GitHub Pages site here"),
    Service("Amazon S3", (".s3.amazonaws.com", ".s3-website",
                          ".s3.dualstack.", ".amazonaws.com"),
            "NoSuchBucket"),
    Service("Heroku", (".herokuapp.com", ".herokudns.com", ".herokussl.com"),
            "No such app"),
    Service("Shopify", (".myshopify.com",),
            "Sorry, this shop is currently unavailable"),
    Service("Fastly", (".fastly.net", ".fastlylb.net"),
            "Fastly error: unknown domain"),
    Service("Pantheon", (".pantheonsite.io",),
            "The gods are wise, but do not know of the site which you seek"),
    Service("Tumblr", (".domains.tumblr.com", ".tumblr.com"),
            "Whatever you were looking for doesn't currently exist at this address"),
    Service("Wordpress.com", (".wordpress.com",),
            "Do you want to register"),
    Service("Ghost", (".ghost.io",),
            "The thing you were looking for is no longer here"),
    Service("Helpjuice", (".helpjuice.com",), "We could not find what you're looking for"),
    Service("Helpscout", (".helpscoutdocs.com",), "No settings were found for this company"),
    Service("Cargo Collective", (".cargocollective.com",), "404 Not Found"),
    Service("Statuspage", (".statuspage.io",),
            "You are being <a href=\"https://www.statuspage.io\">redirected"),
    Service("Surge.sh", (".surge.sh",), "project not found"),
    Service("Bitbucket", (".bitbucket.io",), "Repository not found"),
    Service("Intercom", (".custom.intercom.help",),
            "This page is reserved for artistic dogs"),
    Service("Webflow", (".proxy.webflow.com", ".proxy-ssl.webflow.com"),
            "The page you are looking for doesn't exist or has been moved"),
    Service("Wix", (".wixdns.net",), "Error ConnectYourDomain occurred"),
    Service("Netlify", (".netlify.app", ".netlify.com"), "Not Found - Request ID"),
    Service("Readme.io", (".readme.io",), "Project doesnt exist... yet!"),
    Service("Uservoice", (".uservoice.com",), "This UserVoice subdomain is currently available"),
    Service("Zendesk", (".zendesk.com",), "Help Center Closed"),
    Service("Desk.com", (".desk.com",), "Sorry, We Couldn't Find That Page"),
    Service("Campaign Monitor", (".createsend.com",),
            "Trying to access your account?"),
    Service("Acquia", (".acquia-sites.com",), "The site you are looking for could not be found"),
    Service("Agile CRM", (".agilecrm.com",), "Sorry, this page is no longer available"),
    Service("Aha!", (".ideas.aha.io",), "There is no portal here"),
    Service("Anima", (".animaapp.io",), "If this is your website and you've just created it"),
    Service("Bigcartel", (".bigcartel.com",), "<h1>Oops! We couldn&#8217;t find that page.</h1>"),
    Service("Feedpress", (".redirect.feedpress.me",), "The feed has not been found"),
    Service("Kinsta", (".kinsta.cloud",), "No Site For Domain"),
    Service("LaunchRock", (".launchrock.com",), "It looks like you may have taken a wrong turn"),
    Service("Ngrok", (".ngrok.io",), "Tunnel .* not found"),
    Service("Smartling", (".smartling.com",), "Domain is not configured"),
    Service("Strikingly", (".s.strikinglydns.com",), "But if you're looking to build your own website"),
    Service("Tave", (".clientaccess.tave.com",), "Error 404: Page Not Found"),
    Service("Teamwork", (".teamwork.com",), "Oops - We didn't find your site"),
    Service("Tilda", (".tilda.ws",), "Please renew your subscription"),
    Service("Worksites", (".worksites.net",), "Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist"),
    Service("Vercel", (".vercel.app", ".vercel-dns.com"),
            "The deployment could not be found"),
    Service("Azure", (".azurewebsites.net", ".cloudapp.azure.com",
                      ".trafficmanager.net", ".blob.core.windows.net",
                      ".azureedge.net"),
            "404 Web Site not found"),

    # Not claimable — listed so a dangling CNAME here is reported as untidy
    # configuration rather than an exploitable takeover.
    Service("Cloudfront", (".cloudfront.net",), "", claimable=False,
            note="AWS validates domain ownership, so the name cannot simply be claimed."),
    Service("Akamai", (".akamai.net", ".akamaiedge.net", ".edgekey.net",
                       ".edgesuite.net"), "", claimable=False,
            note="Akamai configuration is account-bound; not claimable by a third party."),
    Service("Cloudflare", (".cloudflare.net", ".cdn.cloudflare.net"), "",
            claimable=False, note="Cloudflare requires zone ownership."),
    Service("Google", (".googlehosted.com", ".ghs.google.com",
                       ".storage.googleapis.com"), "", claimable=False,
            note="Google verifies domain ownership before serving a custom domain."),
)


def match_service(cname: str) -> Service | None:
    """The hosting service a CNAME points at, if it is one we know."""
    cname = (cname or "").lower().rstrip(".")
    if not cname:
        return None
    best: Service | None = None
    best_len = -1
    for svc in SERVICES:
        for suffix in svc.cnames:
            # Longest suffix wins: ".s3.amazonaws.com" must beat ".amazonaws.com"
            if cname.endswith(suffix) and len(suffix) > best_len:
                best, best_len = svc, len(suffix)
    return best


def body_confirms(service: Service, body: str) -> bool:
    """Does the served page look like this service's unclaimed-name error?"""
    if not service.fingerprint or not body:
        return False
    # A couple of fingerprints are regexes in the source data.
    try:
        return re.search(service.fingerprint, body, re.I | re.S) is not None
    except re.error:
        return service.fingerprint.lower() in body.lower()


async def resolve_cname(host: str, timeout: int = 8) -> list[str]:
    """Full CNAME chain for a host, in order."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "+timeout=5", "+tries=1", "CNAME", host,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return []
    return [line.strip().rstrip(".").lower()
            for line in out.decode("utf-8", "replace").splitlines() if line.strip()]


async def resolves(host: str, timeout: int = 8) -> bool:
    """Does the name resolve to an address at all?"""
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "+timeout=5", "+tries=1", "A", host,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        return True   # unknown — assume fine rather than report a guess
    return bool(out.decode().strip())


def _finding(host: str, cname: str, service: Service, evidence: str,
             confirmed: bool) -> dict:
    if not service.claimable:
        return {
            "engine": "takeover", "rule_id": "dangling-cname",
            "name": f"Dangling CNAME to {service.name}",
            "severity": Severity.low,
            "host": host, "url": f"https://{host}", "matched_at": host,
            "description": (
                f"{host} has a CNAME to {cname} ({service.name}) but the target "
                f"doesn't resolve. {service.note} So this is not a takeover — "
                f"it's a broken record that will confuse anyone auditing DNS, and "
                f"one that would become dangerous if the service's ownership "
                f"model ever changed."
            ),
            "evidence": evidence,
            "remediation": f"Remove the CNAME for {host} if the {service.name} "
                           f"resource no longer exists.",
            "references": ["https://github.com/EdOverflow/can-i-take-over-xyz"],
            "tags": ["dns", "hygiene"], "cve": [], "cwe": ["CWE-1104"],
            "cvss_score": None,
            "dedupe_key": make_dedupe_key("takeover", "dangling-cname", host, host),
            "raw": {"cname": cname, "service": service.name},
        }

    return {
        "engine": "takeover",
        "rule_id": "subdomain-takeover-confirmed" if confirmed else "subdomain-takeover-possible",
        "name": f"Subdomain takeover {'confirmed' if confirmed else 'candidate'} — {service.name}",
        "severity": Severity.critical if confirmed else Severity.high,
        "host": host, "url": f"https://{host}", "matched_at": host,
        "description": (
            f"{host} points at {cname}, which is {service.name}, and "
            + ("that service is currently serving its 'this name is not claimed' "
               "page. " if confirmed else
               "the CNAME target does not resolve. ")
            + f"Anyone can register {cname.split('.')[0]} on {service.name} and "
            f"immediately control what {host} serves — with a valid certificate, "
            f"on a hostname your users already trust.\n\n"
            f"The damage depends on what else the parent domain does. If cookies "
            f"are set on the parent domain they are readable from here. If OAuth "
            f"redirect URIs allow subdomains, this is account takeover. Even "
            f"without either, it is a phishing page hosted on your own name."
        ),
        "evidence": evidence,
        "remediation": (
            f"1. Remove the DNS record for {host} immediately — that closes it "
            f"whatever else you do.\n"
            f"2. If the subdomain is still needed, re-claim the name on "
            f"{service.name} *first*, then repoint DNS.\n"
            f"3. Audit the rest of the zone the same way: this rarely happens once, "
            f"because it's a symptom of decommissioning without a DNS step.\n"
            f"4. Add DNS record removal to your service-decommission checklist."
        ),
        "references": [
            "https://github.com/EdOverflow/can-i-take-over-xyz",
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
        "tags": ["dns", "takeover", "critical"],
        "cve": [], "cwe": ["CWE-350"],
        "cvss_score": 8.6 if confirmed else 6.5,
        "dedupe_key": make_dedupe_key("takeover", "subdomain-takeover", host, host),
        "raw": {"cname": cname, "service": service.name, "confirmed": confirmed},
    }


@register(EngineSpec(
    name="takeover",
    label="Checking for subdomain takeover",
    description="Dangling CNAMEs pointing at hosting services where the name can "
                "be re-registered by anyone. Verified against the service's own "
                "unclaimed-name page, so untakeoverable providers aren't reported "
                "as criticals.",
    phase="post_http",
    takes="hosts",
    produces="findings",
    weight=6,
    default_in=("quick", "standard", "deep"),
))
async def _engine(targets: list[str], ctx: dict) -> list[dict]:
    log = ctx.get("log")
    findings: list[dict] = []
    checked = 0

    async def check(host: str) -> dict | None:
        nonlocal checked
        chain = await resolve_cname(host)
        if not chain:
            return None
        checked += 1

        cname = chain[-1]
        service = match_service(cname)
        if service is None:
            return None

        # Does the CNAME target still exist? If it resolves and answers, the
        # resource is live and there's nothing to claim.
        target_live = await resolves(cname)

        if not service.claimable:
            if target_live:
                return None
            return _finding(host, cname, service,
                            f"{host} CNAME {cname} (does not resolve)", False)

        # Read what the service serves. This is the difference between "this
        # might be takeoverable" and "this is takeoverable".
        resp = await fetch.request(f"https://{host}", follow=True, timeout=12, ctx=ctx)
        if not resp.ok:
            resp = await fetch.request(f"http://{host}", follow=True, timeout=12, ctx=ctx)

        confirmed = body_confirms(service, resp.body)
        if not confirmed and target_live:
            return None      # live resource, normal page — fine

        snippet = (resp.body or "")[:300].replace("\n", " ").strip()
        evidence = (f"{host} CNAME {cname} ({service.name})\n"
                    f"HTTP {resp.status} from {host}\n"
                    f"Body: {snippet or '<empty>'}")
        return _finding(host, cname, service, evidence, confirmed)

    results = await fetch.gather_limited(
        [check(h) for h in targets[:400]], limit=12)
    findings = [r for r in results if r]

    if log:
        crit = sum(1 for f in findings
                   if f["rule_id"] == "subdomain-takeover-confirmed")
        await log("info",
                  f"[takeover] {checked} host(s) with CNAMEs, {len(findings)} issue(s)",
                  "takeover")
        if crit:
            await log("error",
                      f"[takeover] {crit} CONFIRMED takeover(s) — a dangling name "
                      f"is serving an unclaimed-project page. Remove the DNS "
                      f"record now; anyone can claim it.", "takeover")
    return findings
