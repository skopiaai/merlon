/**
 * Plain-language layer.
 *
 * Scanner output is written for people who already know the jargon. This
 * translates the common cases into "what it means" and "what to do", so the
 * results page is readable without a security background.
 *
 * Add entries as you meet new issue types — matching is by substring against
 * the nuclei template ID and the finding name, most specific first.
 */

import type { Finding, Severity } from "./api";

interface Plain { what: string; fix: string; }

const RULES: { match: RegExp; what: string; fix: string }[] = [
  {
    match: /hsts|strict-transport/i,
    what: "Your site doesn't tell browsers to always use HTTPS. Someone on the same network — a café Wi-Fi, for instance — could push a visitor onto an unencrypted connection and read their traffic.",
    fix: "Add the header `Strict-Transport-Security: max-age=31536000; includeSubDomains` to all HTTPS responses. In Nginx: `add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;`",
  },
  {
    match: /content-security-policy|csp/i,
    what: "There's no Content Security Policy, which is the browser-level control that stops injected scripts from running. It's the safety net for cross-site scripting bugs you haven't found yet.",
    fix: "Add a Content-Security-Policy header. Start in report-only mode (`Content-Security-Policy-Report-Only`) to see what would break, then enforce it once the policy is clean.",
  },
  {
    match: /x-frame-options|clickjack/i,
    what: "Your pages can be embedded inside someone else's site in a hidden frame. An attacker can overlay invisible buttons so a visitor clicks something they didn't intend — approving a payment, changing a setting.",
    fix: "Send `X-Frame-Options: DENY`, or better, `Content-Security-Policy: frame-ancestors 'none'`. Use `SAMEORIGIN` if you legitimately frame your own pages.",
  },
  {
    match: /x-content-type-options|mime.?sniff/i,
    what: "Browsers are allowed to guess the type of files you serve. An uploaded file that looks like an image could be interpreted as a script.",
    fix: "Add `X-Content-Type-Options: nosniff` to every response.",
  },
  {
    match: /\.git|\.svn|\.env|config.*expos|backup.*file/i,
    what: "A file that should never be public is reachable from the internet. Depending on what's in it, this can hand over source code, database passwords, or API keys outright.",
    fix: "Block it at the web server immediately, then assume anything inside it is compromised — rotate every credential it contained. Move secrets out of the web root entirely.",
  },
  {
    match: /directory.?listing|dir.?list|open.?dir/i,
    what: "A folder on your server shows its full file listing to anyone who visits it. Attackers use these to find backups, old versions, and files nobody meant to publish.",
    fix: "Turn off directory indexing. Nginx: remove `autoindex on`. Apache: `Options -Indexes`.",
  },
  {
    match: /default.?(login|credential|password)|weak.?password/i,
    what: "Something is running with its factory-default login. This is the single most reliably exploited issue on the internet — automated bots scan for exactly this, continuously.",
    fix: "Change the credentials right now, before anything else on this list. Then check the logs for logins you don't recognise.",
  },
  {
    match: /phpmyadmin|adminer|jenkins|grafana|kibana|admin.?panel|exposed-surface/i,
    what: "An admin interface is reachable from the public internet. Even with a login screen, it gives attackers something to brute-force and exposes you to any vulnerability in that software.",
    fix: "Put it behind a VPN or restrict it to known IP addresses. If it must stay public, enforce multi-factor authentication and rate-limit login attempts.",
  },
  {
    match: /swagger|api.?docs|graphql.?(introspect|playground)/i,
    what: "Your API documentation or schema is publicly readable. It won't break anything by itself, but it hands an attacker a complete map of every endpoint and parameter.",
    fix: "Restrict docs to authenticated users, or disable them in production. For GraphQL, turn off introspection outside development.",
  },
  {
    match: /cors|access-control-allow-origin/i,
    what: "Your cross-origin rules are loose enough that another website could read responses from your API using a visitor's logged-in session.",
    fix: "Replace any wildcard origin with an explicit allowlist of domains you control. Never combine `Access-Control-Allow-Origin: *` with credentials.",
  },
  {
    match: /ssl|tls|certificate|cipher|expired/i,
    what: "There's a problem with your HTTPS setup — an outdated protocol, a weak cipher, or a certificate issue. Visitors may see warnings, and in the worst case the encryption can be downgraded.",
    fix: "Disable TLS 1.0 and 1.1, keep only strong cipher suites, and verify the certificate chain is complete. Test with SSL Labs afterwards.",
  },
  {
    match: /sql.?inject/i,
    what: "The application may be passing user input straight into database queries. If confirmed, this typically means an attacker can read or modify your entire database.",
    fix: "Verify this manually before acting on it — then fix by using parameterised queries everywhere. Never build SQL by concatenating strings.",
  },
  {
    match: /xss|cross.?site.?script/i,
    what: "User input may be rendered into the page without escaping, letting an attacker run JavaScript in a visitor's browser — stealing their session, or acting as them.",
    fix: "Escape all output by context, and add a Content Security Policy as a second line of defence. Modern frameworks escape by default — check anywhere you bypassed that.",
  },
  {
    match: /seo-cloaking|cloaked|seo-spam|malicious-redirect|js-spam-redirect/i,
    what: "Your site is serving gambling or pharmacy spam to Google while showing the "
      + "normal page to you. This isn't a misconfiguration — someone has write access "
      + "to the server and is selling your domain's search reputation. Visitors who "
      + "find you through search get redirected to a gambling site.",
    fix: "Treat this as an incident. Snapshot the files and logs first, then find the "
      + "injected content (recently modified templates, rogue plugins, PHP files "
      + "calling eval), find how they got in (unpatched CMS, webshell, weak admin "
      + "password), rotate every credential, and only then remove the spam. Finally, "
      + "use Google Search Console's Security Issues report to request a review — "
      + "until you do, the domain keeps ranking for gambling terms.",
  },
  {
    match: /unexpected-language/i,
    what: "A large amount of text in an unexpected language appeared on this page. On a "
      + "site that doesn't serve that language, this is almost always injected content.",
    fix: "Check whether that language is meant to be there. If not, treat it as a "
      + "compromise and audit the site's files against a known-good backup.",
  },
  {
    match: /takeover|dangling.?cname|subdomain.?takeover/i,
    what: "A subdomain points at a service that no longer exists. Anyone can register that service name and serve content from your domain — including convincing phishing pages.",
    fix: "Delete the dangling DNS record now, or reclaim the service it points to. Audit all CNAMEs for other orphans.",
  },
  {
    match: /version.?(disclos|detect)|banner|server.?header|tech.?detect/i,
    what: "Your server announces its exact software version. Not harmful alone, but it lets attackers skip straight to the exploits that work on your specific build.",
    fix: "Suppress version banners. Nginx: `server_tokens off;`. It's low priority — keeping the software patched matters far more.",
  },
  {
    match: /cve-\d{4}/i,
    what: "Software you're running matches a publicly known vulnerability. Exploit code for published CVEs is usually available within days, and scanning for them is fully automated.",
    fix: "Check the CVE reference below for the fixed version and update. If you can't update immediately, look for a documented workaround or restrict access to the affected component.",
  },
];

const BY_SEVERITY: Record<Severity, Plain> = {
  critical: {
    what: "A serious issue that could give an attacker direct access. Treat it as urgent.",
    fix: "Verify it manually, then fix or take the affected component offline until you can.",
  },
  high: {
    what: "A significant weakness worth fixing soon.",
    fix: "Confirm the finding, then schedule a fix in the next few days.",
  },
  medium: {
    what: "A meaningful gap that makes other attacks easier.",
    fix: "Worth fixing in your next maintenance window.",
  },
  low: {
    what: "A minor hardening gap. Low risk on its own.",
    fix: "Fix when convenient — these add up.",
  },
  info: {
    what: "Informational. Something observed about the target, not a weakness by itself.",
    fix: "No action needed. Useful context for understanding your attack surface.",
  },
};

export function explain(f: Finding): Plain {
  const haystack = `${f.rule_id} ${f.name} ${f.tags.join(" ")} ${f.cve.join(" ")}`;
  const hit = RULES.find((r) => r.match.test(haystack));
  if (hit) return { what: hit.what, fix: f.remediation?.trim() || hit.fix };

  return {
    what: f.description?.trim() || BY_SEVERITY[f.severity].what,
    fix: f.remediation?.trim() || BY_SEVERITY[f.severity].fix,
  };
}

/** CSS variables, not literals — so severity colours follow the theme. */
export const SEV_HEX: Record<Severity, string> = {
  critical: "var(--crit)",
  high: "var(--high)",
  medium: "var(--med)",
  low: "var(--low)",
  info: "var(--info)",
};

export const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Human summary of the whole scan. */
export function verdict(counts: Record<string, number>) {
  const c = counts.critical ?? 0, h = counts.high ?? 0;
  const m = counts.medium ?? 0, l = counts.low ?? 0;
  const total = c + h + m + l;

  if (c > 0)
    return { grade: "!", title: "Needs urgent attention",
      line: `${c} critical ${c === 1 ? "issue" : "issues"} found. Start at the top of the list.` };
  if (h > 0)
    return { grade: "!", title: "Some real problems",
      line: `${h} high-severity ${h === 1 ? "issue" : "issues"} worth fixing this week.` };
  if (m > 0)
    return { grade: "~", title: "A few things to tighten",
      line: `${m} medium ${m === 1 ? "issue" : "issues"} — mostly hardening gaps.` };
  if (l > 0)
    return { grade: "~", title: "Mostly clean",
      line: `Only ${l} low-severity ${l === 1 ? "item" : "items"}. Nothing urgent.` };
  return { grade: "✓", title: "Nothing found",
    line: total === 0 ? "No issues detected in what was tested." : "Clean scan." };
}
