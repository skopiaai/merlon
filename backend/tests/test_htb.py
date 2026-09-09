"""Tests for the Hack The Box layer.

The reasoning in `htb.py` is pure — it takes an Observation and returns ranked
actions — so all of it is testable without a network, a VPN, or a spawned box.
That is why the knowledge and the tool-running live in different modules.

The properties worth protecting here are the ones that would silently make the
tool useless rather than broken:

  * a 32-hex string is not a flag unless context says so (it is also every MD5);
  * hard-tier techniques must not drown an easy box, and must appear on a hard
    one — a ranked list that always returns everything is not ranked;
  * the hint ladder must actually escalate, or "give me the answer" gives a nudge;
  * privesc suggestions must not fire before there is a shell.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app import htb, htbcontent, htbscan

# --------------------------------------------------------------------- flags


def test_htb_braces_flag_is_certain():
    flags = htb.classify_flag("we found HTB{a_real_flag_here} in the output")
    assert len(flags) == 1
    assert flags[0]["kind"] == "htb"
    assert flags[0]["confidence"] > 0.95


def test_hex_from_root_txt_is_the_root_flag():
    digest = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    flags = htb.classify_flag(digest, source="cat /root/root.txt")
    assert flags[0]["kind"] == "root"
    assert flags[0]["confidence"] > 0.9


def test_hex_from_user_txt_is_the_user_flag():
    digest = "0123456789abcdef0123456789abcdef"
    flags = htb.classify_flag(digest, source="/home/bob/user.txt")
    assert flags[0]["kind"] == "user"


def test_md5_output_is_not_reported_as_a_flag():
    """The single most likely false positive, and the reason for `source`.

    32 hex characters is the shape of a machine flag and also of every MD5 ever
    printed. Reporting `md5sum` output as a captured flag would train you to
    ignore the flag panel, which is the one thing it must never do.
    """
    out = "5d41402abc4b2a76b9719d911017c592  file.txt"
    assert htb.classify_flag(out, source="md5sum file.txt") == []


def test_hex_without_context_is_low_confidence_not_hidden():
    """Suppressing a real flag costs more than listing a hash."""
    flags = htb.classify_flag("d41d8cd98f00b204e9800998ecf8427e")
    assert len(flags) == 1
    assert flags[0]["kind"] == "unknown"
    assert flags[0]["confidence"] < 0.5


def test_flags_are_deduplicated():
    digest = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    flags = htb.classify_flag(f"{digest} {digest}", source="user.txt")
    assert len(flags) == 1


# ---------------------------------------------------------------- difficulty

def _box(**kw) -> htb.Observation:
    base = dict(host="10.10.11.5",
                ports=[{"port": 445, "service": "microsoft-ds"},
                       {"port": 88, "service": "kerberos-sec"},
                       {"port": 80, "service": "http"}])
    base.update(kw)
    return htb.Observation(**base)


def test_hard_tier_rules_are_hidden_on_an_easy_box():
    keys = {a["key"] for a in htb.next_actions(_box(difficulty="easy"))}
    assert "adcs" not in keys
    assert "delegation" not in keys
    assert "dcsync" not in keys
    # ...but the easy-box basics are all there.
    assert {"smb", "kerberos", "web", "full-port"} <= keys


def test_hard_tier_rules_appear_on_a_hard_box_with_credentials():
    obs = _box(difficulty="hard", creds=[{"user": "svc", "secret": "x"}])
    keys = {a["key"] for a in htb.next_actions(obs)}
    assert "spray" in keys
    assert "bloodhound" in keys
    assert "adcs" in keys


def test_credential_gated_rules_need_credentials():
    """`spray` with nothing to spray is noise, and noise is what buries the
    one action that matters."""
    without = {a["key"] for a in htb.next_actions(_box(difficulty="hard"))}
    assert "spray" not in without
    assert "bloodhound" not in without

    with_creds = {a["key"] for a in htb.next_actions(
        _box(difficulty="hard", creds=[{"user": "a", "secret": "b"}]))}
    assert "spray" in with_creds


def test_shell_gated_rules_need_a_shell():
    no_shell = {a["key"] for a in htb.next_actions(_box(difficulty="hard"))}
    assert "pivot" not in no_shell
    assert "container-escape" not in no_shell

    shelled = {a["key"] for a in htb.next_actions(
        _box(difficulty="hard", has_shell=True, shell_user="svc"))}
    assert "pivot" in shelled


def test_unknown_difficulty_behaves_as_easy():
    """A typo in the difficulty field must not silently unlock everything."""
    keys = {a["key"] for a in htb.next_actions(_box(difficulty="banana"))}
    assert "adcs" not in keys


def test_insane_sees_everything_hard_does():
    hard = {a["key"] for a in htb.next_actions(
        _box(difficulty="hard", creds=[{"user": "a", "secret": "b"}],
             has_shell=True))}
    insane = {a["key"] for a in htb.next_actions(
        _box(difficulty="insane", creds=[{"user": "a", "secret": "b"}],
             has_shell=True))}
    assert hard <= insane


# --------------------------------------------------------------------- phases

@pytest.mark.parametrize("kw,expected", [
    ({}, "recon"),
    ({"ports": [{"port": 22, "service": "ssh"}]}, "enum"),
    ({"ports": [{"port": 80, "service": "http"}]}, "web"),
    ({"ports": [{"port": 80}], "creds": [{"user": "a", "secret": "b"}]}, "foothold"),
    ({"has_shell": True, "shell_user": "www-data"}, "user"),
    ({"has_shell": True, "shell_user": "bob"}, "privesc"),
    ({"is_root": True}, "root"),
])
def test_phase_progression(kw, expected):
    obs = htb.Observation(host="10.10.11.5", **kw)
    assert htb.current_phase(obs) == expected


def test_www_data_shell_is_not_treated_as_user_level():
    """Landing as www-data and calling it done is the classic stall.

    The phase stays at `user`, which keeps enumeration advice in front of you
    instead of jumping to privilege escalation you cannot do yet.
    """
    obs = htb.Observation(host="10.10.11.5", has_shell=True, shell_user="www-data")
    assert htb.current_phase(obs) == "user"


def test_privesc_leads_once_there_is_a_shell():
    obs = _box(has_shell=True, shell_user="bob", os_guess="Linux 5.x")
    actions = htb.next_actions(obs)
    assert actions[0]["key"] == "privesc-linux"


def test_windows_shell_gets_windows_privesc():
    obs = _box(has_shell=True, shell_user="bob", os_guess="Windows Server 2019")
    assert htb.next_actions(obs)[0]["key"] == "privesc-windows"


# ---------------------------------------------------------------- hint ladder

def test_hint_ladder_escalates_to_a_real_command():
    obs = _box()
    levels = [htb.hint(obs, level=n)["hint"] for n in (1, 2, 3, 4)]
    assert len(set(levels)) == 4, "every rung must say something different"
    assert levels[0].endswith("?"), "level 1 should ask, not tell"
    # Level 4 is the payoff: something you can paste.
    assert any(c in levels[3] for c in ("nmap", "smbclient", "ffuf", "curl",
                                        "netexec", "ldapsearch"))


def test_hint_levels_are_clamped():
    obs = _box()
    assert htb.hint(obs, level=0)["level"] == 1
    assert htb.hint(obs, level=99)["level"] == 4


def test_hint_labels_name_the_rung():
    obs = _box()
    assert htb.hint(obs, 1)["level_label"] == "nudge"
    assert htb.hint(obs, 4)["level_label"] == "exact command"


def test_hint_can_target_a_specific_action():
    obs = _box()
    assert htb.hint(obs, 4, key="smb")["key"] == "smb"


def test_host_is_substituted_into_commands_and_hints():
    obs = htb.Observation(host="10.10.11.77",
                          ports=[{"port": 445, "service": "microsoft-ds"}])
    smb = next(a for a in htb.next_actions(obs) if a["key"] == "smb")
    assert "10.10.11.77" in smb["commands"][0]
    assert all("{host}" not in c for c in smb["commands"])
    assert all("{host}" not in h for h in smb["hints"])


# ------------------------------------------------------------ writeup policy

def test_active_machine_writeups_are_refused():
    policy = htb.writeup_policy("active")
    assert policy["allowed"] is False
    assert "rules" in policy["note"].lower()


def test_retired_machine_writeups_are_allowed():
    assert htb.writeup_policy("retired")["allowed"] is True


def test_no_flag_or_solution_database_is_shipped():
    """The guarantee in the module docstring, enforced.

    If someone later adds a dict of machine names to flags, this fails. That is
    the point: it would be a rule violation for the user and would get their
    account banned, so it must not be possible to add it quietly.
    """
    source = Path(htb.__file__).read_text()
    assert "user.txt" not in source or "FLAG_FILES" in source
    # No 32-hex literals anywhere in the module.
    import re
    literals = re.findall(r"[\"'][0-9a-f]{32}[\"']", source)
    assert not literals, f"looks like a stored flag: {literals}"


# ------------------------------------------------------------------- XP maths

def test_machine_xp_matches_the_published_table():
    assert htb.xp_for("machine", "easy") == 200                    # user only
    assert htb.xp_for("machine", "easy", root=True) == 450         # user + root
    assert htb.xp_for("machine", "insane", root=True) == 1050


def test_active_content_gets_the_multiplier():
    assert htb.xp_for("machine", "easy", active=True) == 260        # 200 * 1.3


def test_unknown_difficulty_earns_nothing_rather_than_guessing():
    assert htb.xp_for("machine", "impossible") == 0
    assert htb.xp_for("nonsense", "easy") == 0


def test_sherlock_xp_counts_tasks_and_completion():
    assert htb.xp_for("sherlock", "easy", tasks=5) == 20 * 5 + 175


def test_streak_needs_two_hundred_xp():
    assert htb.streak_status(0)["xp_needed"] == 200
    assert htb.streak_status(200)["safe"] is True
    assert htb.streak_status(999)["xp_needed"] == 0


def test_streak_week_runs_monday_to_sunday_utc():
    from datetime import datetime, timezone
    wed = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)   # a Wednesday
    start, end = htb.week_bounds(wed)
    assert start.weekday() == 0 and start.hour == 0
    assert end.weekday() == 6 and end.hour == 23


def test_rank_advances_every_fifteen_levels():
    assert htb.rank_label(1)["rank"] == "Beginner"
    assert htb.rank_label(16)["rank"] == "Apprentice"
    assert htb.rank_label(31)["rank"] == "Skilled"
    assert htb.rank_label(500)["rank"] == "Grandmaster"    # no cap, clamps


def test_rank_grades_run_one_to_three():
    assert {htb.rank_label(n)["grade"] for n in range(1, 16)} == {"I", "II", "III"}


def test_plan_prefers_fewer_items():
    routes = htb.plan_to_target(400)
    assert routes[0]["count_needed"] <= routes[-1]["count_needed"]
    assert all(r["total"] >= 400 for r in routes)


# ------------------------------------------------------------------ nmap XML

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <hostnames><hostname name="dc01.corp.htb"/></hostnames>
  <ports>
   <port protocol="tcp" portid="445">
    <state state="open"/>
    <service name="microsoft-ds" product="Windows Server 2019"/>
   </port>
   <port protocol="tcp" portid="8080">
    <state state="closed"/>
    <service name="http-proxy"/>
   </port>
   <port protocol="tcp" portid="88">
    <state state="open"/>
    <service name="kerberos-sec"/>
    <script id="smb-os" output="Domain_Name: CORP"/>
   </port>
  </ports>
  <os><osmatch name="Microsoft Windows Server 2019"/></os>
 </host>
</nmaprun>"""


def test_nmap_xml_parses_open_ports_only():
    ports, os_guess, hostnames = htbscan.parse_nmap_xml(NMAP_XML)
    assert [p["port"] for p in ports] == [88, 445]     # 8080 was closed
    assert os_guess.startswith("Microsoft Windows")
    assert "dc01.corp.htb" in hostnames


def test_nmap_xml_extracts_domain_from_script_output():
    """The vhost the web app wants is usually in a script result, not in DNS."""
    _, _, hostnames = htbscan.parse_nmap_xml(NMAP_XML)
    assert "CORP" in hostnames


def test_malformed_nmap_xml_returns_empty_rather_than_raising():
    assert htbscan.parse_nmap_xml("not xml at all") == ([], "", [])
    assert htbscan.parse_nmap_xml("") == ([], "", [])


# ------------------------------------------------------------- range warnings

@pytest.mark.parametrize("host", ["10.10.10.5", "10.10.11.200", "10.129.4.5"])
def test_htb_ranges_produce_no_warning(host):
    assert htbscan.range_warning(host) == ""


def test_other_private_ranges_are_flagged():
    """10.0.0.0/8 is also where every corporate network lives."""
    warning = htbscan.range_warning("10.4.5.6")
    assert warning and "do not own" in warning


def test_public_addresses_are_flagged_harder():
    assert "not a private address" in htbscan.range_warning("93.184.216.34")


# ------------------------------------------------------- GTFOBins parsing

GTFO_ENTRY = """---
functions:
  shell:
  - code: find . -exec /bin/sh \\; -quit
    contexts:
      sudo:
      suid:
        code: find . -exec /bin/sh -p \\; -quit
  file-read:
  - code: find /path -exec cat {} \\;
    comment: reads via cat
...
"""

INHERIT_ENTRY = """---
functions:
  file-read:
  - code: vim -c ':redir! >out'
  inherit:
  - code: vim -c ':lua ...'
    from: lua
...
"""


@pytest.fixture
def gtfo_repo(tmp_path: Path) -> Path:
    d = tmp_path / "_gtfobins"
    d.mkdir(parents=True)
    (d / "find").write_text(GTFO_ENTRY)
    (d / "vim").write_text(INHERIT_ENTRY)
    (d / "lua").write_text(
        "---\nfunctions:\n  shell:\n  - code: lua -e 'os.execute(\"/bin/sh\")'\n...\n")
    return tmp_path


def test_gtfobins_entries_have_no_file_extension(gtfo_repo: Path):
    """The repository uses `_gtfobins/find`, not `find.md`.

    Globbing for `*.md` parses zero files and reports success, which is the
    worst possible failure: a privesc database that is silently empty.
    """
    entries = htbcontent.parse_gtfobins(gtfo_repo)
    assert "find" in entries
    assert entries["find"]["shell"]


def test_suid_context_variant_is_kept_separately(gtfo_repo: Path):
    """`-p` is the difference between a root shell and a useless one."""
    codes = [c["code"] for c in htbcontent.parse_gtfobins(gtfo_repo)["find"]["shell"]]
    assert any("-p" in c for c in codes)
    assert any("-p" not in c for c in codes)


def test_inheritance_points_rather_than_copying(gtfo_repo: Path):
    """vim inherits lua's *capability*, not lua's command line.

    Copying `lua -e 'os.execute(...)'` under vim would produce a command that
    looks authoritative and does not run.
    """
    vim = htbcontent.parse_gtfobins(gtfo_repo)["vim"]
    all_codes = [c["code"] for cmds in vim.values() for c in cmds]
    assert not any(code.startswith("lua -e") for code in all_codes)
    assert any("see the lua entry" in code for code in all_codes)


def test_empty_repo_parses_to_nothing_without_raising(tmp_path: Path):
    assert htbcontent.parse_gtfobins(tmp_path) == {}


# ------------------------------------------------------------- sudo -l lookup

@pytest.fixture
def loaded_knowledge(gtfo_repo: Path, tmp_path: Path, monkeypatch):
    import time
    entries = htbcontent.parse_gtfobins(gtfo_repo)
    store = tmp_path / "gtfobins.json"
    store.write_text(json.dumps({"updated_at": time.time(), "entries": entries}))
    monkeypatch.setattr(htbcontent, "GTFO_FILE", store)
    return store


def test_sudo_l_output_becomes_a_ready_command(loaded_knowledge):
    entries = htbcontent.parse_sudo_l("(root) NOPASSWD: /usr/bin/find")
    assert entries[0]["exploitable"] is True
    assert "/bin/sh" in entries[0]["command"]


def test_unknown_sudo_binary_says_so_without_pretending(loaded_knowledge):
    entries = htbcontent.parse_sudo_l("(ALL) /opt/scripts/backup.sh")
    assert entries[0]["exploitable"] is False
    assert "GTFOBins" in entries[0]["note"]


def test_exploitable_entries_sort_first(loaded_knowledge):
    text = "(ALL) /opt/custom.sh\n(root) NOPASSWD: /usr/bin/find"
    entries = htbcontent.parse_sudo_l(text)
    assert entries[0]["binary"] == "find"


def test_lookup_accepts_a_bare_name_or_a_path(loaded_knowledge):
    assert htbcontent.lookup("find")["found"]
    assert htbcontent.lookup("/usr/bin/find")["found"]


def test_missing_database_does_not_raise(tmp_path, monkeypatch):
    """Before the first knowledge update the file does not exist."""
    monkeypatch.setattr(htbcontent, "GTFO_FILE", tmp_path / "absent.json")
    result = htbcontent.lookup("find")
    assert result["found"] is False
    assert "note" in result


# --------------------------------------------------------- shell output triage

def test_seimpersonate_is_recognised():
    hits = htbcontent.suggest_from_shell_output(
        "SeImpersonatePrivilege          Enabled")
    assert any("SeImpersonate" in h["title"] for h in hits)
    assert any("Potato" in h["command"] or "potato" in h["why"].lower() for h in hits)


def test_container_detection_fires():
    hits = htbcontent.suggest_from_shell_output("12:devices:/docker/abc123")
    assert any("container" in h["title"].lower() for h in hits)


def test_credentials_in_output_are_surfaced():
    hits = htbcontent.suggest_from_shell_output('db_password = "Summer2026!"')
    assert any("credential" in h["title"].lower() for h in hits)


def test_clean_output_produces_no_hits():
    assert htbcontent.suggest_from_shell_output("total 0\ndrwxr-xr-x 2 root root") == []


# ------------------------------------------------------------------ integrity

def test_every_rule_has_a_four_rung_ladder():
    for rule in htb.RULES:
        assert len(rule.ladder) == 4, f"{rule.key} ladder is {len(rule.ladder)} rungs"
        assert all(rule.ladder), f"{rule.key} has an empty rung"


def test_every_rule_declares_a_known_phase():
    phases = {p["key"] for p in htb.PHASES}
    for rule in htb.RULES:
        assert rule.phase in phases, f"{rule.key} has unknown phase {rule.phase}"


def test_every_rule_declares_a_known_difficulty():
    for rule in htb.RULES:
        assert rule.min_difficulty in htb.DIFFICULTY_ORDER, rule.key


def test_rule_keys_are_unique():
    keys = [r.key for r in htb.RULES]
    assert len(keys) == len(set(keys))


def test_summary_is_serialisable():
    """It goes over the API, so it has to survive json.dumps."""
    json.dumps(htb.summary())


def test_hint_for_an_inapplicable_action_says_so():
    """Silently answering a different question is the worst kind of wrong.

    Ask for a hint on ADCS before you have found port 88 and the honest answer
    is "that does not apply yet" — which is itself useful. Returning the
    credential-spraying hint under the ADCS heading is not.
    """
    obs = _box(difficulty="hard", ports=[{"port": 80, "service": "http"}])
    result = htb.hint(obs, level=4, key="adcs")
    assert result["substituted"] is True
    assert result["requested_key"] == "adcs"
    assert result["key"] != "adcs"
    assert "does not apply" in result["note"]


def test_hint_for_an_applicable_action_is_not_flagged_as_substituted():
    obs = _box(ports=[{"port": 445, "service": "microsoft-ds"}])
    result = htb.hint(obs, level=4, key="smb")
    assert result["substituted"] is False
    assert result["key"] == "smb"
    assert "note" not in result
