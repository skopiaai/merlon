"""Analyzer and crypto-solver tests.

Built around synthetic challenge files shaped like the real thing: a flag
appended after an image's end marker, a flag inside an archive, layered
encodings, and RSA parameters with the classic implementation failures.

The point is to prove the chain finds the flag without a human choosing which
tool to run.
"""

import base64
import struct
import zlib

import pytest

from app import analyzer, cryptosolve

FLAG = "flag{terrier_cyber_quest_2026}"


def run(coro):
    from .conftest import run_coroutine
    return run_coroutine(coro)


# ---------------------------------------------------------- flag detection

@pytest.mark.parametrize("text,expected", [
    (f"noise {FLAG} noise", FLAG),
    ("FLAG{upper_case_works}", "FLAG{upper_case_works}"),
    ("CTF{another_format}", "CTF{another_format}"),
    ("TCQ{event_specific}", "TCQ{event_specific}"),
    ("picoCTF{generic_brace_form}", "picoCTF{generic_brace_form}"),
])
def test_flag_patterns(text, expected):
    assert expected in analyzer.find_flags(text)


def test_no_false_flags_on_ordinary_text():
    assert analyzer.find_flags("def main() { return 0; }") == []


def test_flags_are_deduplicated():
    assert len(analyzer.find_flags(f"{FLAG} {FLAG} {FLAG}")) == 1


# ------------------------------------------------------------- entropy

def test_entropy_distinguishes_random_from_repetitive():
    import os
    assert analyzer.shannon_entropy(os.urandom(4096)) > 7.5
    assert analyzer.shannon_entropy(b"A" * 4096) < 0.5


def test_entropy_of_empty_input():
    assert analyzer.shannon_entropy(b"") == 0.0


# ---------------------------------------------------------- categorisation

@pytest.mark.parametrize("filetype,name,expected", [
    ("ELF 64-bit LSB executable", "chal", "binary"),
    ("PNG image data, 100 x 100", "stego.png", "forensics"),
    ("pcap capture file", "traffic.pcap", "network"),
    ("ASCII text", "cipher.txt", "crypto"),
    ("data", "flight.tlog", "drone"),
])
def test_category_guess(filetype, name, expected):
    assert analyzer.guess_category(filetype, name) == expected


# ------------------------------------------------- real files, real chain

def _make_png(tmp_path, trailer: bytes = b""):
    """A minimal valid PNG, optionally with data appended after IEND —
    the single most common forensics challenge."""
    def chunk(typ: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + typ + data
                + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    raw = zlib.compress(b"\x00\xff\xff\xff")
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
           + chunk(b"IDAT", raw) + chunk(b"IEND", b"") + trailer)
    p = tmp_path / "chal.png"
    p.write_bytes(png)
    return p


def test_flag_appended_after_png_end_is_found(tmp_path):
    path = _make_png(tmp_path, trailer=FLAG.encode())
    report = run(analyzer.analyze(str(path), "chal.png"))
    assert FLAG in report.flags
    assert report.category_hint == "forensics"


def test_plain_png_yields_no_flag(tmp_path):
    report = run(analyzer.analyze(str(_make_png(tmp_path)), "clean.png"))
    assert report.flags == []


def test_flag_in_plain_file_is_found(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text(f"some notes\n{FLAG}\nmore notes")
    report = run(analyzer.analyze(str(p), "notes.txt"))
    assert FLAG in report.flags


def test_report_survives_an_empty_file(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    report = run(analyzer.analyze(str(p), "empty.bin"))
    assert report.size == 0
    assert isinstance(report.steps, list)


def test_high_entropy_is_called_out(tmp_path):
    import os
    p = tmp_path / "packed.bin"
    p.write_bytes(os.urandom(200_000))
    report = run(analyzer.analyze(str(p), "packed.bin"))
    assert any("entropy" in s.lower() for s in report.summary)


def test_missing_tools_are_reported_not_fatal(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("hello")
    report = run(analyzer.analyze(str(p), "x.txt"))
    assert report.steps, "steps must be recorded even when tools are absent"
    for step in report.steps:
        assert step.ok or step.note, "a failed step must explain itself"


# ------------------------------------------------------------ decode chains

def test_single_layer_base64():
    payload = base64.b64encode(FLAG.encode()).decode()
    chains = cryptosolve.decode_chain(payload)
    assert any(FLAG in c["output"] for c in chains)


def test_nested_base64_hex_rot13():
    """base64(hex(rot13(flag))) — three layers, peeled automatically."""
    rot = cryptosolve._try_rot(FLAG, 13).decode()
    payload = base64.b64encode(rot.encode().hex().encode()).decode()
    chains = cryptosolve.decode_chain(payload)
    assert any(FLAG in c["output"] for c in chains), \
        f"expected the flag after peeling; got {[c['chain'] for c in chains][:5]}"


def test_binary_encoding():
    payload = " ".join(format(b, "08b") for b in FLAG.encode())
    assert any(FLAG in c["output"] for c in cryptosolve.decode_chain(payload))


def test_decode_chain_terminates_on_garbage():
    assert isinstance(cryptosolve.decode_chain("!!!!not encoded!!!!"), list)


def test_shortest_chain_comes_first():
    chains = cryptosolve.decode_chain(base64.b64encode(FLAG.encode()).decode())
    depths = [c["depth"] for c in chains]
    assert depths == sorted(depths)


# ------------------------------------------------------------------- xor

def test_single_byte_xor_recovers_plaintext():
    ct = bytes(b ^ 0x5A for b in b"the quick brown fox jumps over it")
    best = cryptosolve.xor_single_byte(ct)[0]
    assert best["key"] == 0x5A
    assert "quick brown fox" in best["output"]


# ------------------------------------------------------------------- RSA

def test_small_exponent_recovers_message():
    m = int.from_bytes(b"flag{cube_root}", "big")
    result = cryptosolve.analyse_rsa(m ** 3 + 1, 3, c=m ** 3)
    recovered = [f.get("recovered") for f in result["findings"] if f.get("recovered")]
    assert "flag{cube_root}" in recovered


def test_close_primes_are_factored():
    n = 1000000007 * 1000000009
    issues = [f["issue"] for f in cryptosolve.analyse_rsa(n, 65537)["findings"]]
    assert any("close together" in i for i in issues)


def test_shared_factor_between_keys():
    shared = 1000000007
    n1, n2 = shared * 1000003, shared * 999983
    findings = cryptosolve.analyse_rsa(n1, 65537, other_n=[n2])["findings"]
    hit = next(f for f in findings if "Shared prime" in f["issue"])
    assert hit["p"] == str(shared)


def test_strong_parameters_report_nothing_alarming():
    # Two distant 512-bit primes, standard exponent.
    p = 0xE1D4B3A2F5C6978899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF01
    q = 0xC3B2A1908F7E6D5C4B3A29180706F5E4D3C2B1A09F8E7D6C5B4A39281706F5E5
    findings = cryptosolve.analyse_rsa(p * q, 65537)["findings"]
    assert any("No classic weakness" in f["issue"] for f in findings)


def test_integer_root_is_exact_for_large_numbers():
    """Floats would lose precision here; the flag would come out corrupted."""
    big = 10 ** 60 + 7
    assert cryptosolve._int_root(big ** 3, 3) == big
