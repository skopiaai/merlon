"""CTF arsenal — the six Terrier Cyber Quest categories.

Built for the format the event actually runs: a Jeopardy-style online
qualifier, then a 36-hour in-person finale scored on severity, methodology and
complexity. Under time pressure the bottleneck is rarely knowledge — it's
recalling the right command fast. So each category carries a triage order (what
to run first on an unknown artefact), a tool list with copy-paste commands, and
the patterns that recur in these challenges.

Everything here is reference material. Commands are templates with {file},
{host}, {url} placeholders for the UI to substitute.
"""

from __future__ import annotations

CATEGORIES: dict[str, dict] = {

    # ------------------------------------------------------------------ web
    "web": {
        "label": "Web",
        "colour": "#00f0ff",
        "summary": "CTF web is logic, not hygiene. Scanners rarely score here — "
                   "read the application and look for what the developer assumed.",
        "triage": [
            "View source and every linked JS bundle — comments, endpoints, keys",
            "Check /robots.txt, /sitemap.xml, /.git/, /.env, /backup, /admin",
            "Inspect cookies and any JWT (decode header/payload, check the alg)",
            "Map every parameter; note anything that looks like an ID or a path",
            "Try the intended flow once, then break the order of operations",
        ],
        "tools": [
            {"name": "curl", "for": "Precise requests — the workhorse",
             "cmd": "curl -isk -X GET '{url}' -H 'Cookie: session=…'"},
            {"name": "httpx", "for": "Fingerprint and status of many hosts",
             "cmd": "httpx -u {url} -json -tech-detect -include-response-header"},
            {"name": "katana", "for": "Crawl for hidden endpoints",
             "cmd": "katana -u {url} -jsonl -depth 3 -known-files all"},
            {"name": "ffuf", "for": "Directory and parameter discovery",
             "cmd": "ffuf -u {url}/FUZZ -w /opt/wordlists/Discovery/Web-Content/raft-medium-directories.txt -mc all -fc 404"},
            {"name": "nuclei", "for": "Known CVEs on the stack",
             "cmd": "nuclei -u {url} -severity medium,high,critical"},
            {"name": "jwt decode", "for": "Inspect a token without a library",
             "cmd": "echo '{token}' | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool"},
        ],
        "patterns": [
            "IDOR — swap an ID between two accounts you control; the classic scorer",
            "JWT alg confusion — 'none', or HS256 signed with the public key",
            "SSTI — template syntax in any field that gets rendered back",
            "Race conditions — two simultaneous requests on a one-time action",
            "Mass assignment — add role/is_admin to a JSON body the API accepts",
            "SSRF — any parameter taking a URL the server fetches",
            "Prototype pollution — __proto__ keys in JSON on Node backends",
            "Second-order injection — input stored now, executed on another page",
        ],
    },

    # ------------------------------------------------- binary and reversing
    "binary": {
        "label": "Binary & Reversing",
        "colour": "#ff2e97",
        "summary": "Identify, then understand, then exploit. Most CTF binaries "
                   "give up their secret to `strings` and a look at main().",
        "triage": [
            "file — what is it, is it stripped, static or dynamic",
            "strings -n 8 — flags and hints hide here more often than you'd think",
            "checksec — which mitigations are on tells you the intended path",
            "objdump/r2 — find main, follow the comparison that gates success",
            "ltrace/strace — watch libc and syscalls without reading assembly",
        ],
        "tools": [
            {"name": "file", "for": "Identify format and architecture",
             "cmd": "file {file}"},
            {"name": "strings", "for": "Readable data in the binary",
             "cmd": "strings -n 8 {file} | less"},
            {"name": "checksec", "for": "RELRO / stack canary / NX / PIE",
             "cmd": "pwn checksec {file}"},
            {"name": "radare2", "for": "Disassemble and analyse",
             "cmd": "r2 -AA {file}   # then: afl, s main, pdf"},
            {"name": "objdump", "for": "Quick disassembly of a function",
             "cmd": "objdump -d -M intel {file} | less"},
            {"name": "readelf", "for": "Sections, symbols, dynamic imports",
             "cmd": "readelf -a {file} | less"},
            {"name": "ltrace", "for": "Library calls at runtime",
             "cmd": "ltrace ./{file}"},
            {"name": "strace", "for": "Syscalls at runtime",
             "cmd": "strace -f ./{file}"},
            {"name": "gdb", "for": "Dynamic analysis and breakpoints",
             "cmd": "gdb -q {file}   # then: break main, run, info registers"},
            {"name": "upx", "for": "Unpack a UPX-packed binary",
             "cmd": "upx -d {file}"},
            {"name": "pwntools", "for": "Scripting interaction with a binary",
             "cmd": "python3 -c \"from pwn import *; p=process('./{file}'); p.interactive()\""},
        ],
        "patterns": [
            "Hardcoded comparison — strings or a strcmp against the flag",
            "XOR-obfuscated string built at runtime; watch memory in gdb",
            "Buffer overflow into a return address (check NX and canary first)",
            "Format string — printf(user_input) leaking or writing memory",
            "Anti-debug via ptrace — patch the check or set the return value",
            "Packed binary — unpack before anything else makes sense",
        ],
    },

    # ---------------------------------------------------------- cryptography
    "crypto": {
        "label": "Cryptography",
        "colour": "#a855f7",
        "summary": "The maths is almost never broken; the implementation is. "
                   "Look for reused keys, tiny exponents, and predictable nonces.",
        "triage": [
            "Identify the encoding first — base64/hex/rot are not encryption",
            "If RSA: how big is n, what is e, are there several ciphertexts",
            "If a hash: identify the algorithm, then check for known plaintext",
            "If a cipher: ECB shows repeating blocks; look at the ciphertext",
            "Check for reused nonce/IV across messages — instant break",
        ],
        "tools": [
            {"name": "CyberChef-ish decode", "for": "Chained decoding locally",
             "cmd": "echo '{data}' | base64 -d | xxd | head"},
            {"name": "hash-identifier", "for": "Which hash algorithm is this",
             "cmd": "hashid '{hash}'"},
            {"name": "john", "for": "Crack hashes with a wordlist",
             "cmd": "john --wordlist=/opt/wordlists/rockyou.txt {file}"},
            {"name": "openssl", "for": "Inspect keys and certificates",
             "cmd": "openssl rsa -in {file} -text -noout"},
            {"name": "python + pycryptodome", "for": "Everything else",
             "cmd": "python3 -c \"from Crypto.Util.number import *; print(long_to_bytes({n}))\""},
            {"name": "sympy", "for": "Factoring and modular arithmetic",
             "cmd": "python3 -c \"import sympy; print(sympy.factorint({n}))\""},
            {"name": "RsaCtfTool", "for": "Automated attacks on weak RSA",
             "cmd": "RsaCtfTool --publickey {file} --uncipherfile {cipher}"},
        ],
        "patterns": [
            "Small e (e=3) with no padding — take the integer cube root",
            "Shared modulus or common factor between two public keys (GCD)",
            "Fermat factorisation when p and q are close together",
            "Wiener's attack when d is small",
            "ECB mode — identical plaintext blocks give identical ciphertext",
            "Nonce reuse in CTR/GCM — XOR the ciphertexts together",
            "Hash length extension on naive MAC = hash(secret || message)",
            "Padding oracle when the server distinguishes padding errors",
        ],
    },

    # -------------------------------------------------------------- forensics
    "forensics": {
        "label": "Forensics",
        "colour": "#39ff5f",
        "summary": "Something is hidden in a file, a capture, or a memory image. "
                   "Work outside-in: metadata, then structure, then content.",
        "triage": [
            "file + exiftool — type and metadata, including stray comment fields",
            "binwalk — is another file embedded inside this one",
            "strings — cheap and frequently decisive",
            "For images: check LSBs, colour planes, and appended data after EOF",
            "For pcap: Statistics → Protocol Hierarchy, then follow streams",
        ],
        "tools": [
            {"name": "exiftool", "for": "All metadata, all formats",
             "cmd": "exiftool {file}"},
            {"name": "binwalk", "for": "Find and extract embedded files",
             "cmd": "binwalk -e {file}"},
            {"name": "foremost", "for": "Carve files by signature",
             "cmd": "foremost -i {file} -o carved/"},
            {"name": "steghide", "for": "Extract hidden data (JPEG/WAV)",
             "cmd": "steghide extract -sf {file}"},
            {"name": "zsteg", "for": "LSB steganography in PNG/BMP",
             "cmd": "zsteg -a {file}"},
            {"name": "pngcheck", "for": "Corrupt or manipulated PNG structure",
             "cmd": "pngcheck -v {file}"},
            {"name": "tshark", "for": "Read a packet capture",
             "cmd": "tshark -r {file} -q -z io,phs"},
            {"name": "tshark export", "for": "Pull files out of HTTP traffic",
             "cmd": "tshark -r {file} --export-objects http,extracted/"},
            {"name": "volatility3", "for": "Memory image analysis",
             "cmd": "vol -f {file} windows.pslist"},
            {"name": "sleuthkit", "for": "Disk image forensics",
             "cmd": "fls -r {file}"},
        ],
        "patterns": [
            "Data appended after the image EOF marker — binwalk or a hex editor",
            "Flag in EXIF comment, or in a PNG tEXt chunk",
            "LSB steganography — zsteg for PNG, or check colour planes",
            "Wrong file extension / corrupted magic bytes — fix the header",
            "Password for steghide hidden elsewhere in the challenge",
            "Deleted-but-recoverable file in a disk image",
            "Credentials in cleartext protocol traffic in a pcap",
        ],
    },

    # ------------------------------------------------------------ network/ICS
    "network": {
        "label": "Network & ICS",
        "colour": "#ffb31a",
        "summary": "Industrial protocols were designed for isolated networks and "
                   "mostly have no authentication at all. That is the finding.",
        "triage": [
            "Map what's listening — and on which industrial ports",
            "Identify the protocol: Modbus 502, S7comm 102, DNP3 20000, BACnet 47808",
            "Read before you write. Never issue a write to an ICS device",
            "In a pcap, filter by protocol and reconstruct the control sequence",
            "Look for cleartext credentials and management interfaces",
        ],
        "tools": [
            {"name": "nmap ICS scripts", "for": "Identify industrial devices",
             "cmd": "nmap -Pn -sV --script s7-info,modbus-discover,bacnet-info -p 102,502,20000,44818,47808 {host}"},
            {"name": "nmap service scan", "for": "General service identification",
             "cmd": "nmap -sV -sC -p- --min-rate 1000 {host}"},
            {"name": "tshark filter", "for": "Isolate a protocol in a capture",
             "cmd": "tshark -r {file} -Y 'modbus || s7comm || dnp3'"},
            {"name": "tshark creds", "for": "Cleartext credentials in traffic",
             "cmd": "tshark -r {file} -Y 'http.authorization || ftp.request.command == \"PASS\"'"},
            {"name": "scapy", "for": "Craft or replay packets",
             "cmd": "python3 -c \"from scapy.all import *; print(rdpcap('{file}').summary())\""},
            {"name": "pymodbus", "for": "Read Modbus registers (read-only)",
             "cmd": "python3 -c \"from pymodbus.client import ModbusTcpClient as C; c=C('{host}'); print(c.read_holding_registers(0,10).registers)\""},
            {"name": "tcpdump", "for": "Capture traffic",
             "cmd": "tcpdump -i any -w capture.pcap host {host}"},
        ],
        "patterns": [
            "Modbus/S7comm with no authentication — reading is often the flag",
            "Default credentials on an HMI or engineering workstation",
            "Cleartext Telnet/FTP/HTTP management on an OT segment",
            "Flat network — IT and OT reachable from the same segment",
            "Firmware or project files exposed over TFTP/FTP",
            "Replayed control sequences in a capture reveal the process logic",
        ],
    },

    # -------------------------------------------------------- drone/telemetry
    "drone": {
        "label": "Drone & Telemetry",
        "colour": "#21b8ff",
        "summary": "Almost always MAVLink. Unauthenticated by design, so the "
                   "challenge is usually parsing a log rather than breaking crypto.",
        "triage": [
            "Identify the log format: .tlog (MAVLink), .bin/.log (ArduPilot DataFlash)",
            "Parse to readable messages first — don't guess at the binary",
            "Look at GPS tracks, mode changes, and parameter values",
            "Check for MAVLink signing; if absent, injection is trivially possible",
            "Correlate telemetry timestamps against the challenge narrative",
        ],
        "tools": [
            {"name": "pymavlink dump", "for": "Read a telemetry log",
             "cmd": "python3 -m pymavlink.tools.mavlogdump {file}"},
            {"name": "pymavlink filter", "for": "Extract one message type",
             "cmd": "python3 -m pymavlink.tools.mavlogdump --types GPS_RAW_INT {file}"},
            {"name": "pymavlink to CSV", "for": "Get data into a spreadsheet",
             "cmd": "python3 -m pymavlink.tools.mavlogdump --format csv --types GLOBAL_POSITION_INT {file} > track.csv"},
            {"name": "mavparams", "for": "Dump vehicle parameters from a log",
             "cmd": "python3 -m pymavlink.tools.mavparmdiff {file}"},
            {"name": "tshark MAVLink", "for": "MAVLink over UDP in a capture",
             "cmd": "tshark -r {file} -Y mavlink_proto -T fields -e mavlink_proto.msgid"},
            {"name": "exiftool geotags", "for": "GPS coordinates in drone imagery",
             "cmd": "exiftool -gpslatitude -gpslongitude -createdate {file}"},
        ],
        "patterns": [
            "Flag or coordinates embedded in a STATUSTEXT message",
            "GPS track that spells something when plotted",
            "Unsigned MAVLink — no authentication on command messages",
            "Geotagged images revealing an operator or launch location",
            "Parameter values changed mid-flight telling the story",
            "Telemetry over unencrypted 915MHz/UDP captured in a pcap",
        ],
    },
}

# The event itself — so the countdown and checklist need no configuration.
EVENT = {
    "name": "Indian Army Terrier Cyber Quest 2026 — Bug Hunting",
    "organiser": "Territorial Army · CyberPeace Foundation · NCRB",
    "url": "https://www.cyberchallenge.in/tcq2026",
    "milestones": [
        {"label": "Registration closes", "date": "2026-08-20", "note": "Teams of up to 3, free entry, Indian citizens"},
        {"label": "Shortlisting / online CTF", "date": "2026-09-01", "note": "Jeopardy-style qualifier, runs to 10 Sept"},
        {"label": "Grand Finale", "date": "2026-10-06", "note": "36 hours in person, USI of India, New Delhi"},
        {"label": "Award ceremony", "date": "2026-10-09", "note": ""},
    ],
    "scoring": ["Severity of vulnerabilities detected", "Methodology", "Complexity", "Originality"],
    "rules": [
        "Operate strictly within the provided sandbox and targets",
        "Never attempt to access real or third-party systems",
        "Report anything found outside the sandbox via coordinated disclosure",
        "One participant may enter only one track",
    ],
    "prep": [
        "Register before 20 August — collect certification/badge links first",
        "Agree who covers which category across the three of you",
        "Practise the finale writeup format; methodology is explicitly scored",
        "Pre-download tools and wordlists — assume venue network is poor",
    ],
}


def arsenal() -> dict:
    return {"categories": CATEGORIES, "event": EVENT}


def category_names() -> list[str]:
    return list(CATEGORIES)
