"""
ARGUS - Listening Port Sentinel: what on this machine accepts connections.

MITRE T1571 (Non-Standard Port), T1571-adjacent T1205 (Traffic Signalling) and
T1021 (Remote Services). The tactic that matters is the one an implant needs:
something on this box has to be reachable before anything can reach it.

WHY THIS IS A DIFF, LIKE persistence.py, AND NOT A LIST.

`netstat -ano` already prints every listener. Nobody reads it, for the same
reason nobody reads Autoruns: on this machine that is dozens of sockets, almost
all of them Windows' own, and the useful question is never "what is listening"
but "what STARTED listening since I last looked, and is it reachable from
outside this machine". That needs memory between runs. So a baseline is kept in
%LOCALAPPDATA% and only the delta is alerted on, and the FIRST PASS NEVER
ALERTS -- everything present when the sentinel first runs is the status quo.

AND A CHANGE MUST SURVIVE TWO SCANS. Run against this machine for a day, the
first version produced 38 findings and 33 of them were Firefox and VS Code
opening short-lived sockets. See _pending below: the property that separates a
listener worth reporting from one that is not is how long it lasts, not what it
is called.

THE ONE DISTINCTION THAT CARRIES THE WHOLE DETECTOR is bind address, not port
number. A service bound to 127.0.0.1 cannot be reached from the network at all:
ARGUS's own orchestrator is one of these (127.0.0.1:8420), and so are most
developer tools. A service bound to 0.0.0.0 or :: accepts from anything that can
route to this host -- the coffee-shop wifi, the hotel LAN, the other side of a
VPN. The same port number means completely different things in those two cases,
which is why "port 4444 is open" is a scary-sounding non-fact and "something new
is accepting connections from the network" is an actual finding.

WHAT IT REFUSES TO DO, and this is the same rule network_skill.outbound()
follows: NO reverse DNS, NO WHOIS, NO reputation lookups, no sending a port list
anywhere. Asking what is listening on your own machine must not itself tell a
third party what is listening on your machine. Everything here is psutil
counters and a local JSON file; the module imports no network library at all,
and its test asserts that it never grows one.

WHAT IT CANNOT DO, stated rather than implied:

  * It cannot see listeners owned by processes this user may not query. psutil
    returns the socket but not always the owning process name without
    elevation; those are reported as an unknown owner rather than skipped,
    because an unattributable listener is MORE interesting than an attributed
    one, not less.
  * It cannot tell you whether the port is reachable from the internet. That
    depends on the router in front of you, and finding out means sending
    traffic to somebody. It reports reachable-from-this-network, which is what
    is knowable locally, and says so in those words.
  * A UDP "listener" has no listen state. UDP sockets bound to a wildcard
    address are collected, and flagged as bound rather than listening, because
    conflating the two would overstate what is known.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import threading
import time

import paths

TECHNIQUE = "T1571"

# Every 45 seconds. A new listener is the kind of thing worth noticing within a
# minute rather than within an hour, and one sweep measured well under a tenth
# of a second -- psutil reads the same table netstat does, in one call.
SCAN_INTERVAL_S = 45

# More new listeners than this in one pass is a machine that just booted or
# came out of sleep, not an intrusion. Same reasoning as persistence.py's flood
# threshold: burying one real finding under forty routine ones is how a
# detector gets muted.
_FLOOD_THRESHOLD = 25

BASELINE_PATH_OVERRIDE = None      # tests point this at a temp file

# ── the confirmation pass ────────────────────────────────────────────────────
#
# A CHANGE MUST SURVIVE TWO CONSECUTIVE SCANS BEFORE IT IS REPORTED, and this
# is not tuning -- it is the difference between a detector and a noise machine.
#
# Measured, on this machine, before it existed: 38 listener changes in one day,
# 33 of them Firefox, VS Code and Electron apps opening and closing short-lived
# sockets. WebRTC alone churns several a minute. Every one was a true statement
# about the socket table and none of them was a change worth a person's
# attention, and they buried the four that were.
#
# The property that separates them is DURATION, not identity -- an allowlist of
# "browsers are fine" would be exactly the kind of signature list this suite
# avoids, and would also excuse a backdoor that named itself firefox.exe. A
# thing that accepts connections in order to be reached has to keep accepting
# them; an ephemeral socket by definition does not. At a 45-second cadence a
# change has to hold for roughly 45 seconds to be reported, which no WebRTC
# socket does and every implant must.
#
# THE BASELINE IS HELD BACK for an unconfirmed change. Committing it on the
# first sighting would absorb the new listener into the baseline, so the second
# pass would see no change at all and the finding would be lost silently --
# which is a far worse failure than the noise this replaces.
_pending: set = set()              # {(change_kind, socket_id)} seen once

# Addresses that mean "anything that can reach this host". The distinction this
# detector is built on -- see the module header.
WILDCARD_ADDRS = frozenset({"0.0.0.0", "::", "*", ""})
LOOPBACK_ADDRS = frozenset({"127.0.0.1", "::1", "localhost"})

# ── the UDP cut-off ──────────────────────────────────────────────────────────
# Windows hands out 49152-65535 for ephemeral source ports, but the practical
# floor is lower: the measured flood included 57542 and 56781 alongside a
# svchost socket on 5050, and services below 1024 are assigned rather than
# random. 10000 is the line between "a port something CHOSE" and "a port the
# OS picked" for the purposes of this detector -- generous on the service side,
# which is the direction to be generous in, since a missed service is a blind
# spot and a reported ephemeral port is noise that buries real findings.
_UDP_EPHEMERAL_FLOOR = 10000

# UDP ports above the floor that are still genuinely services, so the cut-off
# does not create a blind spot for the things people actually run.
_UDP_SERVICE_PORTS = frozenset({
    51820,      # WireGuard
    500, 4500,  # IKE / IPsec NAT-T (below the floor, listed for the record)
    27015,      # Source engine / game servers
    19132,      # Minecraft Bedrock
    10000,      # Webmin / misc
    33434,      # traceroute
})

# Ports Windows itself listens on, world-bound, on a stock install. Present so a
# clean machine does not read as compromised on day one -- these still appear in
# the inventory and are still diffed, they simply do not get an elevated
# severity for being world-bound. NOT an allowlist of processes: a listener on
# 445 owned by something that is not the System process is still graded on its
# owner, because the port number is not the thing being trusted here.
_ROUTINE_WINDOWS_PORTS = frozenset({
    135,      # RPC endpoint mapper
    139,      # NetBIOS session
    445,      # SMB
    5353,     # mDNS
    5355,     # LLMNR
    3702,     # WS-Discovery
    1900,     # SSDP
})

# Ports with a well-known remote-access meaning. A NEW listener here is worth
# more than a new listener on an arbitrary high port, because it is what a
# person would deliberately expose -- or what a tool exposes by default.
NOTABLE_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP (Remote Desktop)", 5900: "VNC",
    5985: "WinRM (HTTP)", 5986: "WinRM (HTTPS)", 1433: "SQL Server",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
    4444: "Metasploit default handler", 1080: "SOCKS proxy",
    8080: "HTTP alternate", 9001: "Tor / common C2 default",
}

# Directories a legitimate long-running network service is essentially never
# installed into. Raises severity; never the sole reason for a finding.
SUSPICIOUS_DIRS = (
    r"\appdata\local\temp",
    r"\windows\temp",
    r"\downloads",
    r"\users\public",
    r"\$recycle.bin",
)

# Interpreters and proxy binaries. One of these ACCEPTING CONNECTIONS is a
# different proposition from one merely running: it is a script that has opened
# a socket, which is the shape of a handler rather than of a tool.
SUSPICIOUS_EXES = (
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
)

_state = {
    "supported": True,
    "running": False,
    "baseline_established": False,
    "baseline_at": "",
    "listeners": 0,
    "world": 0,
    "unattributed": 0,
    "changes_total": 0,
    "pending": 0,
    "scans": 0,
    "desyncs": 0,
    "last_error": "",
    "uncovered": "reachability from outside this network (needs sending traffic)",
    "attribution": "socket owner via psutil; unattributable sockets are reported as such",
}
_lock = threading.RLock()


# ── collection ───────────────────────────────────────────────────────────────
def scope_of(addr: str) -> str:
    """world / loopback / specific -- the only classification that matters.

    "specific" is a bind to one real interface address (192.168.1.40, say):
    reachable from that network but not from every interface. Graded between
    the two, and named rather than folded into either, because a service bound
    deliberately to the LAN address is a decision somebody made and a service
    bound to 0.0.0.0 is usually a default nobody looked at.
    """
    a = (addr or "").strip().lower()
    # IPv6 addresses arrive with a scope suffix on some interfaces (fe80::1%12).
    a = a.split("%", 1)[0]
    if a in WILDCARD_ADDRS:
        return "world"
    if a in LOOPBACK_ADDRS or a.startswith("127."):
        return "loopback"
    return "specific"


def _owner(pid):
    """(name, exe) for a socket's owning process, best effort.

    A socket whose owner cannot be read is NOT dropped. Returning ("?", "") and
    letting it through is deliberate: an unattributable listener is a stronger
    signal than an attributed one, and a detector that silently discarded what
    it could not explain would be blind to exactly the case worth seeing.
    """
    if not pid:
        return "?", ""
    try:
        import psutil
        p = psutil.Process(pid)
        try:
            exe = p.exe() or ""
        except Exception:
            exe = ""
        return (p.name() or "?"), exe
    except Exception:
        return "?", ""


def collect() -> dict:
    """{socket_id: entry} for everything this machine is accepting on.

    Keyed on (proto, scope, port, owning image) rather than on the exact bind
    address or the PID. Both of those churn for reasons that are not security
    events -- a service restarts and gets a new PID, DHCP hands out a different
    LAN address -- and keying on them would make every reboot look like the
    whole listener set had been replaced.
    """
    import psutil

    out = {}
    for c in psutil.net_connections(kind="inet"):
        try:
            laddr = c.laddr
            if not laddr:
                continue
            addr = getattr(laddr, "ip", "") or ""
            port = int(getattr(laddr, "port", 0) or 0)
            if not port:
                continue

            is_tcp = _is_stream(c)
            # TCP has an explicit accept state; anything else on a TCP socket is
            # an established or closing connection, which is network_skill's
            # question, not this one.
            if is_tcp and (c.status or "").upper() != "LISTEN":
                continue
            # UDP HAS NO LISTEN STATE, and taking every bound UDP socket as a
            # "listener" was a false-positive machine. Measured on the owner's
            # log within an hour of shipping: a dozen findings in one tick for
            # svchost and firefox on udp/57542, 60885, 56781, 57167, 58121,
            # 65253 -- every one of them an EPHEMERAL SOURCE PORT for an
            # OUTBOUND datagram, which Windows binds to 0.0.0.0 and therefore
            # scope_of() correctly, and uselessly, called world-reachable.
            # They churn every few seconds, so they also desynchronised the
            # baseline and pushed a spoken alert.
            #
            # A UDP socket is only worth reporting when its port MEANS
            # something: a service listens on a port it was assigned, and the
            # ephemeral range is by definition the one the OS hands out at
            # random. So UDP is kept on well-known and registered-service ports
            # and dropped above them. TCP is untouched -- a TCP socket in LISTEN
            # is unambiguous whatever its port number, and a backdoor on a high
            # TCP port is exactly what this detector is for.
            scope = scope_of(addr)
            if not is_tcp:
                if scope == "loopback":
                    continue
                if port >= _UDP_EPHEMERAL_FLOOR and port not in _UDP_SERVICE_PORTS:
                    continue

            proto = "tcp" if is_tcp else "udp"
            name, exe = _owner(c.pid)
            sid = f"{proto}:{scope}:{port}:{os.path.basename(exe or name).lower()}"
            out[sid] = {
                "proto": proto,
                "port": port,
                "addr": addr,
                "scope": scope,
                "pid": int(c.pid or 0),
                "name": name,
                "exe": exe,
                "listening": bool(is_tcp),
            }
        except Exception:
            # One unreadable socket must never cost the rest of the table.
            continue
    return out


def _is_stream(conn) -> bool:
    """TCP or not, without importing socket.

    Deliberately duck-typed on the enum's own name rather than compared against
    socket.SOCK_STREAM: `import socket` is one of the signatures the capability
    scanner reads as NETWORK ACCESS, and this module's whole claim is that it
    reaches nothing. Importing a network library for one integer constant would
    make that claim false in the only place anyone can check it -- the imports.
    """
    t = getattr(conn, "type", None)
    if t is None:
        return False
    name = str(getattr(t, "name", "")).upper()
    if name:
        return name.endswith("STREAM")
    try:
        return int(t) == 1           # SOCK_STREAM
    except (TypeError, ValueError):
        return False


# ── grading ──────────────────────────────────────────────────────────────────
def classify(entry: dict) -> tuple:
    """(severity, [reasons]) for a NEWLY-APPEARED listener.

    Pure -- no psutil, no clock, no globals -- so the judgement that decides
    whether ARGUS interrupts you can be tested on dicts rather than by getting
    a real backdoor to open a real socket.
    """
    reasons = []
    scope = entry.get("scope", "")
    port = int(entry.get("port", 0) or 0)
    name = (entry.get("name") or "").lower()
    exe = (entry.get("exe") or "").lower()

    if scope == "loopback":
        # Cannot be reached from off this machine. Recorded for the inventory,
        # never alarmed on -- this is where most of a developer's sockets live
        # and treating them as findings is how the detector becomes noise.
        return "low", ["bound to loopback — not reachable from the network"]

    if scope == "world":
        reasons.append("accepts connections from any network this machine is on")
    else:
        reasons.append(f"accepts connections on {entry.get('addr', 'a network interface')}")

    label = NOTABLE_PORTS.get(port)
    if label:
        reasons.append(f"port {port} is {label}")

    if name == "?" and not exe:
        reasons.append("I can't tell which process owns it")

    for d in SUSPICIOUS_DIRS:
        if d in exe:
            reasons.append(f"the program lives in {d.strip(chr(92))}")
            break

    base = os.path.basename(exe) or name
    if base in SUSPICIOUS_EXES:
        reasons.append(f"an interpreter is holding the socket ({base})")

    # SEVERITY. World-bound plus any second reason is high; world-bound alone on
    # a routine Windows port is medium, because a stock Windows install has
    # several and grading those high would mean the first scan after a reboot
    # cried wolf. Everything else that is reachable is medium.
    strong = (label is not None
              or (name == "?" and not exe)
              or base in SUSPICIOUS_EXES
              or any(d in exe for d in SUSPICIOUS_DIRS))
    if scope == "world" and strong:
        return "high", reasons
    if scope == "world" and port in _ROUTINE_WINDOWS_PORTS:
        reasons.append("this is a standard Windows service port")
        return "medium", reasons
    return "medium", reasons


def diff(old: dict, new: dict) -> list:
    """Listeners that appeared or vanished. Pure and total.

    APPEARED is the finding. DISAPPEARED is recorded at low severity for the
    timeline -- a service stopping is overwhelmingly a normal event, and there
    is no way here to distinguish "the user quit their dev server" from
    "something tidied up after itself".
    """
    changes = []
    for sid, cur in new.items():
        if sid not in old:
            changes.append({"change": "appeared", "id": sid, **cur})
    for sid, prev in old.items():
        if sid not in new:
            changes.append({"change": "disappeared", "id": sid, **prev})
    return changes


def severity_of(change: dict) -> tuple:
    if change.get("change") == "disappeared":
        return "low", ["a listener stopped (usually just a program closing)"]
    return classify(change)


# ── baseline ─────────────────────────────────────────────────────────────────
def _baseline_path():
    return BASELINE_PATH_OVERRIDE or paths.writable("listening_baseline.json")


def load_baseline():
    """The stored baseline, or None when there is no usable one.

    None and {} are DIFFERENT, exactly as in persistence.py: an empty-but-real
    baseline must still be diffed against, or the first listener to appear on a
    machine that had none would be absorbed silently.
    """
    try:
        with open(_baseline_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None
        entries = data.get("entries")
        if isinstance(entries, dict):
            _state["baseline_at"] = data.get("at", "")
            return entries
        return None
    except (OSError, ValueError):
        return None


def save_baseline(entries: dict) -> bool:
    try:
        path = _baseline_path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                       "entries": entries}, fh, separators=(",", ":"))
        os.replace(tmp, path)
        return True
    except OSError as e:
        _state["last_error"] = f"baseline save: {type(e).__name__}"
        return False


# ── emit / scan ──────────────────────────────────────────────────────────────
def _emit(record, change):
    sev, reasons = severity_of(change)
    port = change.get("port", 0)
    proto = change.get("proto", "tcp")
    finding = {
        "technique": TECHNIQUE,
        "detector": "listening",
        "severity": sev,
        "target": f"{proto}/{port}",
        "name": change.get("name") or "?",
        "pid": int(change.get("pid", 0) or 0),
        "path": change.get("exe", ""),
        "action": change["change"],
        "surface": change.get("scope", ""),
        "where": f"{change.get('addr', '?')}:{port}",
        "reasons": reasons,
        "reason": f"listening_{change['change']}_{change.get('scope', '')}",
        # Per (change kind, socket identity). A listener that comes and goes on
        # the same port with the same owner is one standing condition; the same
        # port appearing under a DIFFERENT program is a different key and
        # alerts immediately, which is the case worth catching.
        "dedup": f"listening|{change['change']}|{change['id']}",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    with _lock:
        _state["changes_total"] += 1
    try:
        if record:
            record(finding)
    except Exception as e:
        _state["last_error"] = f"emit: {type(e).__name__}"
    return finding


def _emit_desync(record, changes):
    """One finding standing in for an implausible burst of them."""
    appeared = sum(1 for c in changes if c.get("change") == "appeared")
    finding = {
        "technique": TECHNIQUE,
        "detector": "listening",
        "severity": "medium",
        "target": "listener baseline",
        "name": "baseline desync",
        "pid": 0,
        "path": "",
        "action": "desync",
        "surface": "all",
        "where": "listening baseline",
        "reasons": [f"{len(changes)} listener changes in one pass "
                    f"({appeared} new) exceeds the {_FLOOD_THRESHOLD} "
                    f"plausibility limit",
                    "usually a boot or a resume from sleep, not an intrusion",
                    "baseline re-anchored; individual changes suppressed"],
        "reason": "listening_baseline_desync",
        "dedup": "listening|desync",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    with _lock:
        _state["changes_total"] += 1
        _state["desyncs"] += 1
    try:
        if record:
            record(finding)
    except Exception as e:
        _state["last_error"] = f"emit desync: {type(e).__name__}"
    return finding


def run_checks(record) -> list:
    """One full pass: collect, diff, emit, re-baseline."""
    try:
        entries = collect()
    except Exception as e:
        _state["last_error"] = f"collect: {type(e).__name__}: {e}"[:120]
        return []

    with _lock:
        _state["scans"] += 1
        _state["listeners"] = len(entries)
        _state["world"] = sum(1 for e in entries.values() if e["scope"] == "world")
        _state["unattributed"] = sum(1 for e in entries.values()
                                     if e.get("name") == "?" and not e.get("exe"))

    old = load_baseline()
    if old is None:
        save_baseline(entries)
        with _lock:
            _state["baseline_established"] = True
            _state["baseline_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        return []

    with _lock:
        _state["baseline_established"] = True
    changes = diff(old, entries)

    # THE CONFIRMATION PASS. See _pending's own comment for why a change has to
    # be seen twice: without it, a browser's short-lived sockets produced 33 of
    # 38 daily findings and buried the ones that mattered.
    global _pending
    seen_now = {(c["change"], c["id"]) for c in changes}
    confirmed = [c for c in changes if (c["change"], c["id"]) in _pending]
    confirmed_keys = {(c["change"], c["id"]) for c in confirmed}
    with _lock:
        # Next round waits on whatever is new this round. A change that
        # vanished before confirmation simply drops out of the set, which is
        # the ephemeral case resolving itself.
        _pending = seen_now - confirmed_keys
        _state["pending"] = len(_pending)

    emitted = []
    if len(confirmed) > _FLOOD_THRESHOLD:
        emitted.append(_emit_desync(record, confirmed))
    else:
        for change in confirmed:
            try:
                emitted.append(_emit(record, change))
            except Exception as e:
                _state["last_error"] = f"emit {change.get('id', '?')}: {type(e).__name__}"

    # Commit ONLY what was confirmed. Saving `entries` wholesale would fold an
    # unconfirmed listener into the baseline, so the next pass would see no
    # change and the finding would be lost -- the noise would be gone and so
    # would the detector.
    merged = dict(old)
    for change in confirmed:
        if change["change"] == "appeared":
            if change["id"] in entries:
                merged[change["id"]] = entries[change["id"]]
        else:
            merged.pop(change["id"], None)
    save_baseline(merged)
    return emitted


# ── the spoken answer ────────────────────────────────────────────────────────
def inventory() -> dict:
    """The live picture, grouped. Local only, and the ONLY collector call the
    voice path makes -- it does not read the baseline, because "what is
    listening right now" is a different question from "what changed"."""
    try:
        entries = collect()
    except Exception as e:
        return {"error": f"{type(e).__name__}", "world": [], "loopback": [],
                "specific": []}
    out = {"error": "", "world": [], "loopback": [], "specific": []}
    for e in entries.values():
        out.setdefault(e["scope"], []).append(e)
    for k in ("world", "loopback", "specific"):
        out[k].sort(key=lambda e: (e["port"], e.get("name", "")))
    return out


def is_windows_service(entry: dict) -> bool:
    """Is this socket held by Windows itself?

    Decided on the OWNING IMAGE'S LOCATION, not on the port number. A binary
    under %SystemRoot% (or the kernel's own "System" pseudo-process) holding a
    listener is Windows doing what Windows does -- RPC, SMB, NetBIOS, mDNS,
    WS-Discovery, the SSDP ephemerals. Planting a binary there needs
    administrator rights, and the tamper and persistence detectors are the ones
    that speak to that; treating the location as ordinary here is not a trust
    decision so much as a division of labour.

    THIS IS ONLY EVER USED TO SUMMARISE, NEVER TO SUPPRESS. Every one of these
    sockets is still collected, still diffed, and still alerts if it APPEARS --
    what this changes is that report() counts them in one clause instead of
    reading thirty svchost lines aloud and burying the postgres server that is
    the actual answer to the question.
    """
    name = (entry.get("name") or "").strip().lower()
    exe = (entry.get("exe") or "").strip().lower()
    if name in ("system", "system idle process"):
        return True
    if not exe:
        return False               # unattributed is never "routine"
    root = (os.environ.get("SystemRoot") or r"C:\Windows").lower()
    return exe.startswith(root + os.sep) or exe.startswith(root + "/")


def _describe(entry: dict) -> str:
    who = entry.get("name") or "?"
    if who == "?":
        who = "something I can't identify"
    label = NOTABLE_PORTS.get(entry["port"])
    txt = f"{who} on {entry['proto']} {entry['port']}"
    if label:
        txt += f", which is {label}"
    return txt


def _sentences(bits: list) -> str:
    """Join clauses into spoken sentences with each one capitalised.

    Worth its own function because the naive ". ".join() produced "44 things
    accept connections. that's svchost.exe on udp 123." -- lowercase after a
    full stop, which a TTS engine reads with the wrong intonation and which
    looks broken in the HUD transcript beside it.
    """
    out = []
    for b in bits:
        b = b.strip()
        if b:
            out.append(b[0].upper() + b[1:])
    return ". ".join(out) + "." if out else ""


def report() -> str:
    """A spoken answer to "what's listening on my machine?".

    String logic only -- no model, no network. What accepts connections on this
    machine is precisely the detail that must not become someone else's
    telemetry on its way to being phrased nicely, and it is the same rule
    network_skill.outbound() and persistence.report() follow.

    IT RANKS, RATHER THAN LISTING. The first version of this read the reachable
    sockets out in port order and produced, verbatim: "44 things on this machine
    accept connections from the network. That's svchost.exe on udp 123;
    svchost.exe on tcp 135; System on tcp 445; svchost.exe on tcp 5040, and 40
    more." Every word of that is true and none of it is the answer -- a
    Postgres server bound to 0.0.0.0 was sitting at position twelve, inside the
    "and 40 more". That is netstat with a voice, which the module header
    specifically says nobody reads.

    So: things that are NOT Windows' own services first, notable remote-access
    ports called out by name, and the routine Windows surface reduced to a
    single count that says what it is.
    """
    inv = inventory()
    if inv.get("error"):
        return (f"I couldn't read the socket table just now "
                f"({inv['error']}).")

    loop = inv["loopback"]
    reachable = inv["world"] + inv["specific"]
    if not reachable:
        return (f"Nothing on this machine is accepting connections from the "
                f"network, Boss. {len(loop)} thing"
                f"{'s are' if len(loop) != 1 else ' is'} listening on loopback "
                f"only, which nothing outside this box can reach.")

    # Notable = worth a name. Routine = worth a number.
    notable, routine = [], []
    for e in reachable:
        if NOTABLE_PORTS.get(e["port"]) or not is_windows_service(e):
            notable.append(e)
        else:
            routine.append(e)
    # World-bound before LAN-bound, then by port, so the loudest exposure leads.
    notable.sort(key=lambda e: (e["scope"] != "world", e["port"]))

    bits = []
    if notable:
        shown = notable[:4]
        more = len(notable) - len(shown)
        bits.append(f"{len(notable)} thing{'s' if len(notable) != 1 else ''} "
                    f"worth naming accept{'' if len(notable) != 1 else 's'} "
                    f"connections from the network")
        bits.append("; ".join(_describe(e) for e in shown)
                    + (f"; and {more} more" if more > 0 else ""))
    else:
        bits.append("nothing outside Windows' own services is accepting "
                    "connections from the network")

    if routine:
        bits.append(f"the other {len(routine)} are standard Windows services — "
                    f"file sharing, network discovery, that sort of thing")
    bits.append(f"another {len(loop)} listen on loopback only, which nothing "
                f"off this machine can reach")

    unknown = sum(1 for e in reachable if e.get("name") == "?" and not e.get("exe"))
    if unknown:
        bits.append(f"{unknown} of them I can't attribute to a program without "
                    f"more privilege than I have")
    return _sentences(bits)


# ── loop / lifecycle ─────────────────────────────────────────────────────────
def _watch_loop(record):
    with _lock:
        _state["running"] = True
    while True:
        try:
            run_checks(record)
        except Exception as e:
            _state["last_error"] = f"loop: {type(e).__name__}: {e}"[:120]
        time.sleep(SCAN_INTERVAL_S)


def start(record):
    try:
        import psutil  # noqa: F401
    except Exception:
        _state["supported"] = False
        _state["last_error"] = "psutil unavailable"
        return
    t = threading.Thread(target=_watch_loop, args=(record,), daemon=True,
                         name="argus-listening-watch")
    t.start()


def status() -> dict:
    with _lock:
        degraded = ""
        if not _state["supported"]:
            degraded = "psutil unavailable"
        elif not _state["baseline_established"]:
            degraded = "baseline not yet established (first scan pending)"
        elif _state["unattributed"]:
            degraded = (f"{_state['unattributed']} listening socket(s) cannot be "
                        f"attributed to a process without elevation")
        return {
            "detector": "listening",
            "technique": TECHNIQUE,
            "techniques": [TECHNIQUE],
            "ok": _state["running"] and _state["supported"],
            "degraded": degraded,
            "listeners": _state["listeners"],
            "world_reachable": _state["world"],
            "unattributed": _state["unattributed"],
            "baseline_established": _state["baseline_established"],
            "baseline_at": _state["baseline_at"],
            "scans": _state["scans"],
            "desyncs": _state["desyncs"],
            # Changes seen once and waiting for a second sighting. Almost
            # always short-lived application sockets on their way out; exposed
            # so the confirmation pass is visible rather than magic.
            "awaiting_confirmation": _state["pending"],
            "findings_total": _state["changes_total"],
            "uncovered": _state["uncovered"],
            "attribution": _state["attribution"],
            "last_error": _state["last_error"],
        }
