"""
ARGUS - Network status.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import socket
import subprocess
import time

import psutil


def interface_state() -> dict:
    """Local interface posture only; never opens a socket or resolves a name."""
    try:
        stats = psutil.net_if_stats()
        up = sorted(name for name, state in stats.items() if state.isup)
        counters = psutil.net_io_counters()
        return {
            "interfaces_up": tuple(up[:16]),
            "interface_count": len(stats),
            "bytes_sent": int(counters.bytes_sent),
            "bytes_received": int(counters.bytes_recv),
        }
    except Exception:
        return {}


def local_ip() -> str:
    """Report non-loopback interface addresses without making a connection."""
    ipv4, ipv6 = [], []
    try:
        for addresses in psutil.net_if_addrs().values():
            for addr in addresses:
                value = str(addr.address or "").split("%", 1)[0]
                if not value or value.startswith("127.") or value == "::1":
                    continue
                if addr.family == socket.AF_INET and not value.startswith("169.254."):
                    ipv4.append(value)
                elif addr.family == socket.AF_INET6 and not value.lower().startswith("fe80:"):
                    ipv6.append(value)
    except Exception:
        return "I couldn't read this machine's local IP addresses."
    addresses = list(dict.fromkeys(ipv4 + ipv6))
    if not addresses:
        return "This machine has no active local IP address."
    return "Local IP: " + ", ".join(addresses[:4]) + "."


def is_online() -> str:
    try:
        start = time.time()
        socket.create_connection(("1.1.1.1", 53), timeout=3).close()
        ms = (time.time() - start) * 1000
        return f"You're online. Latency to DNS is about {ms:.0f} milliseconds."
    except OSError:
        return "You appear to be offline."


def wifi_info() -> str:
    # Through execpolicy rather than subprocess directly: same allowlist,
    # same metacharacter check, same audit event, and the job object gives
    # the timeout teeth over anything netsh might spawn.
    import execpolicy

    try:
        out = execpolicy.run(
            ["netsh", "wlan", "show", "interfaces"],
            timeout=6, text=True,
        ).stdout
    except (execpolicy.ExecDenied, subprocess.SubprocessError, FileNotFoundError):
        return "I couldn't read the Wi-Fi status."

    ssid = signal = None
    for line in out.splitlines():
        line = line.strip()
        if line.lower().startswith("ssid") and "bssid" not in line.lower():
            ssid = line.split(":", 1)[-1].strip()
        elif line.lower().startswith("signal"):
            signal = line.split(":", 1)[-1].strip()

    if not ssid:
        return "You're not connected to Wi-Fi."
    msg = f"Connected to {ssid}"
    if signal:
        msg += f" at {signal} signal strength"
    return msg + "."


def wifi_set(enabled: bool, adapter: str = "Wi-Fi") -> str:
    """Enables or disables the named adapter -- "Wi-Fi" is the default name
    Windows gives its own wireless adapter, overridable for a machine that
    renamed it. Same execpolicy.run() path as wifi_info(); the write is
    netsh's own "interface set interface", not a new mechanism."""
    import execpolicy

    try:
        execpolicy.run(
            ["netsh", "interface", "set", "interface",
             adapter, "enable" if enabled else "disable"],
            timeout=8, text=True)
    except execpolicy.ExecDenied as e:
        return f"I can't do that: {e}"
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        return f"I couldn't change Wi-Fi: {e}"
    return f"Wi-Fi {'enabled' if enabled else 'disabled'}."


def data_usage() -> str:
    io = psutil.net_io_counters()
    sent = io.bytes_sent / (1024 ** 3)
    recv = io.bytes_recv / (1024 ** 3)
    return f"Since boot you've downloaded {recv:.1f} and uploaded {sent:.1f} gigabytes."


# ── what is talking to the internet ──────────────────────────────────────────
#
# "Who is my machine talking to right now?" -- the question you ask when
# something feels off, and the one Windows makes hardest to answer. Task
# Manager shows throughput, Resource Monitor shows a wall of rows, and neither
# groups by the thing you care about: which PROGRAM is holding connections.
#
# NO REVERSE DNS, AND THAT IS DELIBERATE. Turning 104.18.x.x into a hostname
# means asking a resolver, which tells that resolver -- and anyone between you
# and it -- exactly which addresses you are curious about. Looking up what your
# machine is connected to should not itself be a disclosure of what your
# machine is connected to. Ports and addresses are shown as they are.
#
# NO REPUTATION LOOKUPS either, for the same reason files_skill.inspect()
# refuses them: sending an IP to a scoring service reports your traffic to a
# third party, which is precisely what a person asking this question is
# usually trying to find out about.
#
# LOOPBACK AND LAN ARE EXCLUDED. A connection to 127.0.0.1 is a program
# talking to itself -- ARGUS's own orchestrator is on 127.0.0.1:8420 and would
# otherwise top its own list, which is both noise and slightly absurd.

_LOCAL_PREFIXES = ("127.", "0.", "::1", "fe80:", "10.", "192.168.")
_PORT_NAMES = {
    80: "http", 443: "https", 53: "dns", 22: "ssh", 21: "ftp", 25: "smtp",
    587: "smtp", 993: "imaps", 995: "pop3s", 3389: "rdp", 445: "smb",
    1433: "sql", 3306: "mysql", 5432: "postgres", 6379: "redis",
    8080: "http-alt", 8443: "https-alt",
}
MAX_REPORTED = 8


def _is_remote(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith("172."):
        # 172.16.0.0/12 is private; 172.32.x is not. Checked properly rather
        # than by prefix, because "172." alone would hide real traffic.
        try:
            return not (16 <= int(ip.split(".")[1]) <= 31)
        except (IndexError, ValueError):
            return True
    return not ip.startswith(_LOCAL_PREFIXES)


def outbound() -> list:
    """[{proc, pid, peers, ports}] for programs holding remote connections.

    Grouped by process, because "chrome has 40 connections" is one fact and
    forty rows is not an answer.
    """
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        # net_connections needs privileges for OTHER users' sockets; without
        # them psutil raises rather than returning a partial list.
        return []

    by_pid = {}
    for c in conns:
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
            continue
        ip = getattr(c.raddr, "ip", "")
        if not _is_remote(ip):
            continue
        entry = by_pid.setdefault(c.pid or 0, {"peers": set(), "ports": set()})
        entry["peers"].add(ip)
        entry["ports"].add(getattr(c.raddr, "port", 0))

    # MERGED BY NAME, not left per-PID. Found by running it: a browser or an
    # Electron app is a dozen processes, so a per-PID list printed
    # "claude.exe: 2 addresses. claude.exe: 2 addresses." -- which reads as a
    # duplication bug and buries the actual answer. The question is WHICH
    # PROGRAM is talking out, and that is one row per program.
    #
    # Peers are UNIONED across the processes, never summed: two helpers
    # talking to the same server is one address, and summing would inflate
    # every multi-process app.
    by_name = {}
    for pid, e in by_pid.items():
        try:
            name = psutil.Process(pid).name() if pid else "system"
        except Exception:
            name = f"pid {pid}"
        agg = by_name.setdefault(name, {"peers": set(), "ports": set(),
                                        "procs": 0})
        agg["peers"] |= e["peers"]
        agg["ports"] |= e["ports"]
        agg["procs"] += 1

    out = [{
        "proc": name,
        "procs": a["procs"],
        "peers": len(a["peers"]),
        "ports": sorted(a["ports"])[:4],
    } for name, a in by_name.items()]
    out.sort(key=lambda r: (r["peers"], r["proc"]), reverse=True)
    return out


def _port_label(ports) -> str:
    named = []
    for p in ports:
        named.append(_PORT_NAMES.get(p, str(p)))
    seen, uniq = set(), []
    for n in named:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    return ", ".join(uniq[:3])


def connections_report() -> str:
    """A spoken answer. String logic only -- no model, no lookups."""
    rows = outbound()
    if not rows:
        return ("Nothing on this machine currently holds an open connection "
                "to the internet — or I don't have the privileges to see "
                "them all.")

    total = sum(r["peers"] for r in rows)
    bits = [f"{len(rows)} program{'' if len(rows) == 1 else 's'} "
            f"{'is' if len(rows) == 1 else 'are'} connected out, "
            f"{total} address{'' if total == 1 else 'es'} in total"]
    for r in rows[:MAX_REPORTED]:
        procs = r.get("procs", 1)
        bits.append(f"{r['proc']}"
                    + (f" ({procs} processes)" if procs > 1 else "")
                    + f": {r['peers']} "
                    f"{'address' if r['peers'] == 1 else 'addresses'}"
                    + (f" over {_port_label(r['ports'])}" if r["ports"] else ""))
    if len(rows) > MAX_REPORTED:
        bits.append(f"and {len(rows) - MAX_REPORTED} more")
    return (". ".join(bits) + ". I'm not looking any of these up — that would "
            "tell someone else what you're connected to.")
