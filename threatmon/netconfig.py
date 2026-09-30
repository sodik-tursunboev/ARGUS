"""
ARGUS - Network Integrity: is your traffic still going where you think it is?

MITRE T1565.001 (Stored Data Manipulation -- the hosts file), T1557
(Adversary-in-the-Middle -- DNS redirection), T1090 (Proxy -- a proxy or PAC
file injected into your settings).

WHY THIS ONE MATTERS ON A PERSONAL MACHINE. Every commodity infostealer and
banking trojan does one of exactly three things to put itself between you and
the internet: it writes your hosts file, it changes your DNS servers, or it
points your proxy at a PAC file it controls. None of them need admin. All three
are invisible in normal use -- your browser shows the right domain and the right
padlock while the answer comes from somebody else's server. This detector
watches all three and tells you, in a sentence, when one of them changes.

FOUR SURFACES, FIXED AND DOCUMENTED. All readable non-elevated, all free
(the whole sweep measured under a millisecond):

  * hosts file      %SystemRoot%\\System32\\drivers\\etc\\hosts
  * DNS servers     per-interface NameServer (static) and DhcpNameServer
  * proxy           HKCU Internet Settings: ProxyEnable/ProxyServer/AutoConfigURL
  * WinHTTP proxy   HKLM WinHttpSettings (what `netsh winhttp` sets, machine-wide)

THE NOISE PROBLEM, HANDLED HONESTLY. A naive version of this alerts every time
you join a different Wi-Fi, because DhcpNameServer changes with the network --
and an alert that fires in every coffee shop gets ignored within a week. So the
two DNS sources are graded very differently:

  * a STATIC NameServer appearing or changing is HIGH. Malware sets DNS
    statically, because a static setting survives the next DHCP lease. On this
    machine the static value is currently empty, so anything appearing there is
    meaningful by definition.
  * DhcpNameServer changing is LOW and says so: "this is normal when you change
    network". It is still recorded, because on a hostile network it is exactly
    how a rogue DHCP server would reach you -- but it is never cried wolf over.

Likewise the hosts file distinguishes BLOCKING (an entry pointing at 127.0.0.1
or 0.0.0.0 -- what every ad-blocking hosts list does, thousands of times) from
REDIRECTION (an entry pointing at a real remote address -- which no ad-blocker
does and which sends your traffic somewhere). Only the second is high on its
own. A blocked domain is graded up only if it is a security or update domain,
because "silently stop Windows Update and Defender from reaching home" is a
real and specific attack, not an ad-blocker.

FLOOD GUARD. Importing an ad-blocking hosts list adds tens of thousands of
entries at once. Past _FLOOD_THRESHOLD changes in a single pass this reports ONE
finding describing the bulk change instead of burying everything else. Crossing
the threshold is itself reported, so nothing hides behind it.

WHAT IT CANNOT DO. It cannot tell you which process made the change -- that
needs kernel ETW, and it does not guess (pid is always 0). It has no threat
intelligence and makes no network call of its own: it reports that your DNS
server changed and to what, never whether that address is "known bad", because
looking that up would mean sending your machine's real network configuration to
somebody else. That is the exact thing this detector exists to notice.

CRASH DISCIPLINE. Each surface is collected independently. A surface that throws
is excluded from the diff for that pass rather than having everything it could
not read reported as deleted, and the baseline keeps its previous entries.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import threading
import time

import paths

try:
    import winreg
except Exception:
    winreg = None

# surface -> ATT&CK id. T1557 (Adversary-in-the-Middle) is the honest parent for
# a local DNS redirect: its published sub-techniques are LLMNR/NBT-NS, ARP and
# DHCP spoofing, none of which is "the resolver setting was rewritten", but the
# parent's meaning -- positioning yourself between the user and their traffic --
# is exactly right. Tagging the parent rather than forcing a sub-technique that
# does not fit is deliberate.
SURFACE_TECHNIQUE = {
    "hosts":   "T1565.001",
    "dns":     "T1557",
    "proxy":   "T1090",
    "winhttp": "T1090",
    # 1.4.1: the trust anchors themselves. A rogue root CA in the CURRENT USER
    # store enables the exact adversary-in-the-middle this module claims T1557
    # for, needs no admin to install, and was entirely unwatched -- the audit's
    # cheapest remaining network gap.
    "rootcerts": "T1553.004",
}
TECHNIQUE = "T1557"

# DNS/proxy changes matter quickly -- a PAC file planted now is used by the next
# banking login. The sweep is sub-millisecond, so a tight cadence is free.
SCAN_INTERVAL_S = 30
_FLOOD_THRESHOLD = 50

BASELINE_PATH_OVERRIDE = None
HOSTS_PATH_OVERRIDE = None
# Tests redirect these at scratch keys under HKCU. They must never be pointed at
# the live values: writing a real AutoConfigURL or a real static NameServer
# would genuinely reroute this machine's traffic, so the suite exercises the
# identical code path against a scratch hive instead and only ever READS the
# real settings.
IFACES_KEY_OVERRIDE = None
IFACES_HIVE_OVERRIDE = None
INET_KEY_OVERRIDE = None

_IFACES = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
_INET = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_CONNECTIONS = (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
                r"\Connections")
_PROXY_VALUES = ("ProxyEnable", "ProxyServer", "AutoConfigURL")
# 1.4.1: certificate trust anchors. Only the thumbprint SET is recorded -- a
# thumbprint is a public identifier and reveals nothing sensitive. Both the
# Current User hive (writable without admin: the actual attack) and Local
# Machine are watched, and both Root and Intermediate/CA buckets.
_CERT_STORES = (
    ("HKCU", r"Software\Microsoft\SystemCertificates\Root\Certificates"),
    ("HKCU", r"Software\Microsoft\SystemCertificates\CA\Certificates"),
    ("HKLM", r"Software\Microsoft\SystemCertificates\Root\Certificates"),
    ("HKLM", r"Software\Microsoft\SystemCertificates\CA\Certificates"),
)
# Tests point this at () to keep the cert collector out of a hosts-focused
# diff -- the same override discipline collect_winhttp uses, so a suite never
# mixes the real user's trust anchors into a synthetic baseline.
CERT_STORES_OVERRIDE = None

# Addresses that mean "send this nowhere" rather than "send this to me". An
# entry pointing here is blocking a domain, which is what ad-blocking hosts
# lists do by the thousand; an entry pointing anywhere else is redirection.
_BLACKHOLE = {"127.0.0.1", "0.0.0.0", "::1", "::", "localhost"}

# A short, fixed, documented list -- a SEVERITY HINT, never a detection rule.
# Blocking one of these is the specific, well-known move of stopping security
# software from updating or reporting; blocking anything else is probably an
# ad-blocker. Substring match on the lowercased hostname.
_SECURITY_DOMAINS = (
    "windowsupdate", "update.microsoft", "microsoftupdate", "defender",
    "msftncsi", "sophos", "mcafee", "symantec", "norton", "kaspersky",
    "avast", "avg.com", "bitdefender", "eset", "malwarebytes", "clamav",
    "virustotal", "trendmicro", "crowdstrike", "sentinelone",
)

_state = {
    "supported": winreg is not None,
    "running": False,
    "baseline_established": False,
    "entries": 0,
    "changes_total": 0,
    "desyncs": 0,
    "scans": 0,
    "failed_surfaces": [],
    "hosts_writable": None,
    "last_error": "",
    "attribution": "no process attribution (needs kernel ETW); no threat "
                   "intelligence lookups -- reporting your DNS to a reputation "
                   "service would leak the very thing this watches",
}
_lock = threading.RLock()


# ── helpers ──────────────────────────────────────────────────────────────────
def _hosts_path():
    if HOSTS_PATH_OVERRIDE:
        return HOSTS_PATH_OVERRIDE
    return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                        "System32", "drivers", "etc", "hosts")


def parse_hosts(text: str) -> dict:
    """{hostname: ip} from hosts-file text. Pure -- unit-testable on a string.

    Comments (whole-line and trailing) are stripped, one entry per hostname
    because a hostname's ADDRESS changing is the signal; several hostnames on
    one line are separate entries, which is how the file actually behaves.
    """
    out = {}
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        for host in parts[1:]:
            h = host.strip().lower()
            if h:
                out[h] = ip
    return out


def is_blackhole(ip: str) -> bool:
    return (ip or "").strip().lower() in _BLACKHOLE


def is_security_domain(host: str) -> bool:
    h = (host or "").lower()
    return any(d in h for d in _SECURITY_DOMAINS)


def classify_hosts_entry(host: str, ip: str) -> tuple:
    """(severity, reasons) for a hosts entry that just appeared. Pure."""
    if is_blackhole(ip):
        if is_security_domain(host):
            return "high", [f"blocks a security/update domain ({host}) — this is "
                            f"how malware stops antivirus and Windows Update"]
        return "medium", [f"blocks {host} (this is also what ad-blocking hosts "
                          f"lists do, so it may be intentional)"]
    return "high", [f"redirects {host} to {ip} — traffic for that name now goes "
                    f"to that address instead of the real one"]


# ── collectors ───────────────────────────────────────────────────────────────
def collect_hosts() -> dict:
    path = _hosts_path()
    try:
        _state["hosts_writable"] = os.access(path, os.W_OK)
    except Exception:
        _state["hosts_writable"] = None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    return {f"hosts:{h}": {"value": ip, "item": h, "where": path}
            for h, ip in parse_hosts(text).items()}


def collect_dns() -> dict:
    out = {}
    key = IFACES_KEY_OVERRIDE or _IFACES
    hive = IFACES_HIVE_OVERRIDE or winreg.HKEY_LOCAL_MACHINE
    with winreg.OpenKey(hive, key) as root:
        for i in range(winreg.QueryInfoKey(root)[0]):
            try:
                guid = winreg.EnumKey(root, i)
            except OSError:
                continue
            try:
                with winreg.OpenKey(root, guid) as ik:
                    for val, kind in (("NameServer", "static"),
                                      ("DhcpNameServer", "dhcp")):
                        try:
                            v = str(winreg.QueryValueEx(ik, val)[0] or "").strip()
                        except FileNotFoundError:
                            continue
                        if not v:
                            continue
                        out[f"dns:{guid}:{kind}"] = {
                            "value": v, "item": f"{kind} DNS",
                            "where": f"interface {guid[:10]}…", "kind": kind}
            except OSError:
                continue
    return out


def collect_proxy() -> dict:
    out = {}
    key = INET_KEY_OVERRIDE or _INET
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
        for val in _PROXY_VALUES:
            try:
                v = winreg.QueryValueEx(k, val)[0]
            except FileNotFoundError:
                continue
            # ProxyEnable=0 with no server is the default "off" state; recording
            # it would make turning the proxy ON look like a mere value change
            # rather than something appearing. Skip the inert default.
            if val == "ProxyEnable" and not int(v or 0):
                continue
            if v in (None, ""):
                continue
            out[f"proxy:{val}"] = {"value": str(v), "item": val,
                                   "where": "Internet Settings"}
    return out


def collect_winhttp() -> dict:
    """The machine-wide WinHTTP proxy blob (`netsh winhttp set proxy`).

    The 20-byte value is the "direct access, no proxy" default; anything longer
    carries a proxy string. Recorded as a length+hex summary rather than parsed,
    because a change of ANY kind here is the thing worth reporting and a partial
    parser would be a way to miss one.
    """
    out = {}
    if IFACES_KEY_OVERRIDE or INET_KEY_OVERRIDE:
        return out                       # tests drive the other surfaces
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _CONNECTIONS) as k:
            v = winreg.QueryValueEx(k, "WinHttpSettings")[0]
    except FileNotFoundError:
        return out
    blob = bytes(v or b"")
    printable = "".join(chr(b) for b in blob if 32 <= b < 127)
    out["winhttp:WinHttpSettings"] = {
        "value": f"{len(blob)}B/{blob.hex()[:64]}",
        "item": "WinHTTP proxy",
        "where": "HKLM Internet Settings\\Connections",
        "proxy_text": printable,
    }
    return out


def collect_certs() -> dict:
    """Certificate trust anchors as {store:thumbprint} entries (T1553.004).

    The audit's gap: a rogue root CA under HKCU SystemCertificates\\Root makes
    every HTTPS interception silent -- Windows will happily trust it for THIS
    user and no admin prompt ever appears. Enumerating subkey names (the
    thumbprints) and diffing the SET catches an installed anchor regardless of
    what it claims to be; nothing about a certificate's content is read, so
    the collector leaks nothing and costs one key walk.
    """
    out = {}
    stores = CERT_STORES_OVERRIDE if CERT_STORES_OVERRIDE is not None else _CERT_STORES
    for hive_name, sub in stores:
        hive = winreg.HKEY_CURRENT_USER if hive_name == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        try:
            with winreg.OpenKey(hive, sub, 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as root:
                n = winreg.QueryInfoKey(root)[0]
                for i in range(n):
                    try:
                        thumb = winreg.EnumKey(root, i)
                    except OSError:
                        continue
                    if not thumb:
                        continue
                    out[f"rootcerts:{hive_name}:{thumb}"] = {
                        "value": thumb, "item": thumb,
                        "where": f"{hive_name}\\{sub}",
                        "kind": "root" if sub.rstrip("\\").endswith("Root") else "ca",
                    }
        except (FileNotFoundError, OSError):
            continue
    return out


COLLECTORS = {
    "hosts":   collect_hosts,
    "dns":     collect_dns,
    "proxy":   collect_proxy,
    "winhttp": collect_winhttp,
    "rootcerts": collect_certs,
}


def collect_all() -> tuple:
    entries, ok, failed = {}, set(), {}
    for surface, fn in COLLECTORS.items():
        try:
            entries.update(fn() or {})
            ok.add(surface)
        except Exception as e:
            failed[surface] = f"{type(e).__name__}: {e}"[:120]
    return entries, ok, failed


# ── diff / severity ──────────────────────────────────────────────────────────
def surface_of(entry_id: str) -> str:
    return entry_id.split(":", 1)[0]


def diff(old: dict, new: dict, ok_surfaces: set) -> list:
    """Changes between two snapshots, restricted to surfaces that scanned OK.
    Pure and total -- the correctness of this detector lives here."""
    changes = []
    for eid, cur in new.items():
        surf = surface_of(eid)
        if surf not in ok_surfaces:
            continue
        prev = old.get(eid)
        if prev is None:
            changes.append({"change": "added", "id": eid, "surface": surf,
                            "value": cur.get("value", ""), "prev": "",
                            "item": cur.get("item", ""), "where": cur.get("where", ""),
                            "kind": cur.get("kind", "")})
        elif prev.get("value", "") != cur.get("value", ""):
            changes.append({"change": "modified", "id": eid, "surface": surf,
                            "value": cur.get("value", ""), "prev": prev.get("value", ""),
                            "item": cur.get("item", ""), "where": cur.get("where", ""),
                            "kind": cur.get("kind", "")})
    for eid, prev in old.items():
        surf = surface_of(eid)
        if surf not in ok_surfaces or surf not in COLLECTORS:
            continue
        if eid not in new:
            changes.append({"change": "removed", "id": eid, "surface": surf,
                            "value": "", "prev": prev.get("value", ""),
                            "item": prev.get("item", ""), "where": prev.get("where", ""),
                            "kind": prev.get("kind", "")})
    return changes


def severity_of(change: dict) -> tuple:
    """(severity, reasons) for one change. Pure -- no I/O, no clock."""
    surf, kind, cur = change["surface"], change.get("change"), change.get("value", "")
    item = change.get("item", "")

    if surf == "hosts":
        host = change["id"].split(":", 1)[1]
        if kind == "removed":
            return "low", [f"hosts entry for {host} was removed"]
        sev, reasons = classify_hosts_entry(host, cur)
        if kind == "modified":
            reasons.insert(0, f"an existing hosts entry was repointed "
                              f"({change.get('prev', '')} → {cur})")
            sev = "high"
        return sev, reasons

    if surf == "dns":
        if change.get("kind") == "dhcp":
            # Changes with every network you join. Recorded, never alarmed.
            return "low", ["DNS served by DHCP changed — normal when you join a "
                           "different network, but worth knowing if you did not"]
        if kind == "removed":
            return "medium", ["a statically-set DNS server was removed"]
        return "high", [f"a STATIC DNS server is set to {cur} — malware sets DNS "
                        f"statically so it survives the next DHCP lease"]

    if surf == "proxy":
        if kind == "removed":
            return "low", [f"{item} was cleared"]
        if item == "AutoConfigURL":
            return "high", [f"a proxy auto-config (PAC) URL was set to {cur} — "
                            f"almost nothing legitimate sets this on a personal "
                            f"machine, and it can silently reroute chosen sites"]
        if item == "ProxyEnable":
            return "high", ["a proxy was switched ON for your account"]
        return "high", [f"your proxy server was set to {cur} — browser traffic "
                        f"now goes through it"]

    if surf == "winhttp":
        if kind == "removed":
            return "low", ["the machine-wide WinHTTP proxy setting was cleared"]
        return "high", ["the machine-wide WinHTTP proxy setting changed "
                        "(what `netsh winhttp set proxy` writes)"]

    if surf == "rootcerts":
        thumb = (item or "")[:16]
        bucket = "root" if change.get("kind") == "root" else "certificate-authority"
        if kind == "removed":
            return "low", [f"a {bucket} certificate anchor was removed -- often a "
                           f"normal cleanup, but so is uninstalling antivirus"]
        store = change.get("id", "").split(":")[1] if ":" in change.get("id", "") else "HKCU"
        if store == "HKCU" and change.get("kind") == "root":
            return "high", [f"a NEW ROOT certificate ({thumb}…) was added for YOUR "
                            f"user only, without admin -- this is exactly how "
                            f"HTTPS interception is made invisible"]
        return "high", [f"a new {bucket} certificate anchor ({thumb}…) appeared in "
                        f"{store} -- every HTTPS connection now trusts whoever "
                        f"holds its private key"]

    return "medium", ["network configuration changed"]


def correlate(window_s: int = 120) -> list:
    """Other detections from this suite in the last window_s seconds. Late
    import to avoid the package cycle; never raises."""
    try:
        import threatmon
        now, out = time.time(), []
        for r in threatmon.recent(20):
            if r.get("detector") == "netconfig":
                continue
            try:
                ts = time.mktime(time.strptime(r.get("ts", ""), "%Y-%m-%dT%H:%M:%S"))
            except Exception:
                continue
            if 0 <= now - ts <= window_s:
                out.append(f"{r.get('detector')}: {r.get('name', '?')} "
                           f"[{r.get('technique', '')}]")
        return out[:3]
    except Exception:
        return []


# ── baseline ─────────────────────────────────────────────────────────────────
def _baseline_path():
    return BASELINE_PATH_OVERRIDE or paths.writable("netconfig_baseline.json")


def report() -> str:
    """A spoken answer to "is anything redirecting my traffic?".

    String logic only -- no model, no network. This module's own status line
    already says why: reporting your DNS to a reputation service would leak
    the very thing it exists to watch. Phrasing it through a hosted model
    would leak it just as thoroughly.
    """
    s = status()
    if s.get("last_error"):
        return (f"I couldn't finish checking your network settings "
                f"({s['last_error']}).")
    if not s.get("baseline_established"):
        return ("I haven't finished my first network-settings scan yet, so I "
                "have nothing to compare against. Ask me again in a minute.")

    found = s.get("findings_total", 0)
    surfaces = s.get("surfaces", 0)
    bits = [f"I'm watching {surfaces} places traffic can be redirected — "
            f"your hosts file, DNS servers, system proxy, WinHTTP proxy, and "
            f"the certificate authorities your machine trusts"]

    failed = s.get("surfaces_failed") or []
    if failed:
        bits.append(f"I couldn't read {', '.join(str(f) for f in failed)}")

    if s.get("hosts_writable"):
        # Not a finding, but worth saying: a hosts file writable without
        # elevation is the cheapest redirection an attacker can buy.
        bits.append("your hosts file is writable without admin rights, which "
                    "is worth tightening")

    if not found:
        bits.append("nothing has changed since I took the baseline")
    else:
        recent = correlate(window_s=3600) or []
        bits.append(f"{found} change{'s' if found != 1 else ''} since then"
                    + (f", {len(recent)} in the last hour" if recent else ""))
    return ". ".join(bits) + "."


def load_baseline():
    """The stored baseline, or None when there is no usable one.

    None and {} are DIFFERENT and the distinction is load-bearing. A clean
    machine legitimately has an EMPTY baseline: no hosts entries, no static DNS,
    no proxy -- which is exactly this machine's state. If "empty" were treated as
    "not established", every pass would re-baseline and the FIRST hostile change
    would be silently absorbed instead of reported. That is the normal case, not
    an edge case, so the sentinel is None and only None means "establish".
    """
    try:
        with open(_baseline_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return None
        entries = data.get("entries")
        return entries if isinstance(entries, dict) else None
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


# ── emit ─────────────────────────────────────────────────────────────────────
def _emit(record, change):
    sev, reasons = severity_of(change)
    surf = change["surface"]
    finding = {
        "technique": SURFACE_TECHNIQUE.get(surf, TECHNIQUE),
        "detector": "netconfig",
        "severity": sev,
        "target": (change.get("item") or change["id"])[:120],
        "name": change.get("item") or surf,
        "pid": 0,                       # not knowable in user mode -- never guessed
        "path": "",
        "action": change["change"],
        "surface": surf,
        "where": change.get("where", ""),
        "command": (f"{change['change']}: {change.get('item', '')} "
                    f"= {change.get('value') or '(cleared)'}")[:300],
        "previous": (change.get("prev") or "")[:300],
        "reasons": reasons,
        "correlated": correlate() if change["change"] != "removed" else [],
        "reason": f"netconfig_{change['change']}_{surf}",
        "dedup": f"netconfig|{change['change']}|{change['id']}",
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


def _emit_bulk(record, changes):
    """One finding for an implausible flood -- an ad-blocking hosts import is
    thousands of entries and must not bury a real redirect."""
    kinds, surfaces = {}, {}
    for c in changes:
        kinds[c["change"]] = kinds.get(c["change"], 0) + 1
        surfaces[c["surface"]] = surfaces.get(c["surface"], 0) + 1
    # A redirect hiding inside a bulk blocking import is the one case worth
    # naming individually, so it is counted and called out rather than lost.
    redirects = [c for c in changes
                 if c["surface"] == "hosts" and c["change"] != "removed"
                 and not is_blackhole(c.get("value", ""))]
    reasons = [f"{len(changes)} network-config changes in one pass exceeds the "
               f"{_FLOOD_THRESHOLD}-change plausibility limit",
               "typically an ad-blocking hosts list being imported or removed",
               "individual changes suppressed; baseline re-anchored"]
    if redirects:
        reasons.insert(0, f"{len(redirects)} of them REDIRECT to a real address "
                          f"rather than blocking — e.g. "
                          f"{redirects[0]['id'].split(':', 1)[1]} → "
                          f"{redirects[0].get('value')}")
    finding = {
        "technique": SURFACE_TECHNIQUE.get("hosts", TECHNIQUE),
        "detector": "netconfig",
        "severity": "high" if redirects else "medium",
        "target": "network configuration",
        "name": "bulk change",
        "pid": 0, "path": "",
        "action": "bulk",
        "surface": "all",
        "where": "netconfig baseline",
        "command": (f"{len(changes)} changes ("
                    + ", ".join(f"{v} {k}" for k, v in sorted(kinds.items()))
                    + "; " + ", ".join(f"{k}={v}" for k, v in sorted(surfaces.items()))
                    + ")"),
        "previous": "",
        "reasons": reasons,
        "correlated": correlate(),
        "reason": "netconfig_bulk_change",
        "dedup": "netconfig|bulk",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    with _lock:
        _state["changes_total"] += 1
        _state["desyncs"] += 1
    try:
        if record:
            record(finding)
    except Exception as e:
        _state["last_error"] = f"emit bulk: {type(e).__name__}"
    return finding


# ── scan ─────────────────────────────────────────────────────────────────────
def run_checks(record) -> list:
    entries, ok, failed = collect_all()
    with _lock:
        _state["scans"] += 1
        _state["entries"] = len(entries)
        _state["failed_surfaces"] = sorted(failed)
        if failed:
            _state["last_error"] = "; ".join(f"{k}: {v}" for k, v in failed.items())[:160]

    old = load_baseline()
    if old is None:                      # NOT `not old` -- see load_baseline()
        save_baseline(entries)
        with _lock:
            _state["baseline_established"] = True
        return []

    with _lock:
        _state["baseline_established"] = True
    changes = diff(old, entries, ok)
    emitted = []
    if len(changes) > _FLOOD_THRESHOLD:
        emitted.append(_emit_bulk(record, changes))
    else:
        for change in changes:
            try:
                emitted.append(_emit(record, change))
            except Exception as e:
                _state["last_error"] = f"emit {change.get('id', '?')}: {type(e).__name__}"

    # Merge, never replace: a surface that FAILED this pass must keep its
    # baseline entries or the next good pass reports them all as new.
    merged = dict(old)
    for eid in [e for e in old if surface_of(e) in ok]:
        merged.pop(eid, None)
    merged.update(entries)
    save_baseline(merged)
    return emitted


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
    if not _state["supported"]:
        _state["last_error"] = "winreg unavailable"
        return
    t = threading.Thread(target=_watch_loop, args=(record,), daemon=True,
                         name="argus-netconfig-watch")
    t.start()


def status() -> dict:
    with _lock:
        failed = list(_state["failed_surfaces"])
        degraded = ""
        if not _state["supported"]:
            degraded = "unsupported OS (winreg unavailable)"
        elif failed:
            degraded = (f"{len(failed)} of {len(COLLECTORS)} surfaces unreadable: "
                        f"{', '.join(failed)}")
        elif not _state["baseline_established"]:
            degraded = "baseline not yet established (first scan pending)"
        return {
            "detector": "netconfig",
            "technique": TECHNIQUE,
            "techniques": sorted(set(SURFACE_TECHNIQUE.values())),
            "ok": _state["running"] and _state["supported"] and len(failed) < len(COLLECTORS),
            "degraded": degraded,
            "surfaces": len(COLLECTORS),
            "surfaces_failed": failed,
            "entries": _state["entries"],
            "baseline_established": _state["baseline_established"],
            "scans": _state["scans"],
            "desyncs": _state["desyncs"],
            "findings_total": _state["changes_total"],
            "hosts_writable": _state["hosts_writable"],
            "attribution": _state["attribution"],
            "last_error": _state["last_error"],
        }
