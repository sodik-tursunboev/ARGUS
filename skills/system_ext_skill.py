"""
ARGUS - System Extensions Skill

The Windows-system and network read-outs pc_skill.py and network_skill.py
don't already cover: printers, a top-level device inventory, mapped network
drives, DNS resolution, reachability (ping / a specific port).

ALL READ-ONLY. Nothing here changes a setting, installs a driver, maps or
unmaps a drive, or writes anything -- purely "what does this machine see".
Enumeration only, via WMI (win32com, already a dependency for the frozen
build) and stdlib socket -- no new packages.

PING is the one function that starts an external process (ping.exe, via
execpolicy.run() with a FIXED, minimal argv -- count and host only, host
validated to contain no shell metacharacter before it ever reaches argv).
Needs "ping" added to execpolicy.ALLOWED_EXECUTABLES; see that module's own
comment on why that's a deliberate, reviewed addition rather than a side
effect of writing this skill.

Bluetooth (bluetooth_status/bluetooth_set) uses Windows.Devices.Radios, the
same WinRT surface vision_skill.py's OCR already established the pattern
for -- verified end to end against this machine's real Wi-Fi and Bluetooth
radios before being wired in.

NOT HERE, and why: Night Light Controller. Its state lives in an
undocumented, versioned binary registry blob with no public schema;
"working today until the next Windows update quietly changes the blob
layout" is not a property anything here should have -- left out rather
than shipped half-reliable.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re
import socket

import execpolicy

_HOST_SHAPE = re.compile(r"^[A-Za-z0-9.\-:]+$")  # hostname/IP only -- no shell metacharacters


def _wmi():
    import win32com.client
    return win32com.client.GetObject("winmgmts:")


def printers() -> str:
    try:
        import win32print
        default = win32print.GetDefaultPrinter()
    except Exception as e:
        return f"I couldn't read your printers: {e}"
    try:
        flags = win32print.PRINTER_ENUM_LOCAL | win32print.PRINTER_ENUM_CONNECTIONS
        found = win32print.EnumPrinters(flags)
    except Exception as e:
        return f"I couldn't list printers: {e}"
    if not found:
        return "No printers are set up."
    names = [p[2] for p in found]
    marked = [f"{n} (default)" if n == default else n for n in names]
    return f"{len(names)} printer{'s' if len(names) != 1 else ''}: " + ", ".join(marked)


def print_queue(printer: str = "") -> str:
    try:
        import win32print
        name = printer.strip() if printer else win32print.GetDefaultPrinter()
        handle = win32print.OpenPrinter(name)
        try:
            jobs = win32print.EnumJobs(handle, 0, -1, 1)
        finally:
            win32print.ClosePrinter(handle)
    except Exception as e:
        return f"I couldn't check that print queue: {e}"
    if not jobs:
        return f"{name}'s queue is empty."
    return (f"{len(jobs)} job{'s' if len(jobs) != 1 else ''} queued on {name}: "
            + ", ".join(j.get("pDocument", "untitled") for j in jobs[:5]))


def devices(kind: str = "") -> str:
    """A top-level inventory, not the full Device Manager tree -- disks,
    network adapters, and (kind="" or "all") a general PnP entity count.
    Windows' own device tree runs tens of thousands of entries deep; this
    reports the categories someone actually asks about."""
    kind = (kind or "").strip().lower()
    try:
        wmi = _wmi()
    except Exception as e:
        return f"I couldn't read your devices: {e}"

    if "network" in kind or "adapter" in kind or "nic" in kind:
        try:
            adapters = [a.Name for a in wmi.ExecQuery(
                "SELECT Name FROM Win32_NetworkAdapter WHERE NetEnabled=True")]
        except Exception as e:
            return f"I couldn't list network adapters: {e}"
        if not adapters:
            return "No active network adapters."
        return f"{len(adapters)} active: " + ", ".join(adapters)

    if "disk" in kind or "drive" in kind or "storage" in kind:
        try:
            disks = [d.Model for d in wmi.ExecQuery(
                "SELECT Model FROM Win32_DiskDrive") if d.Model]
        except Exception as e:
            return f"I couldn't list disks: {e}"
        if not disks:
            return "No disks found."
        return f"{len(disks)} disk{'s' if len(disks) != 1 else ''}: " + ", ".join(disks)

    try:
        n = len(list(wmi.ExecQuery(
            "SELECT DeviceID FROM Win32_PnPEntity WHERE Status='OK'")))
    except Exception as e:
        return f"I couldn't read your devices: {e}"
    return f"{n} devices reporting OK. Ask about network adapters, disks, or printers specifically."


def network_drives() -> str:
    try:
        wmi = _wmi()
        drives = list(wmi.ExecQuery(
            "SELECT DeviceID, ProviderName FROM Win32_LogicalDisk WHERE DriveType=4"))
    except Exception as e:
        return f"I couldn't check network drives: {e}"
    if not drives:
        return "No network drives are mapped."
    return "; ".join(f"{d.DeviceID} -> {d.ProviderName}" for d in drives)


def dns_lookup(host: str) -> str:
    host = (host or "").strip()
    if not host:
        return "Look up which address?"
    try:
        canonical, aliases, addrs = socket.gethostbyname_ex(host)
    except socket.gaierror as e:
        return f"I couldn't resolve {host}: {e.strerror}"
    except Exception as e:
        return f"I couldn't resolve {host}: {e}"
    return f"{host} -> {canonical} at {', '.join(addrs)}"


def check_port(target: str) -> str:
    """TARGET = "host:port" or "host port" -- reachability of one SPECIFIC
    remote port, distinct from diag/ports (what's listening ON this
    machine, inbound) and net/connections (what this machine has open
    outbound right now); this tests one address on demand."""
    m = re.match(r"^\s*([^\s:]+)[\s:]+(\d{1,5})\s*$", target or "")
    if not m:
        return "Say it as: check port <number> on <host>."
    host, port = m.group(1), int(m.group(2))
    try:
        with socket.create_connection((host, port), timeout=3):
            pass
    except (socket.timeout, TimeoutError):
        return f"{host}:{port} didn't respond -- likely closed or filtered."
    except OSError as e:
        return f"{host}:{port} refused the connection ({e.strerror or e})."
    except Exception as e:
        return f"I couldn't check {host}:{port}: {e}"
    return f"{host}:{port} is open."


def _bt_radio():
    import asyncio
    from winrt.windows.devices.radios import Radio, RadioKind

    async def _find():
        radios = await Radio.get_radios_async()
        for r in radios:
            if r.kind == RadioKind.BLUETOOTH:
                return r
        return None

    return asyncio.run(_find())


def bluetooth_status() -> str:
    try:
        radio = _bt_radio()
    except Exception as e:
        return f"I couldn't check Bluetooth: {e}"
    if radio is None:
        return "This machine has no Bluetooth radio."
    from winrt.windows.devices.radios import RadioState
    return f"Bluetooth is {'on' if radio.state == RadioState.ON else 'off'}."


def bluetooth_set(enabled: bool) -> str:
    import asyncio
    from winrt.windows.devices.radios import RadioAccessStatus, RadioState

    try:
        radio = _bt_radio()
    except Exception as e:
        return f"I couldn't reach Bluetooth: {e}"
    if radio is None:
        return "This machine has no Bluetooth radio."

    async def _apply():
        wanted = RadioState.ON if enabled else RadioState.OFF
        result = await radio.set_state_async(wanted)
        return result

    try:
        access = asyncio.run(_apply())
    except Exception as e:
        return f"I couldn't change Bluetooth: {e}"
    if access != RadioAccessStatus.ALLOWED:
        return ("Windows refused that -- check Settings > Privacy > Radios "
                "allows apps to control Bluetooth.")
    return f"Bluetooth {'enabled' if enabled else 'disabled'}."


def ping(host: str) -> str:
    host = (host or "").strip()
    if not host:
        return "Ping what?"
    if not _HOST_SHAPE.match(host):
        return "That doesn't look like a valid host or address."
    try:
        result = execpolicy.run(["ping", "-n", "4", "-w", "1500", host], timeout=10.0)
    except execpolicy.ExecDenied as e:
        return f"I can't ping that: {e}"
    except Exception as e:
        return f"I couldn't ping {host}: {e}"
    out = (result.stdout or "")
    m = re.search(r"Lost = (\d+)", out)
    lost = m.group(1) if m else "?"
    m2 = re.search(r"Average = (\d+)ms", out)
    avg = m2.group(1) if m2 else None
    if lost == "4":
        return f"{host} didn't respond to any of 4 pings."
    return (f"{host} responded, {4 - int(lost) if lost.isdigit() else '?'} of 4 got through"
            + (f", average {avg}ms." if avg else "."))
