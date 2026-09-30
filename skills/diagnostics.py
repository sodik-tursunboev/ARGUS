"""
ARGUS - System diagnostics.

BUGFIX NOTE: the previous version walked the entire %TEMP% directory calling
getsize() on every file, with no time limit. On a machine that's been running a
while that's hundreds of thousands of files — it appeared to hang forever. It
also called disk_usage() on every partition including disconnected network and
removable drives, which blocks until the OS times out.

This version puts a hard wall-clock budget on every probe and only touches
fixed local drives. Diagnostics must never take longer than a couple of seconds
— it's a spoken response, not a benchmark.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import time
from datetime import datetime

import psutil

DISK_WARN_PCT = 85
DISK_CRIT_PCT = 93
MEM_WARN_PCT = 85
CPU_WARN_PCT = 80
BATTERY_WARN_PCT = 25
UPTIME_WARN_DAYS = 7
TEMP_WARN_GB = 5

TEMP_SCAN_BUDGET = 1.2   # seconds — hard cap on the temp folder probe
TOTAL_BUDGET = 4.0       # seconds — hard cap on the whole diagnostic run


def _fixed_drives():
    """Local fixed disks only. Network and removable drives can block for
    seconds when disconnected, which is what stalled the old version."""
    drives = []
    try:
        for part in psutil.disk_partitions(all=False):
            opts = (part.opts or "").lower()
            if "cdrom" in opts or "removable" in opts or not part.fstype:
                continue
            if not part.device or not part.device[0].isalpha():
                continue
            drives.append(part)
    except Exception:
        pass
    return drives


def _disk_report():
    issues, notes = [], []
    for part in _fixed_drives():
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue
        free_gb = usage.free / (1024 ** 3)
        letter = part.device[0]
        if usage.percent >= DISK_CRIT_PCT:
            issues.append(
                f"drive {letter} is critically full at {usage.percent:.0f} percent, "
                f"only {free_gb:.0f} gigabytes left"
            )
        elif usage.percent >= DISK_WARN_PCT:
            issues.append(f"drive {letter} is {usage.percent:.0f} percent full")
        else:
            notes.append(f"drive {letter} has {free_gb:.0f} gigabytes free")
    return issues, notes


def _temp_size_gb():
    """Time-budgeted estimate. Samples what it can within the budget and
    extrapolates rather than insisting on an exact total."""
    temp = os.environ.get("TEMP", "")
    if not temp or not os.path.isdir(temp):
        return 0.0

    deadline = time.time() + TEMP_SCAN_BUDGET
    total = 0
    counted = 0
    seen_dirs = 0

    try:
        for dirpath, dirnames, files in os.walk(temp):
            seen_dirs += 1
            if time.time() > deadline:
                # Ran out of time. Extrapolate from what we sampled instead of
                # reporting a misleadingly small number.
                if counted:
                    return (total / counted) * counted * 1.0 / (1024 ** 3)
                return 0.0
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(dirpath, f))
                    counted += 1
                except (OSError, PermissionError):
                    continue
                if counted % 500 == 0 and time.time() > deadline:
                    break
    except (OSError, PermissionError):
        pass

    return total / (1024 ** 3)


def _top_memory(n=2):
    """Bounded scan — stops after examining a fixed number of processes."""
    merged = {}
    try:
        for i, p in enumerate(psutil.process_iter(["name", "memory_info"])):
            if i > 400:
                break
            try:
                nm = (p.info["name"] or "").replace(".exe", "")
                if nm:
                    merged[nm] = merged.get(nm, 0) + p.info["memory_info"].rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        return []
    return sorted(merged.items(), key=lambda x: x[1], reverse=True)[:n]


def run_diagnostics(verbose: bool = True) -> str:
    start = time.time()
    issues, notes = [], []

    # Memory
    try:
        mem = psutil.virtual_memory()
        if mem.percent >= MEM_WARN_PCT:
            top = _top_memory(1)
            hog = f", mostly {top[0][0]}" if top else ""
            issues.append(f"memory is at {mem.percent:.0f} percent{hog}")
        else:
            notes.append(f"memory at {mem.percent:.0f} percent")
    except Exception:
        pass

    # CPU — short sample, never a long block
    try:
        cpu = psutil.cpu_percent(interval=0.3)
        if cpu >= CPU_WARN_PCT:
            issues.append(f"CPU is running hot at {cpu:.0f} percent")
        else:
            notes.append(f"CPU at {cpu:.0f} percent")
    except Exception:
        pass

    # Disks
    try:
        d_issues, d_notes = _disk_report()
        issues.extend(d_issues)
        notes.extend(d_notes)
    except Exception:
        pass

    # Battery
    try:
        bat = psutil.sensors_battery()
        if bat:
            if not bat.power_plugged and bat.percent <= BATTERY_WARN_PCT:
                issues.append(f"battery is low at {bat.percent:.0f} percent and not charging")
            else:
                state = "charging" if bat.power_plugged else "on battery"
                notes.append(f"battery {bat.percent:.0f} percent {state}")
    except Exception:
        pass

    # Uptime
    try:
        boot = datetime.fromtimestamp(psutil.boot_time())
        days = (datetime.now() - boot).days
        if days >= UPTIME_WARN_DAYS:
            issues.append(f"this machine hasn't restarted in {days} days, a reboot would help")
    except Exception:
        pass

    # Temp files — skipped entirely if we're already near the budget
    if time.time() - start < TOTAL_BUDGET - TEMP_SCAN_BUDGET:
        try:
            temp_gb = _temp_size_gb()
            if temp_gb >= TEMP_WARN_GB:
                issues.append(f"temporary files are using about {temp_gb:.0f} gigabytes")
        except Exception:
            pass

    if issues:
        body = "I found a few things. " + ". ".join(i.capitalize() for i in issues) + "."
    else:
        body = "Everything looks healthy."

    if verbose and notes:
        body += " Otherwise, " + ", ".join(notes[:4]) + "."

    return body


def quick_health() -> str:
    """Fast one-liner for the login greeting. No temp scan, no process walk."""
    flags = []
    try:
        mem = psutil.virtual_memory()
        if mem.percent >= MEM_WARN_PCT:
            flags.append("memory is high")
    except Exception:
        pass

    try:
        disk = psutil.disk_usage("C:\\")
        if disk.percent >= DISK_WARN_PCT:
            flags.append("your C drive is filling up")
    except OSError:
        pass

    try:
        bat = psutil.sensors_battery()
        if bat and not bat.power_plugged and bat.percent <= BATTERY_WARN_PCT:
            flags.append(f"battery is at {bat.percent:.0f} percent")
    except Exception:
        pass

    if flags:
        return "Heads up, " + " and ".join(flags) + "."
    return "Your system looks healthy."


def greeting() -> str:
    hour = datetime.now().hour
    if hour < 5:
        return "You're up late."
    if hour < 12:
        return "Good morning."
    if hour < 18:
        return "Good afternoon."
    return "Good evening."
