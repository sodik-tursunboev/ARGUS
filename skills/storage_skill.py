"""
ARGUS - Disk space, per drive, and what is taking it up.

WHY THIS IS NOT PART OF pc_skill.system_stats().

system_stats() answers "how is the machine doing" with one combined sentence,
and its disk figure is hardcoded to C:\\. That is the wrong answer to three
questions people actually ask:

    "how much space is left on D"      -- a drive it never looks at
    "how much space have I got"        -- buried in a wall of CPU and memory
    "what is taking up all my space"   -- not answerable at all

So this is a separate skill with focused answers rather than another branch in
a stats dump. It is READ-ONLY by design: it reports sizes and never deletes
anything. Reclaiming space is a destructive action and belongs behind the
staged-confirmation path in power_skill, not behind a question about numbers.

SPOKEN OUTPUT. Every reply here is read aloud, so sizes are rounded to
something sayable -- "forty-two gigabytes free" rather than "42.37 GB". The
exact figure helps nobody hearing it.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import time

import psutil

# Drives that are not really drives. disk_partitions(all=False) already filters
# most of this on Windows, but a disconnected network drive or an empty optical
# bay still shows up and then blocks for seconds inside disk_usage(). This
# module previously did not exist, but diagnostics.py hit exactly that and its
# comment records it, so the same guard is applied here rather than rediscovered.
_SKIP_OPTS = ("cdrom", "removable")

LOW_SPACE_PCT = 90          # at or above this, say so unprompted
_DEPTH_LIMIT = 6            # folders deep, when measuring a directory
_WALK_BUDGET = 6.0          # seconds; a full walk of a big tree is unbounded


def _human(num_bytes: float) -> str:
    """A size a person can hear. Not a precise one."""
    gb = num_bytes / (1024 ** 3)
    if gb >= 1024:
        return f"{gb / 1024:.1f} terabytes"
    if gb >= 10:
        return f"{gb:.0f} gigabytes"
    if gb >= 1:
        return f"{gb:.1f} gigabytes"
    mb = num_bytes / (1024 ** 2)
    if mb >= 1:
        return f"{mb:.0f} megabytes"
    return f"{num_bytes / 1024:.0f} kilobytes"


def _drives() -> list:
    """(letter, usage) for every fixed drive that answers promptly."""
    out = []
    for part in psutil.disk_partitions(all=False):
        opts = (part.opts or "").lower()
        if any(s in opts for s in _SKIP_OPTS):
            continue
        try:
            out.append((part.mountpoint, psutil.disk_usage(part.mountpoint)))
        except (PermissionError, OSError):
            # An unreadable or disconnected mount. Skipping it is right --
            # failing the whole answer because one drive is offline would
            # make the common case depend on the rare one.
            continue
    return out


import re

# A drive letter has to be NAMED, not merely present as a stray single letter.
# The first version collected every standalone letter in the phrase, so "how
# much space is left on d" and "how much space is left" both produced a match
# for C: -- the "c" never appeared, but the fallback reported C: anyway and the
# question about D got a confident answer about the wrong disk.
_LETTER_RE = re.compile(
    r"\b(?:on|in|for)\s+(?:the\s+|my\s+)?([a-z])\b(?!\w)"   # "on d"
    r"|\b([a-z])\s*:"                                        # "d:"
    r"|\b([a-z])\s+drive\b"                                  # "d drive"
    r"|\bdrive\s+([a-z])\b",                                 # "drive d"
    re.I)


def _named_letter(target: str) -> str:
    """The drive letter the phrase explicitly names, or "" if none."""
    m = _LETTER_RE.search(target or "")
    if not m:
        return ""
    return next((g for g in m.groups() if g), "").lower()


def _match_drive(target: str):
    """The mountpoint a phrase names, or None if it names none or an unknown one."""
    letter = _named_letter(target)
    if not letter:
        return None
    for mount, _ in _drives():
        if mount[0].lower() == letter:
            return mount
    return None


def free_space(target: str = "") -> str:
    """How much room is left -- on one drive, or on all of them."""
    drives = _drives()
    if not drives:
        return "I couldn't read any drives on this machine."

    wanted = _match_drive(target)
    named = _named_letter(target)
    if wanted:
        drives = [(m, u) for m, u in drives if m == wanted]
    elif named:
        # A drive WAS named and it does not exist. Say so, rather than falling
        # back to reporting C: -- answering a question about D with C's figures,
        # confidently and without mentioning the substitution, is worse than
        # admitting the drive is unknown.
        have = ", ".join(m.rstrip(chr(92)) for m, _ in drives)
        return (f"I don't see a {named.upper()} drive on this machine. "
                f"There's {have}.")

    if len(drives) == 1:
        mount, u = drives[0]
        line = (f"{mount.rstrip(chr(92))} has {_human(u.free)} free "
                f"out of {_human(u.total)}")
        if u.percent >= LOW_SPACE_PCT:
            line += f", which is {u.percent:.0f} percent full"
        return line + "."

    parts = [f"{m.rstrip(chr(92))} {_human(u.free)} free" for m, u in drives]
    reply = "Drive space: " + ", ".join(parts) + "."
    tight = [m.rstrip(chr(92)) for m, u in drives if u.percent >= LOW_SPACE_PCT]
    if tight:
        reply += f" {', '.join(tight)} is getting full."
    return reply


def _dir_size(path: str, deadline: float) -> tuple[int, bool]:
    """Bytes under path. Returns (size, complete).

    Time-bounded on purpose. Walking a home directory can touch hundreds of
    thousands of files, and an assistant that goes silent for two minutes
    because it was asked a casual question has failed regardless of how
    accurate the eventual number is. A partial figure, LABELLED as partial,
    is the better answer.
    """
    total, complete = 0, True
    for root, dirs, files in os.walk(path, onerror=lambda e: None):
        if time.monotonic() > deadline:
            return total, False
        depth = root[len(path):].count(os.sep)
        if depth >= _DEPTH_LIMIT:
            dirs[:] = []
        for fn in files:
            try:
                # lstat, not stat: a symlink or junction pointing back up the
                # tree would otherwise be followed and counted repeatedly,
                # and on Windows the AppData junctions do exactly that.
                total += os.lstat(os.path.join(root, fn)).st_size
            except OSError:
                continue
    return total, complete


# ── where largest() is allowed to look ──────────────────────────────────
# ARGUS-SEC-001. largest() took a path straight from the request and listed
# it. Confirmed reachable through router._dispatch with an arbitrary target,
# which is the "untrusted content -> LLM -> tool -> privileged operation"
# path the threat model treats as hostile. All of these worked:
#
#     C:\\Users                             every account on the machine
#     C:\\Windows\\System32                   OS layout
#     %LOCALAPPDATA%\\ARGUS                  the folder holding secrets.dat
#     \\\\localhost\\C$\\Users                  admin-share traversal
#     ..\\..\\..\\Windows                      relative escape
#
# It reveals filenames, sizes and the existence of credential stores -- the
# reconnaissance step before a targeted read. The question this skill exists
# to answer is "what is filling up MY folders", so the answer is confinement
# to the user's own profile, checked after resolution rather than by
# inspecting the string for "..".
HOME = os.path.realpath(os.path.expanduser("~"))


def _confine(target: str):
    """Resolve a requested folder, or return (None, reason).

    realpath() FIRST, then containment. Checking the raw string for ".." or a
    leading "\\\\" is the classic mistake: it misses symlinks, junctions, 8.3
    short names, and "C:\\Users\\example\\..\\..\\Windows". Resolving first means
    whatever the string was, the decision is made about the real location.
    """
    raw = (target or "").strip().strip('"').strip("'")
    if not raw:
        return HOME, ""

    expanded = os.path.expandvars(os.path.expanduser(raw))
    # A UNC path can name this machine's own admin share (\\localhost\C$) and
    # so re-enter the filesystem from outside the confinement check, as well
    # as reaching other hosts entirely.
    if expanded.startswith("\\\\") or expanded.startswith("//"):
        return None, "network paths are not searched"

    if not os.path.isabs(expanded):
        expanded = os.path.join(HOME, expanded)
    try:
        real = os.path.realpath(expanded)
    except OSError:
        return None, "that path could not be resolved"

    if os.path.commonpath([real, HOME]) != HOME:
        return None, "I only look inside your own folders"

    # ARGUS's own state lives under the home directory too, and it holds the
    # DPAPI secret store, the integrity manifest and the audit log. Listing it
    # is reconnaissance against ARGUS itself.
    try:
        import integrity
        if integrity.is_protected(real):
            return None, "that folder belongs to ARGUS itself"
    except Exception:
        pass
    return real, ""


def largest(target: str = "") -> str:
    """What is using the space in a folder. Read-only, never deletes.

    Confined to the user's own profile -- see _confine().
    """
    path, refusal = _confine(target)
    if path is None:
        return f"I can't look there — {refusal}."
    if not os.path.isdir(path):
        return f"I couldn't find a folder at {path}."

    deadline = time.monotonic() + _WALK_BUDGET
    entries, complete = [], True
    try:
        with os.scandir(path) as it:
            children = list(it)
    except OSError as e:
        return f"I couldn't read that folder ({e.__class__.__name__})."

    for entry in children:
        if time.monotonic() > deadline:
            complete = False
            break
        try:
            if entry.is_dir(follow_symlinks=False):
                size, done = _dir_size(entry.path, deadline)
                complete = complete and done
            elif entry.is_file(follow_symlinks=False):
                size = entry.stat(follow_symlinks=False).st_size
            else:
                continue
        except OSError:
            continue
        entries.append((size, entry.name))

    if not entries:
        return f"There's nothing measurable in {path}."

    entries.sort(reverse=True)
    top = [f"{name} at {_human(size)}" for size, name in entries[:3] if size]
    if not top:
        return f"Everything in {path} is too small to be worth reporting."

    reply = f"In {os.path.basename(path) or path}, the largest are " \
            + ", ".join(top) + "."
    if not complete:
        reply += " That's a partial scan — the folder was too large to finish."
    return reply


def analyze(target: str = "", limit: int = 6) -> str:
    """Break a folder down into what is filling it, largest subfolders first,
    with loose files summed separately. Read-only and time-bounded: the same
    _confine() gate, the same _dir_size() deadline walk, and an incomplete
    scan is LABELLED partial rather than silently trusted -- an answer that is
    right about part of the folder beats one that is silently wrong about all
    of it. The missing twin of largest(): largest answers "the biggest single
    thing", this answers "is one folder eating everything"."""
    path, refusal = _confine(target)
    if path is None:
        return f"I can't look there — {refusal}."
    if not os.path.isdir(path):
        return f"I couldn't find a folder at {path}."

    deadline = time.monotonic() + _WALK_BUDGET
    folders, loose, complete = [], 0, True
    try:
        with os.scandir(path) as it:
            children = list(it)
    except OSError as e:
        return f"I couldn't read that folder ({e.__class__.__name__})."

    for entry in children:
        if time.monotonic() > deadline:
            complete = False
            break
        try:
            if entry.is_dir(follow_symlinks=False):
                size, done = _dir_size(entry.path, deadline)
                complete = complete and done
                folders.append((size, entry.name))
            elif entry.is_file(follow_symlinks=False):
                # A file listed here is a loose file in this folder -- its size
                # counts separately because "which subfolder is eating my disk"
                # is a different question from "is this one big download".
                loose += entry.stat(follow_symlinks=False).st_size
        except OSError:
            continue

    if not folders and not loose:
        return f"There's nothing measurable in {path}."

    total = loose + sum(size for size, _ in folders)
    folders.sort(reverse=True)
    shown = [f"{name} at {_human(size)}" for size, name in folders[:limit] if size]
    if not shown and not loose:
        return f"Everything in {path} is too small to be worth reporting."

    reply = f"In {os.path.basename(path) or path}, {_human(total)} in total."
    if shown:
        reply += " The biggest are " + ", ".join(shown) + "."
    if loose:
        reply += f" Another {_human(loose)} sits in loose files."
    if not complete:
        reply += " That's a partial scan — the folder was too large to finish."
    return reply


def describe() -> str:
    return ("Reports free space per drive, what is using space in a folder, "
            "and what is filling a folder. Read-only.")
