"""
ARGUS - Clipboard-hijack detection (MITRE T1565.002 / T1115).

Crypto clipboard "clippers" sit in the background and silently rewrite a copied
wallet address to the attacker's, so the victim pastes -- and pays -- the wrong
one. This looks for that: a wallet-address-shaped string in the clipboard
turning into a DIFFERENT one.

DELIBERATELY ON THE EXISTING READ PATH. The spec is explicit: reuse the already-
hardened clipboard read (control_skill.clipboard_read), do NOT stand up a new,
continuously-polling clipboard access point -- that would be its own privacy
liability and would undo the redaction hardening. So detection is TRIGGERED by a
read the user already asked for, not by a background monitor. Two signals:

  * LIVE SWAP (high): within a single observation we read once more after a short
    beat and no user action; if the address mutated in that window, something is
    actively rewriting the clipboard -- a clipper caught in the act.
  * CHANGED-SINCE-LAST (medium): the wallet address differs from the one seen on
    the previous read. This is the spec's literal ask, and its honest limit: a
    read-on-demand assistant cannot see a swap that happens entirely between two
    reads, and a legitimate re-copy also changes the address. Reported at medium
    confidence for that reason; status() states the limitation plainly.

Addresses are MASKED (head…tail) everywhere they are recorded -- the point is to
flag the swap, not to copy the value around.

CRASH DISCIPLINE. Reuses the same mechanism the read path already uses; every
step is guarded, and a detector failure returns nothing rather than breaking the
user's clipboard read.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re
import time

TECHNIQUE = "T1565.002"
REREAD_DELAY_S = 0.12          # the beat between the two live reads (tests set 0)

# A small, precise set of common formats clippers target. Not an ever-growing
# list -- these cover the chains clipboard swappers actually go after.
WALLET_PATTERNS = [
    ("ETH", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("BTC", re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")),
    ("BTC-bech32", re.compile(r"\bbc1[a-z0-9]{25,62}\b")),
    ("TRON", re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")),
]

_last = {}                     # type -> last-seen address
_state = {
    "supported": True,
    "reads": 0,
    "findings_total": 0,
    "last_error": "",
    "coverage": "on-demand reads only (a swap entirely between two reads is not visible)",
}


def extract_wallets(text: str) -> dict:
    """{type -> first address of that type} found in text. Pure, tolerant."""
    out = {}
    s = text or ""
    for name, rx in WALLET_PATTERNS:
        try:
            m = rx.search(s)
            if m:
                out[name] = m.group(0)
        except Exception:
            continue
    return out


def _mask(addr: str) -> str:
    a = addr or ""
    return (a[:6] + "..." + a[-4:]) if len(a) > 12 else a


def _default_reader() -> str:
    try:
        import pyperclip
        return pyperclip.paste() or ""
    except Exception:
        return ""


def _finding(reason, severity, wtype, before, after):
    return {
        "technique": TECHNIQUE,
        "detector": "clipboard",
        "severity": severity,
        "target": "clipboard",
        "name": wtype,
        "pid": 0,
        "path": "",
        "reason": reason,
        "detail": f"{wtype} wallet address {reason}: {_mask(before)} -> {_mask(after)}",
        "dedup": f"clipboard|{wtype}|{_mask(after)}",
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def observe(text: str, reader=None) -> list:
    """Called from the clipboard-read path with the text just read. Returns (and
    records) any hijack findings. Never raises into the caller."""
    reader = reader or _default_reader
    findings = []
    try:
        _state["reads"] += 1
        now = extract_wallets(text)

        # 1. live swap: read once more after a beat, no user action in between.
        if now:
            try:
                if REREAD_DELAY_S:
                    time.sleep(REREAD_DELAY_S)
                second = extract_wallets(reader())
                for wtype, addr in now.items():
                    if wtype in second and second[wtype] != addr:
                        findings.append(_finding("swapped live (active clipper)",
                                                 "high", wtype, addr, second[wtype]))
            except Exception as e:
                _state["last_error"] = f"reread: {type(e).__name__}"

        # 2. changed since the previous read.
        live_types = {f["name"] for f in findings}
        for wtype, addr in now.items():
            prev = _last.get(wtype)
            if prev and prev != addr and wtype not in live_types:
                findings.append(_finding("changed since last read", "medium",
                                         wtype, prev, addr))
            _last[wtype] = addr

        for f in findings:
            try:
                from threatmon import record
                record(f)
            except Exception as e:
                _state["last_error"] = f"record: {type(e).__name__}"
        _state["findings_total"] += len(findings)
        return findings
    except Exception as e:
        _state["last_error"] = f"observe: {type(e).__name__}"
        return []


def status() -> dict:
    return {
        "detector": "clipboard",
        "technique": TECHNIQUE,
        "ok": _state["supported"],
        "degraded": "",
        "reads": _state["reads"],
        "findings_total": _state["findings_total"],
        "coverage": _state["coverage"],
        "last_error": _state["last_error"],
    }
