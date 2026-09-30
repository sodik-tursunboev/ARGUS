"""
ARGUS - Noticing when something is plugged in.

A removable drive appearing is the oldest attack in the book and the one your
machine tells you least about: Windows shows a tray bubble for a second and
then forgets. On a personal machine it is also usually just your own USB
stick -- so the useful behaviour is not alarm, it is MEMORY. ARGUS says
something arrived, remembers whether it has seen it before, and keeps the
list.

WHAT MAKES A DEVICE "KNOWN": its volume serial, not its drive letter. Letters
are recycled constantly -- the same E: is your camera in the morning and a
stranger's stick in the afternoon -- so keying on the letter would call every
new device familiar. The serial is stable across replugs and different
machines, which is exactly the property wanted.

SEVERITY IS DELIBERATELY LOW. A USB stick appearing is not an incident, and
raising it as one would train you to ignore threatmon's output -- which costs
you the findings that matter. First sight of an unknown device is "medium";
a device you have plugged in before is recorded and not raised at all. The
spoken alert threshold is high/critical, so this never interrupts you by
voice; it lands on the HUD and in the log where it belongs.

WHAT IT DOES NOT DO: block, eject, scan the contents, or read a single file
from the device. Reading an unknown removable drive is how you get hit by the
thing you were trying to detect, and an assistant that auto-mounts and
inspects attacker-supplied media has enlarged the attack surface it was meant
to watch. It reports arrival. What is on the stick is your call to make, and
files_skill.inspect() is there when you make it.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import threading
import time

import paths

# T1091 Replication Through Removable Media / T1200 Hardware Additions.
TECHNIQUE = "T1091"
SCAN_INTERVAL_S = 8         # plugging in and walking away should still register
_FLOOD_THRESHOLD = 20       # more devices than this in one sweep is not real

STORE_OVERRIDE = None       # tests point this at a temp file

_lock = threading.RLock()
_state = {
    "running": False,
    "seen": {},             # serial -> {"label", "first", "last", "letters"}
    "present": set(),       # serials currently attached
    "arrivals": 0,
    "unknown": 0,
    "last_error": "",
    "loaded": False,
}


def _store_path():
    return STORE_OVERRIDE or os.path.join(paths.writable("vault"),
                                          "usb_devices.json")


def _load():
    """Devices seen before. Absent is fine -- everything is new on day one."""
    with _lock:
        if _state["loaded"]:
            return
        _state["loaded"] = True
    try:
        with open(_store_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            with _lock:
                _state["seen"] = {k: v for k, v in data.items()
                                  if isinstance(v, dict)}
    except FileNotFoundError:
        pass
    except Exception as e:
        with _lock:
            _state["last_error"] = f"load: {type(e).__name__}"


def _save():
    try:
        path = _store_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with _lock:
            blob = json.dumps(_state["seen"], indent=1)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(blob)
        os.replace(tmp, path)      # atomic: a crash keeps the previous list
        return True
    except Exception as e:
        with _lock:
            _state["last_error"] = f"save: {type(e).__name__}"
        return False


def _volume_info(letter: str):
    """(label, serial) for a drive letter, or ("", "").

    GetVolumeInformationW rather than psutil: psutil reports mount points and
    filesystems, and the SERIAL is the whole point -- it is what makes a
    device recognisable after a replug on a different letter.
    """
    try:
        import ctypes
        from ctypes import wintypes

        name_buf = ctypes.create_unicode_buffer(261)
        fs_buf = ctypes.create_unicode_buffer(261)
        serial = wintypes.DWORD()
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(letter), name_buf, 261,
            ctypes.byref(serial), None, None, fs_buf, 261)
        if not ok:
            return "", ""
        return name_buf.value or "", f"{serial.value:08X}"
    except Exception:
        return "", ""


def removable_drives() -> list:
    """[(letter, label, serial)] for attached removable volumes.

    DRIVE_REMOVABLE (2) only. Fixed disks and network shares are not what this
    watches, and including them would make every reconnect look like an event.
    """
    out = []
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        mask = k32.GetLogicalDrives()
        for i in range(26):
            if not (mask >> i) & 1:
                continue
            letter = f"{chr(65 + i)}:\\"
            try:
                if k32.GetDriveTypeW(ctypes.c_wchar_p(letter)) != 2:
                    continue
            except Exception:
                continue
            label, serial = _volume_info(letter)
            if serial:
                out.append((letter, label, serial))
    except Exception as e:
        with _lock:
            _state["last_error"] = f"enumerate: {type(e).__name__}"
    return out


def diff(current: list) -> list:
    """Devices that have just arrived. Departures are not findings.

    Pure with respect to the list it is handed, so arrival logic can be tested
    without a USB stick.
    """
    now = time.time()
    _load()
    findings = []
    serials = {s for _, _, s in current}

    if len(current) > _FLOOD_THRESHOLD:
        with _lock:
            _state["last_error"] = f"implausible device count ({len(current)})"
        return []

    with _lock:
        was = set(_state["present"])
        _state["present"] = serials

    for letter, label, serial in current:
        if serial in was:
            continue                      # still plugged in, not an arrival
        with _lock:
            known = _state["seen"].get(serial)
            _state["arrivals"] += 1
            rec = known or {"label": label, "first": now, "letters": []}
            rec["label"] = label or rec.get("label", "")
            rec["last"] = now
            letters = set(rec.get("letters") or [])
            letters.add(letter)
            rec["letters"] = sorted(letters)[:6]
            _state["seen"][serial] = rec
            if not known:
                _state["unknown"] += 1
        _save()

        if known:
            # A device you have used before. Recorded, not raised: an alert
            # every time you plug in your own stick is an alert you learn to
            # ignore.
            continue

        findings.append({
            "technique": TECHNIQUE,
            "detector": "usbwatch",
            # NOT high. See the module docstring: a USB stick appearing is not
            # an incident, and raising it as one costs the findings that are.
            "severity": "medium",
            "target": f"{letter} {label}".strip(),
            "name": label or "removable drive",
            "pid": 0,
            "path": letter,
            "action": "attached",
            "serial": serial,
            "reasons": ["first time this device has been attached"],
            "reason": "usb_new_device",
            "dedup": f"usbwatch|new|{serial}",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        })
    return findings


def scan(_processes=None) -> list:
    """One sweep. Shaped like the POLL detectors so it can move there."""
    try:
        return diff(removable_drives())
    except Exception as e:
        with _lock:
            _state["last_error"] = f"scan: {type(e).__name__}"
        return []


def _watch_loop(record):
    while True:
        with _lock:
            if not _state["running"]:
                return
        try:
            for finding in scan():
                record(finding)
        except Exception as e:
            with _lock:
                _state["last_error"] = f"loop: {type(e).__name__}"
        time.sleep(SCAN_INTERVAL_S)


def start(record):
    with _lock:
        if _state["running"]:
            return
        _state["running"] = True
    _load()
    # Seed the currently-attached set WITHOUT raising findings: the drive that
    # was already plugged in when ARGUS started did not "arrive", and greeting
    # it as an event on every boot is noise.
    try:
        for letter, label, serial in removable_drives():
            with _lock:
                _state["present"].add(serial)
                if serial not in _state["seen"]:
                    _state["seen"][serial] = {
                        "label": label, "first": time.time(),
                        "last": time.time(), "letters": [letter]}
        _save()
    except Exception:
        pass
    threading.Thread(target=_watch_loop, args=(record,), daemon=True,
                     name="argus-usb-watch").start()


def report() -> str:
    """A spoken answer to "what's plugged in?". String logic only."""
    _load()
    current = removable_drives()
    with _lock:
        known = dict(_state["seen"])
    if not current:
        n = len(known)
        return ("Nothing removable is plugged in right now."
                + (f" I've seen {n} device{'' if n == 1 else 's'} before."
                   if n else ""))
    bits = []
    for letter, label, serial in current:
        seen_before = serial in known and known[serial].get("first", 0) < time.time() - 60
        name = label or "unlabelled drive"
        bits.append(f"{name} on {letter.rstrip(chr(92))} "
                    f"({'known' if seen_before else 'new to me'})")
    return ("Plugged in: " + "; ".join(bits) + ". I don't read what's on them "
            "— check anything you open.")


def status() -> dict:
    _load()
    with _lock:
        return {
            "detector": "usbwatch",
            "technique": TECHNIQUE,
            "techniques": [TECHNIQUE, "T1200"],
            "ok": _state["running"],
            "degraded": "" if _state["running"] else "not started",
            "attached_now": len(_state["present"]),
            "devices_known": len(_state["seen"]),
            "arrivals": _state["arrivals"],
            "first_time_devices": _state["unknown"],
            "reads_contents": False,
            "last_error": _state["last_error"],
        }
