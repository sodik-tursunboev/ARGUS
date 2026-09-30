"""
ARGUS - Guided remediation: "I found something, Boss. Want me to fix it?"

Asked for directly: ARGUS should not only detect an issue but offer to repair
it, and then actually repair it. This is that, and the shape of it is decided
entirely by one question -- what is the worst thing this code can be talked
into doing?

THE FIVE RULES THIS MODULE IS BUILT FROM

1. A FIXED TABLE, NEVER A FREE-FORM ACTION. Every repair is one of the entries
   in FIXES below, written and reviewed here. There is no path that takes a
   command, a path, a registry key or a process name from a language model and
   acts on it. The model cannot reach this module at all: the offer is built
   from a DETECTION RECORD that a detector produced, and apply() re-derives
   every target from that record rather than from anything anybody said.

2. NOTHING HAPPENS WITHOUT A YES. offer() stages; apply() acts; they are
   separate calls with an explicit confirmation between them, and a stale offer
   expires (OFFER_TTL_S). The staged offer is keyed to the finding it came
   from, so "yes" cannot be replayed against a different one.

3. IT WILL NOT TOUCH ARGUS. Every target passes integrity.is_protected() first.
   That covers the install directory, the writable state directory and the
   vault -- so no repair can remove ARGUS's own autostart entry, quarantine its
   own binary, or stop its own process. The rule that the AI must not modify
   the layer that governs the AI applies to the repair engine most of all,
   because a repair engine is precisely the shape of tool an attacker would
   want to talk into deleting auth.py.

4. REVERSIBLE WHERE REVERSIBLE IS POSSIBLE. A flagged download is MOVED to a
   quarantine folder, not deleted. An autostart entry is written to an undo
   journal before it is removed, so it can be put back by hand. Where a repair
   genuinely cannot be undone it says so in the offer, in those words, before
   he answers.

5. IT REFUSES RATHER THAN GUESSES. A fix that cannot establish its target
   exactly -- a pid that has been reused, a registry value that has changed
   since the finding, a file that has moved -- refuses and says why. Repairing
   the wrong thing is worse than repairing nothing, and on this machine the
   wrong thing could be the owner's work.

WHAT IT DELIBERATELY CANNOT DO, and why each one is absent rather than pending:

  * TURN A WINDOWS PROTECTION BACK ON. Defender, the firewall, UAC and Secure
    Boot all need administrator rights, and the honest options were "run
    elevated" or "don't". A voice assistant holding a standing elevation token
    so it can flip security settings is a far larger hole than the one it
    closes -- so threatmon/defenses.py tells him WHERE the switch is and he
    flips it. That is not a limitation to be engineered around later; it is
    the answer.
  * DELETE ANYTHING. Quarantine moves. files_skill already owns deletion, at
    L4, behind a PIN, and duplicating it here at a lower level would be a way
    around its own gate.
  * EDIT HKLM. Every registry repair here is HKCU, which this user owns
    outright. An HKLM write needs elevation and is refused for the same reason
    as the protections above.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import shutil
import threading
import time

import paths

try:
    import winreg
except Exception:                                   # non-Windows / test hosts
    winreg = None

# An offer nobody answered is not an instruction. Matches power_skill's own
# staging window: long enough to think about, short enough that "yes" said to
# something else five minutes later cannot land on it.
OFFER_TTL_S = 120.0

QUARANTINE_DIR_OVERRIDE = None      # tests point these at temp dirs
UNDO_PATH_OVERRIDE = None

_lock = threading.RLock()
_offer = {"fix": "", "finding": None, "at": 0.0, "detail": ""}
_state = {"applied": 0, "refused": 0, "last_error": ""}


def _quarantine_dir() -> str:
    return QUARANTINE_DIR_OVERRIDE or paths.writable("quarantine")


def _undo_path() -> str:
    return UNDO_PATH_OVERRIDE or paths.writable("remedy_undo.jsonl")


def _journal(entry: dict) -> None:
    """Append what was changed, so a repair can be undone by hand.

    Best-effort and deliberately NOT a precondition: a repair that could not
    write its journal line still runs, because refusing to remove a malicious
    Run key because a log file is read-only would be the wrong trade. The
    journal is a convenience for the owner, not a safety control -- the safety
    controls are the confirmation and the protected-path check.
    """
    try:
        entry = dict(entry)
        entry["at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        path = _undo_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except OSError as e:
        _state["last_error"] = f"journal: {type(e).__name__}"


def _is_ours(path: str) -> bool:
    """Is this part of ARGUS? Rule 3, and it fails CLOSED.

    An integrity module that will not import is not permission to proceed --
    it is the exact condition under which the check matters most, so an
    unavailable checker means every path is treated as protected.
    """
    try:
        import integrity
        return bool(integrity.is_protected(path))
    except Exception:
        return True


# ── the fixes ────────────────────────────────────────────────────────────────
#
# Each entry: which detector findings it applies to, what it would do in
# words, whether it can be undone, and the function that does it. apply()
# functions return (ok, spoken_detail) and must never raise.

def _f_remove_autostart_applies(f: dict) -> bool:
    """Only entries this user can actually remove.

    HKLM IS EXCLUDED HERE, not refused later. An offer ARGUS knows it will have
    to decline is a worse answer than not offering: he says yes, waits, and
    gets "actually I can't". Excluding it at the applies() stage lets the
    quarantine fix -- which CAN act on the same finding, because the file the
    entry points at is usually in his own profile -- be offered instead.
    """
    if f.get("detector") != "persistence":
        return False
    if f.get("action") not in ("added", "modified"):
        return False
    surface = str(f.get("surface", ""))
    if surface == "startup":
        return True                     # a Startup-folder shortcut: his to move
    if surface != "run":
        return False
    return "HKCU" in str(f.get("where", "")).upper()


def _hkcu_run_value(finding: dict):
    """(subkey, value_name) for a persistence finding, if it is an HKCU Run
    entry this user may edit. None for anything else -- HKLM needs elevation
    and is refused rather than attempted."""
    eid = str(finding.get("target") or "")
    where = str(finding.get("where") or "")
    if "HKCU" not in where.upper():
        return None
    # where is "HKCU\Software\...\Run"; target is the value name.
    sub = where.split("\\", 1)[1] if "\\" in where else ""
    if not sub or not eid:
        return None
    return sub, eid


def _f_remove_autostart(finding: dict):
    surface = str(finding.get("surface", ""))

    if surface == "startup":
        # A shortcut in the Startup folder. Quarantined rather than deleted,
        # so a mistake is a file in a folder rather than a lost installer.
        path = str(finding.get("path") or finding.get("command") or "")
        if not path or not os.path.isfile(path):
            return False, ("I can't find that startup item any more — it may "
                           "already be gone.")
        if _is_ours(path):
            return False, ("That startup entry is part of my own installation, "
                           "so I won't touch it.")
        return _quarantine(path, reason="autostart")

    pair = _hkcu_run_value(finding)
    if not pair:
        return False, ("That one lives under HKEY_LOCAL_MACHINE, which needs "
                       "administrator rights. I won't ask for those — you'll "
                       "want to remove it yourself.")
    sub, name = pair
    if winreg is None:
        return False, "I can't reach the registry on this machine."

    try:
        access = winreg.KEY_READ | winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub, 0, access) as k:
            try:
                current, _typ = winreg.QueryValueEx(k, name)
            except FileNotFoundError:
                return False, ("That startup entry is already gone — nothing "
                               "left to remove.")
            # RULE 5: refuse rather than guess. If the command behind the value
            # is not the one the finding described, something changed since the
            # detection and this is no longer the thing he agreed to remove.
            expected = str(finding.get("command") or "")
            if expected and str(current).strip() != expected.strip():
                return False, ("That entry has changed since I flagged it, so "
                               "I've left it alone. Ask me again and I'll look "
                               "at it fresh.")
            if _is_ours(str(current)):
                return False, ("That entry points at my own installation, so I "
                               "won't remove it.")
            _journal({"fix": "remove_autostart", "hive": "HKCU", "key": sub,
                      "value": name, "was": str(current)[:400]})
            winreg.DeleteValue(k, name)
    except PermissionError:
        return False, ("Windows wouldn't let me remove that one without "
                       "administrator rights.")
    except FileNotFoundError:
        # The KEY is gone, not just the value -- an uninstall took the whole
        # thing. Reported identically to a missing value: from where he is
        # standing "it's already gone" is the same fact, and the generic
        # "I couldn't remove it (FileNotFoundError)" that used to come out of
        # the OSError branch below reads like a failure when it is a success.
        return False, ("That startup entry is already gone — nothing left to "
                       "remove.")
    except OSError as e:
        return False, f"I couldn't remove it ({type(e).__name__})."
    return True, (f"Removed {name} from your startup entries. I wrote down "
                  f"what it was, so you can put it back if that was wrong.")


def _f_quarantine_applies(f: dict) -> bool:
    path = str(f.get("path") or "")
    return bool(path) and f.get("detector") in ("listening", "lolbin",
                                                "persistence", "usb")


def _quarantine(path: str, reason: str = "flagged"):
    """MOVE a file into the quarantine folder. Never deletes."""
    if not path or not os.path.isfile(path):
        return False, "I can't find that file any more."
    if _is_ours(path):
        return False, ("That file is part of my own installation, so I won't "
                       "move it.")
    try:
        dest_dir = _quarantine_dir()
        os.makedirs(dest_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        dest = os.path.join(dest_dir, f"{stamp}__{os.path.basename(path)}")
        shutil.move(path, dest)
    except PermissionError:
        return False, ("Windows wouldn't let me move that — it's probably "
                       "still running, or owned by another account.")
    except OSError as e:
        return False, f"I couldn't move it ({type(e).__name__})."
    _journal({"fix": "quarantine", "from": path, "to": dest, "reason": reason})
    return True, (f"Moved {os.path.basename(path)} into quarantine. It's not "
                  f"deleted — it's in my quarantine folder if you need it back.")


def _f_quarantine_file(finding: dict):
    return _quarantine(str(finding.get("path") or ""),
                       reason=str(finding.get("detector") or "flagged"))


def _f_clear_clipboard_applies(f: dict) -> bool:
    return f.get("detector") == "clipboard"


def _f_clear_clipboard(finding: dict):
    try:
        import pyperclip
        pyperclip.copy("")
    except Exception as e:
        return False, f"I couldn't clear the clipboard ({type(e).__name__})."
    _journal({"fix": "clear_clipboard"})
    return True, ("Cleared your clipboard. Whatever was in there is gone — "
                  "copy the real address again before you paste.")


def _f_stop_process_applies(f: dict) -> bool:
    return (f.get("detector") in ("listening", "lolbin", "lsass")
            and int(f.get("pid", 0) or 0) > 4)


def _f_stop_process(finding: dict):
    """Stop the process a detector flagged. The most destructive thing here,
    and the guards are why it is allowed at all.

    THE PID IS RE-VERIFIED AGAINST THE NAME FROM THE FINDING. Windows reuses
    pids, and a finding is minutes old by the time anybody answers a question
    about it -- so the pid alone could by then be the owner's editor. If the
    process at that pid is not the one that was flagged, this refuses.
    """
    pid = int(finding.get("pid", 0) or 0)
    want = str(finding.get("name") or "").lower()
    if pid <= 4:
        return False, "That's a system process — I won't touch it."
    try:
        import psutil
        p = psutil.Process(pid)
        name = (p.name() or "").lower()
        try:
            exe = p.exe() or ""
        except Exception:
            exe = ""
    except Exception:
        return False, ("That process isn't running any more — it stopped on "
                       "its own.")

    if want and name != want:
        return False, (f"Process {pid} is {name} now, not {want} — Windows has "
                       f"reused the number, so I've left it alone.")
    if _is_ours(exe):
        return False, "That's part of me. I'm not going to stop myself."
    root = (os.environ.get("SystemRoot") or r"C:\Windows").lower()
    if exe and exe.lower().startswith(root + os.sep):
        return False, ("That's a Windows system program. Stopping it could "
                       "take the machine down with it, so I won't — that one "
                       "needs you.")
    try:
        p.terminate()
        p.wait(timeout=5)
    except Exception:
        try:
            p.kill()
        except Exception as e:
            return False, f"I couldn't stop it ({type(e).__name__})."
    _journal({"fix": "stop_process", "pid": pid, "name": name, "exe": exe})
    return True, (f"Stopped {name}. If it starts itself again, that's worth "
                  f"knowing — ask me what runs at startup.")


def _f_lock_applies(f: dict) -> bool:
    """CRITICAL ONLY, and the narrowing is deliberate.

    This started as the catch-all: anything critical OR high, so there was
    always something to offer. That made "fix it" on an ordinary high-severity
    finding -- which is most of them -- answer with an offer to lock the
    screen, and an accidental yes then locks the machine over something that
    did not warrant it.

    Locking is not a repair. It is a holding action for the case where
    something serious is happening and ARGUS has nothing that actually fixes
    it, and restricting it to critical is what keeps it meaning that.
    """
    return str(f.get("severity")) == "critical"


def _f_lock(finding: dict):
    try:
        import ctypes
        ok = bool(ctypes.windll.user32.LockWorkStation())
    except Exception as e:
        return False, f"I couldn't lock the screen ({type(e).__name__})."
    if not ok:
        return False, "Windows refused to lock the screen."
    return True, "Screen locked. Your PIN opens it."


FIXES = {
    "remove_autostart": {
        "label": "remove that startup entry",
        "applies": _f_remove_autostart_applies,
        "apply": _f_remove_autostart,
        "undoable": True,
        "describe": lambda f: (f"take {f.get('name') or 'it'} out of your "
                               f"startup entries"),
    },
    "quarantine": {
        "label": "quarantine that file",
        "applies": _f_quarantine_applies,
        "apply": _f_quarantine_file,
        "undoable": True,
        "describe": lambda f: (f"move {os.path.basename(str(f.get('path') or '')) or 'it'} "
                               f"into quarantine, where it can't run"),
    },
    "stop_process": {
        "label": "stop that program",
        "applies": _f_stop_process_applies,
        "apply": _f_stop_process,
        "undoable": False,
        "describe": lambda f: (f"stop {f.get('name') or 'it'}, "
                               f"process {f.get('pid')}"),
    },
    "clear_clipboard": {
        "label": "clear the clipboard",
        "applies": _f_clear_clipboard_applies,
        "apply": _f_clear_clipboard,
        "undoable": False,
        "describe": lambda f: "clear your clipboard",
    },
    "lock_screen": {
        "label": "lock the screen",
        "applies": _f_lock_applies,
        "apply": _f_lock,
        "undoable": True,
        "describe": lambda f: "lock the screen while you look at it",
    },
}

# The order a fix is preferred in when several apply. Deliberately least
# destructive first: quarantining a file is recoverable, stopping a process is
# not, and locking the screen is a holding action rather than a repair -- so it
# is offered only when nothing better fits.
FIX_ORDER = ("remove_autostart", "quarantine", "clear_clipboard",
             "stop_process", "lock_screen")


def available_for(finding: dict) -> list:
    """Fix keys that genuinely apply to this finding, best first."""
    if not finding:
        return []
    out = []
    for key in FIX_ORDER:
        spec = FIXES.get(key)
        if not spec:
            continue
        try:
            if spec["applies"](finding):
                out.append(key)
        except Exception:
            continue
    return out


# ── the offer / confirm handshake ────────────────────────────────────────────
def latest_fixable() -> dict:
    """The most recent finding ARGUS could actually do something about.

    Reads threatmon's own buffer -- no re-scan. Returns {} when there is
    nothing, which is a real answer and the common one.
    """
    try:
        import threatmon
        recent = threatmon.recent(40)
    except Exception:
        return {}
    for rec in recent:
        if rec.get("severity") not in ("critical", "high", "medium"):
            continue
        if available_for(rec):
            return rec
    return {}


def offer(finding: dict = None) -> str:
    """Stage a repair and ASK. Never acts.

    The spoken half of "I found something, Boss. Want me to fix it?" -- and the
    fact that this returns a question rather than a result is the whole design.
    """
    if finding is None:
        finding = latest_fixable()
    if not finding:
        return ("Nothing I can repair right now, Boss — nothing recent that I "
                "have a safe fix for.")

    keys = available_for(finding)
    if not keys:
        return ("I can see it, but I don't have a repair for that one that I'd "
                "trust to run unsupervised. It needs you.")

    key = keys[0]
    spec = FIXES[key]
    what = str(finding.get("name") or finding.get("target") or "something")
    reasons = finding.get("reasons") or []
    why = reasons[0] if isinstance(reasons, list) and reasons else ""

    with _lock:
        _offer.update(fix=key, finding=dict(finding), at=time.time(),
                      detail=spec["describe"](finding))

    bits = [f"I've found something, Boss — {what}"]
    if why:
        bits.append(why)
    bits.append(f"I can {spec['describe'](finding)}")
    bits.append("that's reversible — I'll write down what I changed"
                if spec["undoable"] else "that one can't be undone")
    bits.append("want me to?")
    return ". ".join(b[0].upper() + b[1:] for b in bits if b) + ""


def pending() -> dict:
    """The staged offer, or {} once it has expired."""
    with _lock:
        if not _offer["fix"]:
            return {}
        if time.time() - _offer["at"] > OFFER_TTL_S:
            _offer.update(fix="", finding=None, at=0.0, detail="")
            return {}
        return {"fix": _offer["fix"], "detail": _offer["detail"],
                "finding": dict(_offer["finding"] or {}),
                "age": round(time.time() - _offer["at"], 1)}


def cancel() -> str:
    with _lock:
        had = bool(_offer["fix"])
        _offer.update(fix="", finding=None, at=0.0, detail="")
    return ("Left it alone." if had else "There was nothing waiting.")


def apply_pending() -> str:
    """Carry out the staged repair. The ONLY function here that changes
    anything, and it can only ever run what offer() staged."""
    p = pending()
    with _lock:
        _offer.update(fix="", finding=None, at=0.0, detail="")

    if not p:
        return ("There's nothing waiting on a yes — the offer expired, or "
                "there wasn't one.")

    spec = FIXES.get(p["fix"])
    if not spec:
        return "I've lost track of what I offered. Ask me again."

    try:
        ok, detail = spec["apply"](p["finding"])
    except Exception as e:
        ok, detail = False, f"That went wrong ({type(e).__name__})."

    with _lock:
        if ok:
            _state["applied"] += 1
        else:
            _state["refused"] += 1

    # AUDITED EITHER WAY. A repair that ran and a repair that refused are both
    # things the owner should be able to read back later, and a refusal is the
    # more interesting of the two -- it is the guard doing its job.
    try:
        import security
        security.audit("remedy", f"{p['fix']} on "
                                 f"{str(p['finding'].get('name'))[:40]}",
                       "ok" if ok else "refused")
        security.security_event(
            security.CONFIG_CHANGED if ok else security.TOOL_DENIED,
            component="remedy", reason=p["fix"],
            status="ok" if ok else "failed")
    except Exception:
        pass
    return detail


def status() -> dict:
    p = pending()
    return {
        "detector": "remedy",
        "kind": "guided repair — offers, never acts unasked",
        "fixes": sorted(FIXES),
        "pending": p.get("fix", ""),
        "applied": _state["applied"],
        "refused": _state["refused"],
        "quarantine": _quarantine_dir(),
        "undo_journal": _undo_path(),
        "cannot": ["re-enable Windows protections (needs administrator)",
                   "delete anything (quarantine moves, files_skill deletes)",
                   "write to HKEY_LOCAL_MACHINE"],
        "last_error": _state["last_error"],
    }
