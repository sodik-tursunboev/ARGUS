"""
ARGUS - User settings.

WHY THIS EXISTS SEPARATELY FROM config.py.

config.py is under integrity control and inside is_protected(), so ARGUS
cannot write to it -- deliberately, because config.py holds the PIN hash and
the authorization defaults, and a program that can rewrite its own security
configuration has no security configuration. That protection is not something
to work around for the sake of a settings panel.

So settings are LAYERED instead:

    config.py                     defaults, shipped, read-only, integrity-sealed
    %LOCALAPPDATA%\\ARGUS\\settings.json   what the user changed, writable

get() reads the override if there is one and the config default otherwise.
Nothing here ever writes to the source tree.

NOT EVERY SETTING IS EDITABLE, and that is the important part.

A settings endpoint reachable from a web view is new attack surface: a page
that can flip AUTH_ENABLED or CLOUD_ENABLED is a privilege-escalation path
wearing a nice UI. So every field carries a CLASS:

    live      safe, applies immediately            (nudges, cache, city)
    restart   safe, needs a restart to take effect (models, voice, wake word)
    locked    security-relevant, shown but NOT writable through the API

"locked" fields are visible in the UI -- hiding them would just make the
security posture harder to inspect -- but the only way to change them is to
edit config.py as a human, which is exactly the bar those settings deserve.
An unknown key is rejected outright rather than stored, so a typo or an
injected field cannot quietly become a setting.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import threading

import paths

SETTINGS_PATH = paths.writable("settings.json")

LIVE = "live"
RESTART = "restart"
LOCKED = "locked"

# name -> (class, type, label, help)
#
# The catalogue is explicit rather than derived from config.py: a setting
# should appear in the UI because someone decided it belongs there, not
# because it happened to be an uppercase module global.
FIELDS = {
    # ── voice & interaction ────────────────────────────────────────────
    "ASSISTANT_NAME": (RESTART, str, "Assistant name",
                       "What you call it. The wake matcher derives from this."),
    "WAKE_FUZZ": (RESTART, float, "Wake sensitivity",
                  "0-1. Lower hears you more often and wakes more easily."),
    "DEFAULT_CITY": (LIVE, str, "Weather city",
                     "Used when you ask for the weather without naming a place."),
    "USER_NAME": (LIVE, str, "Your name", "How ARGUS addresses you."),

    # ── behaviour ──────────────────────────────────────────────────────
    "PROACTIVE_ENABLED": (LIVE, bool, "Unprompted suggestions",
                          "Occasional remarks when something seems worth saying."),
    "ANSWER_CACHE_ENABLED": (LIVE, bool, "Remember answers",
                             "Reuse a previous answer for a repeated question."),
    "VOICE_REPLAY_DETECTION": (LIVE, bool, "Replay detection",
                               "Refuse a command that is a recording played back."),
    "ZT_ENABLED": (LIVE, bool, "Zero-trust session scoring",
                   "Dynamic trust score on top of the static permission levels. "
                   "Off still leaves every static rule in place."),

    # ── models ─────────────────────────────────────────────────────────
    "OLLAMA_MODEL": (RESTART, str, "Local model", "Runs offline. Needs Ollama."),
    "WHISPER_MODEL": (RESTART, str, "Speech model",
                      "Larger is more accurate and slower."),
    "PIPER_MODEL_PATH": (RESTART, str, "Voice", "The Piper voice used to speak."),
    "GROQ_MODEL": (RESTART, str, "Cloud model (Groq)", "Fastest tier."),
    "GEMINI_MODEL": (RESTART, str, "Cloud model (Gemini)",
                     "Second tier, used when Groq is rate limited."),

    # ── security: visible, never writable from here ────────────────────
    "CLOUD_ENABLED": (LOCKED, bool, "Cloud allowed",
                      "Whether anything may leave this machine. Edit config.py."),
    "AUTH_ENABLED": (LOCKED, bool, "Authentication",
                     "Lock/unlock and permission levels. Edit config.py."),
    "AUTH_IDLE_LOCK_SECONDS": (LOCKED, int, "Auto-lock after",
                               "Seconds of inactivity before locking."),
    "PUSH_TO_TALK_FOR_SENSITIVE": (LOCKED, bool, "Push-to-talk for risky actions",
                                   "Require a key held down for L3+ actions."),
    "VAULT_PATH": (LOCKED, str, "Vault location",
                   "Where notes, profile and logs live."),
}

_lock = threading.Lock()
_overrides: dict | None = None


def _read_proactive():
    from skills import proactive_skill
    return proactive_skill.is_enabled()


def _read_anscache():
    import anscache
    return anscache.enabled()


# Settings whose CURRENT state is owned by a running component rather than by
# this file. Privacy mode can silence proactive nudges without going through
# settings, and ARGUS_NO_CACHE can disable the answer cache from the
# environment -- so for these the override file is not authoritative, and
# reading the component is the only way the panel can show what is actually
# happening. Reporting the remembered override instead meant the panel could
# confidently show OFF for a feature that was running.
LIVE_READERS = {
    "PROACTIVE_ENABLED": _read_proactive,
    "ANSWER_CACHE_ENABLED": _read_anscache,
}

# The SHIPPED values, captured before anything can overwrite them.
#
# _apply_live() sets attributes on the config module so a change takes effect
# without a restart -- which means the module no longer holds the shipped
# default, and reset() had nothing to restore. Measured: changing the weather
# city and then resetting left the city changed, with the override file
# correctly empty. The setting looked reverted and was not.
_DEFAULTS: dict = {}


def _capture_defaults():
    """Must run before the FIRST _apply_live of the process, or it captures an
    override as though it were the shipped default. Every entry point that can
    mutate config calls this, so ordering cannot be got wrong from outside."""
    if _DEFAULTS:
        return
    import config

    for name in FIELDS:
        _DEFAULTS[name] = getattr(config, name, None)


_stamp = None       # (mtime_ns, size) of the file as of the last read


def _file_stamp():
    try:
        st = os.stat(SETTINGS_PATH)
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def _sync_live(names):
    """Mirror externally-changed live settings into THIS process's config."""
    names = [n for n in names if n in FIELDS]
    if not names:
        return
    _capture_defaults()
    merged = {n: (_overrides[n] if n in _overrides else _DEFAULTS.get(n))
              for n in names}
    _apply_live(names, merged)


def _load() -> dict:
    """Re-read whenever the file has changed underneath us.

    ARGUS runs as a process tree -- argus -> voice -> {stt, tts} -- and each
    process imports this module separately, so a module-global cache gives
    every one of them its own private copy of the settings. Without the stamp
    check the API process would save a setting, write the file, and the
    listener would go on using whatever it read at startup, forever.

    That is not hypothetical: with the naive cache the running server reported
    WAKE_FUZZ=0.7 while the file on disk held {}, and nothing detected the
    split. A wake word that quietly ignores the sensitivity the user just set
    is precisely the "it ignores me" failure this project keeps hitting, so
    the cost of a stat() per read is the right trade.
    """
    global _overrides, _stamp
    stamp = _file_stamp()
    if _overrides is not None and stamp == _stamp:
        return _overrides
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}

    first, previous = _overrides is None, (_overrides or {})
    _overrides, _stamp = data, stamp
    if not first:
        # Someone else edited the file. config.X still holds this process's
        # old value, so bring it forward too -- most of ARGUS reads config
        # directly rather than going through get().
        _sync_live([n for n in set(previous) | set(data)
                    if previous.get(n) != data.get(n)])
    return _overrides


def _coerce(name: str, value):
    """Force the declared type. A settings file is user-editable and a string
    where a bool belongs would otherwise reach code that assumes otherwise."""
    kind = FIELDS[name][1]
    if kind is bool:
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        return bool(value)
    if kind is int:
        return int(value)
    if kind is float:
        return float(value)
    return str(value)


def get(name: str, default=None):
    """The effective value: live component, else user override, else shipped."""
    _capture_defaults()
    if name in LIVE_READERS:
        try:
            return LIVE_READERS[name]()
        except Exception:
            pass        # component not loaded in this process; fall through
    if name in _load():
        try:
            return _coerce(name, _overrides[name])
        except (ValueError, TypeError, KeyError):
            pass
    # _DEFAULTS, not the live config module: _apply_live may have written the
    # override onto config, so reading it back would return the override even
    # after it had been removed.
    if name in _DEFAULTS:
        return _DEFAULTS[name]
    import config

    return getattr(config, name, default)


def all_settings() -> list:
    """Every catalogued field with its current value, for the UI."""
    _capture_defaults()
    out = []
    for name, (cls, kind, label, help_text) in FIELDS.items():
        default = _DEFAULTS.get(name)
        out.append({
            "name": name,
            "label": label,
            "help": help_text,
            "class": cls,
            "type": kind.__name__,
            "value": get(name, default),
            "default": default,
            "overridden": name in _load(),
            "editable": cls != LOCKED,
        })
    return out


def update(changes: dict) -> tuple[list, list]:
    """Apply changes. Returns (applied, rejected-with-reason).

    Rejects rather than ignores: a setting that silently fails to save is
    worse than one that refuses, because the user believes it took effect.
    """
    _capture_defaults()
    applied, rejected = [], []
    with _lock:
        data = dict(_load())
        for name, value in (changes or {}).items():
            if name not in FIELDS:
                rejected.append((name, "not a known setting"))
                continue
            cls = FIELDS[name][0]
            if cls == LOCKED:
                rejected.append(
                    (name, "security setting — edit config.py directly"))
                continue
            try:
                data[name] = _coerce(name, value)
            except (ValueError, TypeError):
                rejected.append((name, f"expected {FIELDS[name][1].__name__}"))
                continue
            applied.append(name)

        if applied:
            os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
            tmp = SETTINGS_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=1, sort_keys=True)
            os.replace(tmp, SETTINGS_PATH)
            globals()["_overrides"] = data
            # Our own write, so record its stamp: otherwise the next _load()
            # sees a changed file, calls it a foreign edit, and re-applies
            # what we just applied.
            globals()["_stamp"] = _file_stamp()
            _apply_live(applied, data)
    return applied, rejected


def _apply_live(names: list, data: dict):
    """Push the settings that CAN take effect now into the running modules.

    Only the ones marked live. A restart-class setting is saved and waits --
    pretending it applied would be the same lie as saving nothing.
    """
    _capture_defaults()
    for name in names:
        if FIELDS[name][0] != LIVE:
            continue
        try:
            if name == "ANSWER_CACHE_ENABLED":
                os.environ.pop("ARGUS_NO_CACHE", None) if data[name] \
                    else os.environ.__setitem__("ARGUS_NO_CACHE", "1")
            elif name == "PROACTIVE_ENABLED":
                from skills import proactive_skill
                proactive_skill.enable() if data[name] else proactive_skill.disable()
            else:
                import config
                setattr(config, name, data[name])
        except Exception as e:
            print(f"[settings] {name} saved but could not apply live: {e}")


def reset(name: str = "") -> int:
    """Drop one override, or all of them. Returns how many were removed."""
    _capture_defaults()
    with _lock:
        data = dict(_load())
        before = set(data)
        if name:
            data.pop(name, None)
        else:
            data.clear()
        os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1, sort_keys=True)
        globals()["_overrides"] = data
        globals()["_stamp"] = _file_stamp()

        # Put the shipped values back where _apply_live wrote the overrides.
        # Emptying the file is not a reset if the old value is still running.
        removed = sorted(n for n in (before - set(data)) if n in FIELDS)
        _apply_live(removed, {n: _DEFAULTS.get(n) for n in removed})
        return len(before) - len(data)


def needs_restart() -> list:
    """Overridden settings whose class means they are not live yet."""
    return [n for n in _load() if n in FIELDS and FIELDS[n][0] == RESTART]
