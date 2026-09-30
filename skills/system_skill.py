"""
ARGUS - System skill (feature flags, runtime config query, own stats).

Three surfaces, all local, all harmless on their own:

  FEATURE FLAGS -- a persistent, ALLOWLISTED store of booleans. ARGUS already
  has plenty of toggles, but they live in different places (config.py knobs,
  settings.json overrides, one-off env vars). This is a single stable
  catalogue that future versions can wire real behaviour to. Each entry is
  marked `live` (it switches real behaviour TODAY, through an existing
  module) or `aspirational` (it is named and documented so a future ARGUS can
  wire it without churn; storing it changes nothing yet -- that is
  deliberate, not a stub). The setter REFUSES any name not in the catalogue,
  so flags.json can never accumulate invented knobs that quietly do nothing.

  RUNTIME CONFIG QUERY -- read-only. The layered settings system (settings.py:
  get/update/reset, live-apply, needs_restart) already IS the configuration
  manager. system/settings exposes what it reports; it never writes config.py
  or settings.json. Changing a setting goes through the settings panel.

  OWN TELEMETRY -- "how is ARGUS doing" routes to telemetry.stats(), over the
  audit-backed per-command records (see skills/telemetry.py).

NOT SECURITY-SENSITIVE ALONE. Reading your own flags/settings/stats reveals
nothing a local process could not already see. Nothing here is L0, because it
does describe this machine's state and configuration -- it rides L1 alongside
the other report skills.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import threading

import paths

_STORE_PATH = paths.writable("flags.json")

_lock = threading.Lock()

# The feature-flag catalogue. name -> {desc, live: fn-or-none}. `live` is the
# name of the module whose real switch this flag flips; absent/None means
# aspirational (documented, stored, not yet wired). Keep this list SMALL and
# thoughtful -- every entry is a promise of future behaviour.
_FLAG_DOCS = {
    "proactive_nudges": "ARGUS may volunteer short unprompted remarks",
    "answer_cache": "responses are cached for reuse within a session",
    "telemetry": "per-command latency and outcome records are kept",
    "gesture_watch": "wake and respond to hand gestures (future wiring)",
    "dictate_typing": "dictate types into any focused window (already PIN-"
                      "gated; this is a future convenience toggle)",
    "cloud_inference": "general questions may go to a cloud model "
                       "(governed by config.CLOUD_ENABLED, which is locked "
                       "in settings -- aspirational here)",
}

# Live flags and what toggling them actually does. Anything not here stores
# and lists without switching behaviour -- see module docstring.
def _apply_proactive(on: bool) -> None:
    from skills import proactive_skill
    proactive_skill.enable() if on else proactive_skill.disable()


def _apply_answer_cache(on: bool) -> None:
    if on:
        os.environ.pop("ARGUS_NO_CACHE", None)
    else:
        os.environ["ARGUS_NO_CACHE"] = "1"


def _apply_telemetry(on: bool) -> None:
    from skills import telemetry
    telemetry.set_enabled(on)


LIVE = {
    "proactive_nudges": _apply_proactive,
    "answer_cache": _apply_answer_cache,
    "telemetry": _apply_telemetry,
}


def _load() -> dict:
    try:
        with open(_STORE_PATH, "r", encoding="utf-8") as f:
            store = json.load(f)
        return {k: bool(v) for k, v in store.items() if isinstance(v, bool)}
    except Exception:
        return {}


def _save(store: dict) -> None:
    try:
        with open(_STORE_PATH, "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2)
    except Exception:
        pass


def flags(name: str = "") -> str:
    """List all flags (with state) or one flag, as a spoken sentence."""
    store = _load()
    if name:
        n = (name or "").strip().lower()
        if n in _FLAG_DOCS:
            state = "on" if store.get(n) else "off"
            kind = "live" if n in LIVE else "documented but not yet wired"
            return f"{n} is {state} -- {_FLAG_DOCS[n]}. It's {kind}."
        return f"I don't have a feature flag called {name}."
    bits = []
    for n in sorted(_FLAG_DOCS):
        state = "on" if store.get(n) else "off"
        bits.append(f"{n} {state}")
    if not bits:
        return "No feature flags defined."
    return ". ".join(bits) + "."


def set_flag(name: str, on: bool) -> str:
    """Set a flag. Refuses anything not in the catalogue. Applies live flags
    through their real switch, then persists."""
    n = (name or "").strip().lower()
    if n not in _FLAG_DOCS:
        return (f"{name or 'that'} isn't a flag I keep -- I only manage: "
                f"{', '.join(sorted(_FLAG_DOCS))}.")
    on = bool(on)
    with _lock:
        store = _load()
        store[n] = on
        _save(store)
    apply = LIVE.get(n)
    if apply:
        try:
            apply(on)
        except Exception:
            return f"Stored {n} = {on}, but the live switch didn't take: check its module."
    return f"{n} is now {'on' if on else 'off'}."


def stats() -> str:
    from skills import telemetry
    return telemetry.stats()


def settings() -> str:
    """A read-only report of the current settings as ARGUS sees them."""
    try:
        import settings as _s
        rows = _s.all_settings()
    except Exception as e:
        return f"I couldn't read the settings ({type(e).__name__})."
    bits = []
    for r in rows:
        name = r.get("name", "?")
        value = r.get("value", "?")
        restart = " (needs restart)" if r.get("class") == _s.RESTART else ""
        bits.append(f"{name} is {value}{restart}")
    if not bits:
        return "No settings to report."
    return ". ".join(bits[:20]) + "."