'ARGUS - Local personalization: preferences, aliases, and learned workflows.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import re
import threading
import time
import uuid

from config import VAULT_PATH

STORE_PATH = os.path.join(VAULT_PATH, "personalization.json")

_lock = threading.Lock()

# ── data minimization: preferences are a BOUNDED set of known behavioral
# switches, not an arbitrary free-form key-value blob. An alias's NAME is
# open-ended (that's the point -- the user invents their own vocabulary),
# but a preference KEY must be one of these, because nothing in ARGUS reads
# an unrecognised key; storing one would just be dead data under a made-up
# name. Add a key here only when real code consults it (see git grep
# get_preference for every consumer).
KNOWN_PREFERENCE_KEYS = frozenset({
    "default_browser", "default_editor", "default_terminal", "default_music_app",
    "response_verbosity",       # "concise" | "detailed"
    "preferred_language",
    "security_report_detail",   # "concise" | "detailed" -- overrides response_verbosity for security topics
})

# Values default to local storage. Cloud-safe values require an explicit
# allowlist entry, and credential-like values are refused before storage.

LOCAL_PRIVATE = "LOCAL_PRIVATE"
CLOUD_SAFE = "CLOUD_SAFE"

# Deny cloud sharing by default:
# anything not listed here stays local, permanently, with no override short
# of editing this constant and shipping a new build.
CLOUD_SAFE_KEYS = frozenset({"preferred_language", "response_verbosity"})

SOURCE_EXPLICIT = "EXPLICIT"
SOURCE_INFERRED = "INFERRED"
SOURCE_SYSTEM_DEFAULT = "SYSTEM_DEFAULT"

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9 _-]{0,47}$", re.I)
_MAX_VALUE_LEN = 120

_INFER_PROMOTE_AT = 3        # consistent observations before an inferred pref is stored
_INFER_CONFIDENCE_START = 0.5
_INFER_CONFIDENCE_STEP = 0.15
_INFER_CONFIDENCE_CAP = 0.9
_STALE_INFERRED_DAYS = 45     # an inferred (never explicit) pref unused this long is pruned
_STALE_SUGGESTION_DAYS = 14   # an unconfirmed workflow suggestion this old is dropped

def _default_store() -> dict:
    """A FRESH dict with fresh nested containers every call -- not a shared
    module-level constant. _load() below hands its return value straight to
    callers that mutate it in place (store["preferences"][key] = ...); a
    shallow `dict(SOME_SHARED_DICT)` would copy the outer dict but leave
    nested dict/list values shared, so a write on one "missing file" load
    would silently pollute every future one until the process restarts."""
    return {"preferences": {}, "aliases": {}, "workflows": [], "suggestions": [],
            "_observations": {}}


# ── storage ──────────────────────────────────────────────────────────────

def _load() -> dict:
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            blob = json.load(f)
    except (OSError, ValueError):
        return _default_store()
    if not isinstance(blob, dict):
        return _default_store()
    out = _default_store()
    for key in out:
        if key in blob and isinstance(blob[key], type(out[key])):
            out[key] = blob[key]
    return out


def _save(store: dict) -> None:
    """Never raises -- a personalization write failing must not break the
    request that produced it."""
    try:
        os.makedirs(VAULT_PATH, exist_ok=True)
        tmp = STORE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(store, f, ensure_ascii=False, indent=1, sort_keys=True)
        os.replace(tmp, STORE_PATH)
    except OSError as e:
        print(f"[personalize] could not save: {e}")


def _valid_name(name: str) -> bool:
    return bool(name) and bool(_NAME_RE.match(name.strip()))


def _looks_like_secret(value: str) -> bool:
    """Reuses security.py's own credential detection rather than a second
    pattern list. Refused outright, never stored redacted -- a redacted
    value ("[redacted]") would just be useless data under a real-looking key.

    Inherits redact()'s own boundary: it catches bare/structured credential
    SHAPES (an API key, a high-entropy password pasted as the value), not
    an arbitrary low-entropy word inside a prose sentence -- that's
    deliberate on security.py's part, to avoid flagging ordinary text
    everywhere else it's used. A preference/alias value is expected to be
    short (an app name, a setting), so this is the right tool for it; it is
    not a general secret-scanner for long free text."""
    try:
        import security
        return security.redact(value) != value
    except Exception:
        return False


def _audit(event: str, detail: str, outcome: str = "ok") -> None:
    try:
        import security
        security.audit(f"personalize_{event}", detail[:150], outcome)
    except Exception:
        pass


# personalization.* events on the ONE existing hub (main._hud_events), same
# lazy-import/best-effort pattern agents/events.py and agents/team_events.py
# both already use. No second event bus.
_EVENTS = frozenset({
    "personalization.preference_created", "personalization.preference_updated",
    "personalization.preference_removed", "personalization.alias_created",
    "personalization.alias_removed", "personalization.workflow_suggested",
    "personalization.workflow_created", "personalization.workflow_updated",
    "personalization.workflow_removed", "personalization.workflow_started",
    "personalization.workflow_completed", "personalization.workflow_failed",
})


def _emit(event_type: str, **fields) -> None:
    if event_type not in _EVENTS:
        return
    payload = {k: v for k, v in fields.items() if isinstance(v, (str, int, float, bool))}
    payload["ts"] = time.time()
    try:
        import main as _main
        hub = getattr(_main, "_hud_events", None)
        if hub is not None:
            hub.publish(event_type, payload)
    except Exception:
        pass


# ── preferences ──────────────────────────────────────────────────────────

def set_preference(key: str, value: str, *, source: str = SOURCE_EXPLICIT) -> str:
    key = (key or "").strip().lower().replace(" ", "_")
    value = (value or "").strip()
    if key not in KNOWN_PREFERENCE_KEYS:
        return f"I don't have a '{key}' preference to set."
    if not value or len(value) > _MAX_VALUE_LEN:
        return "That value doesn't look right, so I haven't saved it."
    if _looks_like_secret(value):
        _audit("preference_refused", f"key={key} reason=secret_shaped", "denied")
        return "That looked like a credential, not a preference, so I haven't saved it."

    with _lock:
        store = _load()
        now = time.time()
        existing = store["preferences"].get(key)
        classification = CLOUD_SAFE if key in CLOUD_SAFE_KEYS else LOCAL_PRIVATE
        store["preferences"][key] = {
            "preference_id": existing["preference_id"] if existing else uuid.uuid4().hex[:12],
            "key": key, "value": value, "source": source,
            "confidence": 1.0 if source == SOURCE_EXPLICIT else _INFER_CONFIDENCE_START,
            "classification": classification,
            "created_at": existing["created_at"] if existing else now,
            "updated_at": now, "last_used": existing.get("last_used", 0.0) if existing else 0.0,
            "usage_count": existing.get("usage_count", 0) if existing else 0,
        }
        store["_observations"].pop(key, None)  # an explicit set supersedes any running tally
        _save(store)
    _audit("preference_set", f"key={key} source={source}")
    _emit("personalization.preference_created" if not existing else "personalization.preference_updated",
          key=key, source=source)
    return f"Got it — {key.replace('_', ' ')} set to {value}."


def get_preference(key: str, default=None):
    """Deterministic lookup, zero model calls. Marks
    usage so retention (section 16) can tell a used preference from a
    stale, never-consulted one."""
    key = (key or "").strip().lower().replace(" ", "_")
    with _lock:
        store = _load()
        rec = store["preferences"].get(key)
        if rec is None:
            return default
        rec["last_used"] = time.time()
        rec["usage_count"] = rec.get("usage_count", 0) + 1
        _save(store)
    return rec["value"]


def forget_preference(key: str) -> str:
    key = (key or "").strip().lower().replace(" ", "_")
    with _lock:
        store = _load()
        if key not in store["preferences"]:
            return f"I don't have a '{key}' preference recorded."
        del store["preferences"][key]
        _save(store)
    _audit("preference_removed", f"key={key}")
    _emit("personalization.preference_removed", key=key)
    return f"Cleared your {key.replace('_', ' ')} preference."


def observe_choice(key: str, value: str) -> None:
    """Record a stable, non-sensitive preference inferred from repeated choices."""
    key = (key or "").strip().lower().replace(" ", "_")
    value = (value or "").strip()
    if key not in KNOWN_PREFERENCE_KEYS or not value or _looks_like_secret(value):
        return
    with _lock:
        store = _load()
        if store["preferences"].get(key, {}).get("source") == SOURCE_EXPLICIT:
            return  # explicit always wins; don't even tally
        tally = store["_observations"].get(key)
        if not tally or tally.get("value") != value:
            tally = {"value": value, "count": 0}
        tally["count"] += 1
        store["_observations"][key] = tally
        if tally["count"] < _INFER_PROMOTE_AT:
            _save(store)
            return
        now = time.time()
        existing = store["preferences"].get(key)
        confidence = min(_INFER_CONFIDENCE_CAP,
                         _INFER_CONFIDENCE_START + _INFER_CONFIDENCE_STEP * (tally["count"] - _INFER_PROMOTE_AT))
        store["preferences"][key] = {
            "preference_id": existing["preference_id"] if existing else uuid.uuid4().hex[:12],
            "key": key, "value": value, "source": SOURCE_INFERRED, "confidence": confidence,
            "classification": CLOUD_SAFE if key in CLOUD_SAFE_KEYS else LOCAL_PRIVATE,
            "created_at": existing["created_at"] if existing else now,
            "updated_at": now, "last_used": 0.0, "usage_count": 0,
        }
        _save(store)
    _audit("preference_inferred", f"key={key} confidence={confidence:.2f}")
    _emit("personalization.preference_created", key=key, source=SOURCE_INFERRED)


def list_preferences() -> list:
    with _lock:
        return list(_load()["preferences"].values())


# ── aliases ──────────────────────────────────────────────────────────────

def set_alias(name: str, target: str, *, source: str = SOURCE_EXPLICIT) -> str:
    name = (name or "").strip().lower()
    target = (target or "").strip()
    if not _valid_name(name):
        return "That alias name doesn't look right, so I haven't saved it."
    if not target or len(target) > _MAX_VALUE_LEN:
        return "That doesn't look like something I can point an alias at."
    if _looks_like_secret(target):
        _audit("alias_refused", f"name={name} reason=secret_shaped", "denied")
        return "That looked like a credential, not a target, so I haven't saved it."

    with _lock:
        store = _load()
        now = time.time()
        existing = store["aliases"].get(name)
        store["aliases"][name] = {
            "alias_id": existing["alias_id"] if existing else uuid.uuid4().hex[:12],
            "name": name, "target": target, "source": source,
            "created_at": existing["created_at"] if existing else now,
            "updated_at": now, "last_used": existing.get("last_used", 0.0) if existing else 0.0,
            "usage_count": existing.get("usage_count", 0) if existing else 0,
        }
        _save(store)
    _audit("alias_set", f"name={name}")
    _emit("personalization.alias_created", name=name, source=source)
    return f"Got it — when you say \"{name}\" I'll use {target}."


def resolve_alias(name: str) -> str | None:
    """Deterministic lookup used by apps_skill.py etc, zero model calls.
    Checked BEFORE any system-default alias table, since a user's own word
    for something should win over a shipped default."""
    name = (name or "").strip().lower()
    if not name:
        return None
    with _lock:
        store = _load()
        rec = store["aliases"].get(name)
        if rec is None:
            return None
        rec["last_used"] = time.time()
        rec["usage_count"] = rec.get("usage_count", 0) + 1
        _save(store)
    return rec["target"]


def forget_alias(name: str) -> str:
    name = (name or "").strip().lower()
    with _lock:
        store = _load()
        if name not in store["aliases"]:
            return f"I don't have an alias for \"{name}\"."
        del store["aliases"][name]
        _save(store)
    _audit("alias_removed", f"name={name}")
    _emit("personalization.alias_removed", name=name)
    return f"Removed the alias for \"{name}\"."


def list_aliases() -> list:
    with _lock:
        return list(_load()["aliases"].values())


# ── workflows ────────────────────────────────────────────────────────────
# A workflow is a saved LIST of (skill, action, target) triples that already
# passed through the SAME classifier/registry every live command does.
# Running one calls router.dispatch_known() per action -- the exact front
# door, so auth/policy/audit apply identically to a workflow action as to
# the same action spoken alone.

def _validate_actions(actions: list) -> str:
    """Returns an error string, or "" if every action names a real,
    currently-registered capability. Refuses arbitrary skill/action
    strings by construction -- no shell blobs, nothing not already in
    skills/registry.py's catalog."""
    if not actions or not isinstance(actions, list) or len(actions) > 12:
        return "A workflow needs between 1 and 12 real actions."
    try:
        from skills.registry import SKILLS
    except Exception:
        return "The capability registry is unavailable right now."
    for a in actions:
        if not isinstance(a, dict) or "skill" not in a or "action" not in a:
            return "Every workflow step needs a skill and an action."
        skill, action = a["skill"], a["action"]
        if skill not in SKILLS or action not in SKILLS[skill].get("actions", {}):
            return f"\"{skill}/{action}\" isn't a capability I have."
    return ""


def create_workflow(name: str, actions: list, *, description: str = "",
                    source: str = SOURCE_EXPLICIT, suggestion_id: str = "") -> str:
    name = (name or "").strip()
    if not _valid_name(name):
        return "That workflow name doesn't look right, so I haven't saved it."
    err = _validate_actions(actions)
    if err:
        return err

    with _lock:
        store = _load()
        if any(w["name"].lower() == name.lower() for w in store["workflows"]):
            return f"A workflow named \"{name}\" already exists."
        now = time.time()
        wf = {
            "workflow_id": uuid.uuid4().hex[:12], "name": name,
            "description": (description or "")[:200], "created_from": source,
            "actions": [{"skill": a["skill"], "action": a["action"], "target": str(a.get("target", ""))[:200]}
                       for a in actions],
            "constraints": {}, "enabled": True, "classification": LOCAL_PRIVATE,
            "created_at": now, "updated_at": now, "last_run": 0.0, "run_count": 0,
        }
        store["workflows"].append(wf)
        if suggestion_id:
            store["suggestions"] = [s for s in store["suggestions"] if s["suggestion_id"] != suggestion_id]
        _save(store)
    _audit("workflow_created", f"name={name} steps={len(wf['actions'])} source={source}")
    _emit("personalization.workflow_created", name=name, steps=len(wf["actions"]))
    return f"Saved \"{name}\" as a workflow with {len(wf['actions'])} step{'s' if len(wf['actions']) != 1 else ''}."


def delete_workflow(name: str) -> str:
    name = (name or "").strip().lower()
    with _lock:
        store = _load()
        before = len(store["workflows"])
        store["workflows"] = [w for w in store["workflows"] if w["name"].lower() != name]
        if len(store["workflows"]) == before:
            return f"I don't have a workflow named \"{name}\"."
        _save(store)
    _audit("workflow_removed", f"name={name}")
    _emit("personalization.workflow_removed", name=name)
    return f"Removed the \"{name}\" workflow."


def list_workflows() -> list:
    with _lock:
        return list(_load()["workflows"])


def run_workflow(name: str) -> dict:
    """Replays each saved action through router.dispatch_known() -- the
    same auth/policy/audit gate a live command goes through, one at a time,
    stopping at the first refusal or error rather than plowing on with a
    partially-authorized sequence."""
    name = (name or "").strip().lower()
    with _lock:
        store = _load()
        wf = next((w for w in store["workflows"] if w["name"].lower() == name), None)
    if wf is None:
        return {"ok": False, "error": f"I don't have a workflow named \"{name}\"."}
    if not wf.get("enabled", True):
        return {"ok": False, "error": f"The \"{name}\" workflow is disabled."}

    err = _validate_actions(wf["actions"])
    if err:  # policy/registry may have changed since this was saved
        _audit("workflow_failed", f"name={name} reason=stale_actions", "failed")
        _emit("personalization.workflow_failed", name=name, reason="stale_actions")
        return {"ok": False, "error": err}

    import router
    _emit("personalization.workflow_started", name=name, steps=len(wf["actions"]))
    results = []
    for step in wf["actions"]:
        reply = router.dispatch_known(step["skill"], step["action"], step.get("target", ""))
        refused = router.last_refused()
        results.append({"skill": step["skill"], "action": step["action"], "reply": reply, "refused": refused})
        if refused:
            _audit("workflow_failed", f"name={name} reason=refused step={step['skill']}/{step['action']}", "failed")
            _emit("personalization.workflow_failed", name=name, reason="refused")
            return {"ok": False, "error": "One step needed authorization that wasn't given.", "results": results}

    with _lock:
        store = _load()
        for w in store["workflows"]:
            if w["name"].lower() == name:
                w["last_run"] = time.time()
                w["run_count"] = w.get("run_count", 0) + 1
        _save(store)
    _audit("workflow_run", f"name={name} steps={len(results)}")
    _emit("personalization.workflow_completed", name=name, steps=len(results))
    return {"ok": True, "results": results}


# ── workflow suggestion: pattern NOTICING is
# automatic; creating a real, runnable workflow from it always needs an
# explicit yes. Recent-dispatch tracking lives here, not in router.py,
# because router.py already has a bounded, best-effort recorder for
# telemetry.py (skills/telemetry.py's `record`) and this follows the exact
# same shape: a small in-memory ring, never persisted, never raises,
# reset on restart. Unlike telemetry's aggregate counts, pattern detection
# needs order and timing, which the aggregate can't give it -- there was
# nothing here to reuse (checked: telemetry.py keeps counts only).
_RECENT_CAP = 40
_recent_actions: list = []       # [(skill, action, ts), ...], oldest first
_SEQUENCE_LEN = 3                # how many co-occurring actions make a "pattern"
_SEQUENCE_WINDOW_S = 120         # actions must fall within this span to count together
_PATTERN_REPEAT_THRESHOLD = 3    # times the same set must recur before suggesting
_SUGGEST_COOLDOWN_S = 24 * 3600  # proactive_skill.py's own cooldown philosophy


def note_dispatch(skill: str, action: str, target: str = "") -> None:
    """Best-effort, called from router.py's dispatch tail next to the
    existing telemetry.record() call. Never raises, never blocks a request
    on its own account."""
    if skill in ("chat", "personalize", "security"):
        return  # not workflow-shaped material
    try:
        with _lock:
            _recent_actions.append((skill, action, str(target)[:60], time.time()))
            del _recent_actions[:-_RECENT_CAP]
        _maybe_suggest()
    except Exception:
        pass


def _maybe_suggest() -> None:
    now = time.time()
    with _lock:
        window = [a for a in _recent_actions if now - a[3] <= _SEQUENCE_WINDOW_S]
    if len(window) < _SEQUENCE_LEN:
        return
    # The TARGET distinguishes the steps, not just (skill, action) -- the
    # example sequence is "opens VS Code, opens the ARGUS project, opens
    # Windows Terminal", which is apps/open three times with three different
    # targets. Collapsing on (skill, action) alone would see that as one
    # repeated action, never three.
    key = tuple(sorted({(a[0], a[1], a[2]) for a in window[-_SEQUENCE_LEN:]}))
    if len(key) < _SEQUENCE_LEN:
        return  # not enough DISTINCT steps, just one thing repeated fast

    store = _load()
    now_str = time.time()
    # decay stale suggestions on the way in
    store["suggestions"] = [s for s in store["suggestions"]
                            if now_str - s["created_at"] < _STALE_SUGGESTION_DAYS * 86400]
    sig = "|".join(f"{s}/{a}:{t}" for s, a, t in key)
    existing = next((s for s in store["suggestions"] if s["signature"] == sig), None)
    if existing:
        existing["seen_count"] += 1
        if existing["seen_count"] < _PATTERN_REPEAT_THRESHOLD:
            _save(store)
            return
        if now_str - existing.get("last_suggested_at", 0) < _SUGGEST_COOLDOWN_S:
            _save(store)
            return
        existing["last_suggested_at"] = now_str
        _save(store)
        _audit("workflow_suggested", f"sig={sig[:80]}")
        _emit("personalization.workflow_suggested", signature=sig[:80])
        return
    actions_for_sig = [{"skill": s, "action": a, "target": t} for s, a, t in key]
    store["suggestions"].append({
        "suggestion_id": uuid.uuid4().hex[:12], "signature": sig,
        "actions": actions_for_sig, "seen_count": 1,
        "created_at": now_str, "last_suggested_at": 0.0,
    })
    _save(store)


def pending_suggestions() -> list:
    with _lock:
        store = _load()
        return [s for s in store["suggestions"] if s["seen_count"] >= _PATTERN_REPEAT_THRESHOLD]


def reject_suggestion(suggestion_id: str) -> str:
    with _lock:
        store = _load()
        before = len(store["suggestions"])
        store["suggestions"] = [s for s in store["suggestions"] if s["suggestion_id"] != suggestion_id]
        if len(store["suggestions"]) == before:
            return "I don't have that suggestion anymore."
        _save(store)
    return "Won't suggest that one again."



# cloud_worker.py may call for personalization. Denies by default; returns
# nothing for a key not on CLOUD_SAFE_KEYS, full stop, no override param. ──

def cloud_safe_context() -> dict:
    with _lock:
        store = _load()
    return {k: v["value"] for k, v in store["preferences"].items() if k in CLOUD_SAFE_KEYS}


# ── retention / pruning ──────────────────────────────

def prune() -> int:
    """Removes stale INFERRED preferences (never explicit, unused for
    _STALE_INFERRED_DAYS) and stale unconfirmed suggestions. Explicit
    preferences and saved workflows never auto-expire -- only an explicit
    forget/delete removes those. Called opportunistically (see summary()),
    same "check on read" shape history_store.py's own STALE_AFTER uses,
    rather than a new background thread for a low-stakes concern."""
    now = time.time()
    removed = 0
    with _lock:
        store = _load()
        for key, rec in list(store["preferences"].items()):
            if rec.get("source") != SOURCE_INFERRED:
                continue
            last = max(rec.get("last_used", 0.0), rec.get("updated_at", 0.0))
            if now - last > _STALE_INFERRED_DAYS * 86400:
                del store["preferences"][key]
                removed += 1
        before = len(store["suggestions"])
        store["suggestions"] = [s for s in store["suggestions"]
                                if now - s["created_at"] < _STALE_SUGGESTION_DAYS * 86400]
        removed += before - len(store["suggestions"])
        if removed:
            _save(store)
    return removed


# ── explainability + summary ──────────────────────

def explain(key: str) -> str:
    with _lock:
        store = _load()
    rec = store["preferences"].get((key or "").strip().lower().replace(" ", "_"))
    if rec is None:
        alias = store["aliases"].get((key or "").strip().lower())
        if alias is None:
            return f"I don't have anything about \"{key}\"."
        return f"\"{alias['name']}\" means {alias['target']} ({alias['source'].lower()})."
    basis = "you told me directly" if rec["source"] == SOURCE_EXPLICIT else \
        f"you've consistently chosen it ({int(rec['confidence'] * 100)}% confidence)"
    return f"Your {key.replace('_', ' ')} is {rec['value']} — {basis}."


def summary() -> str:
    prune()
    with _lock:
        store = _load()
    prefs, aliases, workflows = store["preferences"], store["aliases"], store["workflows"]
    if not prefs and not aliases and not workflows:
        return "I haven't learned any preferences, aliases, or workflows yet."
    parts = []
    if prefs:
        parts.append(f"{len(prefs)} preference{'s' if len(prefs) != 1 else ''}")
    if aliases:
        parts.append(f"{len(aliases)} alias{'es' if len(aliases) != 1 else ''}")
    if workflows:
        parts.append(f"{len(workflows)} saved workflow{'s' if len(workflows) != 1 else ''}")
    return "I know: " + ", ".join(parts) + "."
