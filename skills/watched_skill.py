'ARGUS - Watched tasks.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import re
import threading
import time
import uuid

import paths

from skills import monitor_skill as _mon

_STORE_PATH = paths.writable("watched.json")

MAX_WATCHED_TASKS = 10
WATCH_TTL_S = 30 * 60.0          # same expiry discipline as monitor_skill
POLL_INTERVAL = 30.0
MAX_RESULTS_PER_WATCH = 3

_lock = threading.Lock()


# The spoken trigger words the intent fast-path may leave on the front of
# the condition half. Stripped so monitor_skill._parse sees what it knows:
# "watch for battery_above 80" -> "battery_above 80". Anything ELSE left on
# the front is simply refused by _parse's allowlist -- fail closed, the same
# way a monitor request it doesn't recognise is refused.
_TRIGGER_RE = re.compile(
    r"^(?:watch\s+(?:for\s+|that\s+|until\s+)?|tell\s+me\s+when\s+|"
    r"let\s+me\s+know\s+when\s+|notify\s+me\s+when\s+|ping\s+me\s+when\s+)*",
    re.I)


def _split_request(text: str):
    """"<condition> then <goal>" -> (condition_text, goal_text) or None.

    The comma form is matched FIRST: " then " is a substring of ", then ",
    so checking it first would leave a trailing comma on the condition half
    ("battery_above 80,") and _parse's float() would refuse the very request
    the owner clearly made. Trailing punctuation is stripped after the split
    for the same reason -- "battery_above 80." is the same condition.
    """
    t = (text or "").strip()
    if not t:
        return None
    for sep in (", then ", " then ", " Then "):
        left, _, right = t.partition(sep)
        if right.strip():
            cond = _TRIGGER_RE.sub("", left, count=1).strip()
            return cond.rstrip(".,;: ").strip(), right.strip()
    return None


def set_watch(text: str) -> str:
    """Set a watched task: parse the condition, plan the task, VALIDATE the
    plan, store it, and tell the owner exactly what will be staged on fire.

    Every failure mode here is a refusal to store, never a stored watch with
    a weaker plan than the one described.
    """
    split = _split_request(text)
    if not split:
        return ("A watched task needs both halves -- what to wait for, then "
                "what to do. Like: 'watch for battery_above 80, then check "
                "what's using the CPU'.")
    cond_text, goal = split
    goal = goal[:200]

    # EVENT half: monitor_skill's own parser. It refuses anything outside
    # its allowlist and confines paths itself -- a condition this module
    # would not be allowed to WATCH is one it may not stage work on either.
    parsed = _mon._parse(cond_text)
    if isinstance(parsed, str):
        return parsed
    cond, args, label = parsed

    # TASK half: planned and validated NOW, while the owner is present to
    # hear it. No model at fire time, no validation at fire time -- the
    # steps stored are the exact steps validate_plan() approved.
    import router
    try:
        raw = router.chat_json(router.PLAN_PROMPT, goal)
    except Exception:
        return ("I can't plan that task right now -- the local model isn't "
                "answering, and I won't set a watch on a plan I haven't "
                "checked.")
    steps, refusal = router.validate_plan((raw or {}).get("steps"), web=False)
    if refusal:
        return (f"I can watch for that, but not do that afterward: {refusal} "
                f"Set the watch with a task I'm allowed to plan.")

    import security
    now = time.time()
    with _lock:
        watches = _load()
        watches = [w for w in watches
                   if w.get("enabled", True) or now - w.get("created_at", 0) < 3600]
        if len(watches) >= MAX_WATCHED_TASKS:
            return (f"You already have {MAX_WATCHED_TASKS} watched tasks -- "
                    f"cancel one first.")
        task = {
            "id": uuid.uuid4().hex[:8],
            "cond": cond, "args": args, "label": label,
            "goal": goal, "steps": steps,
            # Same explicit flag monitor_skill's store carries: absence is
            # NOT treated as enabled anywhere here -- a half-written record
            # is a disabled one, never an active watcher.
            "enabled": True,
            "created_at": now, "expires_at": now + WATCH_TTL_S,
            "results": [],
        }
        watches.append(task)
        _save(watches)
    try:
        security.audit("watched_set", f"{task['id']}: {label} -> "
                       f"{router.describe_plan(steps)}"[:160], "ok")
    except Exception:
        pass
    _ensure_running()
    minutes = int(WATCH_TTL_S // 60)
    return (f"Watching ({task['id']}): {label}. When it happens I'll stage "
            f"this plan for your go ahead: {router.describe_plan(steps)}. "
            f"Good for {minutes} minutes -- say 'what did you find' to ask.")


def _load() -> list:
    try:
        with open(_STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save(watches: list) -> None:
    try:
        with open(_STORE_PATH, "w", encoding="utf-8") as f:
            json.dump(watches, f, indent=2)
    except Exception:
        pass


def _find(watches: list, query: str):
    q = (query or "").strip().lower()
    if not q:
        return None
    for w in watches:
        if q in w["id"].lower():
            return w
    for w in watches:
        if q in w.get("label", "").lower() or q in w.get("goal", "").lower():
            return w
    return None


def list_tasks(query: str = "") -> str:
    watches = [w for w in _load() if w.get("enabled", True)]
    if query:
        w = _find(watches, query)
        watches = [w] if w else []
    if not watches:
        return "No active watched tasks." if not query else \
            f"No watched task matching {query}."
    import router
    return "; ".join(
        f'{w["id"]}: watching {w["label"]}, then: {router.describe_plan(w["steps"])}'
        for w in watches)


def cancel(query: str) -> str:
    with _lock:
        watches = _load()
        w = _find(watches, query)
        if not w:
            return (f"I don't have a watched task matching {query}."
                    if query else "Cancel which watched task?")
        watches = [x for x in watches if x["id"] != w["id"]]
        _save(watches)
    return f'Stopped watching: {w.get("label", w["id"])} ({w["id"]}).'


def status() -> str:
    watches = _load()
    if not watches:
        return "No watched tasks."
    active = [w for w in watches if w.get("enabled", True)]
    pending = sum(len(w.get("results", [])) for w in watches)
    return (f"{len(watches)} watched task{'s' if len(watches) != 1 else ''} "
            f"total, {len(active)} active, {pending} result"
            f"{'s' if pending != 1 else ''} waiting.")


def results(query: str = "", limit: int = 5) -> str:
    watches = _load()
    if query:
        w = _find(watches, query)
        watches = [w] if w else []
    lines = []
    for w in watches:
        for r in w.get("results", [])[-limit:]:
            when = time.strftime("%H:%M", time.localtime(r["at"]))
            lines.append(f'[{when}] {w["label"]}: {r["text"]}')
    if not lines:
        return "No results yet." if query else "No watched tasks have fired yet."
    return " | ".join(lines[-limit:])


def unread_count() -> int:
    """For proactive_skill's nudge -- a COUNT only, never the condition or
    the plan. See the module docstring."""
    return sum(len(w.get("results", [])) for w in _load())


def mark_read() -> None:
    with _lock:
        watches = _load()
        for w in watches:
            w["results"] = []
        _save(watches)


# ═══════════════════════════════════════════════════════════════════════════
# THE FIRE PATH -- the only place a watch touches the plan slot, and even
# there it only STAGES. stage_validated_plan() refuses when a plan is
# already staged or paused (one plan at a time, unchanged), re-validates the
# stored steps, and still requires the owner's go ahead to run.
# ═══════════════════════════════════════════════════════════════════════════

def _fire(w: dict) -> None:
    """One-shot: record the result, then try to stage the stored plan.

    Staging is refused, and the refusal recorded, when the goal's BUDGET is
    already exhausted (agent/budgets.py -- the same ledger the plan runner's
    replanner uses). A task that has already had its owner-approved attempts
    cannot be resurrected by a second watch firing: the watcher hands the
    task to the same bounded ledger, it does not open a second one.
    """
    import security
    detail = "your watched condition is true"
    try:
        s = _mon._snapshot()
        detail = _mon._eval({"cond": w["cond"], "args": w.get("args", {})},
                            s) or detail
    except Exception:
        pass
    detail = detail[:120]

    ok, note = False, ""
    try:
        from agent import budgets
        over, why = budgets.exceeded(w.get("goal", ""))
        if over:
            note = f"budget exhausted: {why}"
        else:
            import router
            ok, note = router.stage_validated_plan(w["goal"], w["steps"])
    except Exception as e:
        note = f"couldn't stage ({type(e).__name__})"
    w["results"] = (list(w.get("results", []))
                    + [{"at": time.time(), "text": detail,
                        "staged": bool(ok), "note": note[:120]}]
                    )[-MAX_RESULTS_PER_WATCH:]
    w["enabled"] = False          # one-shot, exactly like monitor_skill
    try:
        security.audit("watched_fire", f'{w["id"]}: {detail}; staged={ok}',
                       "ok" if ok else "blocked")
    except Exception:
        pass


def _run_due() -> None:

    # watchers. The due-check is skipped entirely -- no evaluation, no fire,
    # no record -- and expiry is still honored by the next tick after the
    # state lifts (watches keep their timestamps, so nothing resurrects).
    try:
        import security_state
        if security_state.watchers_suspended():
            return
    except Exception:
        pass
    now = time.time()
    with _lock:
        watches = _load()
    active = [w for w in watches if w.get("enabled", True) and w.get("cond")]
    if not active:
        return
    fired = []
    expired = []
    for w in active:
        if now >= w.get("expires_at", 0):
            w["enabled"] = False
            expired.append(w)
            continue
        try:
            s = _mon._snapshot()
            if _mon._eval({"cond": w["cond"], "args": w.get("args", {})}, s):
                fired.append(w)
        except Exception as e:
            print(f"[watched] probe failed for {w['id']}: "
                  f"{type(e).__name__}: {e}")
    if not (fired or expired):
        return
    with _lock:
        current = _load()
        by_id = {w["id"]: w for w in current}
        for w in fired:
            if w["id"] in by_id:
                _fire(by_id[w["id"]])
        for w in expired:
            # Expired watches are disabled too -- and PERSISTED, or a restart
            # would resurrect a watch nobody has any use for any more. Flag
            # only: the stale snapshot dict carries no results and must not
            # clobber anything a concurrent _fire wrote.
            if w["id"] in by_id:
                by_id[w["id"]]["enabled"] = False
        _save(list(by_id.values()))


_thread = None
_thread_lock = threading.Lock()


def _ensure_running():
    global _thread
    with _thread_lock:
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(target=_loop, name="argus-watched",
                                       daemon=True)
            _thread.start()


def _loop():
    while True:
        time.sleep(POLL_INTERVAL)
        try:
            _run_due()
        except Exception as e:
            print(f"[watched] tick failed: {type(e).__name__}: {e}")


def restart_pending():
    """Resume any enabled watch from a previous run. Starts the poll thread
    only if there is actually something to watch."""
    watches = _load()
    if any(w.get("enabled", True) for w in watches):
        _ensure_running()


# Same boot-time resume discipline as monitor_skill's own tail: importing
# this module is what revives watches from a previous run.
restart_pending()
