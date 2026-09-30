'ARGUS - Persistent goals.'

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

_STORE_PATH = paths.writable("goals.json")

MAX_GOALS = 5
GOAL_TTL_S = 24 * 3600.0          # recurring goals auto-expire, like scheduler
MAX_RECURRING_RUNS = 24           # ~hourly for a day; tighter than scheduler's 144
POLL_INTERVAL = 30.0
MAX_RESULTS_PER_GOAL = 5
MIN_INTERVAL_S = 300.0            # a "recurring" goal faster than this is a loop

_lock = threading.Lock()

# ── parsing the schedule half ────────────────────────────────────────────────
# "Every morning, prepare a briefing" / "every 30 minutes check anomalies" /
# "in 10 minutes check what's eating the CPU". Fixed shapes only -- this is
# not a natural-language date parser, and anything it cannot parse is a
# refusal to store, never a guessed schedule.
_NAMED_SCHEDULES = {
    "morning": (24 * 3600.0, "every morning"),
    "day":     (24 * 3600.0, "every day"),
    "hour":    (3600.0, "every hour"),
}
_EVERY_N = re.compile(r"(?:every|each)\s+(\d+)\s*(min(?:ute)?s?|h(?:ou)?rs?)\b", re.I)
_NAMED = re.compile(r"(?:every|each)\s+(morning|day|hour)\b", re.I)
_ONCE = re.compile(r"\bin\s+(\d+)\s*(min(?:ute)?s?|h(?:ou)?rs?)\b", re.I)
_UNIT_S = {"min": 60.0, "mins": 60.0, "minute": 60.0, "minutes": 60.0,
           "h": 3600.0, "hr": 3600.0, "hrs": 3600.0, "hour": 3600.0,
           "hours": 3600.0}


def _parse_schedule(text: str):
    """(kind, interval_s, cleaned_goal_text) or None. Pure."""
    t = (text or "").strip()
    if not t:
        return None

    # "in N minutes ..." -> one-shot. Checked first: "in" wins over any
    # "every" that might appear later in the goal text itself.
    m = _ONCE.search(t)
    if m:
        span = m.span()
        rest = (t[:span[0]] + t[span[1]:]).strip(" ,.;:")
        return "once", float(m.group(1)) * _UNIT_S.get(m.group(2).lower(), 60.0), rest

    m = _EVERY_N.search(t)
    if m:
        span = m.span()
        rest = (t[:span[0]] + t[span[1]:]).strip(" ,.;:")
        return "interval", float(m.group(1)) * _UNIT_S.get(m.group(2).lower(), 60.0), rest

    m = _NAMED.search(t)
    if m:
        span = m.span()
        rest = (t[:span[0]] + t[span[1]:]).strip(" ,.;:")
        seconds, _label = _NAMED_SCHEDULES[m.group(1).lower()]
        return "interval", seconds, rest

    return None


def create(text: str) -> str:
    """Create a persistent goal: parse the schedule, plan the goal, VALIDATE
    the plan once while the owner is present, store it, say what will be
    staged each time it fires."""
    parsed = _parse_schedule(text)
    if not parsed:
        return ("A persistent goal needs a schedule and a task -- like "
                "'every morning, prepare a system briefing' or 'in 10 "
                "minutes check what's using the CPU'.")
    kind, interval_s, goal = parsed
    goal = (goal or "").strip(" ,.;:")[:200]
    if not goal:
        return ("I can hear the schedule, but not the goal -- what should I "
                "prepare each time?")
    if kind == "interval" and interval_s < MIN_INTERVAL_S:
        return (f"The shortest recurring goal I'll accept is "
                f"{int(MIN_INTERVAL_S // 60)} minutes.")

    # The task half is planned and whole-plan validated NOW, while the owner
    # is present -- identical to watched_skill's set path. The stored steps
    # are the exact steps validate_plan() approved; nothing is re-generated
    # or re-interpreted at fire time.
    import router
    try:
        raw = router.chat_json(router.PLAN_PROMPT, goal)
    except Exception:
        return ("I can't plan that goal right now -- the local model isn't "
                "answering, and I won't store a goal on a plan I haven't "
                "checked.")
    steps, refusal = router.validate_plan((raw or {}).get("steps"), web=False)
    if refusal:
        return (f"I can repeat that on a schedule, but not do that: {refusal} "
                f"Rephrase it with steps I'm allowed to plan.")

    import security
    now = time.time()
    with _lock:
        goals = _load()
        goals = [g for g in goals
                 if g.get("enabled", True) or now - g.get("created_at", 0) < 3600]
        if len(goals) >= MAX_GOALS:
            return (f"You already have {MAX_GOALS} persistent goals -- "
                    f"cancel one first.")
        g = {
            "id": uuid.uuid4().hex[:8],
            "goal": goal, "steps": steps,
            "kind": kind, "interval_s": interval_s if kind == "interval" else None,
            "next_run": now + interval_s,
            "enabled": True,
            "created_at": now,
            "expires_at": (now + GOAL_TTL_S) if kind == "interval" else None,

            # of the actual code path -- never an alternate permission source.
            "scope": "stage_only",
            # validate_plan returns step DICTS ({"skill", "action", "target"}).
            "allowed_capabilities": sorted(
                {f"{s.get('skill', '?')}/{s.get('action', '?')}" for s in steps}),
            "confirmation_policy": "owner_go_ahead_each_run",
            "failure_policy": "record_and_wait_for_next_interval",
            "budget": {"max_runs": 1 if kind == "once" else MAX_RECURRING_RUNS},
            "run_count": 0,
            "results": [],
        }
        goals.append(g)
        _save(goals)
    try:
        security.audit("goals_create", f'{g["id"]}: {g["kind"]} -> '
                       f'{router.describe_plan(steps)}'[:160], "ok")
    except Exception:
        pass
    _ensure_running()
    when = (f"every {_human_seconds(interval_s)}" if kind == "interval"
            else f"in {_human_seconds(interval_s)}")
    tail = (f" It expires after 24 hours -- say 'goals' to review it." if kind == "interval"
            else "")
    return (f"Persistent goal ({g['id']}): {when}, I'll stage this plan for "
            f"your go ahead: {router.describe_plan(steps)} -- each run still "
            f"waits for you.{tail}")


def _human_seconds(s: float) -> str:
    s = int(s)
    if s < 3600:
        return f"{max(1, s // 60)} minutes"
    return f"{s / 3600:.1f} hours"


def _load() -> list:
    try:
        with open(_STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save(goals: list) -> None:
    try:
        with open(_STORE_PATH, "w", encoding="utf-8") as f:
            json.dump(goals, f, indent=2)
    except Exception:
        pass


def _find(goals: list, query: str):
    q = (query or "").strip().lower()
    if not q:
        return None
    for g in goals:
        if q in g["id"].lower():
            return g
    for g in goals:
        if q in g.get("goal", "").lower():
            return g
    return None


def list_tasks(query: str = "") -> str:
    goals = [g for g in _load() if g.get("enabled", True)]
    if query:
        g = _find(goals, query)
        goals = [g] if g else []
    if not goals:
        return "No persistent goals." if not query else \
            f"No goal matching {query}."
    import router
    parts = []
    for g in goals:
        when = (f"every {_human_seconds(g['interval_s'])}"
                if g["kind"] == "interval" else "once")
        parts.append(f'{g["id"]}: {g["goal"]} ({when}) -> '
                     f'{router.describe_plan(g["steps"])}')
    return "; ".join(parts)


def cancel(query: str) -> str:
    with _lock:
        goals = _load()
        g = _find(goals, query)
        if not g:
            return (f"I don't have a persistent goal matching {query}."
                    if query else "Cancel which goal?")
        goals = [x for x in goals if x["id"] != g["id"]]
        _save(goals)
    import security
    try:
        security.audit("goals_cancel", f'{g["id"]} {g["goal"][:60]}', "ok")
    except Exception:
        pass
    return f'Cancelled goal {g["goal"][:60]} ({g["id"]}).'


def status() -> str:
    goals = _load()
    if not goals:
        return "No persistent goals."
    active = [g for g in goals if g.get("enabled", True)]
    pending = sum(len(g.get("results", [])) for g in goals)
    return (f"{len(goals)} persistent goal{'s' if len(goals) != 1 else ''} "
            f"total, {len(active)} active, {pending} prepared result"
            f"{'s' if pending != 1 else ''} waiting.")


def results(query: str = "", limit: int = 5) -> str:
    goals = _load()
    if query:
        g = _find(goals, query)
        goals = [g] if g else []
    lines = []
    for g in goals:
        for r in g.get("results", [])[-limit:]:
            when = time.strftime("%H:%M", time.localtime(r["at"]))
            lines.append(f'[{when}] {g["goal"][:50]}: {r["text"]}')
    if not lines:
        return "Nothing prepared yet." if query else \
            "No persistent goal has fired yet."
    return " | ".join(lines[-limit:])


def unread_count() -> int:
    """For proactive_skill's nudge -- a COUNT only, never the goal or plan."""
    return sum(len(g.get("results", [])) for g in _load())


def mark_read() -> None:
    with _lock:
        goals = _load()
        for g in goals:
            g["results"] = []
        _save(goals)


# ═══════════════════════════════════════════════════════════════════════════
# THE FIRE PATH. The clock never runs a step: it re-validates stored steps
# through stage_validated_plan (which refuses a tampered store, a busy slot,
# or an over-budget goal) and records what happened.
# ═══════════════════════════════════════════════════════════════════════════

def _fire(g: dict) -> None:
    """One scheduled tick: try to stage the stored plan; record the outcome."""
    import security
    ok, note = False, ""
    try:
        from agent import budgets
        over, why = budgets.exceeded(g.get("goal", ""))
        if over:
            note = f"budget exhausted: {why}"
        else:
            import router
            allowed, why2 = budgets.reserve_plan(g.get("goal", ""), len(g["steps"]))
            if not allowed:
                note = f"budget refused: {why2}"
            else:
                ok, note = router.stage_validated_plan(g["goal"], g["steps"])
                if ok:
                    note = ("prepared -- say 'go ahead' to run it "
                            f"(staged copy expires soon): {note}")
    except Exception as e:
        note = f"couldn't prepare ({type(e).__name__})"
    g["results"] = (list(g.get("results", []))
                    + [{"at": time.time(), "text": note[:160],
                        "staged": bool(ok)}])[-MAX_RESULTS_PER_GOAL:]
    g["run_count"] = int(g.get("run_count", 0)) + 1
    try:
        security.audit("goals_fire", f'{g["id"]}: staged={ok}; {note}'[:140],
                       "ok" if ok else "blocked")
    except Exception:
        pass


def _run_due() -> None:

    # goal preparation entirely; stored schedules keep their timestamps and
    # resume from where the state left them.
    try:
        import security_state
        if security_state.watchers_suspended():
            return
    except Exception:
        pass
    now = time.time()
    with _lock:
        goals = _load()
    active = [g for g in goals if g.get("enabled", True) and g.get("steps")]
    if not active:
        return
    due, expired = [], []
    for g in active:
        if g.get("expires_at") and now >= g["expires_at"]:
            g["enabled"] = False
            expired.append(g)
            continue
        if g["kind"] == "interval" and now < g.get("next_run", 0):
            continue
        due.append(g)
    if not (due or expired):
        return
    with _lock:
        current = _load()
        by_id = {g["id"]: g for g in current}
        for g in due:
            live = by_id.get(g["id"])
            if not live or not live.get("enabled", True):
                continue
            _fire(live)
            if live["kind"] == "interval":
                max_runs = (live.get("budget") or {}).get("max_runs") or MAX_RECURRING_RUNS
                if live["run_count"] >= max_runs:
                    live["enabled"] = False
                    live["results"] = (live.get("results", [])
                                       + [{"at": time.time(),
                                           "text": "run budget reached -- "
                                                   "re-create the goal to continue",
                                           "staged": False}])[-MAX_RESULTS_PER_GOAL:]
                else:
                    live["next_run"] = now + (live["interval_s"] or MIN_INTERVAL_S)
            else:
                live["enabled"] = False     # one-shot: prepared once, done
        for g in expired:
            if g["id"] in by_id:
                by_id[g["id"]]["enabled"] = False
        _save(list(by_id.values()))


_thread = None
_thread_lock = threading.Lock()


def _ensure_running():
    global _thread
    with _thread_lock:
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(target=_loop, name="argus-goals",
                                       daemon=True)
            _thread.start()


def _loop():
    while True:
        time.sleep(POLL_INTERVAL)
        try:
            _run_due()
        except Exception as e:
            print(f"[goals] tick failed: {type(e).__name__}: {e}")


def restart_pending():
    """Resume any enabled goal from a previous run. Starts the poll thread
    only if there is actually something to run."""
    goals = _load()
    if any(g.get("enabled", True) for g in goals):
        _ensure_running()


restart_pending()
