"""
ARGUS - Scheduler Skill

Background / recurring / scheduled execution -- "check my disk space every
hour", "look for anomalies every 30 minutes", "check the weather every
morning". This is the one place in ARGUS that runs something WITHOUT the
owner present to approve that specific run, so it is the most tightly
bounded module in the project, not the least.

THE BOUNDARY. A scheduled task may ONLY target a (skill, action) pair
already in router.CHAINABLE -- the narrowest, already-reviewed, strictly
READ-ONLY tier in the whole codebase (system stats, weather, disk space,
anomaly checks, security summary -- never files, power, browser, vision, or
anything that types, clicks, downloads, or spends). router.PLANNABLE, the
WIDER tier the live task planner uses, is deliberately NOT the ceiling
here: PLANNABLE is trusted because a human is watching the plan run right
now and can say stop; nothing is watching a background task fire at 3 a.m.,
so it gets the narrower trust, not the same one.

EVERY RUN GOES THROUGH THE SAME AUTHORIZATION AS A SPOKEN COMMAND.
router.dispatch_known() calls the exact _dispatch() a live utterance uses,
so a scheduled task fired while the machine is LOCKED is refused exactly
the way a stranger's spoken command would be -- there is no separate,
looser execution path for background work. This means most scheduled
checks simply produce nothing while ARGUS is locked, which is correct: it
mirrors the machine's actual security posture rather than working around it.

RESULTS ARE PULLED, NEVER PUSHED. See announce.py's own header for why: "no
detector finding can be announced... what this machine has detected must
not be read aloud to a room." A background task's findings are exactly that
shape of thing, so they land in results() for the owner to ASK for, and at
most a generic, content-free COUNT ("you have 2 results waiting") rides in
through proactive_skill's existing nudge mechanism -- never the findings
themselves, unprompted.

BOUNDED, NOT INDEFINITE. MAX_TASKS caps the queue, MIN_INTERVAL_SECONDS
stops a task from hammering itself, and every recurring task carries a hard
MAX_RECURRING_SECONDS expiry (24h) after which it stops and has to be
re-approved -- an unattended task nobody remembers scheduling, still
running weeks later, is its own kind of risk even if every individual run
is harmless.

Tasks due in the same tick run CONCURRENTLY (a small thread pool) -- safe
because every schedulable action is read-only and independent by
construction. schedule()'s CONTAINS parameter is the one conditional this
module allows: a task still runs on schedule, but only counts toward
results()/the nudge when its own output contains that substring ("check
for anomalies, but only tell me if it finds something") -- not a general
expression evaluator, which would be a second, unreviewed way to run
arbitrary logic.

NOT HERE, on purpose:
  - Retry Engine: retrying an ACTION that failed is a correctness hazard
    independent of the autonomy question -- a step that failed partway
    should not be blindly repeated.
  - Alternative Strategy Engine: choosing a DIFFERENT action than the one
    approved is a decision-making change, not a scheduling one.
  - Event-triggered Task Executor, in the generic sense ("watch for X,
    then run Y" for an arbitrary X): ARGUS already has purpose-built event
    detectors (presencewatch.py, gesturewatch.py, the threatmon USB/tamper
    watchers) that trigger a FIXED, reviewed response each. A generic
    version would be a new, unreviewed capability class layered on top of
    those, which is a bigger and different decision than "let me schedule
    a read-only check" -- worth asking about specifically rather than
    building quietly here.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import re
import threading
import time
import uuid

import paths

_STORE_PATH = paths.writable("scheduled_tasks.json")

MIN_INTERVAL_SECONDS = 60.0
MAX_RECURRING_SECONDS = 24 * 3600.0     # a recurring task auto-expires after this
MAX_TASKS = 20
POLL_INTERVAL = 30.0
MAX_RESULTS_PER_TASK = 5
# A 24-hour expiry is a time bound; this independent run ceiling also prevents
# an unusually short interval (or a clock adjustment) from turning one saved
# schedule into an excessive amount of unattended work.
MAX_RECURRING_RUNS = 144

_lock = threading.Lock()


def _audit(event: str, detail: str, outcome: str) -> None:
    """Lifecycle events are auditable without making persistence depend on it."""
    try:
        import security
        security.audit(event, detail[:120], outcome)
    except Exception:
        pass


def _task_max_runs(task: dict) -> int:
    """Read a stored run budget; old records get the strict safe default."""
    try:
        value = int((task.get("budget") or {}).get("max_runs"))
        if value > 0:
            return value
    except (TypeError, ValueError):
        pass
    return 1 if task.get("kind") == "once" else MAX_RECURRING_RUNS


def _schedulable(skill: str, action: str) -> bool:
    """Lazy + local: router.py imports every skill module at load time,
    including this one, so a module-level `import router` here would be a
    cycle -- same reasoning as intent.py's router_plan_pending() helper."""
    try:
        import router
        return (skill, action) in router.CHAINABLE
    except Exception:
        return False


def _load() -> list:
    try:
        with open(_STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save(tasks: list) -> None:
    try:
        with open(_STORE_PATH, "w", encoding="utf-8") as f:
            json.dump(tasks, f, indent=2)
    except Exception:
        pass


def _find(tasks: list, query: str):
    q = (query or "").strip().lower()
    if not q:
        return None
    for t in tasks:
        if q in t["id"].lower():
            return t
    for t in tasks:
        label = f'{t["skill"]} {t["action"]} {t["target"]}'.lower()
        if q in label:
            return t
    return None


def schedule(skill: str, action: str, target: str, seconds, recurring: bool = False,
            contains: str = "") -> str:
    """CONTAINS, given, is the one conditional this module allows: the task
    still runs on schedule (it has to, to know the answer), but only counts
    toward unread_count()/nudges/results() when its own read-only output
    contains that substring -- "check for anomalies every 10 minutes, but
    only tell me if it finds something" rather than a generic expression
    evaluator, which would be a second, unreviewed way to run arbitrary
    logic. Case-insensitive substring match on the result TEXT only."""
    skill = (skill or "").strip()
    action = (action or "").strip()
    if not _schedulable(skill, action):
        return (f"I only schedule read-only checks -- {skill}/{action} isn't "
                f"one of them. Ask me to do it directly instead.")
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return "How often, or how soon?"
    if recurring and seconds < MIN_INTERVAL_SECONDS:
        return f"The shortest recurring interval I'll accept is {int(MIN_INTERVAL_SECONDS)} seconds."
    if seconds < 1:
        return "That's too soon."

    with _lock:
        tasks = _load()
        tasks = [t for t in tasks if t.get("enabled", True)
                 or time.time() - t.get("created_at", 0) < 3600]  # prune old disabled ones
        if len(tasks) >= MAX_TASKS:
            return f"You already have {MAX_TASKS} scheduled tasks -- cancel one first."
        now = time.time()
        max_runs = (1 if not recurring else min(
            MAX_RECURRING_RUNS,
            max(1, int(MAX_RECURRING_SECONDS / seconds))))
        task = {
            "id": uuid.uuid4().hex[:8],
            "skill": skill, "action": action, "target": target or "",
            "kind": "interval" if recurring else "once",
            "interval_s": seconds if recurring else None,
            "created_at": now,
            "next_run": now + seconds,
            "expires_at": (now + MAX_RECURRING_SECONDS) if recurring else None,
            "enabled": True,
            "contains": (contains or "").strip(),
            # Persistent-goal contract: all values
            # are descriptive constraints derived from the schedule's actual
            # code path, never an alternate permission source.
            "scope": "read_only",
            "allowed_capabilities": [f"{skill}/{action}"],
            "budget": {"max_runs": max_runs, "max_results": MAX_RESULTS_PER_TASK},
            "confirmation_policy": "authorize_each_run",
            "failure_policy": "record_then_wait_for_next_interval",
            "last_run": None,
            "run_count": 0,
            "results": [],
        }
        tasks.append(task)
        _save(tasks)
    _ensure_running()
    _audit("schedule_add", f"{task['id']} {skill}/{action} {task['kind']}", "ok")
    when = f"every {_human_seconds(seconds)}" if recurring else f"in {_human_seconds(seconds)}"
    return f"Scheduled ({task['id']}): {skill} {action} {when}."


def _human_seconds(s: float) -> str:
    s = int(s)
    if s < 60:
        return f"{s} seconds"
    if s < 3600:
        return f"{s // 60} minutes"
    return f"{s / 3600:.1f} hours"


def list_tasks() -> str:
    tasks = _load()
    if not tasks:
        return "No scheduled tasks."
    now = time.time()
    parts = []
    for t in tasks:
        if t.get("terminal_reason"):
            state = f" ({t['terminal_reason']})"
        elif t.get("expires_at") and now >= t["expires_at"]:
            state = " (expired)"
        else:
            state = "" if t.get("enabled", True) else " (paused)"
        when = (f"every {_human_seconds(t['interval_s'])}" if t["kind"] == "interval"
                else "once")
        parts.append(f'{t["id"]}: {t["skill"]} {t["action"]} {when}{state}')
    return "; ".join(parts)


def cancel(query: str) -> str:
    with _lock:
        tasks = _load()
        t = _find(tasks, query)
        if not t:
            return f"I don't have a scheduled task matching {query}." if query else "Cancel which task?"
        tasks = [x for x in tasks if x["id"] != t["id"]]
        _save(tasks)
    _audit("schedule_cancel", f"{t['id']} {t['skill']}/{t['action']}", "ok")
    return f'Cancelled {t["skill"]} {t["action"]} ({t["id"]}).'


def pause(query: str) -> str:
    with _lock:
        tasks = _load()
        t = _find(tasks, query)
        if not t:
            return f"I don't have a scheduled task matching {query}." if query else "Pause which task?"
        t["enabled"] = False
        _save(tasks)
    _audit("schedule_pause", f"{t['id']} {t['skill']}/{t['action']}", "ok")
    return f'Paused {t["skill"]} {t["action"]} ({t["id"]}).'


def resume(query: str) -> str:
    with _lock:
        tasks = _load()
        t = _find(tasks, query)
        if not t:
            return f"I don't have a scheduled task matching {query}." if query else "Resume which task?"
        if t.get("terminal_reason"):
            return (f"That schedule {t['terminal_reason']}; create a new one "
                    f"to run it again.")
        if t.get("expires_at") and time.time() >= t["expires_at"]:
            t.update(enabled=False, terminal_reason="expired")
            _save(tasks)
            _audit("schedule_stop", f"{t['id']} expired", "stopped")
            return "That schedule expired; create a new one to run it again."
        t["enabled"] = True
        if t["kind"] == "interval":
            t["next_run"] = time.time() + (t["interval_s"] or MIN_INTERVAL_SECONDS)
        _save(tasks)
    _ensure_running()
    _audit("schedule_resume", f"{t['id']} {t['skill']}/{t['action']}", "ok")
    return f'Resumed {t["skill"]} {t["action"]} ({t["id"]}).'


def status() -> str:
    tasks = _load()
    if not tasks:
        return "No scheduled tasks."
    now = time.time()
    expired = [t for t in tasks if t.get("expires_at") and now >= t["expires_at"]]
    active = [t for t in tasks if t.get("enabled", True)
              and not t.get("terminal_reason") and t not in expired]
    pending_results = sum(len(t.get("results", [])) for t in tasks)
    finished = sum(1 for t in tasks if t.get("terminal_reason") or t in expired)
    return (f"{len(tasks)} scheduled task{'s' if len(tasks) != 1 else ''}, "
            f"{len(active)} active, {finished} finished, {pending_results} result"
            f"{'s' if pending_results != 1 else ''} waiting.")


def results(query: str = "", limit: int = 5) -> str:
    tasks = _load()
    if query:
        t = _find(tasks, query)
        tasks = [t] if t else []
    lines = []
    for t in tasks:
        for r in t.get("results", [])[-limit:]:
            when = time.strftime("%H:%M", time.localtime(r["at"]))
            lines.append(f'[{when}] {t["skill"]} {t["action"]}: {r["text"]}')
    if not lines:
        return "No results yet." if query else "No results from any scheduled task yet."
    return " | ".join(lines[-limit:])


def unread_count() -> int:
    """For proactive_skill's nudge -- a COUNT only, never the findings
    themselves. See module docstring."""
    tasks = _load()
    return sum(len(t.get("results", [])) for t in tasks)


def mark_read() -> None:
    with _lock:
        tasks = _load()
        for t in tasks:
            t["results"] = []
        _save(tasks)


# ═══════════════════════════════════════════════════════════════════════════
# THE BACKGROUND LOOP
# ═══════════════════════════════════════════════════════════════════════════

_thread = None
_thread_lock = threading.Lock()


def _ensure_running():
    global _thread
    with _thread_lock:
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(target=_loop, name="argus-scheduler", daemon=True)
            _thread.start()


def _loop():
    while True:
        time.sleep(POLL_INTERVAL)
        try:
            _run_due()
        except Exception as e:
            print(f"[scheduler] tick failed: {type(e).__name__}: {e}")


def _run_one(t: dict, now: float) -> dict:
    """Runs ONE due task and returns its updates -- pulled out of _run_due()
    so a tick with several tasks due at once can run them CONCURRENTLY
    (ThreadPoolExecutor below). Safe to parallelize because every
    schedulable action is read-only and independent by construction (that
    is what router.CHAINABLE already means); nothing here writes shared
    state except through the dict this function returns, collected back on
    the calling thread."""
    if t.get("expires_at") and now >= t["expires_at"]:
        return {"enabled": False, "terminal_reason": "expired"}
    if t.get("run_count", 0) >= _task_max_runs(t):
        return {"enabled": False, "terminal_reason": "run budget exhausted"}
    if not _schedulable(t["skill"], t["action"]):
        # The allowlist itself changed since this was scheduled (a future
        # edit narrowed CHAINABLE) -- refuse rather than run something no
        # longer trusted for unattended execution.
        return {"enabled": False, "terminal_reason": "capability no longer allowed"}

    import router  # lazy -- see _schedulable()
    try:
        reply = router.dispatch_known(t["skill"], t["action"], t["target"])
    except Exception as e:
        reply = f"failed: {type(e).__name__}"

    update = {
        "last_run": now,
        "run_count": t.get("run_count", 0) + 1,
        "enabled": t["kind"] == "interval",
    }
    contains = (t.get("contains") or "").strip()
    if not contains or contains.lower() in str(reply).lower():
        results = list(t.get("results", []))
        results.append({"at": now, "text": str(reply)[:300]})
        update["results"] = results[-MAX_RESULTS_PER_TASK:]
    if update["enabled"]:
        update["next_run"] = now + (t["interval_s"] or MIN_INTERVAL_SECONDS)
    return update


def _run_due():
    now = time.time()
    with _lock:
        tasks = _load()
    due = [t for t in tasks if t.get("enabled", True) and t["next_run"] <= now]
    if not due:
        return

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(4, len(due))) as pool:
        updates = list(pool.map(lambda t: _run_one(t, now), due))
    for t, upd in zip(due, updates):
        t.update(upd)
        if upd.get("terminal_reason"):
            _audit("schedule_stop", f"{t['id']} {upd['terminal_reason']}", "stopped")
    changed = True

    if changed:
        with _lock:
            # Re-read-modify-write against the CURRENT file rather than the
            # snapshot taken above, in case schedule()/cancel() ran while
            # this tick was in flight -- last-writer-wins on the whole list
            # is acceptable here (single background thread, and any
            # collision is a schedule() adding a row this tick didn't touch).
            current = _load()
            by_id = {t["id"]: t for t in current}
            for t in due:
                if t["id"] in by_id:
                    by_id[t["id"]].update(t)
            _save(list(by_id.values()))


def restart_pending():
    """Resumes any task that was already scheduled from a previous run, same
    idea as timer_skill's own restart persistence. Cheap (one small JSON
    read) and safe to call on import -- it only starts the poll thread if a
    task is actually enabled, so a fresh install with nothing scheduled
    starts no thread at all."""
    tasks = _load()
    if any(t.get("enabled", True) for t in tasks):
        _ensure_running()


restart_pending()
