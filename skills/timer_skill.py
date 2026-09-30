"""
ARGUS - Timers and reminders.

Previously these were threading.Timer objects and nothing else, which meant a
reminder existed only inside the running process: close ARGUS, reboot, or
crash, and every pending reminder was silently gone. Silently is the problem
-- you don't discover a lost reminder, you just never get reminded, which is
strictly worse than being told up front that it couldn't be set.

Reminders are now written to disk as they're created and reloaded at startup.
A single background thread polls for due ones rather than one Timer thread per
reminder: the poll is trivially cheap at this scale, it survives the process
sleeping (a laptop lid closing mid-timer is the common case, and a Timer's
countdown does not account for suspend), and overdue reminders can be
delivered late rather than lost.

Storage is plain JSON next to the vault, for the same reason the profile is
plain markdown: it can be read, checked and edited by hand.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import threading
import time
from datetime import datetime

from plyer import notification

from config import VAULT_PATH

REMINDERS_PATH = os.path.join(VAULT_PATH, "reminders.json")
POLL_SECONDS = 5
# Fired late rather than dropped, but only within reason -- a reminder that
# came due while the machine was off for a week is noise, not a reminder.
MAX_LATE_SECONDS = 12 * 3600

_lock = threading.RLock()
_started = False


def _load() -> list:
    try:
        with open(REMINDERS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        # A corrupt or missing store must not take the assistant down with it.
        return []


def _save(items: list):
    os.makedirs(VAULT_PATH, exist_ok=True)
    tmp = REMINDERS_PATH + ".tmp"
    # Write-then-replace: a crash partway through a direct write would leave
    # truncated JSON and lose every pending reminder, not just the new one.
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=1)
    os.replace(tmp, REMINDERS_PATH)


def _fire(label: str, late: bool = False):
    msg = label or "Timer done."
    if late:
        msg = f"(missed) {msg}"
    try:
        notification.notify(title="ARGUS", message=msg, timeout=10)
    except Exception as e:
        print(f"[timer] notification failed: {e}")


def _poll():
    while True:
        try:
            now = time.time()
            due, keep = [], []
            with _lock:
                for item in _load():
                    (due if item.get("due", 0) <= now else keep).append(item)
                if due:
                    _save(keep)
            for item in due:
                late = (time.time() - item.get("due", 0)) > POLL_SECONDS * 3
                if time.time() - item.get("due", 0) > MAX_LATE_SECONDS:
                    print(f"[timer] dropped stale reminder: {item.get('label')}")
                    continue
                _fire(item.get("label", ""), late=late)
        except Exception as e:
            print(f"[timer] poll error: {e}")
        # Watchers ride the same thread. Isolated separately so a watcher
        # throwing cannot cost a reminder its delivery, and vice versa.
        try:
            poll_watchers()
        except Exception as e:
            print(f"[watcher] poll error: {e}")
        time.sleep(POLL_SECONDS)


def start():
    """Starts the poller. Safe to call more than once; called at startup so
    reminders saved in a previous session resume without needing a new one."""
    global _started
    with _lock:
        if _started:
            return 0
        _started = True
    threading.Thread(target=_poll, daemon=True).start()
    pending = len(_load())
    if pending:
        print(f"[timer] {pending} reminder(s) restored")
    return pending


# ═══════════════════════════════════════════════════════════════════════════
# WATCHERS: "whenever a PDF lands in Downloads, file it"
# ═══════════════════════════════════════════════════════════════════════════
#
# A reminder is a task with a TIME as its trigger. A watcher is a task with a
# CONDITION as its trigger -- a file appearing, a process starting, a window
# opening. Same poller, same store, same "survives a restart" property, which
# is why this lives here rather than in a module of its own.
#
# THE PERMISSION IS GIVEN ONCE, WHEN THE WATCHER IS CREATED, and that is the
# whole design question. The point of a watcher is that it acts without being
# asked each time; the point of ARGUS is that nothing acts without permission.
# The reconciliation:
#
#   * Creating a watcher is an L2 action -- the owner authenticates and sees
#     the steps in words before it exists. That is the consent.
#   * The steps are FIXED at creation: a validated list of (skill, action,
#     target) from the task loop's own allowlist, replayed verbatim. No model
#     is consulted when a watcher fires, so what runs is exactly what was
#     approved, every time.
#   * Every step STILL passes auth.authorize() when it runs. Creating a
#     watcher is not a standing grant: if ARGUS is locked when the trigger
#     fires, the step is refused, the refusal is reported once, and the
#     watcher keeps watching. It never inherits permission from having been
#     approved earlier -- the same rule the task loop applies to plans.
#
# TEMPLATES, so a step can name the thing that triggered it: {path}, {name},
# {stem}, {ext}, {date} and {time} are substituted into targets at fire time.
# "rename {name} to {date}-{stem}" is the Downloads example, verbatim.
#
# WHAT IS NOT HERE. No loops, no parallel branches, no conditionals inside a
# watcher's steps. A watcher is one trigger and one straight-line action list,
# and the honest reason is that anything richer is a program, and a program
# authored by voice and run unattended is not something this project should
# ship.

WATCHERS_PATH = os.path.join(VAULT_PATH, "watchers.json")
MAX_WATCHERS = 12

# Same shape as MAX_WATCHERS above, watched_skill.MAX_WATCHED_TASKS and
# scheduler_skill.MAX_TASKS -- every other background-task creator in this
# codebase bounds its store; set_timer() was the one left unbounded, an
# unlimited-notification-spam / unbounded-file-growth gap with no backstop.
MAX_TIMERS = 20
WATCH_KINDS = ("folder", "process", "window", "schedule")
# A watcher may execute a fixed, pre-approved plan when it fires. That is more
# powerful than monitor_skill's read-only notification watches, so it must not
# remain armed on the strength of a single, possibly-stale approval forever.
# The hard expiry below enforces that -- but it RENEWS on every successful
# fire (see poll_watchers()), by this same window, measured from that fire.
# So a watcher that keeps proving itself useful (keeps firing successfully)
# stays alive indefinitely in practice, while one that goes quiet -- never
# fires, or fires once and then stops -- hard-expires this many seconds after
# its last real event and requires the owner to create a fresh watch (which
# re-validates the steps against PLANNABLE via add_watcher()'s own
# router.validate_plan() call) rather than silently carrying yesterday's
# intent forward forever.
MAX_WATCHER_SECONDS = 24 * 3600.0
# A watcher that keeps failing is a watcher that keeps doing nothing loudly.
# After this many consecutive failed firings it is paused, not deleted.
MAX_CONSECUTIVE_FAILURES = 5


def _load_watchers() -> list:
    try:
        with open(WATCHERS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save_watchers(items: list):
    os.makedirs(VAULT_PATH, exist_ok=True)
    tmp = WATCHERS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=1)
    os.replace(tmp, WATCHERS_PATH)


def _new_id(items: list) -> int:
    return (max((int(i.get("id", 0)) for i in items), default=0) + 1)


def _watcher_expires_at(w: dict) -> float:
    """Return a watcher's hard expiry; missing legacy data fails closed.

    Old records did not contain a machine-readable epoch. A legacy record is
    allowed only until 24h after its recorded creation timestamp; a malformed
    or absent timestamp is already expired. This prevents an upgrade from
    accidentally granting an existing unattended action watch an unlimited
    new lifetime.
    """
    try:
        expires = float(w.get("expires_at"))
        if expires > 0:
            return expires
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(str(w.get("created", ""))).timestamp() + MAX_WATCHER_SECONDS
    except (TypeError, ValueError):
        return 0.0


def _watcher_expired(w: dict, now: float | None = None) -> bool:
    return (now if now is not None else time.time()) >= _watcher_expires_at(w)


def _fill(template: str, ctx: dict) -> str:
    """Substitute {path}, {name}, {stem}, {ext}, {date}, {time}. Unknown
    braces are left alone rather than raising -- a typo in a template must not
    crash the poller for every other watcher."""
    out = str(template or "")
    for k, v in ctx.items():
        out = out.replace("{" + k + "}", str(v))
    return out


def add_watcher(kind: str, subject: str, steps: list, label: str = "",
                pattern: str = "") -> str:
    """Create a watcher. Steps are validated by the task loop's allowlist.

    Late import of router: it imports this module, so a top-level import would
    be a cycle. validate_plan() is the SAME function plans go through, so a
    watcher can contain exactly what a plan can and nothing more -- power,
    deletion, repair and dictation are refused here for the same reason.
    """
    kind = (kind or "").strip().lower()
    if kind not in WATCH_KINDS:
        return f"I can watch a folder, a process, a window, or a time — not {kind}."
    subject = (subject or "").strip()
    if not subject:
        return "What should I watch?"
    try:
        import router
        clean, refusal = router.validate_plan(steps)
    except Exception as e:
        return f"I couldn't check those steps ({type(e).__name__})."
    if refusal:
        return refusal

    if kind == "folder":
        from skills import files_skill
        try:
            subject = files_skill._resolve_folder(subject)
        except files_skill.FileOpError as e:
            return str(e)
    if kind == "schedule":
        # "HH:MM" every day. Anything else is a reminder, which already exists.
        import re
        if not re.fullmatch(r"\d{1,2}:\d{2}", subject):
            return "Give me a time as HH:MM and I'll run it every day at that time."

    with _lock:
        items = _load_watchers()
        if len(items) >= MAX_WATCHERS:
            return (f"I'm already watching {MAX_WATCHERS} things. Remove one "
                    f"first.")
        wid = _new_id(items)
        now = time.time()
        items.append({
            "id": wid, "kind": kind, "subject": subject,
            "pattern": (pattern or "*").strip() or "*",
            "label": (label or f"{kind} {os.path.basename(subject) or subject}")[:60],
            "steps": clean,
            "created": datetime.now().isoformat(timespec="seconds"),
            "expires_at": now + MAX_WATCHER_SECONDS,
            "seen": [],              # folder: names already handled
            "last_fired": 0.0, "fires": 0, "failures": 0, "paused": False,
            "last_result": "",
        })
        _save_watchers(items)
    start()
    try:
        import security
        security.audit("watcher_add", f"#{wid} {kind} {subject[:40]} "
                                      f"{len(clean)} steps", "ok")
    except Exception:
        pass
    desc = "; ".join(f"{s['skill']} {s['action']}"
                     + (f" {s['target'][:30]}" if s.get("target") else "")
                     for s in clean)
    return (f"Watching. Whenever that happens I'll {desc}. Say \"stop "
            f"watching {wid}\" to remove it.")


def list_watchers() -> str:
    items = _load_watchers()
    if not items:
        return "I'm not watching anything."
    bits = []
    for w in items:
        if _watcher_expired(w):
            state = "expired"
        else:
            state = "paused" if w.get("paused") else f"fired {w.get('fires', 0)}x"
        bits.append(f"#{w['id']} {w['label']} ({state})")
    return f"{len(items)} watcher{'s' if len(items) != 1 else ''}: " + "; ".join(bits) + "."


def remove_watcher(ident: str) -> str:
    q = (ident or "").strip().lower()
    with _lock:
        items = _load_watchers()
        keep = []
        removed = None
        for w in items:
            if removed is None and (q == str(w.get("id")) or q in w.get("label", "").lower()):
                removed = w
                continue
            keep.append(w)
        if removed is None:
            return f"I don't have a watcher matching {ident}."
        _save_watchers(keep)
    return f"Stopped watching {removed['label']}."


def pause_watcher(ident: str, paused: bool = True) -> str:
    q = (ident or "").strip().lower()
    with _lock:
        items = _load_watchers()
        for w in items:
            if q == str(w.get("id")) or q in w.get("label", "").lower():
                w["paused"] = bool(paused)
                if not paused:
                    w["failures"] = 0
                _save_watchers(items)
                return (f"{'Paused' if paused else 'Resumed'} {w['label']}.")
    return f"I don't have a watcher matching {ident}."


def watcher_status() -> str:
    """Progress reporting: what fired, when, and whether it worked."""
    items = _load_watchers()
    if not items:
        return "I'm not watching anything."
    bits = []
    for w in items:
        if _watcher_expired(w):
            bits.append(f"#{w['id']} {w['label']}: expired; create a new watch to continue")
            continue
        if w.get("last_fired"):
            ago = int((time.time() - w["last_fired"]) / 60)
            when = "just now" if ago < 1 else f"{ago} minutes ago"
            bits.append(f"#{w['id']} {w['label']}: last fired {when}, "
                        f"{w.get('last_result', '')[:60]}")
        else:
            bits.append(f"#{w['id']} {w['label']}: hasn't fired yet")
    return " ".join(bits)


# ── triggers ─────────────────────────────────────────────────────────────────
def _folder_events(w: dict) -> list:
    """New files matching the pattern since last look. Returns contexts."""
    import fnmatch
    folder = w.get("subject", "")
    if not os.path.isdir(folder):
        return []
    seen = set(w.get("seen") or [])
    out = []
    try:
        entries = list(os.scandir(folder))
    except OSError:
        return []
    now = time.time()
    names_now = set()
    for e in entries:
        try:
            if not e.is_file():
                continue
            names_now.add(e.name)
            if e.name in seen:
                continue
            if not fnmatch.fnmatch(e.name.lower(), (w.get("pattern") or "*").lower()):
                continue
            st = e.stat()
            # A file still being written is not a file that has arrived. Wait
            # until it has stopped changing for a few seconds -- otherwise the
            # watcher moves a half-downloaded PDF and the download fails.
            if now - st.st_mtime < 4:
                continue
            if e.name.lower().endswith((".crdownload", ".part", ".tmp")):
                continue
            stem, ext = os.path.splitext(e.name)
            out.append({"path": e.path, "name": e.name, "stem": stem,
                        "ext": ext.lstrip("."), "date": time.strftime("%Y-%m-%d"),
                        "time": time.strftime("%H-%M")})
        except OSError:
            continue
    # Forget names that have gone, so the seen-list cannot grow forever.
    w["seen"] = sorted((seen & names_now) | {c["name"] for c in out})
    return out


def _process_event(w: dict) -> list:
    """The named process is running and was not at the last look."""
    want = (w.get("subject") or "").lower().removesuffix(".exe")
    running = False
    try:
        import psutil
        for p in psutil.process_iter(["name"]):
            n = (p.info.get("name") or "").lower().removesuffix(".exe")
            if n == want:
                running = True
                break
    except Exception:
        return []
    was = bool(w.get("_running"))
    w["_running"] = running
    if running and not was:
        return [{"name": want, "date": time.strftime("%Y-%m-%d"),
                 "time": time.strftime("%H-%M"), "path": "", "stem": want, "ext": ""}]
    return []


def _window_event(w: dict) -> list:
    """A window whose title contains the subject is now in the foreground."""
    want = (w.get("subject") or "").lower()
    try:
        from skills import pc_skill
        fw = pc_skill.focused_window()
    except Exception:
        return []
    title = (fw or {}).get("title", "").lower()
    hit = bool(want) and want in title
    was = bool(w.get("_front"))
    w["_front"] = hit
    if hit and not was:
        return [{"name": (fw or {}).get("title", "")[:60], "path": "",
                 "stem": "", "ext": "", "date": time.strftime("%Y-%m-%d"),
                 "time": time.strftime("%H-%M")}]
    return []


def _schedule_event(w: dict) -> list:
    """Once a day, at HH:MM."""
    try:
        hh, mm = (int(x) for x in w.get("subject", "0:0").split(":"))
    except ValueError:
        return []
    now = datetime.now()
    today_key = now.strftime("%Y-%m-%d")
    if w.get("_last_day") == today_key:
        return []
    if (now.hour, now.minute) >= (hh, mm):
        w["_last_day"] = today_key
        return [{"name": w.get("label", ""), "path": "", "stem": "", "ext": "",
                 "date": today_key, "time": now.strftime("%H-%M")}]
    return []


_TRIGGERS = {"folder": _folder_events, "process": _process_event,
             "window": _window_event, "schedule": _schedule_event}


def _fire_watcher(w: dict, ctx: dict) -> str:
    """Replay the fixed steps for one event. Every step through the gate."""
    import router
    done, failure = 0, ""
    for step in w.get("steps") or []:
        d = {"skill": step["skill"], "action": step["action"],
             "target": _fill(step.get("target", ""), ctx)}
        try:
            reply = router._dispatch(d, f"watcher {w.get('id')}", None)
        except Exception as e:
            failure = f"{type(e).__name__}"
            break
        text = str(reply or "").strip()
        if not text or router._STEP_FAILED.search(text):
            failure = text[:120] or "no reply"
            break
        done += 1
    total = len(w.get("steps") or [])
    if failure:
        return f"stopped at step {done + 1} of {total}: {failure}"
    return f"done, {done} step{'s' if done != 1 else ''}"


def poll_watchers() -> int:
    """One pass over every watcher. Called from the reminder poller. Returns
    how many fired. Never raises -- one broken watcher must not stop the rest
    or the reminders sharing the thread."""
    fired = 0
    with _lock:
        items = _load_watchers()
    if not items:
        return 0
    changed = False
    now = time.time()
    for w in items:
        if w.get("paused"):
            continue
        if _watcher_expired(w, now):
            # Store a visible terminal state and audit it once. It is paused,
            # not removed, so the owner can inspect what expired and choose to
            # recreate it deliberately.
            w["paused"] = True
            w["last_result"] = "expired — create a new watch to continue"
            changed = True
            try:
                import security
                security.audit("watcher_expired", f"#{w.get('id')} {w.get('label', '')[:40]}",
                               "expired")
            except Exception:
                pass
            continue
        fn = _TRIGGERS.get(w.get("kind"))
        if not fn:
            continue
        try:
            events = fn(w)
        except Exception as e:
            print(f"[watcher] #{w.get('id')} trigger error: {type(e).__name__}")
            continue
        if not events:
            continue
        for ctx in events[:5]:                 # a burst is capped per pass
            result = _fire_watcher(w, ctx)
            fired += 1
            changed = True
            w["last_fired"] = time.time()
            w["fires"] = int(w.get("fires", 0)) + 1
            w["last_result"] = result
            ok = result.startswith("done")
            if ok:
                # Renew the hard expiry from THIS success rather than from
                # creation, by updating the stored field directly instead of
                # changing how _watcher_expires_at() computes things at read
                # time -- that keeps its "legacy record, no expires_at"
                # fallback meaning what it says (old data) instead of being
                # overloaded to also mean "last success". A FAILED fire must
                # NOT land here: expiry is the independent backstop for a
                # watcher that has gone quiet (never fires, or stops firing),
                # separate from MAX_CONSECUTIVE_FAILURES below, which is the
                # circuit breaker for one that is actively failing. Letting a
                # failed fire renew expiry would blur the two -- a watcher
                # that is broken every time would keep re-arming its own
                # license to keep trying instead of eventually hard-expiring.
                w["expires_at"] = time.time() + MAX_WATCHER_SECONDS
            w["failures"] = 0 if ok else int(w.get("failures", 0)) + 1
            try:
                import security
                security.audit("watcher_fire",
                               f"#{w.get('id')} {ctx.get('name', '')[:40]} -> {result[:50]}",
                               "ok" if ok else "failed")
            except Exception:
                pass
            if w["failures"] >= MAX_CONSECUTIVE_FAILURES:
                w["paused"] = True
                print(f"[watcher] #{w.get('id')} paused after "
                      f"{MAX_CONSECUTIVE_FAILURES} failures")
    # Persist seen-lists and counters; the transient _running/_front/_last_day
    # keys are saved too, which is harmless and keeps a restart from re-firing
    # a schedule that already ran today.
    if changed or any(k in w for w in items for k in ("seen",)):
        with _lock:
            _save_watchers(items)
    return fired


def _human(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds} seconds"
    if seconds < 3600:
        return f"{seconds // 60} minutes"
    hours = seconds / 3600
    return f"{hours:.0f} hours" if hours >= 2 else "an hour"


def set_timer(seconds: int, label: str) -> str:
    if seconds <= 0:
        return "That timer duration didn't make sense — try again with a clear amount of time."
    start()
    item = {
        "due": time.time() + seconds,
        "label": (label or "Timer done.").strip(),
        "created": datetime.now().isoformat(timespec="seconds"),
    }
    with _lock:
        items = _load()
        if len(items) >= MAX_TIMERS:
            return (f"You already have {MAX_TIMERS} timers pending -- "
                    f"let one finish or cancel one before setting another.")
        items.append(item)
        _save(items)
    return f"Timer set for {_human(seconds)}."


def soonest_due_within(seconds: int):
    """The single soonest reminder due within the next `seconds`, as a raw
    dict ({"due": epoch, "label": str}), or None. list_pending() returns a
    spoken-friendly STRING, which proactive_skill can't do arithmetic on --
    this exists so a caller can compute "in about N minutes" itself rather
    than parsing one back out of prose.
    """
    now = time.time()
    upcoming = [i for i in _load() if now <= i.get("due", 0) <= now + seconds]
    if not upcoming:
        return None
    return min(upcoming, key=lambda i: i["due"])


def list_pending() -> str:
    items = sorted(_load(), key=lambda i: i.get("due", 0))
    if not items:
        return "You have no reminders set."
    now = time.time()
    parts = []
    for item in items[:6]:
        left = max(0, int(item.get("due", 0) - now))
        parts.append(f"{item.get('label', 'reminder')} in {_human(left)}")
    extra = f", and {len(items) - 6} more" if len(items) > 6 else ""
    return "Pending: " + "; ".join(parts) + extra + "."


def cancel(query: str = "") -> str:
    with _lock:
        items = _load()
        if not items:
            return "There are no reminders to cancel."
        q = (query or "").strip().lower()
        if not q or q in ("all", "everything", "them all"):
            _save([])
            return f"Cancelled all {len(items)} reminder{'s' if len(items) > 1 else ''}."
        kept = [i for i in items if q not in i.get("label", "").lower()]
        removed = len(items) - len(kept)
        if not removed:
            return f"I couldn't find a reminder matching {query}."
        _save(kept)
        return f"Cancelled {removed} reminder{'s' if removed > 1 else ''}."
