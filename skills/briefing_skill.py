"""
ARGUS - The wake briefing: what you missed, said out loud.

The behaviour this implements is the one shown in a reference video:
an assistant that greets you knowing something about you -- "you woke up late
today" -- rather than reciting a fixed line, and can tell you what happened
while you were away.

WHERE "LATE" COMES FROM. Nothing is guessed and nothing is hardcoded. ARGUS
records the hour it starts each session and keeps the last SESSION_HISTORY of
them; "late" means later than the MEDIAN of your own previous starts by more
than LATE_MARGIN_H hours. The median, not the mean, because one 3am debugging
session should not move the baseline for a week. Until MIN_SESSIONS starts have
been recorded there is no baseline and the briefing simply does not comment on
timing -- an assistant that says "you're late" on day one, having never seen
you before, is guessing and sounds it.

WHAT IT COMPOSES. Nothing here re-implements a capability; it reads what ARGUS
already knows and writes one spoken paragraph:
  * how long you were away, and whether this start is unusual for you
  * threat detections recorded since your last session (threatmon)
  * anything the machine wants you to know (disk pressure, battery)
It is deliberately SHORT. This is read aloud on wake, so it is two or three
sentences, not a report -- the failure mode of a briefing feature is that it
becomes something you talk over.

LOCAL ONLY. Every input is local state. The optional headline line is the one
outward-facing part and is off unless asked for, because a machine that reaches
the internet the instant it wakes is a different privacy posture than one that
does not.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import re
import time

import paths

SESSION_HISTORY = 30        # starts kept for the "usual for you" baseline
MIN_SESSIONS = 5            # below this there is no baseline worth quoting
LATE_MARGIN_H = 1.5         # hours past your median start before it is "late"
AWAY_MIN_H = 3.0            # below this, "while you were away" is not a thing

STORE_OVERRIDE = None       # tests point this at a temp file


def _store_path():
    return STORE_OVERRIDE or paths.writable("sessions.json")


def _load() -> dict:
    try:
        with open(_store_path(), encoding="utf-8") as fh:
            d = json.load(fh)
        if isinstance(d, dict) and isinstance(d.get("starts"), list):
            return d
    except (OSError, ValueError):
        pass
    return {"starts": [], "last_end": 0.0}


def _save(d: dict) -> bool:
    try:
        path = _store_path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(d, fh, separators=(",", ":"))
        os.replace(tmp, path)
        return True
    except OSError:
        return False


def _median(vals):
    s = sorted(vals)
    n = len(s)
    if not n:
        return None
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2.0


def record_start(now: float = None) -> dict:
    """Called once per session. Returns what it learned about this start."""
    now = now if now is not None else time.time()
    d = _load()
    prev = list(d["starts"])
    last = prev[-1] if prev else 0.0

    d["starts"] = (prev + [now])[-SESSION_HISTORY:]
    _save(d)

    hours_away = (now - last) / 3600.0 if last else 0.0
    hour_now = time.localtime(now).tm_hour + time.localtime(now).tm_min / 60.0
    baseline = None
    if len(prev) >= MIN_SESSIONS:
        hours = [time.localtime(t).tm_hour + time.localtime(t).tm_min / 60.0
                 for t in prev]
        baseline = _median(hours)

    verdict = "unknown"
    if baseline is not None:
        if hour_now > baseline + LATE_MARGIN_H:
            verdict = "late"
        elif hour_now < baseline - LATE_MARGIN_H:
            verdict = "early"
        else:
            verdict = "usual"
    return {"hour": hour_now, "baseline": baseline, "verdict": verdict,
            "hours_away": hours_away, "sessions_known": len(prev),
            # The previous session's start, carried so situation() can ask
            # "did the machine reboot since he was last here" without loading
            # the store a second time.
            "previous_start": last}


def current_info(now: float = None) -> dict:
    """The same shape as record_start(), computed WITHOUT recording a start.

    This is what an on-demand "what did I miss" uses. Calling record_start()
    there would append a timestamp that is not a session start at all, and the
    "usual for you" baseline is a median over exactly those timestamps -- so
    asking the question repeatedly would teach ARGUS that you habitually start
    at whatever times you happened to ask, and the answer would drift toward
    always saying "usual".
    """
    now = now if now is not None else time.time()
    starts = _load().get("starts") or []
    last = starts[-1] if starts else 0.0
    hour_now = time.localtime(now).tm_hour + time.localtime(now).tm_min / 60.0
    baseline = None
    if len(starts) >= MIN_SESSIONS:
        hours = [time.localtime(t).tm_hour + time.localtime(t).tm_min / 60.0
                 for t in starts]
        baseline = _median(hours)
    verdict = "unknown"
    if baseline is not None:
        if hour_now > baseline + LATE_MARGIN_H:
            verdict = "late"
        elif hour_now < baseline - LATE_MARGIN_H:
            verdict = "early"
        else:
            verdict = "usual"
    return {"hour": hour_now, "baseline": baseline, "verdict": verdict,
            "hours_away": (now - last) / 3600.0 if last else 0.0,
            "sessions_known": len(starts),
            "previous_start": last}


def _timing_phrase(info: dict) -> str:
    v = info.get("verdict")
    if v == "late":
        return "You're up later than you usually are."
    if v == "early":
        return "You're up earlier than usual."
    return ""


def _away_phrase(info: dict) -> str:
    h = info.get("hours_away") or 0
    if h < AWAY_MIN_H:
        return ""
    if h < 24:
        return f"You've been away about {int(round(h))} hours."
    days = h / 24.0
    return f"You've been away about {int(round(days))} day{'s' if round(days) != 1 else ''}."


def _since_last_detections(since: float) -> str:
    """Threat detections recorded since SINCE. Reads threatmon's own buffer --
    it does not re-scan, so this is free and cannot disturb a detector."""
    try:
        import threatmon
        recent = threatmon.recent(40)
    except Exception:
        return ""
    if not recent:
        return ""
    fresh = []
    for r in recent:
        try:
            ts = time.mktime(time.strptime(r.get("ts", ""), "%Y-%m-%dT%H:%M:%S"))
        except Exception:
            continue
        if ts >= since:
            fresh.append(r)
    if not fresh:
        return ""
    high = [r for r in fresh if r.get("severity") in ("critical", "high")]
    if high:
        lead = high[0]
        return (f"While you were away I flagged {len(high)} thing"
                f"{'s' if len(high) != 1 else ''} worth your attention — "
                f"{lead.get('detector', 'a detector')} caught "
                f"{lead.get('name', 'something')}.")
    return (f"{len(fresh)} low-level detection"
            f"{'s' if len(fresh) != 1 else ''} while you were away, nothing urgent.")


# ── situational awareness ────────────────────────────────────────────────────
#
# "Every time I open it, it must be smart."
#
# The complaint behind that is precise, and it is not about the greeting's
# wording. brief() above only ever spoke when something was UNUSUAL -- a late
# start, a long absence, a full disk -- so on the ordinary launch, which is
# most of them, it returned "" and ARGUS greeted him knowing nothing. An
# assistant that has been watching the machine all day and opens with "hello"
# is indistinguishable from one that just booted.
#
# So this collects what ARGUS can cheaply and locally know at the moment of
# waking, and RANKS it. The ranking is the whole design: the briefing stays two
# or three sentences (see brief()'s own note on why -- a briefing you talk over
# is a briefing that gets muted), so the question is never "what could I say"
# but "of everything true right now, which one or two matter most".
#
# EVERY INPUT IS ALREADY-KNOWN LOCAL STATE. Nothing here scans, probes, or
# reaches the network: psutil counters the sampler already reads, threatmon's
# existing buffer, the reminder file, the session file. Waking up must not cost
# a burst of work, and a machine that opens sockets the instant it wakes is a
# different privacy posture than one that does not.

# Rank bands. Lower sorts first, and the bands are meaningful rather than
# arbitrary: everything in band 0 is something he would be annoyed to discover
# later, everything in band 5 is pleasant continuity he loses nothing by
# missing.
_URGENT = 0        # a detection, or an action staged and waiting on him
_HURTING = 1       # the machine needs something now
_CHANGED = 2       # the world is not how he left it
_COMMITTED = 3     # something he asked for is coming due
_RHYTHM = 4        # timing and absence -- the original briefing
_CONTINUITY = 5    # what he was in the middle of

# A reminder further out than this is not news at wake time.
_SOON_S = 90 * 60

# Below this, "here's what you were doing" is telling him something he has not
# had time to forget. See _continuity_note().
CONTINUITY_MIN_H = 1.0


def _note(rank: int, kind: str, say: str) -> dict:
    return {"rank": rank, "kind": kind, "say": say}


def _urgent_notes(info: dict) -> list:
    """Detections, and anything staged waiting on a decision."""
    out = []

    # Staged actions FIRST, and this is the one that would genuinely bite: a
    # shutdown or a delete confirmed by PIN outlives a restart of the voice
    # process, so it is entirely possible to open ARGUS with one already armed
    # and no memory of arming it. Saying nothing there is the worst option.
    try:
        from skills import power_skill
        if power_skill.has_pending():
            out.append(_note(_URGENT, "staged_power",
                             "There's still a power request waiting on your "
                             "PIN — say cancel if you don't want it."))
    except Exception:
        pass
    try:
        from skills import files_skill
        if files_skill.has_pending_delete():
            out.append(_note(_URGENT, "staged_delete",
                             "There's a file deletion staged and waiting on "
                             "confirmation."))
    except Exception:
        pass

    since = time.time() - max(info.get("hours_away", 0), 0) * 3600
    det = _since_last_detections(since) if info.get("hours_away", 0) else ""
    if det:
        out.append(_note(_URGENT, "detections", det))
    return out


def _hurting_notes() -> list:
    """The machine asking for something.

    One threshold per condition, defined once here. The previous version of
    this lived in a separate _machine_phrase() that brief() appended after
    everything else, which meant a full disk was always the LAST thing said
    and a 97-percent-full drive lost to a remark about the hour. Ranked
    alongside everything else, it competes on how much it matters.
    """
    out = []
    try:
        import psutil
    except Exception:
        return out

    try:
        disk = psutil.disk_usage("C:\\").percent
        if disk >= 90:
            out.append(_note(_HURTING, "disk",
                             f"Your disk is {int(disk)} percent full."))
    except Exception:
        pass
    try:
        batt = psutil.sensors_battery()
        if batt and not batt.power_plugged and batt.percent <= 25:
            out.append(_note(_HURTING, "battery",
                             f"You're on battery and down to "
                             f"{int(batt.percent)} percent."))
    except Exception:
        pass
    try:
        mem = psutil.virtual_memory().percent
        if mem >= 90:
            out.append(_note(_HURTING, "memory",
                             f"Memory is at {int(mem)} percent — something is "
                             f"holding a lot of it."))
    except Exception:
        pass
    return out


def _changed_notes(info: dict) -> list:
    """Ways the machine is not how he left it.

    A REBOOT IS WORTH RAISING, because it silently invalidates everything else
    he believes about the session: what was open is gone, and an unexpected
    restart is also how a crash, a forced update, or something worse presents
    itself. Read from the OS boot time, not from ARGUS's own uptime -- ARGUS
    restarting is not the machine restarting, and conflating them would report
    a reboot every time the app was relaunched.

    THE WINDOW IS THE ABSENCE, NOT THE SESSION FILE, and the difference is a
    bug observed during verification. Comparing the boot time against the previous
    recorded session START reports a reboot that happened at any point since
    that timestamp -- so relaunching ARGUS twelve minutes after using it
    announced a restart from two days earlier as news. What makes a reboot news
    is that it happened WHILE HE WAS GONE, so the comparison is against the
    start of the absence, and a quick relaunch has no window for anything to
    have happened in.
    """
    out = []
    hours_away = max(0.0, float(info.get("hours_away") or 0.0))
    if not hours_away:
        return out                      # first ever session: nothing to compare
    away_started = time.time() - hours_away * 3600
    try:
        import psutil
        booted = psutil.boot_time()
    except Exception:
        return out
    if booted > away_started:
        hours = max(0.0, (time.time() - booted) / 3600.0)
        when = (f"{int(round(hours * 60))} minutes ago" if hours < 1
                else f"about {int(round(hours))} hours ago")
        out.append(_note(_CHANGED, "reboot",
                         f"The machine restarted {when} — you weren't here for it."))
    return out


def _committed_notes() -> list:
    """Reminders he set that are about to come due. His own commitments are
    the least surprising thing to be reminded of and the easiest to have
    forgotten across a restart."""
    out = []
    try:
        from skills import timer_skill
        soon = timer_skill.soonest_due_within(_SOON_S)
    except Exception:
        return out
    if not soon:
        return out
    left = max(0, int(soon.get("due", 0) - time.time()))
    mins = int(round(left / 60.0))
    when = "in under a minute" if mins <= 0 else f"in about {mins} minutes"
    out.append(_note(_COMMITTED, "reminder",
                     f"You've got '{soon.get('label', 'a reminder')}' {when}."))
    return out


def _continuity_note(info: dict) -> dict | None:
    """What he was in the middle of last time.

    Quoted back verbatim rather than summarised. Summarising needs a model
    call on the wake path -- which is the one path where latency is most
    visible -- and a paraphrase of his own words read back to him is worse
    than the words.

    ONLY AFTER A REAL GAP. Told what he said twelve minutes ago, he already
    knows; the line is only worth its second of speech once he has been away
    long enough to have lost the thread. The upper bound needs no check here
    because history_store expires its transcript after six hours, so the
    window this can fire in is roughly one to six hours -- narrow, but that is
    exactly the span where re-anchoring helps and outside it the line would be
    either redundant or archaeology.
    """
    if float(info.get("hours_away") or 0.0) < CONTINUITY_MIN_H:
        return None
    try:
        from skills import history_store
        msgs = history_store.load(20)
    except Exception:
        return None
    for m in reversed(msgs):
        if m.get("role") != "user":
            continue
        text = (m.get("content") or "").strip()
        # Long enough to have been about something. A trailing "thanks" or
        # "stop" is not what he was working on.
        if len(text.split()) < 4:
            continue
        return _note(_CONTINUITY, "continuity",
                     f"Last thing you had me on was \"{text[:90]}\".")
    return None


def situation(info: dict = None) -> list:
    """Everything worth possibly saying at wake time, ranked, best first.

    Returns a list of {"rank", "kind", "say"}. Deliberately returns the whole
    ranked set rather than a sentence: brief() decides how much to speak, the
    HUD may want more of it, and a test can assert on the ranking directly
    instead of on prose.
    """
    if info is None:
        info = current_info()

    notes = []
    for producer in (lambda: _urgent_notes(info),
                     _hurting_notes,
                     lambda: _changed_notes(info),
                     _committed_notes):
        try:
            notes.extend(producer() or [])
        except Exception:
            # One broken producer must not cost the whole briefing. This runs
            # on the wake path; a traceback here means ARGUS greets in silence.
            continue

    timing = _timing_phrase(info)
    if timing:
        notes.append(_note(_RHYTHM, "timing", timing))
    away = _away_phrase(info)
    if away:
        notes.append(_note(_RHYTHM, "away", away))

    try:
        cont = _continuity_note(info)
        if cont:
            notes.append(cont)
    except Exception:
        pass

    notes.sort(key=lambda n: n["rank"])
    return notes


# How many ranked notes actually get spoken. Two, and the third only when it
# is the CONTINUITY line -- "you were in the middle of X" is what turns a
# status readout back into a conversation, and it is short. Three status facts
# in a row is a bulletin, which is the failure mode this whole module's header
# warns about.
_SPEAK_MAX = 2


def brief(info: dict = None, include_detections: bool = True) -> str:
    """The spoken wake briefing. Returns "" when there is nothing worth saying.

    Returning empty is still a real outcome on a genuinely quiet launch --
    inventing filler is how a feature like this becomes noise the user talks
    over. What CHANGED is that "quiet" is now judged against everything ARGUS
    actually knows (see situation()) rather than against three hardcoded
    conditions, so the ordinary launch usually does have something true and
    useful to lead with instead of falling silent by default.
    """
    if info is None:
        info = record_start()

    notes = situation(info)
    if not include_detections:
        # The caller has said detections are not theirs to speak (the on-demand
        # path, where they are reported separately). Dropping them here rather
        # than never collecting them keeps situation() one function with one
        # meaning.
        notes = [n for n in notes if n["kind"] != "detections"]

    # AWAY and TIMING are two halves of the same observation, and speaking both
    # is how the old version produced "You're up later than usual. You've been
    # away about 9 hours." -- two sentences that a person would have said as
    # one. Keep whichever ranks first and drop the other.
    seen_rhythm = False
    kept = []
    for n in notes:
        if n["kind"] in ("timing", "away"):
            if seen_rhythm:
                continue
            seen_rhythm = True
        kept.append(n)

    spoken = [n for n in kept if n["kind"] != "continuity"][:_SPEAK_MAX]
    cont = next((n for n in kept if n["kind"] == "continuity"), None)
    if cont and len(spoken) < _SPEAK_MAX + 1:
        spoken.append(cont)
    return " ".join(n["say"] for n in spoken)


# ── self-review ──────────────────────────────────────────────────────────────
#
# "What did I get wrong today?" -- ARGUS reading back its own conversation and
# finding the things it did not understand.
#
# IT REPORTS. IT DOES NOT REWRITE ITSELF. The tempting version of this is an
# assistant that notices a failure, edits its own routing rules and tells you
# next morning that it has "evolved". That is an AI modifying the code that
# governs the AI, which is the one thing this project's rules forbid outright,
# and it would do it by editing files the integrity manifest signs -- so the
# first thing a self-improving ARGUS would learn is how to break its own boot.
#
# The honest version is more useful anyway. ARGUS cannot tell whether a new
# regex is CORRECT; you can. So it finds the phrasings that fell through and
# hands you the list, which is exactly the raw material for fixing them -- and
# every fix stays a reviewed change rather than an overnight mutation.
#
# HOW A FAILURE IS RECOGNISED, without new logging: re-run each thing you
# actually said through intent.match(). Nothing matching is not itself a
# failure -- chat is the correct destination for a question. The signal is a
# phrasing that LOOKS like an instruction and reached nothing, plus replies
# where ARGUS said outright that it could not do something.
#
# ITS HONEST LIMIT: this finds phrasings that reach NOTHING, not ones that
# reach the WRONG place. "Rotate my screen" routes to vision/describe because
# it contains "my screen", so it looks handled here and is not reported --
# a mis-route is invisible to a check that only asks whether something
# matched. Catching those needs a reply you judged wrong, which is the
# `refused` half, and beyond that it needs you.

_REVIEW_MAX = 60

# A QUESTION, recognised so that everything else can be treated as an
# instruction. This is inverted on purpose, and the first version got it
# wrong in a way worth recording: it listed the verbs ARGUS supports and
# checked for those. But a routing gap is BY DEFINITION a verb ARGUS does not
# support -- "defragment my drive", "rotate my screen" -- so a detector built
# from the supported vocabulary can never see one. It reported a clean sheet
# every day while missing every real gap.
#
# Questions reaching the model are the system working. So: not a question,
# and it did not route, and it is long enough not to be "thanks" -- that is
# an instruction ARGUS had no answer for.
_QUESTION = re.compile(
    r"^(?:what|who|whom|whose|where|when|why|how|which|is|are|was|were|do|"
    r"does|did|can|could|should|would|will|shall|may|might|am)\b", re.I)
_MIN_GAP_WORDS = 3          # below this it is a greeting, not an instruction


def _looks_like_instruction(text: str) -> bool:
    t = (text or "").strip()
    if t.endswith("?") or _QUESTION.match(t):
        return False
    return len(t.split()) >= _MIN_GAP_WORDS

# Replies that mean ARGUS declined or could not act. Matched loosely on
# purpose: a false positive here costs one extra line in a report you are
# reading anyway, and a miss costs the gap staying invisible.
_FAILED_REPLY = re.compile(
    r"\b(?:i (?:don'?t|do not|can'?t|cannot|couldn'?t|could not) "
    r"(?:see|find|know|do|open|reach|understand|help)|"
    r"i'?m not (?:able|sure how)|not sure how to help|unable to|"
    r"didn'?t work|that didn'?t|i don'?t have a|no such|couldn'?t find)\b",
    re.I)


def review(max_items: int = _REVIEW_MAX) -> dict:
    """What ARGUS did not understand, from its own transcript.

    Pure with respect to the transcript it is handed, so the classification
    can be tested against fabricated conversations rather than whatever
    happens to be in today's history.
    """
    try:
        from skills import history_store
        msgs = history_store.load(max_items)
    except Exception:
        msgs = []

    try:
        import intent
    except Exception:
        intent = None

    unrouted, refused, seen = [], [], set()
    for i, m in enumerate(msgs):
        if m.get("role") != "user":
            continue
        text = (m.get("content") or "").strip()
        if not text or len(text) < 3:
            continue
        key = text.lower()

        # The reply that followed, if there was one.
        reply = ""
        if i + 1 < len(msgs) and msgs[i + 1].get("role") == "assistant":
            reply = (msgs[i + 1].get("content") or "").strip()

        matched = None
        if intent is not None:
            try:
                matched = intent.match(text)
            except Exception:
                matched = None

        if not matched and _looks_like_instruction(text) and key not in seen:
            seen.add(key)
            unrouted.append(text[:100])
        elif reply and _FAILED_REPLY.search(reply) and key not in seen:
            seen.add(key)
            refused.append({"said": text[:100], "reply": reply[:120]})

    return {
        "considered": sum(1 for m in msgs if m.get("role") == "user"),
        "unrouted": unrouted[:8],
        "refused": refused[:5],
        # Stated because it is the design, not a detail.
        "self_modifies": False,
    }


def review_report() -> str:
    """The spoken version. String logic only -- no model, no network."""
    r = review()
    if not r["considered"]:
        return "I don't have enough conversation saved to review yet."
    if not r["unrouted"] and not r["refused"]:
        return (f"I looked back over {r['considered']} things you asked me. "
                f"Nothing fell through — I understood all of them.")

    bits = [f"Out of {r['considered']} things you asked me"]
    if r["unrouted"]:
        n = len(r["unrouted"])
        bits.append(f"{n} sounded like {'an instruction' if n == 1 else 'instructions'} "
                    f"I don't have a route for: "
                    + "; ".join(f'"{u}"' for u in r["unrouted"][:3]))
    if r["refused"]:
        n = len(r["refused"])
        bits.append(f"{n} I couldn't carry out: "
                    + "; ".join(f'"{x["said"]}"' for x in r["refused"][:3]))
    return (". ".join(bits) + ". I can't fix those myself — "
            "changing how I route commands is a change you make and review.")


def status() -> dict:
    d = _load()
    starts = d.get("starts") or []
    hours = [time.localtime(t).tm_hour + time.localtime(t).tm_min / 60.0
             for t in starts]
    base = _median(hours) if len(hours) >= MIN_SESSIONS else None
    return {
        "skill": "briefing",
        "sessions_recorded": len(starts),
        "baseline_known": base is not None,
        "usual_start_hour": round(base, 1) if base is not None else None,
        "needs": max(0, MIN_SESSIONS - len(starts)),
    }
