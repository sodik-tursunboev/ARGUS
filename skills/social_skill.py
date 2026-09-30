"""
ARGUS - Social responses and self-knowledge.

Two kinds of reply live here and they have opposite requirements.

FACTS -- who built ARGUS, who the creator is, what ARGUS is -- must be identical
every time. They are claims about a real person and about what the system does
with the user's data. A model asked to phrase those freshly will eventually
invent a credential or soften a privacy boundary, so they are never generated.

FLAVOUR -- greetings, thanks, goodbyes, jokes -- must NOT be identical every
time. Measured on the old fixed lists, over 40 asks each:

    what_can_you_do   1 distinct / 40   the same sentence, every single time
    joke              5 distinct / 40   each one heard ~10 times
    thanks            5 distinct / 40
    how_are_you       5 distinct / 40

That is what makes it sound like a recording rather than a reply.

Generating on demand is the obvious fix and the wrong one: 257ms measured per
line, paid on the hot path, to answer "thanks". Generating a BATCH is 487ms for
six lines -- 81ms each -- so lines are produced ahead of time by a background
refill and served from a pool instantly. When the pool is empty (cloud down,
rate limited, first run) the original fixed lists answer immediately, so the
worst case is exactly the old behaviour rather than a stall.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import random
import threading
import time
from datetime import datetime

import config

# Authoritative application metadata, read from config so there is ONE place it
# is written. The AUTHOR fields, not USER_FULL_NAME: authorship is not something a
# settings edit should be able to reassign (see config.py, "Authorship").
_APP = config.ASSISTANT_NAME
_CREATOR = config.COPYRIGHT_HOLDER

# Whether pleasantries may be phrased by a MODEL. OFF unless asked for.
#
# They used to be: prewarm() fired a background Groq call per kind at every startup
# (eight of them), and respond() topped a pool up whenever it ran low -- so saying
# "thanks" or asking for a joke cost a hosted call, made only to vary a pleasantry.
# On the local fallback the same refill ran on Ollama, which on a 4GB card queues
# behind (or ahead of) the person's real request. That is a model call spent on a
# deterministic answer, which is exactly what should cost nothing. The fixed lists
# below answer instantly and cost nothing; set ARGUS_SOCIAL_LLM=1 to bring the
# generated variety back.
LLM_VARIETY = os.environ.get("ARGUS_SOCIAL_LLM", "").strip().lower() in (
    "1", "true", "yes", "on")

# Capability facts. Kept as data rather than prose so the spoken summary can be
# rephrased without anything being invented -- the model is given this list and
# asked to compress it, never asked what ARGUS can do.
CAPABILITY_FACTS = [
    "open, close and switch between applications and windows",
    "find and open files",
    "search and research the web",
    "check the weather",
    "run system diagnostics and report CPU, memory and disk",
    "control volume and screen brightness",
    "set timers and reminders",
    "search saved notes and remember facts about the user",
    "take screenshots and read what is on screen",
    "answer general questions",
    "say what is in front of you right now -- the app, window and open file",
    "report how your machine has been running over time, not just this second",
    "watch a folder or metric until something changes, then tell you once",
    "check ARGUS's own usage, feature flags and current settings",
    "list and control Windows services, with PIN confirmation for changes",
    "read and set your environment variables, with PIN confirmation for changes",
    "read the Windows security, application and system event logs",
    "drive your applications through their user interface -- read and click "
    "their controls, type and select with your permission",
]

CAPABILITIES = (
    "I can open and close any app, switch windows, find files, search and research "
    "the web, check the weather, run system diagnostics, control volume and "
    "brightness, set timers and reminders, search your notes, take screenshots, "
    "read your screen, remember things about you, and answer questions. I'll also "
    "mention things unprompted occasionally, like a low battery or a reminder "
    "coming up -- say 'stop mentioning things' if you'd rather I didn't. Anything "
    "touching this machine or your own data runs locally; only general questions "
    "can go to a cloud model."
)


def _time_greeting():
    h = datetime.now().hour
    if h < 5:
        return "Still up?"
    if h < 12:
        return "Good morning."
    if h < 18:
        return "Good afternoon."
    return "Good evening."


_HELLO_TAILS = [
    "What do you need?",
    "What can I do?",
    "Ready when you are.",
    "Go ahead.",
    "I'm listening.",
    "",  # sometimes just the greeting, which is the most natural of all
]

RESPONSES = {
    "how_are_you": [
        "All systems nominal. What do you need?",
        "Running clean. What can I do?",
        "Everything's green on my end. What's up?",
        "No complaints — nothing's on fire. You?",
        "Operational. What are we doing?",
    ],
    "thanks": [
        "Anytime.", "Of course.", "No problem.",
        "That's what I'm for.", "Sure thing.",
    ],
    "hello": None,  # handled dynamically by time of day
    "who_are_you": [
        "I'm Argus, named for the watchman with a hundred eyes. I run on this "
        "machine — anything about you or this computer never leaves it.",
        "Argus. A voice assistant running on your own hardware. General "
        "questions may go to a cloud model for speed; your data doesn't.",
        "Argus — I watch this machine so you don't have to. Everything personal "
        "stays local, by design.",
    ],
    # Every variant says WHO and says both BUILT and DESIGNED: the fact is the
    # same whichever one is picked, and none of them is model-generated. This is
    # the APPLICATION's creator -- not the maker of any model it happens to call
    # (see runtime_answer for that distinction).
    "who_built_you": [
        f"{_APP} was built and designed by {_CREATOR}.",
        f"{_CREATOR} built me. He designed and developed the whole system.",
        f"I was built and designed by {_CREATOR} — he's my developer and my commander.",
        f"{_CREATOR}. He built and designed me, and I answer to him.",
        f"My creator and designer is {_CREATOR}. Everything I am, he built.",
    ],
    "about_creator": [
        f"{_CREATOR} built and maintains ARGUS.",
    ],
    "what_can_you_do": [CAPABILITIES],
    "goodbye": [
        "I'll be here.", "Standing by.", "Talk soon.",
        "Right here when you need me.",
    ],
    "sorry": ["Nothing to apologise for.", "All good.", "No harm done."],
    "compliment": ["Appreciated.", "That's what I'm here for.", "I'll take it."],
    "are_you_there": ["I'm here.", "Listening.", "Right here."],
    "joke": [
        "A programmer's wife tells him: go to the shop and buy a loaf of bread, and if they have eggs, get a dozen. He comes back with twelve loaves.",
        "There are two hard problems in computing: cache invalidation, naming things, and off-by-one errors.",
        "I would tell you a UDP joke, but you might not get it.",
        "I'd tell you a joke about async, but you probably wouldn't get it yet.",
        "There are 10 kinds of people: those who understand binary, and those who don't.",
    ],
}

# ── What may never be generated ────────────────────────────────────────
# Identity and the privacy boundary. See this module's docstring.
FIXED_KINDS = {"who_are_you", "who_built_you", "about_creator"}

# What the model is told the user just did. Only flavour appears here.
_GEN_BRIEF = {
    "how_are_you": "asked how you are",
    "thanks": "thanked you",
    "goodbye": "is signing off for now",
    "sorry": "apologised for something minor",
    "compliment": "paid you a compliment",
    "are_you_there": "checked whether you are still listening",
    "joke": "asked you for a short joke",
}

_PERSONA = ("You are ARGUS, a local voice assistant. Your tone is crisp and "
            "tactical -- confident, dry, never flowery, never corporate. Your "
            "replies are spoken aloud.")

POOL_TARGET = 6        # lines fetched per refill; 487ms measured for six
POOL_REFILL_AT = 2     # refill once a pool drops to this
MAX_LINE_CHARS = 120   # a pleasantry; anything longer is the model rambling
# what_can_you_do is deliberately asked for TWO sentences summarising ten
# capabilities, so the pleasantry ceiling rejected every valid answer and its
# pool silently stayed empty -- the one kind that most needed the variety.
MAX_SUMMARY_CHARS = 400
MIN_REFILL_GAP = 20.0  # seconds between refills of the SAME kind

_pool: dict[str, list[str]] = {}
_inflight: set[str] = set()
_last_refill: dict[str, float] = {}
_lock = threading.Lock()

# Last line used for each kind, so the next one can avoid it.
_last_used = {}


def _pick(kind: str, options: list) -> str:
    """Random, but never the same line twice in a row for this kind."""
    if not options:
        return "I'm here."
    if len(options) == 1:
        return options[0]
    fresh = [o for o in options if o != _last_used.get(kind)]
    choice = random.choice(fresh or options)
    _last_used[kind] = choice
    return choice


def _clean_line(raw: str, limit: int = MAX_LINE_CHARS) -> str:
    """A generated line is untrusted output: strip list markers and quotes, and
    reject anything that isn't a single short spoken sentence."""
    line = (raw or "").strip()
    line = line.lstrip("0123456789.)-–—* \t").strip()
    line = line.strip('"').strip("'").strip()
    if not line or len(line) > limit:
        return ""
    if line.startswith(("#", "{", "[")):
        return ""
    return line


def _generate(kind: str, count: int) -> list:
    """One call, several lines. Returns [] on any failure -- this is a
    best-effort garnish and must never raise into a reply."""
    try:
        import groq_client
        from ollama_client import chat as local_chat

        if kind == "what_can_you_do":
            user = ("Summarise these abilities as ONE spoken reply of two short "
                    "sentences. Use only what is listed, add nothing:\n- "
                    + "\n- ".join(CAPABILITY_FACTS))
            count = 1
        else:
            brief = _GEN_BRIEF.get(kind)
            if not brief:
                return []
            user = (f"The user {brief}. Write {count} different one-line spoken "
                    f"replies, under 12 words each. One per line. No numbering, "
                    f"no quotes, no emoji.")

        if groq_client.available():
            raw = groq_client.chat(_PERSONA, user)
        else:
            # Local is slower but this is off the hot path, and it keeps
            # variety working with no network at all.
            raw = local_chat(_PERSONA, user)
    except Exception:
        return []

    if kind == "what_can_you_do":
        # One answer, not a list -- join the whole reply and keep it whole.
        whole = " ".join(l.strip() for l in (raw or "").splitlines() if l.strip())
        cleaned = _clean_line(whole, MAX_SUMMARY_CHARS)
        return [cleaned] if cleaned else []

    lines = [_clean_line(l) for l in (raw or "").splitlines()]
    return [l for l in lines if l][:max(count, 1)]


def _refill(kind: str):
    try:
        lines = _generate(kind, POOL_TARGET)
        if lines:
            with _lock:
                _pool.setdefault(kind, []).extend(lines)
                del _pool[kind][POOL_TARGET * 2:]      # never unbounded
    finally:
        with _lock:
            _inflight.discard(kind)
            _last_refill[kind] = time.time()


def _maybe_refill(kind: str):
    """Kicks off a background top-up. Never blocks the caller."""
    if not LLM_VARIETY:
        return
    if kind in FIXED_KINDS:
        return
    if kind != "what_can_you_do" and kind not in _GEN_BRIEF:
        return
    with _lock:
        if kind in _inflight:
            return
        if len(_pool.get(kind, [])) > POOL_REFILL_AT:
            return
        if time.time() - _last_refill.get(kind, 0.0) < MIN_REFILL_GAP:
            return
        _inflight.add(kind)
    threading.Thread(target=_refill, args=(kind,), name=f"social-{kind}",
                     daemon=True).start()


def prewarm(kinds=None):
    """Fills the pools ahead of first use, so even the first 'thanks' of a
    session is a fresh line. Called at startup; safe to call more than once."""
    if not LLM_VARIETY:
        return
    for kind in (kinds or list(_GEN_BRIEF) + ["what_can_you_do"]):
        _maybe_refill(kind)


def runtime_answer(maker: bool = False) -> str:
    """What ARGUS is running on, said from the live configuration.

    Nothing model-specific is written here. Model ids come from config, whether a
    hosted tier exists comes from whether it has a key, and "the last reply came
    from" comes from the request trace -- what a real call actually did. It is
    answered by code for the same reason identity is: a model asked to describe
    itself says whatever it was trained to say about itself, not what this
    installation is configured with.

    MAKER answers "who made the model you use", which is a different question
    from "who built you": ARGUS is one person's application, and the models it
    calls are somebody else's."""
    try:
        import route_trace
        info = route_trace.runtime_info(probe=False)
    except Exception:  # noqa: BLE001 -- never a dead end
        return "I can't read my own runtime details just now."

    local = info.get("local_model") or "the local model"
    local_name = sorted(route_trace.LOCAL_PROVIDERS)[0].capitalize()
    tiers = [t for t in info.get("cloud_tiers", []) if t.get("configured")]

    def _tier(t):
        return f"{t['model']} on {t['provider'].capitalize()}"

    if maker:
        ids = sorted({t["model"] for t in tiers} | {local})
        return (f"I'm {_APP}, built and designed by {_CREATOR}. The language "
                f"models underneath are {', '.join(ids)}; beyond those names I "
                f"don't hold details about who trained them.")

    if info.get("cloud_enabled") and tiers:
        general = "For general conversation I use " + _tier(tiers[0])
        if len(tiers) > 1:
            general += (", then " + " and ".join(_tier(t) for t in tiers[1:])
                        + " if that's unavailable")
        general += f", and {local} on this machine as the last resort."
        down = [t["provider"].capitalize() for t in tiers if not t.get("available")]
        if down:
            general += (" " + " and ".join(down)
                        + (" isn't" if len(down) == 1 else " aren't")
                        + " available at the moment.")
    else:
        general = (f"General conversation runs on {local} on this machine; no "
                   f"cloud model is set up.")
    private = (f"Anything about your computer or your own data runs only on "
               f"{local}, through {local_name}.")
    last = ""
    if info.get("current_model"):
        where = "in the cloud" if info.get("current_engine") == "cloud" else "on this machine"
        last = (f" The last reply that used a model came from "
                f"{info['current_model']} ({info['current_provider'].capitalize()}, "
                f"{where}).")
    return f"{general} {private}{last}"


def respond(kind: str, target: str = "") -> str:
    # Runtime metadata rides the existing who_are_you action (a new action name
    # would have to be added to auth.KNOWN_ACTIONS); TARGET is only a
    # discriminator, never spoken back.
    if kind == "who_are_you" and target in ("model", "model_maker"):
        return runtime_answer(maker=(target == "model_maker"))

    if kind == "hello":
        tail = _pick("hello_tail", _HELLO_TAILS)
        greeting = _time_greeting()
        return f"{greeting} {tail}".strip() if tail else greeting

    # Identity is never generated.
    if kind in FIXED_KINDS:
        return _pick(kind, RESPONSES.get(kind) or [])

    line = None
    with _lock:
        pool = _pool.get(kind)
        if pool:
            line = pool.pop(0)
    _maybe_refill(kind)     # top up for next time, in the background

    if line:
        _last_used[kind] = line
        return line
    return _pick(kind, RESPONSES.get(kind) or [])
