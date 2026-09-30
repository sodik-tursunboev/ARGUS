"""
ARGUS - Conversational follow-up.

The single most bot-like thing about ARGUS is that every utterance is an
island. Ask "what's the weather in London", then "what about tomorrow", and
the second one is parsed as if the first never happened -- so it either
misroutes or gets handed to the LLM with no idea what "tomorrow" refers to.
People don't repeat the full noun phrase every turn; they say "it", "that",
"what about X". Handling that is most of the difference between something
that converses and something that merely accepts commands.

This keeps a short-lived record of the last re-targetable action and rewrites
elliptical follow-ups against it, producing a normal decision dict that routes
exactly as if the user had said the whole thing.

Scope is deliberately narrow. It only fires on explicit elliptical forms, only
within a short window, and only for skills where swapping the target is
meaningful -- "what about" after a shutdown request must never become a second
shutdown request. Everything else falls through untouched.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re
import time

FOLLOWUP_WINDOW = 120  # seconds a context stays usable

# Swapping the target only makes sense where the action is a lookup or a
# window/app operation. Deliberately excludes power (staged, PIN-gated),
# profile/vault (writes), timer and control -- re-running those against a
# half-understood new target is how an assistant does real damage.
RETARGETABLE = {"weather", "knowledge", "research", "apps", "window", "files", "youtube"}

# DESTRUCTIVE ACTIONS ARE NEVER RETARGETABLE, whatever their skill.
#
# The set above is per-SKILL, and "files" is in it because retargeting a
# SEARCH is useful -- "find my cv", "what about my resume". But files also
# owns delete, and the check could not tell them apart, so:
#
#     "delete notes.txt"  ->  "and passwords.txt"
#         -> files/delete "passwords.txt"
#
# A question-shaped follow-up staged the deletion of a file the user had
# never named for deletion. The PIN still gated the deletion itself, but the
# target was chosen by an ambiguous phrase rather than by the user -- and
# with the PIN-farming issue fixed alongside this, that is exactly the pair
# that turns two small weaknesses into a chain.
#
# Keyed on (skill, action) so a skill can stay retargetable for its safe
# operations while its dangerous ones are excluded.
NEVER_RETARGET = {
    ("files", "delete"), ("files", "confirm_delete"),
    ("power", "request"), ("power", "confirm"),
    ("pc", "dictate"), ("control", "clipboard_write"),
    ("profile", "forget"),
}

# Referring to a THING that was just acted on. "it"/"that" only resolve to a
# target the user themselves named -- never to something ARGUS inferred.
_PRONOUN_VERBS = {
    # Closing. "shut" and "end" were missing, so "close it" and "kill it"
    # worked while "shut it" and "end it" resolved to nothing -- the same
    # request in a slightly different word, silently ignored.
    "close": ("apps", "close"), "quit": ("apps", "close"), "kill": ("apps", "close"),
    "shut": ("apps", "close"), "end": ("apps", "close"), "exit": ("apps", "close"),
    "terminate": ("apps", "close"), "stop": ("apps", "close"),
    "open": ("apps", "open"), "launch": ("apps", "open"), "start": ("apps", "open"),
    "run": ("apps", "open"), "reopen": ("apps", "open"),
    "minimize": ("window", "minimize"), "minimise": ("window", "minimize"),
    "hide": ("window", "minimize"),
    "maximize": ("window", "maximize"), "maximise": ("window", "maximize"),
    "focus": ("window", "focus"), "switch to": ("window", "focus"),
    "show": ("window", "focus"),
}

# Longest first so "switch to" is tried before "switch" would be, and the
# British spellings are accepted alongside the American keys.
_PRONOUN_VERB_RE = (
    r"^(" + "|".join(
        re.escape(v) for v in sorted(_PRONOUN_VERBS, key=len, reverse=True))
    + r"|minimise|maximise)"
    r"\s+(?:it|that|this|them)(?:\s+again)?$"
)

# BUGFIX: the pronoun rewrite above used to fire against WHATEVER was last
# recorded, ignoring what kind of thing it was. Every entry in _PRONOUN_VERBS
# maps to an app or a window operation, but RETARGETABLE also contains
# weather, knowledge, research, files and youtube -- so:
#
#     "what's the weather in London"  ->  "open it"   ->  apps/open "London"
#     "look up photosynthesis"        ->  "close it"  ->  apps/close "photosynthesis"
#
# Both observed directly. "it" has to refer to something that can actually be
# opened or closed, so the referent's own skill has to be one of these.
_PRONOUN_REFERENTS = {"apps", "window"}

_last = {"skill": None, "action": None, "target": None, "at": 0.0}

# ── FILE CONTEXT ─────────────────────────────────────────────────────────────
#
# "Move THAT to Documents" -- where "that" is the file ARGUS just found, not
# anything the owner typed. _last above records the SEARCH QUERY ("my cv"),
# which is not a path and cannot be moved; this records the resolved path the
# search actually produced.
#
# Kept separate from _last on purpose. A file stays referrable across a couple
# of unrelated remarks -- people find something, think, then act on it -- while
# the conversational referent is replaced by every retargetable command. Fusing
# them would mean asking the weather in between lost the file.
FILE_CONTEXT_WINDOW = 300          # five minutes
_last_file = {"path": None, "at": 0.0}


def remember_file(path: str) -> None:
    """Record a file ARGUS resolved, so "that" can refer to it."""
    p = str(path or "").strip()
    if p:
        _last_file.update(path=p, at=time.time())


def last_file() -> str:
    """The file "that" refers to, or "" if there isn't one any more."""
    if not _last_file["path"]:
        return ""
    if time.time() - _last_file["at"] > FILE_CONTEXT_WINDOW:
        return ""
    return _last_file["path"]


def clear_file() -> None:
    _last_file.update(path=None, at=0.0)


# ── SCREEN CONTEXT ───────────────────────────────────────────────────────────
#
# The referent that is not in the conversation at all. Somebody looking at a
# window says "close it" without ever having named the program -- and before
# this, that resolved to nothing, because _last only knows what was SAID.
#
# Deliberately the LAST resort: a thing the owner actually named always wins
# over a thing that merely happens to be in front of them. Otherwise "open
# notepad" followed by "close it" would close whatever had stolen focus in
# between, which is exactly the sort of surprise that makes an assistant
# untrustworthy.
def focused_app() -> str:
    """The process name of the focused window, without its extension.

    Reached through pc_skill rather than read here: it needs ctypes.windll,
    which the capability scanner counts as a filesystem capability. This
    module declares none, and a skill gaining an undeclared capability aborts
    the boot -- so the call goes where the declaration already is.
    """
    try:
        from skills import pc_skill
        w = pc_skill.focused_window()
    except Exception:
        return ""
    name = (w or {}).get("process") or ""
    return name[:-4] if name.lower().endswith(".exe") else name


def record(skill: str, action: str, target: str):
    """Called from the router once a decision is made. Only remembers things
    worth referring back to -- a target that's empty carries no information,
    and a non-retargetable skill would only produce dangerous rewrites."""
    if skill not in RETARGETABLE or not (target or "").strip():
        return
    # Checked at RECORD time, not at resolve time: if a destructive action is
    # never remembered, there is nothing for a later follow-up to retarget,
    # and no second place where the exclusion could be forgotten.
    if (skill, action) in NEVER_RETARGET:
        return
    _last.update(skill=skill, action=action, target=target.strip(), at=time.time())


def has_context() -> bool:
    return bool(_last["target"]) and (time.time() - _last["at"] <= FOLLOWUP_WINDOW)


def clear():
    _last.update(skill=None, action=None, target=None, at=0.0)


# Leading prepositions people attach to the new target: "what about IN london",
# "how about FOR tomorrow". Stripped so the target reaches the skill in the
# same shape it would have if said directly.
_LEAD_PREP = re.compile(r"^(?:in|for|at|on|about|with)\s+")


def resolve(text: str):
    """Rewrites an elliptical follow-up into a full decision, or returns None.

    None means "this isn't a follow-up" -- the overwhelmingly common case, and
    the caller should carry on with normal matching.
    """
    t = re.sub(r"[^\w\s']", " ", text.lower()).strip()
    t = re.sub(r"\s+", " ", t)
    if not t:
        return None

    # THE CONVERSATIONAL REFERENT IS TRIED FIRST, and the screen only after it.
    #
    # The guard used to be the first line of this function, which meant that
    # with no conversation to refer back to, nothing resolved at all. The
    # screen fallback at the bottom needs to run in exactly that case -- but it
    # must never run INSTEAD of something the owner actually named. "Open
    # notepad" then "close it" has to close notepad even if a notification
    # stole focus in between, so the ordering here is the whole safety of the
    # feature, not a detail of its structure.
    if not has_context():
        return _resolve_from_screen(t)

    # "what about tomorrow" / "how about london" -- reuse the previous skill
    # and action against a new target.
    m = re.match(r"^(?:what|how) about (.+)$", t)
    if m:
        target = _LEAD_PREP.sub("", m.group(1)).strip()
        if target and len(target.split()) <= 6:
            return {"skill": _last["skill"], "action": _last["action"], "target": target}

    # A bare "and london?" / "and tomorrow" continues the same query. Requires
    # a short tail: "and then open chrome and check the weather" is a new
    # instruction, not an ellipsis.
    m = re.match(r"^and (?:in |for |at |what about )?(.+)$", t)
    if m:
        target = _LEAD_PREP.sub("", m.group(1)).strip()
        words = target.split()
        if target and len(words) <= 3 and words[0] not in {"then", "also", "now", "please"}:
            return {"skill": _last["skill"], "action": _last["action"], "target": target}

    # "close it", "minimise that", "open it again" -- a verb plus a pronoun
    # standing in for the thing just acted on.
    # The alternation is BUILT FROM _PRONOUN_VERBS rather than written out.
    #
    # It used to be a separate hardcoded list, and the two drifted: verbs
    # added to the dict ("shut", "end", "exit", "hide") never matched here, so
    # "close it" worked and "shut it" silently resolved to nothing. A lookup
    # table and the pattern that feeds it must not be maintained separately.
    m = re.match(_PRONOUN_VERB_RE, t)
    if m and _last["skill"] in _PRONOUN_REFERENTS:
        verb = m.group(1).replace("minimise", "minimize").replace("maximise", "maximize")
        mapped = _PRONOUN_VERBS.get(verb)
        if mapped:
            skill, action = mapped
            return {"skill": skill, "action": action, "target": _last["target"]}

    # "do it again" / "same again" -- repeat verbatim.
    if re.match(r"^(?:do (?:it|that) again|same again|again|repeat that)$", t):
        return {"skill": _last["skill"], "action": _last["action"], "target": _last["target"]}

    # Nothing in the conversation matched. The screen may still know.
    return _resolve_from_screen(t)


def _resolve_from_screen(t: str):
    """Resolve a pronoun against the window in front of the owner.

    ONLY THE SAFE VERBS. _PRONOUN_VERBS also contains open/launch/start, and
    "open it" pointed at the focused window is nonsense -- it is already open.
    Worse, close/minimise/maximise are recoverable and a wrongly-resolved
    "open" would launch something at random. So this handles the verbs that
    act on a window that already exists, and lets everything else fall through
    to normal matching.

    It returns None whenever it cannot be confident, which is most of the
    time, and that is correct: a wrong guess here closes the wrong program.
    """
    m = re.match(_PRONOUN_VERB_RE, t)
    if not m:
        return None
    verb = m.group(1).replace("minimise", "minimize").replace("maximise", "maximize")
    mapped = _PRONOUN_VERBS.get(verb)
    if not mapped or mapped[1] not in ("close", "minimize", "maximize", "focus"):
        return None
    app = focused_app()
    if not app:
        return None
    # Never resolve to ARGUS itself: "close it" while looking at the HUD would
    # be ARGUS shutting its own interface, which is the one window the owner
    # cannot have meant and the one ARGUS must not act on.
    if app.lower().startswith("argus") or app.lower() in ("python", "pythonw"):
        return None
    return {"skill": mapped[0], "action": mapped[1], "target": app}
