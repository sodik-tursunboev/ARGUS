"""
ARGUS - Disambiguation.

When a fuzzy match to "run one of these" turns up multiple real candidates
with no clear winner, silently picking one (the old behaviour: shortest
name wins) means getting it wrong roughly as often as getting it right --
"open discord" with both Discord and Discord PTB installed just launches
whichever name happens to be shorter, with no indication a choice was even
made. This stages a question instead ("did you mean X or Y?") and waits for
the next utterance to pick.

Same shape of problem as power_skill's staged confirmation (don't act on
ambiguous input, ask first) and deliberately the same shape of fix: a
pending dict, a short window, checked in intent.py before anything else
gets a chance to misinterpret the reply.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re
import time

CLARIFY_WINDOW = 20  # seconds the pending question stays valid

# Replies that reject rather than choose. Checked before any matching, because
# every rule below reads positively and would happily resolve the very option
# being ruled out.
_NEGATED = re.compile(
    r"\b(?:not|neither|none|no(?:ne|pe)?|don'?t|doesn'?t|isn'?t|"
    r"cancel|nevermind|never mind|forget it|stop|other|different|else)\b",
    re.I,
)

_pending = {"options": None, "skill": None, "action": None, "at": 0.0}


def ask(options: list[str], skill: str, action: str) -> str:
    """Stages a clarification and returns the spoken question.

    options: candidate targets, already human-readable, in the order they
             should be offered (index 0 = "the first one").
    skill/action: what to re-dispatch once a choice is resolved -- e.g.
             ("apps", "open"). The resolved target is filled in by resolve().
    """
    options = [o for o in (options or []) if str(o).strip()]
    _pending["options"] = list(options)
    _pending["skill"] = skill
    _pending["action"] = action
    _pending["at"] = time.time()

    # BUGFIX: the multi-option branch assumed at least two. With one option it
    # produced 'I found a few matches: , or "Discord". Which one?' -- a
    # question with an empty first half, spoken aloud. With none it would have
    # raised IndexError on options[-1]. Neither is reachable from the current
    # caller, which only asks when it has 2+ candidates, but a spoken question
    # that reads as broken is worse than the ambiguity it was trying to
    # resolve, and this is one line to make safe.
    if not options:
        _pending["options"] = None
        return "I couldn't find anything matching that."
    if len(options) == 1:
        return f'Did you mean "{options[0]}"?'
    if len(options) == 2:
        return f'Did you mean "{options[0]}" or "{options[1]}"?'
    listed = ", ".join(f'"{o}"' for o in options[:-1]) + f', or "{options[-1]}"'
    return f"I found a few matches: {listed}. Which one?"


def has_pending() -> bool:
    return bool(_pending["options"]) and (time.time() - _pending["at"] <= CLARIFY_WINDOW)


# Unambiguous ordinal words -- checked first, before any content matching,
# since they're a clear positional signal no matter what the options are.
_ORDINAL_STRONG = {
    "first": 0, "1st": 0,
    "second": 1, "2nd": 1,
    "third": 2, "3rd": 2,
    "fourth": 3, "4th": 3,
}

# Bare cardinals are deliberately NOT in the tier above: "one" is filler in
# the extremely common "the X one" construction ("the ptb one", "the second
# one" -- that second example already resolves via _ORDINAL_STRONG, but "the
# ptb one" has no strong ordinal word in it at all). Checking "one" before
# content matching turned it into a landmine that hijacked almost any reply
# ending in "...one". These only apply as a last resort, once content
# matching below has already had a chance to place the reply.
_ORDINAL_WEAK = {"one": 0, "two": 1, "three": 2, "four": 3}


def resolve(text: str):
    """Matches a reply against the pending options.

    Returns (skill, action, target) if the reply clearly picked one, or
    None if it didn't (caller should treat that as effectively a cancel --
    see router._dispatch's clarify handling). Clears the pending state
    either way; a clarification only gets one shot at being answered, same
    as power_skill's confirm() only accepts one PIN attempt per stage.
    """
    if not has_pending():
        _pending["options"] = None
        return None

    options = _pending["options"]
    skill, action = _pending["skill"], _pending["action"]
    _pending["options"] = None
    t = text.lower().strip()
    words = t.split()

    # 0. A negated or refusing reply picks NOTHING. Without this, every match
    # below reads positively: "not the first one" hit the ordinal rule and
    # resolved to -- the first one, the exact option the user just excluded.
    # With two options "not the first" does imply the second, but inferring
    # that from a negation is guesswork on an action that then runs
    # unsupervised, so this asks again rather than assuming.
    if _NEGATED.search(t):
        return None

    # 1. unambiguous ordinal word ("the second one", "1st") or a bare digit
    # ("2", "number two"). Word-list membership, not substring -- so this
    # can't fire on a word buried inside some other token.
    for word, idx in _ORDINAL_STRONG.items():
        if word in words and idx < len(options):
            return skill, action, options[idx]
    for tok in words:
        if tok.isdigit() and 1 <= int(tok) <= len(options):
            return skill, action, options[int(tok) - 1]

    # 2. exact match wins outright, even when it's ALSO a substring of
    # another option. BUGFIX caught before this ever shipped: with options
    # ["discord", "discord ptb"], a reply of plain "discord" is an exact
    # match to the first -- but "discord" in "discord ptb" is ALSO true, so
    # step 3's plain substring check below would count that as hitting
    # BOTH options and refuse to resolve the single most obvious possible
    # answer. Exact match has to be checked, and win, before substring does.
    exact = [o for o in options if o.lower() == t]
    if len(exact) == 1:
        return skill, action, exact[0]

    # 3. the reply names one of the options outright (substring either way,
    # so "the ptb one" would still need step 4 below, but "discord ptb"
    # spoken back in full matches here).
    hits = [o for o in options if o.lower() in t or t in o.lower()]
    if len(hits) == 1:
        return skill, action, hits[0]

    # 4. word-overlap fallback for a partial, informal reply ("the ptb
    # one" for "discord ptb"): words shared by EVERY option don't
    # distinguish anything ("discord" is in both "discord" and "discord
    # ptb", so it can't be what picks between them) and are excluded: only
    # an option whose OWN distinguishing word(s) appear in the reply counts.
    reply_words = set(words)
    all_words = [set(o.lower().split()) for o in options]
    shared = set.intersection(*all_words) if len(all_words) > 1 else set()
    scored = [o for o, ow in zip(options, all_words)
              if (ow - shared) & reply_words]
    if len(scored) == 1:
        return skill, action, scored[0]

    # 5. last resort: a bare cardinal ("two") with nothing else in the reply
    # to go on. Only reached once content matching above has already failed
    # to place it -- see _ORDINAL_WEAK's comment for why this can't run any
    # earlier without misreading ordinary phrasing as a position.
    for word, idx in _ORDINAL_WEAK.items():
        if word in words and idx < len(options):
            return skill, action, options[idx]

    return None


def cancel():
    _pending["options"] = None
