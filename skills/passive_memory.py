"""
ARGUS - Passive memory.

profile_skill stores what ARGUS is TOLD to store ("remember that I'm a
student"). Nobody talks that way. Facts arrive in passing -- "I work at a
hospital", "I live in Tashkent" -- and until now they went straight past and
were gone at the end of the exchange, so ARGUS had to be spoon-fed the same
context repeatedly. That is a large part of what makes it feel like a bot
rather than something that knows you.

This watches ordinary conversation and picks out durable self-disclosures.

Design bias: UNDER-capture, deliberately. A memory that quietly records "I am
tired" as a permanent fact about you is worse than one that misses a few real
facts -- wrong memories surface later as confidently wrong statements, and
the user has to go and clean the file out by hand. So this only fires on
explicit self-descriptive constructions, refuses anything hedged, negated,
hypothetical or transient, and stores at most one fact per exchange.

No model call: this runs after every single exchange, and spending an LLM
round trip on "open notepad" to discover there is no fact in it would put a
real cost on the common case for a rare payoff.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re

from skills import profile_skill

# Adjectives that describe how someone is RIGHT NOW, not who they are. These
# are the difference between memory and noise -- "I am good" is the single
# most common thing said to an assistant and it means nothing durable.
_TRANSIENT = {
    "good", "fine", "ok", "okay", "great", "well", "alright", "tired", "busy",
    "hungry", "sleepy", "bored", "happy", "sad", "angry", "annoyed", "done",
    "back", "here", "ready", "sure", "late", "early", "sorry", "confused",
    "excited", "nervous", "stressed", "cold", "hot", "sick", "ill", "awake",
    "bit", "little", "very", "really", "so", "too", "still", "just", "away",
}

# Any of these anywhere in the sentence disqualifies it. Negation and hedging
# matter most: capturing "I am not a morning person" as "I am a morning
# person" would be worse than capturing nothing at all.
_DISQUALIFY = re.compile(
    r"\?"
    r"|\b(?:not|never|dont|cant|wont|isnt|arent|wasnt)\b"
    r"|n't\b"
    r"|\b(?:if|would|could|should|might|maybe|perhaps|suppose|imagine|pretend|"
    r"whether|unless|wish|hope)\b"
    r"|\byou(?:'re| are|r)\b"
    r"|\b(?:he|she|they|we) (?:is|are|am)\b"
)

# Questions that carry no question mark -- speech recognition rarely supplies
# one, so "do i have a meeting today" arrives looking exactly like a statement
# and was being stored as "I have a meeting today". Auxiliary-before-"I" is
# the reliable signal that a clause is asking rather than telling.
_QUESTION_LEAD = re.compile(
    r"^(?:do|does|did|am|are|is|was|were|have|has|had|can|could|will|would|"
    r"should|shall|may|might)\s+i\b"
)

# "remember that I'm a student" belongs to the EXPLICIT path (intent.py routes
# it to profile/remember). Letting the passive path also fire on it means the
# same fact races to be stored twice, in two different phrasings; _already_known
# would usually catch it, but not reliably enough to depend on. The explicit
# path owns these utterances outright.
_EXPLICIT_LEAD = re.compile(r"^\s*(?:remember|note|save|log|write down)\b")

# Each entry: pattern, profile section, template for the stored sentence.
# All are anchored to the end of a clause so a fragment can't be lifted out of
# the middle of a longer sentence and stored as though it were the whole fact.
_PATTERNS = [
    (re.compile(r"\bmy name(?:'s| is) ([a-z][\w\-]*(?: [a-z][\w\-]*)?)$"), "About", "My name is {0}"),
    (re.compile(r"\bi(?:'m| am) an? ([a-z][\w\s\-]{2,40})$"), "About", "I am a {0}"),
    (re.compile(r"\bi(?:'m| am) from ([a-z][\w\s\-,]{2,40})$"), "About", "I am from {0}"),
    (re.compile(r"\bi live in ([a-z][\w\s\-,]{2,40})$"), "About", "I live in {0}"),
    (re.compile(r"\bi have an? ([a-z][\w\s\-]{2,40})$"), "About", "I have a {0}"),
    (re.compile(r"\bi work at ([a-z][\w\s\-&.]{2,40})$"), "Work", "I work at {0}"),
    (re.compile(r"\bi work for ([a-z][\w\s\-&.]{2,40})$"), "Work", "I work for {0}"),
    # "work as" states the ROLE where "work at"/"for" state the employer. It
    # was missing, so "I work at a hospital" was remembered and "I work as a
    # security analyst" -- the more common way to say what you do -- was not.
    (re.compile(r"\bi work as an? ([a-z][\w\s\-&.]{2,40})$"), "Work", "I work as a {0}"),
    (re.compile(r"\bi work in ([a-z][\w\s\-&.]{2,40})$"), "Work", "I work in {0}"),
    (re.compile(r"\bi(?:'m| am) studying ([a-z][\w\s\-]{2,40})$"), "Work", "I am studying {0}"),
    (re.compile(r"\bi study ([a-z][\w\s\-]{2,40})$"), "Work", "I study {0}"),
    (re.compile(r"\bi(?:'m| am) learning ([a-z][\w\s\-]{2,40})$"), "Work", "I am learning {0}"),
    (re.compile(r"\bi (?:like|love|enjoy) ([a-z][\w\s\-]{2,40})$"), "Preferences", "I like {0}"),
    (re.compile(r"\bi (?:hate|dislike) ([a-z][\w\s\-]{2,40})$"), "Preferences", "I dislike {0}"),
    (re.compile(r"\bi prefer ([a-z][\w\s\-]{2,40})$"), "Preferences", "I prefer {0}"),
    (re.compile(r"\bi always use ([a-z][\w\s\-]{2,40})$"), "Preferences", "I always use {0}"),
]

MAX_VALUE_WORDS = 6      # longer than this is narrative, not a fact
MAX_STORED_FACTS = 60    # stop growing the file on its own past this


def _clauses(text: str):
    """Splits into clauses so a fact is matched against its own clause rather
    than the whole utterance. Without this, "I am a student and I need to buy
    milk" would capture the entire tail as the profession."""
    parts = re.split(r"[.!?;,]|\band\b|\bbut\b|\bbecause\b|\bso\b", text.lower())
    return [p.strip() for p in parts if p.strip()]


def _fact_count() -> int:
    return sum(1 for line in profile_skill.read_profile().splitlines()
               if line.strip().startswith("-") and "nothing recorded yet" not in line)


def _already_known(fact: str) -> bool:
    """Substring match both ways, on the fact's own words. Catches the case
    where the same thing was just stored explicitly via "remember that ..."
    moments earlier in the same exchange."""
    norm = re.sub(r"[^\w\s]", "", fact.lower()).strip()
    for line in profile_skill.read_profile().splitlines():
        if not line.strip().startswith("-"):
            continue
        existing = re.sub(r"[^\w\s]", "", line.split("_(learned")[0].lstrip("- ").lower()).strip()
        if not existing:
            continue
        if norm == existing or norm in existing or existing in norm:
            return True
    return False


def extract(text: str):
    """Returns (fact, section) for one durable self-disclosure, or None.

    Pure -- stores nothing. Split out from observe() so the matching rules can
    be tested directly without touching the profile on disk.
    """
    if not text or len(text) > 300:
        return None
    if _EXPLICIT_LEAD.match(text.lower()):
        return None

    for clause in _clauses(text):
        if _DISQUALIFY.search(clause) or _QUESTION_LEAD.match(clause):
            continue
        for pattern, section, template in _PATTERNS:
            m = pattern.search(clause)
            if not m:
                continue
            value = m.group(1).strip()
            words = value.split()
            if not words or len(words) > MAX_VALUE_WORDS:
                continue
            # "I am a bit tired" -> value "bit tired": every word is a
            # transient descriptor, so there is no durable fact here.
            if all(w in _TRANSIENT for w in words):
                continue
            if words[0] in _TRANSIENT and len(words) == 1:
                continue
            return template.format(value), section
    return None


def observe(text: str):
    """Extracts and stores one fact from an ordinary utterance.

    Returns the stored fact, or None when nothing was worth keeping -- which
    is the overwhelmingly common case, and is not an error.
    """
    found = extract(text)
    if not found:
        return None
    fact, section = found

    if _already_known(fact):
        return None
    if _fact_count() >= MAX_STORED_FACTS:
        # Past this the file stops being a profile and starts being a log.
        # Explicit "remember that ..." still works; only the automatic path
        # is capped, so the user never loses the ability to add something.
        return None

    profile_skill.remember(fact, section)
    return fact
