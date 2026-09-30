"""
ARGUS - Fuzzy matching for words a speech recognizer will mangle.

Proper nouns are the hardest thing to match on a voice path. Whisper has no
reason to expect "Argus" or "Kowalski", so it produces plausible-sounding
spellings instead -- and an exact string comparison then throws away the
utterance entirely.

difflib.SequenceMatcher.ratio() is the obvious tool and is the WRONG one. It
counts matching characters, so it is brutal on a short word with a middle
substitution and forgiving of a long word with an extra prefix:

    "argyz"  vs "argus"    0.600   <- a real, logged mishearing. Rejected.
    "marcus" vs "arcus"    0.909   <- a false wake. Accepted.

Neither number has anything to do with how the words sound. Soundex does: it
drops vowels after the first letter and gives s/z, c/g/k/q/x/z, d/t, m/n the
same code -- exactly the substitutions a recognizer makes -- while keeping the
initial letter significant, which is what separates "marcus" from "argus".

Used as a GATE, with a bounded edit distance to confirm. Either test alone is
too loose: "argue" is one edit from "argus" but codes differently, and plenty
of words share a Soundex code without being remotely similar.

Shared by listener.py (wake word, voice process) and intent.py (creator name,
orchestrator process), which is why this is its own module -- it must not drag
either one's imports into the other.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re

_SOUNDEX_CODES = {
    **dict.fromkeys("bfpv", "1"),
    **dict.fromkeys("cgjkqsxz", "2"),
    **dict.fromkeys("dt", "3"),
    "l": "4",
    **dict.fromkeys("mn", "5"),
    "r": "6",
}


def soundex(word: str) -> str:
    """Classic 4-character Soundex. Non-letters are dropped first."""
    word = "".join(c for c in word.lower() if c.isalpha())
    if not word:
        return ""
    out, prev = word[0].upper(), _SOUNDEX_CODES.get(word[0], "")
    for ch in word[1:]:
        code = _SOUNDEX_CODES.get(ch, "")
        if code and code != prev:
            out += code
        if ch not in "hw":      # h and w don't break a repeated-code run
            prev = code
    return (out + "000")[:4]


def edit_distance(a: str, b: str) -> int:
    """Levenshtein. Small inputs only -- these are single words."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def similarity(a: str, b: str) -> float:
    """Edit distance normalized to 0..1 against the longer string.

    Used for whole multi-word names, where Soundex is too coarse -- it keeps
    only four characters, so every long name collapses to nearly the same code.
    """
    if not a or not b:
        return 0.0
    return 1.0 - edit_distance(a, b) / max(len(a), len(b))


def sounds_like(token: str, candidates, max_edits: int = 2) -> bool:
    """True when TOKEN both codes and spells close enough to any candidate."""
    token = "".join(c for c in token.lower() if c.isalpha())
    if len(token) < 4:
        return False
    code = soundex(token)
    for cand in candidates:
        cand = cand.lower()
        if soundex(cand) == code and edit_distance(token, cand) <= max_edits:
            return True
    return False


def name_matches(spoken: str, full_name: str,
                 first_max_edits: int = 2, full_min_similarity: float = 0.72) -> bool:
    """True when SPOKEN is a plausible transcription of FULL_NAME.

    Handles the two things a recognizer actually does to an unfamiliar name:

      1. Respells it -- "Kowalski" -> "Kovalski", "Kowalsky".
      2. Splits it -- "Kowalski" -> "kowal ski". Comparing the tokens
         JOINED makes a split cost nothing, where a token-by-token comparison
         would fail outright.

    The first name is a hard phonetic gate, so an unrelated surname can't drag
    a match through on length alone. Given only the first name ("who is
    Alex"), the gate is the whole test.
    """
    tokens = re.findall(r"[a-z]+", spoken.lower())
    if not tokens:
        return False
    want = re.findall(r"[a-z]+", full_name.lower())
    if not want:
        return False

    if not sounds_like(tokens[0], [want[0]], max_edits=first_max_edits):
        return False
    if len(tokens) == 1:
        return True
    return similarity("".join(tokens), "".join(want)) >= full_min_similarity
