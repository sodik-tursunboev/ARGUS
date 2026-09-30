"""
ARGUS - Answer cache.

THE ASK: "argus must remember everything and use it in future for being smart.
If argus remembers everything, maybe in the future I will ask almost the same
thing and argus should not use at all cloud either ollama."

So: a repeat question should cost nothing. No Groq call, no Ollama call, no
web search -- just the answer it already gave.

THE ASYMMETRY THAT DECIDES EVERY THRESHOLD HERE.

A cache MISS costs one ordinary answer: a few hundred milliseconds and a
request that was going to happen anyway. A cache HIT ON THE WRONG ENTRY gives
a confidently wrong answer to a question nobody asked -- "what's the capital
of Australia" answered with the capital of Austria, in ARGUS's own voice, with
no indication anything was reused.

Those costs are nowhere near equal, so this is tuned hard toward false
negatives. It would rather answer the question again than guess.

WHY NOT EMBEDDINGS. Semantic similarity would be the obvious tool, and every
option (sentence-transformers, torch) is a multi-gigabyte dependency competing
for the same 4GB of VRAM as Whisper and Piper. So matching here is lexical:
IDF-weighted content-token overlap. It catches the paraphrases that actually
occur in speech -- filler words, politeness, word order, "tell me about X" vs
"what is X" -- and does NOT claim to catch genuine synonymy. "How tall is
Everest" will not match "what is the height of Everest", and that is a miss,
not a wrong answer.

THE MAX-OVER-N TRAP, which this codebase already walked into once tonight.
A lookup takes the BEST match over every cached entry, and the maximum of N
comparisons rises with N. The replay detector in voiceauth.py was calibrated
on single pairs, behaved correctly in testing, and degraded as its history
grew. So the threshold here is calibrated against the max over a realistically
FULL cache, not against pairs -- see the measurements above the constants.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import os
import re
import threading
import time

import paths

CACHE_PATH = paths.writable("answers.json")


def enabled() -> bool:
    """ARGUS_NO_CACHE=1 disables reuse entirely.

    Checked on every call rather than captured at import: the test bootstrap
    sets it before importing ARGUS modules, but a caller flipping it at
    runtime (to compare cached against fresh answers, say) should take effect
    immediately rather than at the next restart.
    """
    return not os.environ.get("ARGUS_NO_CACHE")


MAX_ENTRIES = 400
DEFAULT_TTL_SECONDS = 14 * 24 * 3600     # a fortnight

# CALIBRATED against the max-over-N statistic with a full 60-entry cache,
# 24 real paraphrases and 24 questions that are lexically close to a cached
# one but semantically different:
#
#     correct paraphrases : min 0.333   p10 0.667   mean 0.903
#     must-not-hit        : max 0.518   p90 0.349   mean 0.259
#
# Recall is FLAT at 83% for every threshold from 0.68 to 0.98, with zero false
# hits throughout -- so anywhere in that band costs the same recall, and the
# only thing that varies is margin. 0.82 takes the margin: 0.30 above the
# worst false positive, which was "what is the boiling point of mercury"
# scoring 0.518 against a cached "boiling point of water". That pair is
# exactly the failure this is tuned to avoid -- one content word apart, and an
# answer that would be confidently, dangerously wrong.
#
# The calibration recommended 0.52 for 96% recall and zero false hits on THIS
# sample. It was not taken: 0.52 sits 0.002 above the worst false positive, so
# it is zero-false-hit by luck rather than by margin, and the next corpus that
# differs slightly from the sample gets a wrong answer.
#
# The three misses that remain at 0.82 are all the same shape -- a paraphrase
# that ADDS or DROPS a content word ("how tall is everest" against a cached
# "how tall is mount everest", "how do planes fly" against "how do airplanes
# fly"). They cost one ordinary answer each. Lowering the threshold to catch
# them is what would let "boiling point of mercury" through.
SIMILARITY_THRESHOLD = 0.82

# At least one content word. "what is it" and "who is he" reduce to the empty
# set once stopwords go, and matching those on structure alone would be
# catastrophic -- but they are already excluded by requiring one.
#
# This was 2, which silently refused to cache the most common question shape
# there is: "what is photosynthesis", "what is gravity", "who is Einstein" all
# carry exactly one content token. A single RARE word is a strong identifier,
# and a single common one is handled by the similarity threshold rather than
# by a count -- "what is a firewall" against a cached "how does a firewall
# work" scores about 0.5 on the extra token and correctly misses.
MIN_CONTENT_TOKENS = 1

MIN_ANSWER_CHARS = 25

_lock = threading.Lock()
_cache: list = []          # [{q, tokens, answer, source, at, hits}]
_loaded = False

# Words that carry no topical information. Kept small on purpose: an
# over-eager stopword list strips the very words that distinguish two
# questions, and every word removed here is one that can no longer prevent a
# false match.
STOPWORDS = frozenset("""
a an the is are was were be been being am do does did doing done
what who whom whose which where when why how
can could will would shall should may might must
i me my mine you your yours he him his she her hers it its they them their
we us our ours this that these those there here
of in on at to for from by with about as into like through after before
and or but if then than so because
please tell say show give me know about
hey ok okay argus yeah yes no not
explain describe define meaning mean means exactly actually really just
""".split())

_WORD = re.compile(r"[a-z0-9']+")


def _stem(word: str) -> str:
    """Crude suffix stripping. Consistency matters more than linguistics.

    Two recall failures during calibration were pure inflection: "how does dns
    work" missed "explain how dns works", and "what is a black hole" missed
    "tell me about black holes". Both are the same question, and both scored
    below any usable threshold because work/works and hole/holes are different
    strings.

    This is not a real stemmer and does not need to be. It is applied
    identically to both sides of every comparison, so even a linguistically
    wrong stem ("physics" -> "physic") still matches itself. The length floors
    exist to protect short tokens that would otherwise be mangled into
    collisions -- "dns" must not become "dn", and "ios" must not become "io".
    """
    if len(word) > 4 and word.endswith("ies"):
        return word[:-3] + "y"
    if len(word) > 5 and word.endswith("ing"):
        return word[:-3]
    if len(word) > 4 and word.endswith("ed"):
        return word[:-2]
    if len(word) > 3 and word.endswith("s") and not word.endswith(("ss", "us", "is")):
        return word[:-1]
    return word


def _tokens(text: str) -> frozenset:
    """Content words, lowercased, de-contracted and stemmed. Order is
    deliberately discarded: speech reorders freely and "the capital of France"
    / "France's capital" should not be two different cache entries.

    The trailing-apostrophe strip is load-bearing in both directions. Without
    it "what's" tokenises whole, misses the STOPWORDS entry for "what", and
    survives as a content word -- which dropped "what's photosynthesis" to
    0.50 against a cached "what is photosynthesis" and turned the single most
    natural spoken paraphrase into a miss. It is also what makes the
    possessive claim above true: "France's" only reduces to "france" here.
    """
    out = set()
    for w in _WORD.findall((text or "").lower()):
        w = re.sub(r"'(s|re|ve|ll|d|m)$", "", w).strip("'")
        if not w or w in STOPWORDS or len(w) < 2:
            continue
        out.add(_stem(w))
    return frozenset(out)


def _idf(token: str, corpus: list) -> float:
    """Rarity weight. A token appearing in every cached question tells you
    nothing; one appearing in a single question is what identifies it.

    Computed over the cache rather than a language corpus, which is the right
    denominator here: the question is not "is this word rare in English" but
    "does this word distinguish one of MY cached questions from the others".
    """
    import math

    n = len(corpus) or 1
    seen = sum(1 for e in corpus if token in e["tokens"]) or 1
    return math.log((n + 1) / seen) + 1.0


def similarity(a: frozenset, b: frozenset, corpus: list) -> float:
    """IDF-weighted Jaccard over content tokens.

    Plain Jaccard treats every word equally, so "who is a project creator" and
    "who is elon musk" score on the shared words rather than the differing
    ones. Weighting by rarity puts the decision on the names, which is where
    it belongs.
    """
    if not a or not b:
        return 0.0
    inter = a & b
    union = a | b
    wi = sum(_idf(t, corpus) for t in inter)
    wu = sum(_idf(t, corpus) for t in union)
    return (wi / wu) if wu else 0.0


# ── volatility ─────────────────────────────────────────────────────────
# Questions whose answer is only true for a moment. Caching one of these is
# worse than not caching at all: a stale answer delivered instantly is more
# convincing, and therefore more misleading, than a slow correct one.
VOLATILE = re.compile(
    r"\b(time|date|day|today|tonight|tomorrow|yesterday|now|currently|"
    r"weather|temperature|forecast|rain|snow|"
    r"battery|cpu|ram|memory|disk|usage|uptime|running|processes|"
    r"news|latest|newest|recent|price|stock|score|"
    r"unread|inbox|calendar|schedule|meeting|reminder|timer|"
    r"wifi|network|ip|connected|online)\b",
    re.I,
)

# Questions that are ABOUT the user's own state. These change without any
# question being asked, so a cached answer goes stale silently.
PERSONAL_STATE = re.compile(
    r"\b(my|mine|i)\b.*\b(profile|notes?|reminders?|files?|settings?|"
    r"history|preferences?)\b", re.I,
)

# CONTEXT-DEPENDENT follow-ups must never be cached OR served from cache.
#
# The cache keys on the question text alone, but a follow-up means different
# things in different conversations: "why do they form" is about black holes
# in one thread and about hurricanes in another. Cached from the first, it was
# served -- verbatim and wrong -- in the second, which is exactly how a
# multi-turn thread came apart ("tell me about black holes" / "why do they
# form" answered with a generic "things form because..." left over from an
# earlier, contextless run).
#
# The signal is SHAPE, not a topic list: a referential pronoun standing in for
# something said earlier (it/they/that/those/one/he/she) inside a short
# question, or a bare interrogative fragment. Self-contained questions -- "who
# created python", "what is the capital of france" -- have neither and are
# still cached normally.
_REFERENTIAL = re.compile(
    r"\b(it|its|it's|they|them|their|theirs|that|those|these|this|one|ones|"
    r"he|him|his|she|her|hers)\b", re.I)
# COMPLETE follow-up phrases only, anchored end to end -- not any short
# question that happens to open with an interrogative. "who created python" and
# "how do plants grow" are self-contained and must stay cacheable; only the
# bare fragments below depend on what was just said.
_FRAGMENT = re.compile(
    r"^(why|why though|how come|and then|then what|but why|go on|"
    r"tell me more|like what|such as|anything else|what else|for example|"
    r"really|is that so|and you|what do you mean|say that again|come again|"
    r"and after that|so what happened|do you agree|says who|how so|"
    r"such that|meaning|go ahead|continue)\??$", re.I)


# A lone interrogative word IS a fragment ("why?", "when?"). A lone CONTENT
# word is a topic query and stays cacheable ("photosynthesis", "gravity") --
# so this is deliberately not a blanket "short input" rule, which had wrongly
# caught "what's photosynthesis" and the bare topic "photosynthesis".
_BARE_INTERROGATIVE = re.compile(
    r"^(why|when|how|who|what|where|which|whom|whose|really)\??$", re.I)


def is_context_dependent(question: str) -> bool:
    """True when the question only makes sense against the conversation so far."""
    q = (question or "").strip()
    if _BARE_INTERROGATIVE.match(q):
        return True                                   # "why", "when", "really"
    if _FRAGMENT.match(q):
        return True                                   # "go on", "how come"
    # A referential pronoun in a SHORT question is a stand-in for prior context.
    # Length-bounded so "what is the meaning of life" (self-contained, long) is
    # unaffected while "would you use it" (referential, short) is caught.
    if len(q.split()) <= 6 and _REFERENTIAL.search(q):
        return True
    return False


def is_cacheable(question: str, answer: str = "") -> tuple[bool, str]:
    """(cacheable, reason_if_not). Conservative by design."""
    q = (question or "").strip()
    if len(_tokens(q)) < MIN_CONTENT_TOKENS:
        return False, "too few content words to identify reliably"
    if VOLATILE.search(q):
        return False, "answer changes over time"
    if PERSONAL_STATE.search(q):
        return False, "depends on mutable personal state"
    if is_context_dependent(q):
        return False, "depends on conversation context"

    if answer:
        if len(answer) < MIN_ANSWER_CHARS:
            return False, "answer too short to be worth reusing"

        # A SECRET IN THE ANSWER MUST NOT BE PERSISTED.
        #
        # is_cacheable examined the QUESTION for sensitivity and never the
        # answer, so a reply that happened to contain an API key, a password
        # or a card number was written verbatim to answers.json -- on disk,
        # indefinitely, and read back into a future prompt. Verified: an
        # answer containing a gsk_ key was stored raw.
        #
        # redact() changing the text is the signal: if anything in this answer
        # looks like a credential, the whole answer is refused rather than
        # stored in a redacted form, because a cached answer with "[api key]"
        # where the value should be is a wrong answer being served forever.
        import security

        if security.redact(answer) != answer:
            return False, "answer contains something secret-shaped"
        # Never cache a failure. "I couldn't find a reliable answer" is a
        # statement about one attempt, not a fact about the world, and
        # caching it makes a transient outage permanent.
        import brain

        if brain.UNSURE.search(answer):
            return False, "answer expresses uncertainty"
        if answer.lstrip().startswith(("I couldn't", "I can't", "Sorry")):
            return False, "answer is a failure message"

    # Privacy mode and sensitive content are checked last because they are
    # the most expensive to evaluate.
    try:
        from skills import cloud_gate, privacy_skill

        if privacy_skill.is_muted():
            return False, "privacy mode is on"
        if cloud_gate.is_sensitive(q):
            return False, "question is sensitive"
    except Exception:
        pass

    return True, ""


# ── persistence ────────────────────────────────────────────────────────
def _load():
    global _cache, _loaded
    if _loaded:
        return
    _loaded = True
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        _cache = []
        return
    now = time.time()
    _cache = [
        {**e, "tokens": frozenset(e.get("tokens", []))}
        for e in raw
        if now - e.get("at", 0) < DEFAULT_TTL_SECONDS
    ]


def _save():
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        tmp = CACHE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump([{**e, "tokens": sorted(e["tokens"])} for e in _cache],
                      f, indent=1)
        os.replace(tmp, CACHE_PATH)
    except OSError:
        pass


# ── the two operations ─────────────────────────────────────────────────
def lookup(question: str) -> tuple:
    """(answer, meta) or (None, reason)."""
    if not enabled():
        return None, "cache disabled"
    ok, why = is_cacheable(question)
    if not ok:
        return None, why

    with _lock:
        _load()
        if not _cache:
            return None, "cache empty"
        qt = _tokens(question)
        now = time.time()
        best, best_sim = None, 0.0
        for e in _cache:
            if now - e["at"] > DEFAULT_TTL_SECONDS:
                continue
            s = similarity(qt, e["tokens"], _cache)
            if s > best_sim:
                best, best_sim = e, s

        if best and best_sim >= SIMILARITY_THRESHOLD:
            best["hits"] = best.get("hits", 0) + 1
            best["last"] = now
            return best["answer"], {
                "similarity": round(best_sim, 3),
                "original": best["q"],
                "age_hours": round((now - best["at"]) / 3600, 1),
                "source": best.get("source", "?"),
            }
    return None, f"best match {best_sim:.2f} < {SIMILARITY_THRESHOLD}"


def store(question: str, answer: str, source: str = "") -> bool:
    if not enabled():
        return False
    ok, _ = is_cacheable(question, answer)
    if not ok:
        return False

    with _lock:
        _load()
        qt = _tokens(question)
        now = time.time()

        # Replace a near-duplicate rather than accumulating variants of the
        # same question: without this the cache fills with paraphrases, and a
        # crowded cache is exactly what drives the max-over-N false-match rate
        # up.
        for e in _cache:
            if similarity(qt, e["tokens"], _cache) >= SIMILARITY_THRESHOLD:
                e.update(q=question, tokens=qt, answer=answer,
                         source=source, at=now)
                _save()
                return True

        _cache.append({"q": question, "tokens": qt, "answer": answer,
                       "source": source, "at": now, "hits": 0, "last": now})
        if len(_cache) > MAX_ENTRIES:
            # Evict least recently USED, not oldest. A question asked every
            # week is worth more than one asked once yesterday.
            _cache.sort(key=lambda e: e.get("last", e["at"]))
            del _cache[:len(_cache) - MAX_ENTRIES]
        _save()
    return True


def forget(substring: str = "") -> int:
    """Drop matching entries, or everything. Returns how many went."""
    with _lock:
        _load()
        before = len(_cache)
        if substring:
            needle = substring.lower()
            _cache[:] = [e for e in _cache if needle not in e["q"].lower()]
        else:
            _cache.clear()
        _save()
        return before - len(_cache)


def stats() -> dict:
    with _lock:
        _load()
        return {
            "entries": len(_cache),
            "hits": sum(e.get("hits", 0) for e in _cache),
            "path": CACHE_PATH,
        }


def describe() -> str:
    s = stats()
    return (f"answer cache: {s['entries']}/{MAX_ENTRIES} entries, "
            f"{s['hits']} reuses, threshold {SIMILARITY_THRESHOLD}")
