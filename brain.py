"""
ARGUS - The reasoning layer.

THE PROBLEM THIS SOLVES:
A 3B model asked "what's the population of Uzbekistan" or "who won the last
World Cup" will often just say "I don't know" — and previously that answer went
straight to your speakers. A local model's ignorance was being treated as the
final word.

THE FIX — a cascade. The model gets first attempt, but if it signals uncertainty
the question is escalated automatically:

    local model → Wikipedia → live web search → honest admission

Only after all three fail does ARGUS say it doesn't know, and by then that's
actually true rather than just a small model's default.

It also injects today's date and what ARGUS knows about you into every prompt.
Models have no concept of "now", so without this "what year is it" gets answered
from training data.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re
from datetime import datetime

import gemini_client
import groq_client

# Cloud tiers in the order they are tried: fastest first, most generous quota
# second. Groq measured ~174ms here, Gemini ~300-600ms, the local model
# ~2533ms -- so Gemini earns its place by being the thing that runs when Groq
# is rate-limited, not by being better than Groq.
#
# A tier with no API key reports available() == False and is skipped, so
# adding a provider costs nothing until a key exists for it.
_CLOUD_TIERS = (
    ("groq", groq_client, groq_client.GroqUnavailable),
    ("gemini", gemini_client, gemini_client.GeminiUnavailable),
)
import route_trace
import security
from ollama_client import chat, chat_stream
from skills import knowledge_skill, research_skill, profile_skill, cloud_gate

# A sentence boundary for splitting a live token stream into speakable
# chunks: punctuation followed by whitespace or end-of-buffer. Imprecise on
# abbreviations/decimals ("Mr. Smith", "3.14") but that's an acceptable
# trade-off for a spoken reply -- same heuristic real-time TTS pipelines use.
_SENTENCE_END = re.compile(r"[.!?](?:\s|$)")

# The shortest first sentence a streamed reply may open with and still be judged
# on its own. Anything shorter is not rejected -- it is read past: see _split_head.
_HEAD_MIN = 15

# The shortest whole answer a HOSTED model may give and still be accepted. This was
# 15, the local model's threshold, and it is the wrong one here: the reply prompt
# tells the model to lead with the fact ("Paris."), so a correct answer is often
# shorter than fifteen characters -- and each one was thrown away and asked again,
# of the next provider and then of the local model. Every discarded answer is a
# hosted call whose tokens were already spent.
_CLOUD_MIN_CHARS = 2

# Phrases that mean "the model doesn't actually know". Deliberately broad —
# a false positive just triggers a web search, which is cheap. A false negative
# means you get told "I don't know" when the answer was one search away.
UNSURE = re.compile(
    r"\b("
    r"i (?:do not|don'?t) know"
    r"|i'?m not (?:sure|certain|aware)"
    r"|i (?:do not|don'?t) have (?:access|information|data|enough)"
    r"|i (?:cannot|can'?t) (?:provide|answer|access|browse|verify)"
    r"|no (?:information|data) (?:available|about)"
    r"|unable to (?:find|provide|determine|access)"
    r"|as an ai"
    r"|my (?:training|knowledge) (?:data|cut ?off)"
    r"|i'?m unable"
    r"|beyond my"
    r")\b",
    re.I,
)

# Questions whose answers change over time — always worth checking the web,
# because even a confident local model is working from stale training data.
# Phrases that are ALWAYS a request for current information, whatever else
# the sentence is doing.
_TIME_STRONG = re.compile(
    r"\b(latest|newest|most recent|current price|share price|stock|"
    r"exchange rate|who is the (?:president|ceo|prime minister|leader)|"
    r"how much does .{0,30}\bcost\b|20[2-9]\d|release[ds]?|version)\b",
    re.I,
)

# Words that only mean "look this up" INSIDE a factual question. On their own
# they are ordinary English: "how are you doing today" was web-searched
# because of "today", and came back with advice on how to answer the phrase
# "how are you" -- a nonsense reply to a greeting. "now", "recently" and
# "currently" appear constantly in conversation that wants no lookup at all.
_TIME_WEAK = re.compile(
    r"\b(current|currently|recent|recently|today|todays|now|"
    r"this (?:year|month|week)|price|cost)\b", re.I)

# The frame that turns a weak word into a lookup: an interrogative asking for
# a value or a fact about the world, not about the speaker or the assistant.
_LOOKUP_FRAME = re.compile(
    r"^(?:(?:so|and|but|ok|okay|hey|well|argus)\s+)*"
    r"(?:what|which|who|whose|when|where|how\s+(?:much|many|far|old|big|long)"
    r"|is\s+there|are\s+there|tell\s+me)\b",
    re.I,
)

# Conversation about the speaker or the assistant is never a web lookup, even
# when it contains a time word. "how are you doing today", "what should i do
# now", "i am tired today".
_ABOUT_US = re.compile(
    r"^(?:(?:so|and|but|ok|okay|hey|well|argus)\s+)*"
    r"(?:how\s+are\s+you|how\s+(?:is|was)\s+your|what\s+(?:are|do)\s+you\b|"
    r"i\s|i'm\b|im\b|my\s|we\s|let'?s\b|thanks|thank\s+you)",
    re.I,
)


# A CLOCK QUESTION IS NOT A WEB LOOKUP, and this is a measured fix rather
# than a tidy-up. "what time is it in tokyo right now" matched the weak set on
# "now", was sent to the web, took 10.6 SECONDS, came back with nothing
# usable, and was then answered by the model anyway -- which already has the
# current local time in its context (see _context) and knows the offsets. The
# entire detour was latency with no information in it.
#
# Deliberately narrow: "what time does the shop close" is a fact about the
# world and still belongs on the web, so this matches asking for the CLOCK,
# not every sentence containing the word time.
_CLOCK = re.compile(
    r"\bwhat\s+time\s+is\s+it\b|"
    r"\bwhat(?:'s|\s+is)\s+the\s+(?:current\s+|local\s+)?time\b|"
    r"\btime\s+(?:difference|zone)\b|\btimezone\b|"
    r"\bwhat\s+time\s+(?:is\s+it\s+)?in\s+[A-Za-z]", re.I)


# "What should I do now", "what can we try", "what do you reckon" -- a request
# for a view, not for a number off the web.
_ADVICE = re.compile(
    r"^(?:(?:so|and|but|ok|okay|hey|well|argus)\s+)*"
    r"what\s+(?:should|shall|can|could|would|do|d'?you)\s+(?:i|we|you)\b",
    re.I)


class _TimeSensitive:
    """Kept as an object with .search() so callers do not change."""

    @staticmethod
    def search(text: str):
        t = (text or "").strip()
        if not t:
            return None
        if _ABOUT_US.match(t):
            return None
        if _CLOCK.search(t):
            return None
        if _TIME_STRONG.search(t):
            return _TIME_STRONG.search(t)
        # Asking for ADVICE is not asking for a fact. Checked here, AFTER the
        # strong set, so "what should I buy, the latest phone" still gets
        # looked up while "what should I do now" does not.
        #
        # _ABOUT_US above cannot catch these: it is anchored at position 0 and
        # these questions open with "what", so "what should i do now" matched
        # the weak set on "now" and was web-searched -- the exact case that
        # module's own comment names as wrong and which had gone unfixed.
        if _ADVICE.match(t):
            return None
        if _TIME_WEAK.search(t) and _LOOKUP_FRAME.match(t):
            return _TIME_WEAK.search(t)
        return None


TIME_SENSITIVE = _TimeSensitive()


def _context() -> str:
    """Date/time, plus what ARGUS knows about the user -- FENCED as data.

    The profile used to be concatenated straight into the system prompt, which
    put it at the highest authority level the model has. That matters because
    the profile is not hand-written: passive_memory.py adds facts
    automatically from ordinary conversation, and profile/remember is
    reachable from the LLM router with a model-chosen target. A single stored
    line reading like an instruction would then have been delivered to every
    later turn AS a system instruction.
    """
    now = _now()
    parts = [
        f"Today is {now.strftime('%A, %d %B %Y')} and the time is {now.strftime('%H:%M')}.",
        f"It is {_part_of_day(now.hour)}.",
    ]
    sitting = _at_the_machine_for()
    if sitting:
        parts.append(sitting)
    prof = profile_skill.profile_context()
    if prof:
        parts.append(security.wrap_untrusted(prof, "ARGUS's saved notes about the user"))
    return "\n".join(parts)


def _now():
    """The time ARGUS believes it is, honouring a configured timezone.

    ONE definition, shared with what the spoken clock uses. Two clocks is how
    "what time is it" and the time the model reasons from drift apart -- and
    the model's copy is the one that silently poisons every answer about
    today, tomorrow and "tonight" without ever being visibly wrong.

    Falls back to the machine's own local time on any failure, which is also
    the default when nothing is configured.
    """
    try:
        from skills import pc_skill
        return pc_skill.now()
    except Exception:
        return datetime.now()


def _part_of_day(hour: int) -> str:
    """Named rather than left as a bare 24-hour clock.

    A model reading "the time is 23:40" will happily write "good morning":
    the number is in the prompt but the MEANING of it is not, and every
    greeting-shaped reply was a coin flip. One word costs nothing and removes
    the whole class of mistake.
    """
    if hour < 5:
        return "the middle of the night"
    if hour < 12:
        return "morning"
    if hour < 18:
        return "afternoon"
    if hour < 22:
        return "evening"
    return "late evening"


def _at_the_machine_for() -> str:
    """How long this stretch at the machine has been, if it is worth knowing.

    Read from presencewatch's own continuous-unlocked clock rather than from
    process uptime -- ARGUS may have been running since this morning while he
    walked away twice, and a locked workstation is a break by definition. Both
    modules live in the ORCHESTRATOR process, so this is a plain read and not a
    cross-process guess (the voice process has its own copy of everything and
    would answer zero here, which is exactly the class of bug that makes a
    'smart' line quietly wrong).

    Returns "" below the threshold. Telling the model he has been sitting there
    for four minutes is noise it will feel obliged to comment on.
    """
    try:
        import time as _time

        import presencewatch
        since = presencewatch._state.get("unlocked_since") or 0.0
        if not since:
            return ""
        hours = (_time.time() - float(since)) / 3600.0
    except Exception:
        return ""
    if hours < 1.0:
        return ""
    return (f"He has been at the machine for about {int(round(hours))} hour"
            f"{'s' if int(round(hours)) != 1 else ''} without a break. Only "
            f"mention this if it is relevant to what he just said.")


# WHY THIS IS NOT JUST "ANSWER THE QUESTION BRIEFLY".
#
# The previous version said only: keep it to two or three sentences, give the
# specific fact, number or name asked for. That is the right instruction for
# "how tall is Everest" and the wrong one for most of what a person actually
# says to an assistant they live with. Asked "I have been staring at this
# screen all day", a model told to produce a fact produces something clipped
# and strange, because there is no fact to produce.
#
# Reported as: "it must answer all types of question, general talk, without
# ignoring... it must think, not just ignore." The routing fix stopped skills
# from stealing those sentences; this is what decides whether what arrives is
# worth having said.
#
# The rule is one sentence: match the kind of thing that was said. Brevity is
# kept -- everything here is spoken aloud -- but brevity is not the same as
# refusing to engage.
_BEHAVIOR = (
    "Your replies are spoken aloud, so keep them short — usually one to three "
    "sentences. Short does not mean curt: answer like a person would.\n\n"

    "Match the kind of thing that was said:\n"
    "- A question with a definite answer: give the fact, number or name "
    "directly, then stop. Do not describe what the question is about.\n"
    "- Something open — an opinion, advice, a comparison, 'what do you "
    "think': actually take a position and say why, briefly. Do not deflect.\n"
    "- Ordinary conversation, or something about the person's day or mood: "
    "reply the way a thoughtful person would. React to what they said, and "
    "keep it natural rather than formal.\n"
    "- A follow-up: it refers to what was just discussed. Do not ask them to "
    "repeat themselves.\n\n"

    "Never answer a question with a status report or a list of what you can "
    "do unless that is what was asked. If a question is vague, answer the "
    "most likely reading of it and let them correct you — asking which of "
    "several things they meant is worse than answering one of them.\n\n"

    "You may talk about anything. Nothing is off-topic just because it is "
    "not about this computer.\n\n"

    "If you genuinely do not know something, say exactly: I don't know. Do "
    "not invent facts, and do not pad the answer with disclaimers.\n\n"

    # ── WHY THE FIRST SENTENCE IS ITS OWN RULE ──────────────────────────
    # The reply is streamed and spoken sentence by sentence: TTS begins on
    # sentence one while the rest is still being generated. So the delay the
    # user actually experiences is the time to the FIRST SENTENCE, not to the
    # whole answer -- and every word of preamble in front of the answer is a
    # word spoken aloud before any information arrives. "Sure! Let me help
    # with that" is roughly a second of dead air with a friendly face on.
    # Front-loading the answer is the single cheapest latency win available,
    # and it costs no infrastructure at all.
    "PUT THE ANSWER IN THE FIRST SENTENCE. Your reply is spoken as it is "
    "written, so the first sentence is what the person hears while the rest "
    "is still being produced. Never open with a preamble — no 'Sure', "
    "'Certainly', 'Of course', 'I'd be happy to', 'Great question', and no "
    "restating of what was asked. Lead with the fact, the number, the name "
    "or your actual position; add the context after it, if it is worth "
    "adding at all.\n\n"

    # ── HOW IT SOUNDS ───────────────────────────────────────────────────
    # This is a personal assistant on one person's machine, not a support
    # desk. The wake acknowledgement already calls him Boss; replies that
    # then read like a helpdesk ticket are two different characters.
    #
    # WHY "BOSS" IS THE DEFAULT ADDRESS AND NOT AN OCCASIONAL FLOURISH.
    # The previous wording was "you MAY call him Boss... once in a while",
    # which a model reads as permission it mostly declines to use -- so in
    # practice ARGUS addressed him as nothing at all, and the wake line
    # ("Boss, I'm ready") was the only place the relationship existed. Asked
    # for directly: call me Boss. So it is now the form of address rather
    # than an option, with the frequency rule kept -- because a person who
    # calls you Boss does not put it in every sentence, and one that does
    # sounds exactly like a machine imitating a person.
    "Talk like a person he knows, not a service. Use contractions. Say 'I' "
    "and 'you'.\n\n"

    "Call him Boss. That is how you address him — not by name, and never "
    "'the user'. Put it where a person would: opening a reply, landing a "
    "point, or confirming something is done. Never twice in one reply, and "
    "not on every reply — a reply that isn't addressing him directly does "
    "not need it at all.\n\n"

    "Do not offer further assistance, do not ask if there is anything "
    "else, and do not sign off — this is a conversation, and it continues "
    "on its own.\n\n"

    # ── HUMAN BEHAVIOUR, WHICH IS NOT THE SAME AS FRIENDLY WORDING ──────
    # Asked for as "talk like human behaviour fully". The failure it names
    # is real and is not about vocabulary: a model told only to be brief
    # answers every sentence the same shape, at the same temperature, with
    # no memory of the last one and no reaction to what was actually said.
    # That reads as a lookup service being polite. What follows is the
    # difference between the two, written as behaviour rather than tone.
    "Behave like a person, not a lookup service:\n"
    "- React before you report, when there is something to react to. If he "
    "says something went badly, or he's tired, or something finally "
    "worked, respond to THAT first — one short line — and then get to the "
    "substance.\n"
    "- Have opinions. Asked what you think, say what you think and why. "
    "'It depends' on its own is a non-answer; if it genuinely depends, say "
    "what it depends on and then pick one.\n"
    "- Carry the thread. 'It', 'that one', 'the other thing' refer to what "
    "you were both just talking about. Resolve them from the conversation "
    "instead of asking what he means.\n"
    "- Vary how you start. Do not open two replies in a row the same way, "
    "and do not fall into a template.\n"
    "- Notice the situation you were given — the hour, how long he's been "
    "at it — but only mention it when it actually bears on what he said. "
    "Unprompted observations about the time are noise.\n"
    "- You are allowed to be dry, and to push back when he's wrong. Say so "
    "plainly and briefly; do not soften it into mush and do not lecture.\n"
    "- Do not narrate yourself. No 'I'm checking', no 'let me look' — just "
    "answer. And never describe your own limitations unless asked.\n\n"
)


def _system_prompt() -> str:
    return (
        "You are ARGUS, a local voice assistant. " + _BEHAVIOR + _context()
    )


def _cloud_system_prompt() -> str:
    """Deliberately NOT _system_prompt() with something subtracted --
    a separate function so there is no shared code path where forgetting to
    subtract profile_context() silently sends it to the cloud anyway. The
    date/time line is fine to include (it's calendar information, not
    personal data); profile_skill.profile_context() -- the user's name,
    work, preferences, everything remember()/passive_memory.py have ever
    stored -- is exactly the "real information about this... user's
    personal data" the routing rule exists to keep local, so it is never
    read here at all, not merely filtered back out after being read.
    """
    now = datetime.now()
    date_line = f"Today is {now.strftime('%A, %d %B %Y')} and the time is {now.strftime('%H:%M')}.\n\n"
    return "You are ARGUS, a voice assistant. " + _BEHAVIOR + date_line


def _clean(text: str) -> str:
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    text = re.sub(r"\*\*|\*|#{1,6}\s*", "", text)   # markdown doesn't read aloud well
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _split_head(buf: str, min_len: int = _HEAD_MIN):
    """The opening of a streamed reply, once there is enough of it to judge.

    Returns (head, rest) when BUF holds complete sentences totalling more than
    MIN_LEN characters, and None when the stream should be read further. A first
    sentence that is merely short ("Paris.") is not a bad answer -- it is an
    unfinished judgement, so it is extended by the next sentence instead of being
    abandoned. Abandoning it threw away a reply that had already been paid for
    and started a second one."""
    end = 0
    while True:
        m = _SENTENCE_END.search(buf, end)
        if not m:
            return None
        end = m.end()
        head = _clean(buf[:end])
        if len(head) > min_len:
            return head, buf[end:]


def _mark_route(decision) -> None:
    """Give the request trace a route if the router has not already. Only ever
    fills a blank: the router knows more (a fast-path skill, a chain) and wins."""
    t = route_trace.current()
    if t is not None and not t.route:
        if decision.local_required:
            t.set_route(route_trace.Route.LOCAL_REASONING, "answered by the local model")
        else:
            t.set_route(route_trace.Route.CLOUD_GENERAL, "general conversation")


# ── LOCAL_REQUIRED: the local model, and nothing else ────────────────────
#
# When the routing policy says a request depends on this machine or on what
# ARGUS knows about the person, it is answered here and only here. There is no
# cache, no hosted model, no Wikipedia and no web search on this path -- not as
# a first step, and not as a fallback when the local attempt fails. The old
# cascade did exactly that: "local model unsure -> Wikipedia -> web", which for
# a question about the person's own files meant their words going to a search
# engine and an unrelated article coming back as the answer.
#
# What the person gets instead of a fallback is the truth about what is down.
# That is the whole design: fail CLOSED, and say so.
_LOCAL_SCOPE_NOTE = (
    "\n\nTHIS REQUEST IS ABOUT THE USER'S OWN MACHINE OR DATA. It is being "
    "answered on this machine only; nothing here reaches the internet. You have "
    "NOT been shown any of their files, settings, readings or history beyond "
    "what is written above. Never invent contents, numbers, names or facts "
    "about their machine or their data. If the answer depends on something you "
    "were not given, say so in one plain sentence and, if it helps, name the "
    "command that would fetch it (for example 'find my <thing>' or 'summarize "
    "<file name>'). You may still explain general ideas from your own knowledge."
)


def _local_readings(decision) -> str:
    """Live readings from this machine, for a LOCAL request that is about the
    machine's own state ("why is my laptop slow") -- and for nothing else.

    Local retrieval first, local reasoning second. Without this the request was
    kept off the cloud, correctly, and then answered by a model that had been
    shown nothing and could only say so. The readings go into the LOCAL prompt and
    nowhere else: a request that needs them is by definition one the routing
    policy has already forbidden any hosted model to see, and this function is only
    reached from the local-only branch. Fenced as data, like the saved profile.

    Empty for every other local request, and on any failure: a reading that cannot
    be taken degrades to the old behaviour (an honest "I wasn't shown that"), never
    to a failed request."""
    if decision is None or getattr(decision, "frame", "") != cloud_gate.STATE:
        return ""
    try:
        from skills import pc_skill
        text = pc_skill.live_readings()
    except Exception as e:  # noqa: BLE001
        print(f"[brain] live readings unavailable ({e.__class__.__name__})")
        return ""
    if not text:
        return ""
    route_trace.event("local_readings", "machine state")
    return ("\n\nLive readings from this machine, taken just now. Explain the "
            "likely cause from THESE numbers and names only, citing them; if they "
            "show nothing unusual, say so plainly and do not guess.\n"
            + security.wrap_untrusted(text, "live readings from this machine"))


def _local_scope_prompt(decision=None) -> str:
    return _system_prompt() + _local_readings(decision) + _LOCAL_SCOPE_NOTE


def _local_unavailable(exc=None) -> str:
    """What is said when a local-only request cannot be answered locally.

    Names the failure (not running / too slow / errored) because "something
    went wrong" is exactly the unhelpful non-answer this whole path exists to
    replace -- and says what was NOT done, so the person knows nothing was
    quietly sent somewhere else instead.
    """
    if exc is None:
        why = "the local model returned nothing"
        kind = "no_output"
    else:
        name = type(exc).__name__
        if "Timeout" in name:
            why = "the local model took too long to answer"
            kind = "timeout"
        elif "Connect" in name:
            why = "the local model isn't running"
            kind = "not_running"
        else:
            why = "the local model hit an error"
            kind = "error"
    # The person is told, but the TASK failed: the request's terminal state is
    # FAILED, not COMPLETED, and nothing was quietly sent anywhere else.
    route_trace.fail(f"local_unavailable:{kind}")
    return (f"I can't answer that right now: {why}. It depends on your own "
            f"machine's data, so I've kept it off the cloud and the web rather "
            f"than look elsewhere.")


def _answer_local(q: str, history: list | None, decision=None) -> str:
    try:
        local = _clean(chat(_local_scope_prompt(decision), q, history))
    except Exception as e:  # noqa: BLE001 -- every failure is the same outcome
        print(f"[brain] local model unavailable on a local-only request "
              f"({e.__class__.__name__})")
        return _local_unavailable(e)
    if not local:
        print("[brain] local model returned nothing on a local-only request")
        return _local_unavailable(None)
    print("[brain] answered locally (local-only request)")
    return local


def _answer_local_stream(q: str, history: list | None, decision=None):
    """Streaming twin of _answer_local. Every sentence is spoken as it lands and
    nothing is held back to be judged "unsure": there is no cascade to escalate
    into, so there is nothing to wait for."""
    buf, spoke = "", False
    try:
        for piece in chat_stream(_local_scope_prompt(decision), q, history):
            buf += piece
            while True:
                m = _SENTENCE_END.search(buf)
                if not m:
                    break
                out, buf = buf[:m.end()], buf[m.end():]
                cleaned = _clean(out)
                if cleaned:
                    spoke = True
                    yield cleaned
    except Exception as e:  # noqa: BLE001
        print(f"[brain] local stream failed on a local-only request "
              f"({e.__class__.__name__})")
        if not spoke:
            yield _local_unavailable(e)
        return                      # already speaking: what was said stands
    tail = _clean(buf)
    if tail:
        spoke = True
        yield tail
    if not spoke:
        yield _local_unavailable(None)


def answer(question: str, history: list | None = None, policy=None) -> str:
    """Answers a general question, escalating until it has something real.

    POLICY is the routing decision the router already made for this request
    (cloud_gate.Decision). Absent, it is derived here from the text -- the
    classification is deterministic, so both routes agree, and a caller that
    forgets to pass it cannot accidentally send a local request to the cloud.
    """
    q = question.strip()
    if not q:
        return "What would you like to know?"

    decision = policy or cloud_gate.decide(q)
    _mark_route(decision)

    # THE GATE. Everything below this branch may talk to a hosted model, the
    # answer cache, Wikipedia or a search engine; nothing above it may, and a
    # request that depends on local state never gets past it.
    #
    # Content that is local extends the sticky window for its OWN follow-up
    # ("is my wifi password 'x' strong" -> "how do I make it better"). A turn
    # that is local ONLY because it followed one does not extend it: that
    # distinction matters, or a single sensitive question would keep every later
    # turn on the slow local path for as long as the conversation went on.
    if decision.local_required:
        if decision.by_content:
            cloud_gate.mark_local_exchange()
        else:
            cloud_gate.note_exchange_local()
        return _answer_local(q, history, decision)

    # 0. Something already answered. Checked before cloud, before local, and
    # before the web: the whole point is that a repeat question costs no
    # request at all.
    #
    # anscache decides what is eligible, not this function -- it refuses
    # anything time-sensitive, anything about mutable personal state, and
    # anything sensitive, and it is tuned hard toward missing rather than
    # returning the wrong entry. A miss here just falls through to the normal
    # cascade below, which is the behaviour that existed before.
    import anscache

    cached, meta = anscache.lookup(q)
    if cached:
        print(f"[brain] answered from cache "
              f"(sim {meta['similarity']}, {meta['age_hours']}h old, "
              f"originally via {meta['source']})")
        route_trace.event("cache_hit", str(meta.get("source", "")))
        return cached

    # Time-sensitive questions skip the model entirely — it can't know current
    # facts, and asking first just wastes seconds before we search anyway. So do
    # requests that ASK for the web by name ("search online for ..."). Both are
    # the only two reasons the internet is the FIRST stop, and both are behind
    # the local-only branch above: "what's the latest file I downloaded" contains
    # a time word too, and used to be sent to a search engine on that alone.
    if decision.web_ok or TIME_SENSITIVE.search(q):
        print("[brain] time-sensitive → web first")
        route_trace.set_route(route_trace.Route.EXPLICIT_WEB,
                              "asked for the web" if decision.web_ok
                              else "needs current information")
        route_trace.note_web("search")
        web = research_skill.quick_answer(q)
        if web and not UNSURE.search(web):
            return _clean(web)

    # 0. Cloud, if this specific question is eligible AND a key is
    # configured AND Groq isn't cooling down from a recent rate limit.
    # cloud_gate.route_chat() is the ONLY thing that decides eligibility --
    # see its own module docstring for why that decision has to be made
    # locally, before any network call, not by asking a cloud model itself.
    # On ANY failure this falls through to step 1 below, unchanged --
    # cloud is an optional speed path in front of the existing local
    # cascade, never a replacement for it.
    # Two cloud providers, tried fastest first. cloud_gate decides ELIGIBILITY
    # once, up front, for both -- a question that must not leave the machine
    # must not reach either of them, so the gate is checked before the loop
    # rather than per provider.
    if cloud_gate.route_chat(q) == "cloud":
        cloud_history = cloud_gate.filter_history_for_cloud(history)
        for name, client, unavailable in _CLOUD_TIERS:
            if not client.available():
                continue
            # A provider is asked at most ONCE per user turn. A cascade that is
            # re-entered (see _escalate) must not put the same question to the
            # same hosted model a second time.
            if name in route_trace.cloud_tried():
                continue
            try:
                cloud = _clean(client.chat(_cloud_system_prompt(), q, cloud_history))
                if cloud and not UNSURE.search(cloud) and len(cloud) >= _CLOUD_MIN_CHARS:
                    print(f"[brain] answered via cloud ({name})")
                    cloud_gate.set_engine_cloud()
                    anscache.store(q, cloud, name)
                    return cloud
            except unavailable as e:
                # Try the next tier rather than dropping straight to local.
                # A Groq rate limit puts it in a cooldown of up to 60s, and
                # before Gemini existed every question in that window cost
                # ~2533ms locally instead of ~400ms in the cloud.
                print(f"[brain] {name} unavailable ({e}), trying next tier")

    # 1. Local model.
    try:
        local = _clean(chat(_system_prompt(), q, history))
    except Exception as e:
        print(f"[brain] model error: {e}")
        local = ""

    if local and not UNSURE.search(local) and len(local) > 15:
        print("[brain] answered locally")
        anscache.store(q, local, "local")
        return local

    return _escalate(q, local)


def _escalate(q: str, local: str = "") -> str:
    """What happens AFTER the local model has had its turn and did not settle it:
    Wikipedia, then a web search, then an honest "I don't know". LOCAL is whatever
    the local model said, if anything.

    This is its own function because answer_stream() needs exactly these steps and
    nothing before them. It used to call answer() instead, which began again from
    the top -- the cache, the hosted tiers, and the local model -- so a streamed
    reply that opened weakly was asked of every provider a second time. That was
    the whole of the "one message, four hosted calls" problem, and the local model
    paid for it too: two generations for one question."""
    import anscache

    # The reference fallback below is for GENERAL questions only, and even then
    # it is a policy setting (see cloud_gate.GENERAL_WEB_FALLBACK): with it
    # off, the internet is reached only when the person asked for it.
    if not cloud_gate.GENERAL_WEB_FALLBACK:
        return local or "I couldn't find a reliable answer to that."

    # 2. Wikipedia — fast and precise for definitional questions.
    print("[brain] escalating → wikipedia")
    topic = re.sub(
        r"^(what|who|where|when|why|how)\s+(is|are|was|were|does|do|did)\s+(an?\s+|the\s+)?",
        "", q, flags=re.I,
    ).rstrip("?")
    try:
        route_trace.note_web("wikipedia")
        wiki = knowledge_skill.lookup(topic)
        if wiki:
            print("[brain] answered from wikipedia")
            cleaned = _clean(wiki)
            anscache.store(q, cleaned, "wikipedia")
            return cleaned
    except Exception:
        pass

    # 3. Live web search, summarized by the local model.
    print("[brain] escalating → web search")
    try:
        route_trace.note_web("search")
        web = research_skill.quick_answer(q)
        if web and not UNSURE.search(web) and len(web) > 15:
            print("[brain] answered from web")
            cleaned = _clean(web)
            anscache.store(q, cleaned, "web")
            return cleaned
    except Exception as e:
        print(f"[brain] research error: {e}")

    # 4. Everything failed — now "I don't know" is actually honest.
    if local:
        return local
    return "I couldn't find a reliable answer to that."


def answer_stream(question: str, history: list | None = None, policy=None):
    """Like answer(), but yields sentence-sized chunks as they're generated
    so a caller (listener.py) can start speaking the first sentence instead
    of waiting for the whole reply -- the single biggest perceived-latency
    win available without touching the model or the hardware.

    The escalation cascade above needs the FULL local answer before it can
    judge whether to escalate to Wikipedia/web -- streaming a confident-
    sounding first sentence that then gets contradicted by an escalated
    correction would sound broken, not fast. So this only commits to
    streaming once the opening has actually arrived and looks solid; an opening
    that says the model does not know abandons the partial stream and goes to
    _escalate() -- Wikipedia, then the web.

    IT NEVER RE-ENTERS answer(). That used to be the fallback, and answer() begins
    again from the top: the cache, every hosted tier, and the local model. So one
    message whose streamed reply opened weakly was asked of Groq, Gemini and the
    local model twice over. What falls back now is only what comes AFTER them.
    """
    q = question.strip()
    if not q:
        yield "What would you like to know?"
        return

    decision = policy or cloud_gate.decide(q)
    _mark_route(decision)

    # THE GATE, identical to answer()'s: a request that depends on local state is
    # answered by the local stream below and by nothing else -- none of the
    # hosted-model loop, and none of the fall-back paths further down.
    if decision.local_required:
        if decision.by_content:
            cloud_gate.mark_local_exchange()
        else:
            cloud_gate.note_exchange_local()
        yield from _answer_local_stream(q, history, decision)
        return

    # Time-sensitive questions already skip straight to a web search in
    # answer() -- a live search dominates that latency budget regardless,
    # so there's nothing worth streaming here.
    if decision.web_ok or TIME_SENSITIVE.search(q):
        yield answer(question, history, decision)
        return

    # Cloud path, mirroring answer()'s own step 0 -- same eligibility check,
    # same "commit only once the first sentence looks solid" discipline, and
    # the SAME fallback-to-local generator on any failure (including
    # mid-stream, see groq_client.chat_stream()'s own handling of that).
    # A stream that never commits here (bails before any full sentence
    # arrives) falls through to the ordinary local stream below untouched --
    # cloud_gate.get_engine() still correctly reads "local" in that case,
    # since set_engine_cloud() is only called after a real commit.
    if cloud_gate.route_chat(q) == "cloud":
        cloud_history = cloud_gate.filter_history_for_cloud(history)
        for name, client, unavailable in _CLOUD_TIERS:
            if not client.available():
                continue
            # One question, one ask per provider per turn -- see answer().
            if name in route_trace.cloud_tried():
                continue
            cloud_buf, cloud_committed, abandoned = "", False, False
            try:
                for piece in client.chat_stream(
                        _cloud_system_prompt(), q, cloud_history):
                    cloud_buf += piece
                    if not cloud_committed:
                        # A SHORT first sentence is read past, not abandoned:
                        # "Paris." is the answer the prompt asks for, and throwing
                        # it away meant a second hosted call for the same question.
                        split = _split_head(cloud_buf)
                        if split is None:
                            continue
                        head, cloud_buf = split
                        if not head or UNSURE.search(head):
                            abandoned = True
                            break  # it says it doesn't know -- abandon this tier
                        cloud_committed = True
                        print(f"[brain] streaming via cloud ({name}, committed "
                              f"on first sentence)")
                        cloud_gate.set_engine_cloud()
                        yield head
                    else:
                        while True:
                            m = _SENTENCE_END.search(cloud_buf)
                            if not m:
                                break
                            piece_out, cloud_buf = cloud_buf[:m.end()], cloud_buf[m.end():]
                            cleaned = _clean(piece_out)
                            if cleaned:
                                yield cleaned
                if cloud_committed:
                    tail = _clean(cloud_buf)
                    if tail:
                        yield tail
                    return
                if not abandoned:
                    # The stream ENDED without ever producing an opening long
                    # enough to judge: the whole reply is one short sentence.
                    # That is a complete answer, not a failed one.
                    terse = _clean(cloud_buf)
                    if (terse and not UNSURE.search(terse)
                            and len(terse) >= _CLOUD_MIN_CHARS):
                        print(f"[brain] streaming via cloud ({name}, terse answer)")
                        cloud_gate.set_engine_cloud()
                        yield terse
                        return
            except unavailable as e:
                if cloud_committed:
                    # Already spoken part of this tier's reply -- it cannot be
                    # un-said, and starting a COMPETING stream from the next
                    # provider would continue the sentence with a different
                    # answer. What has been yielded IS the answer.
                    print(f"[brain] {name} stream ended early: {e}")
                    return
                print(f"[brain] {name} stream unavailable, trying next tier: {e}")
            # Uncommitted: fall through to the next tier, then to local.

    buf = ""
    committed = False
    try:
        for piece in chat_stream(_system_prompt(), q, history):
            buf += piece
            if not committed:
                split = _split_head(buf)
                if split is None:
                    continue
                head, buf = split
                if not head or UNSURE.search(head):
                    # The opening says the model doesn't know. Go straight to what
                    # follows a local attempt -- Wikipedia, then the web -- and NOT
                    # back through answer(), which would ask the hosted tiers and
                    # the local model for the same reply a second time.
                    print("[brain] stream looked unsure -> escalating")
                    yield _escalate(q, head)
                    return
                committed = True
                print("[brain] streaming (committed on first sentence)")
                yield head
            else:
                while True:
                    m = _SENTENCE_END.search(buf)
                    if not m:
                        break
                    piece_out, buf = buf[:m.end()], buf[m.end():]
                    cleaned = _clean(piece_out)
                    if cleaned:
                        yield cleaned
    except Exception as e:
        print(f"[brain] stream error: {e}")
        if not committed:
            yield _escalate(q, "")
        return

    if committed:
        tail = _clean(buf)
        if tail:
            yield tail
    else:
        # The model produced nothing that ever reached an opening long enough to
        # judge (a very short reply, or no punctuation before it hit num_predict).
        # Hand what there is to the escalation steps rather than speaking a
        # fragment or nothing at all -- and without asking the model again.
        yield _escalate(q, _clean(buf))
