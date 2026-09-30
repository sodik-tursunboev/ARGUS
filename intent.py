"""
ARGUS - Fast-path intent matching.

Resolves unambiguous commands with pattern rules instead of a model call —
microseconds instead of seconds. Only genuinely open-ended input falls through
to the LLM.

App names are NOT matched against an allowlist here. Whatever noun follows
"open"/"close" is passed to apps_skill, which resolves it against everything
installed on the machine.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import re

import textmatch
from config import ASSISTANT_NAME, USER_FULL_NAME

_NAME_RE = ASSISTANT_NAME.lower()

NUMBER_WORDS = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
    "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
    "twenty": 20, "thirty": 30, "forty": 40, "forty five": 45, "fifty": 50,
    "sixty": 60, "ninety": 90, "a": 1, "an": 1,
}

UNIT_SECONDS = {"second": 1, "sec": 1, "minute": 60, "min": 60, "hour": 3600, "hr": 3600}

# Multipliers for "half an hour" / "quarter of an hour". These have to be
# applied explicitly: "a"/"an" are in NUMBER_WORDS as 1, so without this the
# fraction word is matched over and thrown away.
_FRACTION_WORDS = {"half": 0.5, "quarter": 0.25}

# Structural pieces for volume, matched as "a sound-ish noun" + "a direction"
# rather than as a list of exact phrasings. The old approach enumerated four
# sentences ("volume up", "turn it up", "louder", "turn up the volume") and
# missed everything else a person actually says -- "raise the volume", "turn
# the sound up", "lower the music" all fell through to the LLM. Requiring BOTH
# a noun and a direction is what keeps this from over-matching: "the volume of
# a sphere" has the noun and no direction, "turn down the offer" has the
# direction and no noun, and neither is treated as a command.
# A bare pronoun is not a target. "close it" names nothing ARGUS can look up,
# so the app/window patterns below must NOT claim it -- they used to match with
# target="it" and report "it doesn't appear to be running". Falling through
# instead lets followup_skill resolve the pronoun against whatever was just
# acted on, which is what the user actually meant.
_BARE_PRONOUN = re.compile(r"^(?:it|that|this|them|those)(?:\s+again)?$")

_SOUND_NOUN = r"\b(volume|sound|audio|music)\b"
_LOUDER = r"\b(up|higher|louder|raise|increase|boost|crank)\b"
_QUIETER = r"\b(down|lower|quieter|softer|decrease|reduce)\b"

# Words that follow "open" but mean a website, not an installed app
WEB_TARGETS = {
    "youtube": "https://youtube.com",
    "google": "https://google.com",
    "gmail": "https://mail.google.com",
    "github": "https://github.com",
    "linkedin": "https://linkedin.com",
    "chatgpt": "https://chat.openai.com",
    "reddit": "https://reddit.com",
    "twitter": "https://twitter.com",
    "x": "https://x.com",
}


# Politeness wrappers that carry no intent of their own. Note these are
# matched AFTER punctuation is stripped above, so contractions are already
# flattened ("i'd" -> "i d") -- spell them the way they arrive, not the way
# they're written.
# ORDER MATTERS. Python's alternation is first-match, not longest-match, so a
# short alternative listed before a longer one that starts the same way wins
# and leaves the rest behind: with "would you" ahead of "would you mind",
# "would you mind opening telegram" became "mind opening telegram" and matched
# nothing. Longest first, always.
#
# Deliberately NOT here: "tell me". It looks like politeness but it is load
# bearing -- "tell me a joke" is matched by a pattern containing that exact
# phrase, and stripping it would break the very commands it appears in.
_PREFIXES = re.compile(
    r"^(?:"
    r"i would like you to|i'd like you to|i want you to|i need you to|"
    r"would you mind|do you mind|go ahead and|do you know|"
    r"can you|could you|would you|will you|"
    r"please|hey"
    r")\s+"
)

# Verbs that mean the sentence is an instruction to the machine.
_COMMAND_VERBS = (
    r"open|close|launch|start|run|quit|kill|play|pause|stop|resume|"
    r"mute|unmute|set|take|check|show|find|search|look|read|write|"
    r"minimi[sz]e|maximi[sz]e|focus|switch|turn|remind|remember|forget|"
    r"lock|restart|shut|tell|give|make|put|send|delete|remove|cancel"
)

# "let's" and friends only introduce a command when a command verb follows.
# CONDITIONAL on purpose: stripping them unconditionally turned conversation
# into instructions -- "let's go to the shop" became "go to the shop" and then
# matched apps/open with a target of "shop", so ARGUS went looking for an
# application called Shop. "let's open telegram" is an instruction; "let's go
# to the shop" is not, and the only thing distinguishing them is the verb.
_SOFT_PREFIXES = re.compile(
    r"^(?:let's|lets|just|maybe|why don't you|why dont you|how about you)\s+"
    rf"(?=(?:{_COMMAND_VERBS})\b)"
)

# The missing half. There was a prefix stripper and no suffix one, so the
# politeness people put at the END of a sentence was swallowed into the
# TARGET rather than discarded:
#
#     "open telegram please"        -> target "telegram please"
#     "could you open telegram for me" -> target "telegram for me"
#
# The skill matched, so this looked like success -- and then apps_skill went
# looking for an application literally named "telegram please" and answered
# "I couldn't find an app called telegram please on this machine". That is
# exactly the reported "if I ask another way it just ignores it": the command
# was understood and then thrown away one layer down.
_SUFFIXES = re.compile(
    r"[\s,]+(?:please|for me|thanks|thank you|thanx|"
    r"if you can|if you could|if you don t mind|would you|will you|"
    r"right now|now|already|mate|buddy)\s*$"
)

# "ok" AND "okay" ARE NOT ALWAYS POLITENESS, and treating them as though they
# were cost a whole class of question. They used to sit in the list above, so
# _clean() rewrote:
#
#     "is everything okay"  ->  "is everything"
#     "is anything ok"      ->  "is anything"
#
# which matched no pattern at all and fell through to the model -- while "is
# everything alright", the same question in different words, routed correctly
# to the anomaly check. The most natural way to ask ARGUS whether the machine
# is fine was the one phrasing it could not hear, and nothing reported a
# problem because a fall-through to chat looks like a normal answer.
#
# The distinction is grammatical, not a list of exceptions: after an
# INSTRUCTION, a trailing "ok" is the speaker checking agreement ("open
# notepad, ok"). After a QUESTION opened by a copula or an auxiliary, "okay" is
# the thing being asked about, and removing it deletes the predicate.
_TRAILING_OK = re.compile(r"[\s,]+(?:ok|okay)\s*$")
_ASKS_A_QUESTION = re.compile(
    r"^(?:is|are|was|were|am|do|does|did|can|could|should|would|will|"
    r"has|have|had|anything|everything|all)\b")

# "would you mind OPENING telegram" -- the polite forms take a gerund, which
# then matches no verb pattern at all. Only applied to the first word, so
# ordinary prose containing a gerund is untouched.
# Every way people actually say "write this down". Used in two places (the
# early precedence guard and the vault block) so the phrasings can't drift
# apart. "make/take/add/jot" were missing entirely, so the single most natural
# form -- "make a note that ..." -- matched nothing here at all.
_VAULT_WRITE = re.compile(
    r"^(?:"
    # "make/take/add a note that ..." -- an explicit note noun
    r"(?:make|take|add|jot|write|put)\s+(?:me\s+)?(?:a|an|this)?\s*"
    r"(?:quick\s+)?(?:note|reminder)\b\s*(?:that\s+|about\s+|saying\s+)?"
    # "jot down ...", "write down ..." -- the particle carries the meaning
    r"|(?:jot|write|note|put)\s+down\s+(?:that\s+)?"
    # "remember/save/log that <not about me>". The negative lookahead is what
    # keeps this out of profile's territory: "remember that I like tea" is a
    # FACT ABOUT THE USER and belongs to profile/remember (intent.py's own
    # profile block owns "remember|note that i|my|im"), while "remember that
    # the wifi password changed" is a note. Without the lookahead this guard
    # swallowed both and personal facts stopped reaching the profile.
    # The lookahead has to SPAN the optional "that". Placed after it, regex
    # backtracking simply skips "that" and tests the lookahead against
    # "that i like tea" -- which is not a self-reference, so it passed and
    # personal facts were still swallowed. It has to be checked at the point
    # right after the verb, looking over an optional "that".
    r"|(?:remember|note)\s+(?!(?:that\s+)?(?:i|my|im|i'm)\b)(?:that\s+)?"
    # save/log are never claimed by profile, so they need no exclusion.
    r"|(?:save|log)\s+(?:that\s+)?"
    r")(.+)$"
)

_GERUNDS = {
    "opening": "open", "closing": "close", "launching": "launch",
    "starting": "start", "running": "run", "quitting": "quit",
    "playing": "play", "pausing": "pause", "stopping": "stop",
    "muting": "mute", "unmuting": "unmute", "setting": "set",
    "taking": "take", "checking": "check", "turning": "turn",
    "showing": "show", "finding": "find", "searching": "search",
    "minimizing": "minimize", "minimising": "minimize",
    "maximizing": "maximize", "maximising": "maximize",
    "telling": "tell", "reminding": "remind", "killing": "kill",
}


def _clean(text: str) -> str:
    t = text.lower().strip()
    # BUGFIX: apostrophes used to be replaced with a space here, BEFORE any
    # pattern ran. That silently killed one branch of every regex written as
    # (?:'s| is) -- "what's running", "how's my pc", "that's all" and friends
    # could only ever match via their spelled-out " is" half, so the
    # contraction people actually say fell through to the LLM. (The symptom
    # was patched once by hand-adding a literal "hows it going" alternative in
    # the social block; this fixes the cause instead.) Curly apostrophes are
    # normalised first so text pasted from elsewhere behaves the same as text
    # from the speech recogniser.
    t = t.replace("’", "'")
    t = re.sub(r"[^\w\s%:']", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    # Strip the assistant's own name if it survived into the command text.
    t = re.sub(rf"^(hey |ok |okay )?{_NAME_RE}\b,?\s*", "", t)
    # Looped, not a single pass: these stack in real speech ("can you please
    # open notepad"), and stripping only the outer one leaves "please open
    # notepad" -- which then fails every pattern anchored on the verb.
    # Both ends, looped: real speech stacks these ("hey can you please open
    # notepad for me thanks"), and stripping one layer leaves the next one
    # anchored where a pattern expects the verb or the target.
    for _ in range(4):
        stripped = _PREFIXES.sub("", t)
        stripped = _SOFT_PREFIXES.sub("", stripped)
        stripped = _SUFFIXES.sub("", stripped).strip()
        # Conditional, and checked against the sentence as it stands NOW --
        # after the prefixes have come off, so "hey is everything okay" is
        # recognised as a question by this point rather than as something
        # starting with "hey". See _TRAILING_OK.
        if not _ASKS_A_QUESTION.match(stripped):
            stripped = _TRAILING_OK.sub("", stripped).strip()
        if stripped == t:
            break
        t = stripped

    # "would you mind opening telegram" -> "opening telegram" -> "open telegram"
    parts = t.split(" ", 1)
    if parts and parts[0] in _GERUNDS:
        parts[0] = _GERUNDS[parts[0]]
        t = " ".join(parts)

    # "do you know what time it is" -> "what time is it". The inverted form is
    # how people actually ask once the question is embedded in another clause,
    # and it matched no pattern because every one of them expects "is it".
    t = re.sub(r"\bwhat (time|day|date) it is\b", r"what \1 is it", t)

    return t.strip()


def _num(token: str):
    token = token.strip()
    if token.isdigit():
        return int(token)
    return NUMBER_WORDS.get(token)


# ══════════════════════════════════════════════════════════════════════
# DOES THIS SENTENCE ASK FOR A READING FROM THIS MACHINE?
#
# THE ARCHITECTURAL POINT. The telemetry fast paths used to fire on a NOUN --
# cpu, battery, disk, memory -- so any sentence containing one was captured
# before anything could think about it. The real log has:
#
#     command  What can you do over my PC?
#     reply    System status: CPU at 32 percent, memory at 64 percent...
#
# Nothing was ignored there. A regex saw "my PC", fired pc/stats, and the
# question never reached anything capable of answering it. A confident wrong
# answer is worse than silence: it looks like the assistant cannot understand
# you, which is what kept being reported as "it ignores me".
#
# The fix is NOT another list of banned words. Blacklisting "explain", "should
# i", "is it bad" only covers the phrasings someone happened to observe, and
# the next wording breaks it again. This is a WHITELIST OF SHAPES: a small,
# closed set of ways English asks for a current value. Anything that is not
# one of those shapes goes to the language model, which is the default and
# should always have been.
#
# The four shapes, and why each is unambiguous:

# 1. A possessive tied to a metric, near the start of the question -- so the
#    metric is what is being ASKED ABOUT, not something mentioned in passing.
#    "what is my cpu usage" asks about the CPU; "what can you do over my pc"
#    mentions the PC while asking about ARGUS, and the distance from the
#    question word is what separates them.
_METRIC = (r"pc|computer|laptop|machine|system|cpu|processor|ram|memory|"
           r"disk|drive|storage|space|battery|charge|screen|brightness|"
           r"volume|network|wifi|internet|connection|ip")
#    The question must OPEN with a state word. "should i leave my laptop
#    plugged in overnight" also puts "my laptop" three words in, and was
#    answered with a battery percentage -- but it opens with "should", which
#    asks for advice, not a reading. Requiring the opener is what separates
#    them, and it does so by sentence shape rather than by banning "should".
_POSSESSIVE_TOPIC = re.compile(
    r"(?i)^\W*(?:hey\s+|ok\s+|argus\s+)*"
    r"(?:what(?:'s|s)?|how(?:'s|s)?|is|are|show|tell|give|check)\b"
    rf"(?:\s+\w+){{0,2}}\s+(?:my|this)\s+({_METRIC})\b")

# 2. A quantity question whose answer is a number about here and now.
_QUANTITY = re.compile(
    rf"(?i)\bhow\s+(?:much|many)\s+({_METRIC})?\b[^.?]{{0,24}}?"
    r"\b(?:do i have|have i got|is left|are left|is free|are free|"
    r"am i using|is being used|do i have left)\b"
    # English also puts the adjective first: "how much FREE SPACE is on my C
    # drive" never reaches the trailing form above, because "free" precedes
    # the noun instead of following it.
    rf"|\bhow\s+(?:much|many)\s+(?:free|available|spare|used|remaining)"
    rf"\s+({_METRIC})\b")

# 3. A metric named together with a reading word. "cpu usage", "battery
#    level" -- not how anyone phrases a question about the world.
#
#    "left" and "free" are deliberately NOT here. "my brain feels like it has
#    no memory left" is ordinary English about a tired person, and it was
#    answered with a RAM percentage. Those two words are carried by the
#    quantity shape above ("how much disk space is left"), which requires the
#    question form and so cannot swallow a sentence about a person.
_METRIC_READOUT = re.compile(
    rf"(?i)\b({_METRIC})\s+(?:usage|level|percentage|percent|status|"
    r"temperature)\b")

# 4. Fixed self-state questions. A closed set of phrases, not a vocabulary
#    that grows every time someone finds a new wording.
_SELF_STATE = re.compile(
    r"(?i)^\W*(?:system status|status report|"
    r"am i (?:charging|online|connected|muted)|"
    r"are you (?:online|connected)|"
    r"is it (?:charging|plugged in)|"
    r"what(?:'s| is) my ip|how(?:'s| is) my (?:pc|computer|laptop|system)"
    r")\b")

# 5. Asking what is CONSUMING something here -- a question about this
#    machine's contents, which only this machine can answer.
_CONSUMPTION = re.compile(
    r"(?i)\b(?:taking up|using up|hogging|eating|filling up)\b[^.?]{0,24}"
    rf"\b(?:{_METRIC})\b"
    r"|\b(?:biggest|largest)\b[^.?]{0,20}\b(?:files?|folders?|items?)\b")


# A DEFINITION / EXPLANATION question, as opposed to a request for a live
# value. This is the same distinction wants_live_reading() draws for pc/disk
# metrics, generalised to the concept-naming tools (weather, network) whose
# trigger word doubles as an everyday noun. "what's the difference between
# weather and climate" and "what is an ip address" are questions about the
# world; "what's the weather" and "what's my ip" are readings. The signal is
# the SHAPE -- an indefinite article, "difference between", "explain", "how
# does X work" -- never a keyword list of topics.
_DEFINITION = re.compile(
    r"(?i)\b("
    r"difference between|"
    r"what(?:'s| is| are)\s+(?:a|an)\b|"            # "what is an ip address"
    # "what is weather" / "what is inflation" -- the bare CONCEPT. Excludes
    # the reading shapes, which name the instance: "what is THE weather",
    # "what is MY ip", "what is IT like outside", "what is THERE to do".
    r"what(?:'s| is| are)\s+(?!the\b|my\b|your\b|this\b|its\b|it\b|there\b)\w+|"
    r"what does\b[^?]{0,40}\bmean|"
    r"the (?:difference|point|purpose|meaning)\b|"
    r"explain\b|describe\b|"
    r"how (?:does|do|did)\b[^?]{0,40}\b(work|form|happen)|"
    r"why (?:is|are|does|do|did)\b"
    r")")


def is_definition_question(t: str) -> bool:
    """True when the sentence asks what something IS, not for its current value."""
    return bool(_DEFINITION.search(t))


def wants_live_reading(t: str) -> bool:
    """True when the sentence asks for THIS machine's current state.

    Exposed rather than private: the reachability tests assert on it directly,
    and a second copy of this judgement would drift the way the math predicate
    did when it lived in three places.
    """
    return bool(_POSSESSIVE_TOPIC.search(t) or _QUANTITY.search(t)
                or _METRIC_READOUT.search(t) or _SELF_STATE.search(t)
                or _CONSUMPTION.search(t))


# ══════════════════════════════════════════════════════════════════════
# HOW HOT IS A PART OF THIS MACHINE?
#
# "temperature", "how hot" and "how cold" name the weather AND the hardware, and
# the WEATHER block used to take every one of them: "how hot is my cpu" was
# answered with today's forecast. Nothing here can read a component
# temperature -- pc_skill.live_readings() carries percentages, sizes and names,
# and diagnostics' "running hot" is CPU LOAD -- so there is no reading to route
# to, and the live-readings block further down must not be allowed to answer a
# heat question with a load percentage either ("is my cpu overheating" and
# "what is cpu temperature" both reached it as pc/stats). The honest
# destination is conversation, which is local-only for a question about this
# machine and is told not to invent numbers about it.
#
# Decided by how the sentence ATTACHES a heat word to a part, not by which
# sentences have been seen. The part is the thing being asked about ("how hot is
# my gpu", "cpu temperature", "temperature of the processor", "is my laptop
# running hot"). A weather question attaches the heat word to the air or a place
# ("how hot is it outside", "temperature in london"), which no shape below
# accepts, so those keep reaching the weather skill.
_HEAT_PART = (
    r"cpus?|gpus?|processors?|cores?|"
    r"graphics(?:\s+(?:card|chip|processor|unit))?|video\s+card|"
    r"rtx|gtx|geforce|radeon|ryzen|nvidia|"
    r"chipset|motherboard|mainboard|ssd|nvme|hdd|hard\s+(?:drive|disk)|"
    r"disk|drive|ram|memory|battery|fans?|"
    r"pc|computer|laptop|notebook|macbook|desktop|machine|rig|system")

# "my cpu", "the gaming laptop", "your graphics card": a determiner, up to two
# modifier words ("my main gpu"), then the part. A place noun straight after
# vetoes it -- "the computer room" is somewhere, not something.
_HEAT_NP = (r"(?:(?:my|your|our|this|that|the|these|those)\s+)?"
            r"(?:[a-z0-9]+\s+){0,2}?"
            r"(?:" + _HEAT_PART + r")\b(?!\s+(?:room|lab|office|shop|store)\b)")

# "temp" is also short for "temporary" ("my temp folder"), so on its own it only
# counts when no such noun follows.
_HEAT_WORD = (r"(?:temps|temperatures?|thermals?|"
              r"temp\b(?!\s+(?:folders?|files?|dirs?|directory|data|paths?|"
              r"space|storage|caches?|jobs?)))")

_HEAT_SHAPES = tuple(re.compile(p) for p in (
    # "how hot is my cpu", "how warm does the laptop get"
    r"\bhow\s+(?:hot|hotter|warm|warmer|cool|cooler|cold|colder)\s+"
    r"(?:is|are|was|were|does|do|did|has|have|will|would|can|could|gets?|getting)\s+"
    + _HEAT_NP,
    # "cpu temperature", "gpu temps", "graphics card core temp"
    r"\b(?:" + _HEAT_PART + r")\s+(?:(?:core|package|die|chip|board)\s+)?" + _HEAT_WORD,
    # "temperature of my processor", "temps on the gpu", "temperature in my pc"
    r"\b" + _HEAT_WORD + r"\s+(?:of|for|on|in|inside|within)\s+" + _HEAT_NP,
    # "how hot does it get inside my laptop": the subject is "it", so the part
    # arrives in a place phrase instead.
    r"\bhow\s+(?:hot|hotter|warm|warmer)\b[^.?]{0,24}?\b(?:in|inside|within)\s+"
    + _HEAT_NP,
    # "what are my temps", "how are my thermals"
    r"\b(?:my|our)\s+(?:temps|thermals?)\b",
    # "is my cpu overheating", "is the laptop running hot", "does my pc get too warm"
    r"\b(?:is|are|was|does|do|has)\s+" + _HEAT_NP +
    r"\s+(?:[a-z]+\s+){0,2}?(?:hot|warm|overheat\w*|heating\s+up|burning|boiling)\b",
))


def asks_machine_heat(t: str) -> bool:
    """True when the sentence asks how hot a PART OF THIS MACHINE is -- as
    opposed to how hot the day is. See the note above _HEAT_PART.

    Takes CLEANED text, which is what match() has. Callers holding what the
    person actually said want is_machine_heat_question()."""
    return any(rx.search(t) for rx in _HEAT_SHAPES)


def is_machine_heat_question(text: str) -> bool:
    """asks_machine_heat() for RAW user text.

    The router asks this before its chat gate: nothing reads a component
    temperature, so a heat question has no skill to be handed to however
    cloud_gate frames it. A public wrapper rather than the router calling
    intent._clean() itself -- router.py never reaches into a private name here.
    """
    return asks_machine_heat(_clean(text or ""))


# ══════════════════════════════════════════════════════════════════════
# WHAT LAUNCHES WITH THIS MACHINE -- asked, versus commanded.
#
# "which apps start at boot" contains the words "start" and "boot", and the
# SERVICE matcher (which reads a verb ANYWHERE in the sentence and takes the
# rest as a service name) turned it into service/start with the target "at
# boot" -- a question about startup entries staged as a state-changing action.
# Two things are defined here so the claim and the veto cannot disagree.
#
# _BOOT_LOCUS is WHEN in a machine's life something happens: at boot, on
# startup, with windows, when i log in. It is a time phrase, so it can end a
# sentence about startup entries and can never be a service's name.
_BOOT_LOCUS = (
    r"(?:"
    r"(?:at|on|during|upon|after)\s+(?:the\s+)?(?:(?:windows|system|pc|computer)\s+)?"
    r"(?:boot(?:\s?up)?|start\s?up|log\s?in|log\s?on|sign\s?in)"
    r"|with\s+(?:windows|(?:my|the|this)\s+(?:pc|computer|laptop|machine|system))"
    r"|(?:when|whenever|as|every\s+time|each\s+time)\s+"
    r"(?:windows|(?:my|the|this)\s+(?:pc|computer|laptop|machine|system)|i)\s+"
    r"(?:starts?|boots?|loads?|logs?|signs?|turns?)(?:\s+(?:up|in|on))?"
    r"(?:\s+(?:my|the)\s+(?:pc|computer|laptop|machine))?"
    r"|automatically"
    r")")
# A locus at the END of a would-be service name: "at boot", "chrome at boot".
_BOOT_LOCUS_END = re.compile(r"(?:^|\s)" + _BOOT_LOCUS + r"$")

# An interrogative OPENER makes the sentence a question, and a verb inside a
# question is embedded in it rather than commanding anything ("what happens if
# i stop the spooler" is not a request to stop it). Position, not presence.
_INFO_QUESTION = re.compile(r"^(?:what|which|who|whom|whose|when|where|why|how)\b")

_LAUNCHER = (r"(?:apps?|applications?|programs?|programmes?|softwares?|"
             r"processe?s|tasks?|things?|stuff|items?|entries|scripts?)")
_LAUNCH_VERB = (r"(?:(?:is|are)\s+)?(?:starts?|runs?|launch(?:es)?|loads?|opens?|"
                r"starting|running|launching|loading|opening)(?:\s+up)?")

# The QUESTION shape: an interrogative / listing / existence opener, at most a
# short noun phrase, a launch verb, then a boot locus that ENDS the sentence.
# The `$` is load-bearing. "what starts with windows defender" and "which apps
# start with windows 11" run past the locus, and a trailing continuation changes
# what is being asked. The noun phrase is deliberately narrow (no "do", "should",
# "to", "make"), which is what keeps the how-to form out: "what do i need to do
# to make it start at startup" asks how to configure something, not what is
# configured.
_STARTUP_QUESTION = re.compile(
    r"^(?:(?:tell|show)\s+me\s+|let\s+me\s+know\s+|i\s+(?:want|need)\s+to\s+(?:know|see)\s+)?"
    r"(?:"
    # what / which [of my] <things> [are set to] ...
    r"(?:what(?:'s)?|which)"
    r"(?:\s+(?:of\s+)?(?:(?:my|the|your|all|any|other|those|installed|background)\s+){0,2}"
    + _LAUNCHER + r")?"
    r"(?:\s+(?:is|are)\s+(?:set|configured|scheduled|supposed|meant|going)\s+to)?"
    # show / list me the <things> that ...
    r"|(?:show|list|tell|give)\s+(?:me\s+)?(?:all\s+)?(?:(?:of\s+)?(?:the|my|any)\s+)?"
    + _LAUNCHER + r"\s+(?:that|which)"
    # are there any <things> that ... / does anything ...
    r"|(?:(?:are|is)\s+there\s+(?:any\s+|some\s+)?(?:" + _LAUNCHER + r"|anything|something)"
    r"(?:\s+(?:that|which))?"
    r"|(?:does|do)\s+(?:any\s+(?:of\s+my\s+)?" + _LAUNCHER + r"|anything|something))"
    r")"
    r"\s+(?:(?:automatically|always|currently|actually|normally|usually)\s+)?"
    + _LAUNCH_VERB + r"\s+" + _BOOT_LOCUS +
    r"(?:\s+(?:on\s+)?(?:my|this|the)\s+(?:pc|computer|laptop|machine|system))?"
    r"(?:\s+by\s+default)?(?:\s+(?:every|each)\s+time)?$")


def pc_skill_has_pending_stop() -> bool:
    """Is a process-stop offer awaiting an answer?

    Wrapped rather than imported at module scope: intent.py is imported by
    pc_skill's own callers, and a top-level `from skills import pc_skill` here
    makes that a cycle. Never raises -- a broken import must not turn every
    utterance into an exception.
    """
    try:
        from skills import pc_skill
        return pc_skill.has_pending_stop()
    except Exception:
        return False


def router_plan_pending() -> bool:
    """Is a task plan staged and awaiting approval? Never raises.

    Imported lazily: router imports intent, so a module-level import here is a
    cycle. Same shape as the pc_skill helpers below.
    """
    try:
        import router
        return router.plan_is_pending()
    except Exception:
        return False


def router_plan_paused_pending() -> bool:
    """Is a task plan PAUSED mid-run, waiting on auth? Distinct from
    router_plan_pending() just above, which is a plan that has never run a
    single step yet. Never raises."""
    try:
        import router
        return router.plan_paused_pending()
    except Exception:
        return False


def vision_skill_visual_pending() -> bool:
    """Is a destructive-looking VISUAL (OCR-matched) click awaiting
    confirmation? Same shape as pc_skill_ui_pending() just below, for
    vision_skill.click_text()'s own staged clicks. Never raises."""
    try:
        from skills import vision_skill
        return vision_skill.visual_has_pending()
    except Exception:
        return False


def pc_skill_ui_pending() -> bool:
    """Is a destructive-looking UI press awaiting confirmation? Never raises."""
    try:
        from skills import pc_skill
        return pc_skill.ui_has_pending()
    except Exception:
        return False


def _watch_folder(word: str) -> str:
    """'downloads' -> C:\\Users\\<you>\\Downloads, for the monitor skill's
    folder_has condition. Only named user folders map to a path, and all of
    them sit inside files_skill.SEARCH_ROOTS, so this can never widen where a
    watch may look -- a folder outside that set is refused by the monitor
    skill's own confinement, not silently accepted here."""
    import os
    base = os.path.expandvars(r"%USERPROFILE%")
    _mapping = {
        "download": "Downloads", "downloads": "Downloads",
        "desktop": "Desktop", "document": "Documents", "documents": "Documents",
        "picture": "Pictures", "pictures": "Pictures",
        "video": "Videos", "videos": "Videos",
    }
    return os.path.join(base, _mapping.get((word or "").lower(), "Downloads"))


def match(text: str) -> dict | None:
    raw = text.strip()
    t = _clean(text)
    if not t:
        return None

    # ══════════════════════════════════════════════════════════════════
    # AUTH — checked before everything, including STOP. If ARGUS is locked,
    # the only thing it should be listening for is being unlocked, and an
    # unlock phrase must never be shadowed by a skill pattern that happens to
    # contain the same words.
    if re.match(r"^(?:lock|lock yourself|lock down|lock argus)$", t):
        return {"skill": "auth", "action": "lock", "target": ""}
    if re.match(r"^(?:are you locked|auth status|lock status)$", t):
        return {"skill": "auth", "action": "status", "target": ""}
    m = re.match(r"^(?:unlock|authenticate|log me in|it's me|its me)\b\s*(.*)$", t)
    if m:
        return {"skill": "auth", "action": "unlock", "target": m.group(1).strip()}


    # A sentence that OPENS with a watch trigger AND carries a "then <goal>"
    # tail has already said what it wants done twice over; no keyword buried
    # in the TASK half ("...then check what's using the CPU" is a pc/heavy
    # phrase on its own) may claim it, exactly like the explicit-dictation
    # rule below. This must sit before every topic block for the same reason.
    # Anchored to the start: a plain "tell me when the battery is above 80"
    # has no "then" and still falls through to the monitor block, and a
    # "make a note that ..." sentence still belongs to the vault, not here.
    # The target keeps the full text; watched_skill splits on "then" and each
    # half goes through its own reviewed parser (monitor_skill._parse for the
    # condition, router.validate_plan for the task), so a misfire here still
    # cannot watch or plan anything the allowlists refuse.
    if re.match(r"^(?:tell me when|let me know when|notify me when|"
                r"ping me when|watch for|watch until|watch that)\b", t) \
            and re.search(r"\bthen\b", t):
        return {"skill": "watched", "action": "set", "target": t}


    # above: the sentence itself declared the intent (a schedule), so it
    # outranks any topic keyword in the goal half. The target keeps the full
    # text; goals_skill parses the schedule half and the task half goes
    # through router.validate_plan, so a misfire here still cannot store a
    # goal whose plan the allowlist refuses.
    if re.match(r"^(?:every\s+(?:morning|day|hour|\d+\s*(?:minutes?|hours?))"
                r"\b|each\s+(?:morning|day|hour)\b|in\s+\d+\s*"
                r"(?:minutes?|hours?)\b)", t):
        return {"skill": "goals", "action": "create", "target": t}

    # ══════════════════════════════════════════════════════════════════
    # EXPLICIT DICTATION — an instruction to WRITE SOMETHING DOWN beats any
    # topic keyword inside it.
    #
    # BUGFIX, and it is a precedence bug rather than a phrasing one: the net
    # block below does a bare `\bwifi\b` search, and it sits ~120 lines above
    # the vault block. So "make a note that the wifi password changed" was
    # captured by net/wifi and answered with the current network name -- the
    # note was silently never written, and nothing reported a problem. The
    # same shape applies to any note mentioning a topic another skill sniffs
    # for ("remember that my ip changed", "note that the timer was wrong").
    #
    # A sentence that opens with "make a note that ..." has already said what
    # it wants done; no keyword buried in the CONTENT should be able to
    # override that, so this runs before every topic block.
    # "SAVE THIS AS MY CODING WORKSPACE" IS NOT A NOTE, and it has to be
    # claimed here, above _VAULT_WRITE, because that pattern deliberately runs
    # before every topic block -- so anything starting with "save this as..."
    # became a vault note no matter what followed.
    #
    # The guard is the reason this is safe to put in front: the sentence must
    # BOTH open with "save this/the layout" AND contain the word workspace,
    # layout or setup. "Save this as my bank password" keeps going to the
    # vault, which is where it belongs.
    m = re.match(r"^(?:save|remember)\s+(?:this|these|my screen|the layout)"
                 r"(?:\s+as)?\s+(?:my\s+)?(.+?)(?:\s+workspace|\s+layout|"
                 r"\s+setup)?\s*$", t)
    if m and re.search(r"\b(?:workspace|layout|set-?up)\b", t):
        return {"skill": "apps", "action": "save_workspace",
                "target": m.group(1).strip()}

    m = _VAULT_WRITE.match(t)
    if m:
        content = m.group(1).strip()
        if content:
            return {"skill": "vault", "action": "write",
                    "target": " ".join(content.split()[:6]), "reply": content}

    # ══════════════════════════════════════════════════════════════════
    # STOP — checked before everything else. If the user is trying to
    # interrupt, nothing should be able to shadow that.
    # ══════════════════════════════════════════════════════════════════
    # "stop listening" is privacy mode and "stop mentioning things" is
    # proactive_skill, neither is "stop talking" -- excluded here so the stop
    # pattern doesn't swallow either one before they get their own chance
    # further down.
    # "the shutdown" / "the restart" are excluded for the same reason as
    # "listening" and "mentioning": "never mind the shutdown" is a POWER
    # cancellation, and this pattern was claiming it first and answering with
    # __SILENT__ -- so the user asked to call off a staged shutdown, heard
    # nothing, and the shutdown stayed staged.
    # AN INTERRUPTION IS INTRANSITIVE. That is the actual rule, and it is why
    # this is anchored at BOTH ends instead of growing another keyword.
    #
    # The pattern used to be `^(stop|...)\b` with a list of nouns excluded
    # after it -- listening, mentioning, music, gestures, dictation, shutdown.
    # A list like that can only ever cover the nouns somebody already thought
    # of, and the one it did not cover cost a real command:
    #
    #     "Can you stop unused processes on my PC?"
    #         -> _clean strips "can you"  ->  "stop unused processes on my pc"
    #         -> matches ^stop\b, "process" is not in the exclusion list
    #         -> pc/stop_speaking -> __SILENT__
    #
    # ARGUS was asked to kill background tasks while the CPU sat at eighty
    # percent, and answered by going quiet. Nothing was logged as a reply,
    # because a silence sentinel is not a reply -- so from the outside it was
    # indistinguishable from not being heard at all.
    #
    # "Stop" meaning "be quiet" never takes an object: stop, stop it, stop
    # talking, shut up. The moment a noun phrase follows, it is a transitive
    # command to stop SOMETHING, and that something belongs to whichever block
    # owns it. Anchoring on end-of-string expresses that directly and covers
    # every noun, including the ones nobody has thought of yet.
    #
    # The old exclusion list is kept below as a second guard. It is now
    # redundant for anything with an object -- the anchor catches those first
    # -- but it costs nothing and it still documents the specific phrasings
    # that were reported broken in earlier rounds.
    if re.match(r"^(?:stop|stop it|stop that|stop talking|stop speaking|"
                r"quiet|be quiet|shut up|silence|enough|shush|hush|"
                r"nevermind|never mind|forget it|cancel that|abort|halt)"
                r"(?:\s+(?:to me|please|now|argus|for a (?:second|moment|minute)))?"
                r"\s*$", t) and \
       not re.search(r"\b(listening|recording|mentioning|nudges|suggest\w*|"
                     r"privacy|shut ?down|restart|reboot|sleep|sign ?out|"
                     r"music|song|track|playback|video|hands?|gestures?|"
                     r"dictating|dictation)\b", t):
        # A STAGED, IRREVERSIBLE ACTION OUTRANKS "stop talking".
        #
        # Bare "abort" and "forget it" are genuinely ambiguous -- they could
        # mean either. But with a shutdown waiting for a PIN, the cost of
        # guessing wrong is not symmetric: read as "stop talking", ARGUS goes
        # silent and the shutdown stays armed, so the user believes they
        # cancelled it and they have not. Read as a cancellation with nothing
        # staged, the worst case is that ARGUS stops speaking anyway, which is
        # what those words also mean.
        from skills import power_skill as _ps
        from skills import files_skill as _fs
        from skills import browser_skill as _bs
        from skills import email_skill as _es
        from skills import service_skill as _svc
        from skills import env_skill as _env
        if (_ps.has_pending() or _fs.has_pending_delete() or _bs.has_pending()
                or _es.has_pending() or _svc.has_pending() or _env.has_pending()
                or router_plan_paused_pending()):
            pass          # fall through to the POWER / FILES / BROWSER / EMAIL / SERVICE / ENV / PLAN blocks below
        else:
            return {"skill": "pc", "action": "stop_speaking", "target": ""}

    # ══════════════════════════════════════════════════════════════════
    # CLARIFY — a pending disambiguation ("did you mean X or Y?") takes
    # priority over everything below except STOP above. Whatever's said
    # next is almost always the answer, not an unrelated new command --
    # same reasoning as POWER's pending-confirmation check further down,
    # just checked earlier because a clarification can be staged mid any
    # skill's own matching, not only behind one dedicated trigger phrase.
    # A reply that doesn't resolve to anything falls through to normal
    # matching below instead of being discarded -- resolve() already
    # cleared the pending state either way. BUGFIX: this used to always
    # return a canned "never mind" for an unresolved reply, which meant a
    # perfectly clear new command ("open notepad") said instead of
    # answering the question got silently swallowed instead of acted on.
    # Explicit cancel words ("stop"/"nevermind"/"cancel that"/...) never
    # reach here at all -- the STOP block above already matches those and
    # separately clears clarify_skill's pending state in router.py.
    # ══════════════════════════════════════════════════════════════════
    from skills import clarify_skill
    if clarify_skill.has_pending():
        resolved = clarify_skill.resolve(raw)
        if resolved:
            r_skill, r_action, r_target = resolved
            return {"skill": r_skill, "action": r_action, "target": r_target}

    # ══════════════════════════════════════════════════════════════════
    # PRIVACY — an always-on mic needs an unmissable off switch.
    # ══════════════════════════════════════════════════════════════════
    # ORDER MATTERS, and getting it wrong here was worse than a missed
    # command. Previously ON was tested first and matched any sentence
    # containing "privacy mode" that did not also contain off/disable/end --
    # so "IS PRIVACY MODE ON?", a question, TURNED PRIVACY ON. Asking about a
    # setting must never change it.
    #
    # And OFF only matched the exact sequence "privacy mode off", while people
    # say "turn off privacy mode" -- word order reversed, so nothing matched
    # and privacy could be entered by voice but not left by it.
    #
    # So: question first, then off, then on. A question is unambiguous, and
    # testing OFF before ON means the negative case never has to be expressed
    # as a lookahead on the positive one.
    m = re.search(r"\bprivacy mode\b.*?\bfor (\d+) minutes?\b", t)
    if m:
        return {"skill": "privacy", "action": "on", "target": m.group(1)}

    if re.search(r"\b(are you listening|privacy status|"
                 r"(is|are)\b.*\bprivacy mode\b|"
                 r"\bam i (muted|private)\b|"
                 r"\bprivacy mode\b.*\b(status|on\?)\b)\b", t):
        return {"skill": "privacy", "action": "status", "target": ""}

    if re.search(r"\b(start listening|resume listening|you can listen|"
                 r"listen again|wake up)\b", t) or \
       (re.search(r"\bprivacy( mode)?\b", t)
            and re.search(r"\b(off|disable|end|stop|exit|leave|cancel)\b", t)) or \
       re.search(r"\bunmute (your|the) (mic|microphone)\b", t):
        return {"skill": "privacy", "action": "off", "target": ""}

    # Bare "unmute" is AUDIO, and is handled by control/unmute further down.
    # It used to be listed here, so "unmute" turned privacy off and left the
    # speakers muted -- the opposite of what was asked, silently.
    if re.search(r"\b(privacy mode|stop listening|mute (your|the) (mic|microphone)|"
                 r"go deaf|don'?t listen|stop recording|go private)\b", t):
        return {"skill": "privacy", "action": "on", "target": ""}

    # ══════════════════════════════════════════════════════════════════
    # PROACTIVE — the off switch for unsolicited asides (see
    # proactive_skill.py). Same reasoning as PRIVACY above: this is opt-out,
    # not opt-in, so the phrase to turn it off needs to be unmissable too.
    # ══════════════════════════════════════════════════════════════════
    # "suggestions" and "nudges" are the words people actually use for this,
    # and neither appeared -- so the feature had an off switch nobody could
    # find, and "stop suggesting things" was picked up by pc/stop_speaking
    # instead, silencing ARGUS mid-sentence rather than disabling nudges.
    if re.search(r"\b(stop mentioning|stop the nudges|no more nudges|"
                 r"keep it to yourself|don'?t mention (things|that|stuff))\b", t) or \
       (re.search(r"\b(suggestion|suggestions|nudge|nudges|suggesting)\b", t)
            and re.search(r"\b(stop|off|no more|disable|quit|turn off)\b", t)):
        return {"skill": "proactive", "action": "off", "target": ""}
    if re.search(r"\b(mention things again|you can mention things|start mentioning)\b", t) or \
       (re.search(r"\b(suggestion|suggestions|nudge|nudges|suggesting)\b", t)
            and re.search(r"\b(start|on|enable|resume|turn on|again)\b", t)):
        return {"skill": "proactive", "action": "on", "target": ""}

    # ══════════════════════════════════════════════════════════════════
    # AUDIT — what did ARGUS actually do?
    # ══════════════════════════════════════════════════════════════════
    if re.search(r"\b(what have you done|activity log|audit log|recent actions|"
                 r"what did you do|show me the log)\b", t):
        return {"skill": "audit", "action": "read", "target": ""}
    if re.search(r"\b(any anomal(?:y|ies)|anything (?:unusual|weird|suspicious)|"
                 r"is (?:anything|everything) (?:wrong|ok|okay|alright)|"
                 r"(?:has |have )?anything (?:looked|seemed|been|looking) "
                 r"(?:unusual|odd|strange|weird|off|suspicious)|"
                 r"anything (?:unusual|odd|strange|suspicious)|"
                 r"anything (?:i should be worried about|to worry about))\b", t):
        return {"skill": "anomaly", "action": "check", "target": ""}

    # ══════════════════════════════════════════════════════════════════
    # SECURITY SUMMARY — "how secure am I". Matched deterministically HERE, so
    # it is answered from the local threat-detection state and NEVER reaches the
    # cloud routing tier: real security telemetry about this machine must not
    # leave it, regardless of phrasing. See threatmon.security_summary().
    # ══════════════════════════════════════════════════════════════════
    if re.search(r"\b(security summary|how secure am i|am i secure|are we secure|"
                 r"how safe am i|security (?:report|posture|check|scan|status)|"
                 r"(?:run|give me|do|generate)(?: a| the)? security "
                 r"(?:summary|check|scan|report)|analy[sz]e (?:my )?security|"
                 r"threat (?:report|summary|status))\b", t):
        return {"skill": "security", "action": "summary", "target": ""}
    # "check current security threats" -- the same question with another verb. The
    # block above wants "threat report/summary/status" or "security check/scan", so
    # this matched nothing, cost a local classifier call to find the same skill
    # (seconds, on a cold model), and on a bad day was answered as general chat.
    # Requires the word "security", or "my/this pc" alongside "threat": a bare
    # "any threats to democracy" is a knowledge question and must not land here.
    if re.search(r"\b(?:check|show|list|scan for|look for|any|are there any)\b"
                 r"[\w\s]{0,24}\bsecurity threats?\b", t) or \
       re.search(r"\b(?:check|show|list|scan for|look for|any|are there any)\b"
                 r"[\w\s]{0,16}\bthreats?\b[\w\s]{0,20}\b(?:my|this) "
                 r"(?:pc|computer|machine|laptop|system)\b", t):
        return {"skill": "security", "action": "summary", "target": ""}

    # ══════════════════════════════════════════════════════════════════
    # DEFENSIVE POSTURE — "am I protected?", which is NOT "am I secure?".
    #
    # The two sit next to each other because the line between them is easy to
    # lose and worth stating. The block above answers from what the detectors
    # have SEEN: findings, detections, things that happened. This one answers
    # from what is CONFIGURED: Defender, the firewall, UAC, Secure Boot, LSASS
    # protection. A machine with no detections and its firewall off is "secure"
    # by the first reading and wide open by the second.
    #
    # So the vocabulary is split deliberately: secure / safe / threat / posture
    # go above, and protected / protection / defence / firewall / antivirus /
    # Defender / hardened come here. Anything genuinely ambiguous stays with
    # the summary, which now reports the weak-control count too, so the
    # ambiguous phrasing still surfaces this.
    # Local by construction, same as the summary -- see threatmon/defenses.py.
    # ══════════════════════════════════════════════════════════════════
    if re.search(r"\b(?:am i|are we|is (?:my|this) (?:pc|machine|computer|laptop))"
                 r"\s+(?:actually\s+)?protected\b", t) \
            or re.search(r"\b(?:is|are)\s+(?:my\s+)?(?:the\s+)?"
                         r"(?:firewall|defender|antivirus|anti-?virus|"
                         r"real-?time protection|smart ?screen|uac|"
                         r"secure boot)\b.{0,16}\b(?:on|off|running|enabled|"
                         r"disabled|working|active)\b", t) \
            or re.search(r"\b(?:check|show|what about)\s+(?:my\s+)?"
                         r"(?:defen[cs]es|defen[cs]e|protections?|firewall|"
                         r"antivirus|anti-?virus|defender|hardening)\b", t) \
            or re.search(r"\bhow\s+hardened\b", t) \
            or re.search(r"\b(?:defensive|security)\s+(?:posture|settings|"
                         r"configuration)\b.{0,20}\b(?:check|audit)\b", t) \
            or re.search(r"\bis\s+(?:anything|something)\s+(?:switched|turned)"
                         r"\s+off\b", t):
        return {"skill": "diag", "action": "defenses", "target": ""}

    # ══════════════════════════════════════════════════════════════════
    # PRIVACY WATCH — "has anything used my camera today?". Same reasoning as
    # the security summary above and matched in the same place, ABOVE the cloud
    # tier: which apps opened this machine's microphone is exactly the kind of
    # thing that must never be phrased into leaving it. Answered from the local
    # consent-store timeline by threatmon.privacy.usage_report().
    # ══════════════════════════════════════════════════════════════════
    if re.search(r"\b(?:(?:has|did|is)\s+(?:any\s?thing|any\s?one|any\s?app|"
                 r"some\s?thing|anybody)\s+(?:been\s+)?(?:us(?:e|ed|ing)|"
                 r"access(?:ed|ing)?|turn(?:ed)?\s+on|open(?:ed)?|"
                 r"record(?:ed|ing)?|watch(?:ed|ing)?|listen(?:ed|ing)?\s+"
                 r"(?:to|through))\s+(?:my\s+)?(?:camera|webcam|mic|microphone)|"
                 r"(?:who|what)\s+(?:used|accessed|opened|has\s+used)\s+"
                 r"(?:my\s+)?(?:camera|webcam|mic|microphone)|"
                 r"(?:camera|webcam|mic|microphone)\s+(?:usage|access|activity|"
                 r"history|log)|privacy\s+(?:check|report|watch|summary))\b", t):
        return {"skill": "privacy_watch", "action": "usage", "target": ""}

    # ══════════════════════════════════════════════════════════════════
    # SOCIAL — checked FIRST. These were previously falling through to the
    # model, which routed "how are you" to a profile lookup and answered
    # "I don't know anything about you." Pleasantries are not queries.
    # ══════════════════════════════════════════════════════════════════
    # BUGFIX: these used to match as a PREFIX (\b instead of $), so "what are
    # you doing now" matched "^what are you\b" and got the canned identity
    # reply instead of ever reaching the LLM -- same for "how are you
    # feeling about the game" swallowed by "how are you", "sorry, what was
    # that" swallowed by "sorry", etc. "what are you"/"how are you" in
    # particular are common PREFIXES of completely unrelated questions, not
    # just pleasantries with extra words tacked on, so these five are exact-
    # match only now: anything with real content after the pleasantry falls
    # through to the LLM, which is what should be answering it anyway.
    if re.match(r"^(how are you|how(?:'s| is) it going|how are things|you good|hows it going|how you doing)$", t):
        return {"skill": "social", "action": "how_are_you", "target": ""}
    if re.match(r"^(hello|hi|hey|yo|good morning|good afternoon|good evening|morning)$", t):
        return {"skill": "social", "action": "hello", "target": ""}
    if re.match(r"^(thanks|thank you|cheers|appreciate it|nice one)\b", t):
        return {"skill": "social", "action": "thanks", "target": ""}
    # "Who is the creator?" -- asked ABOUT the creator, not about the user. Checked
    # before the who_built_you block so the more specific question wins, and
    # before profile/summary so it isn't mistaken for "who am I".
    #
    # This has to be answered locally and deterministically. cloud_gate would
    # route it to the cloud (it names no possessive like "my ..." so
    # is_sensitive() reads False), and _cloud_system_prompt deliberately never
    # includes profile_context -- so a cloud model would be asked about a
    # person it has never heard of and would either refuse or invent someone.
    #
    # The NAME IS MATCHED PHONETICALLY, not literally. An exact match here was
    # tested against realistic Whisper output for this name and missed 8 of 12
    # variants -- "tursunbayev", "torsunboev", "tursun boev" -- and every miss
    # fell through to knowledge/lookup, i.e. a Wikipedia and web search for a
    # person who isn't on the internet. That is the reported "it searches the
    # internet, and slow". See textmatch.name_matches.
    m = re.match(r"^(?:and\s+|so\s+)?who(?:'s|s| is| was)\s+(.+?)\??$", t)
    if m and textmatch.name_matches(m.group(1), USER_FULL_NAME):
        return {"skill": "social", "action": "about_creator", "target": ""}
    m = re.match(r"^(?:tell me |what do you know )?about\s+(.+?)\??$", t)
    if m and textmatch.name_matches(m.group(1), USER_FULL_NAME):
        return {"skill": "social", "action": "about_creator", "target": ""}

    # BUGFIX, found in the real audit log: "who built you" got NO reply at
    # all -- not misrouted, not "I don't know", nothing. Neither this exact-
    # match block nor the LLM router recognised it as an identity question,
    # so it silently fell all the way through.
    #
    # It used to be folded into who_are_you, which meant "who built you"
    # answered with the name-and-hundred-eyes line and never actually said WHO
    # BUILT IT. They are different questions and now have different answers.
    # Covers the ownership phrasings too -- owner, commander, creator, boss --
    # which are the same question asked sideways.
    if re.match(r"^who (?:built|made|created|developed|coded|programmed|"
                r"designed|wrote|invented) you\??$", t):
        return {"skill": "social", "action": "who_built_you", "target": ""}
    if re.match(r"^who(?:'s| is) your "
                r"(?:owner|commander|creator|developer|builder|maker|boss|"
                r"master|author|designer|father|dad)\??$", t):
        return {"skill": "social", "action": "who_built_you", "target": ""}
    if re.match(r"^(?:who do you (?:work for|belong to)|whose (?:are you|assistant are you))\??$", t):
        return {"skill": "social", "action": "who_built_you", "target": ""}

    # WHO MADE ARGUS -- BY NAME. The patterns above only knew the second person
    # ("who built YOU"), so "who designed ARGUS" -- the same question -- matched
    # nothing, reached the chat model, and was answered with whatever that model
    # believed about itself. The creator of the APPLICATION is fixed metadata
    # (config.COPYRIGHT_HOLDER) and needs no model at all. Anchored with $ like
    # every pattern in this file: a trailing clause changes the question.
    _SELF = (rf"(?:you|{_NAME_RE}|this (?:assistant|app|application|system|"
             rf"program|software|tool)|the assistant)")
    if re.match(rf"^who (?:actually |really |exactly )?(?:built|made|created|"
                rf"developed|coded|programmed|designed|wrote|invented|engineered|"
                rf"authored) {_SELF}$", t):
        return {"skill": "social", "action": "who_built_you", "target": ""}
    if re.match(rf"^who(?:'s| is| was) (?:the |your )?(?:{_NAME_RE}'?s? )?"
                rf"(?:actual |real |original )?(?:owner|creator|developer|builder|"
                rf"maker|designer|author|programmer|engineer|inventor)"
                rf"(?: of {_SELF})?$", t):
        return {"skill": "social", "action": "who_built_you", "target": ""}
    if re.match(rf"^who(?:'s| is| was) behind {_SELF}$", t):
        return {"skill": "social", "action": "who_built_you", "target": ""}

    # WHICH MODEL IS ARGUS RUNNING ON -- a different question from who built it,
    # and answered from the live configuration, never from what a model believes
    # about itself (see social_skill.runtime_answer). It rides the existing
    # who_are_you action with target="model": a new action name would have to be
    # added to auth.KNOWN_ACTIONS, and until it was it would be authorised at the
    # stricter default level instead of L0.
    _MODEL = r"(?:ai |llm |language |large language |chat |local |cloud )?(?:model|llm)"
    _MODEL_TAIL = (r"(?:\s+(?:currently|actually|really|right now|at the moment))*"
                   r"(?:\s+(?:using|running(?: on)?|use|run(?: on)?|based on|"
                   r"powered by|built on|talking to|speaking to))?"
                   r"(?:\s+(?:right now|currently|at the moment))?")
    if re.match(rf"^(?:what|which) {_MODEL} (?:are you|is this|is {_NAME_RE}|"
                rf"do you|does {_NAME_RE}){_MODEL_TAIL}$", t):
        return {"skill": "social", "action": "who_are_you", "target": "model"}
    if re.match(rf"^what(?:'s| is) (?:your|the|{_NAME_RE}'?s?) (?:current |"
                rf"underlying |main |local |cloud )?(?:ai |language |large language )?"
                rf"(?:model|llm)$", t):
        return {"skill": "social", "action": "who_are_you", "target": "model"}
    if re.match(rf"^what (?:are you|is {_NAME_RE}) (?:powered by|based on|built on)$", t):
        return {"skill": "social", "action": "who_are_you", "target": "model"}
    if re.match(rf"^(?:are you|is {_NAME_RE}|do you run|do you work) (?:running |working |"
                rf"operating )?(?:locally|local|offline|in the cloud|on the cloud|"
                rf"cloud based|cloud|online|local or (?:in the )?cloud|"
                rf"cloud or local)$", t):
        return {"skill": "social", "action": "who_are_you", "target": "model"}
    # "Who made the MODEL you use" is not "who made you": the application's creator
    # is one person, and the models it calls are somebody else's.
    if re.match(r"^(?:who|which company) (?:made|built|created|trained|developed|"
                r"owns|provides|designed) (?:the|your|that) (?:underlying |current |"
                r"main |local |cloud )?(?:ai |language |large language )?"
                r"(?:model|llm)(?: you (?:use|are using|run|run on))?$", t):
        return {"skill": "social", "action": "who_are_you", "target": "model_maker"}

    if re.match(r"^(who are you|what are you|introduce yourself)$", t):
        return {"skill": "social", "action": "who_are_you", "target": ""}
    if re.match(r"^(what can you do|what are your (skills|abilities|features)|help|commands)$", t):
        return {"skill": "social", "action": "what_can_you_do", "target": ""}
    if re.match(r"^(bye|goodbye|good night|see you|that(?:'s| is) all|nothing else)\b", t):
        return {"skill": "social", "action": "goodbye", "target": ""}
    if re.match(r"^(sorry|my bad|oops)$", t):
        return {"skill": "social", "action": "sorry", "target": ""}
    if re.match(r"^(good job|well done|nice work|you(?:'re| are) (great|awesome|the best)|love you)\b", t):
        return {"skill": "social", "action": "compliment", "target": ""}
    if re.match(r"^(are you (there|awake|listening|online)|you there)$", t):
        return {"skill": "social", "action": "are_you_there", "target": ""}
    if re.search(r"\b(tell me a joke|say something funny|make me laugh)\b", t):
        return {"skill": "social", "action": "joke", "target": ""}

    # ══════════════════════════════════════════════════════════════════
    # MATH & CONVERSION — local, instant, more reliable than a 3B model
    # ══════════════════════════════════════════════════════════════════
    if re.search(r"[\d.]+\s*[a-z]+\s+(?:in|to|into)\s+[a-z]+", t) and \
       re.search(r"\b(convert|in|to|into)\b", t) and re.search(r"\d", t):
        if re.search(r"\b(mm|cm|km|inch|inches|foot|feet|yard|mile|miles|gram|grams|kilo|kilogram|pound|pounds|ounce|ounces|tonne|ton|ml|litre|liter|litres|liters|cup|cups|pint|gallon|celsius|fahrenheit|degrees)\b", t):
            return {"skill": "calc", "action": "convert", "target": raw}
    if re.search(r"\bconvert\b", t) or re.search(r"\d+\s*degrees?\s*(c|f|celsius|fahrenheit)\b", t):
        return {"skill": "calc", "action": "convert", "target": raw}

    # ══════════════════════════════════════════════════════════════════
    # KNOWLEDGE
    # ══════════════════════════════════════════════════════════════════
    m = re.match(r"^(?:define|definition of|what does (.+) mean)$|^(?:define|definition of)\s+(.+)$", t)
    if m:
        word = m.group(1) or m.group(2) or ""
        if word:
            return {"skill": "knowledge", "action": "define", "target": word.strip()}
    # A bare "spell accommodate" reached no pattern and fell through to the
    # model, which answered with a Wikipedia article about accommodation.
    m = re.match(r"^(?:how do you spell|how is .+ spell(?:ed|t)|spell(?: out)?)"
                 r"\s+(.+)$", t)
    if m:
        return {"skill": "knowledge", "action": "spell", "target": m.group(1).strip()}
    m = re.match(r"^translate\s+(.+?)\s+(?:in)?to\s+([a-z]+)$", t)
    if m:
        return {"skill": "knowledge", "action": "translate",
                "target": m.group(1).strip(), "reply": m.group(2).strip()}
    # "what i copied" is the same request as "my clipboard" and was not
    # matched, so it fell through to the model -- which, asked to summarise
    # something it had not been given, summarised what WAS in its context and
    # described ARGUS's own system prompt back to the user. Routing it here
    # makes it answer "there's nothing to summarize", which is both correct
    # and not a disclosure.
    if re.search(r"\bsummari[sz]e\b.*\b(clipboard|what i copied|"
                 r"what'?s copied|the copied text|what i just copied)\b", t) or \
       re.search(r"\b(summari[sz]e (my |the )?clipboard)\b", t):
        return {"skill": "knowledge", "action": "summarize_clipboard", "target": ""}
    m = re.match(r"^(?:who|what) (?:is|was|are|were)\s+(?:an? |the )?(.+)$", t)
    if m:
        subject = m.group(1).strip()
        # Don't swallow queries that belong to other skills.
        is_personal = re.search(r"\b(my|your|you|me|i)\b", subject)
        # ONE definition of "this is arithmetic", owned by the calculator.
        #
        # This used to carry its own copy of the operator list, and it drifted:
        # calc learned "%" and "sqrt", this guard did not, so "what is 15% of
        # 240" was claimed as an encyclopaedia lookup and answered with an
        # article instead of 36. A second copy of a rule is a second place for
        # it to be wrong, and the two can only be kept in step by not having
        # two.
        from skills import calc_skill as _calc

        is_math = (_calc.looks_like_math(subject)
                   or re.match(r"^\d+[\d\s\+\-\*/x\.]*$", subject))
        is_other = re.search(r"\b(weather|temperature|forecast|time|date|day|running|open|battery|uptime)\b", subject)

        # ONLY A NAMED ENTITY GOES STRAIGHT TO WIKIPEDIA.
        #
        # This claimed every "what is X" and answered it from a Wikipedia
        # TITLE SEARCH, which returns the article whose title best matches the
        # words -- not the article that answers the question. Measured:
        #
        #   "what is the largest ocean"          -> "The ocean sunfish..."
        #   "what is a firewall"                 -> "The Great Firewall..."
        #   "what is the chemical symbol for gold" -> "Chemical symbols are..."
        #
        # Three confidently wrong answers, which is worse than no answer. The
        # same three questions to the cloud model came back "The Pacific
        # Ocean", "a security device" and "Au" -- correct, and in ~200ms
        # against Wikipedia's ~600ms.
        #
        # So a DESCRIPTIVE phrase now falls through to brain.answer(), whose
        # cascade is cloud -> local -> wikipedia -> web: it tries the fast
        # accurate source first and still reaches Wikipedia when the model
        # does not know. A NAMED ENTITY ("Uzbekistan", "Ada Lovelace") is
        # exactly what a title search is good at, so it still shortcuts here.
        #
        # Capitalisation in the ORIGINAL is the signal -- _clean() lowercases,
        # so raw is consulted rather than the normalised text.
        words = subject.split()
        # An all-caps token that names a REAL environment variable is not a
        # proper noun -- "what is PATH" must return its value, not a Wikipedia
        # article about "path". os.environ membership keeps "what is NATO" a
        # lookup: NATO is a name, not a variable (and env_var/get answers
        # "There's no environment variable called NATO", which would be worse).
        env_ref = any(
            w.strip("%$").upper() in os.environ
            for w in raw.split()[2:] if w.strip("%$")
        )
        named_entity = (
            len(words) <= 4
            and not re.match(r"^(a|an|the)\b", subject)
            and any(w[:1].isupper() for w in raw.split()[2:] if len(w) > 2)
            and not env_ref
        )
        if not (is_personal or is_math or is_other) and named_entity:
            return {"skill": "knowledge", "action": "lookup", "target": subject}

    # ---------- KEEP AWAKE ----------
    # ABOVE the POWER block on purpose. "Sleep" is a power action, so the
    # cancellation line below ("a cancel word plus shutdown/restart/sleep")
    # claimed "don't let it sleep" and answered with a power cancellation --
    # which is the exact opposite instruction. These phrasings are asking for
    # the machine to STAY awake, which is not a power command at all, and they
    # are specific enough that nothing else wants them.
    #
    # "Awake" is required rather than "on" or "up": an earlier version matched
    # keep ... on and swallowed "keep spotify on top", which is a window
    # command. A loose word near a strong verb is how patterns eat their
    # neighbours.
    if re.search(r"\b(?:keep|stay|staying|stays)\b.{0,24}\bawake\b", t) \
            or re.search(r"\b(?:caffeine|prevent sleep|no sleep|"
                         r"don'?t (?:let (?:it|the (?:pc|screen|machine)) )?"
                         r"(?:go to )?sleep|"
                         r"keep the screen (?:on|awake)|stop it sleeping)\b", t):
        return {"skill": "pc", "action": "keep_awake", "target": ""}
    if re.search(r"\b(?:allow|let it|you can|it can)\s+(?:go to\s+)?sleep\b", t) \
            or re.search(r"\b(?:normal sleep|sleep is fine|release the screen|"
                         r"stop keeping.{0,14}awake)\b", t):
        return {"skill": "pc", "action": "allow_sleep", "target": ""}
    if re.search(r"\b(?:are you|am i)\s+keeping\b.{0,16}\bawake\b", t) \
            or re.search(r"\bkeep.?awake status\b", t):
        return {"skill": "pc", "action": "awake_status", "target": ""}

    # ---------- POWER (staged, never immediate) ----------
    # A bare "yes" used to be enough to confirm shutdown/restart/sleep/
    # sign-out -- that's not real authorization (a mishearing, or anyone
    # else in the room, could say it). Confirming now requires the command
    # PIN (config.COMMAND_PIN), so while an action is staged, whatever the
    # user typed/said gets forwarded to power.confirm as a PIN attempt
    # instead of being pattern-matched as anything else here -- otherwise a
    # PIN that happened to look like a word/number would get swallowed by
    # some other skill's pattern before it ever reached the check. "yes"
    # itself still routes to confirm (so the old phrasing gets a clear
    # "wrong PIN" reply instead of silently doing nothing), just no longer
    # succeeds on its own.
    # Cancelling must work in WORDS, not just as a bare token.
    #
    # The cancel test was ^(no|cancel|nevermind|abort)$ -- anchored, so it only
    # ever matched those words ALONE. "cancel the shutdown" therefore failed
    # it, fell into the has_pending() branch above, and was forwarded to
    # power.confirm as a PIN ATTEMPT: trying to cancel a shutdown consumed one
    # of the limited PIN tries and left the shutdown staged. The user asked to
    # stop something irreversible and was silently pushed closer to a lockout.
    #
    # A PIN is digits, so "not all digits AND contains a cancel word" cannot
    # swallow a real PIN attempt.
    _CANCEL = r"\b(no|cancel|nevermind|never ?mind|abort|forget it|stop|don'?t)\b"
    _looks_cancel = bool(re.search(_CANCEL, t)) and not raw.strip().isdigit()

    # PHONETIC fallback, because the word arrives through speech recognition.
    # The real log has "Cancellage." -- the user saying "cancel" while a
    # shutdown was staged. Spelled that way it matched no cancel pattern, so
    # the attempt to call off a shutdown did not call it off. Matching on
    # sound rather than spelling is already how the wake word is recognised;
    # a cancellation deserves at least the same tolerance.
    if not _looks_cancel and not raw.strip().isdigit():
        # NO local `import textmatch` here. The module is already imported at
        # the top of this file, and re-importing it inside match() rebinds the
        # name as a FUNCTION LOCAL for the whole function -- so the uses at
        # the top of match() (name_matches, several hundred lines earlier)
        # raised UnboundLocalError before this line ever ran. "what do you
        # know about me" crashed outright.
        #
        # Soundex agreement ALONE, without an edit-distance bound.
        # "cancellage" codes identically to "cancel" (C524) but is four edits
        # away, so a bounded check rejected it -- and that is the real
        # transcript from a user trying to stop a shutdown.
        #
        # The looser test is right here because the two mistakes are not
        # equally costly. Cancelling something the user actually wanted is an
        # annoyance they fix by asking again; FAILING to cancel leaves an
        # irreversible action armed while the user believes they stopped it.
        # When in doubt about a cancellation, cancel.
        words = [w for w in re.findall(r"[a-z']+", t)[:3] if len(w) >= 4]
        _looks_cancel = any(
            textmatch.soundex(w) == textmatch.soundex(c)
            for w in words for c in ("cancel", "abort", "nevermind"))

    # AMBIGUOUS-PIN GUARD. Every confirming skill below checks the SAME
    # config.COMMAND_PIN, and until this guard existed they were checked in a
    # fixed sequence (power first) -- so a PIN typed while TWO skills each had
    # something staged always confirmed power's action, silently, even when
    # the user meant to confirm the other one. There was no wrong-PIN error to
    # notice by: the PIN is correct, just routed to the wrong pending action.
    # Concrete case that was live: stage a shutdown, then stage an unrelated
    # email within the same window, then type the PIN meaning to send the
    # email -- the machine shut down instead, silently, and the email never
    # sent. This contradicts this file's own stated rule a few lines below
    # ("when in doubt about a confirmation, do not confirm"), so: only ever
    # guess which pending action a PIN belongs to when there is exactly one.
    attempt_probe = re.sub(r"[\s\-]", "", raw.strip())
    if attempt_probe.isdigit():
        from skills import (browser_skill, email_skill, env_skill,
                             files_skill, power_skill as _power_probe,
                             service_skill)
        # (name, pending-now, cancel-callable-or-None). files_skill has no
        # generic cancel() -- cancel_delete() only cancels a pending delete,
        # and there is no cancel_restore() at all, so a pending restore is
        # just left to expire on its own CONFIRM_WINDOW rather than guessing
        # at a function that doesn't exist.
        _ambiguous = [
            (name, cancel_fn) for name, pending, cancel_fn in (
                ("shutdown/restart/sleep", _power_probe.has_pending(), _power_probe.cancel),
                ("delete", files_skill.has_pending_delete(), files_skill.cancel_delete),
                ("restore", files_skill.has_pending_restore(), None),
                ("browser action", browser_skill.has_pending(), browser_skill.cancel),
                ("email", email_skill.has_pending(), email_skill.cancel),
                ("service action", service_skill.has_pending(), service_skill.cancel),
                ("environment variable", env_skill.has_pending(), env_skill.cancel),
            ) if pending
        ]
        if len(_ambiguous) > 1:
            # Cancelling every one of them, rather than trying to guess which
            # the PIN was meant for, is the fix -- not skipping it. Every
            # confirm() below checks the SAME config.COMMAND_PIN, so a correct
            # PIN here would otherwise silently confirm whichever skill's
            # has_pending() block happens to run first (power, always, since
            # its block is textually first), even when the user meant a
            # DIFFERENT pending action. That is a real, reproduced case: stage
            # a shutdown, then stage an unrelated email inside the same
            # window, then type the PIN meaning to confirm the email -- the
            # machine shut down instead, silently, no wrong-PIN error, the
            # email never sent. Clearing all of them is the same direction
            # this file's own rule a few lines below already commits to
            # ("when in doubt about a confirmation, do not confirm"): the
            # user redoes whichever one they meant, against a clean slate,
            # rather than the PIN landing on an action they never chose.
            names = []
            for name, cancel_fn in _ambiguous:
                if cancel_fn is not None:
                    try:
                        cancel_fn()
                    except Exception:
                        pass
                names.append(name)
            import security as _security
            _security.audit("ambiguous_pin_cleared", ", ".join(names), "cancelled")

    from skills import power_skill
    if power_skill.has_pending():
        if _looks_cancel:
            return {"skill": "power", "action": "cancel", "target": ""}
        # ONLY something PIN-SHAPED counts as an attempt.
        #
        # This used to forward every utterance to power.confirm while an
        # action was staged. Measured consequence: after staging a sleep,
        # saying "you awake", "you look great" and "hey there" burned all
        # three PIN attempts and triggered the lockout -- three ordinary
        # sentences, none of them a guess at anything.
        #
        # A PIN is digits. Anything else is the user talking, and talking is
        # not a failed authentication: it gets a reminder that something is
        # still waiting, and the attempt counter is left alone.
        attempt = re.sub(r"[\s\-]", "", raw.strip())
        if attempt.isdigit():
            return {"skill": "power", "action": "confirm", "target": attempt}
        if re.match(r"^(yes|yeah|yep|confirm|do it|go ahead|ok|okay)$", t):
            # Deliberate: this reaches confirm with no PIN and gets the
            # "that's not the right PIN" reply, which is the honest answer to
            # someone trying to approve an action by agreeing with it.
            return {"skill": "power", "action": "confirm", "target": ""}
        # ANYTHING ELSE FALLS THROUGH TO NORMAL MATCHING.
        #
        # Returning a "still waiting for the PIN" stub here held the whole
        # assistant hostage: with a shutdown staged, "what is the weather" got
        # the reminder instead of the weather, and every other question was
        # refused for the full confirmation window. A mishearing that staged a
        # shutdown therefore made ARGUS look frozen -- which is exactly the
        # "it gets stuck" complaint.
        #
        # The staged action is not forgotten: router.py appends a short
        # reminder to whatever the answer turns out to be, so the user gets
        # both the answer they asked for and the fact that something is
        # waiting. Falling through here rather than deciding the reply is what
        # lets those two coexist.

    # ---------- CLEANUP agreement ----------
    # Checked here, after POWER's pending block and BEFORE the unconditional
    # bare-agreement fallback below. That ordering is the whole point: the
    # fallback routes a bare "yes" to power/confirm even when NOTHING is staged,
    # so a cleanup agreement placed after it was never reached -- "yes" went to
    # a power confirmation that did not exist and fell through to chat, and the
    # user's files were never cleared. Guarded by has_pending(), so outside the
    # 90-second window this claims nothing and the old behaviour is untouched.
    # POWER still wins while IT has something staged: shutting down is
    # irreversible and outranks freeing disk space.
    from skills import cleanup_skill as _cleanup
    if _cleanup.has_pending():
        if re.match(r"^(yes|yeah|yep|yup|sure|ok|okay|do it|go ahead|confirm|"
                    r"clean it|clear it|delete them|delete it|please do)$", t):
            return {"skill": "cleanup", "action": "run", "target": ""}
        if re.match(r"^(no|nope|cancel|nevermind|never mind|stop|abort|"
                    r"don'?t|leave it)$", t):
            return {"skill": "cleanup", "action": "cancel", "target": ""}

    # ── the bare-"yes" trap, and why these lines are now conditional ────────
    #
    # This block used to claim a bare "yes", "do it", "go ahead", "no" and
    # "stop" for POWER **unconditionally** -- outside the has_pending() guard
    # thirty lines above, so it fired when nothing was staged at all.
    #
    # The consequence was not subtle. Say anything ARGUS could take as
    # agreement in ordinary conversation -- it makes a suggestion, you say
    # "yeah" -- and the reply was "that's not the right PIN", to a power
    # request that did not exist. Every one of those words is a normal English
    # answer to a normal English question, and five of them were reserved,
    # permanently, for a confirmation flow that was not running. It is the same
    # class of fault as the "okay" suffix bug in _clean(): a word grabbed for a
    # special purpose in every context instead of the one where it means that.
    #
    # A bare agreement is only a power confirmation while a power action is
    # STAGED, and the guarded block above already handles exactly that case
    # correctly, including the PIN-shape check. So what is left here is the
    # EXPLICIT forms, which name the action and cannot be mistaken for
    # conversation. Everything bare falls through to the pending-question
    # handlers below and then to chat, which is where "yes" belongs when
    # nobody has asked a question that needs one.
    # THE CANCEL HALF STAYS UNCONDITIONAL, and the asymmetry is deliberate --
    # removing it alongside the affirmative was a real regression that
    # a deletion regression exposed. power/cancel is the router's
    # universal "clear whatever is staged" path: it also clears a pending FILE
    # DELETION, so a bare "cancel" with a deletion armed has to reach it.
    #
    # The costs are not symmetric, which is the entire argument:
    #   a stray "yes"    confirming nothing -> a confusing PIN error
    #   a stray "cancel" cancelling nothing -> nothing at all
    #   a MISSED "cancel" while something irreversible is armed -> the user
    #     believes they stopped a shutdown or a deletion, and they did not.
    # When in doubt about a cancellation, cancel. When in doubt about a
    # confirmation, do not confirm.
    if re.search(r"^confirm (the )?(shut ?down|restart|reboot|sleep|sign ?out)$", t):
        return {"skill": "power", "action": "confirm", "target": ""}
    if _looks_cancel and re.search(r"\b(shut ?down|restart|reboot|sleep|sign ?out)\b", t):
        return {"skill": "power", "action": "cancel", "target": ""}
    # ── GUIDED REPAIR: answering the "want me to fix it?" question ──────────
    # Placed with the other PENDING-QUESTION handlers (clarify, cleanup, power)
    # rather than beside the rest of the repair routing further down, because
    # that is what it is: an answer to a question ARGUS asked, valid only while
    # the question stands. remedy.pending() expires on its own after two
    # minutes, so a "yes" said to something else later cannot land on it.
    #
    # AFTER power and cleanup deliberately. If a shutdown is staged AND a
    # repair is offered, the shutdown owns "yes" -- it is the irreversible one.
    from threatmon import remedy as _remedy
    if _remedy.pending():
        if re.match(r"^(?:yes|yeah|yep|yup|go ahead|do it|please do|fix it|"
                    r"go on|ok do it|sure|affirmative)\s*$", t):
            return {"skill": "remedy", "action": "apply", "target": ""}
        # "not" is in the list because _clean() strips a trailing "now" as
        # politeness, so "not now" arrives here as the bare word "not". The
        # alternative would be a special case in _clean; matching what actually
        # arrives is smaller and does not change every other pattern.
        if re.match(r"^(?:no|nope|not|don'?t|leave it|not now|cancel|stop|"
                    r"never ?mind|negative)\s*$", t):
            return {"skill": "remedy", "action": "cancel", "target": ""}

    # ── THE TASK LOOP: answering a staged plan ──────────────────────────────
    # Here with the other pending-question handlers, and ABOVE the generic
    # cancel below for the same reason the repair block is: a "no" said to a
    # plan must drop the plan, not fall into a power cancellation that leaves
    # it staged and answerable for another two minutes.
    if router_plan_pending():
        if re.match(r"^(?:yes|yeah|yep|go ahead|do it|run it|go on|proceed|"
                    r"sure|confirm|make it so)\s*$", t):
            return {"skill": "plan", "action": "run", "target": ""}
        if re.match(r"^(?:no|nope|not|don'?t|cancel|stop|never ?mind|"
                    r"forget it|drop it)\s*$", t):
            return {"skill": "plan", "action": "cancel", "target": ""}

    # A plan PAUSED mid-run (router.py's _NEEDS_AUTH path) -- distinct from
    # the block just above, which only ever sees a plan that has not
    # started. Same position in the pending-confirmation order as
    # BROWSER/EMAIL: after POWER and FILES, before the unconditional cancel.
    # Not narrowed to PIN-shaped input the way POWER's own block is, because
    # what resumes a paused plan varies with WHY it paused -- digits for a
    # PIN, a bare "confirm", or nothing special at all once the machine is
    # unlocked -- so, like files/browser/email's own staged actions, any
    # non-cancel utterance is offered to resume_paused_plan() and it decides.
    if router_plan_paused_pending():
        if re.match(r"^(?:no|nope|not|don'?t|cancel|stop|never ?mind|"
                    r"forget it|forget that task|drop it)\s*$", t):
            return {"skill": "plan", "action": "cancel_paused", "target": ""}
        return {"skill": "plan", "action": "resume", "target": raw.strip()}

    # The unconditional cancel, deliberately AFTER the remedy and plan blocks
    # above so a "no" said to an offer cancels THAT offer rather than being
    # absorbed by the generic path -- which would leave it armed for two more
    # minutes after he had already declined it. With nothing offered it
    # behaves exactly as before.
    if re.match(r"^(no|cancel|stop|nevermind|never mind|abort)$", t):
        return {"skill": "power", "action": "cancel", "target": ""}

    # Request phrasings, widened to how people actually ask. Each still names
    # the machine or is an unambiguous bare command, so ordinary sentences
    # containing "sleep" or "turn off" do not trigger a power action.
    if re.search(r"\b(shut ?down|power off|turn off)\b.*\b(pc|computer|laptop|machine|system)\b", t) \
            or re.search(r"\bshut (the )?(pc|computer|laptop|machine) down\b", t) \
            or re.match(r"^shut ?down$", t):
        return {"skill": "power", "action": "request", "target": "shutdown"}
    if re.search(r"\brestart\b.*\b(pc|computer|laptop|machine|system)\b", t) \
            or re.search(r"\breboot (the )?(pc|computer|laptop|machine)\b", t) \
            or re.match(r"^(restart|reboot)$", t):
        return {"skill": "power", "action": "request", "target": "restart"}
    if re.search(r"\b(go to sleep|sleep mode)\b", t) \
            or re.search(r"\b(put|send)\b.*\b(pc|computer|laptop|machine)\b.*\bsleep\b", t) \
            or re.search(r"\bsleep the (pc|computer|laptop|machine)\b", t) \
            or re.match(r"^sleep$", t):
        return {"skill": "power", "action": "request", "target": "sleep"}
    if re.search(r"\b(sign me out|log me out|sign out|log out)\b", t):
        return {"skill": "power", "action": "request", "target": "signout"}

    # ---------- PHONE ----------
    # "call me" is claimed here rather than left to the classifier because it
    # SPENDS MONEY and rings a real phone -- a misrouted guess is not a free
    # mistake. Narrow on purpose: "call me a taxi" and "what do you call this"
    # must not reach it.
    m = re.match(r"^(?:call|phone|ring)\s+(?:me|my phone)"
                 r"(?:\s+and\s+say\s+(.+))?$", t)
    if m:
        return {"skill": "phone", "action": "call",
                "target": (m.group(1) or "").strip()}
    if re.search(r"\b(?:can you|do you)?\s*(?:call|phone|ring) me\b", t) \
            and not re.search(r"\bcall me a\b|\bwhat do you call\b", t):
        return {"skill": "phone", "action": "call", "target": ""}
    if re.search(r"\bphone (?:status|setup)\b|\bcall(?:ing)? status\b", t):
        return {"skill": "phone", "action": "status", "target": ""}

    # ---------- STARTUP / PERSISTENCE ----------
    # threatmon/persistence.py has been watching five autostart surfaces since
    # it was built, and there was no way to ASK it anything -- it could raise
    # a finding but could not answer "what starts with my machine?". Claimed
    # here rather than left to the classifier for the same reason the other
    # security readouts are: the answer is local telemetry, and a misroute
    # sends the question to a cloud model instead of to the detector.
    #
    # The question form is one SHAPE (_STARTUP_QUESTION: opener, short noun
    # phrase, launch verb, a boot locus that ends the sentence), not a list of
    # phrasings. It replaces an unanchored "what starts at boot" pattern that
    # only covered a noun-less sentence and also took "what starts with windows
    # defender". It sits here, well above the SERVICE and APPS blocks, because
    # both of them read "start" / "open" anywhere in a sentence: "which apps
    # start at boot" became a staged service start and "which apps open when
    # windows starts" became the list of running apps.
    if re.search(r"\b(?:startup|start-?up|autostart|auto-?run|boot)\s+"
                 r"(?:programs?|items?|entries|apps?|tasks?)\b", t) \
            or _STARTUP_QUESTION.match(t) \
            or re.search(r"\bcheck\s+(?:my\s+)?(?:startup|autostart|persistence)\b", t):
        return {"skill": "persistence", "action": "check", "target": ""}

    # ---------- HOW HOT IS MY MACHINE (not the weather) ----------
    # "how hot is my cpu" / "what is my cpu temperature" ask about a part of THIS
    # computer. This is the one place in match() that returns None on purpose
    # rather than by falling off the end: None means "no fast path, answer it in
    # conversation", and the exit has to happen HERE, above every block that
    # reads a keyword anywhere in the sentence. Left lower down, the sentence is
    # taken by whichever gets there first: FILE SAFETY ("are my temps ok" became
    # a file inspection), DIAGNOSTICS ("check my laptop temp" became a full
    # diagnostic run), WEATHER (the forecast) or the live-readings block (a CPU
    # LOAD percentage offered as the answer to a heat question). No skill can
    # read a component temperature, so there is nothing to dispatch to; the
    # router keeps a question about this machine on the local model, which is
    # told not to invent figures. See asks_machine_heat.
    if asks_machine_heat(t):
        return None

    # ---------- DNS / HOSTS / PROXY ----------
    # Same gap, same reasoning: threatmon/netconfig.py watches the four places
    # traffic can be redirected and had no spoken route in.
    if re.search(r"\b(?:check|is|are)\b.{0,20}\b(?:my\s+)?"
                 r"(?:dns|hosts? file|proxy|winhttp)\b", t) \
            or re.search(r"\b(?:dns|hosts? file|proxy)\s+"
                         r"(?:settings?|status|integrity|hijack\w*)\b", t) \
            or re.search(r"\bis\s+(?:my\s+)?traffic\s+being\s+redirected\b", t):
        return {"skill": "netconfig", "action": "check", "target": ""}

    # ---------- LISTENING PORTS / ATTACK SURFACE ----------
    # INBOUND, and it has to be matched BEFORE the outbound block below,
    # because the two questions share almost all their vocabulary and only one
    # word tells them apart. "What's open on my machine" and "what's talking to
    # the internet" are opposite directions -- what can reach IN versus what is
    # reaching OUT -- and the outbound pattern's `(?:open\s+)?connections?`
    # alternative will happily claim "show me open ports" if it gets there
    # first, answering a question about exposure with a list of outbound
    # sockets. Direction words (listening / open / exposed / incoming) are
    # required here, so nothing outbound-shaped falls in.
    if re.search(r"\b(?:listening|open|exposed?)\s+(?:tcp\s+|udp\s+|network\s+)?"
                 r"ports?\b", t) \
            or re.search(r"\bwhat(?:'s| is| are)\s+(?:currently\s+)?listening\b", t) \
            or re.search(r"\bports?\s+(?:are\s+)?(?:open|listening|exposed)\b", t) \
            or re.search(r"\b(?:am i|is (?:my|this) (?:pc|machine|computer|laptop))\s+"
                         r"exposed\b", t) \
            or re.search(r"\b(?:what|anything)\b.{0,30}\b(?:accept\w*|allow\w*)\s+"
                         r"(?:incoming|inbound)\s+connections?\b", t) \
            or re.search(r"\b(?:attack surface|what can reach (?:me|my "
                         r"(?:pc|machine|computer|laptop)))\b", t) \
            or re.search(r"\bcheck\s+(?:my\s+)?(?:open\s+)?ports?\b", t):
        return {"skill": "diag", "action": "ports", "target": ""}

    # ---------- OUTBOUND CONNECTIONS ----------
    # "What's talking to the internet?" -- claimed here rather than left to
    # the model, which would answer with a general essay about network
    # monitoring instead of looking at this machine's actual sockets.
    if re.search(r"\bwhat(?:'s| is)\s+(?:talking|connect\w*|phoning|calling)"
                 r"\s+(?:to\s+)?(?:the\s+)?(?:internet|out|home|outside)\b", t) \
            or re.search(r"\b(?:show|list)\s+(?:me\s+)?(?:my\s+)?"
                         r"(?:open\s+|outbound\s+|network\s+)?connections?\b", t) \
            or re.search(r"\bwho\s+is\s+my\s+(?:pc|computer|machine|laptop)\s+"
                         r"talking\s+to\b", t) \
            or re.search(r"\bwhat\s+is\s+phoning\s+home\b", t):
        return {"skill": "net", "action": "connections", "target": ""}

    # ---------- GUIDED REPAIR: asking for one ----------
    # "Can you fix it?" -- the other half of a detection. Claimed here rather
    # than left to the classifier because a misroute sends a request to CHANGE
    # THE MACHINE to a chat model, which answers with a cheerful description of
    # how one might fix such a thing and changes nothing.
    #
    # ANSWERING an offer is handled much earlier, with the other
    # pending-question handlers -- see the remedy.pending() block up there.
    #
    # NOTE the missing "can you". _clean() strips "can you", "could you" and
    # "please" as prefixes before any pattern runs, so a regex that spells them
    # out can only ever match the phrasings _clean did NOT normalise. Matching
    # the stripped form is matching what actually arrives.
    if re.search(r"^fix (?:it|that|this|them|the (?:issue|problem))\b", t) \
            or re.search(r"^(?:repair|remediate|clean) (?:it|that|this)\b", t) \
            or re.search(r"^fix (?:my|the) (?:machine|pc|computer|issue|problem)\b", t) \
            or re.search(r"^sort (?:it|that) out\b", t):
        return {"skill": "remedy", "action": "offer", "target": ""}

    if re.search(r"^(?:what|anything) can you fix\b", t) \
            or re.search(r"^fix (?:anything|something)\b", t) \
            or re.search(r"\b(?:anything|something)\s+(?:you can|to)\s+fix\b", t):
        return {"skill": "diag", "action": "fixes", "target": ""}

    # ---------- FILE OPERATIONS ----------
    # Two-argument operations carry "<what>|<where>" in the target, split by
    # the router. A pipe cannot appear in a Windows filename, so it is a
    # separator nothing can collide with -- unlike a space or the word "to",
    # both of which appear inside real file names.
    #
    # ABOVE the plan block deliberately: "move the invoice to Documents" is one
    # operation, and letting the planner decompose it would turn a direct
    # action into a proposal that needs approving.
    # "MOVE" IS NOT ONLY A FILE VERB. It is also how people position windows
    # and monitors -- "move the window to the right", "move chrome to the
    # second screen". Those belong to window_skill, which sits further down,
    # so this has to decline them rather than claim the verb outright. The
    # discriminator is the DESTINATION: a screen direction or a display is
    # never a folder.
    m = re.match(r"^(?:move|put)\s+(?:the\s+|my\s+)?(.+?)\s+"
                 r"(?:in ?to|to|in)\s+(?:the\s+|my\s+)?(.+?)\s*$", t)
    if m and not re.search(r"\b(?:top|bottom|front|back|left|right|side|"
                           r"corner|centre|center|focus|sleep|awake|"
                           r"window|screen|monitor|display|desktop \d)\b", t):
        return {"skill": "files", "action": "move",
                "target": f"{m.group(1).strip()}|{m.group(2).strip()}"}
    m = re.match(r"^copy\s+(?:the\s+|my\s+)?(.+?)\s+"
                 r"(?:in ?to|to|in)\s+(?:the\s+|my\s+)?(.+?)\s*$", t)
    if m:
        return {"skill": "files", "action": "copy",
                "target": f"{m.group(1).strip()}|{m.group(2).strip()}"}
    m = re.match(r"^rename\s+(?:the\s+|my\s+)?(.+?)\s+to\s+(.+?)\s*$", t)
    if m:
        return {"skill": "files", "action": "rename",
                "target": f"{m.group(1).strip()}|{m.group(2).strip()}"}
    m = re.match(r"^(?:make|create)\s+(?:a\s+)?(?:new\s+)?folder\s+"
                 r"(?:called\s+|named\s+)?(.+?)"
                 r"(?:\s+in\s+(?:the\s+|my\s+)?(.+?))?\s*$", t)
    if m:
        return {"skill": "files", "action": "mkdir",
                "target": f"{m.group(1).strip()}|{(m.group(2) or '').strip()}"}
    m = re.match(r"^(?:zip|compress|archive)\s+(?:the\s+|my\s+)?(.+?)\s*$", t)
    if m:
        return {"skill": "files", "action": "compress",
                "target": f"{m.group(1).strip()}|"}
    m = re.match(r"^(?:unzip|extract)\s+(?:the\s+|my\s+)?(.+?)\s*$", t)
    if m:
        return {"skill": "files", "action": "extract",
                "target": f"{m.group(1).strip()}|"}
    m = re.match(r"^(?:how big is|details? (?:of|about|on)|info (?:on|about))\s+"
                 r"(?:the\s+|my\s+)?(.+?)\s*\??$", t)
    if m:
        return {"skill": "files", "action": "metadata",
                "target": m.group(1).strip()}
    if re.search(r"\b(?:recent|recently (?:changed|modified|saved))\s+files?\b", t) \
            or re.search(r"\bwhat (?:files? )?(?:have i|did i)\s+"
                         r"(?:change|save|edit)\w*\b", t):
        return {"skill": "files", "action": "recent", "target": t}
    if re.search(r"\bduplicate\s+files?\b", t) \
            or re.search(r"\b(?:find|any)\s+duplicates?\b", t):
        return {"skill": "files", "action": "duplicates", "target": ""}

    # ASKING for a plan. Deliberately narrow: a multi-step request is
    # recognised by the CONJUNCTION ("and then", "after that") or by an
    # explicit ask, not by guessing that a long sentence must be complicated.
    # Everything else keeps going to the single-skill path, which is faster,
    # needs no confirmation, and is right for the overwhelming majority.
    m = re.match(r"^(?:plan|work out how) (?:to )?(.+)$", t)
    if m:
        return {"skill": "plan", "action": "stage", "target": m.group(1).strip()}
    if re.search(r"\b(?:and then|then after|after that|and after)\b", t) \
            and re.match(r"^(?:" + _COMMAND_VERBS + r")\b", t):
        return {"skill": "plan", "action": "stage", "target": raw.strip()}

    # ---------- WEBSITE TASK TRIGGER -- browser/task alias to plan_and_stage(web=True)
    # Lead-in phrases: "on the website|online", "browse to <site> and <then>"
    # Reuses the existing plan trigger regexes + website qualifier.
    if re.search(r"\b(?:on the\s+)?(?:website|online|web)\b", t) \
            and re.search(r"\b(?:and then|then after|after that|go to|browse to|navigate to|visit)\b", t) \
            and re.match(r"^(?:" + _COMMAND_VERBS + r")\b", t):
        return {"skill": "browser", "action": "task", "target": raw.strip()}
    # "go to <site> and <then>" without explicit "website/online" --
    # only if it clearly names a site-like target and a followup action.
    m = re.match(r"^go to\s+([\w.:\/-]+?)\s+(?:and\s+|then\s+)(.+)$", t)
    if m:
        site = m.group(1).strip()
        then_clause = m.group(2).strip()
        if re.search(r"\b(?:download|upload|fill|submit|click|find|search|extract|get|save)\b", then_clause):
            return {"skill": "browser", "action": "task", "target": raw.strip()}

    # ---------- SCREEN CONTEXT ----------
    # "What window is this" is about the WINDOW; "what's on my screen" is about
    # the PIXELS and belongs to vision/describe, which captures and describes
    # an image. Two different questions that sound alike, so the window ones
    # name a window and are matched first.
    if re.search(r"\bwhat\s+(?:window|app|program|application)\s+(?:is\s+)?"
                 r"(?:this|that|am i (?:in|on|using))\b", t) \
            or re.search(r"\bwhat(?:'s| is)\s+(?:in\s+)?focus(?:ed)?\b", t) \
            or re.search(r"\bwhich\s+(?:window|app)\s+am i\b", t) \
            or re.match(r"^what am i using$", t):
        return {"skill": "pc", "action": "focused", "target": ""}

    # ---------- UI AUTOMATION ----------
    # The confirm branch first, guarded on a staged press -- same shape as
    # every other pending question in this file. A destructive-looking button
    # is staged rather than clicked (see pc_skill.UI_DESTRUCTIVE), and this is
    # where the answer lands.
    if pc_skill_ui_pending():
        if re.match(r"^(?:yes|yeah|yep|go ahead|do it|press it|click it|"
                    r"confirm|sure)\s*$", t):
            return {"skill": "pc", "action": "ui_confirm", "target": ""}
        if re.match(r"^(?:no|nope|not|don'?t|leave it|cancel|stop|"
                    r"never ?mind)\s*$", t):
            return {"skill": "pc", "action": "ui_cancel", "target": ""}

    # Same shape, one level down: a VISUAL (OCR-matched) click staged by
    # vision_skill.click_text(). Checked separately from UI automation's own
    # pending block above rather than merged into it -- the two live in
    # different skills with their own state, and PC's block already ran (and
    # would have fallen through) by the time this one is reached, so there is
    # no ordering conflict even if both were somehow pending at once.
    if vision_skill_visual_pending():
        if re.match(r"^(?:yes|yeah|yep|go ahead|do it|press it|click it|"
                    r"confirm|sure)\s*$", t):
            return {"skill": "vision", "action": "visual_confirm", "target": ""}
        if re.match(r"^(?:no|nope|not|don'?t|leave it|cancel|stop|"
                    r"never ?mind)\s*$", t):
            return {"skill": "vision", "action": "visual_cancel", "target": ""}

    if re.search(r"\bwhat(?:'s| is| can)?\s+(?:i\s+)?(?:on|in)\s+"
                 r"(?:this|the)\s+(?:window|screen|app)\b", t) \
            or re.search(r"\b(?:what|which)\s+(?:buttons?|controls?|fields?)\b", t) \
            or re.search(r"\bread\s+(?:this|the)\s+(?:window|screen|app|ui)\b", t) \
            or re.search(r"\bwhat can i (?:click|press|do here)\b", t) \
            or re.match(r"^(?:ui|window)\s+tree$", t):
        m = re.search(r"\bin\s+([\w .-]{2,40})$", t)
        return {"skill": "pc", "action": "ui_tree",
                "target": m.group(1).strip() if m else ""}

    # The interaction verbs, most specific first so "double click" is not
    # claimed by "click".
    m = re.match(r"^double[\s-]?click\s+(?:the\s+|on\s+)?(.+?)\s*$", t)
    if m:
        return {"skill": "pc", "action": "ui_double_click", "target": m.group(1).strip()}
    m = re.match(r"^right[\s-]?click\s+(?:the\s+|on\s+)?(.+?)\s*$", t)
    if m:
        return {"skill": "pc", "action": "ui_right_click", "target": m.group(1).strip()}
    m = re.match(r"^hover\s+(?:over\s+|on\s+)?(?:the\s+)?(.+?)\s*$", t)
    if m:
        return {"skill": "pc", "action": "ui_hover", "target": m.group(1).strip()}
    m = re.match(r"^drag\s+(?:the\s+)?(.+?)\s+(?:on ?to|to|over)\s+(?:the\s+)?(.+?)\s*$", t)
    if m:
        return {"skill": "pc", "action": "ui_drag",
                "target": f"{m.group(1).strip()}|{m.group(2).strip()}"}
    m = re.match(r"^scroll\s+(up|down|left|right)(?:\s+(?:in|on)\s+(?:the\s+)?(.+?))?\s*$", t)
    if m:
        return {"skill": "pc", "action": "ui_scroll",
                "target": f"{m.group(1)}|{(m.group(2) or '').strip()}"}
    m = re.match(r"^(?:select|choose|pick)\s+(?:the\s+)?(.+?)"
                 r"(?:\s+(?:from|in)\s+(?:the\s+)?(.+?))?\s*$", t)
    # "pick up", "select all" and "choose me" are not UI selections: the item
    # has to be a real name -- three characters or more and not a bare
    # preposition, pronoun or quantifier.
    if m and len(m.group(1).strip()) >= 3 \
            and not re.fullmatch(r"(?:up|out|all|everything|text|me|it|one|"
                                 r"something|anything)", m.group(1).strip()):
        return {"skill": "pc", "action": "ui_select",
                "target": f"{m.group(1).strip()}|{(m.group(2) or '').strip()}"}
    # "CHECK" IS AN INSPECTION VERB, NOT A CHECKBOX VERB. "Check the ollama
    # process", "check my defences", "check that Save is enabled" -- every one
    # of those is a request to LOOK, and the first version of this pattern
    # claimed all of them as checkbox toggles, silently breaking the process
    # dossier and the verify command. The checkbox sense of "check" needs a
    # box to check: it is only that when a box, checkbox, option or switch is
    # actually named. tick/untick/toggle are unambiguous and keep the bare form.
    m = re.match(r"^(?:tick|untick|uncheck|toggle|turn (?:on|off))\s+"
                 r"(?:the\s+)?(.+?)(?:\s+(?:checkbox|box|switch|option))?\s*$", t) \
        or re.match(r"^check\s+(?:the\s+)?(.+?)\s+(?:checkbox|box|option|switch)\s*$", t)
    if m and not re.search(r"\b(?:volume|brightness|wifi|bluetooth|privacy|"
                           r"lockdown|presence lock|night light|dark mode|light mode)\b", t):
        want = ("on" if re.match(r"^(?:tick|check|turn on)", t)
                else "off" if re.match(r"^(?:untick|uncheck|turn off)", t) else "")
        return {"skill": "pc", "action": "ui_toggle",
                "target": f"{m.group(1).strip()}|{want}"}
    m = re.match(r"^(?:expand|open up|unfold)\s+(?:the\s+)?(.+?)(?:\s+(?:node|group|menu))?\s*$", t)
    if m:
        return {"skill": "pc", "action": "ui_expand", "target": m.group(1).strip()}
    m = re.match(r"^(?:collapse|fold)\s+(?:the\s+)?(.+?)(?:\s+(?:node|group|menu))?\s*$", t)
    if m:
        return {"skill": "pc", "action": "ui_collapse", "target": m.group(1).strip()}
    m = re.match(r"^read\s+(?:the\s+)?(?:table|grid|list)(?:\s+(.+?))?\s*$", t)
    if m:
        return {"skill": "pc", "action": "ui_table", "target": (m.group(1) or "").strip()}
    if re.search(r"\b(?:is there|any)\s+(?:a\s+)?(?:dialog|popup|pop-up|prompt)\b", t) \
            or re.search(r"\bwhat(?:'s| is)\s+(?:the\s+)?(?:dialog|popup)\s+(?:say|asking)", t):
        return {"skill": "pc", "action": "ui_dialog", "target": ""}
    m = re.match(r"^wait (?:for|until)\s+(?:the\s+)?(.+?)(?:\s+(?:appears?|shows? up|loads?))?\s*$", t)
    if m:
        return {"skill": "pc", "action": "ui_wait", "target": m.group(1).strip()}
    m = re.match(r"^(?:is|check (?:that|if|whether))\s+(?:the\s+)?(.+?)\s+(?:is\s+)?"
                 r"(on|off|checked|unchecked|ticked|enabled|disabled|there|present|gone)\s*\??$", t)
    if m and not re.search(r"\b(?:wifi|bluetooth|internet|defender|firewall|"
                           r"privacy|lockdown|antivirus)\b", t):
        return {"skill": "pc", "action": "ui_verify",
                "target": f"{m.group(1).strip()}|{m.group(2)}"}
    m = re.match(r"^(?:capture|screenshot|snap)\s+(?:the\s+)?(.+?)\s+"
                 r"(?:button|panel|element|control|area)\s*$", t)
    if m:
        return {"skill": "pc", "action": "ui_screenshot", "target": m.group(1).strip()}

    m = re.match(r"^(?:click|press|push|tap|hit)\s+(?:the\s+|on\s+)?"
                 r"(.+?)\s*(?:button)?\s*$", t)
    if m and not re.search(r"\b(?:volume|brightness|screenshot)\b", t):
        return {"skill": "pc", "action": "ui_click", "target": m.group(1).strip()}

    m = re.match(r"^(?:type|enter|put|write)\s+(.+?\s+into\s+.+)$", t)
    if m:
        return {"skill": "pc", "action": "ui_type", "target": m.group(1).strip()}

    m = re.match(r"^(?:read|what(?:'s| is) in)\s+(?:the\s+)?"
                 r"([\w .-]{2,40}?)\s+(?:field|box|input)\s*\??$", t)
    if m:
        return {"skill": "pc", "action": "ui_read", "target": m.group(1).strip()}

    # ---------- LOCAL MACHINE CONTROLS ----------
    # Everything here is Win32 or a registry read -- local by construction, no
    # process spawned, nothing leaving the machine. Matched deterministically
    # for the usual reason: a misroute sends a request to CHANGE this computer
    # to a chat model, which describes the Settings app instead of doing it.
    if re.search(r"\b(?:empty|clear|take out)\s+(?:the\s+|my\s+)?"
                 r"(?:recycle ?bin|trash|bin)\b", t):
        return {"skill": "pc", "action": "empty_bin", "target": ""}

    if re.search(r"\b(?:dark|night)\s+(?:mode|theme)\b", t) \
            and not re.search(r"\b(?:is|what|which|are)\b", t):
        return {"skill": "pc", "action": "dark_mode", "target": ""}
    if re.search(r"\blight\s+(?:mode|theme)\b", t) \
            and not re.search(r"\b(?:is|what|which|are)\b", t):
        return {"skill": "pc", "action": "light_mode", "target": ""}
    if re.search(r"\b(?:what|which)\s+(?:theme|mode)\b", t) \
            or re.search(r"\b(?:am i|are we)\s+in\s+(?:dark|light)\s+mode\b", t):
        return {"skill": "pc", "action": "theme", "target": ""}

    if re.search(r"\b(?:screen|display|monitor)\s+(?:resolution|info|"
                 r"setup|size)\b", t) \
            or re.search(r"\bhow many (?:monitors|screens|displays)\b", t) \
            or re.search(r"\bwhat(?:'s| is) my (?:resolution|screen size)\b", t):
        return {"skill": "pc", "action": "display", "target": ""}

    if re.search(r"\b(?:system|machine|pc|computer)\s+(?:info|information|"
                 r"spec|specs|specification)\b", t) \
            or re.search(r"\bwhat\s+(?:windows|version of windows)\b", t) \
            or re.search(r"\bwhat(?:'s| is)\s+(?:my|this)\s+"
                         r"(?:pc|machine|computer|laptop)\b\s*\??$", t):
        return {"skill": "pc", "action": "sysinfo", "target": ""}

    m = re.match(r"^(?:is|do i have)\s+([\w .+-]{2,40}?)\s+installed\s*\??$", t)
    if m:
        return {"skill": "pc", "action": "installed", "target": m.group(1).strip()}
    if re.search(r"\bwhat(?:'s| is)?\s+installed\b", t) \
            or re.search(r"\blist\s+(?:my\s+)?(?:installed\s+)?programs\b", t):
        return {"skill": "pc", "action": "installed", "target": ""}

    m = re.match(r"^(?:keep|pin|put)\s+(.+?)\s+(?:on top|above everything|"
                 r"always on top)\s*$", t)
    if m:
        return {"skill": "pc", "action": "pin_window",
                "target": m.group(1).strip()}
    m = re.match(r"^(?:unpin|release)\s+(.+?)(?:\s+from top)?\s*$", t)
    if m:
        return {"skill": "pc", "action": "unpin_window",
                "target": m.group(1).strip()}

    # ---------- STOPPING PROCESSES ----------
    # The other half of the interrupt fix above. "Stop unused processes" is now
    # allowed past the interrupt block (it has an object), and this is what
    # catches it -- without this it would fall to the classifier, which has no
    # such skill and would answer with a description of Task Manager.
    #
    # The CONFIRMATION branch is first and guarded on an offer actually being
    # staged, exactly like clarify, cleanup and remedy. Placed here rather than
    # with those because the offer is made by pc_skill and expires on its own.
    if pc_skill_has_pending_stop():
        if re.match(r"^(?:yes|yeah|yep|yup|go ahead|do it|please do|stop them|"
                    r"stop it|kill them|sure|confirm|affirmative)\s*$", t):
            return {"skill": "pc", "action": "confirm_stop", "target": ""}
        if re.match(r"^(?:no|nope|not|don'?t|leave (?:it|them)|not now|cancel|"
                    r"stop|never ?mind|negative)\s*$", t):
            return {"skill": "pc", "action": "cancel_stop", "target": ""}

    m = re.match(r"^(?:stop|kill|end|close|quit|terminate|shut)\s+"
                 r"(?:down\s+)?(.*\b(?:process(?:es)?|task(?:s)?|"
                 r"program(?:s)?|app(?:s|lication(?:s)?)?)\b.*)$", t)
    if m:
        return {"skill": "pc", "action": "stop_processes",
                "target": m.group(1).strip()}
    if re.search(r"\b(?:free up|reclaim|lower|reduce|bring down)\s+"
                 r"(?:my\s+|the\s+)?(?:cpu|ram|memory|usage|load)\b", t) \
            or re.match(r"^(?:stop|kill)\s+(?:whatever|what)(?:'s| is)\s+"
                        r"(?:eating|using|hogging|burning)\b", t):
        return {"skill": "pc", "action": "stop_processes", "target": ""}
    if re.search(r"\bwhat(?:'s| is)\s+(?:eating|using|hogging|burning)\s+"
                 r"(?:my\s+|the\s+)?(?:cpu|ram|memory|resources)\b", t) \
            or re.search(r"\b(?:heaviest|biggest)\s+(?:process(?:es)?|"
                         r"program(?:s)?)\b", t):
        return {"skill": "pc", "action": "heavy", "target": ""}

    # ---------- TIMEZONE ----------
    # The clock ARGUS answers with. Matched BEFORE the generic clock patterns
    # further down, which would otherwise claim "what timezone are you using"
    # on the word "timezone" and answer with the local time -- the one reply
    # that cannot possibly address a question about which zone is in use.
    m = re.match(r"^(?:set|change|use|switch)\s+(?:my\s+|the\s+)?"
                 r"time ?zone\s+(?:to\s+)?(.+)$", t)
    if m:
        return {"skill": "pc", "action": "timezone",
                "target": m.group(1).strip()}
    m = re.match(r"^(?:my\s+)?time ?zone\s+is\s+(.+)$", t)
    if m:
        return {"skill": "pc", "action": "timezone",
                "target": m.group(1).strip()}
    if re.search(r"\b(?:what|which)\s+time ?zone\b", t) \
            or re.search(r"\btime ?zone\s+(?:are you|do you|status|setting)\b", t) \
            or re.match(r"^time ?zone$", t):
        return {"skill": "pc", "action": "timezone", "target": ""}

    # ---------- WHAT CHANGED ----------
    # One answer over every baseline-diff detector. Matched here rather than
    # left to the classifier for the same reason as the rest of this group: the
    # answer is local telemetry, and a misroute sends "what changed on my
    # machine" to a cloud model, which will happily write an essay about change
    # management instead of reading this machine's own record.
    #
    # ANCHORED ON THE MACHINE, deliberately. Bare "what's changed" is a
    # perfectly ordinary conversational question -- about a document, a plan,
    # a piece of code -- so a machine word (machine / pc / computer / system /
    # here) or an explicitly security-shaped noun is required. Without one it
    # falls through to chat, which is the safe direction.
    if (re.search(r"\bwhat(?:'s| is| has)?\s+(?:changed|different|new)\b", t)
            and re.search(r"\b(?:machine|pc|computer|laptop|system|here|"
                          r"since (?:yesterday|last night|this morning|i))\b", t)) \
            or re.search(r"\b(?:anything|something)\s+(?:changed|new)\b.{0,24}"
                         r"\b(?:machine|pc|computer|laptop|system)\b", t) \
            or re.search(r"\bwhat\s+happened\s+while\s+i\s+was\s+"
                         r"(?:out|away|gone|asleep)\b", t) \
            or re.search(r"\b(?:change|changes)\s+report\b", t) \
            or re.search(r"\bwhat(?:'s| is| has)?\s+changed\s+(?:in|over)\s+"
                         r"the\s+last\s+\d+", t):
        return {"skill": "diag", "action": "changes", "target": t}

    # ---------- ONE PROCESS, IN DETAIL ----------
    # The natural follow-up to the port and startup questions above: ARGUS says
    # something is listening on 5432, and the next thing out of anyone's mouth
    # is "what IS that". threatmon/procinfo.py can answer it; this is the way in.
    #
    # DELIBERATELY NARROW, because "tell me about X" is the single most general
    # sentence in English and stealing it would break every knowledge question
    # in the app. A match needs the word process or pid, OR a .exe, OR an
    # explicit machine frame ("running", "on my pc") -- so "tell me about the
    # svchost process" routes here and "tell me about the Roman empire" does
    # not. Anything that is genuinely ambiguous is left to fall through to
    # chat, which is the safe direction: answering a factual question with a
    # process dossier is a much worse failure than the reverse.
    m = re.match(r"^(?:what(?:'s| is)|tell me about|describe|look at|check)\s+"
                 r"(?:the\s+)?(?:process\s+)?(?:pid\s+)?"
                 r"(\d{2,7}|[\w.\- ]{2,40}?)"
                 r"(?:\s+process)?"
                 r"(?:\s+(?:doing|running|up to))?"
                 r"(?:\s+on\s+(?:my|this)\s+"
                 r"(?:pc|machine|computer|laptop|system))?\s*\??$", t)
    if m:
        target = m.group(1).strip()
        # The frame that makes it a PROCESS question rather than a general one.
        # Checked on the whole sentence, not on the captured name, so "what is
        # chrome" stays a chat question while "what is chrome doing on my pc"
        # comes here.
        #
        # "exe" is matched as a BARE WORD, not as ".exe". _clean() above
        # rewrites every character outside [\w\s%:'] to a space, so by the time
        # a pattern sees it "what is chrome.exe" has become "what is chrome
        # exe" -- a `\.exe\b` test can never fire here and the most obviously
        # process-shaped phrasing in the language fell straight through to chat.
        explicit = (re.search(r"\b(?:process(?:es)?|pid)\b", t)
                    or re.search(r"\bexe\b", t)
                    or (re.search(r"\b(?:doing|running|up to)\b", t)
                        and re.search(r"\bon\s+(?:my|this)\s+"
                                      r"(?:pc|machine|computer|laptop|system)\b", t)))
        if explicit and target and not target.isspace():
            target = target.removeprefix("the ").strip()
            # Put the extension back on rather than passing "chrome exe" to a
            # name lookup that would match nothing. find() strips it again --
            # this is about not corrupting the name in transit.
            target = re.sub(r"\s+exe$", ".exe", target)
            if target:
                return {"skill": "diag", "action": "process", "target": target}

    # "Is <something> signed" is unambiguous on its own -- nothing else in the
    # app answers it, and no ordinary question is phrased that way.
    m = re.match(r"^is\s+(?:the\s+)?([\w.\-]{2,40})\s+"
                 r"(?:process\s+)?(?:signed|legit|legitimate|safe)\s*\??$", t)
    if m:
        return {"skill": "diag", "action": "process", "target": m.group(1)}

    # "Why is X running" / "what started X" -- a question about provenance,
    # which is exactly the parent-process field of the dossier.
    m = re.match(r"^(?:why\s+is|what\s+started|who\s+started)\s+"
                 r"(?:the\s+)?([\w.\- ]{2,40}?)\s*(?:running|started)?\s*\??$", t)
    if m and re.search(r"\b(?:running|started)\b", t):
        return {"skill": "diag", "action": "process", "target": m.group(1).strip()}

    # ---------- REMOVABLE DEVICES ----------
    if re.search(r"\b(?:what|anything)\b.{0,24}\b(?:plugged in|usb|removable"
                 r"|flash drive|thumb ?drive)\b", t) \
            or re.search(r"\b(?:usb|removable)\s+(?:devices?|drives?|status)\b", t) \
            or re.search(r"\bwhat\s+(?:usb|drives?)\s+(?:do\s+i\s+have|"
                         r"are\s+(?:there|attached))\b", t):
        return {"skill": "usb", "action": "list", "target": ""}

    # ---------- FILE SAFETY ----------
    # "Is this download safe?" -- the question you ask before double-clicking.
    # Claimed here rather than left to the model, which would happily give a
    # confident opinion about a file it has never seen.
    m = re.match(r"^(?:is|are)\s+(?:this|that|my)\s+(.+?)\s+"
                 r"(?:safe|ok|okay|legit|signed|trustworthy|malware|a virus)"
                 r"\??$", t)
    if m:
        return {"skill": "files", "action": "inspect",
                "target": m.group(1).strip()}
    m = re.match(r"^(?:check|inspect|scan|verify)\s+(?:my\s+|this\s+|the\s+)?"
                 r"(latest|last|newest|recent)?\s*download(?:s)?\s*$", t)
    if m:
        return {"skill": "files", "action": "inspect", "target": "latest"}
    m = re.match(r"^(?:check|inspect|verify)\s+(?:if\s+)?(?:the\s+|this\s+|my\s+)?"
                 r"(?:file\s+)?(.+?)\s+(?:is\s+)?"
                 r"(?:safe|signed|legit|ok|okay)\s*\??$", t)
    if m:
        return {"skill": "files", "action": "inspect",
                "target": m.group(1).strip()}

    # ---------- SELF-REVIEW ----------
    # "What did you get wrong today" -- ARGUS reading back its own transcript
    # and reporting what it did not understand. Claimed here rather than left
    # to the model, which would cheerfully invent an answer about its own
    # performance rather than actually look.
    if re.search(r"\bwhat\s+did\s+you\s+(?:get\s+wrong|miss|fail|not\s+"
                 r"understand)\b", t) \
            or re.search(r"\breview\s+(?:your|yourself|your\s+own)\b", t) \
            or re.search(r"\b(?:what|anything)\s+(?:did\s+)?you\s+"
                         r"(?:struggle|couldn'?t|could\s+not)\b", t) \
            or re.search(r"\bself[\s-]?review\b", t):
        return {"skill": "briefing", "action": "review", "target": ""}

    # ---------- LOCKDOWN ----------
    # Arming this means ARGUS may lock the screen on its own, so the phrases
    # are explicit ones nobody says by accident. Claimed here rather than left
    # to the classifier for that reason: a misrouted guess that arms an
    # autonomous lock is not a free mistake.
    if re.search(r"\b(?:arm|enable|turn on|switch on)\s+(?:auto ?)?"
                 r"lock ?down\b", t) \
            or re.search(r"\block\s+(?:yourself|the screen)\s+if\s+you\s+"
                         r"(?:detect|find|see)\b", t):
        return {"skill": "lockdown", "action": "arm", "target": ""}
    if re.search(r"\b(?:disarm|disable|turn off|switch off|stop)\s+"
                 r"(?:auto ?)?lock ?down\b", t):
        return {"skill": "lockdown", "action": "disarm", "target": ""}
    if re.search(r"\block ?down\s+status\b", t):
        return {"skill": "lockdown", "action": "status", "target": ""}

    # ---------- SECURITY STATE / KILL SWITCH ----------

    # kill switch stops everything, so nothing casual may land there -- but
    # equally, nothing may steal the phrase either ("stop" alone must stay
    # pc/stop_speaking). The state read is the phrase that does no harm;
    # recovery is L4 + Hello at the gate, so its phrase can afford to be a
    # little more natural.
    if re.search(r"\b(?:kill|emergency|panic)\s+(?:switch|stop|button)\b"
                 r"|\bstop\s+everything\s+now\b", t):
        return {"skill": "security", "action": "killall", "target": ""}
    if re.search(r"\b(?:security|safety)\s+(?:state|mode|status)\b"
                 r"|\bwhat(?:'s| is)\s+the\s+security\s+state\b", t):
        return {"skill": "security", "action": "state", "target": ""}
    if re.search(r"\b(?:run|begin|start|perform)\s+(?:the\s+)?recovery\b"
                 r"|\brecover\s+(?:from\s+)?lockdown\b", t):
        return {"skill": "security", "action": "recover", "target": ""}

    # ---------- GESTURES ----------
    # Claimed here rather than left to the classifier because arming this
    # OPENS THE CAMERA, and a misrouted guess that switches the webcam on is
    # not a free mistake. Narrow on purpose: "watch this video" and "what did
    # my camera do today" (privacy) must not reach it.
    if re.search(r"\b(?:watch|read|follow)\s+my\s+(?:hands?|gestures?)\b", t) \
            or re.search(r"\bgesture(?:s)?\s*(?:mode|control)\b", t) \
            or re.search(r"\b(?:enable|start|turn on)\s+gestures?\b", t):
        return {"skill": "gesture", "action": "arm", "target": ""}
    if re.search(r"\b(?:stop|quit|end|disable|turn off)\s+(?:watching\s+)?"
                 r"(?:my\s+)?(?:hands?|gestures?)\b", t) \
            or re.search(r"\bgestures?\s+off\b", t):
        return {"skill": "gesture", "action": "disarm", "target": ""}
    if re.search(r"\bgestures?\s+status\b", t):
        return {"skill": "gesture", "action": "status", "target": ""}


    # ---------- WAKE BRIEFING ----------
    # "what did i miss" is a question, so it would otherwise reach the model,
    # which knows nothing about this machine's last few hours. Claimed here so
    # it is answered from real session history and threatmon's own buffer.
    if re.search(r"\bwhat did i miss\b|\bwhat happened while i was\b|"
                 r"\bbrief me\b|\bcatch me up\b(?!.{0,12}\bnews\b)|"
                 r"\banything happen(?:ed)?\b.{0,20}\b(?:while i was away|"
                 r"overnight|last night)\b|\bwhat'?s? new (?:with|on) (?:my )?"
                 r"(?:pc|computer|machine|system)\b", t):
        return {"skill": "briefing", "action": "brief", "target": ""}

    # ---------- LIVE INTEL ----------
    # "what's happening in the world" is a QUESTION, so it would otherwise fall
    # through to conversation and be answered from the model's training data --
    # confidently, and months out of date. Claimed here so it goes to a real
    # search that puts the sources on screen and opens them.
    #
    # Matched against _clean() output (see the cleanup block below for why that
    # matters), and kept narrow: it must not swallow "what is happening" about
    # this machine, which belongs to the security summary above.
    # "whats" without the apostrophe is what speech recognition actually
    # delivers most of the time, so `what'?s?` is not optional polish.
    if (re.search(r"\b(?:what'?s?|what is)\s+(?:happening|going on|new|up)\b"
                  r".{0,22}\b(?:world|globally|internationally|news|tech|"
                  r"technology|ai|cyber|security)\b", t)
            or re.search(r"\b(?:world|latest|breaking|top|tech|technology|"
                         r"cyber ?security|security)\s+news\b", t)
            or re.search(r"\b(?:any|the)\s+news\b|\bnews\s+(?:headlines|today|"
                         r"update)\b|\bheadlines\b|\bcatch me up\b", t)):
        topic = "world"
        if re.search(r"\b(?:tech|technology|ai)\b", t):
            topic = "tech"
        elif re.search(r"\b(?:cyber|breach|hack|vulnerabilit)\w*\b", t):
            topic = "security"
        return {"skill": "intel", "action": "brief", "target": topic}
    if re.search(r"\b(?:search|look ?up|find out|check)\b.{0,14}"
                 r"\b(?:online|on the web|on the internet)\b", t):
        return {"skill": "intel", "action": "brief", "target": raw.strip()}

    # ---------- FACE ----------
    # Enrolment is phrased as teaching, recognition as asking. Both are claimed
    # here rather than left to the classifier because "learn my face" contains
    # no machine noun and would otherwise read as conversation.
    # NOTE: these are matched against the CLEANED text, which strips politeness
    # wrappers -- "can you see me" arrives here as "see me" and "watch for me"
    # as bare "watch". Patterns written against the raw phrasing silently never
    # fire, which is how the first version of this block matched in a REPL and
    # not in the product. Every pattern below was checked against _clean()'s
    # actual output rather than against what the user types.
    if re.search(r"\b(?:learn|remember|memoris|memoriz|enrol|register)\w*"
                 r"\s+(?:my\s+)?face\b", t) \
            or re.search(r"\bface\s+(?:enrol\w*|scan|setup|recognition)\b", t) \
            or re.search(r"\bset ?up\s+face\b", t):
        return {"skill": "face", "action": "enroll", "target": ""}
    if re.search(r"\b(?:forget|delete|remove|erase|wipe)\b.{0,14}\bface\b", t):
        return {"skill": "face", "action": "forget", "target": ""}
    if re.search(r"\b(?:do you (?:recognis|recogniz)e me|(?:recognis|recogniz)e"
                 r" my face|do you see me|see me|do you know (?:who i am|me)|"
                 r"is that me)\b", t):
        return {"skill": "face", "action": "check", "target": ""}
    # "stop ..." first: the enable pattern would otherwise claim the disable
    # phrasing, since both contain the same verb.
    if re.search(r"\bstop\s+(?:watching|guarding)\s+me\b|\b(?:stop|turn off|"
                 r"disable)\s+presence\s+lock\b", t):
        return {"skill": "face", "action": "unwatch", "target": ""}
    if re.search(r"\b(?:watch|guard)\s+me\b|\block\s+when\s+i\s+"
                 r"(?:leave|walk away|am away)\b|\bpresence\s+lock\b", t):
        return {"skill": "face", "action": "watch", "target": ""}

    # ---------- DISK CLEANUP ----------
    # Checked BEFORE file deletion on purpose. "delete not needed temp files"
    # otherwise matched the generic `^delete (.+)$` rule below and went looking
    # for a FILE literally named "not needed temp files" -- a request to clear
    # temp space became a (failed, and had it succeeded, wrong) single-file
    # deletion. Cleanup is a fixed-scope operation with no user-supplied path,
    # so claiming these phrasings here is strictly safer than letting them fall
    # through to a rule that takes an arbitrary target.
    #
    # Scanning is what these map to -- never the deletion itself. The skill
    # measures first, reports real numbers and asks; router.py routes the
    # agreement to cleanup/run while that scan is still pending.
    # SHAPE, not just words. "how would you free up space on a full drive" and
    # "how much free space on my c drive" contain every cleanup word and are
    # both questions -- one wants advice, the other wants a reading, and
    # neither wants files deleted. An interrogative opener therefore vetoes the
    # match outright. "can/could/would/will you ..." is deliberately NOT in the
    # veto: it is a polite imperative ("can you clear my cache"), not a request
    # for information, and treating it as a question is how an assistant ends
    # up explaining a task instead of doing it.
    _asks_about = re.match(r"^(?:how|what|why|when|where|who|which|whose|"
                           r"is|are|was|were|do|does|did|should|tell me|"
                           r"explain|show me)\b", t)
    if not _asks_about and (
            re.search(r"\b(?:clear|clean|empty|purge|wipe|free|delete|remove|"
                      r"get rid of)\b.{0,24}\b(?:cache|caches|temp|tmp|"
                      r"temporary|junk|clutter|disk space|space)\b", t)
            or re.search(r"\b(?:disk ?clean-?up|clean ?up my (?:pc|computer|"
                         r"laptop|machine|drive)|free up (?:some )?(?:disk )?"
                         r"space|running out of (?:disk )?space)\b", t)):
        return {"skill": "cleanup", "action": "scan", "target": ""}

    # ---------- FILE DELETION (staged, never immediate -- same shape as
    # POWER above, same reasoning: irreversible, so a mishearing must not
    # be enough on its own). Checked in the same relative position POWER
    # occupies among the other pending-confirmation types (CLARIFY, then
    # POWER, then this) -- an extreme edge case where two different staged
    # confirmations are somehow pending at once resolves in that same
    # established order rather than a new, undocumented one. ----------
    # BUGFIX caught before shipping: POWER's own unconditional cancel-word
    # handler a few lines above ("no|cancel|...") is checked BEFORE this
    # section, so a bare "cancel" would already have matched power/cancel
    # and returned by the time execution ever reached a files-specific
    # cancel check here -- this block would have been unreachable dead code
    # for that exact input. Cancel-words are NOT re-claimed here; instead
    # router.py's power/cancel dispatch is extended to also clear a pending
    # file deletion, the same "one place clears every pending confirmation
    # type" shape pc/stop_speaking already uses for power+clarify. Only the
    # confirm-routing (a PIN digit typed while a deletion is pending) needs
    # to live here, since that's specific to files having something staged.
    from skills import files_skill
    if files_skill.has_pending_delete() and \
       not re.match(r"^(no|cancel|nevermind|never mind|abort)$", t):
        return {"skill": "files", "action": "confirm_delete", "target": raw.strip()}
    m = re.match(r"^delete (?:my |the )?(?:file )?(.+)$", t)
    if m:
        target = re.sub(r"\b(file|please)\b", "", m.group(1)).strip()
        if target:
            return {"skill": "files", "action": "delete", "target": target}

    # ---------- FILES RESTORE -- staged confirm, same shape as delete
    # "restore <file>", "get <file> back from the recycle bin", "undelete <file>"
    # Guarded against "restart" (power) by requiring a subject that looks like
    # a filename, not a machine command. The exact baseline patterns:
    m = re.match(r"^(?:restore|get|undelete)\s+(?:my |the )?(.+?)\s*$", t)
    if m:
        target = re.sub(r"\b(file|please|back)\b", "", m.group(1)).strip()
        if target and not re.search(r"\b(?:computer|pc|laptop|machine|system)\b", target):
            return {"skill": "files", "action": "restore", "target": target}
    m = re.match(r"^get\s+(?:my |the )?(.+?)\s+back\s+(?:from\s+)?(?:the\s+)?recycle\s+bin\s*$", t)
    if m:
        target = re.sub(r"\b(file|please)\b", "", m.group(1)).strip()
        if target:
            return {"skill": "files", "action": "restore", "target": target}

    # ---------- FILES RESTORE CONFIRM/CANCEL -- pending confirmation handling
    # Same relative position as files/confirm_delete: checked AFTER staging,
    # so a PIN typed while a restore is pending reaches restore_confirm.
    from skills import files_skill
    if files_skill.has_pending_restore() and \
       not re.match(r"^(no|cancel|nevermind|never mind|abort)$", t):
        return {"skill": "files", "action": "confirm_restore", "target": raw.strip()}

    # ---------- BROWSER (staged submit/download/upload) -- same shape and
    # same relative position as FILE DELETION just above: checked after
    # POWER and FILES in the established pending-confirmation order, cancel
    # words NOT re-claimed here (power/cancel's dispatch already clears a
    # pending browser action too, same as it does for files). Only the
    # confirm-routing needs to live here. ----------
    from skills import browser_skill
    if browser_skill.has_pending() and \
       not re.match(r"^(no|cancel|nevermind|never mind|abort)$", t):
        return {"skill": "browser", "action": "confirm", "target": raw.strip()}

    # ---------- EMAIL (staged send/reply/forward) -- same shape, same
    # relative position as BROWSER just above. ----------
    from skills import email_skill
    if email_skill.has_pending() and \
       not re.match(r"^(no|cancel|nevermind|never mind|abort)$", t):
        return {"skill": "email", "action": "confirm", "target": raw.strip()}

    # ---------- SERVICE (staged start/stop/restart) -- same shape as FILES
    # and EMAIL above, same relative position right after them: cancel words
    # not re-claimed here (power/cancel's dispatch already clears a staged
    # service action too, see router.py), only the confirm-routing lives
    # here -- a PIN digit typed while a service action is staged has to reach
    # service/confirm, not be swallowed by some unrelated pattern.
    #
    # PIN-SHAPE GUARD, exactly like POWER's: only something PIN-shaped counts
    # as an attempt. Anything else is the user talking -- "hey there" is not a
    # failed authentication and must not eat one of the three attempts that
    # gate a service change. Non-confirmation speech falls through to normal
    # matching, where the router's pending-reminder appends "still waiting
    # for the PIN" to whatever the real answer was. ----------
    from skills import service_skill as _svc_skill
    if _svc_skill.has_pending() and \
       not re.match(r"^(no|cancel|nevermind|never mind|abort)$", t):
        attempt = re.sub(r"[\s\-]", "", raw.strip())
        if attempt.isdigit():
            return {"skill": "service", "action": "confirm", "target": attempt}
        if re.match(r"^(yes|yeah|yep|confirm|do it|go ahead|ok|okay)$", t):
            # Reaches confirm with no PIN and gets the honest "wrong PIN"
            # reply -- approving by agreement is not approving.
            return {"skill": "service", "action": "confirm", "target": ""}

    # ---------- ENV VAR (staged set) -- identical shape to SERVICE just
    # above: a PIN digit typed while an env_var/set is staged reaches
    # env_var/confirm; ordinary speech falls through. ----------
    from skills import env_skill as _env_skill
    if _env_skill.has_pending() and \
       not re.match(r"^(no|cancel|nevermind|never mind|abort)$", t):
        attempt = re.sub(r"[\s\-]", "", raw.strip())
        if attempt.isdigit():
            return {"skill": "env_var", "action": "confirm", "target": attempt}
        if re.match(r"^(yes|yeah|yep|confirm|do it|go ahead|ok|okay)$", t):
            return {"skill": "env_var", "action": "confirm", "target": ""}

    # ---------- DIAGNOSTICS ----------
    if re.search(r"\b(diagnos\w*|health check|run a check|check my (pc|system|computer|laptop)|scan my (pc|system)|is everything (ok|okay|alright))\b", t):
        return {"skill": "diag", "action": "full", "target": ""}

    # ---------- NETWORK ----------
    if re.search(r"\b(am i online|internet working|are we online|is the internet)\b", t):
        return {"skill": "net", "action": "online", "target": ""}
    # "wifi" alone is not a request for the current network -- "describe how
    # wifi actually transmits data" is a question about radio, and it was
    # answered with the name of the access point. Asking WHICH network, or
    # asking about mine, is the reading; the bare noun is not.
    if re.search(r"\b(network name|what network|which network|"
                 r"what(?:'s| is) my (?:wifi|wi-fi|network)|"
                 r"which wifi|what wifi|am i connected to)\b", t) or \
            (re.search(r"\b(wifi|wi-fi)\b", t) and wants_live_reading(t)):
        return {"skill": "net", "action": "wifi", "target": ""}
    # "what is an ip address" is a definition, not a request for MY ip.
    if re.search(r"\bmy ip\b", t) or \
            (re.search(r"\bip address\b", t) and not is_definition_question(t)):
        return {"skill": "net", "action": "ip", "target": ""}
    if re.search(r"\b(data usage|how much data)\b", t):
        return {"skill": "net", "action": "data", "target": ""}

    # ---------- WINDOWS ----------
    # Each guards against a bare pronoun for the same reason as the app
    # patterns above: "minimise it" must reach followup_skill, not be looked up
    # as a window literally named "it".
    m = re.match(r"^(?:switch to|go to window|focus|bring up window)\s+(.+)$", t)
    if m and not _BARE_PRONOUN.match(m.group(1).strip()):
        return {"skill": "window", "action": "focus", "target": m.group(1).strip()}
    m = re.match(r"^minimi[sz]e\s+(.+)$", t)
    if m and not _BARE_PRONOUN.match(m.group(1).strip()):
        return {"skill": "window", "action": "minimize", "target": m.group(1).strip()}
    m = re.match(r"^maximi[sz]e\s+(.+)$", t)
    if m and not _BARE_PRONOUN.match(m.group(1).strip()):
        return {"skill": "window", "action": "maximize", "target": m.group(1).strip()}
    if re.search(r"\b(show (the )?desktop|minimi[sz]e everything|minimi[sz]e all)\b", t):
        return {"skill": "window", "action": "minimize_all", "target": ""}

    # ---------- WORKSPACES ----------
    # The SAVE form is claimed earlier, above _VAULT_WRITE -- see there for
    # why. Only the recall forms live here.
    m = re.match(r"^(?:set ?up|restore|open|load|bring up|give me)\s+"
                 r"(?:my\s+)?(.+?)\s+(?:workspace|layout|setup|set-?up)\s*$", t)
    if m:
        return {"skill": "apps", "action": "restore_workspace",
                "target": m.group(1).strip()}
    if re.search(r"\b(?:what|which|list)\b.{0,20}\bworkspaces?\b", t) \
            or re.match(r"^workspaces?$", t):
        return {"skill": "apps", "action": "list_workspaces", "target": ""}
    m = re.match(r"^(?:forget|delete|remove)\s+(?:my\s+)?(.+?)\s+"
                 r"(?:workspace|layout)\s*$", t)
    if m:
        return {"skill": "apps", "action": "forget_workspace",
                "target": m.group(1).strip()}

    # ---------- TILING ----------
    # "Put the browser on the left" is the window command people actually say
    # and could not, and the two-window form is one sentence so it must be one
    # action -- arranging half a screen and then failing is worse than not
    # starting. The side is matched from a CLOSED set (see window_skill's
    # _HALVES): anything else is not a side and must fall through rather than
    # be handed to a window search as if it were a name.
    _SIDE = (r"(?:top |bottom )?(?:left|right)(?: side| half)?|top(?: half)?|"
             r"bottom(?: half)?|cent(?:re|er)|middle|full ?screen|"
             r"maximi[sz]ed")
    # The preposition is OPTIONAL, because "put my editor full screen" is how
    # that one is actually said -- nobody says "put my editor to full screen".
    m = re.match(rf"^(?:put|move|snap|throw|send)\s+(.+?)\s+"
                 rf"(?:(?:on|to|in|into)\s+(?:the\s+)?)?({_SIDE})\b"
                 rf"(?:\s+(?:of|on)\s+(?:the\s+)?screen)?\s*$", t)
    if m and not _BARE_PRONOUN.match(m.group(1).strip()):
        first, side2 = m.group(1).strip(), m.group(2).strip()
        # The regex is anchored to the END, so in "code on the left and chrome
        # on the right" the FIRST capture swallows everything up to the last
        # side: "code on the left and chrome". Split that back out, or ARGUS
        # goes looking for a window with that entire sentence as its title.
        two = re.match(rf"^(.+?)\s+(?:on|to|in)\s+(?:the\s+)?({_SIDE})\s+"
                       rf"and\s+(?:put\s+|move\s+)?(.+)$", first)
        if two:
            return {"skill": "window", "action": "arrange",
                    "target": f"{two.group(1).strip()}|{two.group(2).strip()};"
                              f"{two.group(3).strip()}|{side2}"}
        return {"skill": "window", "action": "snap",
                "target": f"{first}|{side2}"}
    if re.search(r"\b(?:tile|split)\s+(?:my\s+)?(?:screen|windows?)\b", t):
        return {"skill": "window", "action": "list", "target": ""}

    # ---------- VAULT SEARCH ----------
    # Placed AHEAD of FILES and RESEARCH deliberately. Both of those match a
    # bare verb plus anything ("find X", "search X"), so with this section in
    # its natural place further down, "search my notes for X" was being taken
    # by research/quick and "find my notes about X" by files/find. Naming the
    # vault is the more specific request and has to be tested first.
    m = re.match(r"^(?:search|find|look up|check|look in)\s+(?:in\s+)?(?:my\s+)?"
                 r"(?:notes?|vault)\s+(?:for\s+|about\s+|on\s+)?(.+)$", t)
    if m:
        return {"skill": "vault", "action": "search", "target": m.group(1).strip()}
    m = re.match(r"^what did i (?:write|note|save|record)\s+about\s+(.+)$", t)
    if m:
        return {"skill": "vault", "action": "search", "target": m.group(1).strip()}

    # ---------- FILES ----------
    m = re.match(r"^(?:find|locate|where is)\s+(?:my\s+)?(?:file\s+)?(.+)$", t)
    if m and not re.search(r"\b(out about|weather)\b", t):
        return {"skill": "files", "action": "find", "target": m.group(1).strip()}
    m = re.match(r"^open (?:my )?file\s+(.+)$", t)
    if m:
        return {"skill": "files", "action": "open", "target": m.group(1).strip()}

    # ---------- FILES CREATE -- "create a file called X", "make a text file X", "create X containing Y"
    # Requires "file" word to avoid capturing apps/open or document phrasings.
    m = re.match(r"^create\s+(?:a\s+)?file\s+(?:called|named)?\s+(.+)$", t)
    if m:
        target = re.sub(r"\b(please)\b", "", m.group(1)).strip()
        if target:
            return {"skill": "files", "action": "create", "target": target}
    m = re.match(r"^make\s+(?:a\s+)?(?:text\s+)?file\s+(.+)$", t)
    if m:
        target = re.sub(r"\b(please)\b", "", m.group(1)).strip()
        if target:
            return {"skill": "files", "action": "create", "target": target}
    m = re.match(r"^create\s+(.+?)\s+containing\s+(.+)$", t)
    if m:
        fname = re.sub(r"\b(please)\b", "", m.group(1)).strip()
        content = m.group(2).strip()
        if fname:
            # content is passed through router to the skill; target holds filename, reply holds content
            return {"skill": "files", "action": "create", "target": fname, "reply": content}

    # ---------- MEDIA ----------
    # "play music" matched nothing and fell through to the model, and "stop
    # the music" was claimed by pc/stop_speaking -- so ARGUS went quiet
    # instead of stopping playback. "play" and "stop" belong to the media
    # keys when a media noun is present.
    # CONTROLLING EXISTING PLAYBACK only -- never "start playing something".
    #
    # A first attempt matched "play" anywhere near a media noun, which took
    # two things it should not have: "i want to play music with my friends"
    # (a sentence, not a command) and "play some music" (a request for
    # content, which youtube/play actually satisfies). A media key on a
    # machine with nothing playing does nothing at all, while ARGUS says
    # "Toggled playback" -- a confident report of something that did not
    # happen. Choosing content belongs to YouTube; these keys only pause,
    # resume, stop and skip what is already going.
    if re.match(r"^(pause|resume|unpause|play)$", t) or \
       re.match(r"^(pause|resume|unpause|stop|halt)\s+(the\s+|this\s+)?"
                r"(music|video|song|playback|track|audio)$", t) or \
       re.match(r"^(pause|resume|play|unpause)\s+it$", t):
        target = "stop" if re.match(r"^(stop|halt)\b", t) else "play_pause"
        return {"skill": "pc", "action": "media", "target": target}
    if re.search(r"\b(previous|prev|last|back)\b.*\b(track|song|video|tune)\b", t) or \
       re.search(r"\bgo back a (track|song)\b", t):
        return {"skill": "pc", "action": "media", "target": "previous"}
    # The word-count guard alone was too blunt: it exists so a stray "next" in
    # ordinary conversation isn't treated as a media command, but it also threw
    # away obvious ones like "play the next song" (4 words). Naming a track
    # explicitly is unambiguous at any length, so that no longer needs to be
    # short -- only the bare, contextless form does.
    if re.search(r"\b(next|skip)\b.*\b(track|song|video|tune)\b", t) or \
       (re.search(r"\b(next|skip)\b", t) and len(t.split()) <= 3):
        return {"skill": "pc", "action": "media", "target": "next"}
    if re.search(r"\b(previous|last|go back)\b.*\b(track|song)\b", t) or \
       re.match(r"^(previous|back)$", t):
        return {"skill": "pc", "action": "media", "target": "previous"}

    # ---------- WEATHER ----------
    # The trigger list was all nouns, so the ways people usually ask -- by
    # describing the CONDITION rather than naming the topic -- missed entirely
    # and fell to the LLM router: "what's it like outside", "is it going to be
    # cold in london", "do i need a jacket".
    if (re.search(r"\b(weather|temperature|forecast|raining|snowing|how (hot|cold))\b", t) or
        re.search(r"\bwhat(?:'s| is) it like (?:outside|out there)\b", t) or
        re.search(r"\b(?:is|will) it (?:be |going to (?:be )?)?"
                  r"(cold|hot|warm|chilly|wet|rain|rainy|sunny|windy|freezing|snow)\b", t) or
        re.search(r"\bdo i need (?:a |an )?(jacket|coat|umbrella)\b", t)) \
            and not is_definition_question(t):
        # "what's the difference between weather and climate" and "explain how
        # weather forms" name the concept, not today's sky -- they belong to
        # the model, not the weather reading.
        m = re.search(r"\b(?:in|for|at)\s+([a-z\s]+?)(?:\s+(?:today|tomorrow|now|right now))?$", t)
        city = m.group(1).strip() if m else ""
        return {"skill": "weather", "action": "get", "target": city}

    # ---------- CLOSE APP ----------
    m = re.match(r"^(?:close|quit|kill|exit|shut down|terminate)\s+(?:the\s+)?(.+)$", t)
    if m:
        target = re.sub(r"\b(app|application|window|program)\b", "", m.group(1)).strip()
        if target and not _BARE_PRONOUN.match(target):
            return {"skill": "apps", "action": "close", "target": target}

    # ---------- DICTATION MODE ----------
    # Claimed ABOVE "open app", because "start dictating" otherwise reads as a
    # request to launch a program called "dictating" -- and above the one-shot
    # "type this ..." form further down, so it is a mode change rather than a
    # request to type the word.
    #
    # The phrases are deliberately explicit. Entering a mode where everything
    # you say becomes keystrokes in whatever window has focus should never be
    # something you trip over by accident.
    if re.match(r"^(?:start|begin|enter)\s+(?:dictating|dictation|"
                r"dictation mode|typing (?:what i say|for me))\b", t) \
            or re.match(r"^(?:take|start taking)\s+dictation\b", t) \
            or re.match(r"^dictation mode(?:\s+on)?$", t):
        return {"skill": "pc", "action": "dictate_on", "target": ""}
    if re.match(r"^(?:stop|end|finish|cancel|quit)\s+(?:the\s+)?"
                r"(?:dictating|dictation)\b", t) \
            or re.match(r"^dictation mode off$", t):
        return {"skill": "pc", "action": "dictate_off", "target": ""}

    # ---------- OPEN APP / SITE ----------
    # Requests where the verb comes AFTER the app, or is implied. "i need
    # notepad opened" and "get notepad open" both fell through to the model,
    # and the model answered "I'm unable to open applications directly" --
    # claiming ARGUS cannot do the one thing it certainly can. A refusal
    # invented by the model is worse than a miss, because it teaches the user
    # the feature does not exist.
    m = re.match(r"^(?:i need|i want|can you get|get|could you get)\s+"
                 r"(?:the\s+|my\s+)?(.+?)\s+"
                 r"(?:open|opened|going|started|launched|running|up)$", t)
    if m:
        target = re.sub(r"\b(app|application|program)\b", "", m.group(1)).strip()
        if target and not _BARE_PRONOUN.match(target):
            return {"skill": "apps", "action": "open", "target": target}

    m = re.match(r"^(?:open|launch|start|run|fire up|bring up|pull up|boot up|go to)\s+(?:the\s+|my\s+)?(.+)$", t)
    if m:
        target = re.sub(r"\b(app|application|program|website|site)\b", "", m.group(1)).strip()

        # "open X" is three different requests and only one of them was
        # reachable. Everything that was not a key of the hardcoded
        # WEB_TARGETS dict became an APP search -- so "open youtube.com" hunted
        # the Start Menu for a program called "youtube.com", and "open my cv"
        # hunted for an application called "cv". Both failed with "I couldn't
        # find an app called ...", which reads as ARGUS being broken rather
        # than as the request being misclassified.
        #
        # Decided by SHAPE rather than by an alias list, so a site nobody
        # thought to add still works:
        #   a domain or scheme      -> a web address
        #   a file extension, or the word "file"/"document" -> a file
        #   anything else           -> an application
        if target in WEB_TARGETS:
            return {"skill": "web", "action": "open_url", "target": WEB_TARGETS[target]}

        # The URL test runs against the RAW text, not the cleaned one.
        # _clean() strips punctuation, so by this point "youtube.com" is
        # "youtube com" and every dot-based check silently fails -- which is
        # why "open youtube.com" went looking for an installed application
        # called "youtube com".
        #
        # Speech has the same problem from the other direction: dictating a
        # web address produces "youtube dot com", with the dot as a WORD.
        # Both spellings are reassembled here.
        raw_target = re.sub(
            r"^(?:open|launch|start|run|fire up|bring up|pull up|boot up|go to)\s+"
            r"(?:the\s+|my\s+)?", "", raw.strip(), flags=re.I).strip()
        spoken = re.sub(r"\s+dot\s+", ".", raw_target, flags=re.I)
        spoken = re.sub(r"\s+slash\s+", "/", spoken, flags=re.I)
        # A FILE EXTENSION IS NOT A TOP-LEVEL DOMAIN. Without this exclusion
        # "open report.pdf" matched the domain shape and tried to browse to
        # http://report.pdf -- name.ext and name.tld are the same pattern, and
        # only the suffix tells them apart.
        _FILE_EXT = (r"\.(pdf|docx?|xlsx?|pptx?|txt|csv|md|rtf|odt|"
                     r"png|jpe?g|gif|bmp|svg|webp|heic|"
                     r"mp3|mp4|wav|mov|avi|mkv|flac|"
                     r"zip|rar|7z|tar|gz|iso|exe|msi|"
                     r"py|js|ts|json|xml|yaml|yml|log|ini|cfg)$")
        if not re.search(_FILE_EXT, spoken, re.I) and (
                re.match(r"^(https?://|www\.)", spoken, re.I) or
                re.match(r"^[a-z0-9][a-z0-9\-]*(\.[a-z0-9\-]+)*\.[a-z]{2,}(/\S*)?$",
                         spoken, re.I)):
            return {"skill": "web", "action": "open_url", "target": spoken}

        # A named file: "open report.pdf", "open the file called notes",
        # "open my cv", "open my resume".
        if re.search(r"\.[a-z0-9]{2,4}$", target) or \
           re.search(r"\b(file|document|folder|pdf|spreadsheet|photo|picture)\b",
                     m.group(1)) or \
           re.match(r"^(cv|resume|curriculum vitae)\b", target):
            cleaned = re.sub(r"^(?:file|document)\s+(?:called|named)\s+", "", target)
            cleaned = re.sub(r"\b(file|document)\b", "", cleaned).strip()
            if cleaned:
                return {"skill": "files", "action": "open", "target": cleaned}

        # START and RUN belong to two skills: "start spotify" launches an
        # app, "start wuauserv" starts a Windows service. When the verb list
        # below gained start/run it also began SHADOWING the SERVICE matcher
        # (which sits far down this function, behind every earlier section),
        # so "start wuauserv" hunted the Start Menu for an app called
        # wuauserv -- the service tests caught it. Disambiguated by REALITY
        # rather than by word lists: when the target names an actual
        # installed service (exact key, display name, or substring -- the
        # same _find() the service skill will run anyway), it goes to the
        # service skill; anything else keeps behaving as an app launch, so
        # "start spotify" still opens Spotify.
        if t.split(None, 1)[0].lower() in ("start", "run"):
            cand = re.sub(r"^(?:the|my)\s+", "", target).strip()
            if cand:
                try:
                    from skills import service_skill as _svcmod
                    _svc_hit = _svcmod._find(cand)
                except Exception:
                    _svc_hit = None
                if _svc_hit is not None:
                    return {"skill": "service", "action": "start", "target": cand}

        if target and not _BARE_PRONOUN.match(target):
            return {"skill": "apps", "action": "open", "target": target}
    # "play music" belongs HERE, not to the media key.
    #
    # It was excluded from YouTube on the assumption the media block would
    # take it. Once that block was narrowed to controlling existing playback
    # only, nothing claimed it and "play music" fell through to the model,
    # which cannot play anything. Asked to play music, the thing that actually
    # plays music should answer.
    m = re.match(r"^play\s+(.+?)(?:\s+on\s+youtube)?$", t)
    if m and m.group(1):
        return {"skill": "youtube", "action": "play", "target": m.group(1).strip()}
    m = re.match(r"^youtube\s+(.+)$", t)
    if m:
        return {"skill": "youtube", "action": "play", "target": m.group(1).strip()}

    # ---------- PROFILE (checked before research: "what do you know about me"
    # must not be treated as a research topic) ----------
    # BUGFIX, found in the real audit log, not guessed: Whisper transcribed
    # "who am i" as one run-together word, "who ami". That missed \bwho am
    # i\b entirely, fell through to the LLM router, which misclassified it
    # as profile/remember -- and WORSE, committed the literal string "WHO
    # AMI" to the profile as a stored fact, which then got read back as
    # real personal information on every later "who am i". \bwho\s*am\s*i\b
    # (optional space) catches the merge without needing to guess every
    # other way two words might run together.
    if re.search(r"\b(what do you know about me|who\s*am\s*i|what have you learned about me|my profile|what do you remember about me)\b", t):
        return {"skill": "profile", "action": "summary", "target": ""}

    # ---------- RESEARCH ----------
    # "deep" is a multi-page web crawl and costs about NINE SECONDS. It is
    # reserved for phrasings that actually ask for research.
    #
    # "tell me about X" and "what do you know about X" used to land here, and
    # they are the two most natural ways to ask an ordinary question. "tell me
    # about quantum computing" took 9.3s of web crawling to produce an answer
    # Groq returns in 174ms. They now fall through to the normal chat cascade
    # (cloud -> local -> wikipedia -> web), which escalates to a search only
    # if the cheaper steps come back unsure -- so the slow path is still
    # reachable when it is genuinely needed, just not paid for up front.
    m = re.match(r"^(?:research|look into|dig into|find out about|"
                 r"do some research on|deep dive on)\s+(.+)$", t)
    if m:
        return {"skill": "research", "action": "deep", "target": m.group(1).strip()}
    # "look up X" goes to knowledge (Wikipedia), "search for X" / "google X"
    # to the web. Both used to land on research/quick, which left
    # knowledge/lookup declared but unreachable -- dead code wearing the name
    # of a feature. The split matches what the words mean: looking something
    # up is a reference lookup, searching is a web search.
    m = re.match(r"^(?:look up|lookup)\s+(.+)$", t)
    if m:
        return {"skill": "knowledge", "action": "lookup", "target": m.group(1).strip()}
    m = re.match(r"^(?:search for|search|google)\s+(.+)$", t)
    if m:
        return {"skill": "research", "action": "quick", "target": m.group(1).strip()}

    # ---------- PROFILE (writes) ----------
    # BUGFIX: this used to consume the pronoun and unconditionally prepend
    # "I ", which mangled every form except a bare "i":
    #
    #   "remember that im a student"              -> "I a student"
    #   "remember that my favourite colour is blue" -> "I favourite colour is blue"
    #
    # Those strings are then written into profile.md permanently AND injected
    # into every conversational prompt by profile_context(), so ARGUS was
    # being told the user's own facts in broken English. The pronoun is
    # captured and mapped instead of discarded.
    m = re.match(r"^(?:remember|note) (?:that )?(i'm|im|i|my)\b\s*(.*)$", t)
    if m:
        pronoun, rest = m.group(1), m.group(2).strip()
        lead = {"i": "I", "im": "I am", "i'm": "I am", "my": "My"}[pronoun]
        fact = f"{lead} {rest}".strip()
        section = "Work" if re.search(r"\b(work|job|career|company|role|study|degree|analyst|engineer)\b", fact) else "About"
        return {"skill": "profile", "action": "remember", "target": fact, "reply": section}
    m = re.match(r"^forget (?:about |that )?(.+)$", t)
    if m:
        return {"skill": "profile", "action": "forget", "target": m.group(1).strip()}

    # ---------- VAULT ----------
    m = _VAULT_WRITE.match(t)
    if m:
        content = m.group(1).strip()
        return {"skill": "vault", "action": "write", "target": " ".join(content.split()[:6]), "reply": content}
    if re.search(r"\b(read my notes|recent notes|my vault|what did i save)\b", t):
        return {"skill": "vault", "action": "read", "target": ""}

    # ══════════════════════════════════════════════════════════════════
    # LIVE READINGS FROM THIS MACHINE
    #
    # Storage, battery and system stats all answer with a number measured
    # here and now. NONE of them may fire unless the sentence actually asks
    # for a reading. That one gate -- see wants_live_reading() -- is what
    # stops "explain how a cpu works" being answered with a CPU percentage,
    # and it works by the SHAPE of the question rather than by listing the
    # phrasings someone happened to catch failing.
    #
    # Anything that is not a reading request falls through to the language
    # model, which is where a question about the world belongs.
    if wants_live_reading(t):

        # "what are the biggest files in my documents" names no disk word at
        # all, so the storage branch below cannot see it. It is unambiguously
        # a storage question and belongs here rather than with the model.
        if re.search(r"\b(biggest|largest)\b.{0,20}\b(files?|folders?|items?|things?)\b", t) \
                and not re.search(r"\b(cpu|ram|memory|battery)\b", t):
            where = re.search(r"\b(?:in|inside|under|within)\s+(?:my\s+|the\s+)?"
                              r"([\w .:\\/-]+?)"
                              r"(?:\s+folder|\s+directory|\s+drive)?\s*$", t)
            return {"skill": "storage", "action": "largest",
                    "target": where.group(1).strip() if where else ""}

        # ---------- STORAGE ----------
        if re.search(r"\b(disk|drive|storage|space)\b", t) and \
           not re.search(r"\b(cpu|ram|memory|battery)\b", t):
            # "what's taking up space" is a different question from "how much
            # is left", and answering it with a number is not answering it.

            # storage/analyze — "analyze <folder>", "break down <folder>", "what's filling <folder>"
            # Checked BEFORE largest so analyze phrases don't fall into largest.
            if re.search(r"\b(analyze|break down|what'?s filling|what is filling)\b", t):
                where = re.search(r"\b(?:in|inside|under|within|of)\s+(?:my\s+|the\s+)?"
                                  r"([\w .:\\/-]+?)"
                                  r"(?:\s+folder|\s+directory|\s+drive)?\s*$", t)
                return {"skill": "storage", "action": "analyze",
                        "target": where.group(1).strip() if where else ""}

            if re.search(r"\b(taking up|using|hogging|biggest|largest|what'?s in)\b", t):
                # "in my downloads folder" -> "downloads". An empty target
                # means the home directory, the sensible default for "what's
                # taking up my space" with no folder named.
                where = re.search(r"\b(?:in|inside|under|within)\s+(?:my\s+|the\s+)?"
                                  r"([\w .:\\/-]+?)"
                                  r"(?:\s+folder|\s+directory|\s+drive)?\s*$", t)
                return {"skill": "storage", "action": "largest",
                        "target": where.group(1).strip() if where else ""}
            return {"skill": "storage", "action": "free", "target": t}

        # ---------- BATTERY ----------
        # Split out of the stats dump: "how long have I got" was answered
        # with a sentence about CPU and memory that happened to contain a
        # percentage.
        if re.search(r"\b(battery|charge|charging|plugged in|on mains|power left)\b", t):
            return {"skill": "pc", "action": "battery", "target": ""}

        # ---------- SYSTEM STATS ----------
        # Still inside wants_live_reading(). The bare noun "cpu" used to be
        # enough on its own, which is precisely how "What can you do over my
        # PC?" and "explain how a cpu works" were both answered with a
        # percentage.
        if re.search(r"\b(system status|how(?:'s| is) my (pc|computer|laptop|system)|"
                     r"cpu|processor|ram|memory)\b", t):
            return {"skill": "pc", "action": "stats", "target": ""}
    # "how long has this pc been up" hit none of these and fell through to the
    # model, which returned an encyclopaedia entry about handheld computers.
    if re.search(r"\b(uptime|how long.*\b(been on|been up|running|up for)\b)", t):
        return {"skill": "pc", "action": "uptime", "target": ""}
    # "what apps are running" -- the single most natural phrasing -- was not in
    # this list, which had "what's running" and "which apps are open" but not
    # the combination of the two.
    # "which process(es) are going on my pc right now" is from the real log.
    # It matched nothing, fell through to the model, and got a paragraph
    # explaining what Task Manager is -- instead of the list of processes the
    # machine could simply have reported. Any "what/which ... running/open/
    # going on" phrased at apps, programs or processes lands here now.
    if re.search(r"\b(what(?:'s| is) running|which apps are open|running apps|"
                 r"what apps are (?:running|open)|list (?:my )?apps|"
                 r"show me (?:my )?(?:running |open )?apps)\b", t) or \
       (re.search(r"\b(process(es)?|app|apps|application|applications|"
                  r"program|programs)\b", t)
            and re.search(r"\b(running|open|going on|active|use|using)\b", t)
            and re.search(r"^(what|which|show|list|tell)\b", t)):
        return {"skill": "apps", "action": "list", "target": ""}
    # window/list is dispatchable in router.py but nothing ever produced it,
    # so "what windows are open" could only reach it via the LLM router.
    if re.search(r"\b(what windows are open|which windows are open|"
                 r"list (?:my )?windows|show me (?:my )?windows|"
                 r"what(?:'s| is) open)\b", t):
        return {"skill": "window", "action": "list", "target": ""}

    # ---------- SCREENSHOT / LOCK / TIME ----------
    if re.search(r"\b(screenshot|screen shot|capture (my |the )?screen)\b", t):
        return {"skill": "pc", "action": "snapshot", "target": ""}
    if re.match(r"^lock( (the |my )?(screen|pc|computer|laptop|it))?$", t):
        return {"skill": "pc", "action": "lock", "target": ""}
    # "the time"/"the date" in a short utterance is a clock question however
    # it's phrased ("do you know the time", "got the time"). Excluding the
    # timer/alarm vocabulary keeps it from stealing "set a timer", and the
    # length cap keeps it out of longer sentences that merely mention time.
    # Note "it is time to go" doesn't match: that's "is time", not "the time".
    if re.match(r"^what(?:'s| is)? the (time|date)|what time is it|what day is it", t) or \
       (re.search(r"\b(the time|the date)\b", t) and len(t.split()) <= 6
            and not re.search(r"\b(timer|remind|alarm|set|in \d)\b", t)):
        return {"skill": "pc", "action": "time", "target": ""}

    # ---------- LAST TASK ----------
    # Past tense, about something ALREADY finished -- a different shape from
    # "go ahead"/"yes" confirming something CURRENTLY staged (those are
    # closed-set, exact-match confirmations resolved long before this point
    # -- see _plan_paused). Bare "what did you do" is claimed above by AUDIT
    # (~line 671, the activity/security log) and is deliberately left alone;
    # this only catches the conversational shapes that ask what ARGUS itself
    # just finished. agent.working_memory.recent_tasks() is the source --
    # see pc_skill.last_task().
    if re.match(r"^(?:what did you just do|what were you doing|"
                r"did (?:it|that) work|what did you do last)\??$", t):
        return {"skill": "pc", "action": "last_task", "target": ""}

    # ---------- DICTATION ----------
    # Inserting literal text, NOT composing content. This used to claim every
    # sentence beginning with type/write/dictate, so "write me a haiku about
    # firewalls", "write a poem" and "write me a script" all became dictation
    # commands -- refused outright while ARGUS was locked, and wrong even when
    # unlocked, since they would have started typing into whatever window had
    # focus. Every creative request in the language was captured by one verb.
    #
    # The discriminator is SHAPE, not a list of content nouns (there is no end
    # to those). Dictation takes literal text to insert -- "type hello world",
    # "write this down", "dictate this: ..." -- while a request to PRODUCE
    # something reaches for an article: "write me A haiku", "write A poem",
    # "write me AN email". An article after the verb means composition, and
    # composition belongs to the model.
    _composing = re.match(r"^(?:type|write|dictate)\s+(?:me\s+|us\s+|him\s+|"
                          r"her\s+|them\s+)?(?:an?|some|another)\b", t)
    _literal = re.match(r"^(?:write|type)\s+(?:this|that|it)\b", t) \
        or re.match(r"^dictate\b", t)
    m = re.match(r"^(?:type|write|dictate)\s+(?:this\s+)?(?::\s*)?(.+)$", t)
    if m and (_literal or not _composing):
        return {"skill": "pc", "action": "dictate", "target": m.group(1).strip()}

    # ---------- VOLUME / BRIGHTNESS ----------
    m = re.search(r"\bvolume\s+(?:to\s+)?(\d+)", t)
    if m:
        return {"skill": "control", "action": "volume_set", "target": m.group(1)}
    # "turn it up/down" carry no sound noun at all -- they rely on context, so
    # they stay as explicit phrasings alongside the structural rule below.
    if re.search(r"\b(turn it up|louder)\b", t) or \
       (re.search(_SOUND_NOUN, t) and re.search(_LOUDER, t)):
        return {"skill": "control", "action": "volume_up", "target": ""}
    if re.search(r"\b(turn it down|quieter)\b", t) or \
       (re.search(_SOUND_NOUN, t) and re.search(_QUIETER, t)):
        return {"skill": "control", "action": "volume_down", "target": ""}
    if re.match(r"^(mute|mute (the )?(sound|audio|volume|speakers?))$", t):
        return {"skill": "control", "action": "mute", "target": ""}
    # "unmute" alone was the only accepted form, so the natural "unmute the
    # volume" and "turn the sound back on" matched nothing at all.
    if re.match(r"^(unmute|unmute (the )?(sound|audio|volume|speakers?)|"
                r"turn (the )?(sound|audio|volume) back on|"
                r"sound back on|un ?mute)$", t):
        return {"skill": "control", "action": "unmute", "target": ""}
    m = re.search(r"\bbrightness\s+(?:to\s+)?(\d+)", t)
    if m:
        return {"skill": "control", "action": "brightness_set", "target": m.group(1)}

    # ---------- CLIPBOARD ----------
    if re.search(r"\b(read|what.s in|check)\b.*\bclipboard\b", t):
        return {"skill": "control", "action": "clipboard_read", "target": ""}

    # ---------- TIMER ----------
    # Listing and cancelling are checked before the "set a timer" parse below,
    # which would otherwise look for a duration in them and find none.
    if re.search(r"\b(what|any|list|show)\b.*\b(timers?|reminders?)\b", t) or \
       re.match(r"^(?:my )?(?:timers?|reminders?)$", t):
        return {"skill": "timer", "action": "list", "target": ""}
    m = re.match(r"^cancel (?:my |the |all )?(?:timers?|reminders?)(?:\s+(?:about|for)\s+(.+))?$", t)
    if m:
        return {"skill": "timer", "action": "cancel", "target": (m.group(1) or "").strip()}
    if re.search(r"\b(timer|remind me|reminder|wake me|alarm)\b", t):
        # BUGFIX: the fraction word used to be dropped entirely. NUMBER_WORDS
        # maps "a" and "an" to 1, so "half an hour" matched ("an", "hour") and
        # set a SIXTY minute timer -- double what was asked for, silently, with
        # a confirmation that said "an hour" so the mistake was invisible until
        # it fired. Same for "quarter of an hour" (60 min instead of 15) and
        # "half a minute" (60s instead of 30).
        m = re.search(r"(?:(half|quarter)\s+(?:of\s+)?)?"
                      r"(\d+|[a-z]+)\s*"
                      r"(second|sec|minute|min|hour|hr)s?\b", t)
        if m:
            n = _num(m.group(2))
            if n and n > 0:
                secs = int(round(n * _FRACTION_WORDS.get(m.group(1) or "", 1.0)
                                 * UNIT_SECONDS[m.group(3)]))
                if secs > 0:
                    label_m = re.search(r"\bto\s+(.+)$", t)
                    return {
                        "skill": "timer",
                        "action": "set",
                        "target": str(secs),
                        "reply": label_m.group(1).strip() if label_m else "Timer done.",
                    }

    # ---------- CONTEXT (current scene) ----------
    # "what am I looking at" used to be vision/describe -- a MODEL staring at
    # pixels, slow and non-local. The live scene (focused window, open file,
    # active tab) is local, L1, and answers the question the user actually
    # meant. The heavy screen questions ("my screen", "on screen", "read my
    # screen") stay on vision below. THIS IS A DELIBERATE BASELINE MOVE --
    # review this routing change before release.
    if re.search(r"\bwhat am i looking at\b", t):
        return {"skill": "context", "action": "current", "target": ""}
    if re.search(r"\bwhat(?:'s| is)\s+(?:in\s+)?front of me\b", t):
        return {"skill": "context", "action": "current", "target": ""}
    if re.search(r"\b(?:what(?:'s| is) selected|what do i have selected"
                 r"|what did i (?:just )?select)\b", t):
        return {"skill": "context", "action": "selection", "target": ""}
    if re.search(r"\b(?:my current file|what file am i (?:working on|using)"
                 r"|what file do i have open|what(?:'s| is) my current file"
                 r"|what did you (?:just )?find|what files did you find)\b", t):
        return {"skill": "context", "action": "file", "target": ""}

    # ---------- HEALTH (rolling picture) ----------
    # Not diag/full (deep diagnostics) and not anomaly/check (process
    # anomalies): this reports how the machine has BEEN, with sustained-
    # failure detection instead of a point-in-time scan.
    if re.search(r"\b(?:is everything|is my (?:pc|machine|system|computer))\s+"
                 r"healthy\b|\bhealth report\b", t):
        return {"skill": "health", "action": "report", "target": ""}
    if re.search(r"\bhow(?:'s| has| is) my (?:machine|pc|system|computer) been\b"
                 r"|\bhow(?:'s| is) (?:the|my) (?:pc|machine|system|computer) "
                 r"doing\b|\bhow have (?:my )?(?:resources?) been\b", t):
        return {"skill": "health", "action": "check", "target": ""}

    # ---------- MONITOR (watch-until) ----------
    # "tell me when X" / "let me know when X" / "watch until X" -- a one-shot
    # watch on an ALLOWLISTED condition. monitor_skill re-parses the target
    # and REFUSES anything outside its own allowlist, so a pattern that
    # misfires here cannot make it watch something it may not. The watch
    # trigger is required: "battery is above 80" is a statement, not a
    # request to watch. Anything unmatched falls through to the LLM router,
    # which knows "monitor" and its target syntax from the ROUTING_PROMPT.
    if re.search(r"\b(?:tell me when|let me know when|notify me when|"
                 r"ping me when|watch\b.*\buntil|watch for|watch that)\b", t):
        m = re.search(r"\bbattery\b.*\b(?:above|over|reaches?|hits?)\s*(\d{1,3})", t)
        if m:
            return {"skill": "monitor", "action": "set",
                    "target": f"battery_above {m.group(1)}"}
        m = re.search(r"\bbattery\b.*\b(?:below|under|drops? (?:to|below|under)|"
                      r"falls? (?:to|below|under))\s*(\d{1,3})", t)
        if m:
            return {"skill": "monitor", "action": "set",
                    "target": f"battery_below {m.group(1)}"}
        m = re.search(r"\bcpu\b.*\b(?:above|over)\s*(\d{1,3})", t)
        if m:
            return {"skill": "monitor", "action": "set",
                    "target": f"cpu_above {m.group(1)}"}
        # "when the cpu settles" has no number -- 50 is the quiet line,

        m = re.search(r"\bcpu\b.*\b(?:below|settles?|comes? down|drops?)\s*"
                      r"(\d{1,3})?", t)
        if m:
            return {"skill": "monitor", "action": "set",
                    "target": f"cpu_below {m.group(1) or 50}"}
        if re.search(r"\b(?:internet|connection|wifi|network|online)\b.*"
                     r"\b(?:back|online|connected|returns?|restored)\b", t):
            return {"skill": "monitor", "action": "set",
                    "target": "net_online"}
        # "watch downloads until a file arrives" / "a file shows up in
        # downloads" -- either word order, folder confined via _watch_folder.
        m = (re.search(r"\b(?:a file|files)\b.*\b(?:arrives?|shows? up|appears?|"
                       r"lands?|arrive)\b.*\b(downloads?|desktop|documents?|"
                       r"pictures?|videos?)\b", t)
             or re.search(r"\b(downloads?|desktop|documents?|pictures?|videos?)\b"
                          r".*\b(?:a file|files)\b.*\b(?:arrives?|shows? up|"
                          r"appears?|lands?|arrive)\b", t))
        if m:
            return {"skill": "monitor", "action": "set",
                    "target": f"folder_has {_watch_folder(m.group(1))}, 1"}

    # ---------- SECURITY LOG (read-only event log) ----------
    # The security log records logon history, so its phrasing is deliberately
    # tied to that: "security log", "login history", "failed logins". A bare
    # "check the logs" stays conversational ("chat") rather than opening the
    # most private log on the machine.
    if re.search(r"\b(security log|event log|login history|logon history|"
                 r"failed log(?:in|on)s?(?: attempts?)?|audit log)\b", t):
        target = ""
        m = re.search(r"\b(security|application|system)\b", t)
        if m:
            target = m.group(1)
        m = re.search(r"\blast\s+(\d{1,2})\b|\b(\d{1,2})\s*(?:entries|events)\b", t)
        if m:
            target += f" {m.group(1) or m.group(2)}"
        return {"skill": "security_log", "action": "read", "target": target.strip()}

    # ---------- SERVICE (read + staged control) ----------
    # Reading is a report; start/stop/restart STAGE (the router then asks for
    # the PIN). The action forms are anchored on a SERVICE-y noun so an
    # ordinary "stop the song" (media, matched earlier) or "restart the
    # computer" (power, matched earlier) never lands here. Unknown targets
    # fail gracefully in service_skill._find() -- the reply says no matching
    # service rather than inventing one.
    if re.search(r"\b(list|show|get|what) (?:the |my )?(?:running |stopped |"
                 r"all )?(?:windows )?services?\b", t) or \
       re.search(r"\bwhich services?\b", t):
        m = re.search(r"\b(stopped|running|active|paused)\b", t)
        target = m.group(1) if m else ""
        return {"skill": "service", "action": "list", "target": target}
    # "start/stop/restart <name>", optionally with "service" between. The
    # name runs to the end of the sentence (politeness words are already
    # stripped by _clean), so "restart the print spooler" captures
    # "print spooler" and "stop spooler" captures "spooler".
    #
    # Guarded four ways: a leading article/quantifier or a name that belongs to
    # another domain (timer, music, app, recording, meeting...) falls through.
    # "start a new timer" and "stop the music" (already matched earlier by
    # TIMER/MEDIA when a noun forces it) must never land on service control.
    # The other two are about the SENTENCE rather than the name, because this
    # search finds the verb anywhere in it: an interrogative opener means the
    # verb is embedded in a question ("what happens if i stop the spooler",
    # "which apps start at boot"), and a name that ends in a boot locus is a time
    # phrase ("at boot", "with windows"), not something that can be a service.
    _NON_SERVICE = re.compile(r"\b(timer|reminder|alarm|music|song|video|"
                              r"playback|recording|conversation|meeting|"
                              r"session|download|upload|downloads?|word|"
                              r"process|node|worker|watcher)\b")
    m = re.search(r"\b(start|stop|restart)\s+(?:the )?(?:service )?"
                  r"([a-z0-9][a-z0-9 ._-]{0,39}?)\s*$", t)
    if m and not re.match(r"^(a|an|the|some|my|new|this|that|another|the )\b",
                          m.group(2).strip()) and \
            not _NON_SERVICE.search(m.group(2)) and \
            not _INFO_QUESTION.match(t) and \
            not _BOOT_LOCUS_END.search(m.group(2).strip()) and \
            len(m.group(2).split()) <= 3:
        svc = m.group(2).strip()
        if svc:
            return {"skill": "service", "action": m.group(1), "target": svc}
    # "is <name> running/stopped" -- includes the "print spooler" two-word
    # case. Only service-state words trigger it; "is wifi on" (net, checked
    # earlier), "is bluetooth on" (sysext) and "is the machine hot" (health)
    # are not here because "on/hot" are not in the state list.
    m = re.search(r"\bis (?:the )?(.+?)\s+(?:still )?(?:running|stopped|"
                  r"active|up|down)\s*\??\s*$", t)
    if m:
        cand = m.group(1).strip()
        # Machine/lead-in words describe the host, not a service -- "is the
        # system running" is a sysinfo question, "is the network up" belongs
        # to net/online (matched earlier anyway). Drop them here.
        if cand and not re.search(r"\b(it|this|that|there|everything|anything|"
                                  r"something|my|pc|computer|laptop|machine|"
                                  r"system|windows|network|server|host|"
                                  r"internet|wifi|bluetooth)\b", cand):
            return {"skill": "service", "action": "status", "target": cand}

    # ---------- ENV VAR (read + staged set) ----------
    # "read my environment variables" -- the user's own list, never a
    # broad "what is X" (that belongs to knowledge/cht).
    if re.search(r"\b(?:what are|list|show|tell me|check|display)\b.*\b(?:my |"
                 r"user )?environment (?:variables?|vars?)\b", t):
        return {"skill": "env_var", "action": "list", "target": ""}
    # "what is PATH": only binds a token that names a REAL variable -- %NAME%,
    # $NAME, or an all-caps token that exists in os.environ. The match runs on
    # raw (not the lowercased t) so the caps signal survives -- _clean()
    # destroys it. Membership is the gate: "what is the path" (a route) and
    # "what is NATO" (a name) fall through, because "path"/"NATO" are not in
    # os.environ. An exact-name probe on the user's own process environment is
    # safe here -- it is exactly what a newly launched program would see.
    m = re.search(r"\b(?:value|setting) of (?:the )?(%[A-Za-z0-9_]+%|"
                  r"\$[A-Za-z0-9_.]+|[A-Z][A-Z0-9_]{0,30})\b", raw) or \
        re.search(r"\bwhat(?:'s| is) (?:the )?(%[A-Za-z0-9_]+%|"
                  r"\$[A-Za-z0-9_.]+|[A-Z][A-Z0-9_]{0,30})\b", raw)
    if m:
        cand = m.group(1).strip("%$ ").upper()
        if cand in os.environ:
            return {"skill": "env_var", "action": "get", "target": cand}
    if re.search(r"\bset\s+[A-Za-z_][A-Za-z0-9_]{0,30}\s*(?:to|=)\s*", t):
        m = re.search(r"\bset\s+([A-Za-z_][A-Za-z0-9_]{0,30})\s*(?:to|=)\s*"
                      r"(.+?)\s*$", t)
        if m:
            name, value = m.group(1).upper(), m.group(2).strip()
            return {"skill": "env_var", "action": "set",
                    "target": f"{name}|{value}"}

    # ---------- VISION ----------
    if re.search(r"\b(my screen|on screen|read my screen)\b", t):
        return {"skill": "vision", "action": "describe", "target": raw}

    # ---------- MATH (last, so it doesn't shadow other patterns) ----------
    try:
        from skills import calc_skill
        if calc_skill.looks_like_math(t):
            return {"skill": "calc", "action": "calculate", "target": raw}
    except ImportError:
        pass

    return None
