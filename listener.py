"""
ARGUS - Voice listener.

WHY THIS REPLACES openWakeWord:
openWakeWord only ships a handful of pretrained wake models — "hey jarvis",
"alexa", "hey mycroft". There is no "argus" model, and training one takes hours.

So detection works differently here: voice activity detection notices when you
start speaking, captures until you stop, then runs a TINY Whisper model over the
segment purely to check whether your name appears in it. If it does, the same
audio is re-transcribed with the accurate model to get the command.

Consequences, both good:
  - Any name works. Change ASSISTANT_NAME in config and it just works.
  - "Argus open telegram" in one continuous breath works naturally, because the
    whole utterance was captured before we decided anything about it. The old
    design had to detect the wake word first and then start recording, which is
    what clipped the beginning of commands.

Cost: a tiny transcription runs whenever you speak near the machine. On GPU
that's roughly 50-150ms, and it only fires on actual speech, not silence.

STAGE 2 — WHAT RUNS WHERE:
This module is the VOICE PROCESS. It owns the microphone InputStream and, via
tts.py, the speaker OutputStream. It deliberately owns nothing else heavy:

  Whisper  -> stt_worker.py, its own process
  Piper    -> tts_worker.py, its own process
  Ollama   -> already a separate service
  HUD, orchestrator, router, skills -> the parent process

Per audio frame this process now does an RMS and one state-machine step. That
is the point: sounddevice's capture and playback callbacks are Python callbacks
that must take the GIL every buffer period, and they used to compete with model
inference, regex cascades and a psutil walk in the same interpreter. See ipc.py.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import collections
import difflib
import os
import queue
import re
import threading
import time

import numpy as np
import requests
import sounddevice as sd

import ipc
import security
import stt_worker
import textmatch
import tts
from config import (
    ASSISTANT_NAME, WAKE_WORDS, WAKE_FUZZ, VAULT_PATH, USER_NAME, USER_FULL_NAME,
    PIPER_MODEL_PATH, WHISPER_MODEL, WAKE_MODEL, FORCE_CPU_STT,
)

ORCHESTRATOR = "http://127.0.0.1:8420"
COMMAND_STREAM_URL = f"{ORCHESTRATOR}/command-stream"
STATE_URL = f"{ORCHESTRATOR}/voice-state"

SAMPLE_RATE = 16000
CHUNK = 1600                  # 100ms frames

# Voice activity detection
# Raised from 450. Every captured segment costs a Whisper pass, so a low
# threshold meant background noise ran transcription continuously — which is
# where a lot of the lag came from.
VAD_START_RMS = 620
VAD_STOP_RMS = 340
SILENCE_HOLD = 0.85           # silence needed to end a segment
PREROLL_FRAMES = 6            # ~0.6s kept before speech starts
MIN_SEGMENT_SEC = 0.55        # shorter bursts are almost never a command
MAX_SEGMENT_SEC = 12.0

# During this window ANY speech is treated as a command without needing the
# name again.
#
# Raised 4.5 -> 10.0 deliberately, and the trade-off is worth stating. It was
# shortened because a long window meant talking to someone ELSE in the room got
# executed. But 4.5s is shorter than a person's thinking pause: ask something,
# hear the answer, pause to consider, and the window has already closed -- so
# the next question needs the name again, and if Whisper drops it (see the
# WAKE_PROMPT note about long single-breath phrasing) the user is simply
# ignored. Being ignored is the failure that gets reported over and over; an
# occasional stray execution is one the user notices immediately and can undo.
# Every irreversible action is separately gated behind auth and confirmation,
# so a misheard sentence in this window cannot do anything serious on its own.
FOLLOWUP_WINDOW = 10.0
# ── continuous conversation ──────────────────────────────────────────────────
#
# A flat 10s after every reply meant a real back-and-forth needed the wake word
# again roughly every other turn: you answer, ARGUS answers, you think for
# twelve seconds, and it has stopped listening.
#
# Simply making the window long is the wrong fix. An always-open microphone
# treats a television, a phone call or somebody else in the room as commands,
# and that failure is much worse than saying the name again -- it is ARGUS
# acting on words nobody addressed to it.
#
# So the window EARNS its length. The first one after a reply stays short. Once
# you have actually spoken into one -- proving a conversation is happening and
# not just a room with noise in it -- the window widens, and keeps widening
# while the exchange continues. A hard ceiling ends it regardless, so a stuck
# window cannot listen indefinitely.
FOLLOWUP_ACTIVE_WINDOW = 30.0    # once the conversation is demonstrably live
CONVERSATION_MAX_S = 240.0       # total continuous span before the name is needed again
# Said at the end of a turn, these mean "we're done" -- honouring them closes
# the window immediately rather than leaving the mic open for the full window
# after the user has clearly finished.
# The apostrophe is optional AND may be curly: Whisper transcribes "that's"
# with U+2019 as often as with an ASCII quote, and a pattern that only
# accepts one of them silently fails on half the real transcripts.
CONVERSATION_ENDERS = re.compile(
    r"^(?:thanks?|thank you|that(?:['’]?s)? all|that will be all|"
    r"nothing|no thanks?|never ?mind|forget it|ok(?:ay)?|cool|great|"
    r"perfect|bye|goodbye|goodnight|good night|done|stop)\b[\s!.,]*$", re.I)

_conv = {"turns": 0, "started": 0.0, "ended": False}

# After ARGUS finishes speaking, ignore the microphone briefly. Speaker output
# bleeding back into the mic was being transcribed as a new command.
TTS_COOLDOWN = 0.9
COMMAND_TIMEOUT = 60
WATCHDOG_LIMIT = 90
MIN_CONFIDENCE = 0.40

# Cold start for the STT worker: a process spawn plus loading tiny.en AND
# small.en, with a CUDA probe in front of each. Slow machines and cold model
# caches both land well inside this; it is paid once.
STT_START_TIMEOUT = 300.0

# Ceiling on unplayed audio held in tts's ring buffer. Synthesis runs ahead of
# playback on purpose (that's the whole point of the pipeline), but letting it
# run arbitrarily far ahead means a barge-in has seconds of already-committed
# speech to cut through before anything changes audibly.
MAX_QUEUED_AUDIO_SEC = 6.0

WHISPER_PROMPT = (
    f"{ASSISTANT_NAME}, open, close, launch, quit, play, pause, stop, search, "
    "research, find, switch to, minimize, volume, brightness, timer, remind, "
    "weather, screenshot, diagnose, system status, remember, notes. "
    "Telegram, Chrome, Spotify, Discord, VS Code, Obsidian, Explorer, Steam. "
    # Prime the recognizer with a locally configured name when present.
    f"{USER_FULL_NAME}." if USER_FULL_NAME else ""
)

# Bias for the WAKE pass, which previously had none at all -- which is why
# tiny.en kept returning "August", "Argyz", "Argaz" for a clearly spoken
# "Argus" and the wake check never even got a chance.
#
# The EXACT WORDING MATTERS, and not in the obvious way. Whisper treats
# initial_prompt as text ALREADY SPOKEN, so a prompt shaped like a sentence
# prefix makes the model continue from it and omit the name from its output --
# the opposite of what is wanted. Measured on synthesized clips, wake-check
# pass rate over five phrases:
#
#   "Argus. Hey Argus. OK Argus. Argus, "   2/5   <- the obvious first attempt
#   "Argus"                                 2/5
#   (no prompt, the old behaviour)          3/5
#   "Argus."                                3/5
#   "The assistant is called Argus."        4/5   <- this
#
# with zero false wakes on ordinary speech in every case. A DECLARATIVE
# sentence supplies the vocabulary without reading as an unfinished utterance,
# so the name still appears in the transcript. Bare "Argus." went from
# "August." (ignored outright) to "Argus." at confidence 1.00.
#
# Known remaining gap: on a long single-breath "Argus, <long question>" the
# name can still be dropped. Say the name alone and use the follow-up window
# for those -- which now actually works, see seg_followup in _run_loop.
WAKE_PROMPT = f"The assistant is called {ASSISTANT_NAME.title()}."

audio_q: "queue.Queue[np.ndarray]" = queue.Queue(maxsize=300)
busy = threading.Event()

# The speech-recognition worker process (stt_worker.py). Started by main().
_stt = None

# Per-call ceilings. The wake pass is tiny.en over at most ~1.5s of audio and
# the command pass is small.en over at most MAX_SEGMENT_SEC, so these are
# "the worker is wedged" thresholds, not "the model is slow" ones.
WAKE_TIMEOUT = 20.0
COMMAND_TRANSCRIBE_TIMEOUT = 45.0

# Persistent, reviewable diagnostics for the "same spoken word transcribes
# differently every time" report -- console prints (see _transcribe below)
# are easy to miss or lose, especially for something that needs comparing
# across several attempts after the fact rather than watched live. Every
# transcription pass (wake AND command -- the report named both) appends
# clip duration, confidence, and the raw text, so the actual numbers exist
# to look at instead of guessing at them. Plain append, same shape as
# security.audit() -- no rotation, deliberately simple.
WAKE_DEBUG_LOG = os.path.join(VAULT_PATH, "wake_debug.log")

# Off by default now. This fires on EVERY transcription -- the wake pass, the
# command pass, and every barge-in poll -- and each call opens, appends to and
# closes a file synchronously on the STT path. Combined with "no rotation,
# deliberately simple", that was unbounded disk growth plus real I/O in the
# one path that needs to stay fast. Flip this on when actually investigating a
# transcription-quality report, then flip it back.
WAKE_DEBUG = False
WAKE_DEBUG_MAX_BYTES = 2 * 1024 * 1024   # one generation kept, then rolled


def _log_wake_debug(tag: str, duration_s: float, confidence: float, text: str):
    """Wake-word diagnostics WITHOUT the transcript.

    This used to write the recognised text verbatim, and the log on this
    machine held lines like "All of which process are going on in my little
    bit." -- ambient conversation, picked up near the wake word, transcribed
    and stored in plaintext. That is a voice transcript on disk, which is
    exactly what "never log private messages or raw authentication material"
    rules out; someone saying a password near the microphone would have had it
    written to the same file.

    The transcript was only ever here to answer "did it hear the wake word or
    something else". Length, word count and whether the wake word matched
    answer that question, and none of them reconstruct what was said. A
    truncated SHA-256 is included so two identical mishearings can still be
    correlated across lines without the text existing anywhere.
    """
    if not WAKE_DEBUG:
        return
    try:
        import hashlib

        spoken = str(text or "")
        digest = hashlib.sha256(spoken.lower().encode("utf-8")).hexdigest()[:8]
        woke = ASSISTANT_NAME.lower() in spoken.lower()
        os.makedirs(VAULT_PATH, exist_ok=True)
        if (os.path.exists(WAKE_DEBUG_LOG)
                and os.path.getsize(WAKE_DEBUG_LOG) > WAKE_DEBUG_MAX_BYTES):
            os.replace(WAKE_DEBUG_LOG, WAKE_DEBUG_LOG + ".1")
        with open(WAKE_DEBUG_LOG, "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')}  {tag:5}  "
                    f"dur={duration_s:5.2f}s  conf={confidence:.2f}  "
                    f"words={len(spoken.split()):2d}  chars={len(spoken):3d}  "
                    f"wake={'y' if woke else 'n'}  h={digest}\n")
    except OSError:
        pass  # diagnostics must never be able to break the listener


# CTranslate2 model instances aren't documented as safe for concurrent
# .transcribe() calls from multiple threads. Nothing previously stopped two
# speech segments detected back-to-back (e.g. noise right after real speech)
# from both transcribing on the same model at once -- a known cause of
# garbled/random output (literal token soup, not a plausible mishearing).
#
# That serialization is now structural rather than a lock: the models live in a
# single-threaded worker process (ipc.serve), which is the only thing that
# touches them, so concurrent .transcribe() calls are not merely avoided by
# convention -- they cannot be expressed. _MODEL_LOCK is gone with the models.

# Set once models AND speech synthesis are fully loaded. argus.py waits on this
# instead of guessing with sleep() — model load time varies hugely by machine
# and by whether the model is cached, so a fixed delay is always wrong somewhere.
READY = threading.Event()
resume = {"pending": False, "at": 0.0}
busy_since = {"t": 0.0}

_WAKE_SET = [w.lower() for w in WAKE_WORDS]
_MAX_WAKE_WORDS = max(len(w.split()) for w in _WAKE_SET)

# ─── Barge-in ──────────────────────────────────────────────────────────
# Previously only intent.py's exact STOP pattern could interrupt -- and even
# that never actually ran during playback, because the main loop skips audio
# processing entirely while busy.is_set() (true for the whole orchestrator
# call + TTS playback). So voice barge-in didn't work AT ALL before this,
# not just "too narrow a phrase list" -- "stop" said while ARGUS was talking
# was simply never captured.
#
# Fix is two parts: (1) the main loop now runs a lightweight check during
# active speech instead of a blanket skip, and (2) that check is fuzzy, the
# same difflib-based matching already used for the wake word (see
# find_wake()), against a much broader phrase list -- catching "hold on",
# "that's enough", "shut up" etc., not just an exact "stop".
#
# Deliberately NOT a live LLM intent classifier: that would mean running
# real inference on the same 4GB card while it's already doing TTS playback
# and possibly an orchestrator LLM call, with a real risk of stuttering
# audio or slowing everything down. This stays on the cheap tiny wake_model
# (same one used continuously for wake detection) and plain fuzzy string
# matching -- fast, bounded, and already proven not to strain this hardware.
INTERRUPT_PHRASES = [
    "stop", "wait", "hold on", "hold up", "that's enough", "thats enough",
    "quiet", "shut up", "cancel", "never mind", "nevermind", "okay stop",
    "ok stop", "enough", "silence", "stop talking", "shush", "hush", "pause",
    "stop it", "be quiet", "halt", "abort",
]
_INTERRUPT_SET = [p.lower() for p in INTERRUPT_PHRASES]
_MAX_INTERRUPT_WORDS = max(len(p.split()) for p in _INTERRUPT_SET)
INTERRUPT_FUZZ = 0.72  # looser than WAKE_FUZZ -- these are short, common
                       # words, and a missed interrupt is more annoying than
                       # an extra false positive while ARGUS is mid-sentence.
# Only worth checking audio this loud -- ambient noise during playback
# (speakers bleeding into the mic, background sound) shouldn't burn a
# transcription pass. Reuses the wake VAD's own onset threshold.
INTERRUPT_CHECK_COOLDOWN = 0.7  # min seconds between interrupt-check passes


def _sounds_like_interrupt(text: str) -> bool:
    """BUGFIX: fuzzy-matching single short words against the interrupt list
    turned out unsafe -- "what" vs "wait" and "stap" vs "stop" score the
    *identical* 0.750 similarity ratio, so no cutoff value can accept one
    mishearing without also accepting the other, and "what's the weather"
    was getting cut off as a false interrupt. Multi-word phrases don't have
    this problem (coincidentally matching 2-3 whole words is much rarer),
    so fuzzy matching now only applies there; single words must match the
    interrupt list exactly. This trades away catching an odd mistranscription
    of "stop" itself, which is a common enough word that Whisper rarely
    mangles it, against not cutting off unrelated sentences that start with
    "what"/"when"/"wait"-adjacent words -- the worse failure mode by far.
    """
    words = re.sub(r"[^\w\s]", " ", text.lower()).split()
    if not words:
        return False
    horizon = min(len(words), _MAX_INTERRUPT_WORDS + 2)
    for span in range(min(_MAX_INTERRUPT_WORDS, horizon), 0, -1):
        for start in range(0, horizon - span + 1):
            phrase = " ".join(words[start:start + span])
            if phrase in _INTERRUPT_SET:
                return True
            if span >= 2 and len(phrase) >= 3:
                if difflib.get_close_matches(phrase, _INTERRUPT_SET, n=1, cutoff=INTERRUPT_FUZZ):
                    return True
    return False


def audio_callback(indata, frames, time_info, status):
    if status:
        print(f"[audio] {status}")
    try:
        audio_q.put_nowait(indata.copy().flatten())
    except queue.Full:
        try:
            audio_q.get_nowait()
            audio_q.put_nowait(indata.copy().flatten())
        except queue.Empty:
            pass


def drain():
    while True:
        try:
            audio_q.get_nowait()
        except queue.Empty:
            return


# STAGE 2 TOKEN NOTE.
# security.SESSION_TOKEN is generated at import time, so now that the listener
# runs in its own process it would otherwise mint a DIFFERENT token from the
# orchestrator's and every request it made would 401. The parent passes the
# real token in at startup (see run_voice_process); this is the fallback for
# running listener.py directly, where they genuinely are the same process.
AUTH = {"x-argus-token": security.SESSION_TOKEN}


def set_session_token(token: str):
    """Adopts the orchestrator's session token. Must be called before main()."""
    global AUTH
    if token:
        security.SESSION_TOKEN = token
        AUTH = {"x-argus-token": token}

# HUD state updates are posted from a dedicated thread. They used to be a
# synchronous requests.post(timeout=2) issued from the same loop that drains
# audio_q -- see the set_state("recording"/"thinking"/"standby") calls in
# main()'s capture path. A busy orchestrator (the HUD polls /status every 1s
# and /telemetry every 2.5s, on top of a streaming /command-stream) could
# therefore stall the capture loop for up to two seconds. That matters more
# than it looks: the VAD times segments off wall-clock (seg_start,
# silence_start), so a stalled consumer ends up judging silence against audio
# that was captured seconds earlier, and segments in the wrong place.
#
# maxsize is small and overflow drops the update: this is a cosmetic HUD
# indicator, and a stale one is strictly better than a late microphone.
_state_q: "queue.Queue[str]" = queue.Queue(maxsize=8)


def _state_worker():
    # One Session, so this isn't opening a fresh TCP connection per update.
    # Headers are passed per-request rather than baked into the Session: this
    # thread starts at import time, which is BEFORE run_voice_process() adopts
    # the orchestrator's real token, so a Session-level copy would pin the
    # wrong one for the life of the process and 401 on every update.
    session = requests.Session()
    while True:
        state = _state_q.get()
        try:
            session.post(STATE_URL, json={"state": state}, headers=AUTH, timeout=2)
        except requests.exceptions.RequestException:
            pass


threading.Thread(target=_state_worker, daemon=True).start()


def set_state(state: str):
    """Fire and forget — never blocks the caller. See _state_q above."""
    try:
        _state_q.put_nowait(state)
    except queue.Full:
        pass


def find_wake(text: str):
    """Looks for the assistant's name near the start of an utterance.

    Returns the remaining text after the name (possibly empty) if found,
    or None if the name isn't there. Uses fuzzy matching because "Argus" is
    routinely transcribed as "Argos", "Arcus", or "Marcus".
    """
    cleaned = re.sub(r"[^\w\s]", " ", text.lower())
    # A possessive on the name ("Argus's, who built you") survives the
    # punctuation strip as a lone "s", which then leads the command and
    # reaches the router as "s who built you". Dropped before the split.
    cleaned = re.sub(r"\bs\b", " ", cleaned) if "'s" in text.lower() else cleaned
    words = cleaned.split()
    if not words:
        return None

    # Only look in the opening few words — the name should lead the command.
    horizon = min(len(words), _MAX_WAKE_WORDS + 2)

    # Best weak candidate seen, kept for the second pass below.
    weak_best, weak_rest = 0.0, None

    # SMALLEST span first. The loop used to run widest-first, which meant
    # "argus what is the capital of France" tested the two-word span "argus
    # what" before the one-word "argus" -- and since that span joins to
    # "arguswhat", the name matched and the command lost its first word.
    # A one-word name is the overwhelmingly common case, so it is tried first
    # and multi-word spans only get a look when nothing single matched.
    for span in range(1, min(_MAX_WAKE_WORDS, horizon) + 1):
        for start in range(0, horizon - span + 1):
            chunk = words[start:start + span]
            rest = " ".join(words[start + span:]).strip()

            if " ".join(chunk) in _WAKE_SET:
                return rest

            # Score the last token AND the whole span joined without spaces.
            # The join is what recovers "are gus" -> "aregus", which Whisper
            # produces often enough to matter and which no per-token test can
            # see.
            score = max(wake_score(chunk[-1]), wake_score("".join(chunk)))
            if score >= WAKE_STRONG:
                return rest
            if score > weak_best:
                weak_best, weak_rest = score, rest

    # Second pass: a near miss counts only when the rest of the utterance is
    # addressed to someone. This is the path that stops "August, what is
    # photosynthesis" from vanishing in silence.
    if weak_best >= WAKE_WEAK and _looks_addressed(weak_rest):
        print(f"[wake] weak match {weak_best:.2f}, accepted on phrasing")
        return weak_rest
    return None


# ─── Phonetic wake matching ────────────────────────────────────────────
# difflib.SequenceMatcher.ratio() is the wrong metric for a mis-transcribed
# proper noun, and it fails in BOTH directions. Measured against the real
# wake list:
#
#   "argyz"  (an actual logged mishearing of "Argus") -> ratio 0.600, REJECTED
#   "argaz"                                           -> ratio 0.600, REJECTED
#   "marcus"                                          -> ratio 0.909, ACCEPTED
#
# So the thing the user really said was thrown away, while "marcus" -- which
# config.py explicitly removed from WAKE_WORDS because it caused false wakes --
# sails through the fuzzy matcher anyway. ratio() counts matching CHARACTERS,
# so a two-letter substitution in the middle of a five-letter word is
# catastrophic to the score, while a one-letter prefix on a six-letter word
# barely registers. Neither has anything to do with how the words sound.
#
# Soundex does. It collapses exactly the substitutions a recognizer makes on a
# proper noun (s/z share a code, c/g/k/q/x/z share a code, vowels are dropped
# after the first letter) while keeping the initial letter significant -- which
# is what rejects "marcus" (M622) against "argus" (A622). Requiring a bounded
# edit distance ON TOP of the phonetic match is what keeps it tight: "argue" is
# only one edit away, but codes as A620, so it is still correctly rejected.
# Soundex/edit live in textmatch.py -- intent.py needs the same matching for
# the creator's name, and it runs in the orchestrator process, so the helpers
# cannot live in this module without dragging sounddevice along with them.
_soundex = textmatch.soundex
_edit_distance = textmatch.edit_distance


# Single-token wake names only -- the phonetic test is applied to the name
# itself, not to a phrase like "hey argus" whose leading filler word would
# dilute both the code and the distance.
_WAKE_NAMES = sorted({w.split()[-1] for w in _WAKE_SET if len(w.split()[-1]) >= 4})
_WAKE_CODES = {}
for _n in _WAKE_NAMES:
    _WAKE_CODES.setdefault(_soundex(_n), []).append(_n)

WAKE_MAX_EDITS = 2      # only ever consulted when the Soundex code already matches

# ── wake matching ──────────────────────────────────────────────────────
#
# THE FAILURE THIS REPLACES. The previous matcher used an exact Soundex code
# as a hard GATE: nothing matched unless the code agreed. Measured against 24
# plausible transcriptions of someone saying "Argus", it silently dropped 6 --
# a 25% chance of being ignored with no speech, no error, and nothing but a
# print to distinguish it from ARGUS being switched off. The gate failed in
# three predictable ways:
#
#   Ergus    Soundex preserves the initial letter, so E622 != A622
#   Are gus  the last token is 3 characters, rejected before matching
#   August   a vowel-shift mishearing codes as A223, nowhere near A622
#
# Two of those ("August", "Are gus") are real, from this project's own logs.
#
# WHY THIS IS SCORED RATHER THAN GATED. Several weak signals agreeing is more
# robust than one strong signal vetoing: spelling distance, the consonant
# SKELETON (vowels are the least reliable part of a transcript -- dropping
# them makes ergus and argus identical), Soundex agreement, and containment.
#
# WHY THERE ARE TWO THRESHOLDS. Calibrated over 20 real mishearings and 29
# ordinary words, the distributions OVERLAP and cannot be separated:
#
#     wake  min 0.500   mean 0.876
#     noise max 0.814   mean 0.530     ("organise" scores 0.814)
#
# "August" appears in both sets and is genuinely ambiguous -- sometimes the
# month, sometimes a mishearing of the name. No token-level matcher resolves
# that, and lowering a single threshold far enough to catch it wakes ARGUS on
# "organise".
#
# So the signal the old matcher threw away gets used: WHAT FOLLOWS. A weak
# phonetic match is accepted only when the rest of the utterance is shaped
# like something addressed to an assistant. "August, what is photosynthesis"
# wakes; "the argument was long" does not. That asymmetry is deliberate --
# being ignored is the failure the user actually reports, and an occasional
# extra answer is a far cheaper mistake than silence.
WAKE_STRONG = 0.82      # confident on the name alone
WAKE_WEAK = 0.55        # plausible, but only if what follows is addressed

# Scoring compares against the REAL NAME only, never the misspelling list.
#
# WAKE_WORDS in config.py carries eleven hand-written mis-transcriptions
# ("arves", "arbus", "arvus", "arbis", ...). Those exist because the old
# matcher could only recognise spellings someone had thought to add, which is
# precisely the hardcoding this scorer removes: it derives closeness from the
# name itself, so a mishearing nobody predicted still matches.
#
# Keeping them in the SCORING set actively hurt -- every extra alias is
# another target to be accidentally close to, and "our house" scored 0.81
# against one of them. They remain honoured as exact matches in _WAKE_SET,
# which costs nothing, and renaming the assistant now needs no alias list at
# all.
_SCORE_NAMES = sorted({ASSISTANT_NAME.lower()})

_VOWELS = "aeiou"


def _skeleton(word: str) -> str:
    return "".join(c for c in word if c.isalpha() and c not in _VOWELS)


def wake_score(phrase: str) -> float:
    """0-1, how much PHRASE sounds like the assistant's name.

    Runs against the configured names, so renaming the assistant in config.py
    keeps working -- and, unlike the old path, does NOT depend on someone
    having hand-written the right misspellings into WAKE_WORDS.
    """
    token = "".join(c for c in (phrase or "").lower() if c.isalpha())
    if len(token) < 3:
        return 0.0

    best = 0.0
    for name in _SCORE_NAMES:
        direct = difflib.SequenceMatcher(None, token, name).ratio()
        skel = difflib.SequenceMatcher(
            None, _skeleton(token), _skeleton(name)).ratio()
        s = max(direct, skel * 0.95)
        # Both shortcuts require a token of real length. A bounded edit
        # distance is meaningless on a short word: edit_distance("are",
        # "argus") is 2, so the guard below is the only thing standing between
        # this matcher and ARGUS waking on the word "are" -- which would fire
        # on "are you free tomorrow" and every other sentence in the room.
        #
        # And the edit-distance shortcut is CORROBORATED by Soundex rather
        # than standing alone. "argue" is one edit from "argus" and is an
        # ordinary English word; Soundex separates them (A620 vs A622) because
        # the final consonant is exactly what differs. Letting distance alone
        # promote a match reintroduced the "argue matched" bug config.py
        # already documents having fixed once.
        if len(token) >= 4 and _soundex(token) == _soundex(name):
            s = max(s, 0.90 if _edit_distance(token, name) <= WAKE_MAX_EDITS
                    else 0.85)
        # Containment, but only when the two are close in LENGTH. Without the
        # length bound, "arguswhat" (the span "argus what" joined) contains
        # "argus" and scored 0.90 -- so the matcher consumed the first word of
        # the actual command and ARGUS was asked "is the capital of France".
        if abs(len(token) - len(name)) <= 2 and (name in token or token in name):
            s = max(s, 0.90)
        best = max(best, s)
    return best


# Openers that mean the speaker is addressing someone rather than talking
# about something. Used only to promote a WEAK phonetic match -- never to wake
# ARGUS on its own, because that would make every question in the room a
# command.
_ADDRESSED_OPENERS = frozenset("""
what what's whats who who's whos where when why how which whose
do does did can could will would should shall may might
tell show give explain define describe list find search look
open close launch start stop play pause resume set turn switch
read write save delete remove create make add remind call send
""".split())

# Bare copulas are DELIBERATELY absent above. "is", "are", "was" and "were"
# open far more sentence fragments than commands: "our house is big" reduced
# to "is big" after a 0.63 phonetic match and woke ARGUS, and so would "the
# office is closed". They are still fine after a STRONG match -- this set only
# governs whether a near miss gets promoted, and a near miss needs the clearer
# signal. The cost is that a mistranscribed "Argus, is it raining" is dropped;
# the benefit is that ordinary conversation stays ordinary conversation.
_WEAK_MIN_WORDS = 2


def _looks_addressed(remainder: str) -> bool:
    """Is the text after a near-miss name shaped like a request?"""
    words = (remainder or "").lower().split()
    if len(words) < _WEAK_MIN_WORDS:
        return False
    return words[0] in _ADDRESSED_OPENERS


def _sounds_like_wake(phrase: str) -> bool:
    """Strong-match test. Kept as a name because other code and tests call it."""
    return wake_score(phrase) >= WAKE_STRONG


def _transcribe(tag: str, audio: np.ndarray, timeout: float):
    """Sends one segment to the STT worker and reports the result the same way
    for both passes, so the wake pass isn't flying blind on confidence.

    The audio crosses the process boundary as raw int16 bytes rather than a
    pickled ndarray: it is the same number of bytes on the wire without a dtype
    round-trip, and a 12-second segment is only ~384KB either way.

    A worker failure is NOT fatal here. It returns ("", 0.0), which every
    caller already handles as "nothing intelligible" -- the same path a silent
    clip takes. ipc.WorkerClient restarts the worker underneath us.
    """
    if _stt is None:
        return "", 0.0
    try:
        text, confidence, duration_s = _stt.call(
            (tag, audio.astype(np.int16, copy=False).tobytes()), timeout=timeout)
    except ipc.WorkerError as e:
        print(f"[stt:{tag}] unavailable: {e}")
        return "", 0.0

    print(f"[stt:{tag}] '{text}' (conf {confidence:.2f}, {duration_s:.2f}s clip)")
    _log_wake_debug(tag, duration_s, confidence, text)
    return text, confidence


def quick_transcribe(audio: np.ndarray):
    """Cheap pass with the tiny model, purely to check for the wake word."""
    return _transcribe("wake", audio, WAKE_TIMEOUT)


def accurate_transcribe(audio: np.ndarray):
    """Full-quality pass, used once we know this is a real command."""
    return _transcribe("cmd", audio, COMMAND_TRANSCRIBE_TIMEOUT)


def _drain_queue(q: "queue.Queue"):
    """Empties a queue without blocking. Used to release the synthesized audio
    arrays still held by tts_queue when execute() stops consuming early."""
    while True:
        try:
            q.get_nowait()
        except queue.Empty:
            return


def execute(command_text: str):
    """Sends a command to the orchestrator and speaks the reply.

    Streams from /command-stream and pipelines synthesis and playback: while
    sentence 1 is playing, sentence 2 is pre-synthesized in the background.

    Playback is no longer per-sentence-blocking. Chunks are handed to tts's
    persistent output stream as they arrive (tts.enqueue) and this function
    only blocks at the very end (tts.wait_until_drained). That is what lets
    consecutive sentences join seamlessly -- see tts.py's playback header for
    why the previous one-sd.play()-per-sentence approach both clipped every
    sentence tail and reopened the audio device between each one.

    `busy` is NOT set here. It is claimed by the dispatch site in main() before
    this thread is even started, and released by handle_segment() -- see the
    comment there.
    """
    t0 = time.time()
    spoke_anything = False
    was_silent = False
    tts_queue: "queue.Queue[tuple]" = queue.Queue(maxsize=12)
    stop_streaming = threading.Event()
    worker = None
    try:
        print(f"You: {command_text}")
        set_state("thinking")

        def _put(item) -> bool:
            """Hands an item to the consumer, giving up if the consumer has
            gone away.

            BUGFIX: every put() here used to be unbounded and blocking against
            a 12-slot queue. execute()'s consume loop breaks out on __SILENT__,
            __TIMEOUT__, __ERROR__ and on a barge-in -- and then stops
            consuming. The worker kept synthesizing, filled the queue, and
            parked on put() for the life of the process. Each occurrence leaked
            a live thread, up to twelve synthesized audio arrays, AND an open
            HTTP stream -- which is also why _finish_exchange never ran for
            those exchanges (main.py's generator never reached its finally, so
            no audit entry, no history, no latency figure). Setting
            stop_streaming didn't help, because the worker was blocked in
            put() and never got back to the top of the loop to check it.
            """
            while not stop_streaming.is_set():
                try:
                    tts_queue.put(item, timeout=0.25)
                    return True
                except queue.Full:
                    continue
            return False

        def tts_stream_worker():
            try:
                with requests.post(COMMAND_STREAM_URL, json={"text": command_text},
                                   headers=AUTH, timeout=COMMAND_TIMEOUT, stream=True) as r:
                    r.raise_for_status()
                    for line in r.iter_lines(decode_unicode=True):
                        if stop_streaming.is_set():
                            break
                        if not line or not line.strip():
                            continue
                        text_line = line.strip()
                        if text_line == "__SILENT__":
                            if not _put(("__SILENT__", None, None)):
                                break
                            continue
                        # Mode changes the orchestrator has AUTHORIZED. They
                        # arrive as sentinels rather than prose because this
                        # process owns the microphone and has to act, not
                        # interpret -- and because a spoken sentence could be
                        # produced by a model, while a sentinel cannot.
                        if text_line in ("__DICTATE_ON__", "__DICTATE_OFF__"):
                            if not _put((text_line, None, None)):
                                break
                            continue
                        # Pre-synthesize the sentence chunk concurrently
                        audio_np, sr = tts.synthesize(text_line, PIPER_MODEL_PATH)
                        if audio_np is not None and sr:
                            if not _put(("__AUDIO__", audio_np, sr)):
                                break
            except requests.exceptions.Timeout:
                _put(("__TIMEOUT__", None, None))
            except requests.exceptions.HTTPError as e:
                # An authenticated endpoint's refusal is not an unreachable
                # model. Preserve only the status code, never the response body
                # (which could contain a command or sensitive detail).
                code = e.response.status_code if e.response is not None else 0
                _put(("__HTTP_ERROR__", code, None))
            except requests.exceptions.RequestException as e:
                _put(("__ERROR__", str(e), None))
            finally:
                _put(("__DONE__", None, None))

        worker = threading.Thread(target=tts_stream_worker, daemon=True)
        worker.start()

        while True:
            try:
                item = tts_queue.get(timeout=COMMAND_TIMEOUT)
            except queue.Empty:
                tts.speak("That took too long, so I stopped.", PIPER_MODEL_PATH)
                break

            tag, data, sr = item
            if tag == "__DONE__":
                break
            elif tag == "__DICTATE_ON__":
                tts.speak(start_dictation(), PIPER_MODEL_PATH)
                break
            elif tag == "__DICTATE_OFF__":
                tts.speak(stop_dictation("asked"), PIPER_MODEL_PATH)
                break
            elif tag == "__SILENT__":
                # STAGE 2: pc_skill.stop_speaking() also calls tts.stop(), but
                # it now runs in the ORCHESTRATOR process, where tts holds no
                # output stream -- so that call is a no-op and cutting playback
                # short has to happen here, on the side that owns the device.
                tts.stop()
                print("(stopped — staying quiet)")
                was_silent = True
                break
            elif tag == "__TIMEOUT__":
                tts.speak("That took too long, so I stopped.", PIPER_MODEL_PATH)
                break
            elif tag == "__HTTP_ERROR__":
                if not spoke_anything:
                    print(f"[error] orchestrator refused voice request: HTTP {data}")
                    if data == 401:
                        message = "My session is out of sync. Please restart ARGUS."
                    elif data == 403:
                        message = "That request was refused by security."
                    elif data == 429:
                        message = "Too many requests. Please try again shortly."
                    else:
                        message = "My local service returned an error. Please try again."
                    tts.speak(message, PIPER_MODEL_PATH)
                break
            elif tag == "__ERROR__":
                if not spoke_anything:
                    print(f"[error] orchestrator: {data}")
                    tts.speak("I couldn't reach my local service.", PIPER_MODEL_PATH)
                break
            elif tag == "__AUDIO__":
                if not spoke_anything:
                    print(f"[timing] first sentence {time.time() - t0:.2f}s")
                spoke_anything = True
                set_state("speaking")
                tts.enqueue(data, sr)
                # Backpressure against the ring buffer, not against the device.
                # Synthesis is allowed to run ahead -- just not so far ahead
                # that a barge-in has to chew through it before going quiet.
                while (tts.queued_seconds() > MAX_QUEUED_AUDIO_SEC
                       and not tts.interrupted()):
                    time.sleep(0.05)
                if tts.interrupted():
                    print("[tts] interrupted")
                    break

        # Everything is queued; now wait for the speaker to actually finish.
        if spoke_anything:
            tts.wait_until_drained()

        print(f"[timing] total {time.time() - t0:.2f}s")
        if not spoke_anything and not was_silent:
            tts.speak("Done.", PIPER_MODEL_PATH)
    finally:
        # Release the worker before anything else: it may be parked in _put()
        # waiting for a consumer that has already gone.
        stop_streaming.set()
        _drain_queue(tts_queue)
        if worker is not None:
            worker.join(timeout=2.0)
            if worker.is_alive():
                print("[tts] stream worker still running after 2s")
        drain()
        set_state("standby")
        # Start the follow-up clock only after the speaker has settled.
        resume["at"] = time.time() + TTS_COOLDOWN
        resume["pending"] = True



UNMUTE_PHRASES = ("start listening", "resume listening", "privacy mode off",
                  "listen again", "unmute", "wake up")


# Consecutive segments rejected for low confidence.
#
# "Sorry, say that again?" re-arms the follow-up window, so a low-confidence
# segment leads straight back to another low-confidence segment -- and the
# things that caused it (an accent, mic level, room noise, an unfamiliar proper
# noun) are exactly the things that do not change when you repeat yourself.
# Reported as ARGUS "saying repeatedly sorry say that again".
#
# So the re-prompt is allowed twice, and after that the transcription is sent
# on regardless. A 0.35-confidence sentence is usually still intelligible to a
# language model, and an imperfect answer beats an infinite apology loop --
# "answer, don't ignore" is the rule this whole path is meant to serve.
MAX_UNCLEAR_RETRIES = 2
_unclear = {"streak": 0}

# Empty/failed transcriptions inside a follow-up window are bounded the same
# way, for the same reason. This is the one failure on the request path that
# used to produce TOTAL silence: the segment had passed the speech-volume
# gate, `busy` was claimed, the HUD showed "thinking" -- and then nothing. No
# re-prompt, no error, no terminal response; indistinguishable from ARGUS
# being switched off mid-conversation. Every other failure here speaks
# ("Sorry, say that again?", "I couldn't reach my brain", "That took too
# long"); this one now does too, and the bound keeps a hiss/fan noise floor
# in the same window from turning into an apology loop.
MAX_EMPTY_RETRIES = 2
_empty = {"streak": 0}


def _too_unclear(text: str, conf: float) -> bool:
    """True when the caller should re-prompt instead of acting on TEXT."""
    if conf >= MIN_CONFIDENCE:
        _unclear["streak"] = 0
        return False
    _unclear["streak"] += 1
    if _unclear["streak"] > MAX_UNCLEAR_RETRIES:
        print(f"[stt] still unclear after {_unclear['streak']} tries "
              f"(conf {conf:.2f}) — answering anyway rather than looping")
        _unclear["streak"] = 0
        return False
    return True


def _ack(text: str):
    """Speaks a short acknowledgement (wake ack, re-prompt) and re-arms the
    follow-up window -- the same bookkeeping execute() does for full
    commands, minus the orchestrator round trip.

    BUGFIX: this used to leave voice_state stuck on "speaking" after the
    line finished playing, since nothing set it back afterward. The HUD's
    state-driven visuals (energy level, and now the voice-activity ring)
    would freeze on the "speaking" look until the next real segment
    happened to change it.
    """
    set_state("speaking")
    tts.speak(text, PIPER_MODEL_PATH)
    set_state("standby")
    resume["at"] = time.time()
    resume["pending"] = True


def handle_segment(audio: np.ndarray, expect_command: bool):
    """Wrapped so a transcription failure logs instead of killing the thread.

    Concurrent transcription is serialized inside _transcribe() itself now
    (see its docstring) rather than by holding a lock around this entire
    function -- that used to also cover execute()'s orchestrator call and
    TTS playback, which could run for seconds and would have starved the
    barge-in interrupt check's own need for the same lock the whole time.

    OWNS THE `busy` FLAG. The dispatch site in main() sets it before starting
    this thread; this function is what releases it, in every exit path. It
    deliberately does NOT belong to execute(), because plenty of segments never
    reach execute() at all (no wake word, privacy mode, too short) and would
    otherwise leave busy set forever. See the dispatch site for why the claim
    has to happen there rather than inside execute().
    """
    try:
        _handle_segment(audio, expect_command)
    except Exception as e:
        print(f"[listener] segment failed: {type(e).__name__}: {e}")
    finally:
        # Guarantees the "recording"/"thinking" state set when this segment
        # was captured always resolves back to standby, even on an ignored
        # segment (not a wake word, muted, too short) that never called
        # execute() or _ack() to do it themselves. Harmless if one of those
        # already did -- re-posting "standby" is a no-op for the HUD.
        set_state("standby")
        busy_since["t"] = 0.0
        busy.clear()


# ── unprompted speech ────────────────────────────────────────────────────────
#
# announce.py carries a KIND across the process boundary and never the words.
# This is where the words live, and keeping them here is the security property:
# nothing another process supplies is ever spoken, so the channel cannot be
# used to put arbitrary sentences in ARGUS's mouth.
#
# A kind with no entry here is dropped rather than spoken as its own name.

# What each threat category says. Written to be ACTIONABLE WITHOUT BEING
# SPECIFIC: enough that you know to go and look, not enough that anyone else
# in the room learns what was found or where. Every one ends by pointing at
# the screen, because the detail is there and only there.
_THREAT_LINES = {
    "threat_persistence":
        "Boss, something just set itself to start with your machine. "
        "It's on your screen.",
    "threat_credential":
        "Boss, something just reached for credentials in memory. "
        "You'll want to look at this now.",
    "threat_traffic":
        "Boss, something just changed how your network traffic is routed. "
        "It's on your screen.",
    "threat_tamper":
        "Boss, something just went after my own protection. "
        "You'll want to look at this now.",
    "threat_tripwire":
        "Boss, one of my tripwires was touched. It's on your screen.",
    # Says "reachable" rather than naming the port or the program, for the same
    # reason every other line here withholds specifics: a room is not private,
    # and someone standing behind you should learn that ARGUS noticed
    # something, not which door it found open.
    "threat_exposure":
        "Boss, something on this machine just started accepting connections "
        "from the network. It's on your screen.",
    # Does not name WHICH protection. Saying "your firewall is off" out loud
    # tells the room exactly which door is open, and this is the one alert
    # where that detail is most directly actionable by somebody else.
    "threat_defenses":
        "Boss, one of your security protections just switched off. "
        "You'll want to look at this now.",
    "threat_generic":
        "Boss, I've detected something that needs your attention. "
        "The details are on your screen.",
    "lockdown":
        "Boss, I've detected something critical and locked the screen. "
        "Your PIN opens it. The details are waiting for you.",
    "long_session":
        "Boss, you've been at this about three hours. "
        "Worth standing up for a minute.",
    "very_long_session":
        "Boss, that's six hours straight now. "
        "I'd take a proper break if I were you.",
    "plan_loop_broken":
        "Boss, I stopped the task I was running -- it kept doing the same "
        "thing without making progress. Nothing further happened. "
        "It's on your screen if you want the details.",
    # agents/agent_manager.py raises this for a CRITICAL inbox item only. Says
    # nothing about what was found -- the details stay on the screen.
    "agent_attention":
        "Boss, the Agent Manager needs you. It's in your agent inbox -- "
        "nothing has been done without you.",
}


def _announcement_text(kind: str) -> str:
    if kind == "welcome_back":
        # Reuses the wake vocabulary so returning sounds like the assistant
        # you were already talking to, not a different canned voice. Instant
        # by construction -- see wake_line().
        return wake_line()
    return _THREAT_LINES.get(kind, "")


def drain_announcements():
    """Speak anything ARGUS has decided to say on its own. Never blocks.

    Called from the capture loop between segments, and deliberately NOT while
    busy: interrupting a reply, or talking over the user mid-sentence, is
    exactly the behaviour that makes people switch a feature like this off.
    """
    try:
        import announce
    except Exception:
        return
    kind = announce.take()
    if not kind:
        return
    text = _announcement_text(kind)
    if not text:
        return
    print(f"[announce] {kind}")
    _ack(text)


def conversation_window(now: float) -> float:
    """How long to keep listening without the wake word. 0 closes the window.

    Pure, so the policy can be tested without a microphone -- which is the
    only honest way to test thresholds about when ARGUS stops listening.
    """
    if _conv.get("ended"):
        return 0.0
    if not _conv["turns"]:
        return FOLLOWUP_WINDOW              # unproven: keep it short
    if _conv["started"] and now - _conv["started"] > CONVERSATION_MAX_S:
        # The ceiling. A conversation that has run this long is either
        # finished or the microphone is hearing something that is not you.
        return 0.0
    return FOLLOWUP_ACTIVE_WINDOW


def conversation_note(text: str, was_followup: bool):
    """Record that a turn happened, and notice when it is over."""
    if not was_followup:
        # A wake-word command starts a FRESH conversation. Without this, an
        # old conversation's turn count would grant a long window to what is
        # actually a brand new, unproven exchange.
        _conv.update(turns=0, started=time.time(), ended=False)
        return
    if CONVERSATION_ENDERS.match((text or "").strip()):
        _conv["ended"] = True
        return
    if not _conv["started"]:
        _conv["started"] = time.time()
    _conv["turns"] += 1


# ── continuous dictation ─────────────────────────────────────────────────────
#
# "Start dictating" and then just talk: every sentence is typed into whatever
# window has focus until you say stop. One-shot dictation already existed
# ("type this: ..."); what was missing was not having to say it every time.
#
# THIS IS THE MOST DANGEROUS MODE IN ARGUS and, like pc_skill.dictate, it does
# not look like it. Keystrokes go into whatever is focused, "\n" is Enter, and
# with a terminal focused that is shell execution. So the mode changes WHEN
# text is typed and changes NOTHING about what is allowed to be typed: every
# chunk still goes through execpolicy.check_dictation, which refuses control
# characters, caps length, and refuses outright when the focused window is a
# terminal. A mode that relaxed those would be a different feature wearing
# this one's name.
#
# It is bounded three ways, because a dictation mode left on is a microphone
# typing into your documents:
#   * a hard ceiling on the whole session
#   * a silence timeout -- nothing said for a while means you walked away
#   * the stop phrase, which is matched BEFORE anything is typed
#
# And a PIN is never typed. If what you just said is the command PIN, the mode
# stops rather than putting it into a document, an address bar, or a chat.

DICTATION_MAX_S = 300.0        # the whole session
DICTATION_SILENCE_S = 45.0     # nothing said -> assume you left
DICTATION_STOP = re.compile(
    r"^(?:argus[,\s]+)?(?:stop|end|finish|cancel|quit)\s+"
    r"(?:the\s+)?(?:dictating|dictation|typing)\b[\s!.,]*$", re.I)

_dictation = {"on": False, "since": 0.0, "last": 0.0, "typed": 0,
              "refused": 0}


def dictation_active(now: float = None) -> bool:
    """True while dictating. EXPIRES here, so the mode cannot be left on.

    Checked on the read rather than by a timer: a timer that fails to fire
    leaves the microphone typing, and this way the only path that can act on
    the mode is the one that just confirmed it is still valid.
    """
    now = now or time.time()
    if not _dictation["on"]:
        return False
    if now - _dictation["since"] > DICTATION_MAX_S:
        stop_dictation("time limit")
        return False
    if _dictation["last"] and now - _dictation["last"] > DICTATION_SILENCE_S:
        stop_dictation("silence")
        return False
    return True


def start_dictation() -> str:
    now = time.time()
    _dictation.update(on=True, since=now, last=now, typed=0, refused=0)
    print(f"[dictation] on — {DICTATION_MAX_S:.0f}s max, "
          f"{DICTATION_SILENCE_S:.0f}s silence timeout")
    try:
        import security
        security.audit("dictation_mode", "on", "ok")
    except Exception:
        pass
    return ("Dictating. Everything you say goes into the focused window. "
            "Say stop dictating when you're done.")


def stop_dictation(reason: str = "asked") -> str:
    was = _dictation["on"]
    typed = _dictation["typed"]
    _dictation.update(on=False, since=0.0, last=0.0)
    if was:
        print(f"[dictation] off ({reason}) — {typed} chunk(s) typed")
        try:
            import security
            security.audit("dictation_mode", f"off reason={reason} "
                           f"typed={typed}", "ok")
        except Exception:
            pass
    if reason == "time limit":
        return "That's five minutes of dictation, so I've stopped."
    if reason == "silence":
        return "I haven't heard anything for a while, so I've stopped dictating."
    if reason == "pin":
        return "That sounded like your PIN, so I stopped rather than type it."
    return f"Stopped dictating. {typed} passage{'' if typed == 1 else 's'} typed."


def _handle_dictation(audio: np.ndarray):
    """One segment, while dictating. Types it, or ends the mode."""
    text, conf = accurate_transcribe(audio)
    text = (text or "").strip()
    if not text:
        return
    _dictation["last"] = time.time()

    # BEFORE anything is typed. Otherwise "stop dictating" is a phrase that
    # appears in your document and the mode never ends.
    if DICTATION_STOP.match(text):
        _ack(stop_dictation("asked"))
        return

    # A PIN must never be typed -- not into a document, an address bar, or a
    # chat window. Same guard the remote channel uses, and it fails CLOSED:
    # if the check is unavailable, anything PIN-shaped still stops the mode.
    try:
        import security
        is_pin = security.is_command_pin(text)
    except Exception:
        is_pin = text.isdigit() and 4 <= len(text) <= 12
    if is_pin:
        _ack(stop_dictation("pin"))
        return

    if _too_unclear(text, conf):
        print(f"[dictation] unclear, not typing: {text[:40]}")
        return

    try:
        from skills import pc_skill
        result = pc_skill.dictate(text)
    except Exception as e:
        _ack(f"I couldn't type that ({type(e).__name__}).")
        return

    if str(result).strip().lower().startswith("typed"):
        _dictation["typed"] += 1
        print(f"[dictation] typed: {text[:60]}")
    else:
        # execpolicy refused -- a terminal has focus, or the text carries
        # control characters. Said out loud, because silently not typing is
        # indistinguishable from ARGUS not having heard.
        _dictation["refused"] += 1
        _ack(str(result))


def _handle_segment(audio: np.ndarray, expect_command: bool):
    """Decides what a captured speech segment means.

    expect_command=True means we're in a follow-up window and the name isn't
    required — you already have its attention.
    """
    t0 = time.time()

    # Dictation takes precedence over everything, including the wake word:
    # while it is on, speech is TEXT rather than instructions. It expires on
    # its own (see dictation_active), so this can never become a permanent
    # state that swallows every command.
    if dictation_active(t0):
        _handle_dictation(audio)
        return

    if expect_command:
        text, conf = accurate_transcribe(audio)
        print(f"[timing] transcribe {time.time() - t0:.2f}s (conf {conf:.2f})")
        if not text or len(text) < 2:
            # FIXED: used to be a bare `return` -- total silence on the one
            # request path that had already claimed `busy` and shown
            # "thinking". Now it speaks once, bounded: after two empty
            # results the window simply closes (no spoken re-prompt to loop
            # on) instead of apologising forever to a fan or a hiss.
            _empty["streak"] += 1
            if _empty["streak"] <= MAX_EMPTY_RETRIES:
                print(f"[stt:{'cmd'}] empty transcription "
                      f"({_empty['streak']}/{MAX_EMPTY_RETRIES}) -- reprompting")
                _ack("Sorry, I didn't catch that.")
            else:
                print("[stt:cmd] still empty after retries -- closing the "
                      "follow-up window quietly")
                _empty["streak"] = 0
            return
        _empty["streak"] = 0        # real text: the bounded-empty counter resets
        # BUGFIX: this used to require the text to look like an imperative
        # command ("open", "play", ...) before acting on it, on the theory
        # that a follow-up window without the wake word would otherwise pick
        # up ambient room conversation. In practice that filter caught
        # ordinary back-and-forth too -- a plain reply like "I'm good"
        # doesn't start with a verb, so it silently became
        # "[ignored, not a command]" and ARGUS never answered at all. Per
        # explicit instruction: anything that doesn't match a fast pattern
        # should still reach the brain rather than being dropped, so nothing
        # is filtered here now -- confidence below is the only remaining
        # gate, and it's about transcription quality, not intent.
        if _too_unclear(text, conf):
            print(f"(unclear: {text})")
            _ack("Sorry, say that again?")
            return
        # Counted BEFORE execute(): this is what proves the conversation is
        # live and earns the longer window for the turn after this one.
        conversation_note(text, was_followup=True)
        if _conv["ended"]:
            # "thanks", "that's all" -- answer it, then stop listening rather
            # than holding the microphone open for another thirty seconds.
            print("[followup] closing — conversation ended")
        execute(text)
        return

    # Not in a follow-up: the name has to be present.
    rough, wake_conf = quick_transcribe(audio)
    if not rough:
        return

    remainder = find_wake(rough)
    if remainder is None:
        # The score is printed because "[ignored]" on its own is unreadable
        # as a bug report. A drop at 0.78 means the name was heard and nearly
        # matched (raise tolerance, or the phrasing did not look addressed);
        # a drop at 0.10 means this was room noise and ARGUS was right to stay
        # quiet. Those need opposite responses and used to look identical.
        best = max((wake_score(w) for w in rough.lower().split()[:4]), default=0.0)
        hint = ("near miss — say the name more clearly, or start with a "
                "question word" if best >= WAKE_WEAK else "not addressed to me")
        print(f"[ignored] wake {best:.2f} ({hint}): {rough[:50]}")
        return

    # Privacy mode: the ONLY thing acted on is the phrase that lifts it.
    # Everything else is discarded here, before any model or disk write.
    from skills import privacy_skill
    if privacy_skill.is_muted():
        if any(p in (remainder or "").lower() for p in UNMUTE_PHRASES):
            print("[privacy] unmute requested")
            execute(remainder)
        else:
            print("[privacy] muted — audio discarded")
        return

    print(f"\n[wake] heard {ASSISTANT_NAME} ({time.time() - t0:.2f}s, wake conf {wake_conf:.2f})")

    # Hearing the name starts a NEW conversation, so the turn count resets and
    # the next window is a short, unproven one again. Without this, yesterday's
    # long conversation would hand a brand-new exchange a 30-second open
    # microphone it has not earned.
    conversation_note("", was_followup=False)

    if not remainder:
        # Just the name on its own — acknowledge and wait for the command.
        # wake_line() is instant by construction (see its header): the model
        # writes the NEXT line in the background, never this one, so calling
        # ARGUS never costs a pause before it answers.
        _ack(wake_line())
        return

    # Name plus a command in one breath — re-run at full accuracy.
    text, conf = accurate_transcribe(audio)
    stripped = find_wake(text)
    command = stripped if stripped else remainder
    print(f"[timing] transcribe {time.time() - t0:.2f}s (conf {conf:.2f})")

    if not command or len(command) < 2:
        _ack("Yes?")
        return

    if _too_unclear(command, conf):
        print(f"(unclear: {command})")
        _ack("Sorry, say that again?")
        return

    execute(command)


def start_workers() -> bool:
    """Brings up the STT and TTS worker processes.

    STT is required -- without it ARGUS cannot hear, and there is nothing
    useful to do but report and let the supervisor retry. TTS failing is
    degraded rather than fatal: the machine still executes commands, it just
    can't speak about them, which is strictly better than refusing to listen.
    """
    global _stt

    print(f"Starting speech recognition worker ({WAKE_MODEL} + {WHISPER_MODEL})...")
    _stt = ipc.WorkerClient(
        "stt", stt_worker.run,
        args=(WAKE_MODEL, WHISPER_MODEL, FORCE_CPU_STT, WHISPER_PROMPT, WAKE_PROMPT),
        start_timeout=STT_START_TIMEOUT,
    )
    if not _stt.start():
        print("[stt] worker failed to start — cannot listen.")
        _stt = None
        return False

    print("Starting speech synthesis worker...")
    if tts.init(PIPER_MODEL_PATH) is None:
        print("[tts] no voice available — continuing without speech.")
    return True


def stop_workers():
    global _stt
    if _stt is not None:
        _stt.stop()
        _stt = None
    tts.shutdown()


def main():
    """Start the workers and run the capture loop. Kept as the module's
    historical entry point; run_voice_process() is what argus.py uses, because
    it also supervises and owns the restart policy."""
    if not start_workers():
        raise RuntimeError("speech recognition worker did not start")
    READY.set()
    try:
        _run_loop()
    finally:
        READY.clear()
        stop_workers()


def _run_loop():
    """The capture loop itself. Owns the microphone stream and nothing else.

    Split out from main() so run_voice_process() can restart JUST this -- and
    the worker processes behind it -- without re-entering worker startup twice
    or re-importing the module the way argus.py's old reload loop did.
    """
    print("=" * 56)
    print(f"{ASSISTANT_NAME} online. Say \"{ASSISTANT_NAME.title()}\" followed by a command.")
    print(f'Try: "{ASSISTANT_NAME.title()}, open Telegram"   ·   Interrupt with "stop"')
    print("=" * 56)

    preroll = collections.deque(maxlen=PREROLL_FRAMES)
    buffer = []
    capturing = False
    loud_run = 0
    silence_start = None
    seg_start = 0.0
    seg_followup = False        # latched when a segment starts -- see below
    followup_until = 0.0
    interrupt_buf = collections.deque(maxlen=15)  # ~1.5s, enough for a short phrase
    last_interrupt_check = 0.0

    # Verify the command path end to end before claiming to be online. A silent
    # auth failure here previously showed up only as "orchestrator unreachable"
    # the first time you spoke.
    try:
        probe = requests.get(f"{ORCHESTRATOR}/status", headers=AUTH, timeout=4)
        if probe.status_code == 200:
            print("[link] orchestrator reachable, token accepted")
        elif probe.status_code == 401:
            print("[link] TOKEN REJECTED — listener and orchestrator disagree.")
        else:
            print(f"[link] unexpected status {probe.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[link] orchestrator NOT reachable: {e}")

    stream = sd.InputStream(
        samplerate=SAMPLE_RATE, channels=1, dtype="int16",
        blocksize=CHUNK, callback=audio_callback,
    )
    stream.start()
    # sounddevice/PortAudio can silently open at a rate other than requested
    # if the device doesn't support it directly -- confirm what we actually
    # got rather than assuming the request was honored. A mismatch here
    # would corrupt every transcription downstream.
    if int(round(stream.samplerate)) != SAMPLE_RATE:
        print(f"[stt] WARNING: mic opened at {stream.samplerate}Hz, not the "
              f"requested {SAMPLE_RATE}Hz — transcription quality will suffer.")
    else:
        print(f"[stt] mic stream confirmed at {int(stream.samplerate)}Hz")

    ambient_rms = 250.0

    try:
        while True:
            # Watchdog — a hung worker used to lock the assistant out entirely.
            if busy.is_set() and busy_since["t"] and \
               time.time() - busy_since["t"] > WATCHDOG_LIMIT:
                print("[watchdog] worker stuck — resetting")
                tts.stop()
                busy.clear()
                busy_since["t"] = 0.0
                resume["pending"] = True
                resume["at"] = time.time()

            # Speech finished: clear the pre-roll (it now contains ARGUS's own
            # voice) and open the follow-up window from this moment.
            if resume["pending"] and not busy.is_set() and time.time() >= resume["at"]:
                preroll.clear()
                buffer = []
                capturing = False
                drain()
                window = conversation_window(resume["at"])
                followup_until = resume["at"] + window
                resume["pending"] = False
                if window:
                    print(f"[followup] {window:.0f}s — no name needed"
                          + (f" (turn {_conv['turns']})" if _conv["turns"] else ""))
                else:
                    print("[followup] closed — say the name again")

            try:
                chunk = audio_q.get(timeout=0.5)
            except queue.Empty:
                # Idle: no audio arriving. The safest possible moment to say
                # something unprompted -- nobody is mid-sentence and ARGUS is
                # not mid-reply. Guarded on busy as well, because a reply can
                # still be playing while the queue is briefly empty.
                if not busy.is_set() and not capturing:
                    drain_announcements()
                continue

            rms = float(np.sqrt(np.mean(chunk.astype(np.float32) ** 2)))

            # While busy (orchestrator call + TTS playback):
            # Barge-in is enabled only during active TTS speech and requires clear, loud
            # intentional human voice (> 1300 RMS) rather than speaker audio bleed,
            # checked with a 1.2s cooldown. This stops high CPU/GPU Whisper polling
            # on ARGUS's own voice and eliminates audio underruns/glitches.
            if busy.is_set():
                if not tts.is_speaking():
                    interrupt_buf.clear()
                    continue
                interrupt_buf.append(chunk)
                now = time.time()
                if rms > 1300 and (now - last_interrupt_check) > 1.2:
                    last_interrupt_check = now
                    snippet = np.concatenate(list(interrupt_buf))
                    text, conf = quick_transcribe(snippet)  # locks internally
                    if text and _sounds_like_interrupt(text):
                        print(f"[barge-in] '{text}' (conf {conf:.2f}) -> stopping")
                        tts.stop()
                        interrupt_buf.clear()
                continue

            # Update ambient noise floor baseline during quiet intervals
            if not capturing:
                ambient_rms = 0.95 * ambient_rms + 0.05 * min(rms, 600.0)

            start_thresh = max(VAD_START_RMS, ambient_rms * 1.8 + 150)
            stop_thresh = max(VAD_STOP_RMS, ambient_rms * 1.1 + 40)

            if not capturing:
                preroll.append(chunk)
                # Require two consecutive loud frames
                if rms > start_thresh:
                    loud_run += 1
                else:
                    loud_run = 0
                if loud_run >= 2:
                    loud_run = 0
                    capturing = True
                    buffer = list(preroll)
                    silence_start = None
                    seg_start = time.time()
                    # BUGFIX: this used to be evaluated at the moment the
                    # segment ENDED, which silently shortened the follow-up
                    # window by however long the user spoke -- plus the 0.65s
                    # of silence needed to close the segment.
                    #
                    # Straight from a real log: "[followup] 4s -- no name
                    # needed" printed, then "Do you know about Uzbekistan?"
                    # (a 2.50s clip) came back "[ignored]". The window was
                    # open when he STARTED talking and had closed by the time
                    # he stopped, so a question asked well inside the window
                    # was judged against the clock ~3.15s later and treated as
                    # if no wake word had been given. A 4.5s window was in
                    # practice a ~1.5s window for any real question, and the
                    # longer the question the more certain it was to be
                    # thrown away.
                    #
                    # Whether you are answering ARGUS is decided by when you
                    # BEGIN speaking, so latch it here.
                    seg_followup = time.time() < followup_until
                    set_state("recording")
            else:
                buffer.append(chunk)
                elapsed = time.time() - seg_start

                done = False
                if elapsed > MAX_SEGMENT_SEC:
                    done = True
                elif rms < stop_thresh:
                    if silence_start is None:
                        silence_start = time.time()
                    elif (time.time() - silence_start) > 0.65:
                        done = True
                else:
                    silence_start = None

                if done:
                    audio = np.concatenate(buffer) if buffer else None
                    capturing = False
                    buffer = []
                    preroll.clear()
                    if audio is not None and len(audio) > SAMPLE_RATE * MIN_SEGMENT_SEC:
                        # Ensure the recorded segment had genuine speech volume above ambient
                        frame_count = max(1, len(audio) // CHUNK)
                        frames = audio[:frame_count * CHUNK].reshape(frame_count, CHUNK).astype(np.float32)
                        peak_frame_rms = float(np.sqrt(np.max(np.mean(frames ** 2, axis=1))))
                        if peak_frame_rms >= start_thresh * 0.85:
                            if busy.is_set():
                                # BUGFIX: `busy` used to be claimed inside
                                # execute(), which only runs AFTER
                                # accurate_transcribe() returns -- 1-3s on
                                # small.en. For that whole window this loop was
                                # fully active and could dispatch a SECOND
                                # handle_segment thread, giving two concurrent
                                # execute() calls, two /command-stream requests
                                # and two replies fighting over the same output
                                # device. Claiming it here closes that window.
                                print("[listener] already handling a command — segment dropped")
                                set_state("standby")
                            else:
                                busy.set()
                                busy_since["t"] = time.time()
                                set_state("thinking")
                                threading.Thread(
                                    target=handle_segment,
                                    args=(audio, seg_followup),
                                    daemon=True,
                                ).start()
                        else:
                            set_state("standby")
                    else:
                        set_state("standby")


    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        stream.stop()
        stream.close()


# ═══════════════════════════════════════════════════════════════════════
# VOICE PROCESS ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════

def _generate_opener(health: str, known: bool) -> str:
    """LLM-written startup greeting -- different wording every launch instead
    of the same fixed sentence. Address the operator using the local config
    value when one is available.

    Falls back to a fixed template if the model call fails -- Ollama may not
    be fully warmed up yet this early in startup, and a greeting is not worth
    blocking or silently skipping over.
    """
    from datetime import datetime

    from ollama_client import chat

    hour = datetime.now().hour
    if hour < 5:
        part_of_day = "very late at night"
    elif hour < 12:
        part_of_day = "morning"
    elif hour < 18:
        part_of_day = "afternoon"
    else:
        part_of_day = "evening"

    operator = (USER_NAME or "").strip()
    intro = (
        f'This is the operator\'s first time launching you, so briefly mention you\'re '
        f'{ASSISTANT_NAME.title()} and that saying "{ASSISTANT_NAME.title()}" '
        f"wakes you for a command."
        if not known else
        "The operator already knows how you work -- do not re-introduce yourself or "
        "explain the wake word."
    )
    # What ARGUS actually knows about this particular wake: whether the operator is up
    # at an unusual hour FOR HIM, how long he has been away, and anything the
    # machine or the detectors want to raise. Passed as CONTEXT for the model to
    # weave in, not as a second announcement after the greeting -- an assistant
    # that says hello and then reads a bulletin is two utterances where a person
    # would have said one. Empty when there is genuinely nothing to note, and
    # the prompt below then simply has nothing extra to work with.
    briefing = ""
    try:
        from skills import briefing_skill
        briefing = briefing_skill.brief(briefing_skill.record_start())
    except Exception as e:
        print(f"[{ASSISTANT_NAME.lower()}] briefing unavailable: {type(e).__name__}")

    context = (f' Also work in, naturally and briefly, what you have noticed: '
               f'"{briefing}". Do not list these -- mention only what matters '
               f'most and say it the way a person would.' if briefing else "")

    name_instruction = f"addresses your operator by name, {operator}; " if operator else ""
    system = (
        f"You are {ASSISTANT_NAME.title()}, a local voice assistant finishing "
        "boot-up. Write ONE short spoken greeting (1-2 sentences, no more) that: "
        f"{name_instruction}fits that it is currently the "
        f"{part_of_day}; and naturally works in this system status without "
        f'reading it like a report: "{health}".{context} {intro} Tone: crisp and '
        "tactical, like a system reporting for duty -- confident, not "
        "robotic, but also NOT flowery or poetic (no phrases like \"evening's "
        "calm descends\"). Plain, direct language. Use different wording and "
        "structure than a generic canned greeting each time. Output ONLY the "
        "greeting text -- no quotes, no preamble, no explanation."
    )
    try:
        text = chat(system, "Generate the greeting now.").strip().strip('"').strip()
        if text and 5 < len(text) < 320:
            return text
    except Exception as e:
        print(f"[{ASSISTANT_NAME.lower()}] LLM greeting failed, using fallback: {e}")

    from skills import diagnostics
    greet = diagnostics.greeting()
    address = f" {operator}" if operator else ""
    if known:
        return f"{greet}{address}. All systems online. {health} What do you need?"
    return (
        f"{greet}{address}. I'm {ASSISTANT_NAME.title()}, and I'm online. {health} "
        f'Say "{ASSISTANT_NAME.title()}" followed by anything you need.'
    )


# ── what ARGUS says when you call its name ───────────────────────────────────
#
# It used to say "Yes?" -- the same syllable, every time, forever. That is what
# a hotkey sounds like, not an assistant.
#
# THE CONSTRAINT IS LATENCY, and it is what shapes everything here. The BOOT
# greeting can afford to call a model, because nobody minds waiting during a
# wake video. A wake acknowledgement cannot: you say "Argus" and then hear
# nothing for two seconds while a 4GB card thinks. That reads as broken, and
# it is exactly the "ARGUS is ignoring me" complaint in a new costume.
#
# So the model never runs on the path that speaks. Lines are generated in the
# BACKGROUND, cached against the situation they were written for, and popped
# instantly on the next wake. The first wake in any new situation uses a
# template and sounds fine; the ones after it are model-written.
#
# LOCAL ONLY, and not by accident: these lines reference when you usually
# start, whether you are up late, how long you were away. That is personal
# state about this machine and its owner, so ollama_client (localhost) is used
# rather than any cloud tier -- the same rule everything else here follows.

_ACK_CACHE_MAX = 4
_ACK_RECENT = 10                    # lines remembered, to avoid repeating
_ACK_REPEAT_WINDOW_S = 120          # within this, you are still mid-conversation
_ACK_MAX_CHARS = 110

_ack_state = {
    "lines": [],                    # pre-generated, for "ctx"
    "ctx": None,
    "recent": collections.deque(maxlen=_ACK_RECENT),
    "last_wake": 0.0,
    "refilling": False,
    "day": "",                      # date string of the last wake
}
_ack_lock = threading.RLock()


def _wake_context(now: float = None) -> dict:
    """Cheap LOCAL signals the acknowledgement can react to. No model, no I/O
    beyond briefing_skill's own small session file."""
    now = now or time.time()
    lt = time.localtime(now)
    h = lt.tm_hour
    part = ("night" if h < 5 else "morning" if h < 12
            else "afternoon" if h < 18 else "evening")
    with _ack_lock:
        last = _ack_state["last_wake"]
        first_today = _ack_state["day"] != time.strftime("%Y-%m-%d", lt)
    ctx = {
        "part": part,
        "first_today": first_today,
        # "again" means you are still talking to it, not starting fresh --
        # a full "Boss, I'm ready, late start today" on the fifth wake in a
        # minute is not attentive, it is a parrot.
        "again": bool(last and (now - last) < _ACK_REPEAT_WINDOW_S),
        "timing": "",
        "away_h": 0.0,
    }
    try:
        from skills import briefing_skill
        info = briefing_skill.current_info(now)
        ctx["timing"] = str(info.get("timing") or "")
        ctx["away_h"] = float(info.get("away_hours") or 0.0)
    except Exception:
        pass
    return ctx


def _ack_key(ctx: dict) -> tuple:
    """What makes two situations 'the same' for caching. Coarse on purpose --
    away_hours changes constantly and would invalidate the cache every wake."""
    return (ctx["part"], ctx["first_today"], ctx["again"], ctx["timing"],
            int(ctx["away_h"] // 3) if ctx["away_h"] else 0)


def _ack_templates(ctx: dict) -> list:
    """Instant fallbacks. Composed from the situation rather than drawn from a
    long list of canned strings: the point is that the line FITS, and a big
    list of generic lines is just "Yes?" with extra steps."""
    if ctx["again"]:
        return ["Still here, Boss.", "Go ahead, Boss.", "Yes, Boss?",
                "Listening.", "With you."]
    out = []
    if ctx["timing"] == "late" and ctx["first_today"]:
        out += ["Boss, I'm ready. Late start today — everything alright?",
                "Ready, Boss. You're up later than usual."]
    if ctx["first_today"] and ctx["part"] == "morning":
        out += ["Morning, Boss. I'm ready.",
                "Boss, I'm ready. How did you sleep?"]
    if ctx["part"] == "evening":
        out += ["Ready, Boss. How was your day?",
                "Boss, I'm ready. Long day?"]
    if ctx["part"] == "night":
        out += ["I'm ready, Boss. Still up?",
                "Ready, Boss. Late one tonight."]
    if ctx["away_h"] >= 3:
        out += ["Boss, I'm ready. You've been away a while."]
    out += ["Boss, I'm ready.", "Ready when you are, Boss.",
            "I'm here, Boss.", "Yes, Boss?"]
    return out


def _ack_pick(candidates: list) -> str:
    """First candidate not said recently, so variety does not depend on luck."""
    import random

    with _ack_lock:
        recent = set(_ack_state["recent"])
    fresh = [c for c in candidates if c and c not in recent]
    chosen = random.choice(fresh) if fresh else (
        random.choice(candidates) if candidates else "Yes, Boss?")
    with _ack_lock:
        _ack_state["recent"].append(chosen)
    return chosen


def _clean_ack(ln: str) -> str:
    """Strip the decoration a model adds to a list it was told not to decorate.

    Applied REPEATEDLY rather than as a fixed sequence, because a single pass
    is order-dependent and got it wrong: stripping quotes and then bullets
    left `- "Ready when you are, Boss."` as `"Ready when you are, Boss.` --
    the leading quote survived because the bullet was still in front of it
    when the quote strip ran. Looping until nothing more comes off means the
    order of these no longer matters, and numbering ("1.", "2)") comes off
    too, which the original missed entirely.
    """
    ln = (ln or "").strip()
    for _ in range(4):
        before = ln
        ln = ln.strip().strip('"“”')
        ln = re.sub(r"^\s*(?:\d+\s*[.)\]]|[-•*])\s*", "", ln)
        if ln == before:
            break
    return ln.strip()


def _ack_refill(ctx: dict):
    """Generate the NEXT few lines for this situation. Background thread only.

    Never speaks, never blocks a caller, and swallows everything: a model that
    is slow, missing or wrong must cost nothing more than falling back to a
    template on the next wake.
    """
    try:
        from ollama_client import chat

        bits = [f"it is {ctx['part']}"]
        if ctx["first_today"]:
            bits.append("this is the first time today they've called you")
        if ctx["timing"] == "late":
            bits.append("they started their day later than they usually do")
        elif ctx["timing"] == "early":
            bits.append("they started earlier than they usually do")
        if ctx["away_h"] >= 3:
            bits.append(f"they have been away about {int(ctx['away_h'])} hours")

        system = (
            "You are ARGUS, a personal assistant. Your operator just said your "
            "name to get your attention. Write 4 DIFFERENT one-line "
            "acknowledgements, one per line, no numbering, no quotes.\n"
            "Rules: address him as Boss. Say you are ready or listening. Each "
            "line at most 12 words. Sound like a person who knows him, not a "
            "system prompt. You may add ONE short natural remark or question "
            f"given that {', and '.join(bits)}. Never mention files, "
            "processes, security, or anything technical. No emoji. No poetry."
        )
        raw = chat(system, "Write the four lines now.")
        lines = []
        for ln in (raw or "").splitlines():
            ln = _clean_ack(ln)
            # A model asked for four lines sometimes writes a preamble too.
            if 4 < len(ln) <= _ACK_MAX_CHARS and not ln.endswith(":"):
                lines.append(ln)
        if lines:
            with _ack_lock:
                if _ack_state["ctx"] == _ack_key(ctx):
                    _ack_state["lines"] = lines[:_ACK_CACHE_MAX]
    except Exception:
        pass                        # templates already cover this
    finally:
        with _ack_lock:
            _ack_state["refilling"] = False


def wake_line(now: float = None) -> str:
    """The acknowledgement to speak RIGHT NOW. Never blocks, never calls a model.

    Returns in microseconds: a cached model-written line when one is available
    for this situation, otherwise a template that fits it. Either way the
    refill happens afterwards, on another thread, for next time.
    """
    now = now or time.time()
    ctx = _wake_context(now)
    key = _ack_key(ctx)

    with _ack_lock:
        if _ack_state["ctx"] != key:
            # The situation changed (new part of day, first wake of a new
            # day, no longer mid-conversation), so lines written for the old
            # one no longer fit and are dropped rather than spoken.
            _ack_state["ctx"] = key
            _ack_state["lines"] = []
        pool = list(_ack_state["lines"])
        _ack_state["last_wake"] = now
        _ack_state["day"] = time.strftime("%Y-%m-%d", time.localtime(now))
        need_refill = (len(pool) <= 1 and not _ack_state["refilling"])
        if need_refill:
            _ack_state["refilling"] = True

    line = _ack_pick(pool) if pool else _ack_pick(_ack_templates(ctx))
    with _ack_lock:
        if line in _ack_state["lines"]:
            _ack_state["lines"].remove(line)

    if need_refill:
        threading.Thread(target=_ack_refill, args=(ctx,),
                         name="wake-ack-refill", daemon=True).start()
    return line[:_ACK_MAX_CHARS]


def _greet_when_awake(hud_awake=None):
    """Hold the greeting until the interface has finished waking.

    The wake video carries its own narration. Speaking across it produced two
    voices at once, and on a slow start ARGUS could greet before the user had
    even clicked to begin the sequence -- a program talking before it had
    visibly opened.

    Waits on the event the HUD sets through /hud-awake, and gives up after
    GREET_WAIT_FOR_HUD_S. Giving up still greets: a missing window is a
    degraded mode, not a reason for a voice assistant to stay silent.
    """
    if hud_awake is not None:
        try:
            if not hud_awake.wait(timeout=GREET_WAIT_FOR_HUD_S):
                print(f"[{ASSISTANT_NAME.lower()}] no HUD wake signal in "
                      f"{GREET_WAIT_FOR_HUD_S:.0f}s — greeting anyway")
        except Exception:
            pass          # a broken handle must not cost the greeting
    _greet()


def _greet():
    """Speaks the startup greeting.

    STAGE 2: this used to be argus.py's login_routine(), running in the parent.
    It cannot stay there any more -- the parent no longer has an output stream,
    and giving it one would mean two processes contending for the same audio
    device. So the greeting moved to the process that owns the speaker, and
    _generate_opener came with it rather than being reached back into argus.py
    for, which would have made the voice process import the launcher.

    Runs on its own thread so a slow Ollama warm-up can't delay the capture
    loop starting -- ARGUS should be listening before it finishes talking.
    Failure is swallowed: a greeting is not worth killing the listener over.
    """
    try:
        from skills import diagnostics, profile_skill

        health = diagnostics.quick_health()
        known = bool(profile_skill.profile_context())
        opener = _generate_opener(health, known)
        print(f"\n[{ASSISTANT_NAME.lower()}] {opener}\n")
        set_state("speaking")
        tts.speak(opener, PIPER_MODEL_PATH)
        set_state("standby")
    except Exception as e:
        print(f"[{ASSISTANT_NAME.lower()}] greeting skipped: {e}")


def _watch_parent():
    """Exits this process, and its workers with it, when the parent goes away.

    The voice process cannot be daemonic -- multiprocessing refuses to let a
    daemonic process have children, and this one owns the STT and TTS workers.
    So it needs its own answer to "the parent died without cleaning up", which
    is what daemon=True would otherwise have provided: a hard-killed argus.py
    (Task Manager, a crash) must not leave a process behind holding the
    microphone and two loaded models.

    parent_process().join() rather than polling os.getppid(): it is an
    OS-level handle, so it cannot be fooled by PID reuse.
    """
    import multiprocessing

    parent = multiprocessing.parent_process()
    if parent is None:
        return          # running listener.py directly; nothing to watch

    def watch():
        parent.join()
        print("[voice] parent process exited — shutting down")
        try:
            stop_workers()
        finally:
            # _exit rather than sys.exit: this is a daemon thread, so an
            # exception here would be swallowed and the process would linger
            # holding the audio device. The workers are already stopped.
            os._exit(0)

    threading.Thread(target=watch, name="parent-watchdog", daemon=True).start()


# How long to wait for the HUD to say it has finished waking before greeting
# anyway. ARGUS is a VOICE assistant -- the window is a nice-to-have and the
# microphone is the product -- so a HUD that never appears (headless, pywebview
# missing, the user never clicked to start the wake video) must not mean ARGUS
# is silent forever. Generous, because the wake clip plus a slow first paint
# genuinely takes a while on a cold start.
GREET_WAIT_FOR_HUD_S = 90.0


def run_voice_process(session_token: str = "", ready_event=None, greet: bool = True,
                      privacy_mirror=None, hud_awake=None):
    """Entry point for the voice process, and its own supervisor.

    REPLACES argus.py's importlib.reload(listener) restart loop. That loop
    recovered from a crash by re-importing this module in place, which rebound
    the globals but could not reclaim anything an in-flight thread still held
    -- so the previous incarnation's Whisper models stayed resident alongside
    the new ones, on a card with 4GB total. It also re-ran the CUDA DLL search
    on every restart, prepending to PATH each time.

    A crash here is now recovered by tearing the worker processes down and
    building them back up, which genuinely releases their memory because the
    OS reclaims it. The audio device is released too, by main()'s own finally.
    """
    ipc.line_buffer_output()
    set_session_token(session_token)
    _watch_parent()

    # Without this, _handle_segment's privacy check reads this process's own
    # untouched copy of privacy_skill._state and never sees a mute that
    # router.py set in the orchestrator -- ARGUS would report that it had
    # stopped listening and carry on transcribing. See skills/privacy_skill.py.
    if privacy_mirror is not None:
        from skills import privacy_skill
        privacy_skill.attach_mirror(*privacy_mirror)
        print("[privacy] mirror attached — mute state shared with orchestrator")
    else:
        print("[privacy] WARNING: no mirror — privacy mode will not reach this process")

    try:
        import psutil
        psutil.Process().nice(psutil.HIGH_PRIORITY_CLASS)
        print("[voice] process priority raised")
    except Exception as e:
        # Cosmetic-ish: without it the audio callbacks are merely at normal
        # priority, which is where they were before Stage 2 anyway.
        print(f"[voice] could not raise priority: {e}")

    backoff = 2
    greeted = False
    while True:
        try:
            if not start_workers():
                raise RuntimeError("speech recognition worker did not start")
            READY.set()
            if ready_event is not None:
                ready_event.set()
            if greet and not greeted:
                greeted = True      # first launch only, not after every restart
                # NOT started immediately. READY.set() above means the speech
                # workers are loaded, which is not the same as the interface
                # being awake -- greeting on it is what made ARGUS talk over
                # the wake video's narration, or speak before the window had
                # visibly opened at all. _greet_when_awake waits for the HUD
                # and falls back on a timer so a headless run still speaks.
                threading.Thread(target=_greet_when_awake,
                                 args=(hud_awake,), daemon=True).start()

            _run_loop()
            print(f"[{ASSISTANT_NAME.lower()}] voice listener exited cleanly — restarting")
        except Exception as e:
            print(f"[{ASSISTANT_NAME.lower()}] voice listener crashed: {e} — "
                  f"restarting in {backoff}s")
            import traceback
            traceback.print_exc()
        finally:
            READY.clear()
            busy.clear()
            stop_workers()

        time.sleep(backoff)
        backoff = min(backoff * 2, 30)


if __name__ == "__main__":
    # Running this module directly is still supported for debugging: the
    # orchestrator has to be up separately, and the token is read from the file
    # main.py publishes at startup.
    import multiprocessing

    multiprocessing.freeze_support()
    token = ""
    try:
        with open(security.token_path(), encoding="utf-8") as f:
            token = f.read().strip()
    except OSError:
        print("[voice] no published token — expect 401s from the orchestrator")
    run_voice_process(token, greet=False)
