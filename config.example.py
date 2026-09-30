"""
ARGUS - Configuration template (copy to config.py before running)

The only file you need to edit.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

# ─── Identity ─────────────────────────────────────────────────────────
# ONE version, referenced everywhere it is shown.
#
# The HUD footer carried a hardcoded "BUILD 1.0.0" and nothing else knew the
# version at all, so the About panel and the footer could disagree the first
# time either was edited. Both read this now.
APP_VERSION = "1.4.3"

# ─── Authorship ───────────────────────────────────────────────────────
# The single source for who wrote this and when. LICENSE holds the GPL text
# verbatim -- it must, since modifying the licence text is not permitted --
# and the FSF copyright line inside it is the copyright on the LICENCE, not
# on ARGUS. So the copyright on the SOFTWARE is asserted here, repeated in
# every source file's SPDX header, and shown in the About panel.
COPYRIGHT_HOLDER = "Sodik Tursunboev"
COPYRIGHT_YEAR = "2026"
CREATED = "2026-09-01"
PROJECT_URL = "https://github.com/sodik-tursunboev/ARGUS"

ASSISTANT_NAME = "ARGUS"

# Phrases that wake it. Include likely mis-transcriptions — speech recognition
# will render "Argus" as "argos", "arcus", even "Marcus" depending on your
# accent and mic. Listing them costs nothing and dramatically improves how often
# it actually hears you.
# Deliberately does NOT include "marcus" — it was in this list and made "mars",
# "markets" and any Marcus-like word wake the assistant. Aliases must be words
# you'd never say by accident.
WAKE_WORDS = [
    "argus", "argos", "arcus", "arghus", "argis", "arguss", "arcos",
    "arves", "arbus", "arvus", "arbis",
    "hey argus", "hey argos", "hey arcus", "ok argus", "okay argus",
]

# Fuzzy match threshold (0-1). HIGHER = stricter.
# At 0.75, "argue" matched. 0.86 keeps genuine mishearings while rejecting
# ordinary speech. Raise it if ARGUS still wakes on its own.
WAKE_FUZZ = 0.86

# ─── Local AI (Ollama) ────────────────────────────────────────────────
OLLAMA_HOST = "http://localhost:11434"

# Two models, two jobs — measured on this machine, not a guess:
#
# OLLAMA_MODEL routes to skills AND handles conversation. Kept as a small,
# non-reasoning model on purpose. A "thinking" model (Qwen3, DeepSeek-R1, ...)
# sounds smarter but for free-form replies it drafts, second-guesses, and
# redrafts its answer internally before ever producing the sentence you
# actually hear — on this 4GB card that reasoning alone regularly ran past
# 600 tokens and STILL never reached a final answer, which either got read
# aloud as raw internal monologue or silently ate several extra seconds per
# reply for nothing. llama3.2:3b just answers.
#   ollama pull llama3.2:3b
OLLAMA_MODEL = "llama3.2:3b"

# OLLAMA_ROUTER_MODEL classifies "what skill/action does this command need"
# as forced JSON.
#
# THIS IS DELIBERATELY THE SAME MODEL AS OLLAMA_MODEL. It used to be qwen3:4b,
# on the reasoning that its extra capacity measurably beats llama3.2:3b at
# classification. That was true in isolation and false in situ: qwen3:4b
# (~2.5GB) and llama3.2:3b (~2GB) were BOTH being sent keep_alive="30m" (see
# ollama_client.py), and every LLM-routed command calls the router model and
# then immediately the chat model (router.py's handle_stream: chat_json ->
# brain.answer_stream). On this 4GB card, with Whisper small.en + tiny.en also
# resident, that is ~5.1GB of demand against 4GB, so Ollama was evicting and
# reloading a multi-gigabyte model on essentially every single command.
#
# That reload is the CPU/RAM spike, and it is also several seconds during
# which listener.py has `busy` set and is discarding the microphone. The
# original comment's real insight -- that JSON-grammar decoding forces the
# first token to "{" and structurally prevents the meandering-thought preamble
# -- is a property of format=json, not of qwen3, so it still holds here.
#

# is to restore qwen3:4b AND give json_mode calls keep_alive="0s" in
# ollama_client.py, trading a per-command reload for not evicting the chat
# model. Do not run both models resident with a long keep_alive again.
OLLAMA_ROUTER_MODEL = OLLAMA_MODEL

# Screen vision needs a separate multimodal model:
#   ollama pull moondream      (~1.7GB, light enough for 4GB cards)
VISION_MODEL = "moondream"

# ─── Cloud AI (optional, off by default) ───────────────────────────────
# General conversation ("what's the meaning of life") can go to a cloud
# model for speed. Anything touching real data about this machine or this
# user -- vault, profile, PC diagnostics, screen vision, process/anomaly
# analysis, or a follow-up to any of those -- ALWAYS stays on local Ollama
# above, with no exception this setting can override. See skills/cloud_gate.py
# for the actual enforcement; this block only controls whether the cloud
# path exists at all.
#
# Provider: Groq. Chosen because it's the one already integrated (and
# tested) elsewhere in this user's own projects, not cold-started here, and
# because its Services Agreement (section 4.2, console.groq.com/docs/legal/
# services-agreement) contractually prohibits training on API inputs/outputs
# without explicit customer permission, with no retention by default beyond
# a 30-day abuse/reliability exception -- checked directly against Groq's
# own current terms before picking it, not assumed.
#
# The key itself lives in config_secrets.py, which is gitignored and never
# committed (verified with `git check-ignore` before this file existed) --
# never put a real key directly in THIS file, which is tracked.
# Resolution order (see secrets_store.py): GROQ_API_KEY environment variable,
# then the DPAPI-encrypted store, then this plaintext file. The plaintext path
# still works so an existing install keeps running, but doctor.py now reports
# WHERE the key came from, so "still plaintext" is visible rather than silently
# permanent. Move it with:  python manage_secrets.py set-groq-key
try:
    from config_secrets import GROQ_API_KEY as _GROQ_FALLBACK
except ImportError:
    _GROQ_FALLBACK = ""   # missing config_secrets.py -> cloud stays off, not an error

try:
    import secrets_store
    GROQ_API_KEY = secrets_store.get_secret("GROQ_API_KEY", _GROQ_FALLBACK)
except Exception:
    GROQ_API_KEY = (_GROQ_FALLBACK or "").strip()

# llama-3.1-8b-instant was here and is RETIRED -- Groq returns
# 404 model_not_found for it. That failure was invisible: groq_client collapses
# every error into GroqUnavailable and brain.py falls back to the local model,
# so ARGUS still answered and looked like cloud routing was working. It never
# made a single successful cloud call.
#
# Measured against this account's actually-available models (GET /v1/models),
# three questions each:
#   openai/gpt-oss-120b   711ms mean, answered 3/3, no <think> leakage  <- this
#   openai/gpt-oss-20b    403, blocked at the project level
#   qwen/qwen3.8-27b      403, blocked at the project level
#   groq/compound-mini    403, blocked at the project level
#   allam-2-7b            403, blocked at the project level
#
# The 403s are a per-project model permission in the Groq console, not a
# billing limit -- enabling gpt-oss-20b there would give a smaller/faster
# option. Avoid the qwen3 reasoning models here regardless: they emit <think>
# blocks, and brain.py's STREAMING path cleans each sentence chunk
# independently, so a block spanning chunks would be spoken aloud.
GROQ_MODEL = "openai/gpt-oss-120b"

# ─── Second cloud tier: Google Gemini ─────────────────────────────────
# Groq is fastest (~174ms measured here) but its free tier is tight, and when
# it rate-limits, groq_client backs off for up to 60 seconds. Every question
# during that window used to fall all the way to the local model at ~2533ms.
#
# Gemini's free tier is far more generous per day at ~300-600ms -- slower than
# Groq, several times faster than local. It sits BETWEEN them, so a Groq rate
# limit costs a few hundred milliseconds instead of two and a half seconds.
#
# Same resolution order as the Groq key, and the same reason: environment
# variable, then the DPAPI-encrypted store, then plaintext. Set it with
#     python manage_secrets.py set-gemini-key
# Leaving it unset simply disables the tier -- the cascade is unchanged.
try:
    from config_secrets import GEMINI_API_KEY as _GEMINI_FALLBACK
except ImportError:
    _GEMINI_FALLBACK = ""

try:
    import secrets_store as _ss
    GEMINI_API_KEY = _ss.get_secret("GEMINI_API_KEY", _GEMINI_FALLBACK)
except Exception:
    GEMINI_API_KEY = (_GEMINI_FALLBACK or "").strip()

# CHOSEN BY MEASUREMENT on this account, five questions each through the real
# client. Do not change it without re-running that -- the first value here was
# "gemini-2.0-flash", picked from general knowledge, and it does not exist for
# this key at all.
#
#   gemini-3.1-flash-lite    831ms median, 0/5 failed, accepts thinkingBudget=0
#   gemini-3.5-flash-lite    802ms median, 0/5 failed, REJECTS thinkingBudget
#   gemini-3.6-flash        8679ms median, 3/5 failed  (thinks, and overloaded)
#   gemini-2.5-flash*         404 "no longer available to new users"
#
# 3.1-flash-lite over the marginally faster 3.5: it ACCEPTS thinkingBudget=0,
# so reasoning is definitively off and latency stays predictable. 3.5 rejects
# that field, which means thinking is on and a harder question can spike.
#
# Two traps worth knowing, both hit while setting this up:
#   - ListModels lists gemini-2.5-flash, which then 404s on use. Listing is
#     not availability; only a real generation call proves a model works.
#   - A wrong model id fails as a 404 -> GeminiUnavailable -> silent fallback
#     to local, exactly the way the retired llama-3.1-8b-instant did above.
#     `python manage_secrets.py status` now checks this explicitly.
GEMINI_MODEL = "gemini-3.1-flash-lite"

CLOUD_ENABLED = bool(GROQ_API_KEY.strip() or GEMINI_API_KEY.strip())

# ─── Speech ───────────────────────────────────────────────────────────
# Two models by design. The tiny one runs constantly to check whether you said
# the wake word (fast, cheap). The accurate one only runs on real commands.
WAKE_MODEL = "tiny.en"       # wake detection only — keep this small
WHISPER_MODEL = "small.en"   # actual commands — accuracy matters here

# Path is relative to this folder. Must match your downloaded .onnx filename.
PIPER_MODEL_PATH = "voices/en_GB-alan-medium.onnx"

# Set True to force CPU-only speech recognition even when a working CUDA GPU
# is present. Useful for isolating whether a transcription-quality problem
# (garbled output, wrong words) is GPU/driver-specific -- flip this on, see
# if it clears up, flip it back off.
FORCE_CPU_STT = False

# ─── Storage ──────────────────────────────────────────────────────────
VAULT_PATH = r"C:\ARGUS\vault"

# ─── Personal ─────────────────────────────────────────────────────────
USER_NAME = "Operator"
# Full name, used two ways that both need it spelled out: it is added to the
# Whisper command prompt so the recognizer has actually heard of it (an
# unprimed foreign proper noun comes back as an incorrect spelling with
# confidence low enough to trip MIN_CONFIDENCE and get "Sorry, say that
# again?"), and intent.py matches "who is <name>" against it phonetically so a
# respelling still routes to the local answer instead of a web search.
USER_FULL_NAME = ""  # Set only in your local config.py if needed.
DEFAULT_CITY = ""  # Set locally if weather and local time features are used.

# ─── Behaviour the settings panel can turn on and off ─────────────────
# These two are the SHIPPED defaults only. Their live state lives in the
# components that own it -- proactive_skill keeps a flag that privacy mode
# can also flip, and the answer cache reads ARGUS_NO_CACHE -- so settings.py
# reads those components rather than these values when reporting what is
# currently true. Without a default here at all, the panel had nothing to
# fall back on and rendered both switches OFF regardless of their real state.
PROACTIVE_ENABLED = True
ANSWER_CACHE_ENABLED = True

# ─── Authentication / lock ────────────────────────────────────────────
# ARGUS listens continuously while you are logged in, so the realistic threat
# is someone in earshot, a replayed recording, or a machine you walked away
# from -- not a remote attacker. See auth.py for the full threat model,
# including what this deliberately does NOT claim to stop.
#
# OFF by default. Turning it on means privileged commands (see auth.PRIVILEGED
# -- power, clipboard, dictation, screen, vault, profile, audit) require an
# unlock first; ordinary ones (weather, time, apps, volume, chat) never do.
AUTH_ENABLED = True

# Factors that must ALL pass to unlock. Available:
#   "pin"        the COMMAND_PIN above, checked as a salted hash
#   "os_account" the process must run as the enrolled Windows account
#                (bind it once with: python manage_secrets.py enroll-owner)
#   "liveness"   repeat a randomly chosen phrase -- defeats a recording,
#                because the phrase is chosen after any recording was made
AUTH_REQUIRED_FACTORS = ("pin", "os_account")
# 1.2.0: os_account added to the shipped default. It costs the user nothing at
# runtime (the process is already running as their account -- the check is
# binding, not a challenge) and it closes a real gap: with PIN alone, a second
# Windows account on a shared machine could unlock with a PIN they watched
# typed. auth.verify() still refuses a presence-only factor set, so this
# pairing can never unlock without the knowledge factor.
#
# "hardware" (TPM, see hwkey.py) and "liveness" (spoken challenge) remain
# opt-in additions; "face" stays opt-in as the second factor it is.

# ─── Zero trust (see zt.py) ───────────────────────────────────────────
# A dynamic session-trust score on top of the static level table. It can only
# REFUSE or demand a fresher unlock -- never allow -- and it is computed from
# security events only (auth outcomes, denials, detector findings), so nothing
# a model or a web page produces can move it. Off here leaves every static
# rule exactly as it was.
ZT_ENABLED = True

# Lock again after this long without talking to ARGUS. 30 minutes, not 5
# (owner, 2026-09-24: "every command asks for the PIN"). Walking away is still
# covered at once, not after the idle window: auth's watchdog locks the moment
# Windows locks (Win+L, lid, screensaver lock) and on resume from sleep.
AUTH_IDLE_LOCK_SECONDS = 1800

# Consecutive failures before the lockout timer starts biting, and the cap on
# how long it can grow. The cap exists because an unbounded backoff is a denial
# of service against the only person who will actually be sitting there.
AUTH_MAX_FAILURES = 5
AUTH_LOCKOUT_MAX_SECONDS = 900

# ─── Voice security (see voiceauth.py) ────────────────────────────────
# Push-to-talk for high-risk actions. An always-listening microphone is the
# weakness a voice assistant cannot design away: a command can be spoken by
# anyone in the room, by a television, or by a recording. Requiring a physical
# key to be HELD at the moment of confirmation means the person has to be at
# the keyboard, which nothing arriving over the audio path can forge.
#
# Off by default because it changes how the assistant feels to use, and an
# ambient assistant that suddenly demands a keypress reads as broken. Turn it
# on when the machine is somewhere other people can talk near it.
PUSH_TO_TALK_FOR_SENSITIVE = False
PUSH_TO_TALK_MIN_LEVEL = 3          # L3_CONFIRM and above
PUSH_TO_TALK_VK = 0x11              # VK_CONTROL

# Refuse an authentication utterance that looks like a played-back recording.
# Secondary to the liveness challenge, never a replacement for it -- see the
# calibration note in voiceauth.py for why its scope is deliberately narrow.
VOICE_REPLAY_DETECTION = True

# ─── Command authorization ────────────────────────────────────────────
# Required to confirm shutdown/restart/sleep/sign-out (see power_skill.py).
# A plain "yes" used to be enough -- but a speech recognizer that
# occasionally mishears is also the thing deciding whether to power off
# your machine, and anyone in the room could say "yes" too. This is set in
# plaintext the same way WAKE_WORDS/USER_NAME above are: the threat model
# here is "don't let a mishearing or a housemate trigger a shutdown", not
# "protect against someone who already has file access to this machine" --
# if they have that, ARGUS itself is already the smaller problem.
#
# Digits only. Empty means "not set up yet" -- shutdown/restart/sleep/
# sign-out will refuse to confirm at all (fail closed) and say so, rather
# than silently accepting anything or silently accepting nothing.
#
# Type it into the HUD's operator channel to confirm, don't say it out
# loud: a spoken PIN isn't very secret, and Whisper mishearing a digit
# would cause false rejections anyway.
# Stored as a SALTED HASH once migrated, not as the PIN itself. ARGUS never
# needs to know this value, only to check one against it, so keeping it
# readable bought nothing. A plaintext value here still works (verify_pin
# accepts both) so nothing breaks mid-upgrade; doctor.py reports which form is
# in use. Migrate with:  python manage_secrets.py set-pin
#
# Threat model is unchanged and worth restating: this stops a mishearing or
# someone in the room triggering a shutdown. It is not, and never was, a
# defence against someone who already has code execution as you.
COMMAND_PIN = ""  # Set locally with manage_secrets.py; never commit a PIN.
