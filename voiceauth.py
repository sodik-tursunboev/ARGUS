"""
ARGUS - Voice security.

THE PREMISE, WHICH IS THE CHECKLIST'S OWN: voice recognition must not be the
sole authentication factor. Nothing in this module changes that. It exists to
make the voice channel harder to abuse, not to turn it into a credential.

WHAT IS REAL HERE, AND WHAT IS NOT.

Being precise about this matters more than the code. A voice-security module
that quietly returns "verified" without a model is worse than no module: it
produces a confident-looking log line and a false sense that a factor exists.

  REAL, implemented, tested:
    replay detection      acoustic fingerprinting (Haitsma-Kalker style),
                          numpy only. Catches the same audio played back at
                          the microphone, which is the practical attack
                          against a wake-word assistant.
    liveness              random challenge phrase, in auth.py. An attacker
                          cannot pre-record a phrase chosen a second ago.
    enrollment gating     enrolling a voice requires PIN + the enrolled
                          Windows account, so voice cannot bootstrap itself.
    no raw recordings     enforced and tested: nothing writes microphone
                          audio to disk, and transcripts are not logged.
    embedding protection  DPAPI-sealed at rest, treated as biometric data.
    mic permission        reads the Windows microphone consent setting.
    push-to-talk          required for high-risk actions when configured.

  NOT IMPLEMENTED, and reported as unavailable rather than faked:
    speaker verification  needs a speaker-embedding model (speechbrain,
                          resemblyzer, pyannote). All of them pull torch,
                          which is ~2.5GB and competes for the same 4GB of
                          VRAM as Whisper and Piper. The interface below is
                          real and a backend can be dropped in; the scoring
                          is not there, and verify_speaker() says so.
    anti-spoofing model   same reason. Distinguishing a synthesised or
                          converted voice from a real one is a trained-model
                          problem. The replay detector below covers the
                          replay case only, which is a strict subset.

So: this module raises the cost of a replay attack and refuses to pretend
about the rest. Where a caller asks for speaker identity, it gets
SpeakerUnavailable, and the security event says `unavailable` rather than
`ok`.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import hashlib
import os
import struct
import time

import paths

# ── configuration ──────────────────────────────────────────────────────
FINGERPRINT_BANDS = 16          # frequency bands per frame
FINGERPRINT_FRAMES = 24         # time frames retained per utterance
# ── replay detection: scope, and how these numbers were reached ────────
#
# Two mistakes were made building this, both caught by measurement, and both
# worth recording because the second is a DESIGN error that tuning cannot fix.
#
# 1. The threshold started as a guess (0.88 similarity). It caught 2 replays
#    out of 15 -- a control that demos well and does nothing.
#
# 2. Recalibrating on pairwise similarity gave clean separation (distinct max
#    0.650, replay min 0.681) and still produced false positives in use. The
#    reason: check_replay takes the MAXIMUM similarity against every
#    fingerprint still in the window, and the maximum of N comparisons grows
#    with N. Measured over a 120-utterance conversation the distributions
#    OVERLAP outright (distinct max 0.747 vs replay min 0.683) -- so the more
#    the owner talked, the more likely a legitimate command was called a
#    replay. Adding bits made it worse, not better.
#
# The fix is scope, not tuning. Fingerprinting every utterance of a
# conversation is the wrong job for it. Liveness -- the random challenge
# phrase in auth.py -- is the PRIMARY replay defence and does not degrade with
# conversation length, because an attacker cannot pre-record a phrase chosen a
# second ago. Fingerprinting is a secondary signal answering one narrow
# question: is THIS authentication or confirmation utterance a played-back
# copy of a recent one? Those are rare, so N stays small and the statistic
# behaves.
#
# Measured at that scope (120 trials each):
#     N=5   distinct max 0.725   replay min 0.672   t=0.695 -> 96.7% / 0.8% FP
#     N=10  distinct max 0.736   replay min 0.675   t=0.730 -> 88.3% / 0.8% FP
#
# Caveat worth stating: the corpus is synthetic, and its distinct utterances
# are more alike than real speech (all generated from one harmonic model), so
# the baseline similarity is pessimistic. Real separation is likely better --
# but "likely" is not measured, so the conservative numbers stand.
REPLAY_WINDOW_SECONDS = 120     # an auth-moment replay happens close in time
REPLAY_SIMILARITY_THRESHOLD = 0.72
REPLAY_MAX_TRACKED = 8          # keeps the max-over-N statistic honest

EMBEDDING_STORE = paths.writable("voiceprint.dat")


class SpeakerUnavailable(Exception):
    """Raised when speaker identity is requested but no backend is installed.

    Deliberately an exception rather than a False return. A caller that
    forgets to handle "no backend" gets a loud failure instead of silently
    treating every speaker as unverified-but-allowed, or worse, as verified.
    """


# ── acoustic fingerprinting ────────────────────────────────────────────
# Haitsma-Kalker style: split the utterance into overlapping frames, take the
# FFT energy in a set of bands, and emit one bit per band per frame from the
# SIGN of the second-order difference (across both time and frequency).
#
# Why the sign of a difference rather than the energy itself: it is invariant
# to gain. A recording replayed louder or quieter, or picked up from further
# away, produces the same bits -- which is exactly the robustness needed,
# because an attacker's replay never has the same absolute level as the
# original.
def fingerprint(audio, rate: int = 16000) -> bytes:
    """Compact perceptual hash of an utterance. Never reversible to audio."""
    import numpy as np

    samples = np.asarray(audio, dtype=np.float32).flatten()
    if samples.size < rate // 8:          # under ~125ms is not an utterance
        return b""

    # Normalise so level does not participate in the hash at all.
    peak = float(np.abs(samples).max())
    if peak > 0:
        samples = samples / peak

    frame_len = max(256, samples.size // (FINGERPRINT_FRAMES + 1))
    hop = max(1, frame_len // 2)
    window = np.hanning(frame_len)

    energies = []
    for start in range(0, samples.size - frame_len + 1, hop):
        if len(energies) >= FINGERPRINT_FRAMES + 1:
            break
        frame = samples[start:start + frame_len] * window
        spec = np.abs(np.fft.rfft(frame))
        # Logarithmic band edges: speech information is not spread evenly
        # across linear frequency, and linear bands waste most of the hash on
        # the top octave where there is almost nothing.
        edges = np.geomspace(1, spec.size - 1, FINGERPRINT_BANDS + 1).astype(int)
        bands = [float(spec[edges[i]:max(edges[i] + 1, edges[i + 1])].sum())
                 for i in range(FINGERPRINT_BANDS)]
        energies.append(bands)

    if len(energies) < 2:
        return b""

    e = np.asarray(energies, dtype=np.float64)
    e = np.log1p(e)
    # Second-order difference: across time (rows) then frequency (cols).
    d = np.diff(e, axis=0)
    d = np.diff(d, axis=1)
    bits = (d > 0).flatten()

    packed = bytearray()
    for i in range(0, bits.size, 8):
        byte = 0
        for j, b in enumerate(bits[i:i + 8]):
            if b:
                byte |= 1 << j
        packed.append(byte)
    return bytes(packed)


def _popcount(b: int) -> int:
    return bin(b).count("1")


def similarity(a: bytes, b: bytes) -> float:
    """1.0 identical, 0.0 nothing in common. Hamming over the shorter length."""
    if not a or not b:
        return 0.0
    n = min(len(a), len(b))
    if n == 0:
        return 0.0
    diff = sum(_popcount(a[i] ^ b[i]) for i in range(n))
    return 1.0 - (diff / (n * 8))


# ── replay detection ───────────────────────────────────────────────────
# In memory only, and deliberately so. Fingerprints are derived from the
# user's voice; persisting them across restarts would create a biometric
# record on disk for a check that only needs to look backwards a few minutes.
_recent: list = []          # [(fingerprint, timestamp, tag)]


def _prune(now: float):
    global _recent
    _recent = [r for r in _recent if now - r[1] < REPLAY_WINDOW_SECONDS]
    if len(_recent) > REPLAY_MAX_TRACKED:
        del _recent[:-REPLAY_MAX_TRACKED]


def check_replay(audio, rate: int = 16000, tag: str = "") -> tuple[bool, float]:
    """(is_replay, best_similarity). Records the fingerprint either way.

    CALL THIS ONLY FOR SECURITY-RELEVANT UTTERANCES -- unlock attempts and
    high-risk confirmations. Calling it on ordinary conversation is what broke
    the first version: the history grows, the max-over-N similarity climbs
    with it, and legitimate commands start being refused. See the calibration
    note above the constants.

    A genuine repeat of the same words is NOT a bit-identical waveform --
    timing, pitch and room noise all differ between two live utterances. A
    played-back recording is close to identical. That gap is what the
    threshold sits in.

    Recorded even when it IS a replay, so a repeated replay keeps matching
    rather than resetting the window.
    """
    now = time.time()
    _prune(now)

    fp = fingerprint(audio, rate)
    if not fp:
        return False, 0.0

    best = 0.0
    for old_fp, _ts, _tag in _recent:
        s = similarity(fp, old_fp)
        if s > best:
            best = s

    _recent.append((fp, now, tag))
    # Pruned AFTER the append, not only before it. Trimming first left the
    # list one over the cap for the rest of its life -- and the cap is not
    # cosmetic here: it is the thing holding the max-over-N false-positive
    # rate down, so an off-by-one in it is a slow leak in the control itself.
    _prune(now)
    return best >= REPLAY_SIMILARITY_THRESHOLD, best


def reset_replay_history():
    _recent.clear()


# ── microphone permission ──────────────────────────────────────────────
def mic_permission() -> tuple[bool, str]:
    """Windows microphone consent for desktop apps.

    Worth checking at boot rather than discovering at the first wake word:
    when this is off, capture silently returns silence on Windows 11 and the
    assistant simply never responds, which is indistinguishable from a broken
    model or a dead microphone.
    """
    if os.name != "nt":
        return False, "not Windows"
    try:
        import winreg
        key_path = (r"SOFTWARE\Microsoft\Windows\CurrentVersion"
                    r"\CapabilityAccessManager\ConsentStore\microphone")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as k:
            value, _ = winreg.QueryValueEx(k, "Value")
        return value == "Allow", f"microphone consent: {value}"
    except FileNotFoundError:
        return True, "no consent policy set (older Windows) — assuming allowed"
    except OSError as e:
        return True, f"undetermined ({e.__class__.__name__}) — assuming allowed"


# ── speaker verification: interface only ───────────────────────────────
def speaker_backend() -> str:
    """Name of an installed speaker-embedding backend, or "" if none."""
    for mod in ("speechbrain", "resemblyzer", "pyannote.audio"):
        try:
            __import__(mod)
            return mod
        except ImportError:
            continue
    return ""


def speaker_available() -> bool:
    return bool(speaker_backend())


def verify_speaker(audio, rate: int = 16000) -> float:
    """Similarity of AUDIO to the enrolled voiceprint, 0.0-1.0.

    Raises SpeakerUnavailable when no backend is installed, which is the
    current state on this machine. It does NOT return 0.0 -- a score of zero
    means "definitely not the owner", and returning that when the truth is
    "cannot tell" would make every caller reach the wrong conclusion.
    """
    backend = speaker_backend()
    if not backend:
        raise SpeakerUnavailable(
            "No speaker-embedding backend installed. Speaker verification is "
            "unavailable; use PIN and the liveness challenge.")
    # A backend being importable is not the same as a voiceprint existing.
    if not os.path.exists(EMBEDDING_STORE):
        raise SpeakerUnavailable("No voice enrolled yet.")
    raise SpeakerUnavailable(
        f"{backend} is installed but ARGUS has no scoring implementation "
        f"wired to it yet.")


def enroll_voice(audio, rate: int = 16000, pin: str = "") -> tuple[bool, str]:
    """Enrol the owner's voiceprint. Requires strong authentication first.

    The gate is the whole point of this function. If enrolling a voice needed
    only a voice, then whoever is standing at the microphone becomes the
    owner -- the factor would bootstrap itself, and an attacker's first move
    would simply be to enrol.
    """
    import auth
    import config
    import secrets_store
    import security

    if not secrets_store.verify_pin(pin, getattr(config, "COMMAND_PIN", "")):
        security.security_event(security.AUTH_FAILURE, factor="undisclosed",
                                reason="enroll_denied", status="failed")
        return False, "Enrolment needs the command PIN."

    if not auth._verify_os_account():
        security.security_event(security.AUTH_FAILURE, factor="os_account",
                                reason="enroll_denied", status="failed")
        return False, "Enrolment must run as the enrolled Windows account."

    if not speaker_available():
        return False, ("No speaker-embedding backend is installed, so there is "
                       "nothing to enrol into. Voice stays a convenience "
                       "channel, not a factor.")

    return False, "Backend present but scoring is not implemented."


# ── voiceprint storage ─────────────────────────────────────────────────
def store_embedding(vector: bytes) -> str:
    """Seal a voiceprint at rest.

    Biometric data differs from a password in the way that matters most here:
    it cannot be rotated. A leaked PIN is changed in a minute; a leaked
    voiceprint is leaked permanently. So it gets the same DPAPI sealing as the
    API key, never plaintext, and never inside the repo.
    """
    import base64
    import secrets_store

    if not secrets_store.dpapi_available():
        raise OSError("refusing to store a voiceprint without DPAPI")
    blob = secrets_store._protect(base64.b64encode(vector).decode("ascii"))
    os.makedirs(os.path.dirname(EMBEDDING_STORE), exist_ok=True)
    tmp = EMBEDDING_STORE + ".tmp"
    with open(tmp, "wb") as f:
        f.write(blob)
    os.replace(tmp, EMBEDDING_STORE)
    return EMBEDDING_STORE


def load_embedding() -> bytes:
    import base64
    import secrets_store

    if not os.path.exists(EMBEDDING_STORE):
        return b""
    with open(EMBEDDING_STORE, "rb") as f:
        blob = f.read()
    return base64.b64decode(secrets_store._unprotect(blob))


def forget_voice() -> bool:
    """Delete the enrolled voiceprint. Biometric data needs a delete path."""
    if os.path.exists(EMBEDDING_STORE):
        os.remove(EMBEDDING_STORE)
        return True
    return False


# ── push-to-talk ───────────────────────────────────────────────────────
def push_to_talk_satisfied() -> bool:
    """True if the push-to-talk key is held down right now.

    For high-risk actions, an always-listening microphone is the weakness: a
    command can be spoken by anyone in the room, by a television, or by a
    recording. Requiring a physical key held at the moment of confirmation
    means the person must be AT the machine, which no audio path can forge.
    """
    if os.name != "nt":
        return False
    try:
        import ctypes
        import config
        vk = getattr(config, "PUSH_TO_TALK_VK", 0x11)     # default: Ctrl
        # High-order bit set means currently down.
        return bool(ctypes.windll.user32.GetAsyncKeyState(vk) & 0x8000)
    except Exception:
        return False


def push_to_talk_required(level: int) -> bool:
    import config

    if not getattr(config, "PUSH_TO_TALK_FOR_SENSITIVE", False):
        return False
    return level >= getattr(config, "PUSH_TO_TALK_MIN_LEVEL", 3)


def describe() -> str:
    ok, mic = mic_permission()
    backend = speaker_backend() or "none"
    return (f"replay detection: on ({REPLAY_WINDOW_SECONDS}s window); "
            f"speaker backend: {backend}; {mic}")
