"""
ARGUS - Text to speech: the PLAYBACK half.

Synthesis lives in tts_worker.py, in its own process. This module owns the
audio device and the buffer feeding it, and calls out to that worker for audio.

That boundary is deliberate and is the core of Stage 2. Synthesis is a
CPU-saturating ONNX graph; playback is a hard realtime deadline serviced by a
Python callback that has to take the GIL every buffer period. Running both in
one interpreter is what made Piper stutter under load. Playback cannot move --
it has to be where the device is -- so synthesis moved instead.

What is still in this process: the output stream, the ring buffer, stop(), and
the drain bookkeeping. What is not: PiperVoice, onnxruntime, and the 63MB model.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import threading
import time

import numpy as np
import sounddevice as sd

import ipc
import paths
import tts_worker

# The synthesis worker, and the API shape it reported at startup.
_client = None
_mode = None  # "chunks" | "wavfile" | "stream_raw" | "cli"

# Barge-in support. Blocking on playback made ARGUS impossible to interrupt
# mid-sentence — a long diagnostics readout couldn't be stopped. stop() now
# clears the ring buffer outright, so an interrupt takes effect within one
# PortAudio buffer rather than at the end of the current sentence.
_stop = threading.Event()
_speaking = threading.Event()


# ═══════════════════════════════════════════════════════════════════════
# PLAYBACK — one persistent output stream, fed by a ring buffer.
#
# WHAT THIS REPLACES, and why it was the direct cause of stuttering audio:
#
# Playback used to be one sd.play() call per synthesized sentence. sd.play()
# is not a "send these samples" call -- internally it runs
# _CallbackContext.start_stream(), which does (sounddevice.py:2662-2673):
#
#     stop()                      # stops AND CLOSES the previous stream
#     self.stream = OutputStream(...)
#     self.stream.start()
#
# So every sentence tore down and reopened the Windows audio device. Two
# distinct defects came out of that:
#
#   1. Device churn between sentences -- tens of milliseconds of open latency
#      each time, heard as a click or a gap at every sentence boundary.
#
#   2. Clipped sentence tails. sd.play() returns immediately; the samples are
#      still being drained by PortAudio afterwards. The old play_audio()
#      waited on a WALL-CLOCK deadline of exactly len(audio)/sample_rate and
#      then returned True -- but sounddevice's default latency is 'high'
#      (sounddevice.py:2158), so ~100-200ms of audio was still sitting in
#      PortAudio's buffer at that moment. The caller then played the next
#      chunk, sd.play() called stop() on the still-draining stream, and the
#      end of every single sentence was cut off mid-word.
#
# Now: one RawOutputStream is opened once and kept open for the session.
# Synthesized chunks are appended to a byte ring buffer, so sentences butt up
# against each other in one continuous stream with no device work in between.
# The callback does nothing but a buffer copy -- see _out_callback.
# ═══════════════════════════════════════════════════════════════════════

_OUT_BLOCK = 1024               # frames per callback (~46ms at 22050Hz)

_pcm_lock = threading.Lock()
_pcm_buf = bytearray()          # int16 mono PCM, at _out_rate
_out_stream = None
_out_rate = 22050
_out_open_lock = threading.Lock()

# Set by the audio callback the moment the ring buffer runs dry. Cleared by
# enqueue(), so it always means "everything handed over so far has been
# handed to the device" rather than "nothing is playing right now".
_drained = threading.Event()
_drained.set()


def _out_callback(outdata, frames, time_info, status):
    """Runs on PortAudio's realtime thread.

    Deliberately does nothing but a buffer copy: no numpy allocation, no
    synthesis, no logging, no print. Every Python object touched here costs
    GIL time this thread does not have, and missing this callback's deadline
    IS the glitch. (sounddevice installs a Python-level callback either way --
    see the closure sd.play() builds at sounddevice.py:178 -- so the only
    thing under our control is how little it does.)

    An underrun fills with silence rather than leaving the buffer undefined:
    a momentary gap while the next sentence is still synthesizing should be a
    pause, not a burst of noise.
    """
    need = frames * 2                      # int16 mono -> 2 bytes per frame
    with _pcm_lock:
        take = min(need, len(_pcm_buf))
        if take:
            outdata[:take] = _pcm_buf[:take]
            del _pcm_buf[:take]
        empty = not _pcm_buf
    if take < need:
        outdata[take:] = b"\x00" * (need - take)
    # is_set() is a plain attribute read with no lock; set() takes one and
    # notifies. Guarding the call keeps an idle stream from doing lock work
    # on every callback forever.
    if empty and not _drained.is_set():
        _drained.set()


def _open_output(sr: int):
    """Opens the session's one output stream, or reuses it.

    latency="high" on purpose. The whole problem being fixed here is the
    device not being fed in time under CPU load, and a larger PortAudio
    buffer is exactly the headroom that buys. The cost is that stop() leaves
    up to one buffer (~100-200ms) of already-committed audio playing after a
    barge-in, which is far less noticeable than the alternative.
    """
    global _out_stream, _out_rate
    with _out_open_lock:
        if _out_stream is not None and int(round(_out_stream.samplerate)) == sr:
            return
        if _out_stream is not None:
            try:
                _out_stream.stop()
                _out_stream.close()
            except Exception as e:
                print(f"[tts] could not close previous output stream: {e}")
            # Whatever is still queued was produced for the OLD rate. Playing
            # it through a stream opened at a different one would come out at
            # the wrong speed and pitch, so it goes.
            with _pcm_lock:
                if _pcm_buf:
                    print(f"[tts] rate change {int(_out_stream.samplerate)}Hz -> {sr}Hz, "
                          f"dropping {len(_pcm_buf) // 2} stale frames")
                    _pcm_buf.clear()
            _out_stream = None

        # BUGFIX: this used to assign _out_stream and then call .start()
        # outside any try. If the device was busy, unplugged, or the driver
        # hiccupped, .start() raised with _out_stream ALREADY assigned -- and
        # every later call hit the "same rate, reuse it" branch above and
        # returned immediately. ARGUS went mute for the rest of the session and
        # nothing ever retried. Left as None on failure so the next enqueue()
        # attempts a fresh open.
        try:
            stream = sd.RawOutputStream(
                samplerate=sr, channels=1, dtype="int16",
                blocksize=_OUT_BLOCK, latency="high", callback=_out_callback,
            )
            stream.start()
        except Exception as e:
            _out_stream = None
            print(f"[tts] could not open the audio device at {sr}Hz: {e}")
            raise

        _out_stream = stream
        _out_rate = sr
        print(f"[tts] output stream open at {sr}Hz "
              f"(latency {float(_out_stream.latency) * 1000:.0f}ms)")


def enqueue(audio: np.ndarray, sr: int):
    """Hands a synthesized chunk to the persistent stream and returns at once.

    This is what makes listener.execute()'s pipeline actually pipeline: the
    caller can queue sentence 2 while sentence 1 is still playing, and the two
    join seamlessly instead of the second one aborting the first.
    """
    if audio is None or len(audio) == 0:
        return
    _open_output(sr)
    _stop.clear()
    _speaking.set()
    _drained.clear()
    with _pcm_lock:
        _pcm_buf.extend(np.asarray(audio, dtype=np.int16).tobytes())


def queued_seconds() -> float:
    """How much unplayed audio is sitting in the ring buffer. Lets a producer
    apply backpressure against the BUFFER instead of against the device."""
    with _pcm_lock:
        return len(_pcm_buf) / 2.0 / float(_out_rate)


def wait_until_drained(timeout: float = 180.0) -> bool:
    """Blocks until everything enqueued has actually been played.

    Returns True if it all played, False if stop() cut it off (or the timeout
    expired). Only meaningful once the caller has finished enqueuing -- see
    listener.execute(), which calls this after its consume loop ends.
    """
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            if _stop.is_set():
                return False
            if _drained.wait(0.05):
                # The ring buffer is empty, but PortAudio still holds up to one
                # buffer of audio it hasn't played yet. Waiting that out is
                # precisely the step the old wall-clock deadline skipped, which
                # is why every sentence lost its last ~150ms.
                if _out_stream is not None:
                    time.sleep(float(_out_stream.latency))
                return not _stop.is_set()
        return False
    finally:
        _speaking.clear()


def stop():
    """Cuts off whatever is currently being spoken."""
    _stop.set()
    with _pcm_lock:
        _pcm_buf.clear()
    _speaking.clear()
    _drained.set()


def interrupted() -> bool:
    """True once stop() has cut off the current utterance, until the next
    enqueue() clears it. Lets a producer (listener.execute()) abandon a reply
    mid-stream without reaching into this module's private Event."""
    return _stop.is_set()


def is_speaking() -> bool:
    """True while audio is actually queued for the device.

    Derived from the ring buffer rather than from a flag a caller has to
    remember to clear: an early break out of execute()'s consume loop (a
    barge-in, a timeout) would otherwise leave this stuck True forever, and
    listener.py's barge-in check would keep burning Whisper passes on silence.
    """
    return _speaking.is_set() and not _drained.is_set()


# ═══════════════════════════════════════════════════════════════════════
# SYNTHESIS — delegated to tts_worker.py, in its own process.
# ═══════════════════════════════════════════════════════════════════════

# Generous: this covers a cold process spawn plus loading and probing a 63MB
# ONNX voice. It is only ever paid once, at startup.
INIT_TIMEOUT = 180.0

# A single sentence. Piper runs ~15x faster than real time on this hardware
# with two threads, so anything approaching this means the worker is wedged,
# not slow -- and listener.execute() should find that out in seconds rather
# than sitting on it for the whole 60s command budget.
SYNTH_TIMEOUT = 30.0


def init(model_path: str) -> str:
    """Starts the synthesis worker and waits for it to load the voice.

    Returns the API shape the worker settled on ("chunks", "stream_raw",
    "wavfile" or "cli"), same contract as before Stage 2 -- callers only ever
    checked it against "cli" to detect the slow path.
    """
    global _client, _mode

    # Resolve relative paths against the bundle, not the working directory —
    # otherwise this works as a script and silently fails once packaged. Done
    # HERE rather than in the worker so the worker receives an absolute path
    # and never has to reason about where it was started from.
    if not os.path.isabs(model_path):
        model_path = paths.resource(*model_path.replace("\\", "/").split("/"))

    if _client is not None:
        return _mode

    _client = ipc.WorkerClient(
        "tts", tts_worker.run, args=(model_path,), start_timeout=INIT_TIMEOUT)
    if not _client.start():
        print("[tts] synthesis worker failed to start — ARGUS will be silent.")
        _mode = None
        return _mode

    _mode = _client.info
    return _mode


def synthesize(text: str, model_path: str = ""):
    """Synthesizes text into a raw audio numpy array and sample rate without
    playing it. Returns (audio_np, sample_rate), or (None, None) on empty
    input or failure.

    model_path is accepted and ignored: the worker was given the resolved path
    at startup and holds the model open. The parameter stays so every existing
    call site keeps working unchanged.
    """
    if not text or not text.strip():
        return None, None
    if _client is None:
        print("[tts] synthesize() called before init()")
        return None, None
    try:
        raw, sr = _client.call(text, timeout=SYNTH_TIMEOUT)
    except ipc.WorkerError as e:
        # Non-fatal by design: one sentence goes unspoken and the caller moves
        # on. ipc.WorkerClient restarts a dead worker on its own, so the next
        # sentence usually succeeds.
        print(f"[tts] synthesis failed: {e}")
        return None, None
    if not raw or not sr:
        return None, None
    # np.frombuffer gives a read-only view onto the bytes that came off the
    # queue; copy so the array owns its memory and can be safely retained by
    # the ring buffer after this frame goes away.
    return np.frombuffer(raw, dtype=np.int16).copy(), sr


def shutdown():
    """Stops the synthesis worker. The output stream is left alone -- it costs
    nothing idle and reopening the device is exactly what Stage 1 removed."""
    global _client
    if _client is not None:
        _client.stop()
        _client = None


def play_audio(audio: np.ndarray, sr: int) -> bool:
    """Plays a pre-synthesized numpy audio array, blocking until it finishes.

    Kept for callers that genuinely want one self-contained utterance (speak()
    below, and listener._ack()). The pipelined voice path should use
    enqueue() + wait_until_drained() instead, so it can queue the next
    sentence while this one is still playing.

    Returns True if played to completion, False if interrupted or failed.
    """
    if audio is None or len(audio) == 0:
        return True
    try:
        enqueue(audio, sr)
    except Exception as e:
        print(f"[tts] playback failed: {e}")
        return False
    return wait_until_drained()


def speak(text: str, model_path: str):
    """Synthesizes and plays text. Interruptible — call stop() from another
    thread to cut it off. Silently no-ops on empty input."""
    audio, sr = synthesize(text, model_path)
    if audio is not None and sr:
        play_audio(audio, sr)

