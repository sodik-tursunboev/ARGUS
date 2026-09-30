"""
ARGUS - Speech synthesis worker process.

Holds the Piper ONNX session. This is the synthesis half of what used to be
tts.py; the playback half (the persistent output stream and its ring buffer)
deliberately stays in the voice process, because it owns the audio device and
must not be on the far side of a queue from it.

That split is the whole point. Synthesis is a CPU-saturating ONNX graph; the
playback callback is a hard realtime deadline. Running them in one process is
what produced the stuttering, and no amount of thread tuning fully fixes it --
Stage 1's PIPER_THREADS cap bought headroom, this removes the contention.

piper and onnxruntime are imported inside run(), not at module level: tts.py
imports this module to reference run() as a Process target, and a module-level
import would pull a 63MB ONNX model's runtime straight back into the audio
process.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import ipc


# How many cores Piper's ONNX session may use. Still capped even though Piper
# now has a process to itself -- isolation stops it competing for the GIL, not
# for cores, and the voice process's callbacks still need one.
PIPER_THREADS = 2


def _build(model_path: str):
    """Loads the voice and works out which Piper API shape this version uses.

    Piper's Python API changed shape across versions, and the CLI reloads the
    ONNX model from disk on every invocation (seconds per reply). Probing once
    here means the model loads once per process instead of once per reply.

    Returns (voice, mode) where mode is "chunks" | "stream_raw" | "wavfile" |
    "cli". A voice of None with mode "cli" means shelling out is all that is
    left.
    """
    import io
    import os
    import wave

    if not os.path.exists(model_path):
        print(f"[tts] voice model not found: {model_path}")
        return None, "cli"

    try:
        from piper import PiperVoice
        voice = PiperVoice.load(model_path)
    except Exception as e:
        print(f"[tts] Python API unavailable ({e}) — falling back to CLI.")
        return None, "cli"

    # Rebuild the session with a bounded thread pool. PiperVoice.load()
    # constructs its InferenceSession with a bare SessionOptions()
    # (piper/voice.py:193-197), which leaves intra_op_num_threads at 0 -- and
    # ONNX Runtime reads 0 as "size the pool to every physical core". PiperVoice
    # is a dataclass (piper/voice.py:101), so the session is simply
    # reassignable; there is no supported load() argument for this.
    #
    # Non-fatal: an unbounded session still synthesizes correctly, it just
    # competes for cores with the voice process. A voice that works badly beats
    # no voice at all, so this must not push us onto the CLI path.
    try:
        import onnxruntime
        so = onnxruntime.SessionOptions()
        so.intra_op_num_threads = PIPER_THREADS
        so.inter_op_num_threads = 1
        so.execution_mode = onnxruntime.ExecutionMode.ORT_SEQUENTIAL
        voice.session = onnxruntime.InferenceSession(
            model_path, sess_options=so, providers=["CPUExecutionProvider"])
        print(f"[tts] Piper ONNX session pinned to {PIPER_THREADS} thread(s).")
    except Exception as e:
        print(f"[tts] could not pin ONNX threads ({e}) — continuing unpinned.")

    def _probe_wavfile():
        buf = io.BytesIO()
        with wave.open(buf, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(22050)
            voice.synthesize("test", wf)

    for mode, probe in (
        ("chunks", lambda: list(voice.synthesize("test"))),
        ("stream_raw", lambda: b"".join(voice.synthesize_stream_raw("test"))),
        ("wavfile", _probe_wavfile),
    ):
        try:
            probe()
            print(f"[tts] Using Piper Python API ({mode}) — model cached in memory.")
            return voice, mode
        except Exception:
            continue

    print("[tts] No working Python API shape — falling back to CLI.")
    return None, "cli"


def _synth_chunks(voice, text: str):
    """New API: synthesize() yields AudioChunk objects."""
    parts = []
    sample_rate = 22050
    for chunk in voice.synthesize(text):
        if hasattr(chunk, "audio_int16_bytes"):
            parts.append(chunk.audio_int16_bytes)
            sample_rate = getattr(chunk, "sample_rate", sample_rate)
        elif isinstance(chunk, (bytes, bytearray)):
            parts.append(bytes(chunk))
    return b"".join(parts), sample_rate


def _synth_stream_raw(voice, text: str):
    """Older API: synthesize_stream_raw() yields raw PCM bytes."""
    raw = b"".join(voice.synthesize_stream_raw(text))
    sr = getattr(getattr(voice, "config", None), "sample_rate", 22050)
    return raw, sr


def _synth_wavfile(voice, text: str):
    """Mid-era API: synthesize() writes into a wave file object."""
    import io
    import wave

    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(22050)
        voice.synthesize(text, wf)
    buf.seek(0)
    with wave.open(buf, "rb") as wf:
        sr = wf.getframerate()
        raw = wf.readframes(wf.getnframes())
    return raw, sr


def _synth_cli(text: str, model_path: str):
    """Last resort: shell out. Reloads the model each call — slow but reliable.

    BUGFIX: the output file used to be the literal relative path "reply.wav",
    which lands in the CURRENT WORKING DIRECTORY. Two problems, both real:

      - In a PyInstaller build the working directory is the bundle, which is
        read-only. Every CLI synthesis would fail, so the fallback that exists
        precisely for when the Python API is unavailable was itself unusable
        exactly where it was most likely to be needed.
      - A fixed filename means two overlapping calls clobber each other's
        audio, and the file was never cleaned up.

    A private temporary file fixes all of it and costs nothing.
    """
    import os
    import subprocess
    import tempfile
    import wave

    fd, out_path = tempfile.mkstemp(prefix="argus-tts-", suffix=".wav")
    os.close(fd)
    try:
        result = subprocess.run(
            ["piper", "--model", model_path, "--output_file", out_path],
            input=text.encode("utf-8"),
            capture_output=True,
            # CREATE_NO_WINDOW, and it is not cosmetic. piper is a CONSOLE
            # program, and the shipped build is windowed -- so with no console
            # to inherit, Windows gives the child a brand new one. Every
            # sentence spoken through the CLI fallback flashed a black console
            # window on top of whatever the owner was doing. sandbox.py already
            # sets this for everything that goes through execpolicy; this path
            # bypasses execpolicy by design (it is worker plumbing, on
            # the direct-call allowlist) and so missed the flag
            # with it.
            creationflags=(subprocess.CREATE_NO_WINDOW
                           if os.name == "nt" else 0),
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.decode(errors="ignore"))
        with wave.open(out_path, "rb") as wf:
            return wf.readframes(wf.getnframes()), wf.getframerate()
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def run(req_q, resp_q, model_path: str):
    """Worker entry point.

    Request payload:  text (str)
    Reply:            (pcm_int16_bytes, sample_rate) — or (b"", 0) for input
                      that produced no audio, which is not an error.
    """
    # Before _build prints anything — see stt_worker.run for why.
    ipc.line_buffer_output()

    voice, mode = _build(model_path)

    def synthesize(text):
        if not text or not text.strip():
            return b"", 0
        if mode == "chunks":
            raw, sr = _synth_chunks(voice, text)
        elif mode == "stream_raw":
            raw, sr = _synth_stream_raw(voice, text)
        elif mode == "wavfile":
            raw, sr = _synth_wavfile(voice, text)
        else:
            raw, sr = _synth_cli(text, model_path)
        if not raw:
            return b"", 0
        return raw, sr

    ipc.serve(req_q, resp_q, synthesize, ready_info=mode)
