"""
ARGUS - Speech recognition worker process.

Holds the two Whisper models and nothing else. Runs as its own process so that
CTranslate2's thread pool and the microphone's PortAudio callback are no longer
in the same interpreter -- see ipc.py for why that mattered more than the
thread caps alone.

Everything here was lifted out of listener.py unchanged in behaviour:
  - the CUDA DLL search that has to happen before faster_whisper is imported
  - _load_model's throwaway inference, which is the only reliable way to find
    out whether CUDA actually works (constructing WhisperModel(device="cuda")
    succeeds even when the libraries are missing, because ctranslate2 resolves
    them lazily and only fails on the FIRST transcription)
  - the gain normalization and the confidence calculation

What is NOT here: the wake-word matching, the interrupt-phrase matching, and
the debug logging. Those are decisions about what a transcription MEANS, they
are cheap, and they belong next to the state machine that acts on them.

faster_whisper is imported inside run(), not at module level. listener.py has
to import this module to reference run() as a Process target, and a module-level
import would pull ctranslate2 and the CUDA runtime straight back into the audio
process -- exactly what this file exists to prevent.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os

import ipc

_HERE = os.path.dirname(os.path.abspath(__file__))

# Cores CTranslate2 may use on the CPU fallback path. Kept even though the
# models now have a process to themselves: process isolation stops these
# threads competing for the GIL, it does not stop them competing for CORES with
# the voice process's audio callbacks.
STT_CPU_THREADS = 2

SAMPLE_RATE = 16000


def _add_cuda_dlls():
    """Must run BEFORE faster_whisper is imported — ctranslate2 resolves CUDA
    DLLs lazily. Checks several plausible locations rather than assuming one
    venv layout.

    Note this now runs once per worker PROCESS. In the old design it ran again
    on every importlib.reload(listener) crash-restart, prepending the same
    directories to PATH each time and growing the environment without bound.
    """
    import glob
    import site

    roots = [os.path.join(_HERE, "venv", "Lib", "site-packages")]
    try:
        roots.extend(site.getsitepackages())
    except Exception:
        pass
    roots.append(os.path.dirname(os.path.dirname(os.__file__)) + os.sep + "site-packages")

    found = []
    for root in roots:
        for sub in ("cublas", "cudnn"):
            d = os.path.join(root, "nvidia", sub, "bin")
            if os.path.isdir(d) and d not in found:
                found.append(d)

    for d in found:
        os.environ["PATH"] = d + os.pathsep + os.environ["PATH"]
        try:
            os.add_dll_directory(d)
        except (AttributeError, OSError):
            pass

    has_cublas = any(glob.glob(os.path.join(d, "cublas64_*.dll")) for d in found)
    return found, has_cublas


def _load_model(WhisperModel, np, name: str, prefer_gpu: bool):
    """Loads a Whisper model, verifying the GPU actually works before trusting it.

    BUGFIX (carried over from listener.py): constructing WhisperModel(device=
    "cuda") succeeds even when the CUDA libraries can't be loaded — ctranslate2
    resolves them lazily, so the failure surfaces on the FIRST TRANSCRIPTION
    instead. Wrapping only the constructor in try/except meant the CPU fallback
    never fired, and the first thing you said crashed the listener thread with
    'cublas64_12.dll is not found'. So we run a throwaway inference here and
    treat that as the real test.
    """
    if prefer_gpu:
        try:
            m = WhisperModel(name, device="cuda", compute_type="float16",
                             num_workers=1)
            probe = np.zeros(SAMPLE_RATE, dtype=np.float32)   # 1s of silence
            list(m.transcribe(probe, language="en", beam_size=1)[0])
            return m, True
        except Exception as e:
            print(f"[stt] GPU unusable for {name}: {type(e).__name__}")
            if "cublas" in str(e).lower() or "cudnn" in str(e).lower():
                print("[stt] CUDA libraries missing. To enable GPU:")
                print("      pip install nvidia-cublas-cu12 nvidia-cudnn-cu12")
            print("[stt] falling back to CPU — slower, but it works.")

    m = WhisperModel(name, device="cpu", compute_type="int8",
                     cpu_threads=STT_CPU_THREADS, num_workers=1)
    return m, False


def _normalize(np, audio):
    """Gain normalization. A quiet mic is one of the largest causes of
    misrecognition — Whisper is far more accurate on a well-levelled signal.

    The empty-input guard is not hypothetical: np.abs(f).max() on a zero-length
    array raises "zero-size array to reduction operation maximum which has no
    identity". The listener's own length checks make that hard to reach today,
    but this runs in a worker process whose only job is to answer requests, and
    a crash here costs a whole utterance plus a traceback for what should be a
    trivially empty result.
    """
    f = (audio.astype(np.float32) / 32768.0).flatten()
    if f.size == 0:
        return f
    peak = float(np.abs(f).max())
    if peak > 0.01:
        f = f * (0.90 / peak)
    return f


def run(req_q, resp_q, wake_model_name: str, command_model_name: str,
        force_cpu: bool, whisper_prompt: str, wake_prompt: str = ""):
    """Worker entry point. Loads both models, then serves transcriptions.

    Request payload:  (tag, audio_int16_bytes)   tag is "wake" or "cmd"
    Reply:            (text, confidence, duration_s)
    """
    # Before anything prints: model loading is the slowest and most
    # diagnostically useful part of startup, and it all happens before
    # ipc.serve() gets a chance to set this up itself.
    ipc.line_buffer_output()

    cuda_dirs, has_cublas = _add_cuda_dlls()

    import numpy as np
    from faster_whisper import WhisperModel

    if cuda_dirs and not has_cublas:
        print("[stt] nvidia packages found but no cublas DLL — expect CPU mode.")
    if force_cpu:
        print("[stt] FORCE_CPU_STT=True in config.py — running Whisper on CPU only.")

    print(f"[stt] loading wake detection ({wake_model_name})...")
    wake_model, gpu = _load_model(WhisperModel, np, wake_model_name,
                                  prefer_gpu=has_cublas and not force_cpu)

    print(f"[stt] loading command recognition ({command_model_name})...")
    command_model, _ = _load_model(WhisperModel, np, command_model_name,
                                   prefer_gpu=gpu)
    device = "GPU" if gpu else "CPU"
    print(f"[stt] running on {device}")

    def transcribe(payload):
        tag, raw = payload
        audio = np.frombuffer(raw, dtype=np.int16)
        duration_s = len(audio) / SAMPLE_RATE

        if tag == "wake":
            # initial_prompt biases Whisper's decoder toward these tokens. The
            # wake pass had NONE, which is why tiny.en kept producing "Argyz",
            # "Argaz", "Arges" for a clearly-spoken "Argus": a proper noun it
            # has no reason to expect, decoded greedily at beam_size=1, on a
            # ~1.5s clip. The command pass has had a prompt all along -- this
            # is the pass that decides whether ARGUS responds AT ALL, and it
            # was the one flying blind.
            #
            # Kept short on purpose: a long prompt costs decode time on the
            # pass that runs on every utterance near the machine, and only the
            # name actually needs biasing here.
            model, kwargs = wake_model, {
                "beam_size": 1,
                "initial_prompt": wake_prompt,
            }
        else:
            model, kwargs = command_model, {
                "beam_size": 5,
                "initial_prompt": whisper_prompt,
                "no_speech_threshold": 0.6,
                "log_prob_threshold": -1.0,
            }

        segments, _ = model.transcribe(
            _normalize(np, audio),
            language="en",
            vad_filter=False,
            condition_on_previous_text=False,
            temperature=0.0,
            **kwargs,
        )

        parts, logprobs = [], []
        for s in segments:
            parts.append(s.text)
            if getattr(s, "avg_logprob", None) is not None:
                logprobs.append(s.avg_logprob)

        text = " ".join(parts).strip()
        confidence = 1.0
        if logprobs:
            avg = sum(logprobs) / len(logprobs)
            confidence = max(0.0, min(1.0, (avg + 1.2) / 1.1))
        return text, confidence, duration_s

    ipc.serve(req_q, resp_q, transcribe, ready_info=device)
