"""
ARGUS - Ollama Client
Thin wrapper around your local Ollama instance. Nothing here ever leaves localhost.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import re

import requests
import route_trace
from config import OLLAMA_HOST, OLLAMA_MODEL, OLLAMA_ROUTER_MODEL, VISION_MODEL

_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.S)

# Replies are spoken aloud in 2-3 sentences by design (see brain.py's system
# prompt) -- 600 tokens of headroom just let an occasional response ramble
# far past that before naturally stopping. A long generation feels slow even
# when the model itself is fast; this caps wall-clock time regardless of
# whether the model would have wrapped up on its own.
CHAT_NUM_PREDICT = 180

# How long a ROUTING classification may take before it is abandoned and the
# question is simply answered. Generation keeps the full 90s -- a slow answer
# is still an answer -- but a slow routing decision is just silence.
ROUTING_TIMEOUT = 20


def _strip_thinking(content: str) -> str:
    """Reasoning models (Qwen3, DeepSeek-R1, ...) can leak their internal
    <think> block straight into message.content instead of the separate
    "thinking" field this client doesn't read — confirmed happening on this
    Ollama build even with think=False. Left unhandled, that block gets
    spoken aloud verbatim by TTS or breaks JSON parsing in the router.

    A closed block is cut out entirely. An UNCLOSED one means num_predict ran
    out mid-thought before any real answer appeared, so everything from
    "<think>" onward is discarded — the result is usually empty, which is
    correct: callers already treat an empty/too-short response as a signal to
    escalate (brain.py's Wikipedia/web cascade, router's chat fallback)
    rather than a real reply.
    """
    if "<think>" in content and "</think>" not in content:
        content = content.split("<think>", 1)[0]
    return _THINK_BLOCK.sub("", content).strip()


def _messages(system_prompt: str, user_message: str, history: list | None) -> list:
    """Builds the message list, keeping ONLY the keys Ollama's API defines.

    conversation_history's entries carry a third key, "tier" (see main.py's
    _finish_exchange), which exists purely so cloud_gate can tell which engine
    answered each exchange. Both callers here used to do a bare
    messages.extend(history), forwarding that tag to Ollama verbatim in every
    message of every request. filter_history_for_cloud() already strips it on
    the Groq path; nothing stripped it on the local one.
    """
    messages = [{"role": "system", "content": system_prompt}]
    for entry in (history or []):
        if isinstance(entry, dict) and entry.get("role") and entry.get("content"):
            messages.append({"role": entry["role"], "content": entry["content"]})
    messages.append({"role": "user", "content": user_message})
    return messages


def chat(system_prompt: str, user_message: str, history: list | None = None,
         json_mode: bool = False) -> str:
    """Sends a chat request to local Ollama and returns the raw text response.
    history: optional list of {"role": "user"/"assistant", "content": ...}."""
    messages = _messages(system_prompt, user_message, history)

    # Structured routing calls get the reasoning-capable router model; every
    # free-form call (conversation, summarisation, definitions...) gets the
    # fast direct one. See config.py for why they're different models.
    payload = {
        "model": OLLAMA_ROUTER_MODEL if json_mode else OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "keep_alive": "30m",
        # Disables Qwen3/DeepSeek-R1 style reasoning outright where Ollama
        # honours it; harmless no-op on models that don't have a "thinking"
        # mode. _strip_thinking() below is the backstop for when it leaks
        # through anyway.
        "think": False,
        "options": {
            # Routing needs determinism; conversation needs a little room.
            # Padded above the bare minimum so a reasoning model that ignores
            # think=False still has room to finish its <think> block AND the
            # real answer instead of getting cut off mid-thought.
            "temperature": 0.1 if json_mode else 0.6,
            "num_predict": 220 if json_mode else CHAT_NUM_PREDICT,
            "num_ctx": 4096,
        },
    }
    if json_mode:
        payload["format"] = "json"   # Ollama enforces valid JSON output

    # Routing gets a MUCH shorter deadline than conversation.
    #
    # Both used 90s. A classification that has not returned in twenty seconds
    # is not going to produce a useful routing decision, and while it runs the
    # person has had no reply at all -- measured at 92s for "what can you do
    # over my pc" before the request died with a ReadTimeout and nothing was
    # said. Ninety seconds of silence is indistinguishable from being ignored,
    # which is exactly what it was reported as. Generation keeps the long
    # deadline: a slow answer is still an answer.
    timeout = ROUTING_TIMEOUT if json_mode else 90
    # Counted by the request trace, so "how many model calls did that cost" and
    # "is the local model up" are facts read off real calls, not guesses.
    with route_trace.provider_call("ollama", payload["model"]):
        resp = requests.post(f"{OLLAMA_HOST}/api/chat", json=payload, timeout=timeout)
        resp.raise_for_status()
        content = resp.json()["message"]["content"]
    return _strip_thinking(content)


def chat_stream(system_prompt: str, user_message: str, history: list | None = None):
    """Streaming chat. The whole stream is ONE provider call as far as the request
    trace is concerned: counted when it starts, recorded when it ends or is
    closed. The behaviour itself is in _stream_raw()."""
    with route_trace.provider_call("ollama", OLLAMA_MODEL):
        yield from _stream_raw(system_prompt, user_message, history)


def _stream_raw(system_prompt: str, user_message: str, history: list | None = None):
    """Like chat(), but yields text as Ollama generates it instead of
    blocking for the full reply -- lets a caller start speaking the first
    sentence while the rest is still being generated.

    Always uses OLLAMA_MODEL (never the router model / json_mode) -- there's
    no structured-output use case for a token stream.

    <think> blocks are filtered out here too, same as _strip_thinking(), but
    incrementally: the opening/closing tags can land in different chunks, so
    this buffers across chunk boundaries rather than regexing each piece in
    isolation.
    """
    messages = _messages(system_prompt, user_message, history)

    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": True,
        "keep_alive": "30m",
        "think": False,
        "options": {"temperature": 0.6, "num_predict": CHAT_NUM_PREDICT, "num_ctx": 4096},
    }

    resp = requests.post(f"{OLLAMA_HOST}/api/chat", json=payload, timeout=90, stream=True)
    resp.raise_for_status()

    buf = ""
    in_think = False
    for line in resp.iter_lines():
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        buf += obj.get("message", {}).get("content", "")

        while buf:
            if in_think:
                end = buf.find("</think>")
                if end == -1:
                    buf = ""  # still inside the block -- discard, nothing to yield yet
                    break
                buf = buf[end + len("</think>"):]
                in_think = False
                continue
            start = buf.find("<think>")
            if start == -1:
                if buf:
                    yield buf
                buf = ""
                break
            if start > 0:
                yield buf[:start]
            buf = buf[start + len("<think>"):]
            in_think = True

        if obj.get("done"):
            break


def chat_json(system_prompt: str, user_message: str, history: list | None = None) -> dict:
    """Same as chat(), but requests structured output and parses it. Falls back
    to a chat response if parsing fails, so bad model output never crashes the
    orchestrator."""
    try:
        raw = chat(system_prompt, user_message, history, json_mode=True)
    except Exception as e:
        # A CLASSIFIER FAILURE MUST NOT BECOME A NON-ANSWER.
        #
        # This used to propagate. Ollama being slow, busy, or not running at
        # all meant the whole request died and the person got silence -- for
        # a question a language model could have answered immediately. The
        # only thing lost by falling through to chat is the chance to run a
        # skill, and that is a far better failure than saying nothing.
        print(f"[route] classifier unavailable ({e.__class__.__name__}); "
              f"answering directly")
        return {"skill": "chat", "action": "reply", "target": user_message}
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.startswith("json"):
            cleaned = cleaned[4:]
    try:
        return json.loads(cleaned.strip())
    except json.JSONDecodeError:
        return {"skill": "chat", "action": "reply", "target": raw, "reply": raw}


def chat_vision(system_prompt: str, user_message: str, image_b64: str) -> str:
    """Sends a request with an attached screenshot to a local VISION_MODEL (must be
    pulled separately in Ollama — a text-only model can't do this)."""
    with route_trace.provider_call("ollama", VISION_MODEL):
        resp = requests.post(
            f"{OLLAMA_HOST}/api/chat",
            json={
                "model": VISION_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message, "images": [image_b64]},
                ],
                "stream": False,
            },
            timeout=90,
        )
        resp.raise_for_status()
        content = resp.json()["message"]["content"]
    return content
