"""
ARGUS - Groq client (cloud, opt-in).

Deliberately shaped like ollama_client.py -- chat()/chat_stream() with the
same signature -- so brain.py's hybrid routing can call either one
interchangeably and the caller doesn't need to know which backend actually
answered. Plain requests, no groq SDK dependency, matching how
ollama_client.py already talks to Ollama over raw HTTP rather than pulling
in a client library for a single JSON-over-HTTPS endpoint.

This is the ONLY file in ARGUS that makes an outbound network call carrying
conversation content. Everything about what's allowed to reach it --
whether a given turn is cloud-eligible at all, and which history entries
are allowed in its payload -- is decided before this module is ever called
(see skills/cloud_gate.py and brain.py's history filtering). This module
itself does not and must not make that decision; it just makes the call
once it's already been cleared to.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import time

import requests

import route_trace
from config import GROQ_API_KEY, GROQ_MODEL
from skills import cloud_gate

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
TIMEOUT = 15  # cloud is chosen FOR speed -- a slow cloud call defeats its
              # own purpose, so this fails fast into the local fallback
              # rather than waiting as long as a local call reasonably might

# This used to be 220, mirroring ollama_client.CHAT_NUM_PREDICT on the logic
# that a spoken reply is 2-3 sentences so a bigger budget buys nothing.
#
# That logic does not survive a REASONING model. gpt-oss-120b spends
# completion tokens thinking before it emits a single word, and the budget
# covers both. Measured on one question at max_tokens=220:
#
#     reasoning_tokens 218 of 220  ->  the answer was EMPTY
#
# which surfaced as brain.py's "cloud stream unavailable: stream produced no
# content" and a silent fall back to the 4-second local model. The reply was
# not slow, it never existed.
MAX_TOKENS = 400

# The fix for the waste itself. Measured on the same question:
#
#     default effort  894ms  156 reasoning tokens  396 total  298-char answer
#     effort "low"    334ms   10 reasoning tokens  267 total  384-char answer
#
# Faster, a third fewer tokens against the per-minute budget, and a LONGER
# answer. There is no axis on which the default is better here -- this is a
# conversational assistant, not a maths tutor.
REASONING_EFFORT = "low"

# After a rate-limit response, skip Groq briefly rather than retrying every
# request into the same 429.
#
# The flat 120s this used to apply was 10-40x too long. Groq's own headers say
# exactly when the budget refills -- x-ratelimit-reset-tokens was observed at
# 2.9s, 6.3s, 8.9s -- so a blanket two-minute lockout turned a three-second
# pause into two minutes of every answer coming from the slow local model.
# The real reset is honoured now, with a floor and a ceiling.
COOLDOWN_MIN = 3.0
COOLDOWN_MAX = 60.0
COOLDOWN_FALLBACK = 15.0
_cooldown_until = 0.0


class GroqUnavailable(Exception):
    """Raised for any Groq failure -- network, auth, rate-limit, malformed
    response. Deliberately ONE exception type: the caller's job is just
    "fall back to local", not to branch on the specific reason, and
    collapsing every failure mode to one type is what makes that fallback
    impossible to accidentally skip for a failure mode nobody anticipated."""


def is_cooling_down() -> bool:
    return time.time() < _cooldown_until


def _refuse_if_local_only() -> None:
    """A request the routing policy marked local-only must never reach a hosted
    model, whatever called this. brain.py decides first and never gets here for
    one; this is the backstop for a path nobody thought of. Refusing looks like
    any other Groq failure (GroqUnavailable), so every caller's existing
    fall-back-to-local handling applies unchanged. See skills/cloud_gate.py."""
    try:
        cloud_gate.guard_egress("hosted model")
    except cloud_gate.LocalOnly as e:
        raise GroqUnavailable(str(e)) from e


def _parse_duration(text: str) -> float:
    """Groq expresses a reset as '2.985s', '1m30s', '12.817s'."""
    if not text:
        return 0.0
    total, num = 0.0, ""
    for ch in str(text):
        if ch.isdigit() or ch == ".":
            num += ch
            continue
        if not num:
            continue
        try:
            v = float(num)
        except ValueError:
            num = ""
            continue
        total += v * {"h": 3600, "m": 60, "s": 1, "d": 86400}.get(ch, 0)
        num = ""
    if num:                       # a bare number means seconds
        try:
            total += float(num)
        except ValueError:
            pass
    return total


def _activate_cooldown(resp=None):
    """Backs off for as long as Groq says it needs, not a fixed guess."""
    global _cooldown_until
    wait = 0.0
    if resp is not None:
        headers = getattr(resp, "headers", {}) or {}
        # retry-after is authoritative when present; otherwise the token
        # bucket's own reset is the number that actually matters, since TPM
        # is what a conversational workload hits first.
        for key in ("retry-after", "x-ratelimit-reset-tokens",
                    "x-ratelimit-reset-requests"):
            wait = _parse_duration(headers.get(key, ""))
            if wait > 0:
                break
    if wait <= 0:
        wait = COOLDOWN_FALLBACK
    wait = max(COOLDOWN_MIN, min(wait + 0.5, COOLDOWN_MAX))
    _cooldown_until = time.time() + wait
    print(f"[groq] rate limited — backing off {wait:.1f}s")


def _sanitize_error(exc: Exception) -> str:
    """A bounded, safe category -- never the raw exception text, which for
    an HTTP client can include request headers or the API key itself in a
    URL/auth error message. Same reasoning as security.py's redact(), just
    for this one outbound channel specifically."""
    text = str(exc).lower()
    if "429" in text or "rate" in text or "quota" in text:
        return "rate_limited"
    if "401" in text or "403" in text or "auth" in text or "api key" in text:
        return "authentication_failed"
    if "timeout" in text or "timed out" in text:
        return "timeout"
    return "provider_error"


def available() -> bool:
    return bool(GROQ_API_KEY.strip()) and not is_cooling_down()


def _payload(system_prompt: str, user_message: str, history: list | None,
             stream: bool, json_mode: bool = False) -> dict:
    messages = [{"role": "system", "content": system_prompt}]
    # Whatever the caller passes, only what fits MAX_CLOUD_CONTEXT travels, newest
    # first and as plain role/content -- enforced HERE, at the edge, so no caller
    # can forget it. See route_trace.trim_history.
    messages.extend(route_trace.trim_history(history))
    messages.append({"role": "user", "content": user_message})
    payload = {
        "model": GROQ_MODEL,
        "messages": messages,
        # Routing wants the same answer every time; conversation does not.
        "temperature": 0.0 if json_mode else 0.6,
        "max_tokens": route_trace.cap_output(320 if json_mode else MAX_TOKENS),
        "stream": stream,
        "reasoning_effort": REASONING_EFFORT,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    return payload


def chat(system_prompt: str, user_message: str, history: list | None = None,
         json_mode: bool = False) -> str:
    """Blocking call, returns the full reply text. Raises GroqUnavailable
    on any failure -- caller (brain.py) catches this and falls back to
    ollama_client.chat() rather than the exchange failing outright.

    json_mode asks the API to guarantee syntactically valid JSON. It exists so
    the ROUTING decision can run here instead of on the local model: routing
    on Ollama took up to 92 seconds and returned nothing, while the same
    decision here takes a fraction of a second. Nothing new leaves the
    machine -- cloud_gate.route_chat() still decides eligibility, and it is
    the same text the answer would have been generated from anyway.
    """
    _refuse_if_local_only()
    if not GROQ_API_KEY.strip():
        raise GroqUnavailable("no API key configured")
    if is_cooling_down():
        raise GroqUnavailable("cooling down after a recent rate limit")

    # PRIVACY WAS DECIDED ABOVE; COST IS DECIDED HERE, in that order, so a local-only
    # request is refused for being local-only and never for being over budget. One
    # user turn may make only so many hosted calls (route_trace.limits()), and when
    # the allowance is spent this raises GroqUnavailable like any other failure, so
    # brain moves on to the next tier or the local model with no new handling.
    with route_trace.provider_call("groq", GROQ_MODEL, refuse_with=GroqUnavailable):
        return _post(system_prompt, user_message, history, json_mode)


def _post(system_prompt: str, user_message: str, history: list | None,
          json_mode: bool) -> str:
    try:
        resp = requests.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
            json=_payload(system_prompt, user_message, history, stream=False,
                          json_mode=json_mode),
            timeout=TIMEOUT,
        )
        if resp.status_code == 429:
            _activate_cooldown(resp)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()
    except requests.exceptions.RequestException as e:
        raise GroqUnavailable(_sanitize_error(e)) from e
    except (KeyError, IndexError, ValueError) as e:
        raise GroqUnavailable("malformed response") from e


def chat_stream(system_prompt: str, user_message: str, history: list | None = None):
    """Like chat(), but yields text as Groq streams it -- matches
    ollama_client.chat_stream()'s shape so brain.py's streaming path can
    use either backend without its own logic caring which one it got.

    Raises GroqUnavailable if the connection can't even be established or
    the FIRST chunk fails -- once streaming has genuinely started and
    something breaks mid-stream, this yields what it has rather than
    discarding a partial reply the user may have already started hearing
    (TTS speaks sentence-by-sentence as chunks arrive, so a partial answer
    already spoken can't be un-said by raising after the fact).
    """
    _refuse_if_local_only()
    if not GROQ_API_KEY.strip():
        raise GroqUnavailable("no API key configured")
    if is_cooling_down():
        raise GroqUnavailable("cooling down after a recent rate limit")

    # The whole stream is ONE hosted call against the turn's allowance. Privacy
    # first (above), cost second (here) -- see chat().
    with route_trace.provider_call("groq", GROQ_MODEL, refuse_with=GroqUnavailable):
        yield from _stream_body(system_prompt, user_message, history)


def _stream_body(system_prompt: str, user_message: str, history: list | None):
    import json as _json

    try:
        resp = requests.post(
            GROQ_URL,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
            json=_payload(system_prompt, user_message, history, stream=True),
            timeout=TIMEOUT,
            stream=True,
        )
        if resp.status_code == 429:
            _activate_cooldown(resp)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise GroqUnavailable(_sanitize_error(e)) from e

    started = False
    try:
        for line in resp.iter_lines():
            if not line:
                continue
            raw = line.decode("utf-8", errors="ignore")
            if not raw.startswith("data: "):
                continue
            raw = raw[len("data: "):]
            if raw.strip() == "[DONE]":
                break
            try:
                obj = _json.loads(raw)
                piece = obj["choices"][0]["delta"].get("content", "")
            except (ValueError, KeyError, IndexError):
                continue
            if piece:
                started = True
                yield piece
    except requests.exceptions.RequestException as e:
        # A connection dropping MID-stream, after some chunks already went
        # out. Those chunks may already be speaking through TTS by the time
        # this fires (see this function's own docstring) -- ending the
        # generator here lets the caller treat what already arrived as the
        # complete-enough answer, rather than raising and turning an
        # already-partially-spoken reply into a hard error on top of it.
        # Only truly silent failures (caught below) still raise.
        print(f"[groq] stream interrupted mid-response: {_sanitize_error(e)}")

    if not started:
        raise GroqUnavailable("stream produced no content")
