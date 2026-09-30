"""
ARGUS - Google Gemini client. The SECOND cloud tier.

WHY A SECOND CLOUD PROVIDER AT ALL.

Measured on this machine: Groq answers in ~174ms, the local model in ~2533ms.
That 14x gap is the entire reason the cloud path exists. But Groq's free tier
is tight, and when it rate-limits, groq_client goes into a cooldown of up to
60 seconds -- during which every question fell all the way through to Ollama
and got slow.

Gemini's free tier allows far more requests per day at ~300-600ms. Slower than
Groq, still several times faster than local. So the cascade becomes:

    Groq (fastest)  ->  Gemini (when Groq is limited)  ->  Ollama (offline)

and a rate limit costs a few hundred milliseconds instead of two and a half
seconds. Gemini is never tried first: Groq is faster, and burning the more
generous quota while the faster provider is available would be backwards.

DELIBERATELY SHAPED LIKE groq_client.py -- available()/chat()/chat_stream()
with the same cooldown behaviour and the same single exception type, so
brain.py's cascade treats the two identically and no caller has to know which
provider answered.

TWO THINGS GEMINI DOES DIFFERENTLY, both of which have bitten this project
before in another form:

  1. The API key goes in the x-goog-api-key HEADER, not in the URL. Gemini
     accepts ?key=... as a query parameter and most examples use it -- which
     writes the key into every proxy log, every error message containing the
     URL, and any crash report. A secret does not belong in a URL.

  2. The 2.5-series models "think" before answering, and that thinking is
     billed against maxOutputTokens. This is exactly the failure already found
     with Groq's gpt-oss-120b, where reasoning consumed 218 of a 220-token
     budget and the answer came back EMPTY. thinkingBudget is pinned to 0 in
     _payload() for the same reason: this is a voice assistant, and a thinking
     model that returns nothing is worse than a fast model that returns
     something.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import re
import time

import requests

import route_trace
from config import GEMINI_API_KEY, GEMINI_MODEL
from skills import cloud_gate

API_ROOT = "https://generativelanguage.googleapis.com/v1beta/models"

# Same reasoning as groq_client's: cloud is chosen FOR speed, so a slow cloud
# call defeats the point and should fail over rather than hang.
TIMEOUT = 15
MAX_TOKENS = 400

# Cooldown after a rate limit, identical in shape to groq_client's so the two
# tiers behave predictably together.
COOLDOWN_MIN = 3.0
COOLDOWN_MAX = 60.0
COOLDOWN_FALLBACK = 15.0
_cooldown_until = 0.0


class GeminiUnavailable(Exception):
    """Raised for any Gemini failure -- network, auth, rate-limit, malformed
    response. One exception type on purpose: the caller's only job is to fall
    through to the next tier, and branching on the reason would just be a way
    to get that wrong."""


def is_cooling_down() -> bool:
    return time.time() < _cooldown_until


def _refuse_if_local_only() -> None:
    """A request the routing policy marked local-only must never reach a hosted
    model, whatever called this. Same backstop, same shape, as groq_client's:
    the refusal is a GeminiUnavailable, so every caller's existing fall-through
    handling applies unchanged. See skills/cloud_gate.py."""
    try:
        cloud_gate.guard_egress("hosted model")
    except cloud_gate.LocalOnly as e:
        raise GeminiUnavailable(str(e)) from e


def _parse_duration(text: str) -> float:
    """Seconds from a retry-after style value. Accepts a bare number or an
    ISO-8601-ish '30s' / '1m30s'."""
    import re

    if not text:
        return 0.0
    text = str(text).strip().lower()
    try:
        return float(text)
    except ValueError:
        pass
    total = 0.0
    for num, unit in re.findall(r"([\d.]+)\s*(ms|s|m|h)?", text):
        try:
            v = float(num)
        except ValueError:
            continue
        total += {"ms": v / 1000, "s": v, "m": v * 60, "h": v * 3600}.get(unit or "s", v)
    return total


def _activate_cooldown(resp=None):
    global _cooldown_until
    wait = 0.0
    if resp is not None:
        headers = getattr(resp, "headers", {}) or {}
        for key in ("retry-after", "x-ratelimit-reset-requests"):
            wait = _parse_duration(headers.get(key, ""))
            if wait > 0:
                break
        if wait <= 0:
            # Gemini reports the retry delay inside the error body rather than
            # a header. Read it if it is there; guess only if it is not.
            try:
                for d in resp.json().get("error", {}).get("details", []):
                    if "retryDelay" in d:
                        wait = _parse_duration(d["retryDelay"])
                        break
            except (ValueError, AttributeError, TypeError):
                pass
    if wait <= 0:
        wait = COOLDOWN_FALLBACK
    wait = max(COOLDOWN_MIN, min(wait + 0.5, COOLDOWN_MAX))
    _cooldown_until = time.time() + wait
    print(f"[gemini] rate limited — backing off {wait:.1f}s")


def _sanitize_error(exc: Exception, status: int | None = None) -> str:
    """A bounded category, never the raw exception text.

    An HTTP client's exception string can carry the full request URL, and for
    an API whose examples put the key in the query string that is a live way
    to leak it into a log. Categories only -- same rule as groq_client.

    THE STATUS CODE IS CHECKED FIRST, and that is not a stylistic preference.
    Matching on the message substring "rate" classified EVERY error from this
    API as a rate limit, because the endpoint is called generateContent --
    "gene(rate)Content". A 404 for a retired model therefore reported as
    rate_limited and put the tier into a 60-second cooldown, over and over,
    for a condition that would never resolve. The word-boundary patterns below
    are the fallback for when no status code is available.
    """
    if status is not None:
        if status == 429:
            return "rate_limited"
        if status in (401, 403):
            return "authentication_failed"
        if status == 404:
            return "model_not_found"
        if status == 400:
            return "bad_request"
        if status in (500, 502, 503, 504):
            return "provider_overloaded"

    text = str(exc).lower()
    if re.search(r"\b429\b|rate[ _-]?limit|quota|resource_exhausted", text):
        return "rate_limited"
    if re.search(r"\b40[13]\b|unauthori|permission_denied|api[ _-]?key", text):
        return "authentication_failed"
    if re.search(r"\b404\b|not[ _-]?found", text):
        return "model_not_found"
    if "timeout" in text or "timed out" in text:
        return "timeout"
    return "provider_error"


def available() -> bool:
    return bool((GEMINI_API_KEY or "").strip()) and not is_cooling_down()


def _headers() -> dict:
    # The key is a HEADER. See the module docstring.
    return {"x-goog-api-key": GEMINI_API_KEY, "Content-Type": "application/json"}


# Whether this model accepts thinkingConfig.thinkingBudget = 0.
# None = not yet known, and that is the point: it is DISCOVERED, not assumed.
#
# Pinning thinkingBudget to 0 is the right instinct -- it is the same lesson
# Groq's gpt-oss-120b taught, where reasoning ate 218 of a 220-token budget
# and returned an empty answer. But the 3.x Gemini models REJECT that field
# outright with "400 Request contains an invalid argument", so the
# optimisation silently turned the whole tier off: every call 400'd,
# collapsed into GeminiUnavailable, and fell through to the local model.
#
# Measured on this account:
#   gemini-3.1-flash-lite   602ms  WITH thinkingBudget=0
#   gemini-3.5-flash-lite   243ms -> 400 with it, 624ms OK without
#   gemini-3.6-flash        395ms -> 400 with it, 2164ms OK without (it thinks)
#
# So the field helps on some models and is fatal on others, and which is which
# changes as Google ships models. Rather than hardcoding another list that
# will go stale, the first 400 teaches it and every later call skips the field.
_thinking_ok: bool | None = None


def _payload(system_prompt: str, user_message: str, history: list | None) -> dict:
    """Translate the OpenAI-shaped history brain.py keeps into Gemini's.

    Two differences that silently corrupt a conversation if missed: the
    assistant role is called "model", and the system prompt is a separate
    top-level field rather than the first message. A "system" entry left in
    contents is rejected outright, and an "assistant" role is treated as an
    unknown role rather than the model's own turn -- which makes the model
    read its own previous answers as things the USER said.
    """
    contents = []
    # Only what fits MAX_CLOUD_CONTEXT travels, newest first -- enforced here at
    # the edge so no caller can forget it. See route_trace.trim_history.
    for msg in route_trace.trim_history(history):
        role = msg.get("role")
        text = (msg.get("content") or "").strip()
        if not text or role == "system":
            continue
        contents.append({
            "role": "model" if role == "assistant" else "user",
            "parts": [{"text": text}],
        })
    contents.append({"role": "user", "parts": [{"text": user_message}]})

    gen_config = {"temperature": 0.6,
                  "maxOutputTokens": route_trace.cap_output(MAX_TOKENS)}
    if _thinking_ok is not False:
        # Try it until the API says otherwise. See _thinking_ok above.
        gen_config["thinkingConfig"] = {"thinkingBudget": 0}

    return {
        "system_instruction": {"parts": [{"text": system_prompt}]},
        "contents": contents,
        "generationConfig": gen_config,
    }


def _extract(data: dict) -> str:
    """Pull the reply text out, tolerating a response with no candidates.

    A safety block or a hit token limit returns 200 with candidates empty or
    a candidate carrying no parts. Indexing straight into [0] there raises
    IndexError and reports as "malformed response", which sends a debugger
    looking for a parsing bug that does not exist.
    """
    candidates = data.get("candidates") or []
    if not candidates:
        reason = (data.get("promptFeedback", {}) or {}).get("blockReason", "")
        raise GeminiUnavailable(f"no candidates{f' ({reason})' if reason else ''}")
    parts = ((candidates[0].get("content") or {}).get("parts") or [])
    text = "".join(p.get("text", "") for p in parts).strip()
    if not text:
        raise GeminiUnavailable(
            f"empty answer (finish: {candidates[0].get('finishReason', '?')})")
    return text


def chat(system_prompt: str, user_message: str, history: list | None = None) -> str:
    """Blocking call, returns the full reply. Raises GeminiUnavailable on any
    failure -- brain.py catches it and falls through to ollama_client."""
    _refuse_if_local_only()
    if not (GEMINI_API_KEY or "").strip():
        raise GeminiUnavailable("no API key configured")
    if is_cooling_down():
        raise GeminiUnavailable("cooling down after a recent rate limit")

    # Privacy was decided above; COST is decided here, in that order (see
    # groq_client.chat). The one-time thinkingBudget retry inside _generate() is
    # capability DISCOVERY, bounded to once per process by _thinking_ok, and is
    # deliberately not counted as a second call.
    with route_trace.provider_call("gemini", GEMINI_MODEL, refuse_with=GeminiUnavailable):
        return _generate(system_prompt, user_message, history)


def _generate(system_prompt: str, user_message: str, history: list | None) -> str:
    global _thinking_ok
    try:
        resp = requests.post(
            f"{API_ROOT}/{GEMINI_MODEL}:generateContent",
            headers=_headers(),
            json=_payload(system_prompt, user_message, history),
            timeout=TIMEOUT,
        )
        # A 400 while thinkingConfig is in play means this model rejects the
        # field, not that the request is wrong. Learn it and retry once --
        # without this the tier is permanently dark on any model that refuses
        # thinkingBudget, and the only symptom is "it always answers locally".
        if resp.status_code == 400 and _thinking_ok is not False:
            _thinking_ok = False
            print("[gemini] model rejects thinkingBudget — retrying without it")
            resp = requests.post(
                f"{API_ROOT}/{GEMINI_MODEL}:generateContent",
                headers=_headers(),
                json=_payload(system_prompt, user_message, history),
                timeout=TIMEOUT,
            )
        elif resp.status_code == 200 and _thinking_ok is None:
            _thinking_ok = True
        if resp.status_code == 429:
            _activate_cooldown(resp)
        # A wrong model name is PERMANENT. Backing off and retrying cannot fix
        # it, and a cooldown just hides it -- so it is said plainly, once,
        # with the setting to change.
        if resp.status_code == 404:
            print(f"[gemini] model {GEMINI_MODEL!r} was rejected (404). "
                  f"Set GEMINI_MODEL in config.py to one this account has: "
                  f"python manage_secrets.py status")
        resp.raise_for_status()
        return _extract(resp.json())
    except GeminiUnavailable:
        raise
    except requests.exceptions.RequestException as e:
        raise GeminiUnavailable(
            _sanitize_error(e, getattr(getattr(e, "response", None),
                                       "status_code", None))) from e
    except (KeyError, IndexError, ValueError) as e:
        raise GeminiUnavailable("malformed response") from e


def chat_stream(system_prompt: str, user_message: str, history: list | None = None):
    """Yields text as Gemini produces it. Same contract as
    groq_client.chat_stream and ollama_client.chat_stream, so brain.py's
    streaming path does not care which provider it got.

    Raises GeminiUnavailable only if the connection or the FIRST chunk fails.
    Once text has started flowing the caller has already begun speaking it,
    and raising then would cut a reply off mid-sentence and start a different
    one -- so a mid-stream failure ends the generator quietly instead.
    """
    _refuse_if_local_only()
    if not (GEMINI_API_KEY or "").strip():
        raise GeminiUnavailable("no API key configured")
    if is_cooling_down():
        raise GeminiUnavailable("cooling down after a recent rate limit")

    # The whole stream is ONE hosted call against the turn's allowance.
    with route_trace.provider_call("gemini", GEMINI_MODEL, refuse_with=GeminiUnavailable):
        yield from _stream_body(system_prompt, user_message, history)


def _stream_body(system_prompt: str, user_message: str, history: list | None):
    global _thinking_ok

    def _open():
        return requests.post(
            f"{API_ROOT}/{GEMINI_MODEL}:streamGenerateContent",
            headers=_headers(),
            params={"alt": "sse"},
            json=_payload(system_prompt, user_message, history),
            timeout=TIMEOUT,
            stream=True,
        )

    try:
        resp = _open()
        # Same thinkingBudget discovery as chat(). Without it the streaming
        # path -- the one the listener actually uses -- stays broken on models
        # that reject the field even after the blocking path has learned.
        if resp.status_code == 400 and _thinking_ok is not False:
            _thinking_ok = False
            print("[gemini] model rejects thinkingBudget — retrying without it")
            resp.close()
            resp = _open()
        elif resp.status_code == 200 and _thinking_ok is None:
            _thinking_ok = True
        if resp.status_code == 429:
            _activate_cooldown(resp)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise GeminiUnavailable(
            _sanitize_error(e, getattr(getattr(e, "response", None),
                                       "status_code", None))) from e

    started = False
    try:
        for raw in resp.iter_lines(decode_unicode=True):
            if not raw or not raw.startswith("data:"):
                continue
            body = raw[5:].strip()
            if not body or body == "[DONE]":
                continue
            try:
                chunk = json.loads(body)
            except ValueError:
                continue
            for cand in chunk.get("candidates") or []:
                for part in ((cand.get("content") or {}).get("parts") or []):
                    piece = part.get("text", "")
                    if piece:
                        started = True
                        yield piece
    except requests.exceptions.RequestException as e:
        if not started:
            raise GeminiUnavailable(_sanitize_error(e)) from e
        # Mid-stream: stop cleanly, the caller keeps what it already spoke.
        return
    finally:
        resp.close()


def describe() -> str:
    if not (GEMINI_API_KEY or "").strip():
        return "gemini: no key configured (tier disabled)"
    state = "cooling down" if is_cooling_down() else "ready"
    return f"gemini: {GEMINI_MODEL}, {state}"
