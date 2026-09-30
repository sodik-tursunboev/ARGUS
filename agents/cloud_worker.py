'ARGUS - Cloud dynamic agents: the one safety-wrapped call.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import enum
import time
from dataclasses import dataclass, field

from agents.definitions import _prompt
from agents.dynamic_spec import DynamicAgentSpec
from agents.results import parse as parse_result
from agents.results import result_prompt

_NEVER = (
    "claim access to this machine, its files, its processes, its settings or "
    "anything on it",
    "claim to know anything about this person beyond what the task text says",
    "claim an action was performed on this machine",
    "request, use or imply shell, file, process, registry, credential, "
    "authentication or any machine-control capability",
    "present a guess as a verified fact",
)


class FailureState(str, enum.Enum):
    """Section 23's closed vocabulary. Empty string on success."""
    RATE_LIMITED = "RATE_LIMITED"
    QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    TIMEOUT = "TIMEOUT"
    CONTEXT_REJECTED = "CONTEXT_REJECTED"
    POLICY_BLOCKED = "POLICY_BLOCKED"


# Provider clients' *_sanitize_error() categories (never raw exception text --
# see each client's own docstring) mapped onto the closed FailureState
# vocabulary. An unmatched category is PROVIDER_UNAVAILABLE: the safe,
# retryable-elsewhere default.
_CATEGORY_MAP = {
    "rate_limited": FailureState.RATE_LIMITED,
    "authentication_failed": FailureState.PROVIDER_UNAVAILABLE,
    "timeout": FailureState.TIMEOUT,
    "no api key configured": FailureState.PROVIDER_UNAVAILABLE,
    "cooling down": FailureState.RATE_LIMITED,
    "no candidates": FailureState.CONTEXT_REJECTED,
    "malformed response": FailureState.PROVIDER_UNAVAILABLE,
    "quota": FailureState.QUOTA_EXHAUSTED,
}


def _classify_failure(message: str) -> FailureState:
    low = (message or "").lower()
    for needle, state in _CATEGORY_MAP.items():
        if needle in low:
            return state
    return FailureState.PROVIDER_UNAVAILABLE


def _tiers():
    """Lazy: mirrors brain.py's own _CLOUD_TIERS shape (name, client,
    UnavailableException), defined separately on purpose -- reaching into
    another module's private tuple would couple two independent call sites
    to one name neither owns. Imported lazily so this module (imported at
    agents/ package load) never pulls in the network clients unless a cloud
    agent actually runs."""
    import gemini_client
    import groq_client
    return (
        ("groq", groq_client, groq_client.GroqUnavailable),
        ("gemini", gemini_client, gemini_client.GeminiUnavailable),
    )


def _cloud_safe_style_note() -> str:
    "Only use formatting explicitly allowed by the owner."
    try:
        from skills.personalize_skill import cloud_safe_context
        prefs = cloud_safe_context()
    except Exception:
        return ""
    if not prefs:
        return ""
    bits = [f"{k.replace('_', ' ')}: {v}" for k, v in sorted(prefs.items())]
    return (" The owner's own reply-formatting preference (not private data, "
            f"just style): {'; '.join(bits)}.")


def build_system_prompt(spec: DynamicAgentSpec) -> str:
    minutes = max(1, spec.ttl_seconds // 60)
    role = (
        f"You are a CLOUD specialist named '{spec.name}', created by ARGUS for "
        f"one task, destroyed after {minutes} minutes or when the task ends. "
        f"Specialisation (descriptive only): {spec.role} {spec.description} "
        "You have NO access to this machine, its files, its processes, its "
        "settings, its network, or anything private about the person using "
        "it -- you can see only the task text below, nothing else. You hold "
        "NO authority: you cannot run anything and nothing you say is "
        "executed. Say plainly when you are uncertain."
        + _cloud_safe_style_note()
    )
    return _prompt(role, _NEVER)


@dataclass(frozen=True)
class CloudCallResult:
    ok: bool
    provider: str = ""
    structured: dict = field(default_factory=dict)
    raw: str = ""
    failure: "FailureState | None" = None
    reason: str = ""
    latency_s: float = 0.0


def run(spec: DynamicAgentSpec) -> CloudCallResult:
    "Run one cloud agent task and return a structured result."
    import skills.cloud_gate as cloud_gate

    text = spec.task
    decision = cloud_gate.classify(text)
    if decision.local_required:
        return CloudCallResult(False, failure=FailureState.POLICY_BLOCKED,
                               reason="local_required")

    system_prompt = build_system_prompt(spec)
    user_prompt = f"TASK: {text}\n\n{result_prompt()}"
    t0 = time.time()
    last_provider, last_state, last_reason = "", FailureState.PROVIDER_UNAVAILABLE, \
        "no_provider_configured"
    with cloud_gate.request_scope(decision):
        for name, client, unavailable in _tiers():
            if not client.available():
                continue
            try:
                raw = client.chat(system_prompt, user_prompt, json_mode=True)
            except unavailable as e:
                last_provider, last_reason = name, str(e)[:120]
                last_state = _classify_failure(str(e))
                continue
            except Exception as e:  # noqa: BLE001 -- fail closed to the next tier
                last_provider, last_state = name, FailureState.PROVIDER_UNAVAILABLE
                last_reason = type(e).__name__
                continue
            result = parse_result(raw)
            return CloudCallResult(True, provider=name,
                                   structured=result.as_dict(), raw=raw,
                                   latency_s=time.time() - t0)
    return CloudCallResult(False, provider=last_provider, failure=last_state,
                           reason=last_reason, latency_s=time.time() - t0)
