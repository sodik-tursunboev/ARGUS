"""
ARGUS - Local agents: deterministic routing.

Route an objective to the right registered agent WITHOUT asking the model.
Rules are cheap keyword patterns; the candidate set is only ever registered,
enabled agents -- the router cannot invent a destination. Ties go to the
rule with the longest matched keyword (most specific), then to rule order.
Anything unmatched falls back to ASSISTANT, whose own prompt routes complex
goals to PLANNER by suggestion.

Routing is a convenience, not an authority: a wrong route still runs inside
the same spec's bounds (context categories, capability groups, handoff
edges), so a misroute can never escalate what an agent may see or request.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re

# (pattern, agent_id). Order matters only for equal-length matches; the
# specificity sort makes most entries order-independent. Patterns are
# word-ish substrings, matched case-insensitively against the objective.
_RULES: tuple[tuple[str, str], ...] = (
    # forensics: evidence/artifact examination (before threat so "examine
    # these audit records" lands here, not on the word 'audit' alone)
    (r"\b(examine|analyse|analyze|review)\b.*\b(audit records?|evidence|"
     r"artifact|hash(es)?|forensic|timeline)\b", "forensics"),
    (r"\bforensic\b", "forensics"),
    # diagnostics: failures, crashes, errors, health of the software itself
    (r"\b(why|why did|why is)\b.*\b(crash|crashed|fail(ed|ing)?|broken|"
     r"died|down)\b", "diagnostics"),
    (r"\b(error|errors|exception|stack trace|traceback|log)s?\b.*"
     r"\b(analy|diagnos|investig|what|why)\b", "diagnostics"),
    (r"\b(diagnos(e|is|tic|tics))\b", "diagnostics"),
    (r"\b(ollama|websocket|endpoint|backend|service)\b.*\b(unavailable|"
     r"disconnected|failing|failing\?)\b", "diagnostics"),
    # threat: detections, alerts, IOCs
    (r"\b(detection|alert|ioc|indicator|malware|suspicious|intrusion|"
     r"attack)\b", "threat"),
    (r"\b(analy[sz]e|correlate|triage)\b.*\b(detection|threat|alert)s?\b", "threat"),
    # response: containment / remediation / recovery planning
    (r"\b(contain(ment)?|remediat(e|ion)|recover(y)?|quarantine|isolate)\b",
     "response"),
    (r"\b(create|draft|prepare|write)\b.*\b(containment|response plan)\b",
     "response"),
    # planner: explicit planning requests / multi-step goals. The lead-verb
    # form ("plan how to X") outranks a domain word inside the goal: the
    # OBJECT of the request is a plan, so PLANNER owns it and may hand off.
    (r"\b(plan|planning|roadmap|step[- ]by[- ]step|break (down|it down)?)\b",
     "planner"),
    (r"^(plan|draft a plan|make a plan|help me plan)\b", "planner"),
    (r"\b(how (do|can) i)\b.*\b(then|after that|and then)\b", "planner"),
    # network
    (r"\b(network|connection|dns|port|firewall|egress|latency)\b", "network"),
    # system
    (r"\b(cpu|memory|ram|gpu|disk|storage|swap|battery|process(es)?|"
     r"performance|telemetry)\b", "system"),
    # security posture ("how secure is my machine" has no noun keyword,
    # so the adjective form is matched too)
    (r"\b(security|posture|integrity|policy|audit|auth(entication)? state|"
     r"hardening)\b", "security"),
    (r"\bhow (secure|protected|safe)\b", "security"),
)

_COMPILED = tuple((re.compile(p, re.I), agent) for p, agent in _RULES)

# Sentence-shape rules whose match wins outright when they hit: if the
# objective LEADS with a planning verb, it is a planning request, and a
# longer domain word later in the sentence must not steal the route
# ("Plan how to diagnose network instability" is ABOUT networking, but the
# OBJECT of the request is a plan -- PLANNER owns it and hands off).
_ANCHOR = re.compile(r"^(plan|draft a plan|make a plan|help me plan)\b", re.I)
_ANCHOR_AGENT = "planner"


def route(objective: str, *, enabled_ids: set[str] | None = None) -> str:
    """Return the agent id for an objective. Only registered+enabled agents
    are ever returned; anything unmatched (or only matching disabled agents)
    falls back to 'assistant'."""
    text = " ".join(str(objective or "").split())
    if not text:
        return "assistant"
    if (_ANCHOR.search(text)
            and (enabled_ids is None or _ANCHOR_AGENT in enabled_ids)):
        return _ANCHOR_AGENT
    best: tuple[int, int, str] | None = None   # (keyword_len, rule_idx, agent)
    for idx, (rx, agent) in enumerate(_COMPILED):
        m = rx.search(text)
        if not m:
            continue
        if enabled_ids is not None and agent not in enabled_ids:
            continue
        key = (len(m.group(0)), idx, agent)
        if best is None or key[:2] > best[:2]:
            best = key
    return best[2] if best else "assistant"
