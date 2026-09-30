"""
ARGUS - Dynamic agents: the Agent Architect.

Given a task the ten core agents cannot efficiently handle, the Architect may
PROPOSE a temporary specialist. That is ALL it can do:

  * it returns a SpawnProposal -- plain data. It creates nothing, registers
    nothing, approves nothing, and cannot (this module has no import of the
    Governor, and the tests scan it for any call that would);
  * it is DETERMINISTIC: a small table of vetted specialist templates matched
    by keyword. No model is consulted, so a proposal is reproducible, costs no
    inference on the one shared 4 GB model, and cannot be steered by prompt
    injection in the task text;
  * it is AUTHORITY-AGNOSTIC: a template asks for what the specialist needs,
    not for what the parent happens to hold. It passes through -- unedited --
    any capability or data class the REQUESTER named. That is deliberate: if
    an agent's output asks for `shell`, the request must reach the Governor so
    it is denied and audited, not be trimmed away here where nobody would see.

Two entry points:
  propose(SpawnRequest)          deterministic, template-driven proposals
  from_untrusted(requester, {})  a hardened parser for a proposal authored by
                                 a MODEL (a future drafting path, and the shape
                                 hostile tests use): it never raises, never
                                 trusts a type, and records any forbidden key
                                 (code, prompt, permissions, ...) so the
                                 Governor can deny it by name.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re
import secrets
import time
from dataclasses import dataclass

from agents.definitions import HANDOFF_GRAPH
from agents.dynamic_spec import (FORBIDDEN_PROPOSAL_KEYS, MAX_TOKENS_PER_SET,
                                 SpawnProposal, SpawnRequest, clean_text)

# The denials the proposal itself states (the Governor's floor adds the rest).
_STATED_DENIALS = ("shell", "filesystem.write", "credentials",
                   "authentication", "machine_control")


@dataclass(frozen=True)
class _Template:
    key: str
    name: str
    role: str
    description: str
    parent: str                 # default parent when the OWNER asks
    patterns: tuple
    capabilities: tuple = ()    # non-baseline groups the specialist needs
    data_classes: tuple = ()    # non-baseline data it needs
    ttl: int = 1200
    calls: int = 3
    handoffs: int = 1
    children: int = 0
    tier: int = 3
    cloud: bool = False
                                 # Governor still forces capabilities/data to
                                 # baseline-only regardless of what is listed
                                 # above; a cloud template never lists a group.

    def __post_init__(self):
        object.__setattr__(
            self, "_rx", tuple(re.compile(p, re.I) for p in self.patterns))

    def score(self, text: str) -> int:
        return sum(1 for rx in self._rx if rx.search(text))


# Ordered MOST specific first: on a tied score the earlier template wins, so
# "review this Python project for security issues" lands on the Python
# specialist rather than the broader Code Review Agent.
_TEMPLATES: tuple = (
    _Template(
        "python_security", "Python Security Specialist",
        "Review Python source for security weaknesses.",
        "Reads only the Python source supplied with the task and reports risky "
        "patterns (injection, unsafe deserialisation, weak cryptography, "
        "hardcoded credentials) with evidence and severity. Recommends fixes "
        "and changes nothing.",
        "security",
        (r"\bpython\b.{0,80}\b(secur\w*|vulnerab\w*|insecure|audit|bandit|review)\b",
         r"\b(secur\w*|vulnerab\w*|audit)\b.{0,80}\bpython\b"),
        children=1),
    _Template(
        "dependency_review", "Dependency Review Specialist",
        "Review a project's dependency list for risky or outdated packages.",
        "Reads only the requirements or manifest text supplied with the task "
        "and flags unpinned versions, known-risk patterns and look-alike "
        "package names. Recommends changes and installs nothing.",
        "security",
        (r"\b(dependenc\w*|requirements?|packages?|supply[- ]chain|pip|npm)\b",)),
    _Template(
        "backend_specialist", "Backend Specialist",
        "Review backend, API and data-layer code for correctness and safety.",
        "Reads only the backend code supplied with the task and reports "
        "correctness, error-handling and safety problems in servers, APIs and "
        "data access. Recommends changes and edits nothing.",
        "planner",
        (r"\b(backend|back-end|server[- ]side|apis?|database|endpoints?)\b",),
        handoffs=0),
    _Template(
        "frontend_specialist", "Frontend Specialist",
        "Review frontend and UI code for correctness and safety.",
        "Reads only the frontend code supplied with the task and reports "
        "correctness, accessibility and unsafe-rendering problems. Recommends "
        "changes and edits nothing.",
        "planner",
        (r"\b(frontend|front-end|ui|html|css|javascript|typescript|svelte|react)\b",),
        handoffs=0),
    _Template(
        "log_analysis", "Log Analysis Specialist",
        "Analyse supplied logs and tracebacks for the likely cause of a failure.",
        "Reads only the log or traceback text supplied with the task, separates "
        "what the text shows from what is inferred, and names the most likely "
        "cause. Recommends next checks and changes nothing.",
        "diagnostics",
        (r"\b(logs?|traceback|stack ?trace|exception|error messages?)\b",)),
    _Template(
        "system_health", "System Health Specialist",
        "Interpret system telemetry for resource problems.",
        "Reads the system telemetry its parent may see and reports resource "
        "anomalies with the numbers behind them. Recommends what to check and "
        "changes nothing.",
        "system",
        (r"\b(cpu|ram|memory|disk|gpu|telemetry|performance|resources?)\b",),
        capabilities=("analysis", "system_read"), data_classes=("telemetry",)),
    _Template(
        "network_posture", "Network Posture Specialist",
        "Summarise network state and policy posture from recorded data.",
        "Reads the network state and network policy its parent may see and "
        "reports anything worth attention. Never probes; recommends only.",
        "network",
        (r"\b(network|firewall|dns|ports?|egress|connections?)\b",),
        capabilities=("analysis", "network_read"),
        data_classes=("network", "netpolicy")),
    _Template(
        "threat_triage", "Threat Triage Specialist",
        "Triage recorded detections and events by evidence.",
        "Reads the detections and recent security events its parent may see "
        "and ranks them by the evidence they carry. Never invents a detection; "
        "recommends only.",
        "threat",
        (r"\b(detections?|alerts?|iocs?|malware|intrusion|triage|threats?)\b",),
        capabilities=("analysis", "security_read"),
        data_classes=("threat_summary", "recent_events")),
    _Template(
        "code_review", "Code Review Agent",
        "Coordinate a review of a codebase and delegate narrow parts.",
        "Reads only the code supplied with the task, splits the review by area "
        "and may request up to two narrower specialists. Recommends changes "
        "and edits nothing.",
        "planner",
        (r"\b(code|project|repo(sitory)?|codebase)\b.{0,40}\breview\w*\b",
         r"\breview\w*\b.{0,40}\b(code|project|repo(sitory)?|codebase)\b"),
        calls=4, children=2),
)


# Public/general work only -- a goal is never routed here unless
# agents/team_planner.py has already confirmed (via skills/cloud_gate.py, the
# SAME classifier every ordinary chat reply is gated by) that it carries no
# local/private/machine signal. No `capabilities`/`data_classes` entries: the
# Governor grants a cloud spec baseline-only regardless, so listing a group
# here would only be misleading.
CLOUD_TEMPLATES: tuple = (
    _Template(
        "cloud_research", "Research Specialist",
        "Research and compare public information on the given topic.",
        "Answers from general/public knowledge only: research, compare "
        "options, weigh trade-offs, and give a recommendation with reasons. "
        "Never claims access to this machine, this person's files, or "
        "anything private, and says plainly when it is not certain.",
        "planner", (), cloud=True, ttl=240, calls=1, tier=3),
    _Template(
        "cloud_writing", "Writing Specialist",
        "Draft, translate or rewrite text from public/general knowledge.",
        "Writes, translates, summarises or rewrites text using only what it "
        "is given in the task and general knowledge. Never invents facts "
        "about this machine or this person.",
        "planner", (), cloud=True, ttl=240, calls=1, tier=3),
)
_CLOUD_BY_KEY = {t.key: t for t in CLOUD_TEMPLATES}

_GENERIC = _Template(
    "generic", "Task Specialist",
    "Analyse the task text it is given and report findings.",
    "Reads only the text supplied with the task and reports what it shows, "
    "what is inferred and what is uncertain. Recommends only.",
    "planner", ())


# the team orchestrator names the specialist it planned for, so its choice is
# reproducible and cannot drift with the wording of the task). Any other hint
# is just more text for the keyword match, as before.
_BY_KEY = {t.key: t for t in _TEMPLATES}


def _dedupe(items) -> tuple:
    seen, out = set(), []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return tuple(out)


def _parent_has_verifier_edge(parent: str) -> bool:
    """Public wiring data only: does the parent's declared edge list include
    the verifier? (A default the Architect adapts to -- the Governor still
    rules on the result.)"""
    if parent in HANDOFF_GRAPH:
        return "verifier" in HANDOFF_GRAPH[parent]
    try:
        from agents.registry import registry
        dyn = registry().get_dynamic(parent)
        return bool(dyn is not None and dyn.dspec.max_handoffs > 0)
    except Exception:
        return False


class AgentArchitect:
    """Proposes. Never authorises."""

    def select(self, text: str) -> str:
        'The template key a piece of text maps to.'
        return self._select(text).key

    def templates(self) -> list:
        return [{"key": t.key, "name": t.name, "role": t.role,
                 "default_parent": t.parent, "cloud": t.cloud, "ttl": t.ttl,
                 "calls": t.calls}
                for t in _TEMPLATES + (_GENERIC,) + CLOUD_TEMPLATES]

    @staticmethod
    def _select(text: str) -> _Template:
        text = str(text or "")[:2000]
        best, best_score = None, 0
        for t in _TEMPLATES:
            s = t.score(text)
            if s > best_score:           # strict: earlier (more specific) wins ties
                best, best_score = t, s
        return best if best is not None else _GENERIC

    def propose(self, req: SpawnRequest, *, now: float | None = None
                ) -> SpawnProposal:
        t = time.time() if now is None else now
        tmpl = (_CLOUD_BY_KEY.get(req.role_hint) or _BY_KEY.get(req.role_hint)
               or self._select(f"{req.role_hint} {req.task}"))
        if req.requester == "owner":
            parent = clean_text(req.parent_hint, 32).lower() or tmpl.parent
        else:
            # An agent spawns under ITSELF; the Governor enforces it, and the
            # Architect does not pretend otherwise.
            parent = req.requester
        forbidden = tuple(sorted({str(k).lower() for k in req.extra_keys
                                  if str(k).lower() in FORBIDDEN_PROPOSAL_KEYS}))
        # A cloud template never carries capabilities/data_classes (see
        # CLOUD_TEMPLATES above) and never inherits handoffs -- both are
        # re-enforced at the Governor either way, but a proposal should not
        # even ASK, so a denial reason (if one ever fires) is never confused
        # with a local specialist's.
        return SpawnProposal(
            proposal_id="p-" + secrets.token_hex(4),
            requester=req.requester, parent_agent_id=parent,
            name=tmpl.name, role=tmpl.role, description=tmpl.description,
            task=req.task,
            agent_type=("EPHEMERAL_CLOUD" if tmpl.cloud else "EPHEMERAL_LOCAL"),
            model_scope=("CLOUD" if tmpl.cloud else "LOCAL_SHARED"),
            requested_capabilities=() if tmpl.cloud else _dedupe(
                tmpl.capabilities + tuple(req.requested_capabilities)),
            requested_data_classes=() if tmpl.cloud else _dedupe(
                tmpl.data_classes + tuple(req.requested_data_classes)),
            denied_capabilities=_STATED_DENIALS,
            priority=tmpl.tier, ttl_seconds=tmpl.ttl,
            max_model_calls=tmpl.calls,
            max_handoffs=(tmpl.handoffs if not tmpl.cloud
                         and _parent_has_verifier_edge(parent) else 0),
            max_children=(0 if tmpl.cloud else tmpl.children), template=tmpl.key,
            forbidden_keys=forbidden, parent_job_id=req.parent_job_id,
            proposed_at=t)

    def from_untrusted(self, requester: str, data, *,
                       now: float | None = None) -> SpawnProposal:
        """Parse a proposal a MODEL wrote. Never raises. Wrong types are
        recorded in invalid_fields (the Governor denies on them); forbidden
        keys are recorded by name; nothing is executed or evaluated."""
        t = time.time() if now is None else now
        d = data if isinstance(data, dict) else {}
        bad: list = []
        forbidden = tuple(sorted({str(k).lower() for k in d
                                  if str(k).lower() in FORBIDDEN_PROPOSAL_KEYS}))

        def text(key, cap):
            v = d.get(key)
            if v is None:
                return ""
            if isinstance(v, str):
                return v[:cap * 2]
            bad.append(key)
            return ""

        def seq(key):
            v = d.get(key)
            if v is None:
                return ()
            if isinstance(v, (list, tuple)):
                return tuple(x[:64] if isinstance(x, str) else "" for x in
                             list(v)[:MAX_TOKENS_PER_SET * 2])
            bad.append(key)
            return ()

        def num(key):
            v = d.get(key)
            if v is None:
                return None
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                bad.append(key)
                return None
            return v

        return SpawnProposal(
            proposal_id="p-" + secrets.token_hex(4),
            requester=str(requester)[:40],
            parent_agent_id=text("parent_agent_id", 40) or str(requester)[:40],
            name=text("name", 60), role=text("role", 200),
            description=text("description", 400), task=text("task", 2000),
            agent_type=text("agent_type", 32) or "EPHEMERAL_LOCAL",
            model_scope=text("model_scope", 32) or "LOCAL_SHARED",
            requested_capabilities=seq("allowed_capabilities")
            + seq("requested_capabilities"),
            requested_data_classes=seq("allowed_data_classes")
            + seq("requested_data_classes"),
            denied_capabilities=seq("denied_capabilities"),
            priority=num("priority"), ttl_seconds=num("ttl_seconds"),
            max_model_calls=num("max_model_calls"),
            max_handoffs=num("max_handoffs"), max_children=num("max_children"),
            template="untrusted", forbidden_keys=forbidden,
            invalid_fields=tuple(sorted(set(bad))), proposed_at=t)


_ARCHITECT = AgentArchitect()


def architect() -> AgentArchitect:
    return _ARCHITECT
