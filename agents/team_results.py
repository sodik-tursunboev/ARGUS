'ARGUS - Agent teams: the normalized result contract.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import enum
import re
from dataclasses import dataclass, field

from agents.team_evidence import (CONTEXT_SOURCE_TYPES, EvidenceClass,
                                  EvidenceStore, SourceType, ground, safe_text)

_CTX_HEAD = re.compile(r"^\[([a-z_]+)\] ", re.M)
MAX_FINDINGS = 8


class FindingKind(str, enum.Enum):
    OBSERVED = "OBSERVED"
    INFERENCE = "INFERENCE"


@dataclass(frozen=True)
class Finding:
    kind: FindingKind
    text: str
    evidence_ids: tuple = ()


@dataclass(frozen=True)
class ActionProposal:
    """A machine action an agent WANTS. Never executed by the team layer: the
    only path is owner approval -> policy -> authentication -> capability bus
    -> executor -> observation -> verifier."""
    skill: str
    action: str
    target: str = ""
    risk: str = ""
    reason: str = "agent_request"
    status: str = "PROPOSED"


@dataclass(frozen=True)
class HandoffRequest:
    from_agent: str
    to_role: str
    reason: str = ""
    context_refs: tuple = ()
    requested_task: str = ""
    priority: int = 3


@dataclass(frozen=True)
class NormalizedResult:
    agent_id: str
    task_id: str
    status: str = "COMPLETED"
    summary: str = ""
    findings: tuple = ()
    evidence_refs: tuple = ()
    recommendations: tuple = ()
    action_proposals: tuple = ()
    confidence: str = ""
    reported_confidence: str = ""
    limitations: tuple = ()
    handoff_requests: tuple = ()
    timing: dict = field(default_factory=dict)
    usage: dict = field(default_factory=dict)
    verification: str = ""
    structured: bool = False

    @property
    def observed(self) -> tuple:
        return tuple(f for f in self.findings if f.kind is FindingKind.OBSERVED)

    def as_dict(self) -> dict:
        return {
            "agent_id": self.agent_id, "task_id": self.task_id,
            "status": self.status, "summary": self.summary,
            "findings": [{"kind": f.kind.value, "text": f.text,
                          "evidence_ids": list(f.evidence_ids)}
                         for f in self.findings],
            "evidence_refs": list(self.evidence_refs),
            "recommendations": list(self.recommendations),
            "action_proposals": [p.__dict__ for p in self.action_proposals],
            "confidence": self.confidence,
            "reported_confidence": self.reported_confidence,
            "limitations": list(self.limitations),
            "handoff_requests": [h.__dict__ for h in self.handoff_requests],
            "timing": dict(self.timing), "usage": dict(self.usage),
            "verification": self.verification, "structured": self.structured,
        }


def parse_context(context_text: str) -> list:
    """[(category, text)] from an agents/context.py block ("[name] text")."""
    text = context_text or ""
    heads = list(_CTX_HEAD.finditer(text))
    out = []
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        out.append((m.group(1), text[m.end():end].strip()))
    return out


def failed_result(agent_id: str, task_id: str, status: str, reason: str, *,
                  timing=None, usage=None) -> NormalizedResult:
    """A worker that produced nothing usable. Honest: no invented summary."""
    return NormalizedResult(
        agent_id=agent_id, task_id=task_id, status=status,
        limitations=(safe_text(f"no result: {reason}", 120),),
        timing=dict(timing or {}), usage=dict(usage or {}))


def normalize(structured: dict, *, agent_id: str, task_id: str,
              store: EvidenceStore, input_sources=(), context_text: str = "",
              job_summary: str = "", requested_caps=(), timing=None,
              usage=None, now: float | None = None) -> NormalizedResult:
    """Raw model reply (agents.results.AgentResult.as_dict()) -> the contract.

    input_sources: [(evidence_id, text)] the agent was handed.
    context_text:  the machine-context block the agent was given (real data)."""
    s = structured or {}
    ctx = parse_context(context_text)
    ctx_by_cat = dict(ctx)
    sources = [("in:" + eid, txt) for eid, txt in input_sources]
    sources += [("ctx:" + cat, txt) for cat, txt in ctx]

    def source_ref(sid: str):
        if sid.startswith("in:"):
            return store.get(sid[3:])
        cat = sid[4:]
        return store.add(CONTEXT_SOURCE_TYPES.get(cat, SourceType.LOG),
                         agent_id, f"context:{cat}", ctx_by_cat.get(cat, ""),
                         task_id=task_id, classification=EvidenceClass.OBSERVED,
                         timestamp=now)

    ev_ids: list = []

    def keep(ref) -> None:
        if ref is not None and ref.evidence_id not in ev_ids:
            ev_ids.append(ref.evidence_id)

    for claim in (s.get("evidence") or [])[:MAX_FINDINGS]:
        sid = ground(str(claim), sources)
        if sid:
            keep(source_ref(sid))
        else:                      # a model's own claim: recorded, never trusted
            keep(store.add(SourceType.MODEL_ANALYSIS, agent_id,
                           "model:analysis", str(claim), task_id=task_id,
                           classification=EvidenceClass.INFERRED,
                           grounded=False, timestamp=now))

    findings = []
    for f in (s.get("findings") or [])[:MAX_FINDINGS]:
        sid = ground(str(f), sources)
        ref = source_ref(sid) if sid else None
        if ref is not None:
            keep(ref)
            findings.append(Finding(FindingKind.OBSERVED, safe_text(f, 240),
                                    (ref.evidence_id,)))
        else:
            findings.append(Finding(FindingKind.INFERENCE, safe_text(f, 240)))

    reported = str(s.get("confidence") or "")[:8]
    observed = [f for f in findings if f.kind is FindingKind.OBSERVED]
    limits = [safe_text(x, 160) for x in (s.get("uncertainty") or [])[:4]]
    if s.get("limitations"):
        limits.append(safe_text(s["limitations"], 160))
    confidence = reported
    if reported in ("medium", "high") and not observed:
        confidence = "low"
        limits.append("confidence lowered: no finding is grounded in evidence "
                      "the agent was given")

    caps = tuple(
        ActionProposal(skill=str(c.get("skill", ""))[:32],
                       action=str(c.get("action", ""))[:32],
                       target=safe_text(c.get("target", ""), 120),
                       risk=str(c.get("risk", ""))[:4])
        for c in (requested_caps or ())[:6] if isinstance(c, dict))
    handoffs = tuple(
        HandoffRequest(from_agent=agent_id, to_role=str(h)[:32].lower(),
                       reason="agent suggestion", context_refs=tuple(ev_ids[:4]),
                       requested_task=f"Continue the analysis of task {task_id}.")
        for h in (s.get("suggested_handoffs") or [])[:3])
    return NormalizedResult(
        agent_id=agent_id, task_id=task_id, status="COMPLETED",
        summary=safe_text(s.get("summary") or job_summary, 400),
        findings=tuple(findings), evidence_refs=tuple(ev_ids),
        recommendations=tuple(safe_text(x, 200) for x in
                              (s.get("recommended_actions") or [])[:6]),
        action_proposals=caps, confidence=confidence,
        reported_confidence=reported, limitations=tuple(limits),
        handoff_requests=handoffs, timing=dict(timing or {}),
        usage=dict(usage or {}),
        verification=str(s.get("verification") or "")[:24],
        structured=bool(s.get("structured")))
