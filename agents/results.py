'ARGUS - Local agents: structured results.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import re
from dataclasses import dataclass, field

VERDICTS = ("verified", "partially_verified", "not_verified",
            "contradicted", "insufficient_evidence")

_RESULT_KEYS = ("summary", "analysis", "findings", "evidence", "assumptions",
                "uncertainty", "recommended_actions", "requested_capabilities",
                "suggested_handoffs", "verification_plan", "user_message",
                "verification", "confidence", "limitations")


@dataclass
class AgentResult:
    summary: str = ""
    analysis: str = ""
    findings: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    uncertainty: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    requested_capabilities: list[dict] = field(default_factory=list)
    suggested_handoffs: list[str] = field(default_factory=list)
    verification_plan: list[str] = field(default_factory=list)
    user_message: str = ""
    verification: str = ""            # verifier verdict; empty for others
    confidence: str = ""
    limitations: str = ""
    verification_needed: bool = False
    raw: str = ""
    structured: bool = False

    def as_dict(self) -> dict:
        return {
            "summary": self.summary,
            "analysis": self.analysis,
            "findings": self.findings[:8],
            "evidence": self.evidence[:8],
            "assumptions": self.assumptions[:6],
            "uncertainty": self.uncertainty[:6],
            "recommended_actions": self.recommended_actions[:8],
            "requested_capabilities": list(self.requested_capabilities[:6]),
            "suggested_handoffs": self.suggested_handoffs[:4],
            "verification_plan": self.verification_plan[:6],
            "user_message": self.user_message[:600],
            "verification": self.verification,
            "confidence": self.confidence,
            "limitations": self.limitations,
            "verification_needed": self.verification_needed,
            "structured": self.structured,
        }


def result_prompt() -> str:
    """The OUTPUT FORMAT block appended to every agent's role prompt."""
    return (
        "\n\nOUTPUT FORMAT (mandatory): reply with ONLY a JSON object with "
        "these keys: summary (one paragraph), analysis (optional detail), "
        "findings (array of short observed facts, may be empty), evidence "
        "(array of 'source: what it shows' strings, may be empty), "
        "assumptions (array, may be empty), uncertainty (array of what you "
        "could NOT determine, may be empty), recommended_actions (array of "
        "short strings, may be empty), requested_capabilities (array of "
        "{\"skill\": str, \"action\": str, \"target\": str}, may be empty -- "
        "requesting does not run anything), suggested_handoffs (array of "
        "agent ids, may be empty), verification_plan (array of checks, may "
        "be empty), user_message (optional plain-language line for the "
        "owner), confidence (\"low\"|\"medium\"|\"high\"), limitations "
        "(optional). VERIFIER agents must also set verification to exactly "
        "one of: verified, partially_verified, not_verified, contradicted, "
        "insufficient_evidence."
    )


def _strings(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(x).strip()[:300] for x in value if x and str(x).strip()]


def parse(raw: str) -> AgentResult:
    """Defensive parse. Bad JSON, wrong shapes, oversize fields: everything
    falls back to an honest plain-text summary rather than an error."""
    text = (raw or "").strip()
    out = AgentResult(raw=text[:4000])
    candidate = text
    # Tolerate a fenced block or leading prose before the JSON.
    m = re.search(r"\{.*\}", text, re.S)
    if m:
        candidate = m.group(0)
    try:
        obj = json.loads(candidate)
    except (json.JSONDecodeError, ValueError):
        out.summary = text[:1200]
        return out
    if not isinstance(obj, dict):
        out.summary = text[:1200]
        return out
    out.structured = True
    out.summary = str(obj.get("summary", "") or "")[:1200]
    out.analysis = str(obj.get("analysis", "") or "")[:2000]
    out.user_message = str(obj.get("user_message", "") or "")[:600]
    out.confidence = str(obj.get("confidence", "") or "").lower()[:12]
    if out.confidence not in ("low", "medium", "high", ""):
        out.confidence = ""
    out.limitations = str(obj.get("limitations", "") or "")[:500]
    out.findings = _strings(obj.get("findings"))[:8]
    out.evidence = _strings(obj.get("evidence"))[:8]
    out.assumptions = _strings(obj.get("assumptions"))[:6]
    out.uncertainty = _strings(obj.get("uncertainty"))[:6]
    out.recommended_actions = _strings(obj.get("recommended_actions"))[:8]
    out.verification_plan = _strings(obj.get("verification_plan"))[:6]
    out.suggested_handoffs = [h.lower()[:32]
                              for h in _strings(obj.get("suggested_handoffs"))][:4]
    v = str(obj.get("verification", "") or "").lower().strip()
    out.verification = v if v in VERDICTS else ""
    # Anything that looks complete enough to verify is fair game for a
    # verifier handoff (the coordinator still bounds depth and edges).
    out.verification_needed = bool(
        out.verification or obj.get("verification_needed") is True)
    caps = obj.get("requested_capabilities")
    if isinstance(caps, list):
        clean = []
        for c in caps[:6]:
            if not isinstance(c, dict):
                continue
            skill = str(c.get("skill", "")).strip().lower()
            action = str(c.get("action", "")).strip().lower()
            target = str(c.get("target", "") or "")
            if skill and action:
                clean.append({"skill": skill, "action": action,
                              "target": target[:500]})
        out.requested_capabilities = clean
    if not out.summary:
        out.summary = text[:1200]
    return out
