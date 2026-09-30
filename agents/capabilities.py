"""Capability request boundary for local agents."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import auth
import router
import security

# Risk cap for agent-REQUESTED capabilities: anything above L2 is never even
# surfaced as a recommendation (it may still be performed the normal way --
# the owner typing/saying it directly -- but an agent will not propose it).
REQUEST_RISK_CAP = 2

# The category vocabulary used by the specs in agents/definitions.py, mapped
# to concrete (skill, action) pairs. Derived from the same reviewed sets the
# planner uses (router.PLANNABLE / CHAINABLE) rather than a new hand-typed
# list, so it cannot name a capability the router would not accept anyway.
_GROUPS = {
    "security_read": {("diag", "defenses"), ("net", "connections"),
                      ("diag", "process")},
    "analysis": {("pc", "stats"), ("storage", "free"), ("diag", "changes"),
                 ("pc", "sysinfo")},
    "system_read": {("pc", "heavy"), ("storage", "largest"), ("diag", "fixes")},
    "network_read": {("net", "connections"), ("diag", "ports")},
    "user_ops": {("apps", "open"), ("apps", "close"), ("window", "focus"),
                 ("control", "volume_set"), ("timer", "set"),
                 ("vault", "write")},
    "verify": {("pc", "stats"), ("diag", "changes")},
}

# Which groups are real analysis vs owner-facing operations. Security agents
# never surface user_ops; the assistant never surfaces security_read. The V2
# specialists get read-only analysis surfaces only: PLANNER may
# PROPOSE user-facing steps but its own requests stay catalog-read-only;
# DIAGNOSTICS reads system+security state; FORENSICS reads security state;
# RESPONSE may READ security/system state and nothing else -- every action
# step it drafts is a proposal the owner takes through the normal path.
_GROUP_POLICY = {
    "security": {"security_read", "analysis", "verify"},
    "threat": {"security_read", "analysis", "verify"},
    "assistant": {"analysis", "user_ops", "verify"},
    "system": {"analysis", "system_read"},
    "network": {"analysis", "network_read"},
    "verifier": {"analysis", "verify"},
    "planner": {"analysis", "system_read", "network_read"},
    "diagnostics": {"analysis", "system_read", "security_read"},
    "forensics": {"security_read", "analysis", "verify"},
    "response": {"analysis", "security_read", "system_read"},
}


class CapabilityDecision:
    __slots__ = ("accepted", "reason", "risk", "skill", "action", "target")

    def __init__(self, skill: str, action: str, target: str,
                 accepted: bool, reason: str, risk: str = ""):
        self.skill, self.action, self.target = skill, action, target
        self.accepted, self.reason, self.risk = accepted, reason, risk

    def as_dict(self) -> dict:
        return {"skill": self.skill, "action": self.action,
                "target": self.target, "accepted": self.accepted,
                "reason": self.reason, "risk": self.risk}


def _group_for(skill: str, action: str) -> str | None:
    for group, pairs in _GROUPS.items():
        if (skill, action) in pairs:
            return group
    return None


def _agent_groups(agent_id: str) -> set[str]:
    groups = _GROUP_POLICY.get(agent_id)
    if groups is not None:
        return groups
    # Not one of the ten core agents. A TEMPORARY agent may request only its
    # approved groups INTERSECTED with every live ancestor's (recomputed now,
    # not trusted from spawn time); an unknown id gets the empty set, so every
    # request is denied -- unknown = denied.
    try:
        from agents.ephemeral import effective_groups
        return set(effective_groups(agent_id))
    except Exception:
        return set()


def process_request(agent_id: str, req: dict) -> CapabilityDecision:
    """Validate ONE capability request. Read-only on the world: audit + return.

    Checks, in order (all must pass, fail-closed):
      1. shape: skill/action are non-empty strings; target within router's own
         500-char bound
      2. the (skill, action) pair exists in router.validate_plan()'s allowlist
         -- if the planner's validator would reject it as a step, an agent
         cannot propose it either
      3. auth.level_for() risk cap: > REQUEST_RISK_CAP is refused for surfacing
      4. the agent's declared group list covers it
    Then: audited, always, accepted or not, as a security event.
    """
    skill = str((req or {}).get("skill", "")).strip().lower()
    action = str((req or {}).get("action", "")).strip().lower()
    target = str((req or {}).get("target", "") or "")

    def _no(why: str, risk: str = "") -> CapabilityDecision:
        security.security_event(
            security.AGENT_CAPABILITY_DENIED, component="agents",
            agent=agent_id, skill=skill, action=action,
            reason=why, status="denied")
        return CapabilityDecision(skill, action, target, False, why, risk)

    if not skill or not action or len(target) > 500:
        return _no("malformed_request")
    steps, refusal = router.validate_plan([{"skill": skill, "action": action,
                                            "target": target}])
    if refusal or not steps:
        return _no("not_plannable")
    level = auth.level_for(skill, action)
    if level > REQUEST_RISK_CAP:
        return _no(f"risk_level_L{level}_exceeds_cap_L{REQUEST_RISK_CAP}",
                   risk=f"L{level}")
    group = _group_for(skill, action)
    if group is None or group not in _agent_groups(agent_id):
        return _no("group_not_allowed_for_agent")
    d = CapabilityDecision(skill, action, target, True, "surfaced_for_owner",
                           risk=f"L{level}")
    security.security_event(
        security.AGENT_CAPABILITY_REQUESTED, component="agents",
        agent=agent_id, skill=skill, action=action,
        level=level, status="requested")
    return d


def process_all(agent_id: str, requests: list[dict]) -> list[dict]:
    """Filter a result's requested_capabilities. Returns the ACCEPTED subset
    (surfaced to the owner); refusals are counted in the audit trail only."""
    out = []
    for req in (requests or [])[:6]:
        d = process_request(agent_id, req)
        if d.accepted:
            out.append(d.as_dict())
    return out
