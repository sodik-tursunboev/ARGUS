'ARGUS - Agent Kernel: the capability catalogue.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

from dataclasses import dataclass

import auth
import router
from skills import registry


@dataclass(frozen=True)
class Capability:
    """One (skill, action) pair, described. Immutable -- a Capability handed
    to a caller (or, eventually, to the local model as context) cannot be
    mutated into claiming a different risk level than the catalogue actually
    computed."""
    skill: str
    action: str
    description: str
    risk: str            # "L0".."L5" -- from auth.level_for(), see module docstring
    reversible: bool      # PLANNABLE excludes irreversible ops by construction
    confirmation: str     # "none" | "policy" | "explicit" -- see _confirmation_for()
    inputs: tuple[tuple[str, str], ...]
    output: str
    effects: tuple[str, ...]
    constraints: tuple[str, ...]
    failure_modes: tuple[str, ...]
    observation: str

    @property
    def name(self) -> str:
        return f"{self.skill}/{self.action}"

    def __str__(self) -> str:
        return f"{self.name} ({self.risk}): {self.description}"

    def as_dict(self) -> dict:
        """Machine-readable semantic contract for planners and local UI."""
        return {
            "name": self.name,
            "description": self.description,
            "inputs": dict(self.inputs),
            "output": self.output,
            "effects": list(self.effects),
            "risk": self.risk,
            "reversible": self.reversible,
            "confirmation": self.confirmation,
            "constraints": list(self.constraints),
            "failure_modes": list(self.failure_modes),
            "observation": self.observation,
        }


_READ_ACTIONS = {
    "analyze", "changes", "connections", "cursor_location", "defenses",
    "display", "extract_text", "find", "find_elements", "fixes", "free",
    "heavy", "installed", "largest", "list", "list_tabs", "locate_text",
    "ports", "process", "read", "read_text", "screenshot", "stats",
    "sysinfo", "ui_read", "ui_tree", "verify_text",
}


def _effects_for(skill: str, action: str) -> tuple[str, ...]:
    """Describe effects, never permission. The real gate remains auth.py."""
    if (skill, action) in router.CHAINABLE or action in _READ_ACTIONS:
        return ("read_only",)
    if skill in {"apps", "window", "pc", "control"}:
        return ("local_ui_state",)
    if skill in {"files", "vault", "timer"}:
        return ("local_storage_write",)
    if skill == "browser":
        return ("browser_state",)
    return ("bounded_local_state",)


def _constraints_for(skill: str, action: str) -> tuple[str, ...]:
    constraints = [
        "registered_plannable_capability",
        "bounded_text_target",
        "whole_plan_validation",
        "per_step_policy_and_authentication",
    ]
    if skill == "files":
        constraints.append("permitted_workspace_roots")
    if skill == "browser":
        constraints.append("reviewed_browser_action_and_network_policy")
    if skill in {"pc", "window"} and action.startswith("ui_"):
        constraints.append("named_uia_target_only")
    return tuple(constraints)


def _confirmation_for(level: int) -> str:
    """What owning this capability costs the caller, in plain terms.

    Mirrors auth.py's own tiers rather than inventing a fourth vocabulary:
    L0/L1 need nothing beyond the machine being unlocked (or nothing at all
    for L0), L2 needs a fresh authentication, L3+ needs an explicit spoken
    confirmation on top of that. "policy" covers L1-L2 because whether it
    actually pauses depends on how stale the last auth is -- authorize()
    decides that at call time, not this table.
    """
    if level <= auth.L0_OPEN:
        return "none"
    if level < auth.L3_CONFIRM:
        return "policy"
    return "explicit"


def _describe(skill: str, action: str) -> str:
    """The registry's own one-line description for this pair, or "" if the
    registry does not (yet) describe it -- see undescribed()."""
    return registry.SKILLS.get(skill, {}).get("actions", {}).get(action, "")


def _build_catalog() -> dict[tuple[str, str], Capability]:
    out: dict[tuple[str, str], Capability] = {}
    for skill, action in sorted(router.PLANNABLE):
        desc = _describe(skill, action)
        level = auth.level_for(skill, action)
        out[(skill, action)] = Capability(
            skill=skill, action=action,
            description=desc or f"{skill} {action} (undescribed)",
            risk=auth.LEVEL_NAMES.get(level, str(level)),
            reversible=True,
            confirmation=_confirmation_for(level),
            inputs=(("target", "bounded string"),),
            output="structured Observation plus owner-facing result",
            effects=_effects_for(skill, action),
            constraints=_constraints_for(skill, action),
            failure_modes=("invalid_target", "policy_refused",
                           "authentication_required", "capability_error",
                           "verification_unavailable"),
            observation="reply classification with optional before/after verifier",
        )
    return out


# Built once at import time. router.PLANNABLE, auth.LEVELS and
# registry.SKILLS are themselves module-level constants that do not change
# at runtime, so there is nothing to gain from rebuilding this per call --
# and every caller sharing one object is what makes it cheap to hand to the
# local model as context later.
CATALOG: dict[tuple[str, str], Capability] = _build_catalog()


def get(skill: str, action: str) -> Capability | None:
    return CATALOG.get((str(skill).strip(), str(action).strip()))


def all_capabilities() -> list[Capability]:
    return sorted(CATALOG.values(), key=lambda c: c.name)


def undescribed() -> list[tuple[str, str]]:
    """Pairs in router.PLANNABLE that the registry does not describe. Empty
    is the goal; non-empty means skills.registry.SKILLS is missing an entry
    for something PLANNABLE actually contains -- a registry gap worth fixing
    there, not here (see the module docstring)."""
    return sorted(k for k, c in CATALOG.items() if "(undescribed)" in c.description)


def find(query: str, limit: int = 8) -> list[Capability]:
    """Search capability names and descriptions by keyword."""
    q = str(query or "").strip().lower()
    if not q:
        return []
    terms = [t for t in q.split() if t]
    scored = []
    for cap in CATALOG.values():
        hay = f"{cap.name} {cap.description}".lower()
        hits = sum(1 for t in terms if t in hay)
        if hits:
            scored.append((hits, cap))
    scored.sort(key=lambda pair: (-pair[0], pair[1].name))
    return [cap for _, cap in scored[:limit]]


def describe() -> str:
    """One-line summary for a status panel or a boot report."""
    skills = {c.skill for c in CATALOG.values()}
    gaps = undescribed()
    base = f"{len(CATALOG)} capabilities across {len(skills)} skills"
    return base if not gaps else f"{base} ({len(gaps)} undescribed)"
