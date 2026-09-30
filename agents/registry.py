'ARGUS - Local agents: the registry.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time
from dataclasses import dataclass, field

from agents.definitions import (ALL_AGENTS, CONTEXT_CATEGORIES, SHARED_MODEL,
                                AgentSpec)
from agents.dynamic_spec import (LIVE_STATUSES, MAX_ACTIVE_EPHEMERAL_AGENTS,
                                 MAX_CHILDREN_PER_AGENT, MAX_SPAWN_DEPTH,
                                 AgentType, DynamicAgentSpec, approval_valid)


class UnknownAgentError(KeyError):
    """Raised for any agent id the registry does not contain."""


class CapacityError(RuntimeError):
    """A dynamic registration would breach a hard limit. `code` is the same
    stable reason vocabulary the Governor uses."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class AgentRuntime:
    """Everything mutable about one agent. Owned by the coordinator under
    the registry lock; the API reads snapshots through agent_status()."""
    spec: AgentSpec
    state: str = "idle"
    current_job_id: str = ""
    queue_position: int = 0
    last_activity_at: float = field(default_factory=time.time)
    last_error: str = ""
    completed_jobs: int = 0
    failed_jobs: int = 0


@dataclass
class DynamicRuntime:
    """One TEMPORARY agent: its frozen, Governor-approved spec plus the
    mutable bookkeeping of its short life.

    `runtime` is the coordinator-facing view (an AgentRuntime whose `spec` is
    an AgentSpec synthesised from `dspec` by agents/ephemeral.py), so the
    coordinator's queue/state code treats a temporary agent exactly like a
    core one. The lifecycle status lives in `dspec.status`; only the
    EphemeralManager writes it, and every change is recorded in `history`.
    """
    dspec: DynamicAgentSpec
    runtime: AgentRuntime
    history: list = field(default_factory=list)   # [(status, ts, note)]
    children: list = field(default_factory=list)  # every child id ever spawned
    spawned_total: int = 0
    model_calls_used: int = 0
    handoffs_used: int = 0
    job_ids: list = field(default_factory=list)
    pending_jobs: int = 0
    result_summary: str = ""
    termination_reason: str = ""
    terminal_at: float = 0.0
    requester: str = ""
    proposal_id: str = ""
    decision_id: str = ""
    task_digest: str = ""
    coord: object = None       # the Coordinator that owns this agent's jobs


class AgentRegistry:
    def __init__(self):
        self._agents: dict[str, AgentRuntime] = {
            spec.id: AgentRuntime(spec=spec) for spec in ALL_AGENTS
        }
        # TEMPORARY agents live in their own map. They are deliberately NOT in
        # _agents: all()/ids()/known() are the CORE view every existing caller
        # (status API, routing candidates, autonomy) depends on, and a spawn
        # must never change what those return.
        self._dynamic: dict[str, DynamicRuntime] = {}
        self._lock = threading.RLock()
        if not self._agents:
            raise RuntimeError("agents: no agents registered")
        for rt in self._agents.values():
            if not rt.spec.shared_model:

                # shared_model=False would mean a second model instance on a
                # 4 GB card.
                raise RuntimeError(f"agents: {rt.spec.id} is not a shared-model agent")
            # V2: every context category a spec names must have a source in
            # context.py -- a category with no source would silently feed the
            # agent nothing and look like a data outage.
            for cat in rt.spec.allowed_context_categories:
                if cat not in CONTEXT_CATEGORIES:
                    raise RuntimeError(
                        f"agents: {rt.spec.id} names unknown context category {cat!r}")
        # V2: handoff edges must point at registered agents (typo-proof),
        # and the verifier stays terminal. The graph must be acyclic.
        for rt in self._agents.values():
            for target in rt.spec.handoff_targets:
                if target not in self._agents:
                    raise RuntimeError(
                        f"agents: {rt.spec.id} hands off to unknown agent {target!r}")
        if self._agents["verifier"].spec.handoff_targets:
            raise RuntimeError("agents: verifier must be terminal")
        # Validate the handoff graph: edges point at registered agents,
        # verifier is terminal, and no self-loops. Bounded depth
        # (MAX_HANDOFFS) prevents any cycle from being infinite.
        for rt in self._agents.values():
            for target in rt.spec.handoff_targets:
                if target not in self._agents:
                    raise RuntimeError(
                        f"agents: {rt.spec.id} hands off to unknown agent {target!r}")
        if self._agents["verifier"].spec.handoff_targets:
            raise RuntimeError("agents: verifier must be terminal")
        # No self-loops
        for rt in self._agents.values():
            if rt.spec.id in rt.spec.handoff_targets:
                raise RuntimeError(
                    f"agents: {rt.spec.id} has a self-loop in handoff_targets")

    # ── lookups ──────────────────────────────────────────────────────────
    def get(self, agent_id: str) -> AgentRuntime:
        """The coordinator-facing runtime for a CORE or a live TEMPORARY agent
        (the coordinator treats both alike). ids()/all()/known() stay core-only."""
        with self._lock:
            rt = self._agents.get(agent_id)
            if rt is not None:
                return rt
            dyn = self._dynamic.get(agent_id)
            if dyn is not None:
                return dyn.runtime
            raise UnknownAgentError(agent_id)

    def require(self, agent_id: str) -> AgentSpec:
        return self.get(agent_id).spec

    def ids(self) -> list[str]:
        """CORE agent ids only -- never temporary agents."""
        with self._lock:
            return sorted(self._agents)

    def all(self) -> list[AgentRuntime]:
        """CORE agents only -- never temporary agents."""
        with self._lock:
            return list(self._agents.values())

    def known(self, agent_id: str) -> bool:
        """True for a CORE agent id (temporary agents: see is_dynamic())."""
        with self._lock:
            return agent_id in self._agents

    # ── lifecycle state ──────────────────────────────────────────────────
    def _runtime_or_none(self, agent_id: str) -> "AgentRuntime | None":
        rt = self._agents.get(agent_id)
        if rt is not None:
            return rt
        dyn = self._dynamic.get(agent_id)
        return dyn.runtime if dyn is not None else None

    def set_state(self, agent_id: str, state: str, *, job_id: str = "",
                  queue_position: int = 0, error: str = "") -> None:
        with self._lock:
            rt = self._runtime_or_none(agent_id)
            if rt is None:
                return      # a temporary agent destroyed under a running job
            rt.state = state
            rt.current_job_id = job_id
            rt.queue_position = queue_position
            if error:
                rt.last_error = error
            rt.last_activity_at = time.time()

    def mark_done(self, agent_id: str, *, ok: bool, job_id: str = "") -> None:
        with self._lock:
            rt = self._runtime_or_none(agent_id)
            if rt is None:
                return      # a temporary agent destroyed under a running job
            rt.state = "idle"
            rt.current_job_id = ""
            rt.queue_position = 0
            rt.last_activity_at = time.time()
            if ok:
                rt.completed_jobs += 1
            else:
                rt.failed_jobs += 1

    # ── temporary (dynamic) agents ───────────────────────────────────────
    # The registry is a STORE with hard-limit backstops, not a decision maker.
    # It will hold a temporary agent only if agents.governor approved exactly
    # that spec (register_dynamic verifies the approval), and it re-checks the
    # numeric limits atomically under its own lock -- the Governor evaluates
    # and the registry commits, so two racing spawns can never both squeeze
    # past a cap.
    def agent_type(self, agent_id: str) -> "AgentType | None":
        with self._lock:
            if agent_id in self._agents:
                return AgentType.CORE
            if agent_id in self._dynamic:
                return self._dynamic[agent_id].dspec.agent_type
            return None

    def is_dynamic(self, agent_id: str) -> bool:
        with self._lock:
            return agent_id in self._dynamic

    def get_dynamic(self, agent_id: str) -> "DynamicRuntime | None":
        with self._lock:
            return self._dynamic.get(agent_id)

    def dynamic_all(self) -> "list[DynamicRuntime]":
        with self._lock:
            return list(self._dynamic.values())

    def dynamic_children(self, parent_id: str, *,
                         live_only: bool = False) -> "list[DynamicRuntime]":
        with self._lock:
            return [d for d in self._dynamic.values()
                    if d.dspec.parent_agent_id == parent_id
                    and (not live_only or d.dspec.status in LIVE_STATUSES)]

    def live_dynamic_count(self) -> int:
        with self._lock:
            return sum(1 for d in self._dynamic.values()
                       if d.dspec.status in LIVE_STATUSES)

    def find_live_duplicate(self, parent_id: str,
                            digest: str) -> "DynamicRuntime | None":
        with self._lock:
            for d in self._dynamic.values():
                if (d.dspec.parent_agent_id == parent_id
                        and d.task_digest == digest
                        and d.dspec.status in LIVE_STATUSES):
                    return d
            return None

    def register_dynamic(self, rec: DynamicRuntime, approval) -> None:
        """Hold a temporary agent. Refuses (PermissionError) anything the
        Governor did not approve, and (CapacityError) anything that would
        breach a hard limit."""
        s = rec.dspec
        if not approval_valid(approval, s):
            raise PermissionError(
                "a temporary agent may be registered only with the Governor's "
                "approval of exactly this spec")
        if not rec.runtime.spec.shared_model or rec.runtime.spec.id != s.agent_id:
            raise ValueError("runtime spec does not match the approved spec")
        with self._lock:
            if s.agent_id in self._agents or s.agent_id in self._dynamic:
                raise ValueError("duplicate agent id")
            if s.spawn_depth > MAX_SPAWN_DEPTH:
                raise CapacityError("spawn_depth_exceeded")
            live = sum(1 for d in self._dynamic.values()
                       if d.dspec.status in LIVE_STATUSES)
            if live >= MAX_ACTIVE_EPHEMERAL_AGENTS:
                raise CapacityError("max_active_agents_exceeded")
            parent_dyn = self._dynamic.get(s.parent_agent_id)
            if parent_dyn is None and s.parent_agent_id not in self._agents:
                raise CapacityError("unknown_parent")
            siblings = sum(1 for d in self._dynamic.values()
                           if d.dspec.parent_agent_id == s.parent_agent_id
                           and d.dspec.status in LIVE_STATUSES)
            if siblings >= MAX_CHILDREN_PER_AGENT:
                raise CapacityError("max_children_exceeded")
            if parent_dyn is not None:
                if parent_dyn.spawned_total >= parent_dyn.dspec.max_children:
                    raise CapacityError("max_children_exceeded")
                parent_dyn.children.append(s.agent_id)
                parent_dyn.spawned_total += 1
            self._dynamic[s.agent_id] = rec

    def unregister_dynamic(self, agent_id: str) -> "DynamicRuntime | None":
        with self._lock:
            return self._dynamic.pop(agent_id, None)

    def set_enabled(self, agent_id: str, enabled: bool) -> None:
        """Enable/disable is an owner decision made through the API, never an
        agent's own or a job's -- nothing else writes this flag."""
        with self._lock:
            self._agents[agent_id].spec = (
                self._agents[agent_id].spec.__class__(**{
                    **self._agents[agent_id].spec.__dict__,
                    "enabled": enabled,
                }))


_REGISTRY = AgentRegistry()


def registry() -> AgentRegistry:
    return _REGISTRY
