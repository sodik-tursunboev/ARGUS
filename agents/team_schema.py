'ARGUS - Agent teams: the TeamPlan schema.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import enum
import hashlib
import re
from dataclasses import dataclass, field

from agents.definitions import ALL_AGENTS, CONTEXT_CATEGORIES
from agents.dynamic_spec import (ALWAYS_DENIED, GRANTABLE_CAPABILITIES,
                                 GRANTABLE_DATA_CLASSES, clean_text)
from agents.dynamic_spec import MAX_HANDOFFS as _P1_MAX_HANDOFFS


MAX_TEAM_MEMBERS = 6
MAX_EPHEMERAL_PER_TEAM = 3
MAX_REPLANS = 2
MAX_HANDOFFS = _P1_MAX_HANDOFFS
MAX_TASKS = 12
MAX_ACTIVE_TEAMS = 3
MAX_INFLIGHT_PER_TEAM = 2                # jobs queued/running at once per team
DEFAULT_MODEL_CALLS = 14
MAX_MODEL_CALLS = 30
DEFAULT_TEAM_RUNTIME_S = 600
MAX_TEAM_RUNTIME_S = 1800
DEFAULT_TASK_TIMEOUT_S = 120
MAX_TASK_TIMEOUT_S = 300
MAX_GOAL_CHARS = 1200
MAX_TITLE_CHARS = 80
MAX_OBJECTIVE_CHARS = 700
MAX_INPUT_REFS = 8
# Structural, not configurable here: ONE coordinator worker thread pulls from
# ONE queue in front of ONE SharedModelRuntime, so at most one heavy inference
# is in flight however many logical agents exist.
MAX_HEAVY_MODEL_INFERENCE = 1

CORE_IDS = frozenset(a.id for a in ALL_AGENTS)
DATA_SCOPE_EXTRA = frozenset({"team_evidence"})


class TaskState(str, enum.Enum):
    PENDING = "PENDING"
    BLOCKED = "BLOCKED"
    READY = "READY"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


class TeamState(str, enum.Enum):
    PLANNING = "PLANNING"
    READY = "READY"
    RUNNING = "RUNNING"
    VERIFYING = "VERIFYING"
    REPLANNING = "REPLANNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


class TaskKind(str, enum.Enum):
    AGENT = "AGENT"          # work by a core agent or a temporary specialist
    VERIFY = "VERIFY"        # the independent verification stage


class FailurePolicy(str, enum.Enum):
    REPLAN = "REPLAN"        # retry once, then a bounded replan, else PARTIAL
    PARTIAL = "PARTIAL"      # no replan: keep what completed, report the rest
    FAIL = "FAIL"            # any required failure fails the team


class Verdict(str, enum.Enum):
    VERIFIED = "VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    CONTRADICTED = "CONTRADICTED"
    FAILED = "FAILED"


TASK_TERMINAL = frozenset({TaskState.COMPLETED, TaskState.FAILED,
                           TaskState.SKIPPED, TaskState.CANCELLED,
                           TaskState.TIMED_OUT})
TEAM_TERMINAL = frozenset({TeamState.COMPLETED, TeamState.PARTIAL,
                           TeamState.FAILED, TeamState.CANCELLED,
                           TeamState.TIMED_OUT})
# Worst verdict wins when two independent assessments are combined.
VERDICT_RANK = {Verdict.VERIFIED: 0, Verdict.PARTIALLY_VERIFIED: 1,
                Verdict.INSUFFICIENT_EVIDENCE: 2, Verdict.CONTRADICTED: 3,
                Verdict.FAILED: 4}

_TID = re.compile(r"^T[1-9][0-9]?$")
_MID = re.compile(r"^M[1-9]$")
_ID_ROLE = re.compile(r"^[a-z][a-z_]{1,31}$")
_EV_REF = re.compile(r"^(ev-[0-9a-f]{8}|task:T[1-9][0-9]?)$")
_SCHEMAS = frozenset({"analysis", "verdict", "plan"})


class PlanError(ValueError):
    """The plan is not valid. `code` is a stable machine-readable string."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}{': ' + detail if detail else ''}")
        self.code = code


def _need(cond: bool, code: str, detail: str = "") -> None:
    if not cond:
        raise PlanError(code, detail)


def _int(v, lo: int, hi: int, code: str) -> int:
    _need(isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi,
          code, f"{v!r} not in {lo}..{hi}")
    return v


def team_id_for(request_id: str) -> str:
    """Deterministic: the same request id always names the same team."""
    return "team-" + hashlib.sha256(str(request_id).encode()).hexdigest()[:8]


def goal_digest(goal: str) -> str:
    """What the audit trail records instead of the goal text."""
    return hashlib.sha256(str(goal).encode("utf-8", "replace")).hexdigest()[:12]


@dataclass(frozen=True)
class TeamMember:
    member_id: str                 # M1..M6, deterministic
    role: str                      # a core agent id, or an Architect template key
    kind: str                      # "core" | "specialist"
    agent_id: str = ""             # core id; "" until a specialist is spawned
    parent_agent_id: str = ""      # a specialist's CORE parent (owner-approved)


@dataclass(frozen=True)
class TeamTaskSpec:
    task_id: str
    title: str
    objective: str
    member_id: str
    required_role: str
    kind: TaskKind = TaskKind.AGENT
    assigned_agent_id: str = ""            # core id; "" for a specialist
    inputs: tuple = ()                     # evidence ids / "task:T#" refs
    dependencies: tuple = ()
    trigger: str = "all_completed"         # | "all_terminal" (verification)
    allowed_data_scope: tuple = ()
    requested_capabilities: tuple = ()
    expected_output_schema: str = "analysis"
    timeout_seconds: int = DEFAULT_TASK_TIMEOUT_S
    priority: int = 2
    required: bool = True
    max_attempts: int = 2                  # one retry for a transient failure
    lineage: tuple = ()                    # roles this work descends from
    origin: str = "plan"                   # plan | handoff | replan | nested


@dataclass(frozen=True)
class TeamPlan:
    team_id: str
    request_id: str
    goal: str
    created_at: float
    members: tuple
    tasks: tuple
    priority: int = 2
    max_agents: int = MAX_TEAM_MEMBERS
    max_ephemeral_agents: int = MAX_EPHEMERAL_PER_TEAM
    max_model_calls: int = DEFAULT_MODEL_CALLS
    max_handoffs: int = MAX_HANDOFFS
    max_replans: int = MAX_REPLANS
    max_runtime_seconds: int = DEFAULT_TEAM_RUNTIME_S
    failure_policy: FailurePolicy = FailurePolicy.REPLAN
    completion_condition: str = "verified"
    mode: str = "team"                     # "team" | "single"
    goal_digest_: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        set_ = lambda k, v: object.__setattr__(self, k, v)   # noqa: E731
        _need(bool(re.match(r"^team-[0-9a-f]{8}$", str(self.team_id))), "bad_team_id")
        _need(isinstance(self.request_id, str) and 1 <= len(self.request_id) <= 40,
              "bad_request_id")
        goal = clean_text(self.goal, MAX_GOAL_CHARS)
        _need(bool(goal), "empty_goal")
        set_("goal", goal)
        set_("goal_digest_", goal_digest(goal))
        _need(isinstance(self.created_at, (int, float)) and self.created_at > 0,
              "bad_created_at")
        _int(self.priority, 1, 4, "bad_priority")
        _int(self.max_agents, 1, MAX_TEAM_MEMBERS, "bad_max_agents")
        _int(self.max_ephemeral_agents, 0, MAX_EPHEMERAL_PER_TEAM,
             "bad_max_ephemeral")
        _need(self.max_ephemeral_agents <= self.max_agents, "ephemeral_over_agents")
        _int(self.max_model_calls, 1, MAX_MODEL_CALLS, "bad_max_model_calls")
        _int(self.max_handoffs, 0, MAX_HANDOFFS, "bad_max_handoffs")
        _int(self.max_replans, 0, MAX_REPLANS, "bad_max_replans")
        _int(self.max_runtime_seconds, 5, MAX_TEAM_RUNTIME_S, "bad_runtime")
        _need(isinstance(self.failure_policy, FailurePolicy), "bad_failure_policy")
        _need(self.completion_condition in ("verified", "all_required_completed"),
              "bad_completion_condition")
        _need(self.mode in ("team", "single"), "bad_mode")
        set_("members", tuple(self.members))
        set_("tasks", tuple(self.tasks))
        _validate_members(self)
        _validate_tasks(self)
        validate_dag(self.tasks)

    @property
    def deadline(self) -> float:
        return self.created_at + self.max_runtime_seconds

    @property
    def edges(self) -> tuple:
        return tuple((d, t.task_id) for t in self.tasks for d in t.dependencies)

    def member(self, member_id: str) -> TeamMember:
        return next(m for m in self.members if m.member_id == member_id)

    def task(self, task_id: str) -> TeamTaskSpec:
        return next(t for t in self.tasks if t.task_id == task_id)

    def as_dict(self) -> dict:
        return {
            "team_id": self.team_id, "request_id": self.request_id,
            "goal_digest": self.goal_digest_, "created_at": self.created_at,
            "deadline": self.deadline, "priority": self.priority,
            "mode": self.mode, "failure_policy": self.failure_policy.value,
            "completion_condition": self.completion_condition,
            "budgets": {"max_agents": self.max_agents,
                        "max_ephemeral_agents": self.max_ephemeral_agents,
                        "max_model_calls": self.max_model_calls,
                        "max_handoffs": self.max_handoffs,
                        "max_replans": self.max_replans,
                        "max_runtime_seconds": self.max_runtime_seconds},
            "members": [m.__dict__ for m in self.members],
            "tasks": [{"task_id": t.task_id, "title": t.title,
                       "member_id": t.member_id, "role": t.required_role,
                       "kind": t.kind.value, "dependencies": list(t.dependencies),
                       "required": t.required, "origin": t.origin}
                      for t in self.tasks],
            "dependencies": [list(e) for e in self.edges],
        }


def _validate_members(plan: TeamPlan) -> None:
    ms = plan.members
    _need(1 <= len(ms) <= plan.max_agents, "bad_member_count", str(len(ms)))
    seen = set()
    eph = 0
    for m in ms:
        _need(isinstance(m, TeamMember) and _MID.match(m.member_id or ""),
              "bad_member_id")
        _need(m.member_id not in seen, "duplicate_member", m.member_id)
        seen.add(m.member_id)
        _need(_ID_ROLE.match(m.role or ""), "bad_role", m.role)
        _need(m.kind in ("core", "specialist", "cloud"), "bad_member_kind")
        if m.kind == "core":
            _need(m.agent_id in CORE_IDS and m.role == m.agent_id,
                  "unknown_core_agent", m.agent_id)
        else:
            eph += 1
            _need(m.parent_agent_id in CORE_IDS, "specialist_needs_core_parent",
                  m.parent_agent_id)
    _need(eph <= plan.max_ephemeral_agents, "too_many_specialists", str(eph))


def _validate_tasks(plan: TeamPlan) -> None:
    ts = plan.tasks
    _need(1 <= len(ts) <= MAX_TASKS, "bad_task_count", str(len(ts)))
    ids = {t.task_id for t in ts}
    _need(len(ids) == len(ts), "duplicate_task_id")
    members = {m.member_id for m in plan.members}
    used = set()
    for t in ts:
        _need(isinstance(t, TeamTaskSpec) and _TID.match(t.task_id or ""),
              "bad_task_id")
        _need(t.member_id in members, "unknown_member", t.member_id)
        used.add(t.member_id)
        _need(1 <= len(clean_text(t.title, MAX_TITLE_CHARS + 1)) <= MAX_TITLE_CHARS
              and t.title == clean_text(t.title, MAX_TITLE_CHARS), "bad_title")
        _need(1 <= len(t.objective) <= MAX_OBJECTIVE_CHARS
              and t.objective == clean_text(t.objective, MAX_OBJECTIVE_CHARS),
              "bad_objective")
        _need(isinstance(t.kind, TaskKind), "bad_kind")
        _need(_ID_ROLE.match(t.required_role or ""), "bad_role", t.required_role)
        mem = plan.member(t.member_id)
        if mem.kind == "core":
            _need(t.assigned_agent_id == mem.agent_id, "assigned_agent_mismatch")
        else:
            _need(t.assigned_agent_id == "", "specialist_is_bound_at_spawn")
        _need(len(t.dependencies) <= MAX_TASKS
              and all(d in ids and d != t.task_id for d in t.dependencies),
              "unresolved_dependency", t.task_id)
        _need(t.trigger in ("all_completed", "all_terminal"), "bad_trigger")
        _need(len(t.inputs) <= MAX_INPUT_REFS
              and all(isinstance(i, str) and _EV_REF.match(i) for i in t.inputs),
              "bad_inputs", t.task_id)
        for scope in t.allowed_data_scope:
            _need(scope in (GRANTABLE_DATA_CLASSES | DATA_SCOPE_EXTRA
                            | set(CONTEXT_CATEGORIES)),
                  "bad_data_scope", str(scope)[:32])
        for cap in t.requested_capabilities:
            _need(cap not in ALWAYS_DENIED, "plan_forbidden_capability",
                  str(cap)[:32])
            _need(cap in GRANTABLE_CAPABILITIES, "plan_unknown_capability",
                  str(cap)[:32])
        _need(t.expected_output_schema in _SCHEMAS, "bad_output_schema")
        _int(t.timeout_seconds, 1, MAX_TASK_TIMEOUT_S, "bad_timeout")
        _int(t.priority, 1, 4, "bad_task_priority")
        _int(t.max_attempts, 1, 3, "bad_max_attempts")
        _need(isinstance(t.required, bool), "bad_required")
        _need(t.origin in ("plan", "handoff", "replan", "nested"), "bad_origin")
        _need(all(isinstance(r, str) and _ID_ROLE.match(r) for r in t.lineage)
              and len(t.lineage) <= MAX_HANDOFFS + 2, "bad_lineage")
        if t.kind is TaskKind.VERIFY:
            _need(t.expected_output_schema == "verdict"
                  and t.trigger == "all_terminal" and t.dependencies,
                  "bad_verify_task", t.task_id)
    _need(used == members, "unused_member")


def validate_dag(tasks) -> None:
    """Kahn's algorithm. A cycle, or a dependency that does not exist, is an
    invalid plan -- never silently trimmed."""
    ids = {t.task_id for t in tasks}
    indeg = {t.task_id: 0 for t in tasks}
    out: dict = {t.task_id: [] for t in tasks}
    for t in tasks:
        for d in t.dependencies:
            _need(d in ids, "unresolved_dependency", f"{t.task_id}->{d}")
            indeg[t.task_id] += 1
            out[d].append(t.task_id)
    ready = [i for i, n in indeg.items() if n == 0]
    seen = 0
    while ready:
        cur = ready.pop()
        seen += 1
        for nxt in out[cur]:
            indeg[nxt] -= 1
            if indeg[nxt] == 0:
                ready.append(nxt)
    _need(seen == len(tasks), "dependency_cycle")


def depth_map(tasks) -> dict:
    """Longest dependency chain ending at each task (for scheduling order)."""
    by = {t.task_id: t for t in tasks}
    memo: dict = {}

    def depth(tid: str) -> int:
        if tid not in memo:
            deps = by[tid].dependencies
            memo[tid] = 0 if not deps else 1 + max(depth(d) for d in deps)
        return memo[tid]

    return {t.task_id: depth(t.task_id) for t in tasks}


def downstream_count(tasks) -> dict:
    """How many tasks (transitively) wait on each task: a critical-path hint."""
    kids: dict = {t.task_id: [] for t in tasks}
    for t in tasks:
        for d in t.dependencies:
            kids[d].append(t.task_id)

    def reach(tid: str, seen: set) -> set:
        for k in kids[tid]:
            if k not in seen:
                seen.add(k)
                reach(k, seen)
        return seen

    return {t.task_id: len(reach(t.task_id, set())) for t in tasks}
