'ARGUS - Agent teams: runtime state.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time
from dataclasses import dataclass, field

from agents.team_evidence import EvidenceStore
from agents.team_schema import (TASK_TERMINAL, TEAM_TERMINAL, TaskKind,
                                TaskState, TeamPlan, TeamState, TeamTaskSpec)

_T = TaskState
_S = TeamState

TASK_TRANSITIONS: dict = {
    _T.PENDING:   frozenset({_T.BLOCKED, _T.READY, _T.SKIPPED, _T.CANCELLED}),
    _T.BLOCKED:   frozenset({_T.READY, _T.SKIPPED, _T.CANCELLED}),
    _T.READY:     frozenset({_T.QUEUED, _T.BLOCKED, _T.FAILED, _T.SKIPPED,
                             _T.CANCELLED}),
    _T.QUEUED:    frozenset({_T.RUNNING, _T.WAITING, _T.COMPLETED, _T.FAILED,
                             _T.CANCELLED, _T.TIMED_OUT}),
    _T.RUNNING:   frozenset({_T.WAITING, _T.COMPLETED, _T.FAILED,
                             _T.CANCELLED, _T.TIMED_OUT}),
    _T.WAITING:   frozenset({_T.READY, _T.RUNNING, _T.COMPLETED, _T.FAILED,
                             _T.CANCELLED, _T.TIMED_OUT}),
    _T.COMPLETED: frozenset(),
    _T.FAILED:    frozenset(),
    _T.SKIPPED:   frozenset(),
    _T.CANCELLED: frozenset(),
    _T.TIMED_OUT: frozenset(),
}

TEAM_TRANSITIONS: dict = {
    _S.PLANNING:   frozenset({_S.READY, _S.FAILED, _S.CANCELLED}),
    _S.READY:      frozenset({_S.RUNNING, _S.FAILED, _S.CANCELLED,
                              _S.TIMED_OUT}),
    _S.RUNNING:    frozenset({_S.VERIFYING, _S.REPLANNING, _S.COMPLETED,
                              _S.PARTIAL, _S.FAILED, _S.CANCELLED,
                              _S.TIMED_OUT}),
    _S.VERIFYING:  frozenset({_S.REPLANNING, _S.RUNNING, _S.COMPLETED,
                              _S.PARTIAL, _S.FAILED, _S.CANCELLED,
                              _S.TIMED_OUT}),
    _S.REPLANNING: frozenset({_S.RUNNING, _S.PARTIAL, _S.FAILED,
                              _S.CANCELLED, _S.TIMED_OUT}),
    _S.COMPLETED:  frozenset(),
    _S.PARTIAL:    frozenset(),
    _S.FAILED:     frozenset(),
    _S.CANCELLED:  frozenset(),
    _S.TIMED_OUT:  frozenset(),
}

MAX_RUN_EVENTS = 120        # bounded per-team activity log (ids/codes only)
MAX_TASK_HISTORY = 24


def can_transition_task(old: TaskState, new: TaskState) -> bool:
    return new in TASK_TRANSITIONS.get(old, frozenset())


def can_transition_team(old: TeamState, new: TeamState) -> bool:
    return new in TEAM_TRANSITIONS.get(old, frozenset())


@dataclass
class TaskRun:
    """One task's mutable life. `spec` never changes after the task is added
    (a replan ADDS tasks; it does not rewrite existing ones)."""
    spec: TeamTaskSpec
    state: TaskState = TaskState.PENDING
    attempt: int = 0
    agent_id: str = ""                 # bound worker: core id, or dyn- id once spawned
    job_id: str = ""                   # the coordinator job of the CURRENT attempt
    job_ids: list = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    ready_at: float = 0.0
    queued_at: float = 0.0
    started_at: float = 0.0
    finished_at: float = 0.0
    deadline: float = 0.0              # absolute; set when the attempt is queued
    wait_reason: str = ""              # "retry" | "nested_children"
    retry_at: float = 0.0
    result: object = None              # agents.team_results.NormalizedResult
    error: str = ""
    inputs_given: list = field(default_factory=list)   # [(evidence_id, text)]
    model_calls: int = 0
    dependency_state: str = "pending"
    replaced_by: str = ""
    history: list = field(default_factory=list)        # [(state, ts, note)]

    @property
    def task_id(self) -> str:
        return self.spec.task_id

    @property
    def terminal(self) -> bool:
        return self.state in TASK_TERMINAL

    @property
    def inflight(self) -> bool:
        return self.state in (TaskState.QUEUED, TaskState.RUNNING)

    def duration_s(self, now: float | None = None) -> float:
        if not self.started_at:
            return 0.0
        end = self.finished_at or (time.time() if now is None else now)
        return max(0.0, end - self.started_at)


@dataclass
class TeamRun:
    plan: TeamPlan
    state: TeamState = TeamState.PLANNING
    tasks: dict = field(default_factory=dict)          # task_id -> TaskRun
    playbook: str = ""
    material: str = ""                                  # owner-supplied, scrubbed
    material_ref: str = ""                              # its USER_SUPPLIED evidence id
    plan_versions: int = 1
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    finished_at: float = 0.0
    last_activity: float = field(default_factory=time.time)
    current_phase: str = "planning"
    replans: int = 0
    handoffs: int = 0
    handoffs_by_agent: dict = field(default_factory=dict)
    handoffs_refused: int = 0
    model_calls: int = 0
    specialists: dict = field(default_factory=dict)    # member_id -> dyn- id
    spawn_denials: int = 0
    evidence: EvidenceStore = field(default_factory=EvidenceStore)
    verdict: str = ""
    verify_log: list = field(default_factory=list)
    termination_reason: str = ""
    cancel_requested: bool = False
    cancel_reason: str = ""
    result: dict | None = None
    activity: list = field(default_factory=list)       # bounded [(ts, code, task, note)]
    done: threading.Event = field(default_factory=threading.Event)
    cleanup_s: float = 0.0
    history: list = field(default_factory=list)        # [(state, ts, note)]

    # ── identity ────────────────────────────────────────────────────
    @property
    def team_id(self) -> str:
        return self.plan.team_id

    @property
    def terminal(self) -> bool:
        return self.state in TEAM_TERMINAL

    # ── task views ──────────────────────────────────────────────────
    def ordered_tasks(self) -> list:
        return [self.tasks[t.task_id] for t in self.plan.tasks
                if t.task_id in self.tasks]

    def agent_tasks(self) -> list:
        return [r for r in self.ordered_tasks() if r.spec.kind is TaskKind.AGENT]

    def verify_tasks(self) -> list:
        return [r for r in self.ordered_tasks() if r.spec.kind is TaskKind.VERIFY]

    def inflight_count(self) -> int:
        return sum(1 for r in self.tasks.values() if r.inflight)

    def all_terminal(self) -> bool:
        return all(r.terminal for r in self.tasks.values())

    def next_task_id(self) -> str:
        n = 1
        while f"T{n}" in self.tasks:
            n += 1
        return f"T{n}"

    def progress(self) -> dict:
        total = len(self.tasks)
        done = sum(1 for r in self.tasks.values() if r.terminal)
        completed = sum(1 for r in self.tasks.values()
                        if r.state is TaskState.COMPLETED)
        return {"total": total, "terminal": done, "completed": completed,
                "fraction": (done / total) if total else 0.0}

    def elapsed_s(self, now: float | None = None) -> float:
        end = self.finished_at or (time.time() if now is None else now)
        return max(0.0, end - self.created_at)

    # ── recording ───────────────────────────────────────────────────
    def note(self, code: str, task_id: str = "", detail: str = "",
             ts: float | None = None) -> None:
        """A bounded activity line: codes and ids only, never text."""
        self.activity.append((time.time() if ts is None else ts, code[:40],
                              task_id[:8], detail[:80]))
        del self.activity[:-MAX_RUN_EVENTS]
        self.last_activity = time.time() if ts is None else ts

    def set_task_state(self, run: TaskRun, new: TaskState, note: str = "",
                       ts: float | None = None) -> bool:
        old = run.state
        if old is new:
            return True
        if not can_transition_task(old, new):
            self.note("illegal_task_transition", run.task_id,
                      f"{old.value}->{new.value}", ts)
            return False
        t = time.time() if ts is None else ts
        run.state = new
        run.history.append((new.value, t, note[:60]))
        del run.history[:-MAX_TASK_HISTORY]
        if new is TaskState.READY:
            run.ready_at = t
        elif new is TaskState.QUEUED:
            run.queued_at = t
        elif new is TaskState.RUNNING:
            run.started_at = run.started_at or t
        elif new in TASK_TERMINAL:
            run.finished_at = t
        self.last_activity = t
        return True

    def set_state(self, new: TeamState, note: str = "",
                  ts: float | None = None) -> bool:
        old = self.state
        if old is new:
            return True
        if not can_transition_team(old, new):
            self.note("illegal_team_transition", "", f"{old.value}->{new.value}", ts)
            return False
        t = time.time() if ts is None else ts
        self.state = new
        self.history.append((new.value, t, note[:60]))
        if new is TeamState.RUNNING and not self.started_at:
            self.started_at = t
        if new in TEAM_TERMINAL:
            self.finished_at = t
            if not self.termination_reason:
                self.termination_reason = note[:60] or new.value.lower()
        self.current_phase = new.value.lower()
        self.last_activity = t
        return True
