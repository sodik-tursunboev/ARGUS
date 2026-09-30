'ARGUS - Agent teams: the orchestrator.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import dataclasses
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass

from agents import cloud_worker, team_events as tev
from agents import team_planner, team_prompts, team_verifier
from agents.cloud_worker import FailureState
from agents.definitions import get_spec, handoff_allowed
from agents.dynamic_spec import (GRANTABLE_DATA_CLASSES, cloud_agents_enabled,
                                 SpawnRequest)
from agents.jobs import CANCELLED as JOB_CANCELLED
from agents.jobs import COMPLETED as JOB_COMPLETED
from agents.jobs import FAILED as JOB_FAILED
from agents.team_evidence import EvidenceClass, SourceType
from agents.team_results import failed_result, normalize
from agents.team_run import TaskRun, TeamRun
from agents.team_schema import (MAX_ACTIVE_TEAMS, MAX_INFLIGHT_PER_TEAM,
                                MAX_TEAM_MEMBERS, FailurePolicy, PlanError,
                                TaskKind, TaskState, TeamPlan, TeamState,
                                Verdict, depth_map, downstream_count, goal_digest)

TICK_S = 0.25
RETRY_DELAY_S = 0.5
MAX_HISTORY_TEAMS = 20
MAX_HANDOFFS_PER_TEAM = 3
MAX_RESULT_CACHE = 200
TRANSIENT_SUBMIT_REFUSALS = frozenset({"queue_full"})
# Failures that retrying cannot fix: a deterministic refusal, a spent budget,
# a posture change. (Everything else -- a model error, a timeout, an evicted
# job -- gets the task's remaining attempts.)
NON_RETRYABLE_PREFIXES = ("spawn_denied", "budget_exhausted", "agent_disabled",
                          "unknown_agent", "priority_above_agent_ceiling",
                          "empty_objective", "bad_priority", "ttl_expired",
                          "parent_not_live", "policy_state", "dynamic_agents",
                          "team_ephemeral_budget", "cancelled", "agent_gone",
                          "cloud_agents_disabled", "cloud:policy_blocked",
                          "cloud:context_rejected", "team_")
# Cloud failure reasons NOT in the prefix list above (rate_limited, timeout,
# quota_exhausted, provider_unavailable) ARE retryable, bounded by the task's
# own max_attempts like everything else -- no infinite retry storm.
_T = TaskState
_S = TeamState


@dataclass(frozen=True)
class Submission:
    accepted: bool
    team_id: str
    reason: str
    single_agent: str = ""
    assessment: dict | None = None
    plan: dict | None = None
    duplicate: bool = False
    creation_ms: float = 0.0

    def as_dict(self) -> dict:
        return {"accepted": self.accepted, "team_id": self.team_id,
                "reason": self.reason, "single_agent": self.single_agent,
                "assessment": self.assessment or {}, "plan": self.plan or {},
                "duplicate": self.duplicate, "creation_ms": self.creation_ms}


class AgentOrchestrator:
    def __init__(self, *, coord=None, manager=None, clock=time.time,
                 auto_tick: bool = True):
        self._coord_override = coord
        self._mgr_override = manager
        self.clock = clock
        self.auto_tick = auto_tick
        self._lock = threading.RLock()
        self._teams: dict = {}                      # team_id -> TeamRun (active)
        self._history: deque = deque(maxlen=MAX_HISTORY_TEAMS)
        self._by_request: dict = {}                 # request_id -> team_id
        self._job_index: dict = {}                  # job_id -> (team_id, task_id)
        # Read WITHOUT the lock by the spawn gate (which runs under the
        # ephemeral manager's spawn lock): plain dict reads, replaced values.
        self._agent_team: dict = {}                 # dyn agent id -> team_id
        self._team_state: dict = {}                 # team_id -> state value
        self._inbox: deque = deque()                # hook notifications
        self._results: dict = {}                    # job_id -> (structured, ctx)
        self._io_lock = threading.Lock()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._wired = False
        self.metrics = {"ticks": 0, "tick_time_s": 0.0, "max_tick_s": 0.0,
                        "teams_created": 0, "teams_declined": 0,
                        "teams_finished": 0, "creation_ms_last": 0.0,
                        "creation_ms_max": 0.0}

    # ── wiring ───────────────────────────────────────────────────────
    def _coord(self):
        if self._coord_override is not None:
            return self._coord_override
        from agents.coordinator import coordinator
        return coordinator()

    def _mgr(self):
        if self._mgr_override is not None:
            return self._mgr_override
        from agents.ephemeral import manager
        return manager()

    def _ensure_wired(self) -> None:
        with self._lock:
            if self._wired:
                return
            self._coord().add_hook(self)
            gates = self._mgr().spawn_gates
            if self._spawn_gate not in gates:
                gates.append(self._spawn_gate)
            self._wired = True

    def _ensure_thread(self) -> None:
        if not self.auto_tick:
            return
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._loop, daemon=True,
                                            name="agents-teams")
            self._thread.start()

    def _loop(self) -> None:
        while True:
            with self._lock:
                active = bool(self._teams)
            self._wake.wait(TICK_S if active else None)
            self._wake.clear()
            try:
                self.tick()
            except Exception:
                pass

    # ── coordinator hooks: never block, never raise ───────────────────
    def job_started(self, job) -> None:
        self._inbox.append(("started", job.job_id, self.clock()))
        self._wake.set()

    def after_result(self, coord, job, raw, result, ctx) -> None:
        # Team jobs (source "team") and specialist jobs (source "spawn": the
        # index may not name the job yet when a fast worker finishes it).
        if job.source not in ("team", "spawn") and job.job_id not in self._job_index:
            return
        with self._io_lock:
            self._results[job.job_id] = (result.as_dict(), ctx or "")
            while len(self._results) > MAX_RESULT_CACHE:
                self._results.pop(next(iter(self._results)))

    def job_finished(self, job, state, reason) -> None:
        self._inbox.append((
            "finished", job.job_id, self.clock(), state, str(reason or ""),
            str(job.result or ""), int(job.attempt),
            list(job.requested_capabilities or ()), job.agent_id))
        self._wake.set()

    def owns_job(self, job) -> bool:
        return job.source == "team" or job.job_id in self._job_index

    def _spawn_gate(self, prop, decision, requester) -> str:
        """A team's specialist asking for a nested worker: allowed only while
        the team is RUNNING and inside its own ephemeral budget. Not a team's
        agent -> not our call. Lock-free by design (see __init__)."""
        team_id = self._agent_team.get(requester)
        if team_id is None:
            return ""
        if self._team_state.get(team_id) != _S.RUNNING.value:
            return "team_not_running"
        run = self._teams.get(team_id)
        if run is None:
            return "team_not_running"
        if self._live_temporaries(run) >= run.plan.max_ephemeral_agents:
            return "team_ephemeral_budget"
        return ""

    # ── entry points ─────────────────────────────────────────────────
    def assess(self, goal: str, material: str = "") -> dict:
        return team_planner.assess(goal, material).as_dict()

    def submit_complex_task(self, goal: str, material: str = "", *,
                            request_id: str = "", priority: int = 2,
                            max_runtime_seconds: int | None = None,
                            max_model_calls: int | None = None,
                            failure_policy: FailurePolicy = FailurePolicy.REPLAN,
                            ) -> Submission:
        """The clean entry point. Upstream ARGUS has already decided this is
        complex, multi-step work; this decides whether a TEAM is the shortest
        safe path, builds the plan deterministically, and starts it. Declined
        submissions name the single agent that should handle the goal."""
        t0 = time.perf_counter()
        material = self._scrub(material)
        # The goal is redacted at rest: it is kept in the plan, shown in views
        # and quoted (bounded) in every task's objective.
        from agents.governor import scrub_task
        goal = scrub_task(goal)
        a = team_planner.assess(goal, material)
        if not a.needs_team:
            self.metrics["teams_declined"] += 1
            tev.audit_declined(goal_digest(goal), a.reason, a.single_agent)
            return Submission(False, "", a.reason, a.single_agent, a.as_dict(),
                              creation_ms=(time.perf_counter() - t0) * 1000)
        rid = request_id or secrets.token_hex(6)
        with self._lock:
            existing = self._by_request.get(rid)
            if existing is not None and existing in self._teams:
                return Submission(True, existing, "duplicate_request",
                                  duplicate=True)
            try:
                plan = team_planner.build_plan(
                    goal, material, request_id=rid, now=self.clock(),
                    priority=priority, max_runtime_seconds=max_runtime_seconds,
                    max_model_calls=max_model_calls,
                    failure_policy=failure_policy, assessment=a)
            except PlanError as e:
                self.metrics["teams_declined"] += 1
                tev.audit_declined(goal_digest(goal), e.code, a.single_agent)
                return Submission(False, "", e.code, a.single_agent, a.as_dict())
            sub = self._start(plan, playbook=a.playbook, material=material,
                              assessment=a)
        sub = dataclasses.replace(sub, creation_ms=(time.perf_counter() - t0) * 1000)
        self.metrics["creation_ms_last"] = sub.creation_ms
        self.metrics["creation_ms_max"] = max(self.metrics["creation_ms_max"],
                                              sub.creation_ms)
        return sub

    def submit_plan(self, plan: TeamPlan, *, playbook: str = "",
                    material: str = "") -> Submission:
        """Backend/test entry for a hand-built, already-validated TeamPlan.
        Same authority checks, same lifecycle; no assessment gate."""
        with self._lock:
            return self._start(plan, playbook=playbook,
                               material=self._scrub(material), assessment=None)

    def _start(self, plan: TeamPlan, *, playbook: str, material: str,
               assessment) -> Submission:
        if len(self._teams) >= MAX_ACTIVE_TEAMS:
            self.metrics["teams_declined"] += 1
            return Submission(False, "", "max_active_teams",
                              assessment.single_agent if assessment else "")
        if plan.team_id in self._teams:
            return Submission(True, plan.team_id, "duplicate_request", duplicate=True)
        why = self._authority_problem(plan)
        if why:
            self.metrics["teams_declined"] += 1
            tev.audit_declined(plan.goal_digest_, why, "")
            return Submission(False, "", why)
        t = self.clock()
        run = TeamRun(plan=plan, playbook=playbook, material=material,
                      created_at=t, last_activity=t)
        for spec in plan.tasks:
            run.tasks[spec.task_id] = TaskRun(spec=spec, created_at=t)
        if material:
            ref = run.evidence.add(SourceType.USER_INPUT, "owner", "supplied_material",
                                   material, classification=EvidenceClass.USER_SUPPLIED,
                                   timestamp=t)
            run.material_ref = ref.evidence_id if ref is not None else ""
        self._teams[plan.team_id] = run
        self._by_request[plan.request_id] = plan.team_id
        self._team_state[plan.team_id] = run.state.value
        self.metrics["teams_created"] += 1
        n_spec = sum(1 for m in plan.members if m.kind == "specialist")
        tev.team_event(tev.TEAM_CREATED, team_id=plan.team_id, state=run.state.value,
                       member_count=len(plan.members), temporary_count=n_spec,
                       task_count=len(plan.tasks), priority=plan.priority)
        tev.team_event(tev.PLAN_CREATED, team_id=plan.team_id,
                       task_count=len(plan.tasks), member_count=len(plan.members),
                       temporary_count=n_spec)
        tev.audit_created(plan.team_id, plan.goal_digest_, plan, n_spec)
        run.note("created", "", f"playbook={playbook or '-'} tasks={len(plan.tasks)}", t)
        self._set_team_state(run, _S.READY, "planned", t)
        self._ensure_wired()
        self._ensure_thread()
        self._wake.set()
        return Submission(True, plan.team_id, "accepted",
                          assessment=assessment.as_dict() if assessment else None,
                          plan=plan.as_dict())

    @staticmethod
    def _scrub(material: str) -> str:
        """Owner-supplied material (code, logs): redacted and bounded LINE BY
        LINE, keeping the line structure -- a finding is grounded against the
        line it quotes, and a log is meaningless as one long line."""
        if not material:
            return ""
        from agents.dynamic_spec import TASK_MAX
        from agents.governor import scrub_task
        lines = [scrub_task(ln) for ln in str(material).splitlines() if ln.strip()]
        return "\n".join(ln for ln in lines if ln)[:TASK_MAX]

    @staticmethod
    def _authority_problem(plan: TeamPlan) -> str:
        """A plan may not hand a core agent a data scope or a capability it
        does not hold. (Specialists are ruled on by the Governor at spawn.)"""
        from agents.governor import authority_for
        for task in plan.tasks:
            member = plan.member(task.member_id)
            if member.kind != "core":
                continue
            auth = authority_for(member.agent_id)
            if auth is None or not auth.live:
                return f"agent_not_live:{member.agent_id}"
            scope = set(task.allowed_data_scope) - {"team_evidence", "provided_source"}
            if not scope <= auth.data_classes:
                return f"scope_not_held:{task.task_id}"
            if not set(task.requested_capabilities) <= auth.capabilities:
                return f"capability_not_held:{task.task_id}"
        return ""

    # ── owner controls ───────────────────────────────────────────────
    def cancel_team(self, team_id: str, reason: str = "owner_cancel") -> bool:
        with self._lock:
            run = self._teams.get(team_id)
            if run is None or run.terminal:
                return False
            run.cancel_requested = True
            run.cancel_reason = reason[:40]
            self._team_state[team_id] = "CANCELLING"      # gate: refuse spawns now
            tev.audit_cancel(team_id, "team", "-", reason)
            self._wake.set()
        self.tick()
        return True

    def cancel_task(self, team_id: str, task_id: str,
                    reason: str = "owner_cancel") -> bool:
        with self._lock:
            run = self._teams.get(team_id)
            task = run.tasks.get(task_id) if run is not None else None
            if run is None or task is None or task.terminal or run.terminal:
                return False
            self._cancel_task(run, task, reason, self.clock())
            tev.audit_cancel(team_id, "task", task_id, reason)
            self._wake.set()
        self.tick()
        return True

    def cancel_agent(self, team_id: str, agent_id: str,
                     reason: str = "owner_cancel") -> int:
        n = 0
        with self._lock:
            run = self._teams.get(team_id)
            if run is None or run.terminal:
                return 0
            for task in list(run.tasks.values()):
                if task.agent_id == agent_id and not task.terminal:
                    self._cancel_task(run, task, reason, self.clock())
                    n += 1
            if n:
                tev.audit_cancel(team_id, "agent", agent_id, reason)
                self._wake.set()
        if n:
            self.tick()
        return n

    def wait(self, team_id: str, timeout: float = 30.0) -> dict | None:
        """Block until the team is terminal; returns its final result."""
        with self._lock:
            run = self._teams.get(team_id) or self._find_history(team_id)
        if run is None:
            return None
        run.done.wait(timeout)
        return run.result

    # ── the scheduler ────────────────────────────────────────────────
    def tick(self, now: float | None = None) -> int:
        """One deterministic pass over every active team: drain job
        notifications, enforce deadlines, refresh the DAG, dispatch what is
        ready, settle what is finished. Cheap: no model call ever happens
        here. Returns the number of active teams after the pass."""
        t = self.clock() if now is None else now
        t0 = time.perf_counter()
        with self._lock:
            self._drain(t)
            for run in list(self._teams.values()):
                try:
                    self._advance(run, t)
                except Exception as e:                   # fail closed, terminally
                    try:
                        self._cancel_all(run, t, f"internal:{type(e).__name__}",
                                         _S.FAILED)
                    except Exception:
                        run.state = _S.FAILED
                        run.finished_at = t
                        run.done.set()
                if run.terminal:
                    self._retire(run)
            active = len(self._teams)
        dt = time.perf_counter() - t0
        self.metrics["ticks"] += 1
        self.metrics["tick_time_s"] += dt
        self.metrics["max_tick_s"] = max(self.metrics["max_tick_s"], dt)
        return active

    def _drain(self, t: float) -> None:
        while self._inbox:
            item = self._inbox.popleft()
            kind, job_id = item[0], item[1]
            ref = self._job_index.get(job_id)
            if ref is None:
                continue
            run = self._teams.get(ref[0])
            task = run.tasks.get(ref[1]) if run is not None else None
            if run is None or task is None or task.job_id != job_id:
                continue                                  # stale attempt
            if kind == "started":
                if task.state is _T.QUEUED:
                    run.set_task_state(task, _T.RUNNING, "job_started", item[2])
                    tev.team_event(tev.TASK_STARTED, team_id=run.team_id,
                                   task_id=task.task_id, agent_id=task.agent_id,
                                   role=task.spec.required_role,
                                   attempt=task.attempt)
                    run.note("task_started", task.task_id, task.agent_id, item[2])
            elif kind == "finished" and not task.terminal:
                self._job_done(run, task, item)

    def _job_done(self, run: TeamRun, task: TaskRun, item) -> None:
        (_k, job_id, ts, state, reason, summary, attempt, caps, agent_id) = item
        extra = max(0, int(attempt) - 1)                  # coordinator retries
        task.model_calls += 1 + extra
        run.model_calls += extra
        if state == JOB_COMPLETED:
            with self._io_lock:
                structured, ctx = self._results.pop(job_id, ({}, ""))
            queued_s = max(0.0, (task.started_at or ts) - task.queued_at)
            sources = list(task.inputs_given)
            if run.material_ref and "provided_source" in task.spec.allowed_data_scope:
                # The owner's material was in the objective: a finding may be
                # grounded against the WHOLE scrubbed text, not its summary.
                sources.append((run.material_ref, run.material))
            task.result = normalize(
                structured, agent_id=task.agent_id, task_id=task.task_id,
                store=run.evidence, input_sources=sources,
                context_text=ctx, job_summary=summary, requested_caps=caps,
                timing={"queued_s": round(queued_s, 3),
                        "run_s": round(max(0.0, ts - (task.started_at or ts)), 3)},
                usage={"model_calls": 1 + extra}, now=ts)
            if task.result.action_proposals:
                tev.audit_proposals(run.team_id, task.task_id, task.agent_id,
                                    task.result.action_proposals)
            if task.spec.kind is TaskKind.AGENT and self._has_live_children(task):
                task.wait_reason = "nested_children"
                run.set_task_state(task, _T.WAITING, "nested_children", ts)
                run.note("task_waiting_children", task.task_id, task.agent_id, ts)
                return
            self._complete_task(run, task, ts)
        elif state == JOB_CANCELLED:
            self._attempt_failed(run, task, reason or "cancelled", ts)
        else:
            self._attempt_failed(run, task, reason or "failed", ts)

    def _complete_task(self, run: TeamRun, task: TaskRun, t: float) -> None:
        if task.wait_reason == "nested_children":
            self._absorb_children(run, task, t)
        task.wait_reason = ""
        run.set_task_state(task, _T.COMPLETED, "completed", t)
        tev.team_event(tev.TASK_COMPLETED, team_id=run.team_id, task_id=task.task_id,
                       agent_id=task.agent_id, role=task.spec.required_role,
                       kind=task.spec.kind.value, attempt=task.attempt,
                       duration_s=task.duration_s(t))
        tev.audit_task(run.team_id, task.task_id, task.agent_id, "COMPLETED",
                       attempt=task.attempt, role=task.spec.required_role)
        run.note("task_completed", task.task_id, task.agent_id, t)
        if task.spec.kind is TaskKind.AGENT:
            self._process_handoffs(run, task, t)

    def _attempt_failed(self, run: TeamRun, task: TaskRun, reason: str,
                        t: float) -> None:
        reason = reason[:60]
        task.error = reason
        task.job_id = ""
        retryable = (not reason.startswith(NON_RETRYABLE_PREFIXES)
                     and task.attempt < task.spec.max_attempts
                     and not run.cancel_requested
                     and run.model_calls + run.inflight_count() < run.plan.max_model_calls)
        if retryable:
            task.wait_reason = "retry"
            task.retry_at = t + RETRY_DELAY_S
            run.set_task_state(task, _T.WAITING, f"retry:{reason}", t)
            run.note("task_retry_pending", task.task_id, reason, t)
            return
        final = _T.TIMED_OUT if reason.startswith("timeout") else (
            _T.CANCELLED if reason.startswith("cancelled") and run.cancel_requested
            else _T.FAILED)
        task.wait_reason = ""
        run.set_task_state(task, final, reason, t)
        tev.team_event(tev.TASK_FAILED, team_id=run.team_id, task_id=task.task_id,
                       agent_id=task.agent_id, role=task.spec.required_role,
                       state=final.value, reason=reason, attempt=task.attempt)
        tev.audit_task(run.team_id, task.task_id, task.agent_id, final.value,
                       attempt=task.attempt, reason=reason,
                       role=task.spec.required_role)
        run.note("task_" + final.value.lower(), task.task_id, reason, t)
        if task.spec.required and task.spec.kind is TaskKind.AGENT:
            self._on_required_failure(run, task, t)

    def _on_required_failure(self, run: TeamRun, task: TaskRun, t: float) -> None:
        if run.cancel_requested or run.terminal:
            return
        policy = run.plan.failure_policy
        if policy is FailurePolicy.FAIL:
            self._cancel_all(run, t, f"task_failed:{task.task_id}", _S.FAILED)
        elif policy is FailurePolicy.REPLAN and run.replans < run.plan.max_replans:
            self._replan(run, "task_failed", t)
        # PARTIAL policy (or replans spent): the rest of the DAG continues;
        # settlement reports what completed and what did not.

    # ── one pass over one team ───────────────────────────────────────
    def _advance(self, run: TeamRun, t: float) -> None:
        if run.terminal:
            return
        if run.cancel_requested:
            self._cancel_all(run, t, run.cancel_reason or "owner_cancel",
                             _S.CANCELLED)
            return
        if run.state is _S.READY:
            self._set_team_state(run, _S.RUNNING, "started", t)
            tev.team_event(tev.STARTED, team_id=run.team_id,
                           task_count=len(run.tasks))
        if t >= run.plan.deadline:
            self._cancel_all(run, t, "team_deadline", _S.TIMED_OUT)
            return
        self._check_timeouts(run, t)
        self._check_waiting(run, t)
        self._refresh_dependencies(run, t)
        self._dispatch(run, t)
        self._settle(run, t)

    def _check_timeouts(self, run: TeamRun, t: float) -> None:
        for task in list(run.tasks.values()):
            if task.inflight and task.deadline and t >= task.deadline:
                self._abort_job(run, task, "team_task_timeout")
                self._attempt_failed(run, task, "timeout", t)

    def _check_waiting(self, run: TeamRun, t: float) -> None:
        for task in list(run.tasks.values()):
            if task.state is not _T.WAITING:
                continue
            if task.wait_reason == "retry" and t >= task.retry_at:
                task.wait_reason = ""
                run.set_task_state(task, _T.READY, "retry", t)
            elif task.wait_reason == "nested_children":
                if task.deadline and t >= task.deadline:
                    self._abort_job(run, task, "team_task_timeout")
                    self._complete_task(run, task, t)      # keep its own result
                elif not self._has_live_children(task):
                    self._complete_task(run, task, t)

    def _dep_outcome(self, run: TeamRun, tid: str) -> str:
        """completed | failed | pending, following replan replacements."""
        seen = set()
        while tid and tid not in seen:
            seen.add(tid)
            dep = run.tasks.get(tid)
            if dep is None:
                return "failed"
            if dep.state is _T.COMPLETED:
                return "completed"
            if dep.terminal:
                if dep.replaced_by:
                    tid = dep.replaced_by
                    continue
                return "failed"
            return "pending"
        return "failed"

    def _refresh_dependencies(self, run: TeamRun, t: float) -> None:
        for task in run.ordered_tasks():
            if task.state not in (_T.PENDING, _T.BLOCKED):
                continue
            outcomes = {d: self._dep_outcome(run, d) for d in task.spec.dependencies}
            if task.spec.trigger == "all_terminal":
                if all(o != "pending" for o in outcomes.values()):
                    task.dependency_state = "ready"
                    self._make_ready(run, task, t)
                else:
                    task.dependency_state = "blocked:" + ",".join(
                        d for d, o in outcomes.items() if o == "pending")
                    run.set_task_state(task, _T.BLOCKED, "waiting_deps", t)
                continue
            if any(o == "failed" for o in outcomes.values()):
                failed = ",".join(d for d, o in outcomes.items() if o == "failed")
                task.dependency_state = "failed:" + failed
                run.set_task_state(task, _T.SKIPPED, f"dependency_failed:{failed}", t)
                tev.team_event(tev.TASK_FAILED, team_id=run.team_id,
                               task_id=task.task_id, role=task.spec.required_role,
                               state=_T.SKIPPED.value, reason="dependency_failed")
                tev.audit_task(run.team_id, task.task_id, "", "SKIPPED",
                               reason=f"dependency_failed:{failed}",
                               role=task.spec.required_role)
                run.note("task_skipped", task.task_id, failed, t)
            elif all(o == "completed" for o in outcomes.values()):
                task.dependency_state = "ready"
                self._make_ready(run, task, t)
            else:
                task.dependency_state = "blocked:" + ",".join(
                    d for d, o in outcomes.items() if o == "pending")
                run.set_task_state(task, _T.BLOCKED, "waiting_deps", t)

    def _make_ready(self, run: TeamRun, task: TaskRun, t: float) -> None:
        if run.set_task_state(task, _T.READY, "deps_satisfied", t):
            tev.team_event(tev.TASK_READY, team_id=run.team_id, task_id=task.task_id,
                           role=task.spec.required_role, kind=task.spec.kind.value)

    def _dispatch_order(self, run: TeamRun) -> list:
        depth = depth_map(run.plan.tasks)
        down = downstream_count(run.plan.tasks)
        ready = [r for r in run.tasks.values() if r.state is _T.READY]
        return sorted(ready, key=lambda r: (r.spec.priority, depth[r.task_id],
                                            -down[r.task_id], int(r.task_id[1:])))

    def _dispatch(self, run: TeamRun, t: float) -> None:
        for task in self._dispatch_order(run):
            if run.terminal or run.state is _S.REPLANNING:
                return
            if task.state is not _T.READY:
                continue                                  # changed by a replan
            if run.inflight_count() >= MAX_INFLIGHT_PER_TEAM:
                return
            if run.model_calls + run.inflight_count() >= run.plan.max_model_calls:
                self._attempt_failed(run, task, "budget_exhausted", t)
                continue
            member = run.plan.member(task.spec.member_id)
            task.inputs_given = team_prompts.inputs_for(task.spec, run, run.evidence)
            if task.spec.kind is TaskKind.VERIFY:
                text = team_prompts.verify_task_text(task.spec, run, run.evidence,
                                                     task.inputs_given)
            else:
                text = team_prompts.agent_task_text(task.spec, run, run.evidence,
                                                    task.inputs_given)
            if member.kind == "core":
                job_id, why = self._launch_core(run, task, member.agent_id, text, t)
            elif member.kind == "cloud":
                job_id, why = self._launch_cloud(run, task, member, text, t)
            else:
                job_id, why = self._launch_specialist(run, task, member, text, t)
            if not job_id:
                if why in TRANSIENT_SUBMIT_REFUSALS:
                    run.note("submit_deferred", task.task_id, why, t)
                    return                                # try again next tick
                self._attempt_failed(run, task, why, t)
                continue
            task.attempt += 1
            task.job_id = job_id
            task.job_ids.append(job_id)
            task.deadline = t + task.spec.timeout_seconds
            run.model_calls += 1
            self._job_index[job_id] = (run.team_id, task.task_id)
            run.set_task_state(task, _T.QUEUED, "submitted", t)
            run.note("task_queued", task.task_id, task.agent_id, t)
            if task.spec.kind is TaskKind.VERIFY and run.state is _S.RUNNING:
                self._set_team_state(run, _S.VERIFYING, "verification_queued", t)
                tev.team_event(tev.VERIFICATION_STARTED, team_id=run.team_id,
                               task_id=task.task_id, agent_id=task.agent_id)

    def _launch_core(self, run: TeamRun, task: TaskRun, agent_id: str,
                     text: str, t: float) -> tuple:
        spec = get_spec(agent_id)
        tier = max(task.spec.priority, spec.max_priority if spec else 0)
        parent_job = ""
        for d in reversed(task.spec.dependencies):
            dep = run.tasks.get(d)
            if dep is not None and dep.state is _T.COMPLETED and dep.job_ids:
                parent_job = dep.job_ids[-1]
                break
        task.agent_id = agent_id
        job, why = self._coord().submit(agent_id, text, priority=tier,
                                        source="team", parent_job_id=parent_job)
        if job is None:
            return "", why or "submit_refused"
        return job.job_id, ""

    def _launch_specialist(self, run: TeamRun, task: TaskRun, member,
                           text: str, t: float) -> tuple:
        "Run one agent task through the architect and governor."
        if self._live_temporaries(run) >= run.plan.max_ephemeral_agents:
            return "", "team_ephemeral_budget"
        from agents.architect import architect
        data = tuple(c for c in task.spec.allowed_data_scope
                     if c in GRANTABLE_DATA_CLASSES)
        req = SpawnRequest(requester="owner", task=text, role_hint=member.role,
                           parent_hint=member.parent_agent_id,
                           requested_capabilities=tuple(task.spec.requested_capabilities),
                           requested_data_classes=data, source="team")
        prop = architect().propose(req, now=t)
        # The team owns verification; a specialist needs no handoff edge.
        prop = dataclasses.replace(prop, max_handoffs=0)
        tev.team_event(tev.AGENT_REQUESTED, team_id=run.team_id, task_id=task.task_id,
                       template=member.role, parent_id=member.parent_agent_id)
        out = self._mgr().request_spawn("owner", text, coord=self._coord(),
                                        source="team", proposal=prop)
        if not out.approved:
            run.spawn_denials += 1
            reason = out.reasons[0] if out.reasons else out.stage
            tev.audit_agent(run.team_id, task.task_id, member.role,
                            member.parent_agent_id, approved=False, reason=reason)
            tev.team_event(tev.AGENT_REQUESTED, team_id=run.team_id,
                           task_id=task.task_id, template=member.role,
                           decision="denied", reason=reason)
            return "", f"spawn_denied:{reason}"
        task.agent_id = out.agent_id
        run.specialists[member.member_id] = out.agent_id
        self._agent_team[out.agent_id] = run.team_id
        tev.audit_agent(run.team_id, task.task_id, member.role,
                        member.parent_agent_id, approved=True, agent_id=out.agent_id)
        tev.team_event(tev.AGENT_SPAWNED, team_id=run.team_id, task_id=task.task_id,
                       agent_id=out.agent_id, template=member.role,
                       parent_id=member.parent_agent_id)
        run.note("specialist_spawned", task.task_id, out.agent_id, t)
        return out.job_id, ""

    def _launch_cloud(self, run: TeamRun, task: TaskRun, member, text: str,
                      t: float) -> tuple:
        "Run one cloud specialist task through the approved boundary."
        if not cloud_agents_enabled():
            return "", "cloud_agents_disabled"
        if self._live_temporaries(run) >= run.plan.max_ephemeral_agents:
            return "", "team_ephemeral_budget"
        from agents.architect import architect
        req = SpawnRequest(requester="owner", task=text, role_hint=member.role,
                           parent_hint=member.parent_agent_id, source="team")
        prop = architect().propose(req, now=t)
        tev.team_event(tev.AGENT_REQUESTED, team_id=run.team_id, task_id=task.task_id,
                       template=member.role, parent_id=member.parent_agent_id)
        out = self._mgr().request_spawn("owner", text, coord=self._coord(),
                                        source="team", proposal=prop)
        if not out.approved:
            run.spawn_denials += 1
            reason = out.reasons[0] if out.reasons else out.stage
            tev.audit_agent(run.team_id, task.task_id, member.role,
                            member.parent_agent_id, approved=False, reason=reason)
            tev.team_event(tev.AGENT_REQUESTED, team_id=run.team_id,
                           task_id=task.task_id, template=member.role,
                           decision="denied", reason=reason)
            return "", f"spawn_denied:{reason}"
        task.agent_id = out.agent_id
        run.specialists[member.member_id] = out.agent_id
        self._agent_team[out.agent_id] = run.team_id
        tev.audit_agent(run.team_id, task.task_id, member.role,
                        member.parent_agent_id, approved=True, agent_id=out.agent_id)
        tev.team_event(tev.AGENT_SPAWNED, team_id=run.team_id, task_id=task.task_id,
                       agent_id=out.agent_id, template=member.role,
                       parent_id=member.parent_agent_id)
        run.note("cloud_spawned", task.task_id, out.agent_id, t)
        job_id = "cloud-" + secrets.token_hex(6)
        from agents.registry import registry
        rec = registry().get_dynamic(out.agent_id)
        if rec is None:                                # destroyed between the lines above
            return "", "agent_gone"
        spec = rec.dspec
        th = threading.Thread(target=self._run_cloud_call, args=(job_id, spec),
                              daemon=True, name=f"cloud-{out.agent_id}")
        th.start()
        return job_id, ""

    def _run_cloud_call(self, job_id: str, spec) -> None:
        """Runs OFF the scheduler thread. Talks to cloud_worker only; every
        other effect (task/team state, events, audit) happens back on the
        scheduler thread via the inbox, exactly like a coordinator job's
        result -- this function must never touch TeamRun/TaskRun directly."""
        result = cloud_worker.run(spec)
        # Same boundary a local job's reply goes through (agents/capabilities.py):
        # validated, audited, and -- for a cloud agent -- ALWAYS denied at the
        # group-membership check (its approved spec holds no group capability),
        # so a proposal never silently reaches the owner as "accepted" and a
        # cloud model that tries is still recorded as a security event.
        accepted = []
        if result.ok:
            try:
                from agents import capabilities
                accepted = capabilities.process_all(
                    spec.agent_id, result.structured.get("requested_capabilities", []))
            except Exception:
                accepted = []
        with self._io_lock:
            self._results[job_id] = (result.structured, "")
            while len(self._results) > MAX_RESULT_CACHE:
                self._results.pop(next(iter(self._results)))
        try:
            self._mgr().cloud_result(
                spec.agent_id, ok=result.ok,
                summary=(result.structured.get("summary", "") if result.ok else ""),
                reason=(result.reason or (result.failure.value if result.failure
                                          else "")))
        except Exception:
            pass
        if result.ok:
            state, reason = JOB_COMPLETED, ""
        else:
            state = JOB_FAILED
            reason = f"cloud:{result.failure.value.lower() if result.failure else 'error'}"
        self._inbox.append((
            "finished", job_id, time.time(), state, reason,
            result.structured.get("summary", "") if result.ok else "",
            1, accepted, spec.agent_id))
        self._wake.set()

    # ── settlement: verification, replanning, the end ─────────────────
    def _settle(self, run: TeamRun, t: float) -> None:
        if run.terminal or run.state is _S.REPLANNING or not run.all_terminal():
            return
        if run.verify_tasks():
            a = team_verifier.assess(run)
            run.verdict = a.combined.value
            run.verify_log.append(a.as_dict())
            vt = run.verify_tasks()[-1]
            tev.audit_verify(run.team_id, vt.task_id,
                             deterministic=a.deterministic.value,
                             model=a.model.value if a.model else "",
                             combined=a.combined.value, reasons=a.reasons)
            tev.team_event(tev.VERIFICATION_COMPLETED, team_id=run.team_id,
                           task_id=vt.task_id, verdict=a.combined.value)
            run.note("verified", vt.task_id, a.combined.value, t)
            any_done = any(r.state is _T.COMPLETED for r in run.agent_tasks())
            if a.combined is Verdict.VERIFIED:
                self._finalize(run, _S.COMPLETED, "verified", t, a)
            elif a.combined is Verdict.PARTIALLY_VERIFIED:
                self._finalize(run, _S.PARTIAL, "partially_verified", t, a)
            elif a.combined in (Verdict.INSUFFICIENT_EVIDENCE, Verdict.CONTRADICTED):
                reason = a.combined.value.lower()
                if (run.plan.failure_policy is FailurePolicy.REPLAN
                        and run.replans < run.plan.max_replans
                        and self._replan(run, reason, t)):
                    return
                if a.combined is Verdict.CONTRADICTED or not any_done:
                    self._finalize(run, _S.FAILED, reason, t, a)
                else:
                    self._finalize(run, _S.PARTIAL, reason, t, a)
            else:
                self._finalize(run, _S.FAILED, "not_verified", t, a)
            return
        required = [r for r in run.agent_tasks() if r.spec.required]
        done = [r for r in required if r.state is _T.COMPLETED]
        if len(done) == len(required) and required:
            self._finalize(run, _S.COMPLETED, "all_required_completed", t, None)
        elif done or any(r.state is _T.COMPLETED for r in run.agent_tasks()):
            self._finalize(run, _S.PARTIAL, "required_task_incomplete", t, None)
        else:
            self._finalize(run, _S.FAILED, "no_task_completed", t, None)

    def _replan(self, run: TeamRun, reason: str, t: float) -> bool:
        """ONE bounded replan: deterministic strategies only, tasks are ADDED,
        the verify stage is re-pointed. False when nothing can be added."""
        run.replans += 1
        tev.team_event(tev.REPLAN_REQUESTED, team_id=run.team_id, reason=reason,
                       replans=run.replans)
        prev = run.state
        self._set_team_state(run, _S.REPLANNING, reason, t)
        view = []
        for r in run.ordered_tasks():
            m = run.plan.member(r.spec.member_id)
            view.append({"task_id": r.task_id, "kind": r.spec.kind.value,
                         "state": r.state.value, "role": r.spec.required_role,
                         "member_kind": m.kind, "required": r.spec.required,
                         "origin": r.spec.origin, "replaced_by": r.replaced_by,
                         "title": r.spec.title, "objective": r.spec.objective,
                         "parent_agent_id": m.parent_agent_id})
        n_spec = sum(1 for m in run.plan.members if m.kind == "specialist")
        proposal = team_planner.replan(
            run.plan, view, reason, playbook_key=run.playbook,
            ephemeral_left=run.plan.max_ephemeral_agents - n_spec,
            agents_left=run.plan.max_agents - len(run.plan.members),
            goal=run.plan.goal)
        if proposal.empty:
            run.note("replan_no_strategy", "", reason, t)
            tev.audit_replan(run.team_id, run.replans, reason + ":no_strategy", ())
            self._set_team_state(run, _S.RUNNING if prev is not _S.VERIFYING
                                 else _S.RUNNING, "replan_empty", t)
            return False
        verified = [v.task_id for v in run.verify_tasks() if v.terminal]
        try:
            new_plan = team_planner.extend_plan(
                run.plan, proposal.members, proposal.tasks,
                verified_task_ids=verified)
        except PlanError as e:
            run.note("replan_rejected", "", e.code, t)
            tev.audit_replan(run.team_id, run.replans, reason + ":" + e.code, ())
            self._set_team_state(run, _S.RUNNING, "replan_rejected", t)
            return False
        run.plan = new_plan
        run.plan_versions += 1
        added = []
        for spec in new_plan.tasks:
            if spec.task_id not in run.tasks:
                run.tasks[spec.task_id] = TaskRun(spec=spec, created_at=t)
                added.append(spec.task_id)
            elif run.tasks[spec.task_id].spec != spec and not run.tasks[spec.task_id].terminal:
                run.tasks[spec.task_id].spec = spec      # re-pointed VERIFY
        for old, new in proposal.replaced:
            if old in run.tasks:
                run.tasks[old].replaced_by = new
        tev.team_event(tev.REPLANNED, team_id=run.team_id, replans=run.replans,
                       added=added, task_count=len(run.tasks))
        tev.audit_replan(run.team_id, run.replans, reason, added)
        run.note("replanned", "", "+".join(proposal.strategy)[:80], t)
        self._set_team_state(run, _S.RUNNING, "replanned", t)
        return True

    def _process_handoffs(self, run: TeamRun, task: TaskRun, t: float) -> None:
        """The explicit handoff protocol (§15): declared edge, no cycle, no
        role already in the team, per-agent and per-team budgets, member and
        model budgets. At most ONE accepted handoff per task."""
        res = task.result
        if res is None or not res.handoff_requests:
            return
        for h in list(res.handoff_requests)[:3]:
            to = str(h.to_role or "").lower()[:32]
            why = self._handoff_refusal(run, task, to)
            if why:
                run.handoffs_refused += 1
                if why != "covered_by_verify_stage":
                    tev.audit_handoff(run.team_id, task.agent_id, to, accepted=False,
                                      reason=why)
                    tev.team_event(tev.HANDOFF, team_id=run.team_id,
                                   from_agent=task.agent_id, to_agent=to,
                                   decision="refused", reason=why)
                continue
            new_member, new_task = team_planner.handoff_task(
                run.plan, task.spec, to, h.requested_task, h.context_refs)
            try:
                new_plan = team_planner.extend_plan(
                    run.plan, [new_member] if new_member else [], [new_task],
                    verified_task_ids=[v.task_id for v in run.verify_tasks()
                                       if v.terminal])
            except PlanError as e:
                tev.audit_handoff(run.team_id, task.agent_id, to, accepted=False,
                                  reason=e.code)
                continue
            run.plan = new_plan
            run.plan_versions += 1
            for spec in new_plan.tasks:
                if spec.task_id not in run.tasks:
                    run.tasks[spec.task_id] = TaskRun(spec=spec, created_at=t)
                elif run.tasks[spec.task_id].spec != spec and not run.tasks[spec.task_id].terminal:
                    run.tasks[spec.task_id].spec = spec
            run.handoffs += 1
            run.handoffs_by_agent[task.agent_id] = run.handoffs_by_agent.get(
                task.agent_id, 0) + 1
            tev.audit_handoff(run.team_id, task.agent_id, to, accepted=True,
                              task_id=new_task.task_id)
            tev.team_event(tev.HANDOFF, team_id=run.team_id, from_agent=task.agent_id,
                           to_agent=to, task_id=new_task.task_id, decision="accepted")
            run.note("handoff_accepted", new_task.task_id, f"{task.agent_id}->{to}", t)
            return

    def _handoff_refusal(self, run: TeamRun, task: TaskRun, to: str) -> str:
        if to == "verifier":
            return "covered_by_verify_stage"
        if get_spec(to) is None:
            return "unknown_target"
        if not get_spec(to).enabled:
            return "target_disabled"
        member = run.plan.member(task.spec.member_id)
        if member.kind != "core":
            return "temporary_agent_handoff_not_allowed"
        if not handoff_allowed(task.agent_id, to):
            return "edge_not_declared"
        if to in task.spec.lineage:
            return "handoff_cycle"
        if any(r.spec.required_role == to for r in run.tasks.values()):
            return "role_already_in_team"
        if run.handoffs >= min(MAX_HANDOFFS_PER_TEAM, run.plan.max_handoffs):
            return "team_handoff_budget"
        if run.handoffs_by_agent.get(task.agent_id, 0) >= run.plan.max_handoffs:
            return "agent_handoff_budget"
        if not any(m.kind == "core" and m.agent_id == to for m in run.plan.members) \
                and len(run.plan.members) >= run.plan.max_agents:
            return "member_limit"
        if run.model_calls + run.inflight_count() + 2 > run.plan.max_model_calls:
            return "model_budget"
        return ""

    # ── cancellation / cleanup ───────────────────────────────────────
    def _abort_job(self, run: TeamRun, task: TaskRun, reason: str) -> None:
        """Stop a task's in-flight work: the queued/running coordinator job
        and, for a specialist, the agent itself (which cascades to any nested
        children and cancels their jobs)."""
        if task.job_id:
            try:
                self._coord().cancel(task.job_id)
            except Exception:
                pass
        if task.agent_id and task.agent_id in self._agent_team:
            try:
                self._mgr().destroy(task.agent_id, reason)
            except Exception:
                pass

    def _cancel_task(self, run: TeamRun, task: TaskRun, reason: str,
                     t: float) -> None:
        if task.terminal:
            return
        self._abort_job(run, task, reason)
        task.wait_reason = ""
        task.job_id = ""
        run.set_task_state(task, _T.CANCELLED, reason, t)
        tev.team_event(tev.TASK_FAILED, team_id=run.team_id, task_id=task.task_id,
                       agent_id=task.agent_id, role=task.spec.required_role,
                       state=_T.CANCELLED.value, reason=reason)
        tev.audit_task(run.team_id, task.task_id, task.agent_id, "CANCELLED",
                       attempt=task.attempt, reason=reason,
                       role=task.spec.required_role)
        run.note("task_cancelled", task.task_id, reason, t)

    def _cancel_all(self, run: TeamRun, t: float, reason: str,
                    final: TeamState) -> None:
        for task in list(run.tasks.values()):
            self._cancel_task(run, task, reason, t)
        self._finalize(run, final, reason, t, None)

    def _finalize(self, run: TeamRun, state: TeamState, reason: str, t: float,
                  assessment) -> None:
        if run.terminal:
            return
        t0 = time.perf_counter()
        self._destroy_team_agents(run, "team_" + state.value.lower())
        run.cleanup_s = time.perf_counter() - t0
        run.termination_reason = reason[:60]
        self._set_team_state(run, state, reason, t)
        run.result = self._compose_result(run, assessment, state, reason, t)
        ev = {_S.COMPLETED: tev.COMPLETED, _S.PARTIAL: tev.PARTIAL,
              _S.FAILED: tev.FAILED, _S.CANCELLED: tev.CANCELLED,
              _S.TIMED_OUT: tev.TIMED_OUT}[state]
        prog = run.progress()
        tev.team_event(ev, team_id=run.team_id, state=state.value, reason=reason,
                       verdict=run.verdict, model_calls=run.model_calls,
                       replans=run.replans, handoffs=run.handoffs,
                       progress=prog["fraction"], duration_s=run.elapsed_s(t))
        tev.audit_end(run.team_id, state.value, reason, tasks_done=prog["completed"],
                      tasks_total=prog["total"], calls=run.model_calls,
                      replans=run.replans, handoffs=run.handoffs,
                      temp=len(run.specialists), verdict=run.verdict,
                      life_s=run.elapsed_s(t))
        run.note("finished", "", f"{state.value}:{reason}", t)
        self.metrics["teams_finished"] += 1
        run.done.set()

    def _destroy_team_agents(self, run: TeamRun, reason: str) -> None:
        """Temporary agents exist only for the goal: destroy every one the team
        asked for (nested children cascade with their parents)."""
        mgr = self._mgr()
        for agent_id in list(run.specialists.values()):
            try:
                mgr.destroy(agent_id, reason)
            except Exception:
                pass

    def _retire(self, run: TeamRun) -> None:
        self._teams.pop(run.team_id, None)
        self._by_request.pop(run.plan.request_id, None)
        self._team_state.pop(run.team_id, None)
        for aid in list(run.specialists.values()):
            self._agent_team.pop(aid, None)
        for jid in [j for j, ref in self._job_index.items() if ref[0] == run.team_id]:
            self._job_index.pop(jid, None)
        self._history.append(run)

    # ── temporary-agent bookkeeping ──────────────────────────────────
    def _team_agent_ids(self, run: TeamRun) -> set:
        return set(run.specialists.values())

    def _live_temporaries(self, run: TeamRun) -> int:
        """Live temporary agents that belong to this team: its specialists and
        anything spawned beneath them (walking the parent chain)."""
        from agents.dynamic_spec import LIVE_STATUSES
        from agents.registry import registry
        ours = self._team_agent_ids(run)
        if not ours:
            return 0
        n = 0
        reg = registry()
        for rec in reg.dynamic_all():
            if rec.dspec.status not in LIVE_STATUSES:
                continue
            aid, hops = rec.dspec.agent_id, 0
            while aid and hops < 4:
                if aid in ours:
                    n += 1
                    break
                parent = reg.get_dynamic(aid)
                aid = parent.dspec.parent_agent_id if parent is not None else ""
                hops += 1
        return n

    def _has_live_children(self, task: TaskRun) -> bool:
        if not task.agent_id or task.agent_id not in self._agent_team:
            return False
        try:
            from agents.registry import registry
            return bool(registry().dynamic_children(task.agent_id, live_only=True))
        except Exception:
            return False

    def _absorb_children(self, run: TeamRun, task: TaskRun, t: float) -> None:
        """A specialist's nested workers contribute their (redacted, clipped)
        summaries as INFERRED evidence of the parent task -- a model's claim,
        never an observation."""
        try:
            from agents.registry import registry
            kids = [(c.dspec.agent_id, c.result_summary)
                    for c in registry().dynamic_children(task.agent_id)]
            for x in list(self._mgr()._recent):
                if x.get("kind") == "destroyed" and x.get("parent_id") == task.agent_id:
                    kids.append((x.get("agent_id", ""), x.get("result_summary", "")))
        except Exception:
            kids = []
        seen = set()
        for aid, summary in kids:
            if aid in seen or not summary:
                continue
            seen.add(aid)
            run.evidence.add(SourceType.MODEL_ANALYSIS, aid, "nested_worker",
                             summary, task_id=task.task_id,
                             classification=EvidenceClass.INFERRED, grounded=False,
                             timestamp=t)
        if seen:
            run.note("nested_absorbed", task.task_id, str(len(seen)), t)

    # ── result composition (deterministic; no model) ─────────────────
    def _compose_result(self, run: TeamRun, assessment, state: TeamState,
                        reason: str, t: float) -> dict:
        observed, inferred, recs, proposals, limits, missing, summaries = \
            [], [], [], [], [], [], []
        for task in run.agent_tasks():
            res = task.result
            tag = f"{task.task_id} {task.spec.required_role}"
            if task.state is _T.COMPLETED and res is not None:
                if res.summary:
                    summaries.append(f"[{tag}] {res.summary}")
                for f in res.findings:
                    (observed if f.kind.value == "OBSERVED" else inferred).append(
                        {"task_id": task.task_id, "agent_id": task.agent_id,
                         "text": f.text, "evidence_ids": list(f.evidence_ids)})
                recs += [{"task_id": task.task_id, "text": r} for r in res.recommendations]
                proposals += [{**p.__dict__, "task_id": task.task_id,
                               "agent_id": task.agent_id} for p in res.action_proposals]
                limits += [f"{tag}: {x}" for x in res.limitations]
            else:
                missing.append({"task_id": task.task_id, "role": task.spec.required_role,
                                "state": task.state.value, "reason": task.error,
                                "required": task.spec.required,
                                "replaced_by": task.replaced_by})
        for v in run.verify_tasks():
            if v.state is not _T.COMPLETED:
                limits.append(f"{v.task_id} verifier: {v.state.value.lower()} "
                              f"{v.error}".strip())
        if state is _S.TIMED_OUT:
            limits.append("team deadline reached before all work finished")
        if state is _S.CANCELLED:
            limits.append(f"cancelled: {run.cancel_reason or reason}")
        counts = run.evidence.counts()
        if counts["ungrounded"]:
            limits.append(f"{counts['ungrounded']} model claim(s) could not be "
                          f"grounded in evidence and were not counted")
        prog = run.progress()
        unresolved = [m for m in missing if not m["replaced_by"]]
        retry_useful = bool(unresolved) and state is not _S.CANCELLED and (
            assessment.retry_useful if assessment else True)
        summary = (f"{state.value}: {prog['completed']}/{prog['total']} tasks "
                   f"completed" + (f", verdict {run.verdict}" if run.verdict else "")
                   + (f", {len(missing)} not completed" if missing else "") + ".")
        return {
            "team_id": run.team_id, "request_id": run.plan.request_id,
            "state": state.value, "termination_reason": run.termination_reason,
            "goal_digest": run.plan.goal_digest_, "playbook": run.playbook,
            "verdict": run.verdict,
            "verification": assessment.as_dict() if assessment else {},
            "summary": summary, "task_summaries": summaries[:12],
            "findings": {"observed": observed[:24], "inferred": inferred[:24]},
            "recommendations": recs[:24], "action_proposals": proposals[:12],
            "evidence": [r.as_dict() for r in run.evidence.all()],
            "evidence_counts": counts, "limitations": limits[:16],
            "missing_work": missing, "retry_useful": retry_useful,
            "timing": {"created_at": run.created_at, "started_at": run.started_at,
                       "finished_at": run.finished_at, "elapsed_s": round(run.elapsed_s(t), 3),
                       "cleanup_s": round(run.cleanup_s, 4)},
            "usage": {"model_calls": run.model_calls,
                      "max_model_calls": run.plan.max_model_calls,
                      "replans": run.replans, "handoffs": run.handoffs,
                      "handoffs_refused": run.handoffs_refused,
                      "specialists_spawned": len(run.specialists),
                      "spawn_denials": run.spawn_denials,
                      "plan_versions": run.plan_versions,
                      "tasks": prog},
            "tasks": [self._task_view(run, r, t) for r in run.ordered_tasks()],
        }

    # ── observability (§24) ──────────────────────────────────────────
    def _find_history(self, team_id: str):
        for run in self._history:
            if run.team_id == team_id:
                return run
        return None

    def _team_view(self, run: TeamRun, t: float, redact=None) -> dict:
        red = redact or (lambda x: x)
        prog = run.progress()
        from agents.team_evidence import safe_text
        return {
            "team_id": run.team_id, "request_id": run.plan.request_id,
            "goal": red(safe_text(run.plan.goal, 240)), "goal_digest": run.plan.goal_digest_,
            "playbook": run.playbook, "state": run.state.value,
            "current_phase": run.current_phase, "priority": run.plan.priority,
            "created_at": run.created_at, "started_at": run.started_at,
            "finished_at": run.finished_at, "deadline": run.plan.deadline,
            "elapsed_s": round(run.elapsed_s(t), 3), "progress": prog,
            "member_count": len(run.plan.members),
            "temporary_count": len(run.specialists),
            "temporary_live": self._live_temporaries(run) if not run.terminal else 0,
            "model_calls": run.model_calls, "replans": run.replans,
            "handoffs": run.handoffs, "last_activity": run.last_activity,
            "verdict": run.verdict, "termination_reason": run.termination_reason,
            "budgets": run.plan.as_dict()["budgets"], "plan_versions": run.plan_versions,
        }

    def _task_view(self, run: TeamRun, r: TaskRun, t: float, redact=None) -> dict:
        red = redact or (lambda x: x)
        res = r.result
        member = next((m for m in run.plan.members if m.member_id == r.spec.member_id),
                      None)
        return {
            "task_id": r.task_id, "title": red(r.spec.title), "kind": r.spec.kind.value,
            "role": r.spec.required_role, "agent_id": r.agent_id,
            "worker_type": member.kind if member is not None else "",
            "member_id": r.spec.member_id, "state": r.state.value,
            "dependency_state": r.dependency_state,
            "dependencies": list(r.spec.dependencies), "required": r.spec.required,
            "origin": r.spec.origin, "attempt": r.attempt,
            "max_attempts": r.spec.max_attempts, "priority": r.spec.priority,
            "queued_at": r.queued_at, "started_at": r.started_at,
            "finished_at": r.finished_at, "duration_s": round(r.duration_s(t), 3),
            "queue_wait_s": round(max(0.0, (r.started_at - r.queued_at)), 3)
            if r.started_at and r.queued_at else 0.0,
            "timeout_s": r.spec.timeout_seconds, "model_calls": r.model_calls,
            "error": r.error, "wait_reason": r.wait_reason,
            "replaced_by": r.replaced_by,
            "result_summary": red(res.summary)[:300] if res is not None else "",
            "findings": len(res.findings) if res is not None else 0,
            "observed": len(res.observed) if res is not None else 0,
            "evidence_refs": list(res.evidence_refs) if res is not None else [],
            "confidence": res.confidence if res is not None else "",
            "verification": res.verification if res is not None else "",
            "handoff_requests": len(res.handoff_requests) if res is not None else 0,
            "action_proposals": len(res.action_proposals) if res is not None else 0,
        }

    def _agent_view(self, run: TeamRun, member, t: float, redact=None) -> dict:
        red = redact or (lambda x: x)
        tasks = [r for r in run.ordered_tasks() if r.spec.member_id == member.member_id]
        current = next((r for r in tasks if not r.terminal), None)
        out = {
            "member_id": member.member_id, "role": member.role,
            "kind": "core" if member.kind == "core" else "temp",
            "worker_type": member.kind,
            "parent": member.parent_agent_id if member.kind != "core" else "planner",
            "agent_id": member.agent_id or run.specialists.get(member.member_id, ""),
            "state": "", "current_task": current.task_id if current else "",
            "queue_position": 0, "started_at": 0.0, "last_activity": 0.0,
            "children": [], "ttl_remaining_s": 0,
            "result_summary": "", "tasks": [r.task_id for r in tasks],
        }
        aid = out["agent_id"]
        try:
            from agents.registry import registry
            reg = registry()
            if member.kind == "core":
                rt = reg.get(aid)
                out.update(state=rt.state, queue_position=rt.queue_position,
                           last_activity=rt.last_activity_at)
                out["children"] = [c.dspec.agent_id for c in reg.dynamic_children(aid)
                                   if c.dspec.agent_id in run.specialists.values()]
            elif aid:
                rec = reg.get_dynamic(aid)
                if rec is not None:
                    v = self._mgr().view(rec, now=t, redact=red)
                    out.update(state=v["state"], queue_position=v["queue_state"]["queue_position"],
                               last_activity=rec.runtime.last_activity_at,
                               children=v["children"], ttl_remaining_s=v["ttl_remaining_s"],
                               result_summary=v["result_summary"])
                else:
                    out["state"] = "DESTROYED"
        except Exception:
            pass
        done = [r for r in tasks if r.state is _T.COMPLETED and r.result is not None]
        if done and not out["result_summary"]:
            out["result_summary"] = red(done[-1].result.summary)[:300]
        if tasks:
            out["started_at"] = min((r.started_at for r in tasks if r.started_at), default=0.0)
        return out

    def _tree(self, run: TeamRun, t: float, redact=None) -> dict:
        """PLANNER (the orchestrator) -> core members -> their specialists.
        A specialist whose parent is not a member hangs off the root."""
        members = [self._agent_view(run, m, t, redact) for m in run.plan.members]
        by_id = {m["agent_id"]: m for m in members if m["kind"] == "core"}

        def node(m):
            return {"id": m["agent_id"] or m["member_id"], "role": m["role"],
                    "kind": m["kind"], "state": m["state"],
                    "current_task": m["current_task"], "children": []}

        root = {"id": "planner", "role": "planner", "kind": "orchestrator",
                "state": run.state.value, "current_task": "", "children": []}
        nodes = {m["member_id"]: node(m) for m in members}
        for m in members:
            n = nodes[m["member_id"]]
            parent = by_id.get(m["parent"]) if m["kind"] == "temp" else None
            if parent is not None:
                nodes[parent["member_id"]]["children"].append(n)
            else:
                root["children"].append(n)
        # verifier last, as the figure in the design shows it
        root["children"].sort(key=lambda n: (n["role"] == "verifier", n["id"]))
        return root

    def teams(self, *, redact=None) -> list:
        t = self.clock()
        with self._lock:
            active = [self._team_view(r, t, redact) for r in self._teams.values()]
            recent = [self._team_view(r, t, redact) for r in reversed(self._history)]
        return active + recent

    def team(self, team_id: str, *, redact=None) -> dict | None:
        t = self.clock()
        with self._lock:
            run = self._teams.get(team_id) or self._find_history(team_id)
            if run is None:
                return None
            out = self._team_view(run, t, redact)
            out["members"] = [self._agent_view(run, m, t, redact) for m in run.plan.members]
            out["tasks"] = [self._task_view(run, r, t, redact) for r in run.ordered_tasks()]
            out["tree"] = self._tree(run, t, redact)
            out["dependencies"] = [list(e) for e in run.plan.edges]
            out["activity"] = [{"ts": a[0], "code": a[1], "task_id": a[2],
                                "detail": a[3]} for a in run.activity[-40:]]
            out["verification"] = run.verify_log[-1] if run.verify_log else {}
            out["verifications"] = list(run.verify_log)
            out["result"] = run.result
            return out

    def tasks(self, team_id: str, *, redact=None) -> list | None:
        t = self.clock()
        with self._lock:
            run = self._teams.get(team_id) or self._find_history(team_id)
            if run is None:
                return None
            return [self._task_view(run, r, t, redact) for r in run.ordered_tasks()]

    def tree(self, team_id: str, *, redact=None) -> dict | None:
        t = self.clock()
        with self._lock:
            run = self._teams.get(team_id) or self._find_history(team_id)
            return None if run is None else self._tree(run, t, redact)

    def status(self) -> dict:
        with self._lock:
            active = len(self._teams)
            states = {}
            for r in self._teams.values():
                states[r.state.value] = states.get(r.state.value, 0) + 1
            recent = len(self._history)
        m = dict(self.metrics)
        m["avg_tick_ms"] = round(1000 * m["tick_time_s"] / m["ticks"], 3) if m["ticks"] else 0.0
        m["max_tick_ms"] = round(1000 * m.pop("max_tick_s"), 3)
        m.pop("tick_time_s", None)
        return {"active_teams": active, "states": states, "recent_teams": recent,
                "limits": {"max_active_teams": MAX_ACTIVE_TEAMS,
                           "max_team_members": MAX_TEAM_MEMBERS,
                           "max_inflight_per_team": MAX_INFLIGHT_PER_TEAM,
                           "max_handoffs_per_team": MAX_HANDOFFS_PER_TEAM,
                           "tick_s": TICK_S},
                "metrics": m, "wired": self._wired}

    # ── team state helper ────────────────────────────────────────────
    def _set_team_state(self, run: TeamRun, new: TeamState, note: str,
                        t: float) -> None:
        if run.set_state(new, note, t):
            self._team_state[run.team_id] = new.value



_ORCHESTRATOR = AgentOrchestrator()


def orchestrator() -> AgentOrchestrator:
    """The process-wide orchestrator. Nothing is wired or started until the
    first complex task is submitted: simple commands, telemetry, chat and
    everything else never pay for it."""
    return _ORCHESTRATOR
