'ARGUS - Agent Kernel: TaskState.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

from dataclasses import dataclass, field

import router


@dataclass
class TaskState:
    "Working memory for one task."
    state: str = "none"
    task_id: str = ""
    plan_id: str = ""
    goal: str = ""
    constraints: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    observed_facts: list[str] = field(default_factory=list)
    completed_actions: list[dict] = field(default_factory=list)
    failed_actions: list[dict] = field(default_factory=list)
    pending_actions: list[dict] = field(default_factory=list)
    candidate_strategies: list[str] = field(default_factory=list)
    security_decisions: list[str] = field(default_factory=list)
    user_approvals: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    pause_reason: str = ""
    final_state: str = ""
    provenance: list[dict] = field(default_factory=list)

    @property
    def active(self) -> bool:
        return self.state != "none"

    def summary(self) -> str:
        """One line, for a status panel or "what are you doing right now"."""
        if self.state == "none":
            return "No task in progress."
        if self.state == "staged":
            return (f"Staged: {self.goal!r} — {len(self.pending_actions)} step(s), "
                    f"waiting for approval.")
        if self.state == "paused":
            return (f"Paused on {self.goal!r} — {len(self.completed_actions)} done, "
                    f"{len(self.pending_actions)} left. Waiting: {self.pause_reason}")
        return f"{self.goal!r}: {self.final_state}"


def current_task() -> TaskState:
    """The live task, reflected from router.plan_snapshot(). Never raises --
    a caller building a status panel must not go down because router's
    internal shape moved out from under this reflection; an empty/"none"
    TaskState is the honest fallback."""
    try:
        snap = router.plan_snapshot()
    except Exception:
        return TaskState()

    state = snap.get("state", "none")
    shared = {
        "task_id": str(snap.get("task_id", "") or ""),
        "plan_id": str(snap.get("plan_id", "") or ""),
        "constraints": list(snap.get("constraints", [])),
        "assumptions": list(snap.get("assumptions", [])),
        "candidate_strategies": list(snap.get("strategies", [])),
        "security_decisions": list(snap.get("security_decisions", [])),
        "user_approvals": list(snap.get("user_approvals", [])),
        "artifacts": list(snap.get("artifacts", [])),
        "final_state": str(snap.get("final_state", "") or ""),
        "provenance": router.plan_provenance(),
    }
    observed_facts = []
    failed_actions = []
    try:
        for observation in router.plan_observations():
            verification = "unverified"
            if observation.verified:
                verification = "changed" if observation.changed else "unchanged"
            observed_facts.append(
                f"{observation.status}: {verification}; {observation.reply[:160]}")
            if not observation.ok and observation.status != "paused":
                failed_actions.append({
                    "status": observation.status,
                    "result": observation.reply[:300],
                    "verified": observation.verified,
                    "changed": observation.changed,
                })
    except Exception:
        pass
    shared["observed_facts"] = observed_facts
    shared["failed_actions"] = failed_actions
    if state == "staged":
        steps = snap.get("steps", [])
        return TaskState(state="staged", goal=snap.get("goal", ""),
                         pending_actions=steps, **shared)
    if state == "paused":
        return TaskState(
            state="paused", goal=snap.get("goal", ""),
            completed_actions=snap.get("results", []),
            pending_actions=snap.get("remaining_steps", []),
            pause_reason=snap.get("reason", ""),
            **shared,
        )
    return TaskState()


def last_task_state() -> TaskState:
    """Rich final state for natural follow-ups after the live plan is gone."""
    try:
        from agent.working_memory import recent_tasks
        items = recent_tasks(1)
    except Exception:
        items = []
    if not items:
        return TaskState()
    item = items[0]
    completed = []
    failed = []
    observed = []
    for record in item.provenance:
        summary = dict(record)
        status = str(record.get("observation", {}).get("status", "unknown"))
        observed.append(f"{record.get('capability', '')}: {status}")
        (completed if status == "success" else failed).append(summary)
    return TaskState(
        state=item.final_state or ("completed" if item.ok else "failed"),
        task_id=item.task_id, plan_id=item.plan_id, goal=item.goal,
        constraints=list(item.constraints), assumptions=list(item.assumptions),
        observed_facts=observed, completed_actions=completed,
        failed_actions=failed, candidate_strategies=list(item.strategies),
        artifacts=list(item.artifacts), final_state=item.final_state,
        provenance=[dict(x) for x in item.provenance],
    )
