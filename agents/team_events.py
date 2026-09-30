'ARGUS - Agent teams: lifecycle events and the audit record.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import re
import time

from agents import events, spawn_audit


TEAM_CREATED = "team.created"
PLAN_CREATED = "team.plan_created"
STARTED = "team.started"
TASK_READY = "team.task_ready"
TASK_STARTED = "team.task_started"
TASK_COMPLETED = "team.task_completed"
TASK_FAILED = "team.task_failed"            # payload.state: FAILED|TIMED_OUT|SKIPPED|CANCELLED
AGENT_REQUESTED = "team.agent_requested"
AGENT_SPAWNED = "team.agent_spawned"
HANDOFF = "team.handoff"                    # payload.decision: accepted|refused
VERIFICATION_STARTED = "team.verification_started"
VERIFICATION_COMPLETED = "team.verification_completed"
REPLAN_REQUESTED = "team.replan_requested"
REPLANNED = "team.replanned"
PARTIAL = "team.partial"
COMPLETED = "team.completed"
FAILED = "team.failed"
CANCELLED = "team.cancelled"
TIMED_OUT = "team.timed_out"

TEAM_EVENTS = (
    TEAM_CREATED, PLAN_CREATED, STARTED, TASK_READY, TASK_STARTED,
    TASK_COMPLETED, TASK_FAILED, AGENT_REQUESTED, AGENT_SPAWNED, HANDOFF,
    VERIFICATION_STARTED, VERIFICATION_COMPLETED, REPLAN_REQUESTED, REPLANNED,
    PARTIAL, COMPLETED, FAILED, CANCELLED, TIMED_OUT,
)

_KEYS = frozenset({
    "team_id", "task_id", "agent_id", "role", "kind", "state", "reason",
    "verdict", "decision", "from_agent", "to_agent", "template", "parent_id",
    "priority", "attempt", "duration_s", "progress", "member_count",
    "temporary_count", "model_calls", "replans", "handoffs", "task_count",
    "added", "ts",
})

_TEAM_ID = re.compile(r"^team-[0-9a-f]{8}$")
_TASK_ID = re.compile(r"^T[1-9][0-9]?$")


def team_event(event_type: str, **fields) -> None:
    """Publish one team event with a whitelisted, clipped payload."""
    if event_type not in TEAM_EVENTS:
        return
    payload: dict = {}
    for key, value in fields.items():
        if key not in _KEYS:
            continue
        if isinstance(value, bool):
            payload[key] = value
        elif isinstance(value, (int, float)):
            payload[key] = round(value, 3) if isinstance(value, float) else value
        elif isinstance(value, str):
            payload[key] = value[:64]
        elif key == "added" and isinstance(value, (list, tuple)):
            payload[key] = [str(x)[:8] for x in value[:12]]
    payload.setdefault("ts", time.time())
    events.emit(event_type, payload)


# ── audit lines ──────────────────────────────────────────────────────────
def _tid(team_id) -> str:
    return team_id if isinstance(team_id, str) and _TEAM_ID.match(team_id) else "?"


def _task(task_id) -> str:
    return task_id if isinstance(task_id, str) and _TASK_ID.match(task_id) else "-"


def _code(value, n: int = 40) -> str:
    s = re.sub(r"[^a-z0-9_:+.-]", "_", str(value or "").lower())[:n]
    return s or "-"


def _tasks(ids) -> str:
    out = [t for t in (ids or ()) if _TASK_ID.match(str(t))]
    return ",".join(out[:12]) or "-"


def _line(event: str, detail: str, outcome: str = "ok") -> tuple:
    return (event, detail[:150], outcome)


def audit_created(team_id, goal_digest, plan, temp_planned: int) -> None:
    spawn_audit.write_lines([_line(
        "agent_team",
        f"created team={_tid(team_id)} goal={_code(goal_digest, 12)} "
        f"tasks={len(plan.tasks)} members={len(plan.members)} "
        f"temp={int(temp_planned)} policy={_code(plan.failure_policy.value)} "
        f"calls={plan.max_model_calls} runtime={plan.max_runtime_seconds}s")])


def audit_declined(request_digest, reason: str, suggested: str) -> None:
    spawn_audit.write_lines([_line(
        "agent_team",
        f"declined goal={_code(request_digest, 12)} reason={_code(reason)} "
        f"single={spawn_audit.safe_ref(suggested)}", "ok")])


def audit_task(team_id, task_id, agent_id, state, *, attempt: int = 0,
               reason: str = "", role: str = "") -> None:
    spawn_audit.write_lines([_line(
        "agent_team_task",
        f"team={_tid(team_id)} task={_task(task_id)} "
        f"agent={spawn_audit.safe_ref(agent_id) if agent_id else '-'} "
        f"role={_code(role) if role else '-'} state={_code(state)} "
        f"attempt={int(attempt)} reason={_code(reason)}",
        "ok" if state == "COMPLETED" or reason == "" else "failed")])


def audit_agent(team_id, task_id, template, parent_id, *, approved: bool,
                agent_id: str = "", reason: str = "") -> None:
    spawn_audit.write_lines([_line(
        "agent_team_agent",
        f"team={_tid(team_id)} task={_task(task_id)} template={_code(template)} "
        f"par={spawn_audit.safe_ref(parent_id)} "
        f"id={spawn_audit.trusted_id(agent_id) if agent_id else '-'}",
        "approved" if approved else f"denied:{_code(reason)}")])


def audit_handoff(team_id, from_agent, to_agent, *, accepted: bool,
                  task_id: str = "", reason: str = "") -> None:
    spawn_audit.write_lines([_line(
        "agent_team_handoff",
        f"team={_tid(team_id)} from={spawn_audit.safe_ref(from_agent)} "
        f"to={spawn_audit.safe_ref(to_agent)} task={_task(task_id)}",
        "accepted" if accepted else f"refused:{_code(reason)}")])


def audit_replan(team_id, n: int, reason: str, added) -> None:
    spawn_audit.write_lines([_line(
        "agent_team_replan",
        f"team={_tid(team_id)} n={int(n)} reason={_code(reason)} "
        f"added={_tasks(added)}")])


def audit_verify(team_id, task_id, *, deterministic: str, model: str,
                 combined: str, reasons) -> None:
    spawn_audit.write_lines([_line(
        "agent_team_verify",
        f"team={_tid(team_id)} task={_task(task_id)} det={_code(deterministic)} "
        f"model={_code(model or 'none')} verdict={_code(combined)} "
        f"reasons={'+'.join(_code(r, 24) for r in list(reasons)[:5]) or '-'}")])


def audit_proposals(team_id, task_id, agent_id, proposals) -> None:
    """Action proposals surfaced by a task: skill/action pairs are the closed
    catalog vocabulary (they already passed the capability boundary)."""
    pairs = ",".join(f"{_code(p.skill, 16)}/{_code(p.action, 16)}"
                     for p in list(proposals)[:6])
    spawn_audit.write_lines([_line(
        "agent_team_proposal",
        f"team={_tid(team_id)} task={_task(task_id)} "
        f"agent={spawn_audit.safe_ref(agent_id)} n={len(list(proposals))} "
        f"pairs={pairs or '-'}", "proposed")])


def audit_end(team_id, state, reason, *, tasks_done: int, tasks_total: int,
              calls: int, replans: int, handoffs: int, temp: int,
              verdict: str, life_s: float) -> None:
    spawn_audit.write_lines([_line(
        "agent_team_end",
        f"team={_tid(team_id)} state={_code(state)} reason={_code(reason)} "
        f"tasks={int(tasks_done)}/{int(tasks_total)} calls={int(calls)} "
        f"replans={int(replans)} handoffs={int(handoffs)} temp={int(temp)} "
        f"verdict={_code(verdict or 'none')} life={int(max(0, life_s))}s",
        "ok" if state in ("COMPLETED", "PARTIAL") else "failed")])


def audit_cancel(team_id, scope, ref, reason) -> None:
    spawn_audit.write_lines([_line(
        "agent_team_cancel",
        f"team={_tid(team_id)} scope={_code(scope, 8)} ref={_code(ref, 16)} "
        f"reason={_code(reason)}")])
