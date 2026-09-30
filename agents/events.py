"""
ARGUS - Local agents: lifecycle events.

Agent events flow through ARGUS's EXISTING event system -- main.py's
_HudEventHub, the same hub every other WS event uses. No second WebSocket
service, no new transport. Publication is strictly fire-and-forget: an
eventing failure must never fail a job, so every publish is swallowed after
an audit fallback (the audit chain is the durable record either way; the WS
push is best-effort for the live HUD).

Payload hygiene matches _HudEventHub's own rule: ids, states, priorities,
durations -- never job text, never results, never anything sensitive.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import time

# The one vocabulary. Event names are stable API: the HUD's
# future Agents Office listens for these.
REGISTERED = "agent.registered"
JOB_QUEUED = "agent.job_queued"
JOB_STARTED = "agent.started"
STATE_CHANGED = "agent.state_changed"
WAITING_AUTH = "agent.waiting_auth"
COMPLETED = "agent.completed"
FAILED = "agent.failed"
CANCELLED = "agent.cancelled"
HANDOFF = "agent.handoff"

# Dynamic (temporary) agent lifecycle -- agents/ephemeral.py. Same hub, same
# envelope, no new transport. agent.started / agent.completed / agent.failed /
# agent.handoff above already fire for a temporary agent's JOBS (they flow
# through the coordinator like any other), and agent.state_changed carries its
# lifecycle status (payload.dynamic = true).
PROPOSED = "agent.proposed"
APPROVED = "agent.approved"
SPAWNED = "agent.spawned"
EXPIRED = "agent.expired"
DESTROYED = "agent.destroyed"
SPAWN_DENIED = "agent.spawn_denied"

DYNAMIC_EVENTS = (PROPOSED, APPROVED, SPAWNED, EXPIRED, DESTROYED, SPAWN_DENIED)

# The ONLY keys a lifecycle payload may carry. Identifiers, states, reason
# CODES and numbers -- never task text, never results, never a capability
# free-text field. A key not on this list is dropped, not forwarded.
_LIFECYCLE_KEYS = frozenset({
    "agent_id", "parent_id", "proposal_id", "requester", "name", "agent_type",
    "spawn_depth", "status", "state", "reason", "reasons", "stage", "ttl_s",
    "priority", "dynamic", "final_status", "ts", "children",
})


def emit(event_type: str, payload: dict) -> None:
    """Best-effort publish + durable audit. Never raises."""
    notify_observers(event_type, payload)
    try:
        import main as _main
        hub = getattr(_main, "_hud_events", None)
        if hub is not None:
            hub.publish(event_type, payload)
            return
    except Exception:
        pass
    # Hub not up (tests, early boot): the audit chain still records it.
    try:
        import security
        security.audit("agent_event",
                       f"{event_type} {payload.get('agent_id', '')}"
                       f" {payload.get('job_id', '')}", "ok")
    except Exception:
        pass


def notify_observers(event_type: str, payload: dict) -> None:
    """The Agent Manager (agents/agent_manager.py) watches the SAME stream
    the HUD does -- no second bus. Its observe() only enqueues (this can run
    under the orchestrator's or the ephemeral manager's lock), and it never
    raises. Imported lazily: agent_manager imports this module."""
    try:
        from agents import agent_manager
        agent_manager.observe(event_type, payload)
    except Exception:
        pass


def lifecycle_event(event_type: str, **fields) -> None:
    """Publish a temporary-agent lifecycle event with a whitelisted payload."""
    payload: dict = {}
    for key, value in fields.items():
        if key not in _LIFECYCLE_KEYS:
            continue
        if isinstance(value, (bool, int, float)):
            payload[key] = value
        elif isinstance(value, str):
            payload[key] = value[:64]
        elif key == "reasons" and isinstance(value, (list, tuple)):
            payload[key] = [str(x)[:64] for x in value[:6]]
        elif key == "children" and isinstance(value, (list, tuple)):
            payload[key] = [str(x)[:16] for x in value[:6]]
    payload.setdefault("ts", time.time())
    emit(event_type, payload)


def job_event(event_type: str, job, *, state: str = "", detail: str = "",
              queue_position: int = 0) -> None:
    """The standard per-job payload shape."""
    payload = {
        "agent_id": job.agent_id,
        "job_id": job.job_id,
        "priority": job.priority,
        "state": state or job.state,
        "ts": time.time(),
    }
    if detail:
        payload["detail"] = detail[:120]
    if queue_position:
        payload["queue_position"] = queue_position
    emit(event_type, payload)
