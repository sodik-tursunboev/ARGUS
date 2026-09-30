"""Job state and lifecycle for local agents."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import time
import uuid
from dataclasses import dataclass, field

# ── lifecycle ────────────────────────────────────────────────────────────────
QUEUED = "queued"
RUNNING = "running"
WAITING_AUTH = "waiting_auth"
EXECUTING = "executing"
VERIFYING = "verifying"
COMPLETED = "completed"
FAILED = "failed"
CANCELLED = "cancelled"
BLOCKED = "blocked"

TERMINAL = {COMPLETED, FAILED, CANCELLED, BLOCKED}
ACTIVE_STATES = {RUNNING, WAITING_AUTH, EXECUTING, VERIFYING}

# How long one job may hold the shared model. Bounded on purpose:
# an agent that hangs must not hang the queue. Generous — llama3.2:3b answers
# in well under this — but never unbounded.
DEFAULT_JOB_TIMEOUT_S = 120.0

# Depth limit for agent->agent handoffs. CONSERVATIVE: THREAT ->
# VERIFIER is one hop and that is the expected shape. A depth that can reach
# three has to be explicitly justified, not defaulted to.
MAX_HANDOFFS = 3
# Retries per job. 1, matching router.py's bounded-patience discipline.
MAX_RETRIES = 1

# Hard cap on live job records (analysis records, not credentials). Same
# bounded-history shape as agent/working_memory.py and threatmon's buffer.
MAX_JOB_HISTORY = 100


class JobStateError(RuntimeError):
    pass


@dataclass
class AgentJob:
    agent_id: str
    objective: str                    # WHAT to analyse; redacted before the model sees it
    priority: int                     # 0..4, lower = more urgent
    job_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    state: str = QUEUED
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    source: str = "api"               # who asked: "api" | "handoff" | "event"
    parent_job_id: str = ""           # set when created by a handoff
    handoff_depth: int = 0
    attempt: int = 0                  # 0 = first try
    cancelled: bool = False
    result: str = ""                  # final summary the owner can read
    error: str = ""
    # A structured capability REQUEST the agent decided it needs. Never

    requested_capabilities: list[dict] = field(default_factory=list)

    def touch(self) -> None:
        self.completed_at = time.time()

    def age_s(self) -> float:
        return time.time() - self.created_at

    def as_dict(self, *, redact=None, detail: bool = False) -> dict:
        """API/serialization view.

        `redact` is security.redact, injected by callers that have it -- this
        module must not import security at module level (import cycle: main ->
        agents.service -> agents.coordinator -> ...), and job text is
        free-form user input, so it goes through redaction exactly once, here,
        for every reader.
        """
        red = (lambda t: redact(t) if redact else str(t))
        d = {
            "job_id": self.job_id,
            "agent_id": self.agent_id,
            "priority": self.priority,
            "state": self.state,
            "source": self.source,
            "parent_job_id": self.parent_job_id,
            "handoff_depth": self.handoff_depth,
            "created_at": self.created_at,
            "age_s": round(self.age_s(), 1),
        }
        if detail:
            d.update({
                "objective": red(self.objective),
                "result": red(self.result) if self.result else "",
                "error": red(self.error) if self.error else "",
                "attempt": self.attempt,
                "started_at": self.started_at or None,
                "completed_at": self.completed_at or None,
                "requested_capabilities": [
                    {"skill": r.get("skill", ""), "action": r.get("action", ""),
                     "target": red(r.get("target", "") or "")}
                    for r in self.requested_capabilities
                ],
            })
        else:
            # List view: one bounded line of the objective, redacted.
            d["objective"] = red(self.objective)[:120]
        return d
