'ARGUS - Local agents: bounded autonomy scheduler.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
import threading
import time

from agents import events
from agents.coordinator import coordinator as get_coord
from agents.registry import registry as get_registry

try:
    import security
except Exception:  # pragma: no cover - tests bootstrap security first
    security = None

# Fixed read-only objectives, one per agent. These are constant data: the
# loop NEVER composes objectives from results, so no agent-to-agent feedback
# loop can exist. Nothing here asks for an action on the machine.
SCHEDULES: dict[str, str] = {
    "security": ("Review the auth, integrity and policy context in your data "
                 "and summarise the machine's security posture in two "
                 "sentences."),
    "threat": ("Review the recent security events in your data and state "
               "whether any pattern deserves attention, with uncertainty "
               "noted."),
    "assistant": ("In one friendly sentence, summarise what ARGUS can help "
                  "the owner with right now, based only on your data."),
    "system": ("Review the system telemetry in your data and report the "
               "single most notable resource observation."),
    "network": ("Review the network context in your data and summarise "
                "connection posture and any policy constraints in two "
                "sentences."),
    "verifier": ("Re-examine the recent completed results attached in your "
                 "data and give a verdict on whether they hold up."),
    "planner": ("Draft a bounded step plan for reviewing this machine's "
                "startup services, for the owner to approve. Steps only -- "
                "nothing may be executed."),
    "diagnostics": ("Review the runtime health in your data and report "
                    "whether any ARGUS subsystem looks degraded."),
    "forensics": ("Examine the recent events in your data and produce a "
                  "short timeline that separates OBSERVED from INFERRED."),
    "response": ("Draft a containment-plan outline (steps only, no "
                 "execution) for a hypothetical confirmed high-severity "
                 "detection on this machine."),
}

ORDER: tuple[str, ...] = tuple(SCHEDULES)
HISTORY_KEEP = 40


class AutonomyState:
    """Runtime state of the loop. All reads/writes take the lock."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        env_on = os.environ.get("ARGUS_AGENTS_AUTONOMY", "1")
        self.enabled: bool = env_on.strip().lower() not in ("0", "false", "off")
        try:
            self.interval_s: int = max(
                90, int(os.environ.get("ARGUS_AGENTS_AUTONOMY_INTERVAL", "240")))
        except ValueError:
            self.interval_s = 240
        self.cycles = 0
        self.jobs_dispatched = 0
        self.skipped_busy = 0
        self.dispatch_failures = 0
        self.last_dispatch_at = 0.0
        self.last_error = ""
        self.next_index = 0
        self.history: list[dict] = []

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "enabled": self.enabled,
                "interval_s": self.interval_s,
                "cycles": self.cycles,
                "jobs_dispatched": self.jobs_dispatched,
                "skipped_busy": self.skipped_busy,
                "dispatch_failures": self.dispatch_failures,
                "last_dispatch_at": self.last_dispatch_at,
                "last_error": self.last_error,
                "schedule": dict(SCHEDULES),
                "recent": list(self.history[-10:]),
            }


_STATE = AutonomyState()


def status() -> dict:
    return _STATE.snapshot()


def set_enabled(on: bool) -> dict:
    with _STATE.lock:
        _STATE.enabled = bool(on)
    if security is not None:
        try:
            security.audit("agent_autonomy",
                           f"owner set autonomy {'on' if on else 'off'}", "ok")
        except Exception:
            pass
    return status()


def _audit(line: str, outcome: str) -> None:
    if security is None:
        return
    try:
        security.audit("agent_autonomy", line, outcome)
    except Exception:
        pass


def tick() -> str | None:
    """One dispatch attempt: pick the next enabled agent and queue ONE
    background analysis job, unless the system is busy. Returns the agent id
    dispatched, or None. Testable without the thread."""
    st = _STATE
    with st.lock:
        if not st.enabled:
            return None
    coord = get_coord()
    # Deference: any queued user/security work, or an active job, wins.
    if coord.queue_depth() > 0:
        with st.lock:
            st.skipped_busy += 1
        return None
    if coord.status().get("active_count", 0) > 0:
        with st.lock:
            st.skipped_busy += 1
        return None
    reg = get_registry()
    with st.lock:
        start_index = st.next_index
    total = len(ORDER)
    for offset in range(total):
        agent_id = ORDER[(start_index + offset) % total]
        try:
            spec = reg.require(agent_id)
        except Exception:
            continue
        if not spec.enabled:
            continue
        job, _why = coord.submit(agent_id, SCHEDULES[agent_id],
                                 priority=4, source="autonomy")
        with st.lock:
            st.next_index = (start_index + offset + 1) % total
            st.cycles += 1
            if job is not None:
                st.jobs_dispatched += 1
                st.last_dispatch_at = time.time()
                st.history.append({"ts": time.time(), "agent_id": agent_id,
                                   "job_id": job.job_id})
                del st.history[:-HISTORY_KEEP]
            else:
                st.dispatch_failures += 1
                st.last_error = "submit refused"
        if job is not None:
            events.emit("agent.autonomy", {"agent_id": agent_id,
                                           "job_id": job.job_id,
                                           "priority": 4,
                                           "ts": time.time()})
            _audit(f"dispatched {agent_id}", "ok")
            return agent_id
        # submit refused (e.g. flooded): fall through to the defer branch
        with st.lock:
            st.skipped_busy += 1
        return None
    # nothing enabled (should not happen: the registry boots ten)
    with st.lock:
        st.next_index = (start_index + 1) % total
    return None


def _loop() -> None:
    while True:
        try:
            tick()
        except Exception as e:
            with _STATE.lock:
                _STATE.last_error = type(e).__name__
            _audit(f"cycle error {type(e).__name__}", "failed")
        try:
            with _STATE.lock:
                interval = _STATE.interval_s
        except Exception:
            interval = 240
        time.sleep(interval)


_thread: threading.Thread | None = None


def start() -> None:
    """Idempotent. Starts the background dispatch thread."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _thread = threading.Thread(target=_loop, name="agents-autonomy",
                               daemon=True)
    _thread.start()
    st = _STATE.snapshot()
    print(f"[agents] autonomy {'on' if st['enabled'] else 'off'} "
          f"(interval {st['interval_s']}s, background tier, kill-switch: "
          f"POST /api/agents/autonomy)")
