"""
ARGUS - Local agents: the coordinator.

One central scheduler for the six logical agents. It owns the queue, the
worker thread, job lifecycle and handoffs. What it deliberately IS NOT:

  - not a security authority: it never authorizes, dispatches or executes.
    Capability requests leave through agents/capabilities.py (audit only);
    a handoff is just another queued ANALYSIS job;
  - not an autonomous loop: jobs exist only when someone submits them (API,
    an existing event hook later, tests). No scheduler, no chatter.

Every lifecycle transition is evented (agents/events.py). Every failure is
isolated: one bad job can never take the worker thread down -- the guard in
_run_one is the last line, but each stage also degrades on its own.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time

import security

from agents import (capabilities, context, ephemeral, events, evidence,
                    model_runtime)
from agents.definitions import TIER_NAMES, get_spec, handoff_allowed
from agents.jobs import (ACTIVE_STATES, BLOCKED, CANCELLED, COMPLETED, FAILED,
                         MAX_HANDOFFS, MAX_JOB_HISTORY, MAX_RETRIES, QUEUED,
                         RUNNING, WAITING_AUTH, TERMINAL, AgentJob,
                         JobStateError)
from agents.queue import BoundedPriorityQueue
from agents.registry import UnknownAgentError, registry
from agents.results import parse as parse_result
from agents.results import result_prompt

_WORKER_POLL_S = 0.05
# Max live job records (history) kept in memory; bounded like every other
# history in ARGUS.
_HISTORY_KEEP = MAX_JOB_HISTORY


class Coordinator:
    def __init__(self):
        self._queue = BoundedPriorityQueue()
        self._history: dict[str, AgentJob] = {}
        self._order: list[str] = []
        self._lock = threading.RLock()
        self._runtime = model_runtime.runtime()
        self._worker: threading.Thread | None = None
        self._started = False

        # Hooks receive job lifecycle events and cannot block or fail a job.
        self._hooks: list = []

    def add_hook(self, hook) -> None:
        with self._lock:
            if hook not in self._hooks:
                self._hooks.append(hook)

    def remove_hook(self, hook) -> None:
        with self._lock:
            if hook in self._hooks:
                self._hooks.remove(hook)

    def _notify(self, name: str, *args) -> None:
        with self._lock:
            hooks = list(self._hooks)
        for hook in hooks:
            fn = getattr(hook, name, None)
            if fn is None:
                continue
            try:
                fn(*args)
            except Exception:
                pass

    def _owned(self, job: AgentJob) -> bool:
        """True when a hook claims this job's follow-up (handoffs) as its own:
        a team job's handoffs go through the team's explicit, bounded protocol
        rather than the coordinator's structural defaults."""
        with self._lock:
            hooks = list(self._hooks)
        for hook in hooks:
            fn = getattr(hook, "owns_job", None)
            try:
                if fn is not None and fn(job):
                    return True
            except Exception:
                continue
        return False

    # ── submission ───────────────────────────────────────────────────────
    def submit(self, agent_id: str, objective: str, priority: int | None = None,
               *, source: str = "api", parent_job_id: str = "",
               handoff_depth: int = 0) -> tuple[AgentJob | None, str]:
        """Accept a job for a known, enabled agent. Returns (job, reason);
        (None, reason) on rejection. Validation is fail-closed and cheap:
        no model call happens here."""
        try:
            rt = registry().get(agent_id)
        except UnknownAgentError:
            return None, "unknown_agent"
        if not rt.spec.enabled:
            return None, "agent_disabled"
        if source != "academy":
            # Operational/user work takes precedence over optional study.
            # This never grants a capability; it only cancels an Academy job.
            try:
                from agents.academy import cancel_for_work
                cancel_for_work(agent_id)
            except Exception:
                pass
        # A TEMPORARY agent takes work only from the spawn pipeline, and only
        # while it is queued, unexpired and inside its model-call budget.
        # Core agents: this is a dict miss and returns "" at once. A fault in
        # the dynamic layer fails CLOSED for a temporary agent and never
        # touches the ten core agents.
        try:
            why_not = ephemeral.manager().submit_gate(agent_id, source)
        except Exception:
            why_not = ("dynamic_gate_error"
                       if registry().is_dynamic(agent_id) else "")
        if why_not:
            return None, why_not
        text = " ".join(str(objective or "").split())
        if not text:
            return None, "empty_objective"
        if len(text) > 2000:
            text = text[:2000]
        tier = rt.spec.priority if priority is None else int(priority)
        if tier < 0 or tier > 4:
            return None, "bad_priority"
        # A job may not run at a tier the spec forbids: an emergency tier is
        # for the security/threat/verifier agents, not for comfort work.
        if tier < rt.spec.max_priority:
            return None, "priority_above_agent_ceiling"
        job = AgentJob(agent_id=agent_id, objective=text, priority=tier,
                       source=source, parent_job_id=parent_job_id,
                       handoff_depth=handoff_depth)
        with self._lock:
            accepted, evicted = self._queue.push(job)
            if not accepted:
                return None, "queue_full"
            if evicted is not None:
                self._finish(evicted, FAILED,
                             "evicted_by_higher_priority_job", ok=False)
            self._history[job.job_id] = job
            self._order.append(job.job_id)
            if len(self._order) > _HISTORY_KEEP:
                drop = self._order.pop(0)
                self._history.pop(drop, None)
            self._set_state(job, QUEUED,
                            queue_position=self._queue.positions().get(job.job_id, 0))
            events.job_event(events.JOB_QUEUED, job)
        self._ensure_worker()
        return job, ""

    # ── worker ───────────────────────────────────────────────────────────
    def _ensure_worker(self) -> None:
        with self._lock:
            if self._started and self._worker and self._worker.is_alive():
                return
            self._started = True
            self._worker = threading.Thread(target=self._loop, daemon=True,
                                            name="agents-coordinator")
            self._worker.start()

    def _loop(self) -> None:
        while True:
            job = self._queue.pop()
            if job is None:
                time.sleep(_WORKER_POLL_S)
                continue
            try:
                self._run_one(job)
            except Exception as e:  # never let one job kill the worker
                try:
                    # A job that already reached a terminal state (e.g. the
                    # error came from the handoff step AFTER it completed) must
                    # not be flipped to FAILED by a later exception.
                    if job.state not in TERMINAL:
                        self._finish(job, FAILED,
                                     f"internal:{type(e).__name__}", ok=False)
                except Exception:
                    pass
                security.audit("agent_job_error", type(e).__name__, "failed")

    # ── one job ──────────────────────────────────────────────────────────
    def _run_one(self, job: AgentJob) -> None:
        try:
            spec = registry().require(job.agent_id)
        except UnknownAgentError:
            # A TEMPORARY agent was destroyed after its job was popped from the
            # queue (TTL, cancellation, kill switch, parent cascade). Not an
            # internal error: the job is simply cancelled.
            self._finish(job, CANCELLED, "agent_gone", ok=False, audit=False)
            return
        if job.cancelled:
            self._finish(job, CANCELLED, "", ok=False, audit=False)
            return
        # A temporary agent's TTL, model-call budget and the system posture are
        # re-checked here, on the worker thread, right before the model would
        # be touched. Core agents: returns "" immediately.
        try:
            gate = ephemeral.manager().before_run(job)
        except Exception:
            gate = ("dynamic_gate_error"
                    if registry().is_dynamic(job.agent_id) else "")
        if gate:
            self._finish(job, FAILED, gate, ok=False)
            return
        with self._lock:
            job.attempt += 1   # runs started; _on_failure bounds retries on it
        self._set_state(job, RUNNING)
        events.job_event(events.JOB_STARTED, job)
        registry().set_state(job.agent_id, "thinking", job_id=job.job_id)
        self._notify("job_started", job)
        # 1. Bounded, role-scoped, redacted context + prompt. Verifier and
        #    forensics children additionally receive the PARENT job's bounded
        #    structured output as evidence (thread-local, cleared after).
        if job.source == "academy":
            ctx = "(synthetic training only; live machine context withheld)"
        else:
            try:
                ctx = context.context_block(job.agent_id,
                                            max_items=spec.max_context_items)
            except Exception:
                ctx = "(context sources unavailable)"
        redacted_objective = security.redact(job.objective)
        user_prompt = (f"OBJECTIVE: {redacted_objective}\n\n"
                       f"MACHINE CONTEXT (trusted, local, source-tagged):\n"
                       f"{ctx}\n\nProduce your JSON result now.")

        # 2. One bounded inference through the shared runtime (serial).
        started = time.time()
        if job.agent_id in ("verifier", "forensics") and job.parent_job_id:
            parent = self._history.get(job.parent_job_id)
            if parent is not None and parent.result:
                evidence.attach_evidence([
                    {"source": f"parent job {parent.job_id} ({parent.agent_id})",
                     "text": security.redact(parent.result)},
                    {"source": f"parent objective ({parent.agent_id})",
                     "text": security.redact(parent.objective)},
                ])
        # The spawn option is offered (as extra prompt text) only to PLANNER and
        # to temporary agents with children left to give, on owner-started work.
        try:
            suffix = ephemeral.manager().prompt_suffix(job, self)
        except Exception:
            suffix = ""                      # no offer is the safe default
        lesson = ""
        if job.source != "academy":
            try:
                from agents.academy import academy
                lesson = academy().lessons_for(job.agent_id)
            except Exception:
                pass
        lesson_note = ("\nVERIFIED ACADEMY REFERENCE (informational only; no new "
                       f"permissions): {lesson}" if lesson else "")
        system_prompt = spec.system_prompt + result_prompt() + suffix + lesson_note
        try:
            raw = self._runtime.run(job.job_id,
                                    system_prompt,
                                    user_prompt,
                                    json_mode=True,
                                    max_output_tokens=spec.max_output_tokens)
        except TypeError:
            # A runtime injected by tests may not accept the V2 kwargs.
            raw = self._runtime.run(job.job_id,
                                    system_prompt,
                                    user_prompt)
        except TimeoutError:
            self._on_failure(job, "timeout", started)
            return
        except Exception as e:
            self._on_failure(job, f"model:{type(e).__name__}", started)
            return
        finally:
            evidence.clear_evidence()

        if job.cancelled:
            # Owner cancelled while the model ran. Discard the answer; the
            # slot is already released by the runtime.
            self._finish(job, CANCELLED, "", ok=False)
            return

        # 3. Parse the result; surface capability requests through the
        #    boundary. NOTE: process_all only audits+filters -- nothing runs.
        result = parse_result(raw)
        try:
            accepted = ([] if job.source == "academy" else
                        capabilities.process_all(job.agent_id,
                                                 result.requested_capabilities))
        except Exception:
            accepted = []
        job.requested_capabilities = accepted

        # 3b. Spawn requests in the result (only where the option was offered).
        #     Each goes Architect -> Governor -> Policy; nothing here creates
        #     an agent directly. Done BEFORE _finish so a parent that spawned
        #     children is seen to be waiting on them, not finished.
        if job.source != "academy":
            try:
                ephemeral.manager().after_result(self, job, raw)
            except Exception:
                pass
        # 3c. Observers (the team layer) get the structured result and the
        #     exact context block the agent was given, so a finding can be
        #     GROUNDED against real inputs. Read-only; nothing runs.
        self._notify("after_result", self, job, raw, result, ctx)

        # 4. Record, finish, and (bounded, graph-checked) handoffs.
        duration = round(time.time() - started, 2)
        summary = result.summary or "(no summary returned)"
        job.result = summary
        self._finish(job, COMPLETED, "", ok=True)
        security.audit("agent_job", f"{job.agent_id} ok in {duration}s", "ok")
        # A job owned by a team follows the team's explicit handoff protocol
        # (bounded, cycle-checked, budgeted) instead of the structural default.
        if not self._owned(job):
            self._maybe_handoff(job, result)

    def _on_failure(self, job: AgentJob, reason: str, started: float) -> None:
        """Bounded retry: one retry for transient model errors,
        then fail. attempt counts runs STARTED, so after the first failure it
        is 1 (<= MAX_RETRIES -> one retry) and after the second it is 2
        (> MAX_RETRIES -> terminal). A queue-wait timeout is never retried:
        it means the card is saturated, not that the model hiccuped."""
        retryable = reason.startswith("model:") and job.attempt <= MAX_RETRIES
        if retryable:
            with self._lock:
                job.state = QUEUED
                self._queue.requeue_front(job)
            events.job_event(events.JOB_QUEUED, job, detail=f"retry:{reason}")
            try:
                ephemeral.manager().job_requeued(job)
            except Exception:
                pass
            return
        self._finish(job, FAILED, reason, ok=False)
        security.audit("agent_job", f"{job.agent_id} failed: {reason}", "failed")

    # ── handoff ──────────────────────────────────────────────────────────
    def _maybe_handoff(self, job: AgentJob, result) -> None:
        """Handoffs, only along DECLARED EDGES (definitions.HANDOFF_GRAPH),
        depth-bounded (MAX_HANDOFFS). Two sources of a target:

          1. the structural default: verification-shaped work suggests the
             verifier, when the spec allows that edge;
          2. the agent's own suggested_handoffs -- filtered through the same
             graph, so a model can never invent a destination.

        A handoff is just another queued ANALYSIS job. The verifier is
        terminal by construction (empty handoff_targets)."""
        if job.handoff_depth >= MAX_HANDOFFS:
            security.audit("agent_handoff_refused",
                           f"depth {job.handoff_depth} >= {MAX_HANDOFFS}",
                           "blocked")
            return
        wants = []
        # 1. the structural verifier edge, where the spec allows it
        if (job.agent_id != "verifier"
                and (result.verification_needed
                     or "verify" in job.objective.lower())
                and self._handoff_ok(job.agent_id, "verifier")):
            wants.append("verifier")
        # 2. the agent's own suggestions, graph-checked
        for target in getattr(result, "suggested_handoffs", ()) or []:
            if target not in wants and self._handoff_ok(job.agent_id, target):
                wants.append(target)
        if not wants:
            return
        for target in wants[:2]:   # bounded fan-out per job
            objective = (f"Handoff from {job.agent_id}. Parent objective was: "
                         f"{job.objective[:280]}. Parent result was: "
                         f"{job.result[:280]}.")
            if target == "verifier":
                objective = (f"Verify this outcome. Objective was: "
                             f"{job.objective[:300]}. Result was: "
                             f"{job.result[:300]}")
            sub, why = self.submit(target, objective,
                                   priority=min(job.priority + 1, 4),
                                   source="handoff", parent_job_id=job.job_id,
                                   handoff_depth=job.handoff_depth + 1)
            if sub is not None:
                try:
                    ephemeral.manager().note_handoff(job.agent_id)
                except Exception:
                    pass
                # Edge + endpoints on the record.
                events.emit(events.HANDOFF, {
                    "agent_id": job.agent_id,
                    "source_agent": job.agent_id,
                    "target_agent": target,
                    "source_job": job.job_id,
                    "target_job": sub.job_id,
                    "priority": sub.priority,
                    "handoff_depth": sub.handoff_depth,
                    "ts": time.time(),
                })
            else:
                security.audit("agent_handoff_refused",
                               f"{job.agent_id}->{target}: {why}", "blocked")

    def root_source(self, job: AgentJob) -> str:
        """The `source` of the job that STARTED this chain (following
        parent_job_id through handoffs and spawns). "unknown" if the chain
        cannot be followed to its root -- callers treat that as untrusted."""
        with self._lock:
            cur, hops = job, 0
            while cur.parent_job_id:
                cur = self._history.get(cur.parent_job_id)
                hops += 1
                if cur is None or hops > 8:
                    return "unknown"
            return cur.source

    @staticmethod
    def _handoff_ok(source: str, target: str) -> bool:
        """A declared edge of the static graph (core agents), or -- for a
        TEMPORARY agent -- verifier-only within its own budget and parent
        chain (agents/ephemeral.py). Anything else is refused."""
        if handoff_allowed(source, target):
            return True
        try:
            return ephemeral.manager().handoff_allowed(source, target)
        except Exception:
            return False

    # ── control ──────────────────────────────────────────────────────────
    def cancel_agent(self, agent_id: str) -> int:
        """Cancel every queued or running job of ONE agent (used when a
        temporary agent is destroyed). Returns how many were cancelled."""
        with self._lock:
            ids = [jid for jid, j in self._history.items()
                   if j.agent_id == agent_id and j.state not in TERMINAL]
        n = 0
        for jid in ids:
            ok, _why = self.cancel(jid)
            if ok:
                n += 1
        return n

    def cancel(self, job_id: str) -> tuple[bool, str]:
        with self._lock:
            job = self._history.get(job_id)
            if job is None:
                return False, "unknown_job"
            if job.state in TERMINAL:
                return False, "already_finished"
            job.cancelled = True
            if job.state == QUEUED:
                removed = self._queue.remove(job_id)
                if removed is not None:
                    self._finish(job, CANCELLED, "", ok=False, audit=False)
                    events.job_event(events.CANCELLED, job)
                    return True, ""
            # running: the worker discards the result on completion (the
            # shared-model call itself is not killed -- unsafe).
            return True, "marked"

    def _finish(self, job: AgentJob, state: str, reason: str, *,
                ok: bool, audit: bool = True) -> None:
        with self._lock:
            job.state = state
            job.touch()
            if reason:
                job.error = reason[:300]
        registry().mark_done(job.agent_id, ok=ok)
        event = {COMPLETED: events.COMPLETED, FAILED: events.FAILED,
                 CANCELLED: events.CANCELLED, BLOCKED: events.FAILED}.get(state)
        if event:
            events.job_event(event, job, detail=reason[:80])
        if audit:
            security.audit("agent_job",
                           f"{job.agent_id} -> {state} {reason}".strip(),
                           "ok" if ok else "failed")
        # Every job end drives a TEMPORARY agent's lifecycle (complete / fail /
        # wait on children / cleanup). A no-op for the ten core agents.
        try:
            ephemeral.manager().job_finished(job, state, reason)
        except Exception:
            pass
        self._notify("job_finished", job, state, reason)

    def _set_state(self, job: AgentJob, state: str, **kw) -> None:
        job.state = state
        if state == QUEUED:
            registry().set_state(job.agent_id, "queued", job_id=job.job_id,
                                 queue_position=kw.get("queue_position", 0))
        else:
            registry().set_state(job.agent_id, state.lower(), job_id=job.job_id)
        if state != QUEUED:
            events.job_event(events.STATE_CHANGED, job, state=state)

    # ── read-only views (API) ────────────────────────────────────────────
    def job(self, job_id: str, *, redact=None) -> dict | None:
        with self._lock:
            job = self._history.get(job_id)
            return job.as_dict(redact=redact, detail=True) if job else None

    def jobs(self, limit: int = 20, *, redact=None) -> list[dict]:
        with self._lock:
            out = []
            for jid in reversed(self._order[-limit:]):
                job = self._history.get(jid)
                if job is not None:
                    out.append(job.as_dict(redact=redact))
            return out

    def queue_depth(self) -> int:
        return len(self._queue)

    def status(self, *, redact=None) -> dict:
        """Safe aggregate for the future Agents Office."""
        reg = registry()
        agents = []
        for rt in reg.all():
            agents.append({
                **rt.spec.as_dict(),
                "state": rt.state,
                "current_job_id": rt.current_job_id,
                "queue_position": rt.queue_position,
                "last_activity_at": rt.last_activity_at,
                "completed_jobs": rt.completed_jobs,
                "failed_jobs": rt.failed_jobs,
                "last_error": rt.last_error[:120],
            })
        # A running TEMPORARY agent's job counts as active work too (autonomy
        # defers on this), though temporary agents never appear in "agents".
        running = [rt.current_job_id for rt in reg.all() if rt.state not in
                   ("idle", "disabled", "queued")]
        try:
            running += [d.runtime.current_job_id for d in reg.dynamic_all()
                        if d.runtime.state not in ("idle", "disabled", "queued")]
            dyn_summary = ephemeral.manager().summary()
        except Exception:
            dyn_summary = {"enabled": False}
        return {
            "agents": agents,
            "model": self._runtime.status(),
            "queue_depth": self._queue.depth(),
            "active_jobs": [j for j in running if j],
            "active_count": len([j for j in running if j]),
            "tiers": TIER_NAMES,
            "dynamic": dyn_summary,
        }


_COORDINATOR = Coordinator()


def coordinator() -> Coordinator:
    return _COORDINATOR


def start() -> None:
    """Idempotent. Emits agent.registered once per process and warms the
    worker loop; no model load happens here."""
    coord = coordinator()
    coord._ensure_worker()
    try:
        reg = registry()
        for rt in reg.all():
            events.emit(events.REGISTERED,
                        {"agent_id": rt.spec.id, "role": rt.spec.role,
                         "shared_model": True})
    except Exception:
        pass
