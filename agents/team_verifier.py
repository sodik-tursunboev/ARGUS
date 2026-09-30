'ARGUS - Agent teams: independent verification.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

from dataclasses import dataclass

from agents.team_schema import VERDICT_RANK, TaskState, Verdict

# agents/results.VERDICTS -> the team vocabulary
MODEL_VERDICTS = {
    "verified": Verdict.VERIFIED,
    "partially_verified": Verdict.PARTIALLY_VERIFIED,
    "not_verified": Verdict.FAILED,
    "contradicted": Verdict.CONTRADICTED,
    "insufficient_evidence": Verdict.INSUFFICIENT_EVIDENCE,
}


@dataclass(frozen=True)
class VerificationAssessment:
    deterministic: Verdict
    model: Verdict | None
    combined: Verdict
    reasons: tuple                # stable codes
    required_total: int
    required_completed: int
    grounded_refs: int
    observed_findings: int
    inferred_findings: int
    missing: tuple                # required task ids not COMPLETED
    retry_useful: bool

    def as_dict(self) -> dict:
        return {"deterministic": self.deterministic.value,
                "model": self.model.value if self.model else "",
                "verdict": self.combined.value, "reasons": list(self.reasons),
                "required_total": self.required_total,
                "required_completed": self.required_completed,
                "grounded_refs": self.grounded_refs,
                "observed_findings": self.observed_findings,
                "inferred_findings": self.inferred_findings,
                "missing": list(self.missing), "retry_useful": self.retry_useful}


def worst(*verdicts) -> Verdict:
    vs = [v for v in verdicts if v is not None]
    return max(vs, key=lambda v: VERDICT_RANK[v]) if vs else Verdict.FAILED


def resolved(run, r):
    """A task that failed and was REPLACED by a replan is judged by its
    replacement (following the chain); anything else by itself."""
    seen = set()
    while r.replaced_by and r.replaced_by in run.tasks and r.task_id not in seen:
        seen.add(r.task_id)
        r = run.tasks[r.replaced_by]
    return r


def deterministic(run) -> tuple:
    """(Verdict, reasons, stats) from the run's records alone."""
    reasons = []
    agent_tasks = run.agent_tasks()
    required = []
    for r in agent_tasks:
        if r.spec.required:
            rr = resolved(run, r)
            if all(rr.task_id != x.task_id for x in required):
                required.append(rr)
    completed = [r for r in required if r.state is TaskState.COMPLETED]
    missing = tuple(r.task_id for r in required if r.state is not TaskState.COMPLETED)
    any_completed = any(r.state is TaskState.COMPLETED for r in agent_tasks)
    grounded = [ref for ref in run.evidence.all() if ref.is_observed_source]
    observed = sum(len(r.result.observed) for r in agent_tasks
                   if r.result is not None)
    inferred = sum(len(r.result.findings) - len(r.result.observed)
                   for r in agent_tasks if r.result is not None)
    unsupported = [r.task_id for r in completed
                   if r.result is not None and r.result.findings
                   and not r.result.observed]
    stats = {"required_total": len(required), "required_completed": len(completed),
             "grounded_refs": len(grounded), "observed_findings": observed,
             "inferred_findings": inferred, "missing": missing}
    if not any_completed:
        reasons.append("no_task_completed")
        return Verdict.FAILED, tuple(reasons), stats
    if missing:
        reasons.append("required_task_incomplete")
        return Verdict.INSUFFICIENT_EVIDENCE, tuple(reasons), stats
    if not grounded:
        reasons.append("no_grounded_evidence")
        return Verdict.INSUFFICIENT_EVIDENCE, tuple(reasons), stats
    if observed == 0:
        reasons.append("no_observed_finding")
        return Verdict.INSUFFICIENT_EVIDENCE, tuple(reasons), stats
    if unsupported:
        reasons.append("inference_only_tasks")
        return Verdict.PARTIALLY_VERIFIED, tuple(reasons), stats
    return Verdict.VERIFIED, tuple(reasons), stats


def model_verdict(run) -> Verdict | None:
    """The VERIFY task's returned verdict, or None if it did not run/return."""
    for r in reversed(run.verify_tasks()):
        if r.state is TaskState.COMPLETED and r.result is not None:
            v = MODEL_VERDICTS.get(str(r.result.verification or "").lower())
            if v is not None:
                return v
            return None
    return None


def assess(run) -> VerificationAssessment:
    det, reasons, stats = deterministic(run)
    mv = model_verdict(run)
    reasons = list(reasons)
    if mv is None:
        reasons.append("model_verdict_unavailable")
        combined = worst(det, Verdict.PARTIALLY_VERIFIED)
    else:
        combined = worst(det, mv)
        if VERDICT_RANK[mv] > VERDICT_RANK[det]:
            reasons.append(f"model_lowered_to:{mv.value.lower()}")
    # A retry is useful when what is missing is WORK (a task that did not
    # complete), not when the completed work simply lacks grounding.
    retry_useful = bool(stats["missing"]) or (
        combined in (Verdict.INSUFFICIENT_EVIDENCE, Verdict.CONTRADICTED))
    return VerificationAssessment(
        deterministic=det, model=mv, combined=combined, reasons=tuple(reasons),
        required_total=stats["required_total"],
        required_completed=stats["required_completed"],
        grounded_refs=stats["grounded_refs"],
        observed_findings=stats["observed_findings"],
        inferred_findings=stats["inferred_findings"],
        missing=tuple(stats["missing"]), retry_useful=retry_useful)
