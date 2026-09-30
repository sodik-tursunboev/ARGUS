"""
ARGUS - Agent Kernel: recent-task memory.

Keeps a short, IN-MEMORY-ONLY history of recently completed tasks (goal
text, outcome, whether it looked like a clean finish), so a later "what did
you just do" or a HUD panel can show continuity across turns. task_state.py's
current_task() only ever shows the task in flight RIGHT NOW, and goes back to
"none" the moment one finishes -- this is what fills the gap immediately
after.

NOT PERSISTED TO DISK, on purpose -- matching auth.py's "state lives in
memory only" rule for the identical reason: nothing here should become an
artefact a restart-surviving log would have to protect, and how (or whether)
task history should join the vault is an open question for a later phase,
not a default to back into now. Bounded to a small ring (same shape as
threatmon.__init__'s _buffer) so this can never grow into a de facto
unbounded log of what the owner has asked ARGUS to do.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading
import time
from collections import deque
from dataclasses import dataclass

_MAX = 20
_lock = threading.Lock()
_history: deque = deque(maxlen=_MAX)


@dataclass(frozen=True)
class CompletedTask:
    goal: str
    outcome: str    # the final reply text, truncated
    ok: bool        # looked like a clean finish, not a stop/abort/refusal
    at: float
    task_id: str = ""
    plan_id: str = ""
    final_state: str = ""
    constraints: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    strategies: tuple[str, ...] = ()
    artifacts: tuple[str, ...] = ()
    provenance: tuple[dict, ...] = ()


def remember_completed(goal: str, outcome: str, ok: bool = True,
                       metadata: dict | None = None,
                       provenance: list[dict] | None = None) -> None:
    """Record one finished (or stopped) task.

    router's terminal plan path invokes this through a guarded local import,
    after the normal execution loop has finished.  This function is storage
    only: task memory is never an authorization input or a dispatch path.
    """
    metadata = metadata if isinstance(metadata, dict) else {}
    safe_provenance = tuple(dict(item) for item in (provenance or [])[-50:]
                            if isinstance(item, dict))
    with _lock:
        _history.append(CompletedTask(
            goal=str(goal or "")[:200],
            outcome=str(outcome or "")[:300],
            ok=bool(ok),
            at=time.time(),
            task_id=str(metadata.get("task_id", "") or "")[:80],
            plan_id=str(metadata.get("plan_id", "") or "")[:80],
            final_state=str(metadata.get("final_state", "") or
                            ("completed" if ok else "failed"))[:40],
            constraints=tuple(str(x)[:240] for x in metadata.get("constraints", [])[:12]),
            assumptions=tuple(str(x)[:240] for x in metadata.get("assumptions", [])[:12]),
            strategies=tuple(str(x)[:300] for x in metadata.get("strategies", [])[:8]),
            artifacts=tuple(str(x)[:500] for x in metadata.get("artifacts", [])[:20]),
            provenance=safe_provenance,
        ))


def recent_tasks(n: int = 5) -> list[CompletedTask]:
    """Newest first -- the same convention threatmon.recent() uses, so a
    caller already familiar with that surface does not have to learn a
    second ordering."""
    with _lock:
        return list(_history)[-n:][::-1]
