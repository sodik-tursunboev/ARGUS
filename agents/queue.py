"""
ARGUS - Local agents: the bounded priority queue.

Strict ordering at the top: P0 beats P1 beats P2 unconditionally. Starvation
prevention lives ONLY at the bottom, and it is deliberately small: a
background/analysis job (P3/P4) that has waited >= STARVATION_WAIT_S may
overtake a later-arriving job of the same lower tier, nothing more. It can
never overtake P0-P2 -- user-requested and security work always win.

Bounded: MAX_DEPTH jobs. When full, an arriving job is accepted ONLY if it is
more urgent than the least-urgent queued job, which is then EVICTED and
handed back to the coordinator (which marks it failed with an honest reason
-- queued work is never silently dropped). An arriving job that is not more
urgent than everything queued is rejected outright.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import itertools
import threading
import time
from dataclasses import dataclass, field

from agents.jobs import AgentJob

# P3/P4 wait this long, then may pass an equal-tier job that arrived later.
STARVATION_WAIT_S = 45.0

MAX_DEPTH = 16

# Only these tiers participate in the starvation allowance.
BACKGROUND_TIERS = {3, 4}


@dataclass
class _Entry:
    job: AgentJob
    enqueued_at: float = field(default_factory=time.time)
    seq: int = 0


class BoundedPriorityQueue:
    def __init__(self, max_depth: int = MAX_DEPTH):
        self._heap: list[_Entry] = []
        self._lock = threading.Lock()
        self._seq = itertools.count()
        self._max_depth = max_depth

    def __len__(self) -> int:
        with self._lock:
            return len(self._heap)

    def depth(self) -> int:
        return len(self)

    def _sort_key(self, e: _Entry) -> tuple:
        job = e.job
        boosted = (job.priority in BACKGROUND_TIERS
                   and time.time() - e.enqueued_at >= STARVATION_WAIT_S)
        # Boosted background jobs sort between P2 and P3: ahead of their own
        # tier's later arrivals, never ahead of P0-P2.
        tier = 2.5 if boosted else float(job.priority)
        return (tier, e.seq)

    def push(self, job: AgentJob) -> tuple[bool, AgentJob | None]:
        """Returns (accepted, evicted). evicted is the least-urgent queued job
        removed to make room -- None when nothing was evicted. False means the
        incoming job itself was rejected (queue full of work at least as
        urgent)."""
        with self._lock:
            incoming = _Entry(job, time.time(), next(self._seq))
            if len(self._heap) >= self._max_depth:
                lowest = max(self._heap, key=self._sort_key)
                if self._sort_key(incoming) >= self._sort_key(lowest):
                    return False, None
                self._heap.remove(lowest)
                self._heap.append(incoming)
                self._heap.sort(key=self._sort_key)
                return True, lowest.job
            self._heap.append(incoming)
            self._heap.sort(key=self._sort_key)
            return True, None

    def pop(self) -> AgentJob | None:
        with self._lock:
            if not self._heap:
                return None
            return self._heap.pop(0).job

    def peek_order(self) -> list[str]:
        with self._lock:
            return [e.job.job_id for e in self._heap]

    def remove(self, job_id: str) -> AgentJob | None:
        """Cancellation of a queued job."""
        with self._lock:
            for i, e in enumerate(self._heap):
                if e.job.job_id == job_id:
                    return self._heap.pop(i).job
            return None

    def positions(self) -> dict[str, int]:
        with self._lock:
            return {e.job.job_id: i + 1 for i, e in enumerate(self._heap)}

    def requeue_front(self, job: AgentJob) -> None:
        """Retry path: an explicitly re-queued job goes back at its tier's
        front (it already waited once)."""
        with self._lock:
            e = _Entry(job, time.time(), next(self._seq) - len(self._heap) - 1)
            self._heap.append(e)
            self._heap.sort(key=self._sort_key)
