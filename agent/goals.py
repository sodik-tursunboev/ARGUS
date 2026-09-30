"""
ARGUS - Agent Kernel: the Goal type.

Deliberately thin. A Goal is what the owner asked for, in their own words,
plus enough bookkeeping to log and refer back to it -- NOT a place to store
interpretation, permission, or a plan. Those live in TaskState
(task_state.py), which is built FROM a Goal but is not one. Keeping the two
separate is what lets "the owner's actual request" stay legible even after
the planner has broken it into steps and some of those steps have failed.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import itertools
import time
from dataclasses import dataclass, field

_id_seq = itertools.count(1)


@dataclass(frozen=True)
class Goal:
    """One thing the owner asked ARGUS to accomplish, verbatim.

    Frozen: once stated, a goal's own text does not change underneath the
    task working on it. A REVISED request is a NEW Goal (and, if a task was
    already in flight, that task's history says so) -- silently mutating the
    goal a running task is judged against is exactly the kind of drift
    working memory (section 15) exists to make visible instead of hiding.
    """
    text: str
    id: int = field(default_factory=lambda: next(_id_seq))
    created_at: float = field(default_factory=time.time)
    web: bool = False   # routes through router's WEB_TASK_PROMPT/allowlist

    def __str__(self) -> str:
        return self.text
