"""Agent kernel. Plans are staged here; router authorization gates every executed step."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

from agent.budgets import (Budget, DEFAULT_BUDGET, clear as clear_budgets,
                           consume_model_call, exceeded, normalize_goal,
                           note_plan, record_replan, replans_left, reserve_plan,
                           summary as budget_summary)
from agent.capability_catalog import Capability, all_capabilities, describe, find, get
from agent.context import Fact, WorldState, capture
from agent.goals import Goal
from agent.kernel import AgentDecision, current_decision, run_goal, task_observations
from agent.observer import Observation, classify_reply, observe
from agent.replanner import diagnose, propose_alternative
from agent.task_state import TaskState, current_task, last_task_state
from agent.working_memory import recent_tasks, remember_completed

__all__ = [
    "Capability", "all_capabilities", "describe", "find", "get",
    "Fact", "WorldState", "capture",
    "Goal",
    "AgentDecision", "current_decision", "run_goal", "task_observations",
    "Observation", "classify_reply", "observe",
    "TaskState", "current_task", "last_task_state",
    "recent_tasks", "remember_completed",
    "Budget", "DEFAULT_BUDGET", "clear_budgets", "exceeded", "normalize_goal",
    "note_plan", "record_replan", "replans_left", "reserve_plan",
    "consume_model_call", "budget_summary",
    "diagnose", "propose_alternative",
]
