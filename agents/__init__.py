'ARGUS - Local agents package.'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

from agents.definitions import (ALL_AGENTS, HANDOFF_GRAPH, AgentSpec,
                                get_spec, handoff_allowed)
from agents.dynamic_spec import AgentStatus, AgentType, DynamicAgentSpec
from agents.jobs import AgentJob
from agents.registry import AgentRegistry, UnknownAgentError

__all__ = [
    "ALL_AGENTS", "HANDOFF_GRAPH", "AgentSpec", "get_spec",
    "handoff_allowed",
    "AgentJob", "AgentRegistry", "UnknownAgentError",
    "AgentType", "AgentStatus", "DynamicAgentSpec",
    "get_coordinator", "get_registry", "get_dynamic_manager",
    "get_orchestrator",
]


def get_coordinator():
    """The process-wide coordinator (agents/coordinator.coordinator())."""
    from agents.coordinator import coordinator
    return coordinator()


def get_registry():
    """The process-wide registry (agents/registry.registry())."""
    from agents.registry import registry
    return registry()


def get_dynamic_manager():
    """The process-wide temporary-agent manager (agents/ephemeral.manager()).

    DYNAMIC AGENTS (docs: agents/dynamic_spec.py, governor.py, architect.py,
    ephemeral.py): temporary specialists that the Architect proposes and the
    Governor rules on, deterministically. "Agents may create intelligence.
    They may never create authority": a child's permissions are a subset of
    its approved parent's, enforced in code, never by prompt."""
    from agents.ephemeral import manager
    return manager()


def get_orchestrator():
    'The process-wide team orchestrator (agents/orchestrator.orchestrator()).'
    from agents.orchestrator import orchestrator
    return orchestrator()
