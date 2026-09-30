"""
ARGUS - Local agents: job evidence.

When the coordinator hands a job to VERIFIER or FORENSICS, the parent job's
structured output is the EVIDENCE those agents are entitled to see. This
module carries it: a small thread-local attachment the coordinator sets
right before running a child job and clears afterwards.

Bounded by construction: at most MAX_EVIDENCE items, each clipped. Nothing
here is a history store -- past jobs are not retained for context dumping; only the explicit parent->child edge carries evidence, and no
secret-shaped text survives the coordinator's redaction funnel (evidence is
redacted at attachment time).
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import threading

MAX_EVIDENCE = 6

_local = threading.local()


def attach_evidence(items: list[dict]) -> None:
    """Set the evidence for the job about to run on THIS thread. Each item:
    {source: str, text: str}. Clipped and capped; extra items are dropped."""
    clean = []
    for item in (items or [])[:MAX_EVIDENCE]:
        if not isinstance(item, dict):
            continue
        text = str(item.get("text", "") or "").strip()
        if not text:
            continue
        clean.append({"source": str(item.get("source", "unknown"))[:60],
                      "text": text[:400]})
    _local.evidence = clean


def clear_evidence() -> None:
    _local.evidence = []


def current_evidence() -> list[dict]:
    return list(getattr(_local, "evidence", ()) or [])
