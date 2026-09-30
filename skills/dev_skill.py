"""
ARGUS - Developer Skill

Read-only git reporting for the ARGUS repository itself: what's changed,
recent history, current branch. Voice-useful while actively developing
ARGUS, which is exactly the situation this project's own notes call out.

DELIBERATELY NOT HERE, and why: a Terminal/PowerShell/CMD Controller, a
Python Runner, a generic Build/Test Runner, a Package Manager. Every one of
those is a way to make an arbitrary interpreter or shell execute something,
which is precisely the capability router.py's own planner header calls
"the single most dangerous component" and pc_skill.dictate calls "the
closest thing ARGUS has to shell execution" -- said about synthesising
KEYSTROKES, a narrower capability than this would be. execpolicy.run()'s
allowlist is enforced by EXECUTABLE NAME only, not by subcommand or
argument content, so allowlisting "python.exe" or "powershell.exe" here
would hand every future skill (and any bug in one) the ability to run
anything, not just what THIS module intends. git is different in kind: every
function below builds its OWN fixed, read-only argv -- status/log/diff/
branch -- never a subcommand or path the caller supplies free-form, so
"git" being allowlisted grants exactly these five read operations and
nothing else, the same shape execpolicy already uses for netsh in
network_skill.

Git ITSELF needs allowlisting in execpolicy.ALLOWED_EXECUTABLES for any of
this to run; see that module's own comment on why that's a deliberate,
reviewed addition.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os

import execpolicy
import paths

# The repo this module reports on: wherever THIS file lives, two levels up
# covers running from skills/ in source form; paths.app_dir() covers a
# frozen build, where git itself won't be present anyway (no .git ships in
# the frozen payload) and every function below says so rather than hanging.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _git(*args) -> tuple:
    """(output, error). Runs git INSIDE REPO_ROOT with a FIXED argv this
    module built -- never one assembled from caller-supplied text beyond a
    bounded integer or a name already validated below."""
    try:
        result = execpolicy.run(["git", "-C", REPO_ROOT, *args], timeout=10.0)
    except execpolicy.ExecDenied as e:
        return "", str(e)
    except Exception as e:
        return "", f"{type(e).__name__}: {e}"
    out = (result.stdout or "").strip()
    err = (result.stderr or "").strip()
    if result.returncode != 0:
        return "", err or f"git exited with status {result.returncode}"
    return out, ""


def _is_repo() -> bool:
    return os.path.isdir(os.path.join(REPO_ROOT, ".git"))


def git_status() -> str:
    if not _is_repo():
        return "This isn't a git repository."
    out, err = _git("status", "--short", "--branch")
    if err:
        return f"I couldn't check git status: {err}"
    lines = out.splitlines()
    branch_line = lines[0] if lines else ""
    changes = lines[1:]
    branch = branch_line.replace("## ", "")
    if not changes:
        return f"On {branch}, nothing changed."
    staged = sum(1 for l in changes if l[:1] not in (" ", "?"))
    unstaged = sum(1 for l in changes if l[1:2] not in (" ",))
    untracked = sum(1 for l in changes if l.startswith("??"))
    bits = []
    if staged:
        bits.append(f"{staged} staged")
    if unstaged:
        bits.append(f"{unstaged} modified")
    if untracked:
        bits.append(f"{untracked} untracked")
    return f"On {branch}: " + ", ".join(bits) + f" ({len(changes)} files total)."


def git_log(count=10) -> str:
    if not _is_repo():
        return "This isn't a git repository."
    try:
        n = max(1, min(int(count), 50))
    except (TypeError, ValueError):
        n = 10
    out, err = _git("log", f"-{n}", "--oneline", "--no-decorate")
    if err:
        return f"I couldn't read the log: {err}"
    if not out:
        return "No commits yet."
    return out.replace("\n", "; ")


def git_diff(staged: bool = False) -> str:
    if not _is_repo():
        return "This isn't a git repository."
    args = ["diff", "--stat"]
    if staged:
        args.insert(1, "--cached")
    out, err = _git(*args)
    if err:
        return f"I couldn't diff that: {err}"
    if not out:
        return "Staged changes: none." if staged else "Unstaged changes: none."
    return out.replace("\n", "; ")


def git_branch() -> str:
    if not _is_repo():
        return "This isn't a git repository."
    current, err = _git("rev-parse", "--abbrev-ref", "HEAD")
    if err:
        return f"I couldn't check the branch: {err}"
    out, err2 = _git("branch", "--format=%(refname:short)")
    others = [b for b in out.splitlines() if b and b != current]
    if not others:
        return f"On {current}, the only branch."
    return f"On {current}. Other branches: " + ", ".join(others[:10]) + "."
