"""
ARGUS - Vault Skill
Writes and reads plain markdown in your local Obsidian vault.
"If it's not in the vault, it didn't happen."
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import os
from datetime import datetime
from config import VAULT_PATH

RAW_DIR = os.path.join(VAULT_PATH, "raw")
WIKI_DIR = os.path.join(VAULT_PATH, "wiki")
OUTPUTS_DIR = os.path.join(VAULT_PATH, "outputs")


def ensure_vault():
    for d in (RAW_DIR, WIKI_DIR, OUTPUTS_DIR):
        os.makedirs(d, exist_ok=True)


def write_note(title: str, content: str, folder: str = "raw") -> str:
    ensure_vault()
    target_dir = {"raw": RAW_DIR, "wiki": WIKI_DIR, "outputs": OUTPUTS_DIR}.get(folder, RAW_DIR)
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
    safe_title = "".join(c if c.isalnum() or c in " -_" else "" for c in title).strip() or "note"
    filename = f"{stamp}_{safe_title}.md"
    path = os.path.join(target_dir, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# {title}\n\n_{datetime.now().isoformat()}_\n\n{content}\n")
    return f"Saved to vault: {filename}"


def _all_notes() -> list:
    ensure_vault()
    files = []
    for d in (RAW_DIR, WIKI_DIR, OUTPUTS_DIR):
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if f.endswith(".md"):
                files.append(os.path.join(d, f))
    files.sort(key=os.path.getmtime, reverse=True)
    return files


def search(query: str, limit: int = 4) -> str:
    """Finds notes containing the query.

    Without this the vault was effectively write-only: read_recent() shows the
    newest few and nothing else, so anything saved more than a handful of notes
    ago could be stored but never retrieved by voice. Matches on filename as
    well as body, since the title is in the filename and is often what gets
    remembered.

    Returns a spoken-friendly summary with a snippet around the hit rather than
    whole documents -- these answers get read aloud.
    """
    q = (query or "").strip().lower()
    if not q:
        return "What should I search your notes for?"

    hits = []
    for path in _all_notes():
        try:
            with open(path, "r", encoding="utf-8") as f:
                body = f.read()
        except OSError:
            continue
        name = os.path.basename(path)
        where = body.lower().find(q)
        if where == -1 and q not in name.lower():
            continue
        # Snippet centred on the match, trimmed to whole-ish words.
        if where != -1:
            start = max(0, where - 60)
            snippet = body[start:where + 120].replace("\n", " ").strip()
        else:
            snippet = body.replace("\n", " ").strip()[:160]
        snippet = " ".join(snippet.split())
        hits.append((name, snippet))
        if len(hits) >= limit:
            break

    if not hits:
        return f"I couldn't find any notes mentioning {query}."

    lines = [f"{n.split('_', 2)[-1].replace('.md', '')}: {s}" for n, s in hits]
    head = f"Found {len(hits)} note{'s' if len(hits) > 1 else ''} about {query}. "
    return head + " | ".join(lines)


def read_recent(n: int = 5) -> str:
    ensure_vault()
    files = []
    for d in (RAW_DIR, WIKI_DIR, OUTPUTS_DIR):
        for f in os.listdir(d):
            if f.endswith(".md"):
                files.append(os.path.join(d, f))
    files.sort(key=os.path.getmtime, reverse=True)
    out = []
    for path in files[:n]:
        with open(path, "r", encoding="utf-8") as f:
            out.append(f.read())
    return "\n\n---\n\n".join(out) if out else "Vault is empty."
