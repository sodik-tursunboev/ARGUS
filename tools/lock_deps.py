"""Regenerate requirements.lock from what is currently installed.

Deliberate act, run after testing an upgrade -- never automatically. A lock
file that regenerates itself on every run records whatever arrived, which is
the opposite of pinning.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import importlib.metadata as md
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REQ = os.path.join(ROOT, "requirements.txt")
LOCK = os.path.join(ROOT, "requirements.lock")

HEADER = open(LOCK, encoding="utf-8").read().split("\n\n")[0] + "\n\n" \
    if os.path.exists(LOCK) else "# ARGUS - pinned direct dependencies.\n\n"


def direct_requirements():
    names = []
    for line in open(REQ, encoding="utf-8-sig"):
        line = line.split("#")[0].strip()
        if not line:
            continue
        name = re.split(r"[\[<>=!;]", line)[0].strip()
        if name:
            names.append(name)
    return names


missing, lines = [], []
for name in direct_requirements():
    try:
        lines.append(f"{name}=={md.version(name)}")
    except md.PackageNotFoundError:
        missing.append(name)

with open(LOCK, "w", encoding="utf-8") as f:
    f.write(HEADER)
    f.write("\n".join(lines) + "\n")

print(f"wrote {len(lines)} pins to {LOCK}")
for line in lines:
    print(f"   {line}")
if missing:
    print(f"\nNOT INSTALLED ({len(missing)}): {', '.join(missing)}")
    sys.exit(1)
