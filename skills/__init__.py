# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

# The capability registry is the single source of truth for every
# (skill, action) pair; exposing it on the package makes "from skills import
# registry" the one import both the router's consistency test and any future
# command-registry surface need.
from skills import registry
