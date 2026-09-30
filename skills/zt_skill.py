"""
ARGUS - Zero-trust and hardware-factor skill.

One surface for the two new security capabilities:

  zt/status     -- the current session-trust score, its band, and the
                   signals currently moving it. Read-only.
  zt/describe   -- the same, as one spoken sentence.
  zt/on|off     -- the scoring layer itself. L2-gated: switching the
                   dynamic layer off is a security decision, so it needs
                   fresh authentication. OFF still leaves every static
                   rule intact -- see zt.py on why that switch exists.
  zt/enroll_hw  -- create/refresh the TPM-resident signing key and enrol
                   its public half. L2, plus the command PIN via the
                   staged-confirm path hw_enroll uses internally... which
                   it does not: enrolment is gated HERE at L2 by the
                   static table, and hwkey.enroll() additionally refuses
                   a machine without a provider. Deliberately NOT L0 --
                   enrolling a factor is a security-relevant write.
  zt/forget_hw  -- remove the enrolment record. The TPM key itself is
                   left in place and inert without its record.
  zt/check_hw   -- run one verification round against the TPM right now.

The skill holds NO logic of its own worth attacking: every answer comes
from zt.py or hwkey.py, both of which fail closed.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

try:
    from config import ZT_ENABLED
except ImportError:
    ZT_ENABLED = True


def status() -> str:
    import zt
    return zt.describe()


def set_enabled(on: bool) -> str:
    """Flip the scoring layer through the settings machinery, so the override
    file, the config module and the runtime state cannot disagree."""
    import settings
    import zt
    applied, rejected = settings.update({"ZT_ENABLED": bool(on)})
    if not applied:
        return f"Couldn't change that ({rejected[0][1] if rejected else 'unknown error'})."
    return (f"Zero-trust scoring {'on' if zt.enabled() else 'off'}. "
            f"{'Every static rule still applies.' if not zt.enabled() else ''}").strip()


def hw_status() -> str:
    import hwkey
    s = hwkey.status()
    if not s["available"]:
        return f"No usable TPM provider here ({s['note']})."
    if not s["enrolled"]:
        return ("A TPM is present but the hardware factor isn't enrolled. "
                "Say \"enroll the hardware factor\" to set it up.")
    return f"Hardware factor enrolled and ready ({s['note']})."


def hw_enroll() -> str:
    import hwkey
    return hwkey.enroll()


def hw_forget() -> str:
    import hwkey
    return ("Hardware factor enrolment removed. The TPM key itself stays "
            "in place but is inert without its record."
            if hwkey.forget() else "There was no hardware enrolment to remove.")


def hw_check() -> str:
    import hwkey
    s = hwkey.status()
    if not (s["available"] and s["enrolled"]):
        return hw_status()
    return ("The TPM signed a fresh challenge and it verified -- the "
            "hardware factor is working."
            if hwkey.verify() else
            "The TPM check FAILED -- either the key was replaced or this "
            "isn't the enrolled machine. Do not trust this session until "
            "you've re-enrolled or investigated.")
