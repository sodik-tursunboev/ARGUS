"""
ARGUS - Hardware-backed user verification: the L5 factor.

WHAT WAS MISSING. auth.py has always carried an L5 tier -- "hardware-backed
only" -- that nothing could satisfy. No factor was wired to it, so
authorize() refused L5 outright rather than silently downgrading it. The
refusal was the correct behaviour for a tier with no backend; the cost was
that the top of the graduation was dead weight, and the README had to list
"hardware-backed" among the things ARGUS is not.

WHAT THIS IS. Windows' own user-verification prompt --
Windows.Security.Credentials.UI.UserConsentVerifier -- which asks the OS to
confirm the ENROLLED user's presence at the moment of the call. The private
half of a Hello credential never leaves the TPM/VBS, nothing here sees or
stores a biometric, and the result is OS-attested: a photograph of you, a
recording of you, a PIN someone watched you type, or another process running
as you cannot produce the S_OK. Windows enrolls one user and requires THAT
user to complete a genuine verification gesture.

THE HONEST LIMITS, which are also the reason nothing here silently
downgrades.

  * Machine support. UserConsentVerifier needs Windows 10 1607+ and an
    enrolled Hello credential (face, fingerprint or PIN). Where either is
    missing, availability() reports it, is_enrolled() is False, and
    auth.authorize() keeps failing closed at L5 -- the same refusal as
    before this module existed, now for the right reason.
  * An optional projection. The Python projection for the security
    namespace is a separate wheel (winsdk, or the winrt.* projection
    packages). It is NOT in requirements.txt: unlike OCR or Bluetooth it
    gates nothing the assistant cannot do without it, and a hard
    dependency would break every install that never uses L5. When the
    package is absent, availability() names it exactly as email_skill
    names absent credentials -- "not configured", never an error.
  * Not a replacement for the PIN. Hello gates L5 operations on machines
    that have it. It does not relax L2-L4, and it never joins
    AUTH_REQUIRED_FACTORS as a substitute for a knowledge factor --
    PRESENCE_ONLY_FACTORS exists precisely because a biometric alone
    proves "someone is here", which is the one thing this module does
    prove better than anything else in ARGUS.

DESIGN RULES (inherited from the modules this sits beside).

  1. Fail closed. Any error -- no projection, no window, user cancels,
     API missing -- is (False, reason) or an exception naming the
     category, never True.
  2. No secrets in logs. Nothing here writes a log line; auth.py records
     categories only, via security.security_event.
  3. The prompt is modal and user-facing. check_availability() and
     verify() invoke it deliberately; nothing polls or backgrounds it.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import asyncio
import os

# The exact pip line that supplies the projection on this machine. Shown to
# the user by doctor.py and the security summary rather than hidden in a
# README: a missing dependency that names its own install command is a
# five-minute fix, one that hides is a permanent blind spot.
#
# TWO FAMILIES, SAME API. The WinRT projections ship under two import roots:
# 'winsdk' (the older winsdk packages) and 'winrt' (the winrt-* packages).
# ARGUS already standardises on winrt-* (vision_skill's OCR, system_ext's
# Bluetooth), so this module accepts either -- it imports whichever is
# present rather than insisting on one, because the security decision must
# not depend on which wheel family a machine happened to install. The install
# hint names the family this project actually uses.
PROJECTION_PACKAGE = "winrt-Windows.Security.Credentials.UI"
INSTALL_HINT = ("pip install winrt-Windows.Security.Credentials.UI"
                "  (or: pip install winsdk)")


def _load_projection():
    """Import the UserConsentVerifier surface from either projection family.

    The projection exposes CLASSES (UserConsentVerifier with static methods,
    plus the two result enums), not a camelCase-free submodule. Returns
    (UserConsentVerifier class, UserConsentVerifierAvailability enum,
    UserConsentVerificationResult enum) or raises ImportError naming what is
    missing. Tried in the order this project actually ships.
    """
    errors = []
    try:
        from winrt.windows.security.credentials.ui import (
            UserConsentVerifier as ucv,
            UserConsentVerifierAvailability as avail,
            UserConsentVerificationResult as result,
        )
        return ucv, avail, result
    except ImportError as e:
        errors.append(f"winrt: {e}")
    try:
        from winsdk.windows.security.credentials.ui import (
            UserConsentVerifier as ucv,
            UserConsentVerifierAvailability as avail,
            UserConsentVerificationResult as result,
        )
        return ucv, avail, result
    except ImportError as e:
        errors.append(f"winsdk: {e}")
    raise ImportError("; ".join(errors))

# Config toggle -- default OFF, matching the docstring above: enabling a
# biometric-gated tier should be a deliberate act, not something a software
# update does to you. Reads ARGUS_HELLO from the environment at import time
# (== "1" to opt in; unset or anything else stays OFF) -- this was previously
# documented but not implemented, so the only working opt-in was hand-editing
# this constant. Until the env var is set, authorize() keeps refusing L5,
# exactly as it always has.
HELLO_ENABLED = os.environ.get("ARGUS_HELLO") == "1"


def availability() -> dict:
    """Can a Hello verification be ATTEMPTED on this machine?

    Static and cheap -- import probes only, never a prompt, never a camera.
    Safe to call from the HUD's polling thread. Never raises.
    """
    info = {
        "kind": "windows_hello",
        "platform_supported": os.name == "nt",
        "projection_installed": False,
        "verified_available": None,   # None = not probed (that needs a prompt API)
        "usable": False,
        "reason": "",
    }
    if os.name != "nt":
        info["reason"] = "not windows"
        return info
    try:
        _load_projection()
        info["projection_installed"] = True
    except ImportError as e:
        info["reason"] = (f"{PROJECTION_PACKAGE} projection not installed "
                           f"({INSTALL_HINT}; detail: {e})")
        return info
    info["usable"] = True
    return info


def hello_available() -> bool:
    """True only when the OS verification surface can genuinely be used."""
    return bool(availability()["usable"])


def check_availability() -> dict:
    """One step further than availability(): asks the OS whether an enrolled
    credential exists, which is the difference between 'the API is here' and
    'a Hello credential is enrolled'. This is the call that answers whether
    L5 is genuinely satisfiable on this machine.

    Returns the availability dict plus 'verified_available' (bool) and, on
    failure, the device-confirmation status. Never raises; user-consent
    verification AVAILABILITY is a status read, not a prompt.
    """
    info = availability()
    if not info["usable"]:
        return info
    try:
        ucv, avail_enum, _result = _load_projection()

        async def _go():
            status = await ucv.check_availability_async()
            return status

        status = asyncio.run(_go())
        info["verified_available"] = (status == avail_enum.AVAILABLE)
        info["availability_status"] = str(status)
        if status != avail_enum.AVAILABLE:
            info["reason"] = f"Hello not usable on this device ({status})"
        return info
    except Exception as e:
        info["verified_available"] = False
        info["reason"] = f"availability check failed: {type(e).__name__}"
        return info


def verify_user(message: str = "Confirm this action in ARGUS") -> tuple:
    """The hardware factor itself. Returns (ok, reason).

    ok is True ONLY after the OS-attested verification of the enrolled
    user. Every other outcome is (False, reason); every reason is a
    category that is safe to log -- never a biometric, never a secret.
    This RAISES HelloUnavailable only through the exception path callers
    catch deliberately; the normal contract is the tuple.
    """
    if os.name != "nt":
        return False, "hardware factor: not windows"
    info = availability()
    if not info["usable"]:
        return False, f"hardware factor unavailable: {info['reason']}"
    if not HELLO_ENABLED:
        return False, "hardware factor disabled in config"
    try:
        ucv, _avail_enum, result_enum = _load_projection()

        async def _go():
            return await ucv.request_verification_async(message)

        result = asyncio.run(_go())
        if result == result_enum.VERIFIED:
            return True, "verified by windows hello"
        if result == result_enum.DEVICE_NOT_PRESENT:
            return False, "no verifier device present"
        if result == result_enum.NOT_CONFIGURED:
            return False, "no hello credential enrolled on this machine"
        if result == result_enum.CANCELED:
            return False, "verification canceled by the user"
        # VERIFYING / anything else: not a success, name the status.
        return False, f"verification not completed ({result})"
    except Exception as e:      # fail closed, name the category
        return False, f"hardware factor error: {type(e).__name__}"


class HelloUnavailable(Exception):
    """Raised when the hardware factor is requested but cannot be attempted.

    Mirrors voiceauth.SpeakerUnavailable: a caller that forgets the
    distinction between 'said no' and 'cannot ask' gets a loud failure
    rather than silently treating every speaker/user as unverified.
    """


def verify_or_raise(message: str = "Confirm this action in ARGUS") -> None:
    """Strict form for callers that must not proceed on any ambiguity.

    Raises HelloUnavailable when the factor cannot be attempted at all;
    returns normally only after a genuine OS-attested verification.
    """
    ok, reason = verify_user(message)
    if not ok:
        raise HelloUnavailable(reason)
