"""
ARGUS - Control Skill
Volume, brightness, and clipboard control. Pure system I/O, no allowlist needed —
none of these actions can install, delete, or execute anything.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import pyperclip
import screen_brightness_control as sbc
from ctypes import cast, POINTER
from comtypes import CLSCTX_ALL
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume


def _get_volume_interface():
    """The system volume endpoint, across pycaw versions.

    EVERY volume and mute command was broken. pycaw's GetSpeakers() used to
    return the raw IMMDevice, and this called .Activate() on it directly. In
    current pycaw (20251023 here) it returns an AudioDevice WRAPPER with no
    .Activate at all, so every call raised

        AttributeError: 'AudioDevice' object has no attribute 'Activate'

    and the user heard "That didn't work" for volume up, volume down, mute,
    unmute and set-volume alike. Voice commands reached this path directly.

    Three paths are tried in order of preference rather than pinning to one
    version: a library that changed its API once can change it again, and a
    voice assistant should not lose its volume control to a dependency bump.
    """
    devices = AudioUtilities.GetSpeakers()

    # 1. Current pycaw: a ready-made endpoint on the wrapper.
    endpoint = getattr(devices, "EndpointVolume", None)
    if endpoint is not None:
        return endpoint

    # 2. Older pycaw: the device itself was the COM object.
    if hasattr(devices, "Activate"):
        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        return cast(interface, POINTER(IAudioEndpointVolume))

    # 3. The wrapper's underlying IMMDevice, if the public property is gone.
    inner = getattr(devices, "_dev", None)
    if inner is not None:
        interface = inner.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        return cast(interface, POINTER(IAudioEndpointVolume))

    raise RuntimeError(
        "this pycaw version exposes no usable audio endpoint "
        f"(GetSpeakers returned {type(devices).__name__})")


def volume_set(percent: int) -> str:
    percent = max(0, min(100, percent))
    vol = _get_volume_interface()
    vol.SetMasterVolumeLevelScalar(percent / 100.0, None)
    return f"Volume set to {percent}%."


def volume_adjust(delta: int) -> str:
    vol = _get_volume_interface()
    current = vol.GetMasterVolumeLevelScalar()
    new_level = max(0.0, min(1.0, current + delta / 100.0))
    vol.SetMasterVolumeLevelScalar(new_level, None)
    return f"Volume {'up' if delta > 0 else 'down'} to {int(new_level * 100)}%."


def mute(state: bool) -> str:
    vol = _get_volume_interface()
    vol.SetMute(1 if state else 0, None)
    return "Muted." if state else "Unmuted."


def _get_mic_interface():
    """Same three-path fallback as _get_volume_interface(), pointed at the
    default CAPTURE device instead of the default render one -- see that
    function's own docstring for why pycaw's API shape isn't trusted to
    stay the same across versions."""
    devices = AudioUtilities.GetMicrophone()

    endpoint = getattr(devices, "EndpointVolume", None)
    if endpoint is not None:
        return endpoint
    if hasattr(devices, "Activate"):
        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        return cast(interface, POINTER(IAudioEndpointVolume))
    inner = getattr(devices, "_dev", None)
    if inner is not None:
        interface = inner.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        return cast(interface, POINTER(IAudioEndpointVolume))
    raise RuntimeError(
        "this pycaw version exposes no usable microphone endpoint "
        f"(GetMicrophone returned {type(devices).__name__})")


def mic_mute(state: bool) -> str:
    """Mutes the DEVICE, at the OS mixer -- different from privacy_skill's
    listening pause, which stops ARGUS's own processing of what the
    microphone hears without touching the device other apps also use."""
    mic = _get_mic_interface()
    mic.SetMute(1 if state else 0, None)
    return "Microphone muted." if state else "Microphone unmuted."


def mic_status() -> str:
    mic = _get_mic_interface()
    muted = bool(mic.GetMute())
    level = int(mic.GetMasterVolumeLevelScalar() * 100)
    return f"Microphone is {'muted' if muted else 'unmuted'}, level {level}%."


def brightness_set(percent: int) -> str:
    percent = max(0, min(100, percent))
    sbc.set_brightness(percent)
    return f"Brightness set to {percent}%."


def clipboard_read() -> str:
    """Reads the clipboard, with secrets stripped.

    This is a useful command right up until your clipboard holds a password
    you just copied from a password manager. Previously that text was spoken
    aloud, written into conversation history, and rendered in the HUD. Now it
    passes through redaction first."""
    import security

    text = pyperclip.paste()
    if not text:
        return "Clipboard is empty."

    safe = security.redact(text)
    if safe != text:
        security.audit("clipboard", "read", "contained secrets — redacted")

    # Clipboard-hijack check (threatmon P5). Runs on THIS existing, hardened read
    # -- no new clipboard access point is created -- and is fully isolated: a
    # detector failure must never break the user's "read my clipboard". Passed
    # the raw text (before redaction) so a wallet address is not masked away
    # before the swap check can see it; threatmon masks it in what it records.
    try:
        from threatmon import clipboard as _clip
        _clip.observe(text)
    except Exception:
        pass

    preview = safe if len(safe) < 200 else safe[:200] + "…"
    return f"Clipboard has: {preview}"


def clipboard_write(text: str) -> str:
    pyperclip.copy(text)
    return "Copied to clipboard."
