"""
ARGUS - Secret storage.

The API key and the command PIN both sat in plaintext in source files. That is
weak for two different reasons, and they need two different fixes:

  GROQ_API_KEY is a bearer credential -- anything that can read the file can
  spend money as you. It should not be readable at rest at all.

  COMMAND_PIN is a verifier -- ARGUS never needs to KNOW it, only to check a
  supplied value against it. Storing it in a form that can be read back is
  gratuitous; a salted hash answers the only question ever asked of it.

WHAT THIS DOES NOT CLAIM. DPAPI encrypts under the logged-in Windows account,
so a process already running as you can still decrypt it -- as can ARGUS
itself, by design. It stops: the key being read out of a file copied off the
machine, committed to git, pasted in a screenshot, or read by another user on
a shared box. It does not stop malware already running as you, and nothing
file-based can. config.py's existing note about the PIN's threat model
("don't let a mishearing or a housemate trigger a shutdown") is the honest
framing for both.

Resolution order for every secret, first hit wins:
  1. environment variable   -- the right answer for CI, containers, and for
                               anyone who does not want a secret on disk
  2. DPAPI-encrypted store  -- %LOCALAPPDATA%\\ARGUS\\secrets.dat
  3. plaintext in config    -- still honoured so an existing install keeps
                               working, but reported by doctor.py so it does
                               not stay that way silently
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import base64
import ctypes
import ctypes.wintypes
import hashlib
import hmac
import json
import os
import secrets as _secrets

import paths

STORE_PATH = os.path.join(
    os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "ARGUS", "secrets.dat")

_PBKDF2_ROUNDS = 200_000


# ── Windows DPAPI ──────────────────────────────────────────────────────
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(data: bytes) -> _Blob:
    buf = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _blob_bytes(blob: _Blob) -> bytes:
    out = ctypes.string_at(blob.pbData, blob.cbData)
    ctypes.windll.kernel32.LocalFree(blob.pbData)
    return out


def dpapi_available() -> bool:
    return os.name == "nt"


def _protect(plaintext: str) -> bytes:
    """CryptProtectData, scoped to the current user."""
    out = _Blob()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(_blob(plaintext.encode("utf-8"))), "ARGUS",
        None, None, None, 0, ctypes.byref(out))
    if not ok:
        raise OSError("CryptProtectData failed")
    return _blob_bytes(out)


def _unprotect(blob: bytes) -> str:
    out = _Blob()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(_blob(blob)), None, None, None, None, 0, ctypes.byref(out))
    if not ok:
        raise OSError("CryptUnprotectData failed")
    return _blob_bytes(out).decode("utf-8")


# ── store ──────────────────────────────────────────────────────────────
def _read_store() -> dict:
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _write_store(data: dict):
    os.makedirs(os.path.dirname(STORE_PATH), exist_ok=True)
    tmp = STORE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, STORE_PATH)


def put_secret(name: str, value: str) -> str:
    """Encrypts VALUE under the current Windows user and stores it.

    Returns where it went, for the caller to report. Refuses rather than
    silently writing plaintext if DPAPI is unavailable -- a secret store that
    quietly stops encrypting is worse than not having one.
    """
    if not dpapi_available():
        raise OSError("DPAPI is Windows-only; use the environment variable instead")
    data = _read_store()
    data[name] = base64.b64encode(_protect(value)).decode("ascii")
    _write_store(data)
    return STORE_PATH


def get_secret(name: str, fallback: str = "") -> str:
    """Environment variable, then the encrypted store, then FALLBACK."""
    env = os.environ.get(name, "").strip()
    if env:
        return env
    blob = _read_store().get(name)
    if blob and dpapi_available():
        try:
            return _unprotect(base64.b64decode(blob)).strip()
        except (OSError, ValueError):
            print(f"[secrets] {name} is in the store but could not be decrypted "
                  f"(different Windows user?) -- falling back")
    return (fallback or "").strip()


def delete_secret(name: str) -> bool:
    """Remove a secret from the encrypted store. True when it was there.

    Biometric and hardware-factor enrolments need a delete path -- keeping a
    voiceprint or a public-key record forever because nobody wrote the
    removal is its own kind of leak. Never raises into the caller.
    """
    try:
        data = _read_store()
        if name not in data:
            return False
        del data[name]
        _write_store(data)
        return True
    except OSError:
        return False


def secret_source(name: str, fallback: str = "") -> str:
    """Where the value actually came from. For doctor.py, so a plaintext
    fallback is visible rather than silently tolerated forever."""
    if os.environ.get(name, "").strip():
        return "environment"
    if _read_store().get(name):
        return "encrypted store"
    if (fallback or "").strip():
        return "PLAINTEXT in config"
    return "not set"


# ── PIN verifier ───────────────────────────────────────────────────────
def hash_pin(pin: str, salt: bytes | None = None) -> str:
    """PBKDF2-SHA256. Stored as algo$rounds$salt$hash so the parameters can
    be raised later without invalidating anything already stored."""
    salt = salt or _secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return "pbkdf2_sha256${}${}${}".format(
        _PBKDF2_ROUNDS, base64.b64encode(salt).decode(),
        base64.b64encode(dk).decode())


def verify_pin(supplied: str, stored: str) -> bool:
    """Constant-time check of SUPPLIED against a hash from hash_pin().

    Accepts a bare plaintext PIN as STORED too, so an install that has not
    migrated still works -- compared with compare_digest either way, so the
    timing behaviour does not differ between the two.
    """
    supplied = str(supplied or "").strip()
    stored = str(stored or "").strip()
    if not supplied or not stored:
        return False
    if not stored.startswith("pbkdf2_sha256$"):
        return hmac.compare_digest(supplied, stored)      # un-migrated
    try:
        _, rounds, salt_b64, hash_b64 = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", supplied.encode("utf-8"),
                                 base64.b64decode(salt_b64), int(rounds))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(base64.b64encode(dk).decode(), hash_b64)


def pin_is_hashed(stored: str) -> bool:
    return str(stored or "").startswith("pbkdf2_sha256$")
