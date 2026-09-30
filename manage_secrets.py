"""
ARGUS - Move secrets out of plaintext.

    python manage_secrets.py status
    python manage_secrets.py set-groq-key
    python manage_secrets.py set-pin

The values are typed in here, never passed as command-line arguments: an
argument is visible in the process list and lands in shell history, which
would defeat the point.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import secrets_store


def status():
    import config

    print("\nARGUS secret status\n" + "=" * 46)

    try:
        from config_secrets import GROQ_API_KEY as plain_key
    except ImportError:
        plain_key = ""
    src = secrets_store.secret_source("GROQ_API_KEY", plain_key)
    ok = bool(config.GROQ_API_KEY)
    print(f"  GROQ_API_KEY : {'set' if ok else 'NOT SET':<8} from {src}")

    try:
        from config_secrets import GEMINI_API_KEY as _plain_gem
    except ImportError:
        _plain_gem = ""
    gsrc = secrets_store.secret_source("GEMINI_API_KEY", _plain_gem)
    gok = bool(getattr(config, "GEMINI_API_KEY", ""))
    print(f"  GEMINI_API_KEY: {'set' if gok else 'NOT SET':<8} from {gsrc}")
    if not gok:
        print("                 -> optional second cloud tier, used when Groq")
        print("                    is rate limited. Set it with:")
        print("                    python manage_secrets.py set-gemini-key")
    if src == "PLAINTEXT in config":
        print("                 -> run: python manage_secrets.py set-groq-key")

    hashed = secrets_store.pin_is_hashed(config.COMMAND_PIN)
    print(f"  COMMAND_PIN  : {'hashed' if hashed else 'PLAINTEXT':<8} in config.py")
    if not hashed:
        print("                 -> run: python manage_secrets.py set-pin")

    print(f"\n  encrypted store: {secrets_store.STORE_PATH}")
    print(f"  DPAPI available: {secrets_store.dpapi_available()}\n")


def set_groq_key():
    key = getpass.getpass("Paste the Groq API key (input hidden): ").strip()
    if not key:
        print("Nothing entered; leaving things as they are.")
        return 1
    # A WARNING, not a refusal. The Gemini equivalent of this check was a hard
    # reject on a prefix and it turned away a real, working key -- provider
    # key formats change, and a hardcoded list of the ones that existed when
    # the code was written will eventually be wrong here too. Flag the likely
    # mistake (pasting the wrong provider's key) and let the user decide.
    if not key.startswith("gsk_"):
        print("Note: Groq keys have started 'gsk_' historically, and this one "
              "does not.")
        print("If you pasted a different provider's key, stop now (ctrl+c). "
              "Otherwise this will be saved as-is.")
        if input("Save it anyway? [y/N] ").strip().lower() != "y":
            print("Not saved.")
            return 1
    where = secrets_store.put_secret("GROQ_API_KEY", key)
    print(f"\nEncrypted under your Windows account and written to:\n  {where}")
    print("\nNow blank the plaintext copy so it isn't the one being used:")
    print("  config_secrets.py  ->  GROQ_API_KEY = \"\"")
    print("Then check with: python manage_secrets.py status")
    return 0


def _verify_gemini_key(key: str) -> tuple:
    """(works, detail). Asks the API whether the key is valid.

    Uses ListModels rather than a generation call: it is cheap, spends no
    token quota, and confirms both that the key authenticates AND that the
    configured model name exists -- which is the OTHER way this tier fails
    silently. A retired model id returns 404 at runtime, collapses into
    GeminiUnavailable, and looks exactly like the tier never helping.
    """
    import requests

    import config

    try:
        resp = requests.get(
            "https://generativelanguage.googleapis.com/v1beta/models",
            headers={"x-goog-api-key": key},      # header, never the URL
            timeout=10,
        )
    except requests.exceptions.RequestException as e:
        return False, f"network error ({e.__class__.__name__})"

    if resp.status_code in (401, 403):
        return False, "authentication_failed"
    if resp.status_code == 429:
        return False, "rate_limited (the key is probably fine)"
    if resp.status_code != 200:
        return False, f"http {resp.status_code}"

    try:
        names = [m.get("name", "").split("/")[-1]
                 for m in resp.json().get("models", [])]
    except ValueError:
        return False, "malformed response"

    wanted = config.GEMINI_MODEL
    if wanted in names:
        return True, f"{len(names)} models available, including {wanted}"

    flash = [n for n in names if "flash" in n and "thinking" not in n]
    hint = f"; try one of: {', '.join(sorted(flash)[:4])}" if flash else ""
    return True, (f"key valid, but GEMINI_MODEL={wanted!r} is NOT in this "
                  f"account's {len(names)} models{hint}")


def set_gemini_key():
    key = getpass.getpass("Paste the Gemini API key (input hidden): ").strip()
    if not key:
        print("Nothing entered; leaving things as they are.")
        return 1

    # NO PREFIX CHECK. The first version rejected anything not starting with
    # "AIza" and refused a real, working Gemini key that starts with "AQ" --
    # Google issues keys under more than one prefix, and a hardcoded list of
    # the ones that existed when this was written is a guess that goes stale.
    #
    # The question worth asking is not "does this look like a key" but "does
    # this key work", so that is what gets asked. A live call is the only
    # check that cannot be wrong about the format.
    if len(key) < 16 or any(c.isspace() for c in key):
        print("That doesn't look like an API key (too short, or contains "
              "spaces). Not saved.")
        return 1

    print("\nChecking the key against the Gemini API...")
    ok, detail = _verify_gemini_key(key)
    if ok:
        print(f"  the key works ({detail})")
    else:
        print(f"  the key did NOT work: {detail}")
        if detail == "authentication_failed":
            print("\nNot saved -- an invalid key fails silently at runtime "
                  "(it collapses into GeminiUnavailable and falls through to "
                  "the local model), so it is better to reject it here.")
            return 1
        # Network trouble is not the key's fault. Save it and say so.
        print("\nCould not reach the API to confirm. Saving anyway -- re-run "
              "`status` once you are online to verify.")

    where = secrets_store.put_secret("GEMINI_API_KEY", key)
    print(f"\nEncrypted under your Windows account and written to:\n  {where}")
    print("\nGemini is the SECOND cloud tier: it is used when Groq is rate-")
    print("limited, not instead of it. Check with:")
    print("  python manage_secrets.py status")
    return 0


def set_pin():
    pin = getpass.getpass("New command PIN (digits, input hidden): ").strip()
    if not pin.isdigit() or len(pin) < 4:
        print("A PIN must be at least 4 digits. Not saved.")
        return 1
    again = getpass.getpass("Repeat it: ").strip()
    if pin != again:
        print("Those didn't match. Not saved.")
        return 1
    print("\nPut this in config.py, replacing the COMMAND_PIN line:\n")
    print(f'COMMAND_PIN = "{secrets_store.hash_pin(pin)}"\n')
    print("The PIN itself is not recoverable from that, which is the point.")
    return 0


def migrate():
    """Moves the secrets that are ALREADY on this machine into protected form.

    Nothing is typed in and nothing is printed: the values are read from the
    files they already sit in, transformed, and written back. Both halves
    verify BEFORE they destroy the readable copy --
      - the API key is encrypted, read back, and compared, and only then is
        the plaintext blanked;
      - the PIN is hashed and the hash is checked against the original before
        it replaces it.
    A failure at any point leaves the original exactly as it was.
    """
    import re

    import config
    import secrets_store

    root = os.path.dirname(os.path.abspath(__file__))
    changed = []

    # ── API key ──────────────────────────────────────────────────────
    try:
        from config_secrets import GROQ_API_KEY as plain_key
    except ImportError:
        plain_key = ""
    plain_key = (plain_key or "").strip()

    if not plain_key:
        print("  GROQ_API_KEY : nothing in plaintext to move")
    else:
        secrets_store.put_secret("GROQ_API_KEY", plain_key)
        if secrets_store.get_secret("GROQ_API_KEY") != plain_key:
            print("  GROQ_API_KEY : FAILED to read back after encrypting — "
                  "plaintext left untouched")
            return 1
        path = os.path.join(root, "config_secrets.py")
        src = open(path, encoding="utf-8").read()
        blanked = re.sub(r'(?m)^GROQ_API_KEY\s*=\s*.*$', 'GROQ_API_KEY = ""', src)
        if 'GROQ_API_KEY = ""' not in blanked:
            print("  GROQ_API_KEY : could not rewrite config_secrets.py — "
                  "blank it by hand")
            return 1
        open(path, "w", encoding="utf-8").write(blanked)
        changed.append("GROQ_API_KEY -> encrypted store, plaintext blanked")
        print(f"  GROQ_API_KEY : encrypted ({len(plain_key)} chars) and removed "
              f"from config_secrets.py")

    # ── command PIN ──────────────────────────────────────────────────
    pin = (getattr(config, "COMMAND_PIN", "") or "").strip()
    if not pin:
        print("  COMMAND_PIN  : not set")
    elif secrets_store.pin_is_hashed(pin):
        print("  COMMAND_PIN  : already hashed")
    else:
        digest = secrets_store.hash_pin(pin)
        if not secrets_store.verify_pin(pin, digest):
            print("  COMMAND_PIN  : hash failed to verify — left as it was")
            return 1
        path = os.path.join(root, "config.py")
        src = open(path, encoding="utf-8").read()
        new = re.sub(r'(?m)^COMMAND_PIN\s*=\s*.*$',
                     f'COMMAND_PIN = "{digest}"', src)
        if digest not in new:
            print("  COMMAND_PIN  : could not rewrite config.py — set it by hand")
            return 1
        open(path, "w", encoding="utf-8").write(new)
        changed.append("COMMAND_PIN -> salted PBKDF2 hash")
        print("  COMMAND_PIN  : replaced with a salted hash "
              "(the digits are no longer stored anywhere)")

    if changed:
        print("\nDone:")
        for c in changed:
            print(f"  - {c}")
        print("\nRestart ARGUS so it picks up the new values.")
    return 0


def enroll_owner():
    """Binds ARGUS to this Windows account for the os_account factor."""
    import auth
    print(auth.enroll_owner())
    return 0


COMMANDS = {"status": status, "set-groq-key": set_groq_key,
            "set-gemini-key": set_gemini_key,
            "set-pin": set_pin, "migrate": migrate,
            "enroll-owner": enroll_owner}

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    fn = COMMANDS.get(cmd)
    if not fn:
        print(__doc__)
        sys.exit(1)
    sys.exit(fn() or 0)
