"""
ARGUS - Anti-tampering.

THE FINDING THIS EXISTS FOR. Before this module, "Argus, delete auth" resolved
to C:\\ARGUS\\argus-os\\auth.py and staged it for the Recycle Bin. files_skill's
SEARCH_ROOTS included C:\\ARGUS, auth.py sits one level down, and MAX_DEPTH is
4. The only thing between a voice command and a deleted authorization layer was
the PIN gate -- and a user who thinks they are deleting a stray download types
the PIN quite happily. Every security-critical file was reachable the same way:
execpolicy.py, sandbox.py, security.py, secrets_store.py, config.py.

So the requirement "the AI must not be able to modify the security layer that
controls the AI" was not a hardening exercise here. It was a live hole.

TWO SEPARATE MECHANISMS, BECAUSE THEY ANSWER DIFFERENT QUESTIONS

  is_protected()  -- PREVENTION, and it is the one that matters. A hard refusal
                     inside the file skills, so ARGUS has no code path that
                     writes, deletes, or ShellExecutes its own security layer.
                     This holds against ARGUS regardless of what the model was
                     persuaded to want, because the check is not in the model.

  verify()        -- DETECTION. A signed manifest of SHA-256 digests. This
                     catches an editor, another process, a bad update, or disk
                     corruption. It cannot stop any of them.

WHAT THIS DOES NOT CLAIM.

Detection here is tamper-EVIDENCE, not a root of trust. The verifier, the
manifest and the signing key all live in the same trust domain as the thing
being verified: an attacker already running as this Windows user can rewrite
integrity.py, re-seal the manifest through this very module, and the next boot
reports clean. Nothing purely file-based can escape that, and claiming
otherwise would be the dangerous kind of security theatre.

What it does buy, honestly:
  - ARGUS cannot tamper with itself                     (prevention, solid)
  - accidental edits and bad updates are caught         (detection, solid)
  - an attacker must specifically know about and target ARGUS's integrity
    system rather than just editing a .py file          (raises the bar)
  - an attacker WITHOUT interactive access as this user cannot forge the
    signature, because the HMAC key is sealed with DPAPI (detection, solid)

For prevention against a local attacker rather than against ARGUS, the files
must be unwritable by the account ARGUS runs as. That is an OS ACL decision,
not a Python one -- see harden_acls() and tools/harden_acls.ps1.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import base64
import fnmatch
import hashlib
import hmac
import json
import os
import re
import shutil
import sys
import time

import paths

# The manifest and the known-good snapshot live OUTSIDE the source tree. If
# they sat next to the files they describe, the same "delete auth" search that
# found auth.py would find them, and a tamperer editing a file in the tree
# would have the manifest right there to edit too.
# One manifest PER BUILD MODE. A source checkout and an installed .exe on the
# same machine describe different artefacts, and sharing a filename meant
# sealing either one silently invalidated the other -- so whichever was sealed
# last verified and the other reported no baseline. Separate files let both
# work, which matters because you develop from source and run the exe.
MANIFEST_PATH = paths.writable(
    "integrity-frozen.json" if paths.is_frozen() else "integrity.json")
SNAPSHOT_DIR = paths.writable(
    "known_good_frozen" if paths.is_frozen() else "known_good")

_HMAC_KEY_NAME = "ARGUS_INTEGRITY_KEY"

def _root() -> str:
    """What "the installation" means, which differs frozen and unfrozen.

    Running from source, it is the directory holding the .py files. Frozen, it
    is the directory holding ARGUS.exe -- the .py files do not exist there at
    all, because PyInstaller compiles them into the bundle.

    That distinction was missing and it BROKE THE PACKAGED APP. The manifest
    was sealed against the source tree; the frozen build then looked for
    auth.py, execpolicy.py and 25 others next to the executable, found none of
    them, classified 27 CRITICAL files as missing, and aborted the boot. From
    a terminal you saw the message; double-clicked, with no console, the app
    simply never opened.
    """
    if paths.is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


ROOT = _root()


# -- what is protected --------------------------------------------------
# Tiered because the response differs. CRITICAL missing or modified is a
# refuse-to-start condition: these files ARE the security layer, and running
# with a modified auth.py is worse than not running. CORE and SKILLS are
# reported and audited but do not block startup, because a corrupted skill
# should not make the machine's assistant unusable.
CRITICAL = [
    "auth.py", "execpolicy.py", "sandbox.py", "security.py",
    "secrets_store.py", "integrity.py", "boot.py", "config.py",
    "voiceauth.py", "netpolicy.py", "plugins.py",
    # faceauth.py supplies the "face" entry in auth.FACTORS. An unprotected
    # authentication factor is one edited `return True` away from being no
    # factor at all -- exactly the "the AI must not be able to modify the layer
    # that controls it" rule -- so it sits at the same tier as voiceauth.py.
    "faceauth.py",
    # 1.2.0: the zero-trust session layer. zt.py can REFUSE any authorize()
    # call above L1 and grades every high/critical detection into the session
    # score -- a module with that much say must be as untouchable as the gate
    # it feeds.
    "zt.py",
    # hwkey.py supplies the "hardware" entry in auth.FACTORS, so it sits at
    # the same tier as faceauth.py for the identical reason: an unprotected
    # authentication factor is one edited `return True` away from being no
    # factor at all.
    "hwkey.py",
    # 1.3.0: hwauth.py supplies the "hello" factor and the L5 Windows Hello
    # gate inside authorize(). It is the module an attacker edits to turn a
    # biometric-gated tier into a rubber stamp, so it protects itself at the
    # same tier as every other factor backend.
    "hwauth.py",
    # settings.py decides which settings are LOCKED -- it is the file that
    # refuses to let AUTH_ENABLED or CLOUD_ENABLED be changed at runtime.
    # Editing it to move a field out of the locked class would hand the
    # settings panel the power to switch authentication off, so it belongs
    # with the rest of the security layer rather than with the features.
    "settings.py",
    # Sets the PIN and the cloud keys. A modified copy could weaken the hash
    # it writes or copy what it is given somewhere else.
    "manage_secrets.py",

    # state machine. grants.py mints/redeems the action-hash-bound tokens the
    # dispatcher re-verifies before every confirmed or planned action; a
    # weakened copy would accept substituted targets or replayed approvals.
    # security_state.py owns NORMAL/SAFE_MODE/LOCKDOWN -- a weakened copy
    # would let a lockdown be lifted without the manifest-proven recovery.
    # Same rule as every factor backend: the security layer protects itself.
    "grants.py",
    "security_state.py",
]

CORE = [
    "router.py", "brain.py", "main.py", "listener.py", "intent.py",
    "ipc.py", "ollama_client.py", "groq_client.py", "gemini_client.py",
    "argus.py",
    "stt_worker.py", "tts_worker.py", "tts.py", "textmatch.py", "paths.py",
    "anscache.py",
    # User-facing announcements and presence-driven task resumption both
    # influence what ARGUS says or executes without a fresh typed command.
    # They are runtime control modules, not optional data, so edits must be
    # visible to the integrity monitor in source and frozen builds.
    "announce.py", "presencewatch.py",
    # The preview harness serves the HUD and exposes the operator channel on
    # loopback; it speaks for the app in a browser, so it is runtime control
    # code that must be classified, not an unclassified loose file.
    "preview_server.py",
    # CORE and not CRITICAL, and the line between them is the point.
    # faceauth.py is CRITICAL because it supplies the "face" entry in
    # auth.FACTORS -- edit it and you have edited an authentication factor.
    # gesturewatch.py supplies NO factor and cannot: a wave carries no
    # identity, so every action it can trigger is one that is harmless when a
    # stranger does it (see its GESTURE_ACTIONS table). It opens the camera
    # and can mute the microphone, which is why it is protected at all.
    "gesturewatch.py",
    # Not on the runtime security path, but all three shape what the user
    # believes or installs: doctor.py is what the fatal dialog sends people to
    # when something has already gone wrong, install_startup.py writes the
    # autostart entry, and build_exe.py produces the shipped artefact.
    "doctor.py", "install_startup.py", "build_exe.py",
]

# DELIBERATELY NOT PROTECTED: config_secrets.py.
#
# It holds an actual API key, and the user is expected to change it -- so
# hashing it would turn a legitimate key rotation into a CRITICAL "modified"
# finding, and CRITICAL aborts the boot. Refusing to start because the owner
# pasted a new Groq key is a worse failure than not noticing an edit to a
# file whose only content is a credential that secrets_store already prefers
# to read from DPAPI-sealed storage instead. It is also optional and often
# absent entirely.
UNPROTECTED_BY_DESIGN = ["config_secrets.py"]

# Shipped data that is not code but is still logic. index.html is 130KB of
# behaviour and is where the About and Security panels are drawn -- an edited
# HUD can report every check green while doing something else, and main.py
# substitutes a live session token into it before serving. It was covered in
# the frozen build and not in the source one, which is the wrong way round for
# the mode the author develops in.
DATA = []

SKILL_GLOB = "skills/*.py"

TIER_CRITICAL = "critical"
TIER_CORE = "core"
TIER_SKILL = "skill"


def protected_files() -> dict[str, str]:
    """Relative path -> tier, for every file under integrity control.

    Frozen, the list is completely different, because the artefacts are
    different: there are no .py files beside the executable, so hashing them
    is meaningless. What exists and matters is the executable itself and the
    bundle it unpacks -- modifying either is the tamper worth catching.

    THE PAYLOAD IS NOT BESIDE THE EXE. PyInstaller 6 onedir puts everything
    into an _internal directory and leaves only the launcher stub outside it,
    so scanning the exe's own folder found exactly one file and the shipped
    build reported "not sealed" with a single-entry manifest -- anti-tampering
    that was, in the artefact users actually run, doing nothing. sys._MEIPASS
    points at that payload directory in both onedir and onefile, so it is what
    gets walked here rather than a hardcoded name.
    """
    if paths.is_frozen():
        return frozen_files(ROOT, getattr(sys, "_MEIPASS", ""),
                            os.path.basename(sys.executable))

    return _source_files()


def frozen_files(root: str, payload: str, exe_name: str) -> dict[str, str]:
    """The frozen file set, for an install described by explicit paths.

    Taking root/payload as arguments rather than reading sys.executable and
    sys._MEIPASS is what lets build_exe.py seal the manifest for the build it
    has just produced. Otherwise the only way to establish a frozen baseline
    would be to run the app and let it seal whatever it found on first launch
    -- which trusts the install at exactly the moment there is no reason to.
    """
    out = {exe_name: TIER_CRITICAL}

    def _rel(full):
        return os.path.relpath(full, root).replace("\\", "/")

    # The interpreter and the stdlib archive. Swapping either is as good
    # as editing the source.
    for fn in sorted(os.listdir(payload)) if os.path.isdir(payload) else []:
        low = fn.lower()
        if ((low.startswith("python") and low.endswith(".dll"))
                or low.endswith(".pkg") or low == "base_library.zip"):
            out[_rel(os.path.join(payload, fn))] = TIER_CRITICAL

    # Everything shipped as DATA rather than as compiled code: intent.py
    # (read as source by /skills), the skills, and the HUD. These are
    # plain text inside the install folder -- editable in Notepad, with no
    # rebuild required -- which makes them the easiest tamper of all, and
    # the HUD in particular is what the user reads the security posture
    # off. The compiled application modules are inside the exe and are
    # covered by hashing the exe itself.
    for rel, tier in (("intent.py", TIER_CRITICAL),):
        full = os.path.join(payload, rel.replace("/", os.sep))
        if os.path.isfile(full):
            out[_rel(full)] = tier
    skills_dir = os.path.join(payload, "skills")
    if os.path.isdir(skills_dir):
        for fn in sorted(os.listdir(skills_dir)):
            if fnmatch.fnmatch(fn, "*.py"):
                out[_rel(os.path.join(skills_dir, fn))] = TIER_SKILL

    # HUD V2 is shipped as data under _internal/hud-v2/dist.  It needs the
    # same frozen baseline coverage as V1; otherwise a package can contain a
    # V2 runtime but verification can never attest its entry or assets.
    # Match source discovery's bounded, fail-closed generated-tree rules.
    v2_dir = os.path.join(payload, "hud-v2", "dist")
    if os.path.isdir(v2_dir):
        v2_files = []
        for dirpath, dirnames, filenames in os.walk(v2_dir):
            dirnames.sort()
            for fn in sorted(filenames):
                if fn.startswith(".") or fn.endswith(".map"):
                    continue
                full = os.path.join(dirpath, fn)
                if os.path.isfile(full) and not os.path.islink(full):
                    v2_files.append(full)
        if len(v2_files) > 2000:
            print(f"[integrity] packaged hud-v2/dist has {len(v2_files)} files, "
                  "over the 2000-file discovery bound -- none added to the "
                  "manifest; investigate before trusting this build")
        else:
            for full in v2_files:
                out[_rel(full)] = TIER_CORE

    # NOT COVERED, deliberately: the several hundred megabytes of third-party
    # DLLs and model files under _internal. Hashing them would add real time to
    # every boot for a much weaker signal, and a tamper that swaps a vendored
    # DLL has already required write access to the install folder -- which the
    # ACL hardening, not this manifest, is the answer to. Saying so here beats
    # implying coverage that is absent.
    return out


def _source_files() -> dict[str, str]:
    out = {}
    for rel in CRITICAL:
        out[rel] = TIER_CRITICAL
    for rel in CORE:
        out[rel] = TIER_CORE
    for rel in DATA:
        if os.path.isfile(os.path.join(ROOT, rel.replace("/", os.sep))):
            out[rel] = TIER_CORE
    skills_dir = os.path.join(ROOT, "skills")
    if os.path.isdir(skills_dir):
        for fn in sorted(os.listdir(skills_dir)):
            if fnmatch.fnmatch(fn, "*.py"):
                out[f"skills/{fn}"] = TIER_SKILL
    # The active-defence detection suite. CORE, not SKILL: these are first-party
    # security modules that make raw Win32/ctypes calls -- the opposite of a
    # sandboxed plugin -- and tampering with the code that watches for tampering
    # must be a reported violation, not a quietly-accepted plugin edit. Frozen,
    # they compile into the exe and are covered by hashing it, exactly like the
    # other CORE .py modules; they are only loose files in source mode.
    tm_dir = os.path.join(ROOT, "threatmon")
    if os.path.isdir(tm_dir):
        for fn in sorted(os.listdir(tm_dir)):
            if fnmatch.fnmatch(fn, "*.py"):
                out[f"threatmon/{fn}"] = TIER_CORE

    # The agent kernel. CORE, matching threatmon/: another first-party
    # subsystem (kernel.py, goals.py, task_state.py, working_memory.py,
    # capability_catalog.py, budgets.py, observer.py, replanner.py,
    # context.py, verifiers*.py) that plans and executes actions rather than
    # watching for tampering -- but the same rule applies either way: a
    # first-party module that decides what ARGUS does next must be a
    # reported violation when it changes, not an unmonitored blind spot.
    # Frozen, it compiles into the exe like every other CORE .py module and
    # needs no separate entry there; it is only loose files in source mode.
    agent_dir = os.path.join(ROOT, "agent")
    if os.path.isdir(agent_dir):
        for fn in sorted(os.listdir(agent_dir)):
            if fnmatch.fnmatch(fn, "*.py"):
                out[f"agent/{fn}"] = TIER_CORE

    # The signed HUD V2 production bundle. CORE, matching main.py/argus.py:
    # a modified build is a reported violation, not a silent swap -- the
    # same discipline that protects every other generated/compiled artifact
    # this manifest already tracks. Walked rather than listed like skills/
    # and threatmon/ because Vite's own output layout is nested
    # (dist/, dist/assets/), not flat.
    v2_dir = os.path.join(ROOT, "hud-v2", "dist")
    if os.path.isdir(v2_dir):
        v2_files = []
        for dirpath, dirnames, filenames in os.walk(v2_dir):
            dirnames.sort()
            for fn in sorted(filenames):
                if fn.startswith(".") or fn.endswith(".map"):
                    continue
                full = os.path.join(dirpath, fn)
                if os.path.isfile(full) and not os.path.islink(full):
                    v2_files.append(full)
        # Bounded: dist/ is a small generated build output, not user-controlled
        # storage. Fails CLOSED: over the bound, nothing from dist/ is trusted.
        if len(v2_files) > 2000:
            print(f"[integrity] hud-v2/dist has {len(v2_files)} files, over "
                  f"the 2000-file discovery bound -- none added to the "
                  f"manifest; investigate before trusting this build")
        else:
            for full in v2_files:
                rel = os.path.relpath(full, ROOT).replace(os.sep, "/")
                out[rel] = TIER_CORE
    return out


# -- prevention: ARGUS cannot touch its own security layer --------------
# Deliberately broader than protected_files(). That map is about detecting
# changes to files that exist; THIS is about refusing to operate anywhere
# inside the installation, including the venv (which is how you would swap a
# library out from under the security code) and the writable state directory
# (which holds the manifest, the snapshot and the DPAPI secret store).
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "."}
try:
    import socket as _socket

    _LOCAL_HOSTS.add(_socket.gethostname().lower())
except Exception:      # noqa: BLE001 - a name lookup must never break the check
    pass

# \\?\C:\...  or  \\?\UNC\server\share\...
_EXTENDED = re.compile(r"^\\\\\?\\(UNC\\)?", re.I)
# \\server\C$\rest  -- the administrative share for a whole drive
_ADMIN_SHARE = re.compile(r"^\\\\([^\\]+)\\([A-Za-z])\$(\\.*)?$")


def _canonical_windows(path: str) -> str:
    """Rewrite the Windows path spellings that name the same file differently.

    Found by red-teaming this module, and all three were live bypasses of
    is_protected():

        \\\\?\\C:\\ARGUS\\argus-os\\auth.py            extended-length prefix
        \\\\localhost\\C$\\ARGUS\\argus-os\\auth.py    admin share
        \\\\127.0.0.1\\C$\\ARGUS\\argus-os\\auth.py    admin share via loopback

    Every one names exactly the file the check exists to protect, and every
    one compared unequal to the install root, so the refusal did not fire.
    os.path.realpath does not fold them together -- \\\\localhost\\C$ stays a
    UNC path all the way down -- so they have to be rewritten before the
    comparison rather than after.

    Only LOCAL admin shares are rewritten. \\\\otherbox\\C$\\... genuinely is a
    different machine's file and must not be treated as ours.
    """
    p = str(path or "")
    m = _EXTENDED.match(p)
    if m:
        # \\?\UNC\server\share -> \\server\share ; \\?\C:\x -> C:\x
        p = ("\\\\" + p[m.end():]) if m.group(1) else p[m.end():]

    m = _ADMIN_SHARE.match(p)
    if m and m.group(1).lower() in _LOCAL_HOSTS:
        p = f"{m.group(2)}:{m.group(3) or os.sep}"
    return p


def _norm(path: str) -> str:
    path = _canonical_windows(path)
    try:
        return os.path.normcase(os.path.realpath(os.path.abspath(path)))
    except (OSError, ValueError):
        return os.path.normcase(os.path.abspath(path))


_INSTALL_ROOT = _norm(ROOT)
_STATE_ROOT = _norm(paths.writable())


def _vault_root() -> str:
    """The vault, resolved lazily.

    Imported inside the function rather than at module scope: execpolicy and
    files_skill import integrity, and config imports enough of the app that a
    module-level import here risks a cycle for a value only needed at call
    time.

    The vault matters because it holds audit.log. Without this, "delete the
    audit log" was a working voice command -- ARGUS erasing its own security
    record on request is the one deletion that must never succeed, and it is
    exactly what an attacker asks for after doing something else. profile.md
    lives here too, but profile_skill writes it directly rather than through
    the file skills, so protecting the directory costs nothing.
    """
    try:
        import config
        return _norm(config.VAULT_PATH)
    except Exception:
        return ""


def is_protected(path: str) -> bool:
    """True if PATH is part of ARGUS itself and must never be modified by it.

    Uses realpath so a symlink or junction pointing into the install does not
    walk around the check, and compares with os.path.normcase because Windows
    paths are case-insensitive -- "C:\\argus\\ARGUS-OS\\Auth.PY" is the same
    file as the one in the manifest.
    """
    if not path:
        return False
    p = _norm(path)
    for root in (_INSTALL_ROOT, _STATE_ROOT, _vault_root()):
        if root and (p == root or p.startswith(root + os.sep)):
            return True
    return False


def refusal(path: str) -> str:
    """What ARGUS says when it declines. Names the reason rather than
    pretending the file does not exist -- a silent "not found" for a file the
    user can see would be its own bug report."""
    name = os.path.basename(path) or path
    return (f"{name} is part of my own installation, so I won't touch it. "
            f"If you really need to change it, do it yourself in an editor.")


# -- the signing key ----------------------------------------------------
def _get_key() -> bytes:
    """HMAC key, sealed with DPAPI under the current Windows user.

    Created on first use. Kept in the same encrypted store as the API key, so
    an attacker who copies integrity.json off the machine cannot forge a
    manifest for it, and one who copies the store cannot decrypt it as another
    user.
    """
    import secrets as _secrets
    import secrets_store

    existing = secrets_store.get_secret(_HMAC_KEY_NAME, "")
    if existing:
        try:
            return base64.b64decode(existing)
        except ValueError:
            pass
    key = _secrets.token_bytes(32)
    try:
        secrets_store.put_secret(_HMAC_KEY_NAME, base64.b64encode(key).decode())
    except OSError:
        # No DPAPI (non-Windows, or a locked-down profile). Fall back to an
        # unsigned manifest rather than refusing to run: unsigned detection of
        # accidental change is still worth having, and verify() reports the
        # downgrade rather than hiding it.
        return b""
    return key


def _sign(payload: str, key: bytes) -> str:
    if not key:
        return ""
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


# -- hashing ------------------------------------------------------------
def file_digest(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical(entries: dict) -> str:
    """Stable serialisation for signing. sort_keys and fixed separators so the
    same content always produces the same bytes -- otherwise a re-serialised
    manifest fails its own signature for no reason."""
    return json.dumps(entries, sort_keys=True, separators=(",", ":"))


# -- sealing ------------------------------------------------------------
def seal(reason: str = "manual") -> dict:
    """Record the current state as known-good, and snapshot it for rollback.

    Sealing is a privileged act: it is how a legitimate change is accepted, so
    anything that can seal can also launder a tamper. There is deliberately NO
    skill, router entry or HTTP endpoint that reaches this function -- it is
    reachable from the command line only. See tools/argus_integrity.py.
    """
    entries = {}
    for rel, tier in protected_files().items():
        full = os.path.join(ROOT, rel)
        if not os.path.exists(full):
            continue
        entries[rel] = {"sha256": file_digest(full), "tier": tier,
                        "size": os.path.getsize(full)}

    key = _get_key()
    payload = _canonical(entries)
    manifest = {
        "version": 2,
        "sealed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "reason": reason,
        "root": ROOT,
        # Which BUILD this describes. A manifest sealed from source lists .py
        # files that do not exist in a frozen install, and applying it there
        # reported 27 missing CRITICAL files and aborted the boot. The two
        # modes describe different artefacts and their manifests are not
        # interchangeable, so each records which one it is.
        "frozen": paths.is_frozen(),
        "entries": entries,
        "signature": _sign(payload, key),
        "signed": bool(key),
    }
    os.makedirs(os.path.dirname(MANIFEST_PATH), exist_ok=True)
    tmp = MANIFEST_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
    os.replace(tmp, MANIFEST_PATH)

    _snapshot(entries)
    return manifest


def seal_frozen(dist_root: str, reason: str = "build") -> dict:
    """Seal the manifest for a BUILT app, from outside that app.

    Called by build_exe.py the moment PyInstaller finishes, so the baseline is
    whatever the build just produced. The alternative -- letting the packaged
    app seal itself on first launch -- establishes the baseline at the one
    moment there is least reason to trust the install, and would quietly
    record a tamper as known-good if the folder had been touched in between.

    The manifest is written to the same per-user location the frozen app reads
    from, so a build on this machine is immediately verifiable. Distributing
    the folder to another machine does NOT carry the baseline with it; that
    install reports "not sealed" until it is sealed there, which is honest --
    a manifest shipped inside the artefact it verifies is a manifest an
    attacker rewrites alongside it.
    """
    payload = os.path.join(dist_root, "_internal")
    exe = next((f for f in os.listdir(dist_root)
                if f.lower().endswith(".exe")), "ARGUS.exe")

    entries = {}
    for rel, tier in frozen_files(dist_root, payload, exe).items():
        full = os.path.join(dist_root, rel.replace("/", os.sep))
        if not os.path.exists(full):
            continue
        entries[rel] = {"sha256": file_digest(full), "tier": tier,
                        "size": os.path.getsize(full)}

    key = _get_key()
    manifest = {
        "version": 2,
        "sealed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "reason": reason,
        "root": dist_root,
        "frozen": True,
        "entries": entries,
        "signature": _sign(_canonical(entries), key),
        "signed": bool(key),
    }
    target = paths.writable("integrity-frozen.json")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    tmp = target + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
    os.replace(tmp, target)
    return manifest


def _snapshot(entries: dict):
    """Known-good copies, for rollback(). Flat filenames with the separator
    escaped, so skills/foo.py and skills_foo.py cannot collide."""
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    for rel in entries:
        src = os.path.join(ROOT, rel)
        dst = os.path.join(SNAPSHOT_DIR, rel.replace("/", "__"))
        try:
            shutil.copy2(src, dst)
        except OSError:
            pass


# -- verification -------------------------------------------------------
class Result:
    def __init__(self):
        self.modified: list[tuple[str, str]] = []   # (rel, tier)
        self.missing: list[tuple[str, str]] = []
        self.added: list[str] = []                  # unmanifested .py in tree
        self.sealed = False
        self.signature_ok = False
        self.signed = False
        self.error = ""

    @property
    def critical_problems(self) -> list[str]:
        bad = [r for r, t in self.modified + self.missing if t == TIER_CRITICAL]
        if self.sealed and self.signed and not self.signature_ok:
            bad.append("manifest signature")
        return bad

    @property
    def ok(self) -> bool:
        return (self.sealed and not self.modified and not self.missing
                and not self.added and (self.signature_ok or not self.signed))

    def summary(self) -> str:
        if not self.sealed:
            return "not sealed - no baseline to compare against"
        if self.error:
            return f"unreadable - {self.error}"
        if self.ok:
            n = len(protected_files())
            return f"{n} files verified" + ("" if self.signed else " (UNSIGNED)")
        parts = []
        if self.signed and not self.signature_ok:
            parts.append("MANIFEST SIGNATURE INVALID")
        if self.modified:
            parts.append(f"{len(self.modified)} modified: "
                         + ", ".join(r for r, _ in self.modified[:4]))
        if self.missing:
            parts.append(f"{len(self.missing)} missing: "
                         + ", ".join(r for r, _ in self.missing[:4]))
        if self.added:
            parts.append(f"{len(self.added)} unexpected: " + ", ".join(self.added[:4]))
        return "; ".join(parts)


_ONE_CACHE: dict = {}       # rel -> (mtime_ns, size, ok, detail)

# -- continuous verification --------------------------------------------
# The boot check answers "was this install intact when it started", which is
# not the same question as "is it intact now". ARGUS is designed to run for
# days: a file replaced an hour after launch was, until this existed, never
# looked at again. The watcher re-runs verify() on a slow timer and reports
# the FIRST time a file changes, once per file, so a single edit does not
# produce an entry every interval.
WATCH_INTERVAL = 300            # seconds; a slow timer, not a hot loop
_watch_thread = None
_watch_stop = None              # threading.Event, created with the thread
_watch_seen: set = set()


def _watch_loop(on_change, stop):
    # One shared Event, so stop_watch() can actually end the loop. The first
    # version constructed a fresh Event() to wait on each iteration, which
    # could never be set by anyone -- the wait was a plain sleep and the
    # "return on set" branch was unreachable.
    while not stop.wait(WATCH_INTERVAL):
        try:
            res = verify()
        except Exception:
            continue
        if not res.sealed:
            continue
        for rel, tier in list(res.modified) + [(r, "missing") for r in res.missing]:
            if rel in _watch_seen:
                continue
            _watch_seen.add(rel)
            try:
                on_change(rel, tier)
            except Exception:
                pass


def start_watch(on_change=None):
    """Begin re-verifying in the background. Idempotent.

    Reports rather than kills the process. A CRITICAL file changing while
    running is already a refuse-to-start condition on the NEXT launch, and
    tearing down a live assistant mid-sentence -- possibly over a file the
    owner edited on purpose -- is a worse answer than an audited alert that
    the next boot then enforces.
    """
    global _watch_thread, _watch_stop
    import threading

    if _watch_thread and _watch_thread.is_alive():
        return _watch_thread
    _watch_stop = threading.Event()

    if on_change is None:
        def on_change(rel, tier):
            try:
                import security
                security.security_event(
                    security.SECURITY_POLICY_CHANGED, component="integrity",
                    reason="changed_while_running", status="failed")
            except Exception:
                pass
            print(f"[integrity] {rel} changed while running ({tier})")

    _watch_thread = threading.Thread(target=_watch_loop,
                                     args=(on_change, _watch_stop),
                                     daemon=True, name="integrity-watch")
    _watch_thread.start()
    return _watch_thread


def stop_watch():
    """End the watcher. Mainly so tests do not leave one running."""
    if _watch_stop is not None:
        _watch_stop.set()


_MANIFEST_CACHE: dict = {}      # {"stamp": (mtime_ns, size), "data": dict}


def _cached_manifest():
    """The parsed manifest, re-read only when the file changes.

    verify_one() opened and JSON-parsed the whole manifest on every call, and
    plugins.verify_permissions() calls it once per skill -- so a single
    /security-report request parsed the same file 27 times. Keyed on the
    file's own (mtime, size) so a re-seal is still picked up immediately.
    """
    try:
        st = os.stat(MANIFEST_PATH)
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        _MANIFEST_CACHE.clear()
        return None
    if _MANIFEST_CACHE.get("stamp") == stamp:
        return _MANIFEST_CACHE.get("data")
    try:
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        _MANIFEST_CACHE.clear()
        return None
    _MANIFEST_CACHE.update(stamp=stamp, data=data)
    return data


def manifest_key(path: str) -> str:
    """The key a given file has in THIS build mode's manifest.

    Source and frozen manifests describe the same logical file under different
    relative paths: skills/apps_skill.py from source, _internal/skills/
    apps_skill.py once packaged, because PyInstaller puts the payload in its
    own directory beside the exe. Callers that built the key by hand got it
    right in source and wrong in the exe -- plugins.verify_permissions()
    looked up "skills/x.py", found nothing in the frozen manifest, reported
    every skill as modified, and aborted the boot of a completely intact
    build. Deriving the key from the real path removes the chance to guess.
    """
    return os.path.relpath(os.path.abspath(path), ROOT).replace("\\", "/")


def verify_one(rel: str) -> tuple[bool, str]:
    """Check ONE manifested file. Returns (ok, human-readable detail).

    verify() hashes 59 files; that is right at boot and far too much work on a
    request that serves a single page. This checks the one file, and caches the
    answer against the file's own (mtime, size) so a page served repeatedly
    costs a stat() rather than a re-hash -- while a file swapped underneath a
    running process still changes those and is re-checked.

    An UNSEALED install returns ok. This exists to catch modification against a
    known baseline; with no baseline there is nothing to compare to, and
    refusing to serve the interface because the manifest has not been created
    yet would brick a fresh install rather than protect it.
    """
    rel = rel.replace("\\", "/")
    full = os.path.join(ROOT, rel.replace("/", os.sep))
    try:
        st = os.stat(full)
    except OSError as e:
        return False, f"{rel} is missing ({e.__class__.__name__})"

    # The key covers the MANIFEST as well as the file. Keyed on the file alone,
    # a re-seal -- which changes the manifest and not the file -- left the old
    # verdict cached, so legitimately re-sealing a modified HUD did not make
    # the server start serving it again. It reported "does not match the
    # manifest" against a manifest it had just been written into, which reads
    # as the integrity system being broken rather than stale.
    try:
        mst = os.stat(MANIFEST_PATH)
        mstamp = (mst.st_mtime_ns, mst.st_size)
    except OSError:
        mstamp = None
    stamp = (st.st_mtime_ns, st.st_size, mstamp)

    hit = _ONE_CACHE.get(rel)
    if hit and hit[0] == stamp:
        return hit[1], hit[2]

    manifest = _cached_manifest()
    if manifest is None:
        return True, "no baseline"
    if bool(manifest.get("frozen", False)) != paths.is_frozen():
        return True, "no baseline for this build mode"

    meta = manifest.get("entries", {}).get(rel)
    if not meta:
        # Not manifested at all. Say so rather than passing silently -- for a
        # caller like the HUD, "this file is not covered" is the answer that
        # matters, and it is exactly the state the frozen build was in.
        return False, f"{rel} is not in the manifest"

    actual = file_digest(full)
    ok = hmac.compare_digest(actual, meta.get("sha256", ""))
    detail = ("verified" if ok else
              f"{rel} does not match the manifest "
              f"(expected {meta.get('sha256', '')[:12]}, got {actual[:12]})")
    _ONE_CACHE[rel] = (stamp, ok, detail)
    return ok, detail


def verify() -> Result:
    res = Result()
    try:
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError) as e:
        res.error = e.__class__.__name__
        return res

    # A manifest from the other build mode describes artefacts that are not
    # supposed to exist here. Treated as NO BASELINE rather than as a
    # violation: reporting it as tampering is how the packaged app came to
    # refuse to start at all. Version 1 manifests predate the field and are
    # assumed to be source builds, which is what they always were.
    if bool(manifest.get("frozen", False)) != paths.is_frozen():
        res.error = ("baseline was sealed for a "
                     f"{'frozen' if manifest.get('frozen') else 'source'} build; "
                     f"this is a {'frozen' if paths.is_frozen() else 'source'} one")
        return res

    res.sealed = True
    entries = manifest.get("entries", {})
    res.signed = bool(manifest.get("signed"))

    if res.signed:
        key = _get_key()
        expected = _sign(_canonical(entries), key)
        # compare_digest: a signature check that leaks position through timing
        # is a signature check an attacker can grind against.
        res.signature_ok = bool(expected) and hmac.compare_digest(
            expected, manifest.get("signature", ""))

    for rel, meta in entries.items():
        full = os.path.join(ROOT, rel)
        tier = meta.get("tier", TIER_CORE)
        if not os.path.exists(full):
            res.missing.append((rel, tier))
            continue
        try:
            if file_digest(full) != meta.get("sha256"):
                res.modified.append((rel, tier))
        except OSError:
            res.missing.append((rel, tier))

    # A file that appeared since sealing matters as much as one that changed:
    # dropping a new module into skills/ is how you add a capability without
    # touching anything the manifest covers.
    for rel in protected_files():
        if rel not in entries and os.path.exists(os.path.join(ROOT, rel)):
            res.added.append(rel)

    return res


# -- rollback -----------------------------------------------------------
def rollback(only: list[str] | None = None, confirm_all: bool = False) -> list[str]:
    """Restore modified files from the known-good snapshot.

    Returns what was restored. Like seal(), reachable from the command line
    only -- an automatic rollback triggered by ARGUS would be a way to undo a
    security fix the user had just applied.

    A BARE rollback() OVERWRITES EVERY MODIFIED FILE, which on a machine with
    uncommitted work means destroying it. That happened here: a test called
    rollback() to undo its own one-file tamper, restored four unrelated files
    that had just been edited, and the next build packaged the reverted code --
    so a fixed bug reappeared with nothing in the diff to explain it.

    So the destructive form now has to be asked for. Pass `only` to name the
    files, or confirm_all=True to mean the whole set deliberately. Calling it
    with neither raises rather than guessing, because the guess is unrecoverable.
    """
    if only is None and not confirm_all:
        raise ValueError(
            "rollback() with no arguments would overwrite every modified file "
            "and discard uncommitted work. Pass only=[...] for specific files, "
            "or confirm_all=True if that is genuinely what you want.")

    restored = []
    res = verify()
    targets = only if only is not None else [r for r, _ in res.modified + res.missing]
    for rel in targets:
        src = os.path.join(SNAPSHOT_DIR, rel.replace("/", "__"))
        dst = os.path.join(ROOT, rel)
        if not os.path.exists(src):
            continue
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            restored.append(rel)
        except OSError:
            pass
    return restored


# -- application signature (Authenticode) -------------------------------
def verify_signature(path: str = "") -> tuple[bool, str]:
    """Authenticode status of the running executable, via WinVerifyTrust.

    Only meaningful frozen: as a script the "executable" is python.exe, whose
    signature says something about Python and nothing about ARGUS. Reported
    honestly rather than presented as an ARGUS guarantee.

    THIS USED TO SHELL OUT, and it was wrong twice over. The command was
    built as a string:

        f"(Get-AuthenticodeSignature '{target}').Status"

    so a path containing a single quote closed the literal and the rest ran
    as PowerShell -- a command-injection hole inside the module whose whole
    job is detecting tampering. It also meant the one component that must not
    depend on anything spawned a shell interpreter to answer a question the
    Win32 API answers directly.

    WinVerifyTrust takes the path as a wide string in a struct. There is no
    parser between this code and the API, so there is nothing to inject into.
    """
    import ctypes
    import ctypes.wintypes
    import sys

    target = path or sys.executable
    if os.name != "nt":
        return False, "not Windows"
    if not paths.is_frozen() and not path:
        return False, (f"running as a script - {os.path.basename(target)} is "
                       f"the interpreter, not ARGUS")
    if not os.path.exists(target):
        return False, "file not found"

    class _GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                    ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_byte * 8)]

    class _FILE_INFO(ctypes.Structure):
        _fields_ = [("cbStruct", ctypes.wintypes.DWORD),
                    ("pcwszFilePath", ctypes.wintypes.LPCWSTR),
                    ("hFile", ctypes.wintypes.HANDLE),
                    ("pgKnownSubject", ctypes.c_void_p)]

    class _WINTRUST_DATA(ctypes.Structure):
        _fields_ = [("cbStruct", ctypes.wintypes.DWORD),
                    ("pPolicyCallbackData", ctypes.c_void_p),
                    ("pSIPClientData", ctypes.c_void_p),
                    ("dwUIChoice", ctypes.wintypes.DWORD),
                    ("fdwRevocationChecks", ctypes.wintypes.DWORD),
                    ("dwUnionChoice", ctypes.wintypes.DWORD),
                    ("pFile", ctypes.POINTER(_FILE_INFO)),
                    ("dwStateAction", ctypes.wintypes.DWORD),
                    ("hWVTStateData", ctypes.wintypes.HANDLE),
                    ("pwszURLReference", ctypes.wintypes.LPCWSTR),
                    ("dwProvFlags", ctypes.wintypes.DWORD),
                    ("dwUIContext", ctypes.wintypes.DWORD),
                    ("pSignatureSettings", ctypes.c_void_p)]

    # WINTRUST_ACTION_GENERIC_VERIFY_V2
    action = _GUID(0xAAC56B, 0xCD44, 0x11D0,
                   (ctypes.c_byte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

    finfo = _FILE_INFO(ctypes.sizeof(_FILE_INFO), target, None, None)
    data = _WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
    data.dwUIChoice = 2               # WTD_UI_NONE
    data.fdwRevocationChecks = 0      # WTD_REVOKE_NONE
    data.dwUnionChoice = 1            # WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(finfo)
    data.dwStateAction = 1            # WTD_STATEACTION_VERIFY
    data.dwProvFlags = 0x00000010     # WTD_SAFER_FLAG

    try:
        wintrust = ctypes.WinDLL("wintrust")
        rc = wintrust.WinVerifyTrust(None, ctypes.byref(action),
                                     ctypes.byref(data))
        data.dwStateAction = 2        # WTD_STATEACTION_CLOSE - free the state
        wintrust.WinVerifyTrust(None, ctypes.byref(action), ctypes.byref(data))
    except OSError as e:
        return False, f"check failed: {e.__class__.__name__}"

    STATUS = {
        0x00000000: "Valid",
        0x800B0100: "NoSignature",
        0x800B0101: "Expired",
        0x800B0109: "UntrustedRoot",
        0x800B010C: "Revoked",
        0x800B0111: "DistrustedPublisher",
        0x80092010: "RevocationOffline",
    }
    code = rc & 0xFFFFFFFF
    return code == 0, STATUS.get(code, f"error 0x{code:08X}")


# -- OS-level prevention ------------------------------------------------
def install_dir_writable() -> tuple[bool, str]:
    """ARGUS-SEC-005: is the INSTALL DIRECTORY writable by this account?

    A frozen build under a user-writable path (C:\\ARGUS, a Downloads folder,
    a USB stick) lets a malicious local process plant a DLL beside the exe --
    Windows' DLL search order loads it -- or replace a bundled binary, gaining
    code execution as the ARGUS process at the next launch and a persistence
    foothold. The manifest hashes the exe and the interpreter, so REPLACING
    one is caught at boot; a NEW DLL dropped for search-order hijacking is not
    in the manifest and would not be. Only an ACL that denies write actually
    prevents the plant -- tools/harden_acls.ps1 -App.

    Returned as posture rather than fixed in code because the fix is an ACL on
    the install location, which needs elevation and is the operator's call.
    Reported writable so the risk is visible instead of silent.
    """
    root = ROOT
    probe = os.path.join(root, ".argus_write_probe")
    try:
        with open(probe, "w") as fh:
            fh.write("")
        os.remove(probe)
        return True, f"install directory {root} is writable (DLL-plant risk)"
    except OSError:
        return False, "install directory is read-only to this account"


def acls_hardened() -> tuple[bool, str]:
    """Whether the install is writable by the account ARGUS runs as.

    This is the only check here that speaks to prevention against a LOCAL
    ATTACKER rather than against ARGUS. Everything else in this module is
    evidence after the fact; an ACL that denies write is the thing that
    actually stops the edit.

    EVERY critical file is probed, not just one. Probing auth.py alone meant
    a run that hardened some files and failed on others -- or a file list
    that had fallen behind the security layer, which is exactly what happened
    -- reported the install as fully hardened. Partial coverage is now
    reported as partial, with the names, because "8 of 13" is the number that
    tells you something is wrong.
    """
    if paths.is_frozen():
        targets = [sys.executable]
    else:
        targets = [os.path.join(ROOT, rel) for rel in CRITICAL]
    targets = [p for p in targets if os.path.exists(p)]
    if not targets:
        return False, "no critical files found to check"

    writable, undetermined = [], []
    for path in targets:
        try:
            # Opening for append and writing nothing does not modify the file
            # (no bytes, and no truncation), but it does take the same write
            # access an attacker would need -- so the ACL answers here.
            with open(path, "ab"):
                pass
            writable.append(os.path.basename(path))
        except PermissionError:
            pass
        except OSError as e:
            undetermined.append(f"{os.path.basename(path)}:{e.__class__.__name__}")

    total = len(targets)
    protected = total - len(writable) - len(undetermined)
    if protected == total:
        return True, f"all {total} security files are read-only to this account"
    if protected == 0:
        return False, (f"security files are WRITABLE by this account "
                       f"(0 of {total} protected) - run tools/harden_acls.ps1 "
                       f"from an elevated PowerShell")
    detail = ", ".join(sorted(writable)[:4])
    return False, (f"PARTIALLY hardened: {protected} of {total} protected; "
                   f"still writable: {detail}"
                   f"{' ...' if len(writable) > 4 else ''}")


def describe() -> str:
    res = verify()
    hardened, acl_note = acls_hardened()
    return (f"integrity: {res.summary()}; "
            f"protected paths: install + state dir; "
            f"acls: {acl_note}")
