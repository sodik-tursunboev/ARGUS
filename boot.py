"""
ARGUS - Secure boot chain.

    BOOT
     ├─ Verify Argus installation integrity
     ├─ Verify security policy
     ├─ Verify OS/user identity
     ├─ Initialize secure storage
     ├─ Start Argus LOCKED
     ├─ Voice/liveness authentication
     ├─ Second factor if required
     └─ UNLOCK  →  Argus operational

WHY THE SPLIT AT "START LOCKED".

Steps 1-5 are machine checks: they run to completion at startup with nobody
present, and their answer does not depend on a human. Steps 6-8 need someone
to speak, so they cannot be part of a startup function -- ARGUS has to be
listening before it can hear a challenge phrase, and it has to be running to
listen.

So run_boot() performs 1-5 and ends with ARGUS LOCKED and operational-but-
restricted: it will hear you, answer the time, do sums, and refuse everything
that touches the machine. The unlock half is driven by voice through
auth.verify() afterwards. Modelling it any other way means either a console
prompt nobody is there to answer, or an assistant that unlocks itself.

FAIL-CLOSED, WITH ONE DELIBERATE EXCEPTION.

A CRITICAL integrity failure aborts the boot -- running with a modified
auth.py is worse than not running, because the user believes they are
protected. A CORE or SKILL failure is reported and logged but does not abort:
a corrupted weather skill should not make the machine's assistant refuse to
start, and an assistant that bricks itself over a checksum will be uninstalled
long before it ever catches an attacker.

WHAT IS HONESTLY NOT HERE.

"Voice authentication" in this chain means a LIVENESS challenge-response: a
random phrase that must be spoken back within a time window. That defeats a
recording, because the attacker cannot have pre-recorded a phrase chosen a
second ago. It is NOT speaker verification -- ARGUS does not know your voice
from anyone else's, and this file does not pretend otherwise. Real speaker ID
needs an embedding model (speechbrain/resemblyzer) that is not installed and
would not fit the 4GB VRAM budget alongside Whisper and Piper. Step 6 reports
`unavailable` for biometrics rather than quietly scoring a match it cannot
compute.

The "second factor" is the PIN. L5 (hardware-backed) is satisfiable only by a
completed Windows Hello verification -- see hwauth.py -- and even that only
after the user deliberately opts in (HELLO_ENABLED defaults off, and the
projection package is optional). On a machine without it, authorize() refuses
L5 outright rather than downgrading it, exactly as it always has.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import time

import security

# Step outcomes.
OK = "ok"
FAILED = "failed"
UNAVAILABLE = "unavailable"
SKIPPED = "skipped"


class Step:
    def __init__(self, name: str, status: str, detail: str = "", fatal: bool = False):
        self.name = name
        self.status = status
        self.detail = detail
        self.fatal = fatal

    def __repr__(self):
        return f"<{self.name}: {self.status}>"

    def line(self) -> str:
        mark = {OK: "ok", FAILED: "FAIL", UNAVAILABLE: "n/a", SKIPPED: "--"}[self.status]
        return f"  [{mark:>4}] {self.name}" + (f" — {self.detail}" if self.detail else "")


class BootReport:
    def __init__(self):
        self.steps: list[Step] = []
        self.aborted = False
        self.abort_reason = ""
        self.started = time.time()

    def add(self, step: Step) -> Step:
        self.steps.append(step)
        return step

    @property
    def ok(self) -> bool:
        return not self.aborted

    def render(self) -> str:
        out = ["BOOT"]
        out += [s.line() for s in self.steps]
        if self.aborted:
            out.append(f"  ABORTED — {self.abort_reason}")
        else:
            out.append("  ARGUS operational (LOCKED)" if _locked_now()
                       else "  ARGUS operational")
        return "\n".join(out)


def _locked_now() -> bool:
    try:
        import auth
        return not auth.is_unlocked()
    except Exception:
        return True


# ── step 1: installation integrity ─────────────────────────────────────
def verify_installation(report: BootReport) -> Step:
    import integrity

    res = integrity.verify()

    if not res.sealed:
        # Never sealed is not a violation -- it is a first run. Reported so it
        # does not stay unsealed silently forever, but it cannot abort: a
        # fresh install would be unable to start.
        return report.add(Step("Verify Argus installation integrity", UNAVAILABLE,
                               "no baseline yet — run `python tools/argus_integrity.py seal`"))

    critical = res.critical_problems
    if critical:
        security.security_event(security.INTEGRITY_VIOLATION,
                                tier="critical", count=len(critical),
                                file=critical[0], status="failed")

        # machine in LOCKDOWN, not merely a failed boot step -- outstanding
        # grants die, staged plans die, and L2+ actions refuse until the
        # owner recovers. The boot step stays fatal (abort) as before; this
        # additionally defends a run where the abort itself is somehow
        # bypassed -- the state gate remains.
        try:
            import security_state
            security_state.enter_lockdown(
                f"critical integrity failure: {critical[0]}", auto=True)
        except Exception:
            pass
        return report.add(Step("Verify Argus installation integrity", FAILED,
                               res.summary(), fatal=True))

    if res.modified or res.missing or res.added:
        security.security_event(security.INTEGRITY_VIOLATION,
                                tier="core",
                                count=len(res.modified) + len(res.missing) + len(res.added),
                                status="failed")
        return report.add(Step("Verify Argus installation integrity", FAILED,
                               res.summary()))

    security.security_event(security.INTEGRITY_VERIFIED,
                            count=len(integrity.protected_files()),
                            signed=res.signed, status="ok")

    # ARGUS has no dynamic plugin loader -- skills are ordinary static imports,
    # which is why "detect modified plugins" is answered by the same manifest
    # as everything else rather than by a separate plugin subsystem. Recorded
    # as one event with a count instead of one per skill: 25 identical lines
    # every boot would bury the events that matter, and the per-skill detail
    # is already in the manifest for anything that needs it.
    n_skills = sum(1 for t in integrity.protected_files().values()
                   if t == integrity.TIER_SKILL)
    security.security_event(security.PLUGIN_LOADED, count=n_skills,
                            component="skills", status="ok")

    return report.add(Step("Verify Argus installation integrity", OK, res.summary()))


def harden_acls(report: BootReport) -> Step:
    """Put the OS-level write protection on, once, if this build can.

    Runs only when already elevated and only when the ACLs are not already
    hardened, so on every boot after the first it is a no-op. Never fatal:
    failing to harden is a weaker posture, not a reason to refuse to start.
    """
    import sandbox
    try:
        ran, note = sandbox.harden_acls_if_needed()
    except Exception as e:
        return report.add(Step("Harden install ACLs", UNAVAILABLE,
                               f"{type(e).__name__}: {e}"))
    if ran:
        return report.add(Step("Harden install ACLs", OK,
                               f"applied automatically — {note}"))
    if note == "already hardened":
        return report.add(Step("Harden install ACLs", OK, note))
    return report.add(Step("Harden install ACLs", UNAVAILABLE, note))


def verify_skills(report: BootReport) -> Step:
    """Skill allowlist, declared capabilities, and dependency pins.

    Separate from the integrity step because it answers a different question.
    Hashes prove no skill CHANGED; this proves no skill does more than it is
    permitted to -- which also catches a skill that was always over-privileged
    and a brand-new one dropped in before the first seal.
    """
    import plugins

    violations = plugins.verify_permissions()
    if violations:
        for v in violations[:4]:
            security.security_event(security.PRIVILEGE_ESCALATION_ATTEMPT,
                                    component=v.skill, reason=v.kind,
                                    status="failed")
        detail = "; ".join(f"{v.skill}: {v.kind}" for v in violations[:3])
        # Fatal: an undeclared capability means a skill can do something the
        # permission model says it cannot, and the model is the thing every
        # other control here is written against.
        return report.add(Step("Verify skill permissions", FAILED, detail,
                               fatal=True))

    mismatched, missing = plugins.check_dependencies()
    note = (f"{len(plugins.SKILL_PERMISSIONS)} skills allowlisted, "
            f"0 violations")
    if mismatched or missing:
        # Not fatal. A dependency drifting from the lock is worth knowing
        # about, but refusing to start over a patch-level bump would make the
        # assistant unusable after any routine pip install.
        parts = []
        if mismatched:
            parts.append(f"{len(mismatched)} version mismatch(es): "
                         + ", ".join(f"{n} want {w} have {h}"
                                     for n, w, h in mismatched[:2]))
        if missing:
            parts.append(f"{len(missing)} missing: " + ", ".join(missing[:3]))
        security.security_event(security.CONFIG_CHANGED, component="dependencies",
                                reason="lock_drift",
                                count=len(mismatched) + len(missing),
                                status="failed")
        return report.add(Step("Verify skill permissions", FAILED,
                               note + "; " + "; ".join(parts)))

    return report.add(Step("Verify skill permissions", OK,
                           note + ", dependencies match the lock"))


# ── step 2: security policy ────────────────────────────────────────────
# Hashes prove the FILE did not change. This proves the POLICY still means
# what it is supposed to mean -- which is a different question, and the one
# that survives an attacker who edited auth.py and re-sealed the manifest.
POLICY_INVARIANTS = [
    ("power/*", ("power", "shutdown"), 4),
    ("files/delete", ("files", "delete"), 4),
    ("pc/dictate", ("pc", "dictate"), 3),
    ("control/clipboard_write", ("control", "clipboard_write"), 3),
]


def verify_policy(report: BootReport) -> Step:
    import auth
    import config

    problems = []

    if auth.DEFAULT_LEVEL < auth.L2_REAUTH:
        problems.append(f"unknown actions default to L{auth.DEFAULT_LEVEL}, not fail-closed")

    for label, (skill, action), minimum in POLICY_INVARIANTS:
        actual = auth.level_for(skill, action)
        if actual < minimum:
            problems.append(f"{label} weakened to L{actual} (expected ≥L{minimum})")

    pin = getattr(config, "COMMAND_PIN", "")
    if pin:
        import secrets_store
        if not secrets_store.pin_is_hashed(pin):
            problems.append("COMMAND_PIN is stored in plaintext")

    if problems:
        security.security_event(security.SECURITY_POLICY_CHANGED,
                                count=len(problems), reason="invariant_violated",
                                status="failed")
        return report.add(Step("Verify security policy", FAILED,
                               "; ".join(problems), fatal=True))

    note = f"{len(auth.LEVELS)} rules, default L{auth.DEFAULT_LEVEL}"
    if not config.AUTH_ENABLED:
        # Not a failure -- it is the user's setting -- but it must be visible
        # on every boot rather than discovered later. An operator who forgot
        # they turned it off is the whole reason this line exists.
        note += "; AUTH DISABLED (config.AUTH_ENABLED = False)"
    return report.add(Step("Verify security policy", OK, note))


# ── step 3: OS / user identity ─────────────────────────────────────────
def verify_identity(report: BootReport) -> Step:
    import auth
    import config

    expected = getattr(config, "OWNER_SID", "")
    if not expected:
        return report.add(Step("Verify OS/user identity", UNAVAILABLE,
                               "no owner enrolled — run `python manage_secrets.py enroll-owner`"))
    if auth._verify_os_account():
        return report.add(Step("Verify OS/user identity", OK,
                               "running as the enrolled Windows account"))

    # Deliberately does not name the enrolled SID or the current one. "Which
    # account did you expect?" is a question an attacker benefits from and the
    # legitimate owner never needs to ask.
    security.security_event(security.AUTH_FAILURE, factor="os_account",
                            reason="sid_mismatch", status="failed")
    return report.add(Step("Verify OS/user identity", FAILED,
                           "not the enrolled Windows account", fatal=True))


# ── step 4: secure storage ─────────────────────────────────────────────
def init_secure_storage(report: BootReport) -> Step:
    import secrets_store

    if not secrets_store.dpapi_available():
        return report.add(Step("Initialize secure storage", UNAVAILABLE,
                               "DPAPI is Windows-only — secrets fall back to environment"))
    try:
        # Round-trip a throwaway value. Checking that the DLL loads proves
        # nothing: DPAPI fails at DECRYPT time when the profile has changed,
        # and that is exactly the case worth catching before ARGUS needs a key.
        probe = secrets_store._unprotect(secrets_store._protect("probe"))
        if probe != "probe":
            raise OSError("round-trip mismatch")
    except OSError as e:
        return report.add(Step("Initialize secure storage", FAILED,
                               f"DPAPI unusable ({e.__class__.__name__})"))

    import config
    src = secrets_store.secret_source("GROQ_API_KEY", getattr(config, "GROQ_API_KEY", ""))
    return report.add(Step("Initialize secure storage", OK, f"DPAPI ready; api key: {src}"))


# ── step 4b: the LSASS elevated helper ─────────────────────────────────
def lsass_capability(report: BootReport) -> Step:
    """Full elevated coverage for LSASS credential-dumping detection, honest.

    The orchestrator runs permanently stripped of SeDebugPrivilege
    (sandbox.drop_privileges), so an ELEVATED credential dump is invisible to
    the in-process scan. Full coverage lives in a separate one-job helper
    (threatmon/lsass_agent.py), registered elevated by
    tools/install_lsass_helper.py. This step asks that helper, live: is it up
    and able to scan RIGHT NOW?

    Deliberately NOT fatal. An absent helper is a coverage gap -- one
    lsass_link.status() already reports honestly to the security summary, and
    this boot line names the exact command to close it with -- not a reason to
    refuse to start.
    """
    import os
    if os.name != "nt":
        return report.add(Step("LSASS elevated helper", UNAVAILABLE,
                               "Windows-only control"))
    try:
        from threatmon import lsass_link
        ok, why = lsass_link.capability()
    except Exception as e:
        return report.add(Step("LSASS elevated helper", UNAVAILABLE,
                               f"{type(e).__name__}: {e}"))
    if ok:
        return report.add(Step("LSASS elevated helper", OK, why))
    # The helper is a same-user scheduled task; the in-process fallback still
    # runs, and naming the install command is the honest next step, not a guess.
    return report.add(Step("LSASS elevated helper", UNAVAILABLE,
                           f"not running — install it once from an elevated "
                           f"shell: python tools/install_lsass_helper.py"
                           + (f" ({why})" if why else "")))


# ── step 5: start locked ───────────────────────────────────────────────
def start_locked(report: BootReport) -> Step:
    import auth
    import config

    auth.lock("boot")
    auth.start()          # inactivity / suspend / workstation-lock watchdog

    security.security_event(security.SESSION_LOCKED, reason="boot", status="ok")

    if not config.AUTH_ENABLED:
        return report.add(Step("Start Argus LOCKED", SKIPPED,
                               "auth disabled — every level below L5 is permitted"))
    return report.add(Step("Start Argus LOCKED", OK,
                           f"unlock with: {describe_unlock()}"))


# ── steps 6-8: the unlock half ─────────────────────────────────────────
def describe_unlock() -> str:
    import auth
    import config

    factors = []
    if getattr(config, "OWNER_SID", ""):
        factors.append("Windows account")
    if getattr(config, "COMMAND_PIN", ""):
        factors.append("PIN")
    if auth.CHALLENGE_WINDOW:
        factors.append("spoken challenge")
    return " + ".join(factors) if factors else "nothing configured"


def voice_liveness_status() -> Step:
    """Step 6, reported honestly.

    Challenge-response liveness IS implemented and does defeat a replayed
    recording. Speaker verification is NOT, and saying "voice authentication"
    without that distinction would overstate it by a wide margin.
    """
    import auth
    import voiceauth

    mic_ok, mic_note = voiceauth.mic_permission()
    if not mic_ok:
        # Worth failing the step rather than noting it: with microphone
        # consent denied, Windows hands the capture stream silence instead of
        # an error, so ARGUS simply never answers and looks broken.
        security.security_event(security.VOICE_VERIFICATION_FAILURE,
                                reason="mic_permission_denied", status="failed")
        return Step("Voice/liveness authentication", FAILED, mic_note)

    if not auth.CHALLENGE_WINDOW:
        return Step("Voice/liveness authentication", UNAVAILABLE, "not configured")

    bits = [f"challenge-response, {auth.CHALLENGE_WINDOW:.0f}s window"]
    import config
    if getattr(config, "VOICE_REPLAY_DETECTION", False):
        bits.append("replay detection on")
    bits.append("no speaker biometrics"
                if not voiceauth.speaker_available()
                else f"backend: {voiceauth.speaker_backend()}")
    return Step("Voice/liveness authentication", OK, "; ".join(bits))


def second_factor_status() -> Step:
    import config

    if not getattr(config, "COMMAND_PIN", ""):
        return Step("Second factor if required", UNAVAILABLE, "no PIN set")
    # Report the L5 posture honestly per machine: the Hello projection is an
    # optional wheel, the gesture gate is opt-in, and each state has a
    # different answer to "can anything here satisfy L5?"
    try:
        import hwauth
        info = hwauth.availability()
        if not info["usable"]:
            note = ("PIN for L2+; TPM key enrolled; Windows Hello projection "
                    "not installed — L5 fails closed")
        elif not hwauth.HELLO_ENABLED:
            note = ("PIN for L2+; TPM key enrolled; Windows Hello available "
                    "but L5 disabled until you opt in (hwauth.HELLO_ENABLED)")
        else:
            note = "PIN for L2+; TPM key enrolled; Windows Hello armed for L5"
    except Exception:
        note = "PIN for L2+; hardware factors unavailable on this machine"
    return Step("Second factor if required", OK, note)


def unlock(supplied: dict) -> tuple[bool, str]:
    """Steps 6-8 as one transaction. The ONLY way ARGUS becomes operational.

    Delegates the decision to auth.verify() rather than reimplementing it, so
    the backoff, lockout and failed-attempt counters are the same ones every
    other authentication path uses. A second implementation would be a second
    set of bugs, and this one would be the one nobody tested.
    """
    import auth

    ok, message = auth.verify(supplied)
    if ok:
        security.security_event(security.SESSION_UNLOCKED,
                                factor=",".join(sorted(supplied)), status="ok")
    else:
        # WHICH factor failed is never recorded or spoken -- that is the
        # "don't reveal which factor was correct" requirement, and it applies
        # to the log as much as to the reply, since the log is readable by
        # anything running as this user.
        security.security_event(security.AUTH_FAILURE,
                                factor="undisclosed", reason="verify_failed",
                                status="failed")
    return ok, message


# ── the chain ──────────────────────────────────────────────────────────
def run_boot(verbose: bool = True) -> BootReport:
    """Steps 1-5. Returns a report; check .ok before starting the app."""
    report = BootReport()

    # harden_acls runs AFTER verify_installation deliberately: hardening is a
    # write to the security layer, and doing it before the integrity check
    # would mean altering files the check is about to verify.
    for fn in (verify_installation, harden_acls, verify_skills, verify_policy,
               verify_identity, init_secure_storage, lsass_capability):
        step = fn(report)
        if step.fatal and step.status == FAILED:
            report.aborted = True
            report.abort_reason = f"{step.name}: {step.detail}"
            security.security_event(security.BOOT_ABORTED,
                                    step=step.name[:40], status="failed")
            if verbose:
                print(report.render())
            return report

    start_locked(report)
    report.add(voice_liveness_status())
    report.add(second_factor_status())

    security.security_event(security.ARGUS_STARTED,
                            duration_ms=int((time.time() - report.started) * 1000),
                            status="ok")
    if verbose:
        print(report.render())
    return report


if __name__ == "__main__":
    import sys

    import config
    security.init_audit(config.VAULT_PATH)
    sys.exit(0 if run_boot().ok else 1)
