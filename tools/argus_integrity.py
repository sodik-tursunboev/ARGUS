"""
ARGUS - Integrity command line.

The ONLY way to seal a baseline or roll back. Deliberately not a skill, not a
router entry and not an HTTP endpoint: sealing is how a legitimate change is
accepted, so anything that can seal can also launder a tamper. Keeping it off
every surface ARGUS itself can reach is the difference between "the AI cannot
modify its security layer" being a property and being a hope.

    python tools/argus_integrity.py status
    python tools/argus_integrity.py seal   [--reason "applied security patch"]
    python tools/argus_integrity.py diff
    python tools/argus_integrity.py rollback
    python tools/argus_integrity.py signature
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import integrity          # noqa: E402
import security           # noqa: E402


def _init_audit():
    try:
        import config
        security.init_audit(config.VAULT_PATH)
    except Exception:
        pass


def cmd_status(_args):
    res = integrity.verify()
    print(f"manifest : {integrity.MANIFEST_PATH}")
    print(f"sealed   : {'yes' if res.sealed else 'NO — run `seal` to create a baseline'}")
    if res.sealed:
        print(f"signed   : {'yes' if res.signed else 'NO (DPAPI unavailable)'}")
        print(f"signature: {'valid' if res.signature_ok else 'INVALID' if res.signed else 'n/a'}")
    print(f"files    : {len(integrity.protected_files())} under integrity control")
    print(f"state    : {res.summary()}")
    hardened, note = integrity.acls_hardened()
    print(f"acls     : {note}")
    if not hardened:
        print("           -> run tools/harden_acls.ps1 as Administrator for OS-level"
              " prevention")
    return 0 if res.ok or not res.sealed else 1


def cmd_seal(args):
    _init_audit()
    before = integrity.verify()
    if before.sealed and not before.ok:
        print("Sealing over an existing baseline that does NOT verify:")
        for rel, tier in before.modified:
            print(f"   modified  {rel}  ({tier})")
        for rel, tier in before.missing:
            print(f"   missing   {rel}  ({tier})")
        for rel in before.added:
            print(f"   new       {rel}")
        # Sealing over a violation is exactly how an attacker would make one
        # disappear. It stays possible -- a real fix produces the same diff --
        # but it is never the default and never silent.
        if not args.force:
            print("\nRefusing. If these changes are yours, re-run with --force.")
            return 1

    m = integrity.seal(args.reason)
    security.security_event(security.CONFIG_CHANGED, component="integrity",
                            reason="sealed", count=len(m["entries"]),
                            signed=m["signed"], status="ok")
    print(f"Sealed {len(m['entries'])} files at {m['sealed_at']}"
          f"{'' if m['signed'] else '  (UNSIGNED — DPAPI unavailable)'}")
    print(f"manifest : {integrity.MANIFEST_PATH}")
    print(f"snapshot : {integrity.SNAPSHOT_DIR}")
    return 0


def cmd_diff(_args):
    res = integrity.verify()
    if not res.sealed:
        print("No baseline. Run `seal` first.")
        return 1
    if res.ok:
        print("No differences.")
        return 0
    for rel, tier in res.modified:
        print(f"modified  {rel}  ({tier})")
    for rel, tier in res.missing:
        print(f"missing   {rel}  ({tier})")
    for rel in res.added:
        print(f"new       {rel}")
    if res.signed and not res.signature_ok:
        print("\nMANIFEST SIGNATURE INVALID — the manifest itself was altered,")
        print("or it was sealed under a different Windows account.")
    return 1


def cmd_rollback(args):
    _init_audit()
    res = integrity.verify()
    if res.ok:
        print("Nothing to roll back.")
        return 0
    targets = [r for r, _ in res.modified + res.missing]
    print("Will restore from the known-good snapshot:")
    for rel in targets:
        print(f"   {rel}")
    if not args.yes:
        reply = input("Proceed? [y/N] ").strip().lower()
        if reply != "y":
            print("Cancelled.")
            return 1
    # The CLI is the one place the whole-set form is appropriate: the user has
    # just been shown the list and typed "y".
    restored = integrity.rollback(confirm_all=True)
    security.security_event(security.CONFIG_CHANGED, component="integrity",
                            reason="rollback", count=len(restored), status="ok")
    print(f"Restored {len(restored)} file(s).")
    for rel in restored:
        print(f"   {rel}")
    missing = set(targets) - set(restored)
    if missing:
        print(f"\nNo snapshot for {len(missing)}: " + ", ".join(sorted(missing)))
    return 0


def cmd_signature(_args):
    ok, status = integrity.verify_signature()
    print(f"authenticode: {status}")
    return 0 if ok else 1


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status").set_defaults(fn=cmd_status)
    sub.add_parser("diff").set_defaults(fn=cmd_diff)
    sub.add_parser("signature").set_defaults(fn=cmd_signature)

    s = sub.add_parser("seal")
    s.add_argument("--reason", default="manual")
    s.add_argument("--force", action="store_true",
                   help="seal even though the current baseline does not verify")
    s.set_defaults(fn=cmd_seal)

    r = sub.add_parser("rollback")
    r.add_argument("--yes", action="store_true")
    r.set_defaults(fn=cmd_rollback)

    args = p.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
