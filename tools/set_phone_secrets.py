"""
ARGUS - Store the Twilio credentials for outbound calls.

Lives in tools/ rather than as a manage_secrets.py subcommand for a reason
worth keeping: manage_secrets.py is one of the 14 CRITICAL files, and once
tools/harden_acls.ps1 has run it is read-only to the owner's own account.
Adding a subcommand there would mean un-hardening the security layer to add a
convenience, which is the wrong trade. This writes through the same
secrets_store API and lands in the same DPAPI-sealed store.

    python tools/set_phone_secrets.py          # set them
    python tools/set_phone_secrets.py status    # check what is set
    python tools/set_phone_secrets.py bin       # set ONLY the TwiML Bin
    python tools/set_phone_secrets.py test      # place ONE real call and
                                                # report what actually happened

Values are TYPED IN, never passed as arguments -- an argument is visible in the
process list and lands in shell history, which is the same rule manage_secrets
follows and the same reason.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import base64
import getpass
import hashlib
import hmac
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import secrets_store  # noqa: E402

FIELDS = [
    ("TWILIO_ACCOUNT_SID", "Twilio Account SID (starts AC...)", False),
    ("TWILIO_AUTH_TOKEN", "Twilio Auth Token", True),
    ("TWILIO_FROM_NUMBER", "The Twilio number calls come FROM (+48...)", False),
    ("OWNER_PHONE_NUMBER", "YOUR mobile, the number to call (+49...)", False),
    # Optional, and only needed on a TRIAL account: trial accounts cannot use
    # the inline Twiml parameter, so Twilio has to be pointed at a URL instead
    # -- and it must be one Twilio can actually reach. A TwiML Bin is hosted by
    # Twilio itself, which is why it is the reliable answer. See PHONE.md.
    ("TWILIO_TWIML_BIN_URL",
     "TwiML Bin URL, https://handler.twilio.com/twiml/EH... "
     "(REQUIRED on a trial account — see PHONE.md; blank on a paid one)",
     False),
]

E164 = re.compile(r"^\+[1-9]\d{6,14}$")

# A TwiML Bin's SID: EH followed by 32 hex characters, same shape as every
# other Twilio SID.
BIN_SID = re.compile(r"^[Ee][Hh][0-9a-fA-F]{32}$")
BIN_HOST = "https://handler.twilio.com/twiml/"


def normalize_bin(raw: str) -> str:
    """Accept whatever the console actually put on the clipboard.

    The Bin page shows a SID (EH...) more prominently than the URL, and the
    URL is nothing more than a fixed host with that SID on the end. Demanding
    the full URL when the SID is what you are looking at is a pointless way to
    fail, so build it here instead.
    """
    raw = (raw or "").strip().strip("/")
    if BIN_SID.match(raw):
        # Only the PREFIX is case-corrected. The 32 hex characters are left
        # exactly as pasted: the path is case-sensitive at Twilio's end, so
        # "helpfully" changing their case would build a URL that 404s. If the
        # SID really is wrong, check_bin() below catches it live.
        return BIN_HOST + "EH" + raw[2:]
    return raw


def _problem(name: str, val: str) -> str:
    """Why this stored value cannot work, or "" if it looks usable.

    status() used to report only whether a value was PRESENT, and said
    "All set" over a stored Account SID sitting in the auth-token slot -- so
    the tool asserted everything was fine while every call failed with an
    opaque 401. Presence is not validity, and a setup tool that cannot tell
    the difference is worse than no setup tool.
    """
    if not val:
        return "NOT SET"
    if name == "TWILIO_ACCOUNT_SID":
        if not val.startswith("AC") or len(val) != 34:
            return f"WRONG SHAPE (expected 34 chars starting 'AC', got {len(val)})"
    if name == "TWILIO_AUTH_TOKEN":
        if val.startswith("AC") and len(val) == 34:
            return "THIS IS YOUR ACCOUNT SID, NOT THE AUTH TOKEN"
        if len(val) != 32:
            return f"WRONG SHAPE (expected 32 hex chars, got {len(val)})"
        if not all(c in "0123456789abcdefABCDEF" for c in val):
            return "WRONG SHAPE (not hexadecimal)"
    if name.endswith("NUMBER") and not E164.match(val):
        return "NOT E.164 (must start + and country code)"
    if name == "TWILIO_TWIML_BIN_URL" and val:
        if not val.startswith("https://handler.twilio.com/twiml/"):
            return ("should start https://handler.twilio.com/twiml/ "
                    "(a TwiML Bin URL)")
    return ""


PROBE = "Argus template probe"


def _api(path: str):
    """GET one Twilio REST resource. (status, parsed-or-text)."""
    import urllib.error
    import urllib.request

    sid = secrets_store.get_secret("TWILIO_ACCOUNT_SID", "")
    tok = secrets_store.get_secret("TWILIO_AUTH_TOKEN", "")
    if not (sid and tok):
        return -1, "no credentials"
    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}{path}"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", "Basic " + base64.b64encode(
        f"{sid}:{tok}".encode()).decode())
    try:
        import json
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:200]
    except Exception as e:
        return -1, f"{type(e).__name__}: {str(e)[:70]}"


def check_account() -> list:
    """Live account checks. Returns a list of problems, empty if healthy.

    THE CHECK THAT WAS MISSING, and it cost days. Every stored value was
    individually well-formed -- correct SID, correct 32-hex token, both
    numbers in E.164 -- so every offline check passed and the tool reported
    "All four look right", while every call reached the phone and played
    "we could not reach your URL server".

    The actual faults were only visible against the live account: the FROM
    number was not owned by the account at all (its SID 404s), and the
    balance was zero with no usage ever recorded. No amount of shape
    validation can see either. Ask Twilio.
    """
    problems = []
    frm = secrets_store.get_secret("TWILIO_FROM_NUMBER", "")
    to = secrets_store.get_secret("OWNER_PHONE_NUMBER", "")

    code, acct = _api(".json")
    if code != 200:
        return [f"cannot read the account: {str(acct)[:120]}"]
    trial = (acct.get("type") == "Trial")
    print(f"  account            {acct.get('type')} / {acct.get('status')}")

    code, bal = _api("/Balance.json")
    if code == 200:
        amount = bal.get("balance")
        print(f"  balance            {amount} {bal.get('currency')}")
        try:
            if float(amount) <= 0:
                problems.append(
                    "the account balance is ZERO — Twilio will connect calls "
                    "but will not execute your TwiML, so the phone hears an "
                    "error announcement instead of the message")
        except (TypeError, ValueError):
            pass

    code, nums = _api("/IncomingPhoneNumbers.json?PageSize=50")
    if code == 200:
        owned = [n.get("phone_number") for n in nums.get("incoming_phone_numbers", [])]
        print(f"  numbers owned      {', '.join(owned) if owned else 'NONE'}")
        if not owned:
            problems.append(
                "this account owns no phone number. A call needs a Twilio "
                "number to originate from — claim the free trial number in "
                "the console, then set TWILIO_FROM_NUMBER to it")
        elif frm and frm not in owned:
            problems.append(
                f"TWILIO_FROM_NUMBER is {frm}, which this account does NOT "
                f"own. Owned: {', '.join(owned)}")

    if trial and to:
        code, ids = _api("/OutgoingCallerIds.json?PageSize=50")
        if code == 200:
            verified = [c.get("phone_number")
                        for c in ids.get("outgoing_caller_ids", [])]
            print(f"  verified numbers   "
                  f"{', '.join(verified) if verified else 'NONE'}")
            if to not in verified:
                problems.append(
                    f"a trial account may only call VERIFIED numbers, and "
                    f"{to} is not one. Verify it in the console")
    return problems


def _sign(url: str, token: str) -> str:
    """Twilio's own request signature: base64(HMAC-SHA1(token, url)).

    A TwiML Bin refuses every request that is not signed by the account that
    owns it -- "Not Authorized - only signed requests from Twilio are allowed"
    -- so a Bin CANNOT be checked by simply fetching it. Measured, after an
    unsigned probe reported a perfectly good Bin as broken and refused to save
    it. Signing the probe exactly as Twilio signs its own webhook is what
    makes the check possible at all.

    Only the URL is signed, because this is a GET with no form body. A POST
    would additionally append its POST parameters as sorted key+value pairs.
    """
    mac = hmac.new(token.encode(), url.encode(), hashlib.sha1).digest()
    return base64.b64encode(mac).decode()


def check_bin(url: str) -> tuple:
    """Fetch the TwiML Bin as Twilio would, and say what kind it is.

    states: "ok"           -- valid TwiML and {{msg}} templating works
            "fixed"        -- valid TwiML, but it speaks fixed text
            "missing"      -- Twilio says no such Bin: definitively wrong
            "unverifiable" -- could not tell from here; NOT a reason to refuse

    THE LAST STATE IS THE IMPORTANT ONE. An earlier version of this had only
    "ok" and "bad", treated everything it could not read as "bad", and used
    that to REFUSE TO SAVE -- so it blocked a correct Bin behind a check that
    was itself broken. A check that cannot be authoritative must never be a
    gate. The authoritative test is a real call, which is what `test` does.

    This lives in the setup tool rather than in phone_skill deliberately.
    netpolicy pins the phone component to api.twilio.com, and placing calls
    does not need any other host; widening that class so a convenience check
    could run would mean loosening the egress policy to make setup nicer,
    which is the wrong trade and the wrong direction. This script is run by
    hand by the owner and is outside the component model -- the same reason it
    is allowed to write the secret store directly.
    """
    import urllib.error
    import urllib.parse
    import urllib.request

    if not url:
        return "missing", "no URL"

    sid = secrets_store.get_secret("TWILIO_ACCOUNT_SID", "")
    token = secrets_store.get_secret("TWILIO_AUTH_TOKEN", "")
    if not (sid and token):
        return "unverifiable", ("the Account SID and Auth Token must be set "
                                "before a Bin can be checked")

    # AccountSid is required by the handler, and the whole URL (query string
    # included) is what gets signed.
    probe = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(
        {"AccountSid": sid, "msg": PROBE})
    try:
        req = urllib.request.Request(probe, method="GET")
        req.add_header("X-Twilio-Signature", _sign(probe, token))
        with urllib.request.urlopen(req, timeout=15) as r:
            ctype = (r.headers.get("content-type") or "").split(";")[0].strip().lower()
            body = r.read(16384).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "missing", ("Twilio says there is no such Bin. Re-copy the "
                               "SID from the Bin's own page in the console.")
        if e.code == 401:
            return "unverifiable", ("Twilio rejected my signature — most "
                                    "likely the stored Auth Token is stale. "
                                    "The Bin itself may well be fine.")
        return "unverifiable", f"HTTP {e.code} while checking; the Bin may be fine"
    except Exception as e:
        return "unverifiable", (f"could not reach Twilio: "
                                f"{type(e).__name__}: {str(e)[:60]}")

    if "<Response>" not in body:
        return "missing", (f"that URL does not return TwiML (no <Response>). "
                           f"First 60 chars: {body.strip()[:60]!r}")
    if ctype and "xml" not in ctype:
        # Twilio rejects a non-XML content type outright (error 12300), so a
        # Bin that looks right in a browser can still fail on a call.
        return "missing", f"served as {ctype!r}, but Twilio requires XML"
    if "<Say" not in body:
        return "missing", "the TwiML has no <Say>, so the call would say nothing"
    if PROBE in body:
        return "ok", "valid TwiML, and {{msg}} templating works"
    return "fixed", ("valid TwiML, but it speaks FIXED text — {{msg}} is not "
                     "in the Bin body, so 'call me' with your own words would "
                     "still say whatever the Bin says")


def set_bin() -> int:
    """Set ONLY the TwiML Bin, without walking the other four prompts.

    Exists because the Bin is the one value that gets added after the fact --
    the other four are set once and never touched again, and pressing Enter
    blindly through four hidden-input prompts to reach the fifth is a good way
    to clear something by accident.
    """
    name = "TWILIO_TWIML_BIN_URL"
    current = secrets_store.get_secret(name, "")
    print("Paste the TwiML Bin URL, or just its SID (EH...).")
    if current:
        print(f"  currently: {current}")
    raw = normalize_bin(input("\nTwiML Bin: "))
    if not raw:
        print("Nothing entered; left unchanged.")
        return 0

    problem = _problem(name, raw)
    if problem:
        print(f"  -> {problem}\n  -> NOT saved.")
        return 1
    print(f"  -> using {raw}")

    state, detail = check_bin(raw)
    print(f"  -> checking it against Twilio… {state.upper()}: {detail}")
    # Only a definitive "no such Bin" blocks. Anything merely unverifiable is
    # saved and settled by a real call -- see check_bin's docstring.
    if state == "missing":
        print("  -> NOT saved. Fix the Bin, then run this again.")
        return 1

    secrets_store.put_secret(name, raw)
    print("  -> saved (encrypted under your Windows account)")
    if state == "unverifiable":
        print("     I could not confirm it from here, so it is saved as given. "
              "The 'test' run below is the real check.")
    if state == "fixed":
        print("\n  NOTE: the Bin speaks fixed text. Add {{msg}} to its <Say> "
              "if you want 'call me and tell me X' to say X.")
    print("\nNow prove it end to end:")
    print("  python tools\\set_phone_secrets.py test")
    return 0


def test() -> int:
    """Place one real call and report the truth about it.

    Placing the call is not the test. Twilio accepts a doomed call with HTTP
    201 and a SID, so the API response proves only that the request was
    well-formed. The test is what the call resource says a few seconds later.
    """
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from skills import phone_skill as P

    if status():
        return 1

    bin_url = secrets_store.get_secret("TWILIO_TWIML_BIN_URL", "").strip()
    if bin_url:
        state, detail = check_bin(bin_url)
        print(f"TwiML Bin: {state.upper()} — {detail}\n")
        if state == "missing":
            print("Fix the Bin first; the call would connect and then fail.")
            return 1

    to = secrets_store.get_secret("OWNER_PHONE_NUMBER", "")
    print(f"This places ONE REAL CALL to {to} and costs trial credit.")
    if input("Type 'yes' to place it: ").strip().lower() != "yes":
        print("Nothing placed.")
        return 0

    reply = P.call("This is Argus, testing the phone line. Everything is fine.")
    print(f"\n  {reply}")
    if not reply.startswith("Calling"):
        return 1

    print("  waiting for the call to finish (this is the part that matters)…")
    out = P.call_outcome(_last_sid(P), wait_s=40)
    print(f"  status={out['status'] or '?'}  duration={out['duration'] or '?'}s"
          f"  error={out['error_code']}")
    if out["error_code"]:
        print(f"\n  FAILED: {P.explain(out['error_code'], out['error'])}")
        return 1
    if out["status"] == "completed":
        # Deliberately not phrased as success. A call whose TwiML could not be
        # fetched ALSO finishes "completed" with error_code None, and the two
        # reasons Twilio records it (Alerts, call Events) are both blocked on
        # a trial account -- so "completed" is genuinely all we know, and
        # saying more than that would be the same lie the API tells.
        print("\n  Twilio says the call completed with no error.")
        print("  That is NOT proof you heard the message: a call whose TwiML")
        print("  failed to load also reports 'completed' here, and the real")
        print("  reason is only in the Alerts API, which trial accounts")
        print("  cannot read. What you HEARD is the actual result:")
        print("    - the message   -> working end to end")
        print("    - 'could not reach your URL server' -> the Bin was not "
              "fetched; see PHONE.md")
        return 0
    print(f"\n  The call ended as '{out['status']}' — not answered, rather "
          f"than misconfigured. Try again and pick up.")
    return 1


def _last_sid(P) -> str:
    """The SID of the call just placed. _record() stores it as last_error only
    on failure, so read it from the state the skill keeps."""
    with P._lock:
        return P._state.get("last_sid", "")


def status() -> int:
    print("Twilio configuration\n")
    bad = []
    for name, label, _ in FIELDS:
        val = secrets_store.get_secret(name, "")
        problem = _problem(name, val)
        # The Bin URL is optional -- absent is fine on a paid account.
        if name == "TWILIO_TWIML_BIN_URL" and not val:
            print(f"  {name:22s} not set (only needed on a trial account)")
            continue
        if problem:
            bad.append((name, problem))
            shown = f"!! {problem}"
        elif name == "TWILIO_AUTH_TOKEN":
            shown = "set (hidden, 32 hex — looks right)"
        elif name.endswith("NUMBER"):
            shown = val                      # a phone number is not a secret
        else:
            shown = val[:6] + "…" + val[-4:] if len(val) > 12 else "set"
        print(f"  {name:22s} {shown}")
    print()
    if bad:
        print(f"{len(bad)} value(s) are wrong or missing:")
        for name, problem in bad:
            print(f"  - {name}: {problem}")
        print("\nRun this without arguments to fix them. In the Twilio console "
              "the Auth Token is hidden behind a 'Show' button — if you copy "
              "without clicking it you get the SID above it instead.")
        return 1

    # Shapes being right is not the same as the account working, and saying
    # so was the single most expensive mistake this tool made. Ask Twilio.
    print("The stored values are well-formed. Checking them against the "
          "live account:\n")
    live = check_account()
    print()
    if live:
        print(f"{len(live)} problem(s) that no offline check could see:")
        for p in live:
            print(f"  - {p}")
        return 1
    print("The account looks healthy too. Try 'phone status', then 'call me'.")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "status":
        return status()
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        return test()
    if len(sys.argv) > 1 and sys.argv[1] == "bin":
        return set_bin()

    print(__doc__.strip().split("\n\n")[0])
    print("\nLeave a value blank to keep whatever is already stored.\n")

    for name, label, hidden in FIELDS:
        current = secrets_store.get_secret(name, "")
        hint = " [currently set]" if current else ""
        raw = (getpass.getpass(f"{label}{hint}: ") if hidden
               else input(f"{label}{hint}: ")).strip()
        if not raw:
            if not current:
                print(f"  -> skipped; {name} is still unset.")
            continue

        # Numbers must be E.164 or Twilio rejects the call with an opaque
        # error at dial time -- far better to refuse it here, where the reason
        # is obvious, than to debug it from a failed call later.
        if name.endswith("NUMBER") and not E164.match(raw):
            print(f"  -> '{raw}' is not E.164. It must start with + and the "
                  f"country code, e.g. +48123456789. Not saved.")
            continue
        # A bare Bin SID is turned into its URL rather than rejected, and the
        # result is checked LIVE -- a Bin that Twilio cannot use should fail
        # here, in front of the person who can fix it, not later on a phone
        # call with no explanation attached.
        if name == "TWILIO_TWIML_BIN_URL":
            fixed_up = normalize_bin(raw)
            if fixed_up != raw:
                print(f"  -> that's the Bin SID; using {fixed_up}")
            raw = fixed_up
            problem = _problem(name, raw)
            if problem:
                print(f"  -> {problem}. NOT saved.")
                continue
            state, detail = check_bin(raw)
            print(f"  -> checking it… {state.upper()}: {detail}")
            if state == "missing":
                print("  -> NOT saved. Fix the Bin, then run this again.")
                continue

        if name == "TWILIO_ACCOUNT_SID" and not raw.startswith("AC"):
            print("  -> Note: Twilio Account SIDs start 'AC'. Saving anyway; "
                  "check it if calls fail.")

        # Validate the token's SHAPE, because this field is hidden input: a
        # mispaste is invisible to the person typing it, and the only symptom
        # is an opaque HTTP 401 at dial time. This exact mistake happened --
        # a 34-char Account SID pasted into the token prompt, which is
        # indistinguishable from a token unless you count the characters.
        if name == "TWILIO_AUTH_TOKEN":
            if raw.startswith("AC") and len(raw) == 34:
                print("  -> That looks like your Account SID, not the Auth "
                      "Token (34 chars starting 'AC'). The token is a "
                      "separate 32-character value. NOT saved.")
                continue
            if len(raw) != 32 or not all(c in "0123456789abcdefABCDEF" for c in raw):
                print(f"  -> A Twilio Auth Token is 32 hexadecimal characters; "
                      f"this is {len(raw)}"
                      f"{'' if all(c in '0123456789abcdefABCDEF' for c in raw) else ' and not all hex'}"
                      f". NOT saved — check you copied the Auth Token and not "
                      f"the SID or an API key secret.")
                continue

        where = secrets_store.put_secret(name, raw)
        print(f"  -> saved (encrypted under your Windows account)")

    print()
    return status()


if __name__ == "__main__":
    sys.exit(main())
