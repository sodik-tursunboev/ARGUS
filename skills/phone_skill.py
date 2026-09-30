"""
ARGUS - Outbound phone calls: "Boss, something needs your attention."

Places a real call to the owner's phone through Twilio when something on this
machine wants a human, and on request ("call me"). Uses Twilio's REST API over
HTTPS -- ARGUS makes an OUTBOUND request and nothing more, so it stays bound to
127.0.0.1 and accepts no inbound connection. Receiving calls is a separate
problem with a separate answer (see PHONE_RELAY.md); nothing here opens a port.

THE CALL IS A DOORBELL, NOT A REPORT. This is the design rule the module is
built around, and it exists to keep a standing promise: real security telemetry
about this machine must never reach the cloud path, however the request is
phrased. A call routed through Twilio IS the cloud path -- the spoken words land
in a third party's call logs and possibly its recordings. So an alert call says
that something needs attention and NOTHING about what: no detector name, no
technique, no process, no path. The detail stays local, on the HUD, for when the
owner gets to the machine. alert() enforces this by construction -- it does not
take a message argument at all, so there is no parameter through which a
detector's findings could ever be spoken down a phone line.

SPENDING MONEY IS A SAFETY PROBLEM. Everything else in ARGUS fails closed and
costs nothing when it does. A call costs real money and rings a real phone,
possibly at 4am, so this module is deliberately hard to make loop:

  * MIN_GAP_S between any two calls, and MAX_PER_DAY overall.
  * QUIET_HOURS, in which only a "critical" alert is allowed through.
  * A single pending-alert flag: while one alert call is outstanding, further
    detections do not queue up more calls.
  * Every refusal is logged with its reason, so a call that did NOT happen is
    as visible as one that did.

Credentials live in the DPAPI-sealed secret store (manage_secrets.py), never in
config.py and never in the repo. Absent credentials are a clean "not
configured", not an error -- the module is inert until deliberately set up.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

TWILIO_API = "https://api.twilio.com/2010-04-01"

MIN_GAP_S = 300            # never two calls inside five minutes
MAX_PER_DAY = 12
QUIET_START_H = 23         # 23:00
QUIET_END_H = 8            # 08:00
CALL_TIMEOUT_S = 20

# What an alert call says. Deliberately content-free -- see the module
# docstring. Chosen to sound like the assistant apologising for interrupting,
# which is what it is doing.
ALERT_LINE = ("Boss, sorry to bother you. This is Argus. "
              "Something on your machine needs your attention. "
              "Nothing else over the phone — come and take a look when you can.")
CRITICAL_LINE = ("Boss, this is Argus. Sorry to interrupt. "
                 "Something on your machine needs your attention now. "
                 "I won't say more over the phone.")

_lock = threading.RLock()
_state = {
    "calls": [],           # epoch seconds of placed calls
    "alert_pending": False,
    "last_error": "",
    "last_call_at": 0.0,
    "last_sid": "",            # so the outcome of the last call can be read
    "refusals": [],
}


# ── configuration ────────────────────────────────────────────────────────────
def _creds():
    """(sid, token, from_number, to_number). Empty strings when unset."""
    try:
        import secrets_store as ss
        return (ss.get_secret("TWILIO_ACCOUNT_SID", ""),
                ss.get_secret("TWILIO_AUTH_TOKEN", ""),
                ss.get_secret("TWILIO_FROM_NUMBER", ""),
                ss.get_secret("OWNER_PHONE_NUMBER", ""))
    except Exception:
        return "", "", "", ""


def configured() -> bool:
    return all(_creds())


def _quiet_now(now: float) -> bool:
    h = time.localtime(now).tm_hour
    if QUIET_START_H <= QUIET_END_H:
        return QUIET_START_H <= h < QUIET_END_H
    return h >= QUIET_START_H or h < QUIET_END_H       # window wraps midnight


def _refuse(reason: str) -> str:
    with _lock:
        _state["refusals"] = (_state["refusals"] + [reason])[-20:]
    try:
        import security
        security.audit("phone_refused", reason[:120], "blocked")
    except Exception:
        pass
    return reason


def _allowed(now: float, critical: bool):
    """(ok, reason). Every rate/quiet rule lives here so alert() and call()
    cannot diverge on when a call is acceptable."""
    if not configured():
        return False, ("Phone calling isn't set up. Add the Twilio details "
                       "with tools/set_phone_secrets.py first.")
    with _lock:
        calls = list(_state["calls"])
    day_ago = now - 86400
    today = [t for t in calls if t >= day_ago]
    if today and now - max(today) < MIN_GAP_S:
        wait = int(MIN_GAP_S - (now - max(today)))
        return False, f"I called you {int(now - max(today))}s ago — holding off for another {wait}s."
    if len(today) >= MAX_PER_DAY:
        return False, f"I've already called {len(today)} times today; that's the daily limit."
    if _quiet_now(now) and not critical:
        return False, "It's quiet hours, and this isn't urgent enough to wake you."
    return True, ""


# ── the call ─────────────────────────────────────────────────────────────────
def _twiml(message: str) -> str:
    """Twilio speaks this. Escaped because the message reaches a markup
    document -- a stray & or < would otherwise break the call outright."""
    from xml.sax.saxutils import escape
    return (f'<?xml version="1.0" encoding="UTF-8"?><Response>'
            f'<Pause length="1"/><Say voice="Polly.Brian">{escape(message)}</Say>'
            f'</Response>')


def _bin_url() -> str:
    """The configured TwiML Bin URL, or "". Only trial accounts need one."""
    try:
        import secrets_store as ss
        return ss.get_secret("TWILIO_TWIML_BIN_URL", "").strip()
    except Exception:
        return ""


def bin_call_url(bin_url: str, message: str) -> str:
    """A Bin URL carrying the message as a Mustache variable.

    The Bin's own body must contain {{msg}} for this to do anything. A Bin
    with fixed text ignores it and speaks the fixed text -- still correct for
    alert(), wrong for call() -- so set_phone_secrets.py checks which kind is
    configured and says which one it found.

    NOTE, because it is a real trade rather than an oversight: this puts the
    spoken text in a URL query string, where it lands in Twilio's request
    logs. It is the only mechanism a trial account has. It does not weaken the
    rule this module exists to keep: alert() still takes no message argument,
    so no detector finding can reach this path at all. Only words the owner
    typed themselves can.
    """
    sep = "&" if "?" in bin_url else "?"
    return f"{bin_url}{sep}msg=" + urllib.parse.quote(message, safe="")


# The Twilio call errors that actually occur here, in plain English. Anything
# not listed is reported with its number, so it can be looked up rather than
# guessed at.
CALL_ERRORS = {
    11200: ("Twilio could not fetch your TwiML Bin URL. Re-copy it from the "
            "Bin's own page in the console."),
    12300: ("Your TwiML Bin returned something that is not XML. It must start "
            "with <?xml version=\"1.0\" encoding=\"UTF-8\"?><Response>."),
    12100: "Your TwiML Bin's XML is malformed.",
    13214: "Twilio rejected the TwiML your Bin returned.",
    21219: ("A trial account may only call numbers you have verified. Verify "
            "this number in the console first."),
}

POLL_TRIES = 8
POLL_GAP_S = 2.5


def explain(code, message: str = "") -> str:
    """Twilio's error number turned into something a person can act on."""
    try:
        code = int(code)
    except (TypeError, ValueError):
        return message or ""
    return CALL_ERRORS.get(code, f"Twilio error {code}. {message}".strip())


def call_outcome(call_sid: str, wait_s: float = 30.0) -> dict:
    """Poll one call to its final state. {status, error_code, error, duration}

    Exists because A FAILED CALL LOOKS EXACTLY LIKE A SUCCESSFUL ONE at the
    point where it is placed. Twilio answers the POST with HTTP 201 and a SID
    and only afterwards goes and fetches the TwiML, so a broken TwiML source
    still produces a flawless-looking API response -- and a phone that says
    "we could not reach your URL server" to someone who is not holding a
    debugger. The truth exists only on the call resource, so this reads it.

    Deliberately NOT called by alert(): that runs on detector threads, and
    waiting half a minute for a phone call to finish is not something a threat
    detector should ever do.
    """
    sid, token, _, _ = _creds()
    if not (sid and token and call_sid):
        return {"status": "", "error_code": None, "error": "", "duration": ""}

    import base64
    url = f"{TWILIO_API}/Accounts/{sid}/Calls/{call_sid}.json"
    ok, why = True, ""
    try:
        import netpolicy
        ok, why = netpolicy.check_egress(url, "phone")
    except Exception:
        pass
    if not ok:
        return {"status": "", "error_code": None,
                "error": f"egress policy refused the check: {why}",
                "duration": ""}

    auth = "Basic " + base64.b64encode(f"{sid}:{token}".encode()).decode()
    deadline = time.time() + wait_s
    last = {"status": "", "error_code": None, "error": "", "duration": ""}
    for _ in range(POLL_TRIES):
        if time.time() > deadline:
            break
        time.sleep(POLL_GAP_S)
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("Authorization", auth)
            with urllib.request.urlopen(req, timeout=CALL_TIMEOUT_S) as r:
                c = json.loads(r.read().decode("utf-8", "replace"))
        except Exception as e:
            last["error"] = f"{type(e).__name__}: {str(e)[:80]}"
            break
        last = {"status": c.get("status") or "",
                "error_code": c.get("error_code"),
                "error": c.get("error_message") or "",
                "duration": c.get("duration") or ""}
        if last["status"] in ("completed", "failed", "busy", "no-answer",
                              "canceled"):
            break
    return last


def _place(message: str, now: float) -> tuple:
    """(ok, detail). The only place an HTTP request is actually made."""
    sid, token, frm, to = _creds()

    url = f"{TWILIO_API}/Accounts/{sid}/Calls.json"
    ok, why = True, ""
    try:
        import netpolicy
        ok, why = netpolicy.check_egress(url, "phone")
    except Exception:
        pass
    if not ok:
        return False, f"egress policy refused the call: {why}"

    import base64

    def _post(params):
        body = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Authorization", "Basic " + base64.b64encode(
            f"{sid}:{token}".encode()).decode())
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=CALL_TIMEOUT_S) as r:
            return json.loads(r.read().decode("utf-8", "replace"))

    # TWO WAYS TO TELL TWILIO WHAT TO SAY, in order of preference. Which one
    # works depends on the account, and both were established by testing
    # against the real API rather than from the docs:
    #
    #  1. A TwiML Bin (handler.twilio.com), if one is configured. Hosted BY
    #     Twilio, so Twilio can always fetch it. Free on a trial account, and
    #     on a trial account it is the ONLY thing that works.
    #  2. Inline Twiml. Cleanest -- the words stay inside the authenticated
    #     POST body and never appear in a URL -- but TRIAL ACCOUNTS CANNOT USE
    #     IT. Measured: both a plain <Say> and a Polly voice are rejected
    #     identically with "trial accounts have limited parameter access", so
    #     it is the Twiml PARAMETER that is blocked, not the voice.
    #
    # There used to be a third, twimlets.com/echo, and it is gone. It was
    # reachable from HERE (HTTP 200, valid TwiML, over both schemes) but
    # Twilio could not fetch it: the call connected and the phone said "we
    # could not reach your URL server". A fallback that does not work is worse
    # than no fallback, because it converts a clean failure into a confusing
    # phone call -- and it was also this module's only plaintext-http
    # endpoint, which violates the network boundary.
    #
    # In both remaining cases it is TWILIO that fetches the URL, not ARGUS, so
    # neither adds egress of ours: the phone class stays pinned to
    # api.twilio.com.
    attempts = []
    bin_url = _bin_url()
    if bin_url:
        attempts.append({"To": to, "From": frm,
                         "Url": bin_call_url(bin_url, message)})
    attempts.append({"To": to, "From": frm, "Twiml": _twiml(message)})
    last = ""
    for i, params in enumerate(attempts):
        try:
            data = _post(params)
            return True, str(data.get("sid", ""))[:40]
        except urllib.error.HTTPError as e:
            # Surface TWILIO'S OWN MESSAGE. Reporting only "HTTP Error 400"
            # hid three different real causes behind one opaque string and
            # turned a one-line fix into several rounds of guessing.
            raw = ""
            try:
                raw = e.read().decode("utf-8", "replace")
                detail = json.loads(raw)
                last = (f"{detail.get('message', '')} "
                        f"[code {detail.get('code')}]").strip()
            except Exception:
                last = f"HTTP {e.code}: {raw[:120]}"
            # Keep trying the remaining forms on a trial-restriction refusal;
            # anything else (bad number, no funds, unverified caller) will fail
            # the same way for every form, so stop and report it.
            if "limited parameter access" in last and i < len(attempts) - 1:
                continue
            # The one failure worth translating here rather than echoing.
            # "Invalid or disallowed parameters provided" tells the owner
            # nothing about what to DO; on a trial account with no Bin
            # configured, there is exactly one thing to do.
            if "limited parameter access" in last and not bin_url:
                return False, ("this is a trial account, which cannot be sent "
                               "the words to say directly — it needs a TwiML "
                               "Bin. See PHONE.md, then run "
                               "tools/set_phone_secrets.py")
            return False, last[:220]
        except Exception as e:
            # Never let a telephony failure escape into a detector's thread.
            return False, f"{type(e).__name__}: {str(e)[:90]}"
    return False, last[:220]


# A real Twilio call SID. Used to decide whether there is anything worth
# polling: if the API did not hand back one of these, there is no call to ask
# about, and tests that stub _place() must not trigger network traffic.
_CALL_SID = re.compile(r"^CA[0-9a-fA-F]{32}$")


def _verify_async(call_sid: str, kind: str):
    """Find out, after the fact, whether the call actually worked.

    Twilio accepts a doomed call with HTTP 201 and a SID, so the moment of
    placing one proves nothing at all. Without this, a broken TwiML source
    produces a cheerful "Calling you now" and then silence -- and for an
    alert, an owner who believes they were told and was not. That is the
    worst failure this module has, because it is invisible.

    WHAT THIS CANNOT SEE, measured rather than assumed. A call whose TwiML
    could not be fetched still finishes as status "completed" with
    error_code None, while the phone plays "we could not reach your URL
    server". Twilio records that reason in the Alerts API and in call Events,
    and BOTH are 401 "not available on a Trial account" -- so on a trial
    account the reason is genuinely unavailable to us. This therefore catches
    busy, no-answer, failed and canceled, plus any error code Twilio does
    attach, and it cannot catch a silent TwiML fetch failure. Do not read a
    clean result here as proof the owner heard anything.

    Runs on its own daemon thread: the reply must not wait half a minute for
    a phone call to end, and a detector thread must not wait at all.
    """
    def run():
        out = call_outcome(call_sid, wait_s=45)
        code = out.get("error_code")
        if not code and out.get("status") == "completed":
            return                       # it worked; nothing to report
        why = (explain(code, out.get("error")) if code
               else f"the call ended as {out.get('status') or 'unknown'}")
        with _lock:
            _state["last_error"] = why[:220]
        try:
            import security
            security.audit("phone_call_failed", f"kind={kind} {why[:100]}",
                           "failed")
        except Exception:
            pass

    threading.Thread(target=run, name="phone-verify", daemon=True).start()


def _record(now: float, ok: bool, detail: str, kind: str):
    with _lock:
        if ok:
            _state["calls"] = (_state["calls"] + [now])[-100:]
            _state["last_call_at"] = now
            _state["last_sid"] = detail        # the call SID, for call_outcome
        else:
            _state["last_error"] = detail
    try:
        import security
        # The call SID and the outcome -- never the spoken words, which for an
        # alert say nothing anyway but for call() carry the user's own text.
        security.audit("phone_call", f"kind={kind} ok={ok} ref={detail[:40]}",
                       "ok" if ok else "failed")
    except Exception:
        pass

    # Placed is not the same as delivered. Go and check, off the hot path.
    if ok and _CALL_SID.match(detail or ""):
        _verify_async(detail, kind)


def alert(critical: bool = False) -> str:
    """Ring the owner because something needs them. Says nothing about WHAT.

    Takes no message parameter on purpose: there is deliberately no way for a
    detector's findings to be passed in and spoken over a phone line.
    """
    now = time.time()
    with _lock:
        if _state["alert_pending"]:
            return _refuse("An alert call is already outstanding.")
    ok, why = _allowed(now, critical)
    if not ok:
        return _refuse(why)

    with _lock:
        _state["alert_pending"] = True
    try:
        placed, detail = _place(CRITICAL_LINE if critical else ALERT_LINE, now)
    except Exception as e:
        # Broad on purpose. alert() is called from detector threads, and a
        # telephony problem must never become a detector's problem -- a failed
        # phone call is not a reason for threat monitoring to stop.
        placed, detail = False, f"{type(e).__name__}: {str(e)[:80]}"
    finally:
        with _lock:
            _state["alert_pending"] = False
    _record(now, placed, detail, "alert")
    return ("Calling you now." if placed
            else f"I couldn't place the call ({detail}).")


def call(message: str = "") -> str:
    """An on-request call ("call me"). The owner asked, so their own words are
    spoken -- but a detector can never reach this path, only alert()."""
    now = time.time()
    ok, why = _allowed(now, critical=True)   # asked for explicitly: not quiet-gated
    if not ok:
        return _refuse(why)
    text = (message or "").strip() or (
        "Boss, this is Argus. You asked me to call. Everything is fine here.")
    placed, detail = _place(text[:400], now)
    _record(now, placed, detail, "requested")
    return ("Calling you now." if placed
            else f"I couldn't place the call ({detail}).")


def status() -> dict:
    now = time.time()
    with _lock:
        calls = list(_state["calls"])
        last_err = _state["last_error"]
        refusals = list(_state["refusals"])[-3:]
    today = [t for t in calls if t >= now - 86400]
    return {
        "skill": "phone",
        "configured": configured(),
        "calls_today": len(today),
        "daily_limit": MAX_PER_DAY,
        "min_gap_seconds": MIN_GAP_S,
        "quiet_hours": f"{QUIET_START_H:02d}:00-{QUIET_END_H:02d}:00",
        "in_quiet_hours": _quiet_now(now),
        "last_call": (time.strftime("%Y-%m-%dT%H:%M:%S",
                                    time.localtime(max(today))) if today else ""),
        "recent_refusals": refusals,
        "discloses_details": False,
        # Whether a TwiML Bin is configured, not the URL itself: it is the
        # thing that decides whether a trial account can speak at all, so its
        # absence should be visible in status rather than discovered on the
        # phone.
        "twiml_bin": bool(_bin_url()),
        "last_error": last_err,
    }
