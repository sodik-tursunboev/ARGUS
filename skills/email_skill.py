"""
ARGUS - Email Skill

Read, search, and send email over plain IMAP/SMTP -- no OAuth flow, no cloud
API key, just an address, an app password, and a host, the same shape
phone_skill already uses for Twilio. Works with Gmail (an app password, not
your real password -- Google's own 2FA-required kind), Outlook, or any other
IMAP/SMTP provider by overriding the host secrets.

Credentials live in the DPAPI-sealed secret store (manage_secrets.py), never
in config.py and never in the repo -- same as phone_skill.py. Absent
credentials are a clean "not configured", not an error; this module is
inert until deliberately set up. Set with:
    EMAIL_ADDRESS, EMAIL_APP_PASSWORD          (required)
    EMAIL_IMAP_HOST, EMAIL_SMTP_HOST           (default to Gmail's)
    EMAIL_IMAP_PORT, EMAIL_SMTP_PORT           (default 993 / 587)

SENDING IS STAGED AND PIN-CONFIRMED -- send/reply/forward all leave this
machine and land in someone else's inbox, permanently and on your name, so
they get the exact same stage/confirm shape browser_skill.stage_submit()
uses and for the same reason: a misheard command should not be able to mail
someone. Reading and searching are not gated, same tier as files/find.

ATTACHMENTS ARE NAMED, NEVER OPENED OR SAVED. list_attachments() reports
filenames only -- auto-downloading or auto-opening an email attachment by
voice is exactly the "arbitrary file from an untrusted source, executed
without looking at it first" risk files_skill.open_file() and
execpolicy.check_open_file() exist to prevent, and email is a strictly
worse source than a local file (it is the classic phishing/malware delivery
path). A human who wants the actual file still opens their mail client.

NOT SCHEDULABLE. Email actions are not in router.CHAINABLE, so
scheduler_skill can never be pointed at them -- "check my email every
5 minutes" is exactly the kind of unattended-and-unbounded behaviour this
project has repeatedly drawn a line in front of elsewhere (see
scheduler_skill.py's own module docstring).
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import email
import email.utils
import imaplib
import smtplib
import time
from email.header import decode_header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import secrets_store
from config import COMMAND_PIN

CONFIRM_WINDOW = 25  # seconds -- identical to every other staged action in ARGUS

_DEFAULT_IMAP_HOST = "imap.gmail.com"
_DEFAULT_SMTP_HOST = "smtp.gmail.com"
_DEFAULT_IMAP_PORT = 993
_DEFAULT_SMTP_PORT = 587

_pending = {"kind": None, "detail": None, "at": 0.0}


def _creds() -> dict:
    ss = secrets_store
    return {
        "address": ss.get_secret("EMAIL_ADDRESS", ""),
        "password": ss.get_secret("EMAIL_APP_PASSWORD", ""),
        "imap_host": ss.get_secret("EMAIL_IMAP_HOST", "") or _DEFAULT_IMAP_HOST,
        "smtp_host": ss.get_secret("EMAIL_SMTP_HOST", "") or _DEFAULT_SMTP_HOST,
        "imap_port": int(ss.get_secret("EMAIL_IMAP_PORT", "") or _DEFAULT_IMAP_PORT),
        "smtp_port": int(ss.get_secret("EMAIL_SMTP_PORT", "") or _DEFAULT_SMTP_PORT),
    }


def configured() -> bool:
    c = _creds()
    return bool(c["address"] and c["password"])


def _decode(value: str) -> str:
    if not value:
        return ""
    parts = decode_header(value)
    out = []
    for text, enc in parts:
        if isinstance(text, bytes):
            out.append(text.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(text)
    return "".join(out)


def _imap():
    c = _creds()
    conn = imaplib.IMAP4_SSL(c["imap_host"], c["imap_port"])
    conn.login(c["address"], c["password"])
    return conn


def _fetch_matching(query: str, limit: int = 8):
    """Searches SUBJECT and FROM (IMAP's OR, both case-insensitive substring)
    across the last 200 messages in INBOX, newest first."""
    conn = _imap()
    try:
        conn.select("INBOX", readonly=True)
        typ, data = conn.search(None, "OR", f'SUBJECT "{query}"', f'FROM "{query}"')
        ids = data[0].split() if typ == "OK" else []
        ids = ids[-200:][::-1]  # newest first
        out = []
        for msg_id in ids[:limit]:
            typ, msg_data = conn.fetch(msg_id, "(RFC822)")
            if typ != "OK" or not msg_data or not msg_data[0]:
                continue
            msg = email.message_from_bytes(msg_data[0][1])
            out.append((msg_id, msg))
        return out
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def search(query: str, limit: int = 5) -> str:
    if not configured():
        return "Email isn't set up -- add EMAIL_ADDRESS and EMAIL_APP_PASSWORD with manage_secrets.py."
    if not (query or "").strip():
        return "Search for what?"
    try:
        hits = _fetch_matching(query, limit=limit)
    except Exception as e:
        return f"I couldn't check your email: {e}"
    if not hits:
        return f"No emails matching {query}."
    lines = []
    for _, msg in hits:
        who = _decode(msg.get("From", "unknown"))
        subj = _decode(msg.get("Subject", "(no subject)"))
        lines.append(f'"{subj}" from {who}')
    return f"{len(hits)} match{'es' if len(hits) != 1 else ''}: " + "; ".join(lines)


def _body_text(msg) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if ctype == "text/plain" and "attachment" not in disp:
                try:
                    return part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    continue
        return ""
    try:
        return msg.get_payload(decode=True).decode(
            msg.get_content_charset() or "utf-8", errors="replace")
    except Exception:
        return str(msg.get_payload())


def read(query: str) -> str:
    if not configured():
        return "Email isn't set up -- add EMAIL_ADDRESS and EMAIL_APP_PASSWORD with manage_secrets.py."
    if not (query or "").strip():
        return "Read which email?"
    try:
        hits = _fetch_matching(query, limit=1)
    except Exception as e:
        return f"I couldn't check your email: {e}"
    if not hits:
        return f"No emails matching {query}."
    _, msg = hits[0]
    who = _decode(msg.get("From", "unknown"))
    subj = _decode(msg.get("Subject", "(no subject)"))
    body = _body_text(msg).strip()
    if not body:
        return f'"{subj}" from {who} -- no readable text body.'
    return f'"{subj}" from {who}: {body[:1500]}'


def list_attachments(query: str) -> str:
    if not configured():
        return "Email isn't set up -- add EMAIL_ADDRESS and EMAIL_APP_PASSWORD with manage_secrets.py."
    if not (query or "").strip():
        return "Which email?"
    try:
        hits = _fetch_matching(query, limit=1)
    except Exception as e:
        return f"I couldn't check your email: {e}"
    if not hits:
        return f"No emails matching {query}."
    _, msg = hits[0]
    names = []
    if msg.is_multipart():
        for part in msg.walk():
            disp = str(part.get("Content-Disposition") or "")
            if "attachment" in disp:
                fn = _decode(part.get_filename() or "")
                if fn:
                    names.append(fn)
    if not names:
        return "No attachments on that email."
    return f"{len(names)} attachment{'s' if len(names) != 1 else ''}: " + ", ".join(names)


def contacts_search(query: str, limit: int = 5) -> str:
    """Recent senders whose name or address matches QUERY -- derived from
    INBOX headers already fetched for search(), not a real address book."""
    if not configured():
        return "Email isn't set up -- add EMAIL_ADDRESS and EMAIL_APP_PASSWORD with manage_secrets.py."
    if not (query or "").strip():
        return "Search contacts for what?"
    try:
        conn = _imap()
        try:
            conn.select("INBOX", readonly=True)
            typ, data = conn.search(None, "ALL")
            ids = (data[0].split() if typ == "OK" else [])[-100:][::-1]
            seen = {}
            for msg_id in ids:
                typ, hdr = conn.fetch(msg_id, "(BODY.PEEK[HEADER.FIELDS (FROM)])")
                if typ != "OK" or not hdr or not hdr[0]:
                    continue
                raw = hdr[0][1].decode("utf-8", errors="replace")
                name, addr = email.utils.parseaddr(raw.replace("From:", "", 1).strip())
                if not addr:
                    continue
                if query.lower() in (name or "").lower() or query.lower() in addr.lower():
                    seen[addr] = name or addr
                if len(seen) >= limit:
                    break
        finally:
            conn.logout()
    except Exception as e:
        return f"I couldn't check your contacts: {e}"
    if not seen:
        return f"No one in recent email matches {query}."
    return "; ".join(f"{n} <{a}>" for a, n in seen.items())


# ═══════════════════════════════════════════════════════════════════════════
# STAGED: compose / reply / forward. See module docstring.
# ═══════════════════════════════════════════════════════════════════════════

def has_pending() -> bool:
    return _pending["kind"] is not None and time.time() - _pending["at"] <= CONFIRM_WINDOW


def cancel() -> str:
    had = _pending["kind"] is not None
    _pending.update(kind=None, detail=None, at=0.0)
    return "Cancelled." if had else "There was nothing to cancel."


def stage_send(to: str, subject: str, body: str) -> str:
    if not configured():
        return "Email isn't set up -- add EMAIL_ADDRESS and EMAIL_APP_PASSWORD with manage_secrets.py."
    if not (to or "").strip() or not (body or "").strip():
        return "Send to whom, and say what?"
    _pending.update(kind="send", detail=(to.strip(), subject.strip(), body.strip()),
                    at=time.time())
    if not COMMAND_PIN:
        return f"You want me to email {to}, but no command PIN is set in config.py."
    return f'You want me to email "{subject or "(no subject)"}" to {to}. Type your PIN to confirm.'


def stage_reply(query: str, body: str) -> str:
    if not configured():
        return "Email isn't set up -- add EMAIL_ADDRESS and EMAIL_APP_PASSWORD with manage_secrets.py."
    if not (query or "").strip() or not (body or "").strip():
        return "Reply to which email, and say what?"
    try:
        hits = _fetch_matching(query, limit=1)
    except Exception as e:
        return f"I couldn't check your email: {e}"
    if not hits:
        return f"No emails matching {query}."
    _, msg = hits[0]
    to_addr = email.utils.parseaddr(msg.get("Reply-To") or msg.get("From", ""))[1]
    subj = _decode(msg.get("Subject", ""))
    if not subj.lower().startswith("re:"):
        subj = f"Re: {subj}"
    _pending.update(kind="send", detail=(to_addr, subj, body.strip()), at=time.time())
    if not COMMAND_PIN:
        return f"You want me to reply to {to_addr}, but no command PIN is set in config.py."
    return f"You want me to reply to {to_addr}. Type your PIN to confirm."


def stage_forward(query: str, to: str) -> str:
    if not configured():
        return "Email isn't set up -- add EMAIL_ADDRESS and EMAIL_APP_PASSWORD with manage_secrets.py."
    if not (query or "").strip() or not (to or "").strip():
        return "Forward which email, and to whom?"
    try:
        hits = _fetch_matching(query, limit=1)
    except Exception as e:
        return f"I couldn't check your email: {e}"
    if not hits:
        return f"No emails matching {query}."
    _, msg = hits[0]
    orig_from = _decode(msg.get("From", "unknown"))
    subj = _decode(msg.get("Subject", ""))
    if not subj.lower().startswith("fwd:"):
        subj = f"Fwd: {subj}"
    body = f"---------- Forwarded message ---------\nFrom: {orig_from}\n\n{_body_text(msg).strip()}"
    _pending.update(kind="send", detail=(to.strip(), subj, body), at=time.time())
    if not COMMAND_PIN:
        return f"You want me to forward that to {to}, but no command PIN is set in config.py."
    return f"You want me to forward \"{subj}\" to {to}. Type your PIN to confirm."


def confirm(supplied: str = "") -> str:
    kind = _pending["kind"]
    if not kind:
        return "There's nothing waiting for confirmation."
    if time.time() - _pending["at"] > CONFIRM_WINDOW:
        _pending.update(kind=None, detail=None, at=0.0)
        return "That confirmation expired. Ask me again if you still want it."
    if not COMMAND_PIN:
        _pending.update(kind=None, detail=None, at=0.0)
        return "No command PIN is set in config.py, so I can't confirm this."
    # ARGUS-SEC-011: the SHARED gate, not a bare verify_pin. One wrong-PIN
    # budget covers every confirming skill, so grinding three guesses here,
    # three on a staged shutdown and three on a service restart stops
    # multiplying the budget. Handles both a migrated PBKDF2 hash and a
    # legacy plaintext PIN, with compare_digest in both branches.
    import security as _security
    if _security.pin_gate_remaining() > 0:
        return (f"Too many wrong PINs across ARGUS. Try again in "
                f"{int(_security.pin_gate_remaining()) + 1} seconds.")
    if not _security.pin_gate_verify(supplied, COMMAND_PIN):
        return "That's not the right PIN. Type it again, or say cancel."

    to, subject, body = _pending["detail"]
    _pending.update(kind=None, detail=None, at=0.0)
    try:
        c = _creds()
        msg = MIMEMultipart()
        msg["From"] = c["address"]
        msg["To"] = to
        msg["Subject"] = subject or "(no subject)"
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(c["smtp_host"], c["smtp_port"], timeout=15) as server:
            server.starttls()
            server.login(c["address"], c["password"])
            server.send_message(msg)
    except Exception as e:
        return f"I couldn't send that: {e}"
    try:
        import security
        security.audit("email_send", f"to {to}: {subject}"[:160], "ok")
    except Exception:
        pass
    return f"Sent to {to}."
