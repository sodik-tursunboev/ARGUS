"""
ARGUS - Store the Telegram bot credentials.

Lives in tools/ for the same reason set_phone_secrets.py does: manage_secrets.py
is one of the CRITICAL files and is read-only once tools/harden_acls.ps1 has
run. Adding a subcommand there would mean un-hardening the security layer to
add a convenience, which is the wrong trade. This writes through the same
secrets_store API and lands in the same DPAPI-sealed store.

    python tools/set_telegram_secrets.py          # set it up
    python tools/set_telegram_secrets.py status   # check it
    python tools/set_telegram_secrets.py test     # send one real message

The token is TYPED IN, never passed as an argument -- an argument is visible in
the process list and lands in shell history.

WHY THIS ASKS FOR SO LITTLE: the chat id is discovered rather than demanded.
Making someone find their own numeric Telegram id is exactly the kind of
console scavenger hunt that made the Twilio path miserable, and it is
unnecessary -- the bot already learns the id the moment you message it.
"""

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import getpass
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import secrets_store  # noqa: E402

API = "https://api.telegram.org"

# "<bot id>:<35 chars>" -- shape only. The authoritative check is getMe.
TOKEN_SHAPE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{30,}$")


def _call(token: str, method: str, params: dict | None = None):
    """(ok, result-or-error-text). Never returns anything containing the token."""
    url = f"{API}/bot{token}/{method}"
    data = urllib.parse.urlencode(params).encode() if params else None
    req = urllib.request.Request(url, data=data,
                                 method="POST" if data else "GET")
    if data:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
        if not d.get("ok"):
            return False, str(d.get("description", "refused"))[:160]
        return True, d.get("result")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return False, str(json.loads(raw).get("description", raw))[:160]
        except ValueError:
            return False, f"HTTP {e.code}: {raw[:120]}"
    except Exception as e:
        # str(e) can carry the URL, and the URL carries the token.
        return False, f"{type(e).__name__}: {str(e).replace(token, '<token>')[:110]}"


def _discover_chat_id(token: str) -> tuple:
    """(chat_id, who). Reads it from whatever you last sent the bot.

    getUpdates only returns messages sent AFTER the bot was created, and only
    while no webhook is set -- both true for a fresh bot.
    """
    ok, res = _call(token, "getUpdates", {"limit": "10", "timeout": "0"})
    if not ok:
        return "", f"could not read updates: {res}"
    if not res:
        return "", ("no messages yet — open Telegram, send your bot any "
                    "message (\"hi\" is fine), then run this again")
    for upd in reversed(res):
        msg = upd.get("message") or upd.get("channel_post") or {}
        chat = msg.get("chat") or {}
        if chat.get("id") is not None:
            who = (chat.get("username") or chat.get("first_name")
                   or chat.get("title") or "you")
            return str(chat["id"]), who
    return "", "found updates, but none carried a chat id"


def status() -> int:
    token = secrets_store.get_secret("TELEGRAM_BOT_TOKEN", "")
    chat = secrets_store.get_secret("TELEGRAM_CHAT_ID", "")
    print("Telegram configuration\n")
    if not token:
        print("  TELEGRAM_BOT_TOKEN   NOT SET")
    elif not TOKEN_SHAPE.match(token):
        print("  TELEGRAM_BOT_TOKEN   !! WRONG SHAPE (expected "
              "'<digits>:<35 chars>')")
    else:
        print("  TELEGRAM_BOT_TOKEN   set (hidden, shape looks right)")
    print(f"  TELEGRAM_CHAT_ID     {chat or 'NOT SET'}")

    if not token:
        print("\nRun this without arguments to set it up.")
        return 1

    # Shape is not validity -- ask Telegram. This is the lesson the Twilio
    # path taught expensively: every stored value was well-formed while
    # nothing worked, because nothing ever asked the service itself.
    print("\nChecking against Telegram:")
    ok, res = _call(token, "getMe")
    if not ok:
        print(f"  the token was REJECTED: {res}")
        return 1
    print(f"  bot                @{res.get('username')} ({res.get('first_name')})")
    if not chat:
        print("  chat id            NOT SET — message your bot, then re-run setup")
        return 1
    print("  chat id            set")
    print("\nReady. Try 'test'.")
    return 0


def test() -> int:
    if status():
        return 1
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from skills import telegram_skill as T

    print("\nSending one real message…")
    print(" ", T.notify("This is Argus. Telegram is working end to end."))
    st = T.status()
    if st["last_error"]:
        print("  last error:", st["last_error"])
        return 1
    print("\nCheck your phone. Unlike the phone path, this one is honest: if it")
    print("said 'Sent.' then Telegram accepted and delivered it.")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "status":
        return status()
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        return test()

    print("Set up the ARGUS Telegram bot.\n")
    print("If you have not made the bot yet:")
    print("  1. Open Telegram and message @BotFather")
    print("  2. Send /newbot and follow the two questions")
    print("  3. It replies with a token like 123456789:AAE...\n")

    current = secrets_store.get_secret("TELEGRAM_BOT_TOKEN", "")
    raw = getpass.getpass(
        f"Bot token{' [currently set]' if current else ''}: ").strip()
    token = raw or current
    if not token:
        print("  -> nothing entered; nothing saved.")
        return 1
    if not TOKEN_SHAPE.match(token):
        print("  -> that doesn't look like a bot token. It is the whole "
              "string BotFather sent, digits then a colon then ~35 "
              "characters. NOT saved.")
        return 1

    ok, res = _call(token, "getMe")
    if not ok:
        print(f"  -> Telegram rejected that token: {res}\n  -> NOT saved.")
        return 1
    username = res.get("username")
    print(f"  -> valid: @{username}")

    if raw:
        secrets_store.put_secret("TELEGRAM_BOT_TOKEN", token)
        print("  -> token saved (encrypted under your Windows account)")

    chat = secrets_store.get_secret("TELEGRAM_CHAT_ID", "")
    if chat:
        print(f"  -> chat id already set ({chat})")
    else:
        print(f"\nNow open Telegram, find @{username}, and send it any "
              f"message.")
        input("Press Enter once you have… ")
        chat, who = _discover_chat_id(token)
        if not chat:
            print(f"  -> {who}")
            return 1
        secrets_store.put_secret("TELEGRAM_CHAT_ID", chat)
        print(f"  -> found you ({who}) and saved the chat id")

    print()
    return status()


if __name__ == "__main__":
    sys.exit(main())
