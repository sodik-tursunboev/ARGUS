# Phone setup

ARGUS can place an outbound call through Twilio when the phone skill is configured. The app remains bound to loopback; it does not accept incoming calls from Twilio.

1. Create a Twilio account and obtain a number that can call your destination.
2. Run `python tools/set_phone_secrets.py` and enter the Account SID, auth token, sender number, and destination number when prompted. Values are stored locally; do not put them in source files or shell arguments.
3. On a trial account, create a TwiML Bin in Twilio and set its URL using `python tools/set_phone_secrets.py bin`.
4. Run `python tools/set_phone_secrets.py status` to check the account. To place one real test call, run `python tools/set_phone_secrets.py test`. A test call may incur charges.

The `alert()` path uses a fixed, content-free message so security findings are not spoken through the phone provider. Calls are rate limited and respect quiet hours, except for critical alerts. Incoming call support is not implemented.
