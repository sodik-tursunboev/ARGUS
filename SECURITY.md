# Security policy

ARGUS is a personal source project with host-control capabilities. It is
provided without a security warranty. Read the [security model](docs/SECURITY_MODEL.md)
for the threat boundaries, implemented controls and known limits before using
it on a machine that contains sensitive data.

## Report a vulnerability

Use GitHub's **Report a vulnerability** feature for a private report. Include
the affected commit or version, the feature involved, reproducible steps and
the impact. Do not place exploit details, credentials or private files in a
public issue. No response-time or disclosure SLA is promised.

## Safe deployment

Keep the API bound to loopback, configure a local command PIN, and review
permissions before enabling actions that affect files, processes, the network
or external providers. Do not commit config.py, config_secrets.py, vault
contents, API keys, PINs, session tokens, databases, logs or voice models.
Use the ignored local configuration and secrets store described in
[Setup and build](docs/BUILD.md).
