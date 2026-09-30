# Security policy

ARGUS is a personal project and is provided without a security warranty.

Please report vulnerabilities privately through GitHub's **Report a vulnerability** feature. Do not put exploit details or credentials in a public issue.

ARGUS has host-control capabilities. Keep the API bound to loopback, use a local command PIN, and review permissions before enabling skills that affect files, processes, or network access. Integrity checks provide tamper evidence within the local account; they are not a hardware root of trust. Face recognition based on an RGB camera is not sufficient as a sole unlock factor.

Never commit `config.py`, `config_secrets.py`, vault data, API keys, PINs, local databases, generated logs, or voice models. See the README for local setup.
