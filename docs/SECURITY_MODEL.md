# ARGUS security model

ARGUS can read local information and act on the Windows host. Its model output
is treated as untrusted input. These controls are implemented in code, but
they do not make ARGUS secure against every local attacker.

## Threat model and trust boundaries

ARGUS is intended for one Windows operator on one machine. The risks include
a second person speaking near the microphone, replayed audio, a browser page
trying to reach the local API, accidental model output, untrusted web content,
an unsafe action target, a compromised integration and modification of local
application files. The controls restrict these paths and record outcomes.

A process already executing as the same Windows user can often read or change
the assistant's local files, configuration and token. Process-local checks,
including ARGUS's lock and integrity verifier, cannot be a hardware root of
trust against that attacker. The optional elevated helper has a narrower role
and a separate IPC boundary.

| Boundary | Enforcement point | Practical limit |
| --- | --- | --- |
| Browser to service | main.py origin allowlist, token, rate/body limits and response headers | Same-user software may access local user-readable material. |
| Model to action | router.py dispatch, auth.py levels, plan validation, grants.py | Correctness still depends on each action implementation. |
| Skill to OS/network | plugins.py, sandbox.py, execpolicy.py, netpolicy.py | Static checks do not prove all runtime behavior safe. |
| Optional cloud use | skills/cloud_gate.py and netpolicy.py | Permitted content leaves the machine for a provider. |
| Local files to verifier | integrity.py and security.py audit chain | Code, manifest and local keys share a user trust domain. |

## Local API and HUD

The service is designed to bind to 127.0.0.1. main.py rejects browser origins
outside a small local allowlist. Nonpublic REST calls require a session token;
the WebSocket checks it too. The token is generated for the local session and
published to a user-scoped file, not compiled into the HUD bundle. Command
endpoints are rate limited and request bodies bounded. The service adds a
Content Security Policy and other restrictive response headers.

Static HUD assets and health are public locally. They must not contain private
state. Do not widen the bind address, origin list or public-route list without
reviewing the threat model. A loopback service still needs token checks because
other programs on the machine can connect to loopback.

## Authentication and authorization

auth.py keeps unlock state in memory and relocks on configured idle and
Windows session events. The example configuration enables a PIN and
Windows-account binding. The PIN is stored as a salted hash when set through
manage_secrets.py. Optional factors include voice liveness, face, TPM
presence and a Windows Hello gesture where supported. A presence-only factor
does not replace the knowledge factor. Failed attempts have backoff and
uniform failure responses.

Every action has a static authorization level from L0 through L5. Unknown
actions default to a protected level. Levels can require an unlocked session,
fresh authentication, explicit confirmation, multiple factors or a
hardware-backed gesture. A model response cannot lower an action's level.
auth.py is the central decision point; router.py invokes it before the skill.
Security state and zero-trust checks can refuse or require more, never grant
an action that static policy denied.

Sensitive confirmation is tied to the skill, action and target. grants.py
issues short-lived, limited-use grants bound to a canonical action hash.
A changed target or stale approval cannot be redeemed as the original action.
Plan steps are checked separately, and a new alternative is staged for the
operator rather than silently executed.

## Security state and recovery

security_state.py defines NORMAL, DEGRADED, SAFE_MODE, LOCKDOWN and RECOVERY.
Transitions come from deterministic findings or authenticated owner actions,
not a model instruction. Safe mode retains narrow diagnostics. Lockdown
revokes outstanding grants and blocks sensitive execution. Recovery requires
the owner and verification of the repaired state. A failure to verify remains
visible as a failure; it must not become an implicit healthy state.

## Network, secrets and local data

netpolicy.py assigns each component a fixed, open or no-network class and
denies unknown components by default. Components with network access have
their own destination and data rules. The cloud gate separates public/general
work from local-private data. Credentials for optional integrations stay in
environment variables or the local secrets store, never in source files.

Do not publish config.py, config_secrets.py, the vault, API keys, PINs,
session tokens, audit logs, databases, screenshots, voice data or model
weights. This repository ships config.example.py with placeholders. The
Git ignore list guards against accidental staging; it is not a security scan.
Review the exact staged files and reachable Git history before a public push.

## Host containment, integrity and audit

sandbox.py attempts to remove Windows privileges the main orchestrator does
not need. execpolicy.py restricts subprocess execution. plugins.py checks
declared skill permissions against static source analysis. These are useful
layers, but not an OS isolation boundary for every skill.

integrity.py checks a protected file manifest and can monitor for changes.
security.py maintains an audit chain and reports security events. Both help
detect changes within their coverage. They cannot guarantee integrity when
an attacker can modify the application, verifier and locally held keys. The
frozen package has exclusions, including third-party binaries; consult the
implementation before using a report as evidence of complete file coverage.

Threat monitors sample selected persistence, process, privacy, USB, network
and LSASS-handle signals. Short-lived events may be missed between samples.
Some collectors need Windows APIs, permissions or the optional elevated
helper. An unavailable collector must be reported as unavailable or degraded,
never as clean.

## Known limits

- Face matching through an ordinary RGB camera is not a reliable sole
  identity or liveness factor.
- Voice replay detection covers a limited set of authentication and
  confirmation utterances; it cannot authenticate every spoken command.
- Same-user code execution can compromise local configuration, tokens,
  model output and audit material.
- Local integrity is tamper evidence, not a hardware-backed trust root.
- Unsigned source-built executables may trigger Windows warnings.
- Optional cloud, phone, search and messaging integrations transmit data
  to providers when used; local-first does not mean offline in those modes.
- Monitoring coverage is partial and time-sampled. No report proves the
  machine is free of compromise.

For private vulnerability reporting, see [Security policy](../SECURITY.md).
For implementation layout, see [Architecture](ARCHITECTURE.md).
