# ARGUS specification

This is the public contract of the source release. The code is authoritative
where details differ. Version and defaults are defined in config.example.py.

## Product scope

ARGUS is a local-first Windows assistant for one operator. It accepts typed or
spoken requests, reports local system and security state, and can carry out
registered actions with policy checks. It is designed for a trusted Windows
account and a loopback-only service. It is not designed as a remote control
service, a multi-tenant platform or a replacement for endpoint protection.

## Runtime inputs and outputs

| Input | Processing | Output |
| --- | --- | --- |
| Typed command | Local HTTP command endpoint, routing and authorization | Text response, audit event and optional HUD update |
| Spoken command | Wake handling, speech-to-text, routing and authorization | Speech and HUD response |
| HUD interaction | Authenticated REST or WebSocket request | Updated UI state and audit event |
| Agent objective | Bounded team or plan admission | Proposed work, evidence, status and owner approval where required |
| Host signal | Defensive monitor and security state | Alert, status change or diagnostic report |

Commands are represented as a named capability, action and target. The
capability registry is in skills/registry.py. Router prompts and natural
language patterns are an input method, not an authority source.

## Authorization contract

auth.py assigns each action a level. The default for an unknown pair is
conservative. The levels are:

| Level | Meaning |
| --- | --- |
| L0 | Public or low-risk response without unlocking ARGUS |
| L1 | ARGUS must be unlocked |
| L2 | Fresh authentication is required |
| L3 | Fresh authentication and explicit confirmation |
| L4 | Stronger multi-factor confirmation |
| L5 | Hardware-backed gesture where configured and supported |

Protected actions refuse when a required factor is unavailable. Confirmation
does not alter the action arguments. For approved high-impact actions,
grants.py binds a short-lived grant to a canonical action hash and checks it
immediately before execution. Multi-step plans do not inherit a blanket
permission to run arbitrary new actions.

## Local API

The API is implemented in main.py. These are endpoint families; the
[local API reference](API.md) lists every route in this source release. The
running service also exposes its generated OpenAPI description locally.

| Family | Representative routes | Purpose |
| --- | --- | --- |
| Transport | /ws, /health, /v2/ | HUD events, health and UI |
| Commands | /command, /command-stream | Typed command and streamed response |
| Operator state | /unlock, /lock, /auth-status, /settings | Authentication and preferences |
| Observation | /status, /telemetry, /route-trace | Runtime and machine state |
| Security | /security-report, /security-summary, /threat-report, /audit-log, /zt | Security posture and audit |
| Agents | /api/agents and nested jobs, teams, inbox, academy and manager routes | Bounded agent work and owner interaction |

The service rejects unapproved browser origins, requires the session token on
nonpublic routes, limits command rate and request size, and adds browser
security headers. The WebSocket has its own token check. Keep the bind address
on loopback; changing it changes the threat model.

## State and files

config.example.py is the distributable configuration template. Copy it to
config.py and set local values there. The latter is ignored by Git. User
memory, audit history, keys, tokens, model weights, logs and other runtime
data are stored outside the public source set. The configured vault path is a
local operator choice. See [Security model](SECURITY_MODEL.md) for the
sensitivity of those files.

The repository includes Python source, HUD source, dependency declarations,
build scripts, first-party city models and required HUD media. The voice
weights and an external 3D office pack are omitted. The code-generated HUD
geometry is available when that pack is absent.

## Failure behavior and limits

- An unavailable factor or invalid grant causes the protected action to be
  refused.
- A failed optional verifier cannot authorize an action. Results must not be
  presented as independently verified when verification did not run.
- An unavailable model or integration limits the related capability; it does
  not grant a fallback route around authorization.
- Agent and plan size, step count, time and model use are bounded in code.
- Defensive monitors are sampled observations. Short-lived events can fall
  between samples and a missing signal is not proof of safety.
- The application is distributed as source. No signed Windows installer or
  third-party model weights are included.

For implementation detail, read [Architecture](ARCHITECTURE.md). For the
user-facing capability groups, read [Features](FEATURES.md).
