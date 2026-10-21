# Local API reference

main.py defines a loopback FastAPI service for the HUD and local clients.
This inventory describes the routes in this source release. Request and
response fields are defined by the Pydantic models and route handlers in
main.py; the running service also exposes its generated OpenAPI description
at /openapi.json. Do not expose this service to the network.

## Transport and access

- The service is intended to bind to 127.0.0.1.
- /, /v2/, /health, /docs and /openapi.json are public local routes. Static
  assets under /assets/ and /v2/assets/ are also public.
- Other REST routes require the X-Argus-Token header. /ws checks the token
  during its handshake.
- The HTTP guard also checks Origin, rate limits command routes, bounds
  request bodies and sets restrictive browser response headers.
- Authentication of the caller and authorization of a requested host action
  are separate checks. A valid session token alone does not authorize a
  privileged skill.

## HUD, command and operator routes

| Method | Path | Role |
| --- | --- | --- |
| WebSocket | /ws | Push local status and event updates |
| GET | / | Basic served page |
| GET | /v2/ | V2 HUD |
| GET | /v2/assets/{asset_path} | HUD build assets |
| GET | /health | Basic health |
| GET | /ollama-check | Local model availability |
| POST | /command | Handle a typed command |
| POST | /command-stream | Stream a command response |
| POST | /voice-state | Report voice state |
| POST | /hud-awake | Report HUD wake state |
| POST | /unlock | Submit an unlock attempt |
| POST | /lock | Lock ARGUS |
| GET, POST | /timezone | Read or set timezone |
| GET | /auth-status | Authentication status |
| GET, POST | /settings | Read or update settings |
| POST | /settings/reset | Reset supported settings |
| GET | /about | Product and runtime metadata |
| GET | /skills | Registered capability information |
| POST | /clear-memory | Clear supported conversational memory |

## Security, diagnostics and repair

| Method | Path | Role |
| --- | --- | --- |
| GET | /zt | Zero-trust status |
| GET | /face/status | Face-factor status |
| POST | /face/enroll | Enroll a face factor |
| POST | /face/forget | Remove a face factor |
| POST | /face/check | Check a face factor |
| POST | /face/presence | Presence action |
| GET | /audit-log | Audited events |
| GET | /security-report | Detailed security report |
| GET | /security-summary | Concise security summary |
| GET | /threat-report | Defensive monitor report |
| GET | /status | Runtime status |
| GET | /route-trace | Recent command routing trace |
| GET | /telemetry | Sampled system telemetry |
| POST | /repair/offer | Propose a guided repair |
| POST | /repair/apply | Apply an approved repair |
| POST | /repair/cancel | Cancel a repair |

Security state, route policy and authorization can refuse a request even
after transport authentication. Reports reflect available collectors; an
unavailable measurement is not a healthy reading.

## Agents and teams

| Method | Path | Role |
| --- | --- | --- |
| GET | /api/agents | Agent summary |
| GET | /api/agents/jobs | Job list |
| GET | /api/agents/jobs/{job_id} | Job detail |
| POST | /api/agents/{agent_id}/jobs | Submit a job |
| POST | /api/agents/route | Route an objective |
| DELETE | /api/agents/jobs/{job_id} | Cancel a job |
| GET, POST | /api/agents/autonomy | Read or set bounded autonomy |
| GET | /api/agents/dynamic | Dynamic specialist status |
| POST | /api/agents/dynamic/spawn | Request a specialist |
| DELETE | /api/agents/dynamic/{agent_id} | Stop a specialist |
| POST | /api/agents/dynamic/enabled | Change dynamic-agent availability |
| GET | /api/agents/teams | Team list |
| POST | /api/agents/teams/assess | Assess a team objective |
| POST | /api/agents/teams | Start bounded team work |
| GET | /api/agents/teams/{team_id} | Team detail |
| GET | /api/agents/teams/{team_id}/tasks | Team tasks |
| GET | /api/agents/teams/{team_id}/tree | Team structure |
| POST | /api/agents/teams/{team_id}/cancel | Cancel a team |
| GET | /api/agents/manager | Agent manager status |
| POST | /api/agents/manager/goals | Request a managed goal |
| GET | /api/agents/inbox | Operator inbox |
| POST | /api/agents/inbox/{message_id}/reply | Reply to an agent message |
| POST | /api/agents/inbox/{message_id}/read | Mark a message read |
| POST | /api/agents/{agent_id}/chat | Chat with an agent |
| GET | /api/agents/academy | Academy status |
| POST | /api/agents/academy/train | Start training work |
| POST | /api/agents/academy/{agent_id}/cancel | Cancel training work |

Agents can propose, analyze and report. They do not gain authority from the
API route itself; requests still pass the policy and governor applicable to
the selected work. See [Specification](SPECIFICATION.md) and
[Security model](SECURITY_MODEL.md).
