

import type {
  BackendAuthStatus, BackendSecurityReport, BackendStatus, BackendThreatReport,
  SecurityAuthStatus, SecurityFields, SecurityPosture,
} from '../types/argus';
import type { AgentSnapshot, AgentState, VoiceMode } from '../stores/agent';
import { FaceStatus } from './face';

/* ── agent state (backend /status -> HUD agent enum) ─────────────────────
   The backend's authoritative ambient signals are voice_state, muted and
   pin_pending; task-state transitions arrive separately over WebSocket and
   keep priority in the store layer (tasks.ts). Absence of any signal is
   STANDBY — idle is a real backend state, never UNKNOWN. */
export function mapAgentState(status: BackendStatus | null): AgentSnapshot {
  if (!status) return { state: 'standby', activeCapability: null, voice: 'idle' };
  if (status.pin_pending) return { state: 'waiting_auth', activeCapability: null, voice: 'idle' };
  if (status.muted) return { state: 'standby', activeCapability: null, voice: 'disabled' };
  // 'speaking' is posted by the listener while a spoken reply plays; the agent
  // STATE stays standby (there is no speaking rung), only the voice mode moves.
  const voice: VoiceMode = status.voice_state === 'recording' ? 'listening'
    : status.voice_state === 'thinking' ? 'processing'
    : status.voice_state === 'speaking' ? 'speaking' : 'idle';
  const state: AgentState = status.voice_state === 'recording' ? 'listening'
    : status.voice_state === 'thinking' ? 'understanding' : 'standby';
  return { state, activeCapability: null, voice };
}

/* ── threat posture (backend /threat-report level -> HUD posture) ────────
   The backend's vocabulary is NOMINAL / ELEVATED / CRITICAL (threatmon.overall_level).
   NOMINAL means "nothing detected" — that is the HEALTHY case and maps to
   'normal', never to 'unknown'. UNKNOWN posture is reserved for the
   disconnected/loading states handled by the store layer. */
export function mapThreatPosture(level: string | undefined | null): SecurityPosture {
  const value = String(level ?? '').toUpperCase();
  if (value === 'CRITICAL') return 'critical';
  if (value === 'ELEVATED' || value === 'WARNING') return 'warning';
  if (value === 'NOMINAL') return 'normal';
  return 'unknown';
}

/* ── auth state (backend /auth-status -> HUD auth field) ─────────────────
   The backend model: authentication can be disabled entirely, unlocked,
   or locked (idle timer / explicit lock / lockout). Locked-out is its own
   state and is reported as such — the HUD never invents "expired". */
export function mapAuthState(auth: BackendAuthStatus | null): SecurityAuthStatus {
  if (!auth) return 'unknown';
  if (auth.locked_out) return 'expired';
  if (auth.enabled === false) return 'valid'; // no gate configured: session is inherently valid
  if (auth.unlocked === true) return 'valid';
  if (auth.unlocked === false) return 'required';
  return 'unknown';
}

/* ── security control rows (all four report endpoints) ───────────────────
   Each row states WHICH condition it is rendering. The backend sources are:
     deviceTrust   /security-report integrity.sealed|ok (integrity subsystem)
     policyEngine  /security-report skills.violations (plugin permission audit)
     authLevel     /auth-status (enabled/unlocked/locked_out)
     userPresence  /face/status (presence_watch) + /auth-status (idle lock)
     executor      /security-report sandbox.privileges_held (dropped privileges)
     networkPolicy /security-report network.egress_policy (netpolicy.describe())
     auditChain    /security-report audit.chain_intact (hash chain verify)
     threatState   /threat-report level (threatmon.overall_level()) */
export function mapSecurityFields(
  report: BackendSecurityReport | null,
  threat: BackendThreatReport | null,
  auth: BackendAuthStatus | null,
  face: FaceStatus | null,
): SecurityFields {
  const notReported = 'NOT REPORTED';

  const integrity = report?.integrity;
  const deviceTrust = integrity?.sealed === true
    ? (integrity.ok === false ? 'SEALED · DRIFT' : 'SEALED')
    : integrity?.sealed === false ? 'UNSEALED'
    : integrity == null ? notReported : 'UNKNOWN';

  const violations = report?.skills?.violations;
  const policyEngine = typeof violations === 'number'
    ? (violations === 0 ? 'ENFORCING' : `${violations} VIOLATION${violations === 1 ? '' : 'S'}`)
    : notReported;

  const authLevel = !auth ? notReported
    : auth.enabled === false ? 'DISABLED'
    : auth.locked_out ? 'LOCKED OUT'
    : auth.unlocked === true ? 'UNLOCKED'
    : auth.unlocked === false ? 'LOCKED'
    : 'UNKNOWN';

  // Presence: the face module's own status() is authoritative. When face is
  // unavailable (no camera/enrolment) the backend says so — render that, not
  // a guess. The session idle lock is a separate real signal from /auth-status.
  const userPresence = !face ? notReported
    : face.available === false ? 'FACE OFFLINE'
    : face.presence_watch === true ? 'WATCHING'
    : auth?.idle_lock_seconds ? 'IDLE LOCK' : 'UNMONITORED';

  // Executor: the orchestrator drops its OS privileges at boot (sandbox.py)
  // and reports the count it still holds. 0 held = the hardened state.
  const held = report?.sandbox?.privileges_held;
  const executor = typeof held === 'number'
    ? (held === 0 ? 'MINIMUM PRIVS' : `${held} PRIVS HELD`)
    : notReported;

  const egress = report?.network?.egress_policy;
  const networkPolicy = typeof egress === 'string' && egress ? 'ENFORCED' : notReported;

  const chain = report?.audit?.chain_intact;
  const auditChain = chain === true ? 'INTACT' : chain === false ? 'BROKEN' : notReported;

  const level = String(threat?.level ?? '').toUpperCase();
  const threatState = level || notReported;

  return { deviceTrust, policyEngine, authLevel, userPresence, executor, networkPolicy, auditChain, threatState };
}

/* Disconnected overlay: the transport is down, so every control row reads
   DISCONNECTED — semantically different from any backend-supplied value. */
export function disconnectedFields(): SecurityFields {
  const value = 'DISCONNECTED';
  return { deviceTrust: value, policyEngine: value, authLevel: value, userPresence: value, executor: value, networkPolicy: value, auditChain: value, threatState: value };
}
