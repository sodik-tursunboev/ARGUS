import { get } from 'svelte/store';
import { fetchHudSnapshot, fetchStatus, fetchAuthStatus, fetchFaceStatus, ApiError } from '../services/api';
import { agent, setAgentSnapshot, type AgentState } from './agent';
import { connection } from './connection';
import { security, setSecuritySnapshot, patchSecurity } from './security';
import { telemetry } from './telemetry';
import { authStatus, securityReport, snapshotStatus, threatReport } from './snapshotView';
import { faceStatus } from './snapshotView';
import { refreshSpeechConfig } from './voice';
import { mapAgentState, mapAuthState, mapSecurityFields, mapThreatPosture, disconnectedFields } from '../lib/adapters';
import { normalizeDetections } from '../lib/threat';
import type { BackendAuthStatus, BackendStatus, HudSnapshot, SecurityFreshness } from '../types/argus';
import type { FaceStatus } from '../lib/face';

let timer: number | null = null;
let stopped = false;

/* Per-endpoint REST freshness. A backend restart takes ALL of these down
   together (same origin), so a full DISCONNECTED transition is correct there;
   a single failed poll inside a healthy session degrades that endpoint only
   (partial), instead of blanking already-verified data. */
function freshnessOf(snapshot: HudSnapshot): SecurityFreshness {
  if (snapshot.security && snapshot.threat) return 'live';
  if (snapshot.security || snapshot.threat) return 'partial';
  return 'unavailable';
}

function apply(snapshot: HudSnapshot) {
  telemetry.set(snapshot.telemetry);
  snapshotStatus.set(snapshot.status);
  securityReport.set(snapshot.security);
  threatReport.set(snapshot.threat);
  faceStatus.set(snapshot.face);
  authStatus.set(snapshot.auth);
  setAgentSnapshot(mapAgentState(snapshot.status));
  // No existing REST route exposes a redacted task contract. Never erase
  // task state supplied by a later live-event adapter with an empty snapshot.
  const alerts = snapshotAlerts(snapshot);
  setSecuritySnapshot({
    posture: mapThreatPosture(snapshot.threat?.level ?? snapshot.telemetry?.threat?.level),
    link: 'online',
    auth: mapAuthState(snapshot.auth),
    freshness: freshnessOf(snapshot),
    fields: mapSecurityFields(snapshot.security, snapshot.threat, snapshot.auth, snapshot.face),
    decision: null,
    alerts,
    recoveryPossible: null,
    updatedAt: Date.now(),
  });
  // Transport truth lives HERE, once per successful snapshot: a full or
  // partial result both mean the backend was reached (live/partial);
  // everything else is owned by the failure path below.
  connection.update((current) => ({
    ...current,
    source: snapshot.status && snapshot.telemetry ? 'live' : 'partial',
    lastSuccessAt: Date.now(), message: null, retryCount: 0,
  }));
  // Speech configuration (STT model / TTS voice) rides its own throttled read.
  if (snapshot.status) void refreshSpeechConfig();
}

/* Recent alerts come ONLY from the backend's documented recent-detections
   list (threatmon /threat-report `recent`, capped at 10 by the backend; the
   HUD takes 8). Every entry must carry an authoritative severity string.
   The "counts" object on the same response is keyed by MITRE technique id,
   NOT severity, and must never be tallied for this row. Field handling
   (ts / at_epoch / at) lives in lib/threat.ts, shared with the charts. */
function snapshotAlerts(snapshot: HudSnapshot) {
  return normalizeDetections(snapshot.threat?.recent).slice(0, 8)
    .map((d) => ({ id: d.id, severity: d.severity.toUpperCase(), label: d.label, timestamp: d.stamp }));
}

export async function bootstrapSnapshot(): Promise<void> {
  connection.update((current) => ({ ...current, source: current.lastSuccessAt ? 'stale' : 'loading', lastAttemptAt: Date.now(), message: null }));
  try { apply(await fetchHudSnapshot()); }
  catch (error) {
    const message = error instanceof ApiError ? error.message : 'Backend is unavailable';
    const hadData = get(connection).lastSuccessAt !== null;
    connection.update((current) => ({ ...current, source: hadData ? 'stale' : 'unavailable', message, retryCount: current.retryCount + 1 }));
    if (!hadData) {
      // Never had a successful exchange: nothing on screen is trustworthy,
      // so the whole security surface reads DISCONNECTED (not UNAVAILABLE —
      // the backend never said that; it was never reached at all).
      setAgentSnapshot({ state: 'error', activeCapability: null, voice: 'disabled' });
      setSecuritySnapshot({
        posture: 'unknown', link: 'offline', auth: 'unknown', freshness: 'unavailable',
        fields: disconnectedFields(), decision: null, alerts: [], recoveryPossible: null, updatedAt: null,
      });
    } else {
      // A healthy session that just lost one poll: keep the last verified
      // values, mark them stale, and let the next poll recover them.
      setSecuritySnapshot({ ...get(security), freshness: 'stale', link: 'offline', updatedAt: get(security).updatedAt });
    }
  }
}

/* ── FAST LANE ────────────────────────────────────────────────────────────
   The full snapshot is six requests (one of them, /security-report, re-verifies
   the integrity manifest), so with the live socket up it only re-runs every 60 s.
   The backend socket carries telemetry, auth.state, security.state and
   security.alert -- NOT voice or lock state -- so on its own the HUD would show
   "LISTENING" up to a minute late and keep saying UNLOCKED for up to a minute
   after the idle auto-lock. /status and /auth-status are both O(1) reads of
   in-memory dicts, so they are polled every few seconds (visible window only).
   The lane is purely additive: it never touches connection/transport state
   (a failed poll is ignored; the full snapshot owns that), and it only moves
   agent STATE between the states the voice pipeline owns, so it can never
   overwrite waiting_auth / blocked / lockdown / a running task. */
const FAST_MS = 3_000;
let fastTimer: number | null = null;
const VOICE_OWNED = new Set<AgentState>(['standby', 'listening', 'understanding']);

/** Shallow compare that ignores uptime_seconds (it changes every call and nothing on the fast lane displays it). */
function sameStatus(a: BackendStatus | null, b: BackendStatus): boolean {
  if (!a) return false;
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const k of keys) if (k !== 'uptime_seconds' && (a as Record<string, unknown>)[k] !== (b as Record<string, unknown>)[k]) return false;
  return true;
}

async function pollFast(): Promise<void> {
  if (get(connection).lastSuccessAt === null) return;          // nothing to refresh until a full snapshot has landed
  const [status, auth] = await Promise.allSettled([fetchStatus(), fetchAuthStatus()]);
  if (status.status === 'fulfilled') {
    const next = status.value;
    if (!sameStatus(get(snapshotStatus), next)) snapshotStatus.update((current) => ({ ...(current ?? {}), ...next }));
    const mapped = mapAgentState(next);
    const current = get(agent);
    const state = VOICE_OWNED.has(current.state) && mapped.state !== 'waiting_auth' ? mapped.state : current.state;
    if (state !== current.state || mapped.voice !== current.voice) setAgentSnapshot({ ...current, state, voice: mapped.voice });
  }
  if (auth.status === 'fulfilled') applyAuth(auth.value);
}

/** Publish a /auth-status reading (only when something the UI shows actually changed). */
function applyAuth(next: BackendAuthStatus): void {
  const before = get(authStatus);
  if (before && before.enabled === next.enabled && before.unlocked === next.unlocked && before.locked_out === next.locked_out && before.lockout_seconds === next.lockout_seconds && before.idle_lock_seconds === next.idle_lock_seconds) return;
  authStatus.set(next);
  patchSecurity({ auth: mapAuthState(next), fields: mapSecurityFields(get(securityReport), get(threatReport), next, get(faceStatus)), updatedAt: Date.now() });
}

/** Re-read the lock state right now (after an unlock attempt, or when the Authentication page opens). Never throws. */
export async function refreshAuthNow(): Promise<void> {
  try { applyAuth(await fetchAuthStatus()); } catch { /* the next poll retries; a failed read never invents a state */ }
}

/** Re-read face enrolment / presence right now. Never throws. */
export async function refreshFaceNow(): Promise<void> {
  try {
    const next = (await fetchFaceStatus()) as FaceStatus;
    faceStatus.set(next);
    patchSecurity({ fields: mapSecurityFields(get(securityReport), get(threatReport), get(authStatus), next), updatedAt: Date.now() });
  } catch { /* keep the last reading */ }
}

function scheduleFast(): void {
  if (stopped) return;
  fastTimer = window.setTimeout(async () => {
    if (document.visibilityState === 'visible') { try { await pollFast(); } catch { /* the full snapshot owns failure reporting */ } }
    scheduleFast();
  }, FAST_MS);
}

export function startSnapshotPolling(): () => void {
  stopped = false;
  const poll = async (): Promise<void> => {
    await bootstrapSnapshot();
    if (stopped) return;
    // REST remains the recovery channel, but an established live channel does
    // not need a second full snapshot every ten seconds.
    const delay = get(connection).socket === 'connected' ? 60_000 : 10_000;
    timer = window.setTimeout(() => void poll(), delay);
  };
  void poll();
  scheduleFast();
  // coming back to the window: catch up immediately rather than wait out the interval
  const onVisible = (): void => { if (document.visibilityState === 'visible') void pollFast().catch(() => undefined); };
  document.addEventListener('visibilitychange', onVisible);
  return () => {
    stopped = true;
    if (timer !== null) { window.clearTimeout(timer); timer = null; }
    if (fastTimer !== null) { window.clearTimeout(fastTimer); fastTimer = null; }
    document.removeEventListener('visibilitychange', onVisible);
  };
}
