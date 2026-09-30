import { derived } from 'svelte/store';
import { agent, stateLabels } from './agent';
import { tasks } from './tasks';
import { connection, stale as connectionStale } from './connection';
import { security } from './security';
import { agentOffice } from './agentOffice';
import { teamOffice } from './teamOffice';
import { snapshotStatus } from './snapshotView';
import { academyState } from './academy';



export type DistrictActivity = 'idle' | 'active' | 'attention' | 'critical' | 'offline';

export interface DistrictLive {
  activity: DistrictActivity;
  status: string;
  detail: string[];
}

export interface CityState {
  connected: boolean;
  stale: boolean;
  backendDisconnected: boolean;
  districts: Record<string, DistrictLive>;
}

const IDLE: DistrictLive = { activity: 'idle', status: 'IDLE', detail: [] };
const NO_SIGNAL: DistrictLive = { activity: 'idle', status: 'NO LIVE SIGNAL', detail: [] };

// Core agent id -> home district (agents/definitions.py's 10 core roles,
// matched by id exactly like lib/3d/AgentOffice3D.svelte's ALL_AGENTS does).
const SECURITY_ROLES = new Set(['security', 'threat', 'forensics', 'response']);
const OPERATIONS_ROLES = new Set(['system', 'network', 'diagnostics']);
const VERIFIER_ROLES = new Set(['verifier']);
// Everything else (assistant, planner, ...) is Agent HQ's.

// agentOffice.ts's real OfficeAgent.state vocabulary (its own LABEL_STATE
// map): idle / queued / thinking / responding / waiting_auth / completed /
// error / blocked. There is no 'executing' or 'active' string here -- that
// would be guessing a vocabulary this store never uses.
const ACTIVE_AGENT_STATES = new Set(['thinking', 'responding']);
const WAITING_AGENT_STATES = new Set(['queued', 'waiting_auth']);

function agentActivity(states: string[]): DistrictActivity {
  if (states.some((s) => ACTIVE_AGENT_STATES.has(s))) return 'active';
  if (states.some((s) => s === 'error' || s === 'blocked')) return 'critical';
  if (states.some((s) => WAITING_AGENT_STATES.has(s))) return 'attention';
  return 'idle';
}

export const cityState = derived(
  [agent, tasks, connection, connectionStale, security, agentOffice, teamOffice, snapshotStatus, academyState],
  ([$agent, $tasks, $connection, $stale, $security, $agentOffice, $teamOffice, $status, $academy]): CityState => {
    const backendDisconnected = $connection.source === 'unavailable';
    const connected = $connection.source === 'live' || $connection.source === 'partial';

    const districts: Record<string, DistrictLive> = {};

    // ── ARGUS CORE TOWER -- overall runtime state + active goal (§6) ──────
    const coreActivity: DistrictActivity =
      $agent.state === 'lockdown' || $agent.state === 'error' ? 'critical'
      : $agent.state === 'blocked' || $agent.state === 'warning' ? 'attention'
      : $agent.state === 'waiting_auth' ? 'attention'
      : ['listening', 'understanding', 'planning', 'executing', 'verifying'].includes($agent.state) ? 'active'
      : 'idle';
    districts['core-tower'] = {
      activity: coreActivity,
      status: stateLabels[$agent.state],
      detail: $tasks.goal ? [`GOAL: ${$tasks.goal}`] : [],
    };

    // ── core-agent-role districts: AGENT HQ / SECURITY / OPERATIONS / VERIFICATION (§7-10) ──
    // link, not loaded: agentOffice.ts sets loaded=true on a FAILED fetch too
    // (it means "we attempted", not "we have data") -- link is the field that
    // actually distinguishes a confirmed empty/idle result from no result.
    const officeReady = $agentOffice.link === 'online' || $agentOffice.link === 'degraded';
    const officeOffline = $agentOffice.link === 'offline';
    const agentsById = new Map(($agentOffice.snapshot?.agents ?? []).map((a) => [a.id, a]));
    function roleDistrict(ids: Set<string>, name: string): DistrictLive {
      if (!officeReady) return officeOffline ? { activity: 'offline', status: 'OFFLINE', detail: [] } : NO_SIGNAL;
      const members = [...ids].map((id) => agentsById.get(id)).filter((a): a is NonNullable<typeof a> => !!a);
      if (!members.length) return NO_SIGNAL;
      const activity = agentActivity(members.map((a) => a.state));
      const working = members.filter((a) => ACTIVE_AGENT_STATES.has(a.state));
      const waiting = members.filter((a) => WAITING_AGENT_STATES.has(a.state));
      const notable = activity === 'critical' ? members.filter((a) => a.state === 'error' || a.state === 'blocked') : working.length ? working : waiting;
      const status = activity === 'idle' ? 'IDLE'
        : working.length ? `${working.length} ACTIVE`
        : activity === 'critical' ? `${notable.length} ${notable[0]?.state.toUpperCase() ?? 'ERROR'}`
        : `${waiting.length} WAITING`;
      return { activity, status, detail: notable.length ? [`${name}: ${notable.map((a) => a.id.toUpperCase()).join(', ')}`] : [] };
    }
    const allCoreIds = new Set(agentsById.keys());
    const hqIds = new Set([...allCoreIds].filter((id) => !SECURITY_ROLES.has(id) && !OPERATIONS_ROLES.has(id) && !VERIFIER_ROLES.has(id)));
    districts['agent-hq'] = roleDistrict(hqIds, 'ACTIVE');
    districts['security-district'] = roleDistrict(SECURITY_ROLES, 'ACTIVE');
    districts['operations-center'] = roleDistrict(OPERATIONS_ROLES, 'ACTIVE');

    // Security District also reflects the real security posture (§8), which
    // can ESCALATE the color even when no security-role agent is currently
    // running a job (e.g. a threatmon detection with no active investigation).
    // Posture only ever escalates, never overwrites a more specific
    // agent-driven status with a plainer posture word.
    const securityNow = districts['security-district'];
    if ($security.posture === 'critical' || $security.posture === 'blocked' || $security.posture === 'lockdown') {
      districts['security-district'] = { ...securityNow, activity: 'critical', status: $security.posture.toUpperCase() };
    } else if (($security.posture === 'degraded' || $security.posture === 'warning' || $security.posture === 'recovery') && securityNow.activity !== 'critical') {
      districts['security-district'] = { ...securityNow, activity: 'attention', status: $security.posture.toUpperCase() };
    }

    // ── VERIFICATION INSTITUTE -- verifier agent + active team's phase (§10) ──
    const verifierDistrict = roleDistrict(VERIFIER_ROLES, 'ACTIVE');
    const activeTeam = $teamOffice.activeTeam;
    if (activeTeam?.current_phase === 'verifying') {
      districts['verification-institute'] = { activity: 'active', status: 'VERIFYING', detail: [`TEAM: ${activeTeam.team_id}`] };
    } else if (activeTeam && ['FAILED', 'PARTIAL', 'CANCELLED', 'TIMED_OUT'].includes(activeTeam.state) && activeTeam.verdict) {
      districts['verification-institute'] = { activity: 'attention', status: activeTeam.verdict.toUpperCase(), detail: [`TEAM: ${activeTeam.team_id}`] };
    } else {
      districts['verification-institute'] = verifierDistrict;
    }

    // ── SPECIALIST DISTRICT -- temp LOCAL agent lifecycle (§11) ────────────
    // Same link-vs-loaded distinction as officeReady above.
    const teamReady = $teamOffice.link === 'online' || $teamOffice.link === 'degraded';
    const teamOffline = $teamOffice.link === 'offline';
    const localTemps = $teamOffice.dynamicAgents.filter((a) => a.type === 'EPHEMERAL_LOCAL');
    if (!teamReady) {
      districts['specialist-district'] = teamOffline ? { activity: 'offline', status: 'OFFLINE', detail: [] } : NO_SIGNAL;
    } else if (!localTemps.length) {
      districts['specialist-district'] = IDLE;
    } else {
      const active = localTemps.filter((a) => a.state === 'ACTIVE');
      districts['specialist-district'] = {
        activity: active.length ? 'active' : 'attention',
        status: `${localTemps.length} SPECIALIST${localTemps.length === 1 ? '' : 'S'} · ${active.length} ACTIVE`,
        detail: localTemps.slice(0, 3).map((a) => `${a.role || a.name}: ${a.state}`),
      };
    }

    // ── CLOUD EMBASSY -- temp CLOUD agent lifecycle (§13) ───────────────────
    const cloudTemps = $teamOffice.dynamicAgents.filter((a) => a.type === 'EPHEMERAL_CLOUD');
    if ($status?.cloud_enabled === false) {
      districts['cloud-embassy'] = { activity: 'idle', status: 'UNAVAILABLE', detail: ['Cloud specialists disabled'] };
    } else if (!teamReady) {
      districts['cloud-embassy'] = teamOffline ? { activity: 'offline', status: 'OFFLINE', detail: [] } : NO_SIGNAL;
    } else if (!cloudTemps.length) {
      districts['cloud-embassy'] = IDLE;
    } else {
      const active = cloudTemps.filter((a) => a.state === 'ACTIVE');
      const failed = cloudTemps.filter((a) => a.state === 'FAILED');
      districts['cloud-embassy'] = {
        activity: active.length ? 'active' : failed.length ? 'attention' : 'idle',
        status: active.length ? `${active.length} ACTIVE` : failed.length ? (failed[0].termination_reason || 'FAILED').toUpperCase() : 'IDLE',
        detail: cloudTemps.slice(0, 3).map((a) => `${a.role || a.name}: ${a.state}`),
      };
    }

    // ── MODEL POWER STATION -- shared local model + queue (§14) ────────────
    const model = $agentOffice.snapshot?.model ?? null;
    if (!officeReady || !model) {
      districts['model-plant'] = officeOffline ? { activity: 'offline', status: 'OFFLINE', detail: [] } : NO_SIGNAL;
    } else if (!model.available) {
      districts['model-plant'] = { activity: 'attention', status: 'UNAVAILABLE', detail: [model.last_error].filter(Boolean) };
    } else {
      const queueDepth = $agentOffice.snapshot?.queue_depth ?? 0;
      // One shared runtime (MAX_HEAVY_MODEL_INFERENCE=1): who holds it, and
      // who is WAITING_FOR_MODEL behind it -- both read from the snapshot.
      const agents = $agentOffice.snapshot?.agents ?? [];
      const running = model.active_job ? agents.find((a) => a.current_job_id === model.active_job) : undefined;
      const waiting = agents.filter((a) => a.state === 'queued').map((a) => a.id.toUpperCase());
      districts['model-plant'] = {
        activity: model.busy ? 'active' : queueDepth > 0 ? 'attention' : 'idle',
        status: model.busy ? `RUNNING${queueDepth ? ` · ${queueDepth} WAITING` : ''}`
          : queueDepth > 0 ? `QUEUED · ${queueDepth}` : 'IDLE',
        detail: [`MODEL: ${model.model_id}`,
          ...(running ? [`IN USE BY: ${running.id.toUpperCase()}`] : []),
          ...(waiting.length ? [`WAITING FOR MODEL: ${waiting.join(', ')}`] : [])],
      };
    }

    // ── POLICY / AUTH GATE (§15) ────────────────────────────────────────────
    const decision = $security.decision;
    if ($agent.state === 'waiting_auth' || decision?.status === 'waiting_auth' || $security.auth === 'required' || $security.auth === 'expired') {
      districts['policy-gate'] = { activity: 'attention', status: $security.auth === 'expired' ? 'AUTH_FAILED' : 'AUTH_REQUIRED', detail: [] };
    } else if (decision?.policy === 'deny') {
      districts['policy-gate'] = { activity: 'critical', status: 'DENIED', detail: decision.capability ? [decision.capability] : [] };
    } else if ($security.auth === 'valid') {
      districts['policy-gate'] = { activity: 'idle', status: 'OPEN', detail: [] };
    } else {
      districts['policy-gate'] = connected ? IDLE : { activity: 'offline', status: 'OFFLINE', detail: [] };
    }

    // ── CAPABILITY CENTER -- real execution state only (§16) ───────────────
    if ($agent.state === 'executing') {
      districts['capability-center'] = { activity: 'active', status: 'EXECUTING', detail: $tasks.activeCapability ? [$tasks.activeCapability] : [] };
    } else if ($agent.state === 'verifying') {
      districts['capability-center'] = { activity: 'active', status: 'VERIFYING', detail: [] };
    } else if (decision?.policy === 'deny' || decision?.status === 'blocked') {
      districts['capability-center'] = { activity: 'critical', status: 'DENIED', detail: [] };
    } else {
      districts['capability-center'] = connected ? IDLE : { activity: 'offline', status: 'OFFLINE', detail: [] };
    }

    // ── ACADEMY -- only sessions reported by the authenticated backend ─────
    if ($academy.link !== 'online' || !$academy.snapshot) {
      districts['academy'] = $academy.link === 'offline'
        ? { activity: 'offline', status: 'OFFLINE', detail: [] } : NO_SIGNAL;
    } else {
      const sessions = $academy.snapshot.sessions;
      const active = sessions.filter((s) => s.state === 'ACTIVE');
      const evaluating = sessions.filter((s) => s.state === 'EVALUATING');
      const queued = sessions.filter((s) => s.state === 'SCHEDULED' || s.state === 'QUEUED');
      // Everyone with an open session is AT the Academy (the city draws them
      // there); one studies at a time on the shared model, the rest wait.
      const present = active.length + evaluating.length + queued.length;
      districts['academy'] = {
        activity: active.length || evaluating.length ? 'active' : queued.length ? 'attention' : 'idle',
        status: present ? `${present} AT ACADEMY · ${active.length} STUDYING`
          + (evaluating.length ? ` · ${evaluating.length} BEING CHECKED` : '') : 'IDLE',
        detail: [...active, ...evaluating, ...queued].slice(0, 10)
          .map((s) => `${s.agent_id.toUpperCase()}: ${s.curriculum} · ${s.state}`),
      };
    }
    // No Data Vault backend is exposed; keep it honest.
    districts['data-vault'] = NO_SIGNAL;

    // Any non-live transport overrides every district's color to muted grey
    // (§5/§22): never claim IDLE -- or, worse, a STICKY 'critical'/'active'
    // left over from before the link dropped -- for state that isn't
    // currently confirmed. This is broader than backendDisconnected on
    // purpose: 'stale' (a lost poll after a previously healthy session)
    // leaves agent.state exactly where it was, which core-tower otherwise
    // has no other way to know is no longer trustworthy.
    if (!connected) {
      for (const id of Object.keys(districts)) districts[id] = { ...districts[id], activity: 'offline' };
    }

    return { connected, stale: $stale, backendDisconnected, districts };
  },
);
