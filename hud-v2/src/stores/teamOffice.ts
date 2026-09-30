import { writable, derived, get } from 'svelte/store';
import { fetchAgentTeams, fetchAgentTeam, fetchDynamicAgents, cancelAgentTeam, ApiError } from '../services/api';
import type { TeamSummary, TeamDetail, DynamicAgentView } from '../types/argus';
import type { TeamLifecycleEvent, DynamicAgentLifecycleEvent } from '../lib/teamEvents';



export type OfficeLink = 'loading' | 'online' | 'degraded' | 'offline';

interface TeamOfficeState {
  link: OfficeLink;
  loaded: boolean;
  teams: TeamSummary[];
  activeTeamId: string | null;
  activeTeam: TeamDetail | null;
  dynamicAgents: DynamicAgentView[];
  selected: { kind: 'core' | 'temp' | 'team_member'; id: string } | null;
  lastError: string | null;
  statusMeta: { active_teams: number; states: Record<string, number>; wired: boolean } | null;
  // CITY-3: last real team.handoff (agents/team_events.py), for the Agent HQ
  // interior's transient handoff-pulse animation -- mirrors agentOffice.ts's
  // own `handoff` field for the Phase-1 core-agent case exactly. Transient by
  // design: it is not part of TeamDetail/TeamMemberView, just the most
  // recent handoff event's from/to pair, for a component to diff its `ts`
  // against and fire a one-shot visual pulse.
  lastHandoff: { from: string; to: string; ts: number } | null;
}

export const teamOffice = writable<TeamOfficeState>({
  link: 'loading',
  loaded: false,
  teams: [],
  activeTeamId: null,
  activeTeam: null,
  dynamicAgents: [],
  selected: null,
  lastError: null,
  statusMeta: null,
  lastHandoff: null,
});

// agents/team_schema.py's TeamState: non-terminal = everything but
// TEAM_TERMINAL (COMPLETED/PARTIAL/FAILED/CANCELLED/TIMED_OUT).
const NON_TERMINAL = new Set(['PLANNING', 'READY', 'RUNNING', 'VERIFYING', 'REPLANNING']);

/** The team the office should show: the newest non-terminal team, else the
 * most recently finished one so a just-completed run stays visible. */
function pickActiveTeam(teams: TeamSummary[]): string | null {
  const active = teams.filter((t) => NON_TERMINAL.has(t.state));
  if (active.length) return active.sort((a, b) => b.created_at - a.created_at)[0].team_id;
  if (teams.length) return teams.sort((a, b) => (b.finished_at || b.created_at) - (a.finished_at || a.created_at))[0].team_id;
  return null;
}

export async function refreshTeamOffice(): Promise<void> {
  try {
    const [teamsResp, dynSnapshot] = await Promise.all([
      fetchAgentTeams(),
      fetchDynamicAgents().catch(() => ({ agents: [], recent: [], tree: [] })),
    ]);
    const activeTeamId = pickActiveTeam(teamsResp.teams);
    const activeTeam = activeTeamId ? await fetchAgentTeam(activeTeamId) : null;
    teamOffice.update((current) => ({
      ...current,
      link: 'online',
      loaded: true,
      lastError: null,
      teams: teamsResp.teams,
      statusMeta: { active_teams: teamsResp.active_teams, states: teamsResp.states, wired: teamsResp.wired },
      activeTeamId,
      activeTeam,
      dynamicAgents: dynSnapshot.agents,
    }));
  } catch (error) {
    teamOffice.update((current) => ({
      ...current,
      link: 'offline',
      loaded: true,
      lastError: error instanceof ApiError ? error.message : 'Agent team control link unavailable',
    }));
  }
}

export function markTeamOfficeDegraded(): void {
  teamOffice.update((c) => (c.link === 'online' ? { ...c, link: 'degraded' } : c));
}

/* ---- live WS patching --------------------------------------------------
   A team.* event patches only what it carries; the team's full shape (tree,
   members, tasks) is re-pulled from REST rather than reconstructed from a
   partial event, so one missed event can't leave the tree stale forever. A
   light poll (see AgentOffice.svelte) is the safety net for missed events;
   this patch keeps the common case (state/progress ticking) instant. */
export function applyTeamEvent(e: TeamLifecycleEvent): void {
  const current = get(teamOffice);
  if (!current.activeTeamId || current.activeTeamId !== e.teamId) {
    // A different (or new) team just became relevant -- pull it fully.
    if (e.type === 'team.created' || e.type === 'team.started') void refreshTeamOffice();
    return;
  }
  const TERMINAL_TYPES = new Set(['team.completed', 'team.failed', 'team.cancelled', 'team.timed_out', 'team.partial']);
  if (TERMINAL_TYPES.has(e.type)) { void refreshTeamOffice(); return; }
  teamOffice.update((c) => {
    if (!c.activeTeam || c.activeTeam.team_id !== e.teamId) return c;
    const patch: Partial<TeamDetail> = {};
    if (e.state) patch.state = e.state;
    if (typeof e.progress === 'number') patch.progress = e.progress;
    if (e.type === 'team.plan_created') void refreshTeamOffice();
    const lastHandoff = e.type === 'team.handoff' && e.fromAgent && e.toAgent
      ? { from: e.fromAgent, to: e.toAgent, ts: Date.now() } : c.lastHandoff;
    return { ...c, activeTeam: { ...c.activeTeam, ...patch }, lastHandoff };
  });
  // Task/agent/verification-shaped events change the tree/members shape;
  // a full re-pull keeps 3D connections and the temp roster honest.
  const STRUCTURAL = new Set([
    'team.task_started', 'team.task_completed', 'team.task_failed',
    'team.agent_spawned', 'team.handoff', 'team.verification_started',
    'team.verification_completed', 'team.replanned',
  ]);
  // ponytail: a full re-fetch (not an in-place tree/member patch) on every
  // structural event. Reconstructing _tree()'s parent-child shape from
  // partial event deltas client-side would duplicate real orchestrator
  // logic and risk drifting from it; ARGUS is single-user/local scale, so a
  // few small GETs per task transition is cheap. Upgrade to incremental
  // patching only if a real team's event volume ever makes this visible.
  if (STRUCTURAL.has(e.type)) void refreshTeamOffice();
}

export function applyDynamicAgentEvent(e: DynamicAgentLifecycleEvent): void {
  if (e.type === 'agent.spawned' || e.type === 'agent.destroyed' || e.type === 'agent.expired') {
    void refreshDynamicAgents();
    return;
  }
  if (!e.agentId) return;
  teamOffice.update((c) => ({
    ...c,
    dynamicAgents: c.dynamicAgents.map((a) => (a.id === e.agentId && e.state ? { ...a, state: e.state as string } : a)),
  }));
}

export async function refreshDynamicAgents(): Promise<void> {
  try {
    const snapshot = await fetchDynamicAgents();
    teamOffice.update((c) => ({ ...c, dynamicAgents: snapshot.agents }));
  } catch { /* link state owns the error surface */ }
}

/* ---- selection (unifies core Phase-1 agents, temp/cloud agents and team
   members for the one detail panel; mutually exclusive with agentOffice's
   own selectedAgentId -- selecting here clears that one and vice versa via
   the component, since only one detail panel is shown at a time) ---- */
export function selectTeamEntity(kind: 'core' | 'temp' | 'team_member', id: string): void {
  teamOffice.update((c) => ({ ...c, selected: { kind, id } }));
}
export function clearTeamSelection(): void {
  teamOffice.update((c) => ({ ...c, selected: null }));
}

export const selectedDynamicAgent = derived(teamOffice, ($t) =>
  $t.selected?.kind === 'temp' ? ($t.dynamicAgents.find((a) => a.id === $t.selected!.id) ?? null) : null);

export const selectedTeamMember = derived(teamOffice, ($t) =>
  $t.selected?.kind === 'team_member'
    ? ($t.activeTeam?.members.find((m) => m.member_id === $t.selected!.id) ?? null)
    : null);

export async function cancelActiveTeam(): Promise<{ ok: boolean }> {
  const id = get(teamOffice).activeTeamId;
  if (!id) return { ok: false };
  const ok = await cancelAgentTeam(id, 'owner_cancel');
  if (ok) await refreshTeamOffice();
  return { ok };
}
