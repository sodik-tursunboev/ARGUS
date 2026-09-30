<script lang="ts">

  import { onMount } from 'svelte';
  import { agentOffice, officeSummary, selectedAgent, selectAgent, refreshAgentOffice, refreshJobs, refreshAutonomy, setAutonomy, submitTestJob } from '../stores/agentOffice';
  import { teamOffice, selectedDynamicAgent, selectedTeamMember, selectTeamEntity, clearTeamSelection, refreshTeamOffice, cancelActiveTeam } from '../stores/teamOffice';
  import { subscribeAgentEvents } from '../lib/agentEventsBus';
  import AgentOffice3D from '../lib/3d/AgentOffice3D.svelte';
  import AgentTown from './AgentTown.svelte';
  import { IconSecurity, IconThreat, IconAI, IconSystem, IconNetwork, IconSeal, IconObjective, IconWrench, IconAuditChain, IconSuccess, iconSize } from '../lib/ui/icons';

  /* Selecting a core agent and selecting a temp/cloud/team-member entity are
     mutually exclusive -- one detail panel shows at a time. */
  function pickCore(id: string): void { clearTeamSelection(); selectAgent(id); }
  function pickDynamic(id: string): void { selectAgent(null); selectTeamEntity('temp', id); }
  const TEAM_TERMINAL = new Set(['COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'PARTIAL']);
  let cancelling = false;
  async function onCancelTeam(): Promise<void> {
    if (cancelling) return;
    cancelling = true;
    await cancelActiveTeam();
    cancelling = false;
  }
  const elapsed = (s: number): string => {
    if (!s) return '0S';
    if (s < 60) return `${Math.round(s)}S`;
    if (s < 3600) return `${Math.round(s / 60)}M ${Math.round(s % 60)}S`;
    return `${Math.floor(s / 3600)}H ${Math.round((s % 3600) / 60)}M`;
  };

  /* Icon per registered agent id — display only. The registry is dynamic:
     an id without an icon here falls back to the ARGUS mark. */
  const roleIcon: Record<string, typeof IconSecurity> = {
    security: IconSecurity, threat: IconThreat, assistant: IconAI,
    system: IconSystem, network: IconNetwork, verifier: IconSeal,
    planner: IconObjective, diagnostics: IconWrench, forensics: IconAuditChain,
    response: IconSuccess,
  };
  const stateClass: Record<string, string> = {
    idle: 'st-idle', queued: 'st-queued', preparing: 'st-busy', thinking: 'st-thinking',
    responding: 'st-busy', waiting_auth: 'st-queued', executing: 'st-ok', verifying: 'st-busy',
    completed: 'st-ok', warning: 'st-queued', blocked: 'st-critical', error: 'st-critical',
    disabled: 'st-idle',
    // Dynamic (temp local/cloud) agent vocabulary -- agents/dynamic_spec.py
    // AgentStatus, lowercased (a distinct enum from the core OfficeAgent one).
    proposed: 'st-queued', validating: 'st-queued', approved: 'st-queued',
    active: 'st-ok', waiting: 'st-queued', failed: 'st-critical',
    expired: 'st-idle', destroyed: 'st-idle',
  };
  const stateLabel = (s: string) => s.replace('_', ' ').toUpperCase();

  let testAgent = 'assistant';
  let testObjective = '';
  let submitting = false;
  let submitNote = '';

  /* Initial authoritative snapshot, then live patches; a light job-refresh
     cadence keeps the queue table honest even if an event was missed. */
  onMount(() => {
    refreshAgentOffice();
    refreshJobs();
    refreshAutonomy();
    refreshTeamOffice();
    const timer = window.setInterval(refreshJobs, 4000);
    // Team/temp-agent state changes less often than the job queue; a lighter
    // cadence is the safety net for a missed WS event.
    const teamTimer = window.setInterval(refreshTeamOffice, 5000);
    const unsub = subscribeAgentEvents(() => { /* live patches already applied by the bus */ });
    return () => { window.clearInterval(timer); window.clearInterval(teamTimer); unsub(); };
  });

  $: snapshot = $agentOffice.snapshot;
  $: link = $agentOffice.link;
  $: model = snapshot?.model ?? null;
  /* Read the link off the store object itself: depending on the extracted
     `link` variable misses same-value re-assignments (store.replace), so
     the offline banner could stay stuck after the control link recovered. */
  $: online = $agentOffice.link === 'online' || $agentOffice.link === 'degraded';

  const stamp = (ts: number) => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const ago = (sec: number) => {
    if (!sec) return '—';
    if (sec < 60) return `${Math.round(sec)}S AGO`;
    if (sec < 3600) return `${Math.round(sec / 60)}M AGO`;
    return `${Math.round(sec / 3600)}H AGO`;
  };

  $: autonomy = $agentOffice.autonomy;
  const toggleAutonomy = () => { if (autonomy) void setAutonomy(!autonomy.enabled); };

  async function submit(): Promise<void> {
    if (!testObjective.trim() || submitting) return;
    submitting = true; submitNote = '';
    const result = await submitTestJob(testAgent, testObjective.trim());
    submitting = false;
    submitNote = result.ok ? 'SUBMITTED — QUEUED' : result.detail.toUpperCase();
    if (result.ok) testObjective = '';
  }
</script>

<section class="office-page" aria-label="Agents Office — local operations">
  <header class="office-head">
    <h1>AGENTS OFFICE <span class="office-head-sub">// LOCAL OPERATIONS</span></h1>
    <p class="office-lede">{$agentOffice.snapshot?.agents.length ?? 'Ten'} logical agents share one local model. They analyse and recommend; every action still passes ARGUS policy and authentication.</p>
  </header>

  {#if $agentOffice.autonomyNote}<p class="rail-note office-autonomy-note">{$agentOffice.autonomyNote}</p>{/if}

  {#if !online && $agentOffice.loaded}
    <section class="panel office-offline">
      <div class="panel-title"><h2>AGENT CONTROL LINK</h2><span class="status critical">OFFLINE</span></div>
      <p class="rail-note">{$agentOffice.lastError ?? 'The agents backend is unreachable.'} The office layout stays up; no agent data is invented while the link is down.</p>
    </section>
  {/if}

  <section class="office-summary panel" aria-label="Office summary">
    <div class="office-metric"><span>LOCAL AGENTS</span><b>{snapshot?.agents.length ?? '—'}</b></div>
    <div class="office-metric"><span>ACTIVE</span><b class="num-ok">{snapshot?.active_count ?? '—'}</b></div>
    <div class="office-metric"><span>QUEUED</span><b class={snapshot?.queue_depth ? 'num-warn' : ''}>{snapshot?.queue_depth ?? '—'}</b></div>
    <div class="office-metric"><span>IDLE</span><b>{$officeSummary.idle || '—'}</b></div>
    <div class="office-metric office-model"><span>MODEL</span><b>{model?.model_id ?? '—'}</b></div>
    <div class="office-metric"><span>MODEL STATE</span><b class={model?.busy ? 'st-thinking' : 'st-ok'}>{model ? (model.busy ? 'BUSY' : model.available ? 'IDLE' : 'UNAVAILABLE') : '—'}</b></div>
    <div class="office-metric"><span>MAX INFERENCE</span><b>{model?.max_concurrency ?? '—'}</b></div>
  </section>

  <section class="panel office-autonomy" aria-label="Autonomy scheduler">
    <div class="panel-title"><h2>AUTONOMY</h2>
      <span class="status {autonomy?.enabled ? 'ok' : 'unknown'}">{autonomy ? (autonomy.enabled ? 'ON — BACKGROUND CYCLES' : 'OFF — ON REQUEST ONLY') : '—'}</span>
      <button class="office-autonomy-btn" on:click={toggleAutonomy} disabled={!autonomy}>
        {autonomy?.enabled ? 'PAUSE AGENTS' : 'RESUME AGENTS'}
      </button>
    </div>    {#if autonomy}
      <div class="office-detail-grid">
        <div><span>CYCLE</span><b>EVERY {autonomy.interval_s}s · ONE JOB</b></div>
        <div><span>DISPATCHED</span><b>{autonomy.jobs_dispatched}</b></div>
        <div><span>DEFERRED (BUSY)</span><b>{autonomy.skipped_busy}</b></div>
        <div><span>LAST DISPATCH</span><b>{autonomy.last_dispatch_at ? stamp(autonomy.last_dispatch_at * 1000) : '—'}</b></div>
      </div>
      <p class="rail-note">When on, each cycle queues one fixed read-only analysis objective for the next agent — round-robin across all ten. Your requests and security work always go first; autonomous work is background tier and pauses the moment the queue is busy.</p>
    {/if}
  </section>

  <section class="office-visual panel" aria-label="3D agents office slot">
    <div class="panel-title"><h2>THE OFFICE</h2><span class="status">{link === 'degraded' ? 'LIVE LINK DEGRADED' : 'LOCAL'}</span></div>
    <div class="office-3d-slot" data-testid="agents-office-3d-slot">
      <AgentOffice3D />
    </div>
  </section>

  <section class="panel office-team" aria-label="Team control panel">
    <div class="panel-title"><h2>ACTIVE TEAM</h2>
      <span class="status {$teamOffice.link === 'offline' ? 'critical' : ''}">{$teamOffice.link === 'offline' ? 'DISCONNECTED' : $teamOffice.link === 'degraded' ? 'DEGRADED' : $teamOffice.activeTeam ? $teamOffice.activeTeam.state : 'NO ACTIVE TEAM'}</span>
      {#if $teamOffice.activeTeam && !TEAM_TERMINAL.has($teamOffice.activeTeam.state)}
        <button class="office-cancel-btn" on:click={onCancelTeam} disabled={cancelling}>{cancelling ? 'CANCELLING…' : 'CANCEL TEAM'}</button>
      {/if}
    </div>
    {#if $teamOffice.activeTeam}
      {@const t = $teamOffice.activeTeam}
      <p class="goal-line">{t.goal || 'No goal text available.'}</p>
      <div class="office-detail-grid">
        <div><span>PROGRESS</span><b>{Math.round(t.progress * 100)}%</b></div>
        <div><span>ELAPSED</span><b>{elapsed(t.elapsed_s)}</b></div>
        <div><span>CURRENT PHASE</span><b>{t.current_phase || '—'}</b></div>
        <div><span>ACTIVE AGENTS</span><b>{t.members.filter((m) => m.kind === 'core').length}</b></div>
        <div><span>TEMP AGENTS</span><b>{t.temporary_live}</b></div>
        <div><span>VERIFICATION</span><b>{t.verification && Object.keys(t.verification).length ? String(t.verification.combined ?? t.verification.verdict ?? 'RAN') : 'NOT STARTED'}</b></div>
        <div><span>MODEL CALLS</span><b>{t.model_calls}</b></div>
        <div><span>REPLANS</span><b>{t.replans}</b></div>
      </div>
    {:else}
      <p class="rail-note">{$teamOffice.link === 'offline' ? ($teamOffice.lastError ?? 'The agent team control link is unreachable.') : 'No investigation is currently running. A team starts when a goal warrants one (voice, text, or the analysis form below).'}</p>
    {/if}
  </section>

  <section class="office-workstations" aria-label="Agent workstations">
    {#each snapshot?.agents ?? [] as a (a.id)}
      <button class="office-card {stateClass[a.state] ?? 'st-idle'}"
              class:selected={$agentOffice.selectedAgentId === a.id}
              on:click={() => pickCore(a.id)}>
        <div class="office-card-head">
          <span class="office-card-icon"><svelte:component this={roleIcon[a.id] ?? IconAI} size={iconSize.major} /></span>
          <b>{a.name}</b>
          <span class="office-state">{stateLabel(a.state)}</span>
        </div>
        <p class="office-card-role">{a.description}</p>
        <div class="office-card-foot">
          <span>{a.current_job_id ? `JOB ${a.current_job_id}` : a.queue_position ? `QUEUE #${a.queue_position}` : 'NO ACTIVE JOB'}</span>
          <span>{ago(Math.max(0, Date.now() / 1000 - (a.last_activity_at || 0)))}</span>
        </div>
      </button>
    {:else}
      <p class="rail-note">{online ? 'Agent registry is empty.' : 'Agent data appears here when the control link is online.'}</p>
    {/each}
  </section>

  <section class="office-workstations office-temp" aria-label="Temporary and cloud specialists">
    {#each $teamOffice.dynamicAgents as a (a.id)}
      <button class="office-card {stateClass[a.state.toLowerCase()] ?? 'st-idle'}"
              class:selected={$teamOffice.selected?.kind === 'temp' && $teamOffice.selected.id === a.id}
              on:click={() => pickDynamic(a.id)}>
        <div class="office-card-head">
          <span class="office-card-icon"><svelte:component this={IconWrench} size={iconSize.major} /></span>
          <b>{a.name}</b>
          <span class="office-origin-tag {a.type === 'EPHEMERAL_CLOUD' ? 'cloud' : 'local'}">{a.type === 'EPHEMERAL_CLOUD' ? 'CLOUD' : 'LOCAL'}</span>
          <span class="office-state">{stateLabel(a.state)}</span>
        </div>
        <p class="office-card-role">{a.description || `Temporary specialist for ${a.parent.toUpperCase()}.`}</p>
        <div class="office-card-foot">
          <span>PARENT {a.parent.toUpperCase()}</span>
          <span>TTL {a.ttl_remaining_s > 0 ? `${Math.round(a.ttl_remaining_s)}S` : '—'}</span>
        </div>
      </button>
    {:else}
      <p class="rail-note">{$teamOffice.link === 'offline' ? 'Temp/cloud specialist data appears here when the control link is online.' : 'No temporary or cloud specialists are currently active.'}</p>
    {/each}
  </section>

  {#if $selectedAgent}
    <section class="panel office-detail" aria-label="Selected agent detail">
      <div class="panel-title"><h2>{$selectedAgent.name.toUpperCase()}</h2><span class="status {stateClass[$selectedAgent.state] ?? ''}">{stateLabel($selectedAgent.state)}</span></div>
      <div class="office-detail-grid">
        <div><span>ROLE</span><b>{$selectedAgent.role}</b></div>
        <div><span>TYPE</span><b>CORE</b></div>
        <div><span>STATE</span><b>{stateLabel($selectedAgent.state)}</b></div>
        <div><span>CURRENT JOB</span><b>{$selectedAgent.current_job_id || '—'}</b></div>
        <div><span>QUEUE POSITION</span><b>{$selectedAgent.queue_position || '—'}</b></div>
        <div><span>LAST ACTIVITY</span><b>{ago(Math.max(0, Date.now() / 1000 - ($selectedAgent.last_activity_at || 0)))}</b></div>
        <div><span>MODEL</span><b>{model?.model_id ?? '—'} · SHARED</b></div>
        <div><span>COMPLETED / FAILED</span><b>{$selectedAgent.completed_jobs} / {$selectedAgent.failed_jobs}</b></div>
        <div><span>CAPABILITY GROUPS</span><b>{$selectedAgent.allowed_capability_groups.join(' · ') || '—'}</b></div>
      </div>
      <p class="rail-note">{$selectedAgent.description} Requests are validated by ARGUS policy and authentication before anything happens — the agent only proposes.</p>
    </section>
  {:else if $selectedDynamicAgent}
    {@const d = $selectedDynamicAgent}
    <section class="panel office-detail" aria-label="Selected specialist detail">
      <div class="panel-title"><h2>{d.name.toUpperCase()}</h2><span class="status">{stateLabel(d.state)}</span></div>
      <div class="office-detail-grid">
        <div><span>ROLE</span><b>{d.role || '—'}</b></div>
        <div><span>TYPE</span><b>{d.type === 'EPHEMERAL_CLOUD' ? 'CLOUD — INTELLIGENCE WORKER' : 'TEMP LOCAL'}</b></div>
        <div><span>STATE</span><b>{stateLabel(d.state)}</b></div>
        <div><span>CURRENT TASK</span><b>{d.current_task || '—'}</b></div>
        <div><span>PARENT</span><b>{d.parent.toUpperCase()}</b></div>
        <div><span>SPAWN DEPTH</span><b>{d.spawn_depth}</b></div>
        <div><span>QUEUE POSITION</span><b>{d.queue_state.queue_position || '—'}</b></div>
        <div><span>MODEL</span><b>{d.type === 'EPHEMERAL_CLOUD' ? 'CLOUD PROVIDER' : (d.model || '—')}</b></div>
        <div><span>TTL REMAINING</span><b>{d.ttl_remaining_s > 0 ? `${Math.round(d.ttl_remaining_s)}S` : 'EXPIRED'}</b></div>
        <div><span>MODEL CALLS</span><b>{d.budget.model_calls_used} / {d.budget.max_model_calls}</b></div>
      </div>
      <p class="rail-note">{d.result_summary || 'No result yet.'} It analyses and recommends only — every action still passes ARGUS policy and authentication.</p>
    </section>
  {:else if $selectedTeamMember}
    {@const m = $selectedTeamMember}
    <section class="panel office-detail" aria-label="Selected team member detail">
      <div class="panel-title"><h2>{m.role.toUpperCase()}</h2><span class="status">{stateLabel(m.state)}</span></div>
      <div class="office-detail-grid">
        <div><span>TYPE</span><b>{m.kind === 'core' ? 'CORE' : m.worker_type.toUpperCase()}</b></div>
        <div><span>STATE</span><b>{stateLabel(m.state)}</b></div>
        <div><span>CURRENT TASK</span><b>{m.current_task || '—'}</b></div>
        <div><span>PARENT</span><b>{m.parent.toUpperCase()}</b></div>
        <div><span>TEAM</span><b>{$teamOffice.activeTeam?.team_id ?? '—'}</b></div>
        <div><span>TTL</span><b>{m.ttl_remaining_s > 0 ? `${Math.round(m.ttl_remaining_s)}S` : '—'}</b></div>
      </div>
      <p class="rail-note">{m.result_summary || 'No result yet.'}</p>
    </section>
  {/if}

  <div class="office-duo">
    <section class="panel" aria-label="Live agent activity">
      <div class="panel-title"><h2>AGENT ACTIVITY</h2><span class="status">{link === 'degraded' ? 'DEGRADED' : online ? 'LIVE' : 'OFFLINE'}</span></div>
      {#if $agentOffice.activity.length}
        <div class="office-activity">
          {#each $agentOffice.activity.slice(0, 12) as e (e.id)}
            <div class="office-activity-row">
              <time>{stamp(e.ts)}</time>
              <b>{e.agentId.toUpperCase()}</b>
              <span class={`office-activity-label ${e.label.includes('FAIL') || e.label.includes('CANCEL') ? 'critical' : e.label.includes('COMPLETE') ? 'ok' : ''}`}>{e.label}</span>
            </div>
          {/each}
        </div>
      {:else}
        <p class="rail-note">NO RECENT AGENT ACTIVITY</p>
      {/if}
    </section>

    <section class="panel" aria-label="Job queue">
      <div class="panel-title"><h2>JOB QUEUE</h2><span class="status">{snapshot?.queue_depth ? `${snapshot.queue_depth} WAITING` : 'CLEAR'}</span></div>
      {#if $agentOffice.jobs.length}
        <div class="office-queue">
          <div class="office-queue-row office-queue-head"><span>PRIO</span><span>AGENT</span><span>OBJECTIVE</span><span>STATE</span></div>
          {#each $agentOffice.jobs.slice(0, 8) as j (j.job_id)}
            <div class="office-queue-row">
              <b>P{j.priority}</b><span>{j.agent_id.toUpperCase()}</span>
              <span class="office-queue-objective">{j.objective || '—'}</span>
              <span>{stateLabel(j.state)}</span>
            </div>
          {/each}
        </div>
      {:else}
        <p class="rail-note">QUEUE CLEAR</p>
      {/if}
    </section>
  </div>

  <section class="panel office-model-panel" aria-label="Shared model">
    <div class="panel-title"><h2>SHARED MODEL</h2><span class="status">{model ? (model.busy ? 'BUSY' : 'READY') : '—'}</span></div>
    <p class="office-model-tag">ONE MODEL // MULTIPLE LOGICAL AGENTS</p>
    <div class="office-detail-grid">
      <div><span>MODEL</span><b>{model?.model_id ?? '—'}</b></div>
      <div><span>AVAILABLE</span><b>{model ? (model.available ? 'YES' : 'NO') : '—'}</b></div>
      <div><span>BUSY / IDLE</span><b>{model ? (model.busy ? 'BUSY' : 'IDLE') : '—'}</b></div>
      <div><span>ACTIVE JOB</span><b>{model?.active_job || '—'}</b></div>
      <div><span>QUEUE DEPTH</span><b>{snapshot?.queue_depth ?? '—'}</b></div>
      <div><span>MAX CONCURRENCY</span><b>{model?.max_concurrency ?? '—'}</b></div>
    </div>
  </section>

  <section class="panel" aria-label="Submit analysis job">
    <div class="panel-title"><h2>ANALYSIS REQUEST</h2><span class="status">OWNER INITIATED</span></div>
    <div class="office-test">
      <label>SELECT AGENT
        <select bind:value={testAgent}>
          {#each snapshot?.agents ?? [] as a (a.id)}<option value={a.id}>{a.name}</option>{/each}
        </select>
      </label>
      <label>OBJECTIVE
        <input bind:value={testObjective} maxlength="180" placeholder="e.g. Summarise current machine health" />
      </label>
      <button class="office-submit" disabled={!testObjective.trim() || submitting || !online} on:click={submit}>
        {submitting ? 'SUBMITTING…' : 'SUBMIT ANALYSIS'}
      </button>
    </div>
    {#if submitNote}<p class="rail-note">{submitNote}</p>{/if}
    <p class="rail-note">Submits through the real coordinator API. Analysis only — the agent cannot execute anything; capability requests surface for owner review.</p>
  </section>

  <section class="panel office-town-panel" aria-label="Agent Town 2D">
    <div class="panel-title"><h2>AGENT TOWN // 2D FALLBACK</h2><span class="status">{online ? 'REAL STATE' : 'OFFLINE'}</span></div>
    <AgentTown agents={snapshot?.agents ?? []} handoff={$agentOffice.handoff} onSelect={(id: string) => selectAgent(id)} />
    <p class="rail-note">Node brightness is real state: violet thinking, amber queued, green active, red blocked. Traces light only on real lifecycle events.</p>
  </section>
</section>

<style>
  .office-page { display: flex; flex-direction: column; gap: 18px; }
  .office-head h1 { font-size: 26px; font-weight: 700; letter-spacing: .01em; color: var(--text-strong, #e6f2f5); }
  .office-autonomy-note { margin: -6px 0 0; }
  .office-autonomy .panel-title { gap: 12px; }
  .office-autonomy-btn { background: rgba(56, 224, 255, .1); color: #7de6ff; border: 1px solid rgba(56, 224, 255, .4); border-radius: 6px; padding: 5px 14px; font-size: 11px; font-weight: 700; letter-spacing: .12em; cursor: pointer; }
  .office-autonomy-btn:hover:not(:disabled) { background: rgba(56, 224, 255, .2); }
  .office-autonomy-btn:disabled { opacity: .4; cursor: default; }
  .office-lede { color: rgba(214, 238, 245, .72); font-size: 13.5px; max-width: 720px; margin-top: 4px; }

  .office-summary { display: flex; flex-wrap: wrap; gap: 26px; padding: 16px 20px; }
  .office-metric { display: flex; flex-direction: column; gap: 4px; }
  .office-metric span { font-size: 10px; letter-spacing: .16em; color: rgba(160, 190, 200, .75); }
  .office-metric b { font-size: 20px; font-weight: 700; color: var(--text-strong, #e6f2f5); font-variant-numeric: tabular-nums; }
  .office-model b { font-size: 16px; }
  .num-ok { color: #4ade9e !important; } .num-warn { color: #ffb244 !important; }

  /* display:grid + place-items:center made this a shrink-to-fit grid item:
     justify-items:center sized the child (AgentOffice3D's wrapper) to its
     own content instead of stretching it to the track's width, which
     Three.js then read as a ~1px container and rendered an invisible
     canvas. AgentOffice3D is a full-bleed viewport now, not a small
     centered placeholder, so the item should stretch (grid's default). */
  .office-3d-slot { min-height: 220px; border: 1px dashed rgba(56, 224, 255, .22); border-radius: 8px; display: grid; }
  .office-3d-placeholder { text-align: center; color: rgba(160, 190, 200, .6); display: grid; gap: 6px; }
  .office-3d-placeholder span { font-size: 12px; letter-spacing: .2em; }
  .office-3d-placeholder :global(small) { font-size: 10.5px; }

  .office-workstations { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }
  .office-card { text-align: left; background: rgba(10, 22, 26, .72); border: 1px solid rgba(56, 224, 255, .14); border-radius: 10px; padding: 14px 16px; display: grid; gap: 8px; cursor: pointer; transition: border-color .15s, background .15s; }
  .office-card:hover { border-color: rgba(56, 224, 255, .4); }
  .office-card.selected { border-color: rgba(56, 224, 255, .75); background: rgba(14, 32, 38, .85); }
  .office-card-head { display: flex; align-items: center; gap: 10px; color: rgba(56, 224, 255, .9); }
  .office-card-icon { display: grid; place-items: center; width: 38px; height: 38px; border-radius: 9px; background: rgba(56, 224, 255, .08); flex: 0 0 auto; }
  .office-card-head b { font-size: 19px; font-weight: 800; color: var(--text-strong, #e6f2f5); letter-spacing: .015em; }
  .office-state { margin-left: auto; font-size: 13.5px; font-weight: 800; letter-spacing: .08em; white-space: nowrap; }
  .office-card:hover .office-card-icon, .office-card.selected .office-card-icon { background: rgba(56, 224, 255, .16); }
  /* Working agents must be visible from across the room: busy/thinking/queued
     cards get a state-colored left rail and glow. */
  .office-card.st-thinking { border-color: rgba(167, 139, 250, .55); box-shadow: 0 0 18px rgba(167, 139, 250, .12), inset 3px 0 0 #a78bfa; }
  .office-card.st-busy { border-color: rgba(56, 224, 255, .55); box-shadow: 0 0 18px rgba(56, 224, 255, .12), inset 3px 0 0 #38e0ff; }
  .office-card.st-queued { border-color: rgba(255, 178, 68, .5); box-shadow: inset 3px 0 0 #ffb244; }
  .office-card.st-ok { border-color: rgba(74, 222, 158, .4); box-shadow: inset 3px 0 0 #4ade9e; }
  .office-card.st-critical { border-color: rgba(255, 92, 92, .55); box-shadow: inset 3px 0 0 #ff5c5c; }
  .st-idle .office-state, .st-idle { color: rgba(140, 190, 205, .8); }
  .st-thinking { color: #a78bfa; } .st-busy { color: #38e0ff; }
  .st-queued { color: #ffb244; } .st-ok { color: #4ade9e; } .st-critical { color: #ff5c5c; }
  .office-card-role { font-size: 12.5px; color: rgba(214, 238, 245, .66); line-height: 1.45; }
  .office-card-foot { display: flex; justify-content: space-between; font-size: 10.5px; color: rgba(160, 190, 200, .7); font-variant-numeric: tabular-nums; }

  .office-detail-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px 22px; padding: 6px 0 10px; }
  .office-detail-grid span { display: block; font-size: 10px; letter-spacing: .14em; color: rgba(160, 190, 200, .7); margin-bottom: 3px; }
  .office-detail-grid b { font-size: 13.5px; font-weight: 600; color: var(--text-strong, #e6f2f5); }

  .office-duo { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  @media (max-width: 1100px) { .office-duo { grid-template-columns: 1fr; } }
  .office-activity { display: grid; gap: 6px; max-height: 240px; overflow-y: auto; }
  .office-activity-row { display: grid; grid-template-columns: 74px 92px 1fr; gap: 10px; font-size: 12.5px; align-items: baseline; font-variant-numeric: tabular-nums; }
  .office-activity-row time { color: rgba(160, 190, 200, .65); }
  .office-activity-row b { color: rgba(214, 238, 245, .85); letter-spacing: .06em; }
  .office-activity-label.ok { color: #4ade9e; } .office-activity-label.critical { color: #ff5c5c; }

  .office-queue { display: grid; gap: 4px; }
  .office-queue-row { display: grid; grid-template-columns: 48px 96px 1fr 100px; gap: 10px; font-size: 12.5px; padding: 5px 0; border-bottom: 1px solid rgba(56, 224, 255, .07); align-items: baseline; }
  .office-queue-head { color: rgba(160, 190, 200, .65); font-size: 10px; letter-spacing: .14em; border-bottom-color: rgba(56, 224, 255, .18); }
  .office-queue-objective { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: rgba(214, 238, 245, .82); }

  .office-model-tag { font-size: 12px; letter-spacing: .22em; color: rgba(56, 224, 255, .85); margin: 2px 0 10px; }
  .office-test { display: flex; flex-wrap: wrap; gap: 12px; align-items: end; }
  .office-test label { display: grid; gap: 5px; font-size: 10px; letter-spacing: .14em; color: rgba(160, 190, 200, .7); }
  .office-test select, .office-test input { background: rgba(6, 16, 20, .9); border: 1px solid rgba(56, 224, 255, .22); color: var(--text-strong, #e6f2f5); border-radius: 6px; padding: 8px 10px; font-size: 13px; }
  .office-test input { width: 300px; max-width: 60vw; }
  .office-submit { background: rgba(56, 224, 255, .12); border: 1px solid rgba(56, 224, 255, .45); color: #9deaff; border-radius: 6px; padding: 9px 18px; font-weight: 600; font-size: 13px; cursor: pointer; }
  .office-submit:disabled { opacity: .45; cursor: default; }
  .office-submit:hover:not(:disabled) { background: rgba(56, 224, 255, .2); }

  .office-town-panel :global(.agent-town) { max-width: 480px; margin: 0 auto; }
  .office-offline .status.critical { color: #ff5c5c; }
  @media (prefers-reduced-motion: reduce) { .office-card, .office-submit { transition: none; } }

  .office-team .panel-title { gap: 12px; flex-wrap: wrap; }
  .office-cancel-btn { margin-left: auto; background: rgba(255, 92, 92, .12); border: 1px solid rgba(255, 92, 92, .5); color: #ff8f8f; border-radius: 6px; padding: 5px 14px; font-size: 11px; font-weight: 700; letter-spacing: .1em; cursor: pointer; }
  .office-cancel-btn:hover:not(:disabled) { background: rgba(255, 92, 92, .22); }
  .office-cancel-btn:disabled { opacity: .5; cursor: default; }

  .office-origin-tag { font-size: 9.5px; font-weight: 800; letter-spacing: .12em; padding: 2px 6px; border-radius: 4px; border: 1px solid; }
  .office-origin-tag.local { color: #7de6ff; border-color: rgba(56, 224, 255, .4); background: rgba(56, 224, 255, .08); }
  .office-origin-tag.cloud { color: #ffcf85; border-color: rgba(255, 178, 68, .45); background: rgba(255, 178, 68, .1); }
  .office-temp { margin-top: -2px; }
</style>
