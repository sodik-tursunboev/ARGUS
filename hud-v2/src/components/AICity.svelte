<script lang="ts">
  /* ARGUS AI CITY -- CITY-1 built the procedural world; CITY-2 wires it to
     real backend state (stores/cityState.ts). The frontend is a VIEW: every
     value on this page is read from stores App.svelte's existing snapshot
     poll + WebSocket already keep live -- no new fetch, no invented
     activity, and a district CITY-2 has no signal for just stays idle. */
  import { onMount } from 'svelte';
  import CityScene from '../lib/city/CityScene.svelte';
  import { DISTRICTS, ENV_DISTRICTS, type DistrictCategory } from '../lib/city/cityLayout';
  import { CATEGORY_STYLES, hexToCss } from '../lib/city/cityPalette';

  // The colour key is generated from the palette the city itself uses, one
  // entry per district family actually on the map -- it cannot drift.
  const KEY = [...new Set<DistrictCategory>([...DISTRICTS, ...ENV_DISTRICTS].map((d) => d.category))];
  import { cityState } from '../stores/cityState';
  import { agentOffice, officeSummary, refreshAgentOffice } from '../stores/agentOffice';
  import { teamOffice, refreshTeamOffice } from '../stores/teamOffice';
  import { refreshManager, refreshInbox } from '../stores/agentManager';
  import { security } from '../stores/security';
  import { tasks } from '../stores/tasks';
  import { academyState, refreshAcademy, sendToAcademy, stopAcademy } from '../stores/academy';

  const STUDY_ROLES = ['system', 'network', 'security', 'threat', 'forensics', 'diagnostics', 'planner', 'verifier', 'response', 'assistant'];
  let studyRole = 'system';
  let academyActionError = '';
  async function startStudy(): Promise<void> {
    academyActionError = '';
    try { await sendToAcademy([studyRole]); }
    catch (error) { academyActionError = error instanceof Error ? error.message : 'Training request failed'; }
  }
  async function stopStudy(role: string): Promise<void> {
    academyActionError = '';
    try { await stopAcademy(role); }
    catch (error) { academyActionError = error instanceof Error ? error.message : 'Cancellation failed'; }
  }

  /* Mirrors AgentOffice.svelte's own onMount exactly: an authoritative REST
     snapshot on page load (§3), never waiting for a future WS event, plus a
     light poll as the safety net for a missed one. Calling these again when
     the Office tab already loaded them is a cheap, idempotent no-op -- both
     write into the same shared stores. */
  onMount(() => {
    refreshAgentOffice();
    refreshTeamOffice();
    // The Agent Manager + CEO inbox: same discipline -- one snapshot now, a
    // light poll as the safety net, WS nudges (agentEventsBus) for live.
    void refreshManager();
    void refreshInbox();
    void refreshAcademy();
    const officeTimer = window.setInterval(refreshAgentOffice, 6000);
    const teamTimer = window.setInterval(refreshTeamOffice, 5000);
    const managerTimer = window.setInterval(() => { void refreshManager(); void refreshInbox(); }, 7000);
    const academyTimer = window.setInterval(() => { void refreshAcademy(); }, 5000);
    return () => { window.clearInterval(officeTimer); window.clearInterval(teamTimer); window.clearInterval(managerTimer); window.clearInterval(academyTimer); };
  });

  $: connectionLabel = $cityState.backendDisconnected ? 'BACKEND DISCONNECTED'
    : $cityState.stale ? 'STALE — LAST KNOWN STATE' : $cityState.connected ? 'LIVE' : 'CONNECTING';
  $: connectionClass = $cityState.backendDisconnected ? 'offline' : $cityState.stale ? 'attention' : $cityState.connected ? 'live' : '';

  $: localTemps = $teamOffice.dynamicAgents.filter((a) => a.type === 'EPHEMERAL_LOCAL').length;
  $: cloudTemps = $teamOffice.dynamicAgents.filter((a) => a.type === 'EPHEMERAL_CLOUD').length;
  $: activeTeams = $teamOffice.statusMeta?.active_teams ?? 0;
  $: queueDepth = $agentOffice.snapshot?.queue_depth ?? 0;
</script>

<section class="city-page" aria-label="ARGUS AI City">
  <header class="city-head">
    <h1><span class="city-head-mark">ARGUS AGENTS CITY</span> <span class="city-head-sub">// LIVE OPERATIONS</span></h1>
    <p class="city-lede">
      You are the <b class="ceo">CEO</b>. The <b class="mgr">Agent Manager</b> runs the teams and
      hires specialists; the agents work across {DISTRICTS.length} districts, in a city with
      {ENV_DISTRICTS.length} environment districts around them. Every colour and every
      status here is read from the same backend state the rest of the HUD shows -- a district
      with nothing to report stays idle, on purpose.
    </p>
    <ul class="city-key" aria-label="District colours">
      {#each KEY as k}<li style={`--k:${hexToCss(CATEGORY_STYLES[k].accent)}`}>{CATEGORY_STYLES[k].label}</li>{/each}
      <li style="--k:#ffd166" class="gold">CEO · Manager</li>
    </ul>
  </header>

  <section class="panel city-status" aria-label="City status">
    <div class="stat"><span>CONNECTION</span><b class={connectionClass}>{connectionLabel}</b></div>
    <div class="stat"><span>ACTIVE GOAL</span><b>{$tasks.goal ?? 'NONE'}</b></div>
    <div class="stat"><span>ACTIVE TEAMS</span><b>{activeTeams}</b></div>
    <div class="stat"><span>CORE AGENTS ACTIVE</span><b>{$officeSummary.active}</b></div>
    <div class="stat"><span>TEMP AGENTS</span><b>{localTemps}</b></div>
    <div class="stat"><span>CLOUD WORKERS</span><b>{cloudTemps}</b></div>
    <div class="stat"><span>MODEL QUEUE</span><b>{queueDepth}</b></div>
    <div class="stat"><span>SECURITY POSTURE</span><b class={$security.posture === 'critical' || $security.posture === 'blocked' || $security.posture === 'lockdown' ? 'critical' : $security.posture === 'normal' ? 'live' : 'attention'}>{$security.posture.toUpperCase()}</b></div>
  </section>

  <section class="panel city-visual" aria-label="City scene">
    <div class="panel-title"><h2>THE CITY</h2><span class="status" class:offline={connectionClass === 'offline'} class:attention={connectionClass === 'attention'}>{connectionLabel}</span></div>
    <CityScene liveState={$cityState.districts} />
    <p class="rail-note">Click a building or an agent for details. Cloud Embassy sits outside the
      secure boundary; the Policy + Auth Gate is the only road into the Capability Center.</p>
  </section>

  <section class="panel city-academy" aria-label="ARGUS Academy training">
    <div class="panel-title"><h2>ARGUS ACADEMY</h2><span class="status" class:offline={$academyState.link === 'offline'}>{$academyState.link.toUpperCase()}</span></div>
    <p class="academy-note">Synthetic local exercises only. A separate verifier and deterministic checks gate each lesson; training never changes permissions. Hermes is unavailable.</p>
    {#if $academyState.link === 'online' && $academyState.snapshot}
      <div class="academy-metrics">
        <span>STUDYING <b>{$academyState.snapshot.counts.ACTIVE ?? 0}</b></span>
        <span>QUEUED <b>{$academyState.snapshot.counts.QUEUED ?? 0}</b></span>
        <span>EVALUATING <b>{$academyState.snapshot.counts.EVALUATING ?? 0}</b></span>
        <span>PASSED TODAY <b>{$academyState.snapshot.counts.completed_today ?? 0}</b></span>
        <span>FAILED TODAY <b>{$academyState.snapshot.counts.failed_today ?? 0}</b></span>
      </div>
      <div class="academy-control">
        <label for="academy-role">SEND AGENT TO STUDY</label>
        <select id="academy-role" bind:value={studyRole}>
          {#each STUDY_ROLES as role}<option value={role}>{role.toUpperCase()}</option>{/each}
        </select>
        <button on:click={() => void startStudy()}>START</button>
      </div>
      {#if academyActionError}<p class="academy-error" role="alert">{academyActionError}</p>{/if}
      <div class="academy-list">
        {#each $academyState.snapshot.sessions.slice(0, 8) as session (session.session_id)}
          <div class="academy-row">
            <b>{session.agent_id.toUpperCase()}</b><span>{session.curriculum}</span><em>{session.state}</em>
            {#if session.score !== null}<span>SCORE {session.score}%</span>{/if}
            {#if ['SCHEDULED', 'QUEUED', 'ACTIVE', 'EVALUATING'].includes(session.state)}
              <button on:click={() => void stopStudy(session.agent_id)}>STOP</button>
            {/if}
          </div>
        {:else}<p class="academy-note">No training sessions yet.</p>{/each}
      </div>
    {:else}
      <p class="academy-note">Academy status is unavailable; no students are shown until the authenticated backend responds.</p>
    {/if}
  </section>

  <section class="panel city-legend" aria-label="District index">
    <div class="panel-title"><h2>DISTRICT INDEX</h2><span class="status">{DISTRICTS.length} DISTRICTS</span></div>
    <div class="city-legend-grid">
      {#each DISTRICTS as d (d.id)}
        {@const live = $cityState.districts[d.id]}
        <div class="city-legend-row" class:outside={!d.secure}>
          <div class="city-legend-row-head"><b>{d.name}</b>
            {#if live && live.activity !== 'idle'}<em class={live.activity}>{live.status}</em>{/if}
          </div>
          <span>{d.purpose}</span>
        </div>
      {/each}
    </div>
  </section>
</section>

<style>
  /* The Agents city is deliberately NOT another black ARGUS window: a navy
     stage, a spectrum edge (command cyan -> learning violet -> CEO gold) and
     a district colour key. Still the ARGUS type and spacing; just more light. */
  .city-page { display: flex; flex-direction: column; gap: 18px; }
  .city-head h1 { font-size: 26px; font-weight: 700; letter-spacing: .01em; color: var(--text-strong, #e6f2f5); }
  .city-head-mark {
    background: linear-gradient(90deg, #7fefff, #b9a4ff 55%, #ffd166);
    -webkit-background-clip: text; background-clip: text; color: transparent;
  }
  .city-head-sub { color: rgba(160, 190, 200, .6); font-weight: 600; }
  .city-lede { color: rgba(214, 238, 245, .78); font-size: 13.5px; max-width: 820px; margin-top: 4px; }
  .city-lede b.ceo { color: #ffe7a3; }
  .city-lede b.mgr { color: #ffd166; }
  .city-key { list-style: none; display: flex; flex-wrap: wrap; gap: 6px 14px; margin: 10px 0 0; padding: 0; }
  .city-key li {
    display: flex; align-items: center; gap: 6px;
    font-size: 10.5px; letter-spacing: .1em; text-transform: uppercase; color: rgba(214, 232, 242, .78);
  }
  .city-key li::before {
    content: ''; width: 10px; height: 10px; border-radius: 3px;
    background: var(--k); box-shadow: 0 0 8px var(--k);
  }
  .city-key li.gold { color: #ffe29a; }

  .city-visual.panel {
    border: 1px solid transparent;
    background:
      radial-gradient(120% 70% at 50% 0%, rgba(56, 224, 255, .09), transparent 60%) padding-box,
      linear-gradient(180deg, #0e1c33, #0a1424) padding-box,
      linear-gradient(115deg, rgba(56, 224, 255, .55), rgba(149, 120, 255, .45) 50%, rgba(255, 209, 102, .5)) border-box;
    box-shadow: 0 0 40px rgba(56, 224, 255, .06), 0 0 60px rgba(149, 120, 255, .05);
  }

  .city-status { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px 16px; padding: 14px 16px; }
  .city-status .stat { display: grid; gap: 3px; }
  .city-status .stat span { font-size: 10px; letter-spacing: .08em; color: rgba(160, 190, 200, .65); }
  .city-status .stat b { font-size: 13px; letter-spacing: .03em; color: #e6f2f5; font-weight: 700; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .city-status .stat b.live { color: #7de6ff; }
  .city-status .stat b.attention { color: #ffb244; }
  .city-status .stat b.critical { color: #ff6b6b; }
  .city-status .stat b.offline { color: #8a97a0; }
  .city-academy { display: grid; gap: 12px; border-color: rgba(149,120,255,.35); }
  .academy-note { margin: 0; color: rgba(214,238,245,.7); font-size: 12px; }
  .academy-metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(125px, 1fr)); gap: 8px; }
  .academy-metrics span { border: 1px solid rgba(149,120,255,.2); padding: 8px; font-size: 10px; color: #bdb5d6; letter-spacing: .05em; }
  .academy-metrics b { display: block; color: #e8deff; font-size: 17px; }
  .academy-control { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
  .academy-control label { font-size: 10px; color: #c4b5fd; letter-spacing: .08em; }
  .academy-control select, .academy-control button, .academy-row button { background: #14233a; border: 1px solid rgba(149,120,255,.5); color: #e8deff; padding: 7px 10px; min-width: 0; }
  .academy-control button, .academy-row button { cursor: pointer; }
  .academy-list { display: grid; gap: 5px; }
  .academy-row { display: flex; align-items: center; flex-wrap: wrap; gap: 6px 14px; border-top: 1px solid rgba(149,120,255,.16); padding: 7px 0; font-size: 11px; min-width: 0; }
  .academy-row b { color: #e8deff; min-width: 85px; }
  .academy-row span { color: rgba(214,238,245,.75); }
  .academy-row em { font-style: normal; color: #c4b5fd; }
  .academy-error { color: #ff9b9b; font-size: 12px; }

  .status.offline { color: #8a97a0; border-color: rgba(138, 151, 160, .4); }
  .status.attention { color: #ffb244; border-color: rgba(255, 178, 68, .4); }

  .city-legend-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 10px 18px; }
  .city-legend-row { display: grid; gap: 3px; padding: 8px 0; border-bottom: 1px solid rgba(56, 224, 255, .08); }
  .city-legend-row-head { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
  .city-legend-row b { font-size: 12.5px; letter-spacing: .05em; color: #9deaff; }
  .city-legend-row span { font-size: 11.5px; color: rgba(214, 238, 245, .68); line-height: 1.4; }
  .city-legend-row.outside b { color: #c4b5fd; }
  .city-legend-row-head em { font-size: 9.5px; font-style: normal; letter-spacing: .07em; color: #7de6ff; white-space: nowrap; }
  .city-legend-row-head em.attention { color: #ffb244; }
  .city-legend-row-head em.critical { color: #ff6b6b; }
  .city-legend-row-head em.offline { color: #8a97a0; }

  @media (max-width: 700px) {
    .city-head h1 { font-size: 20px; }
    .city-legend-grid { grid-template-columns: 1fr; }
    .city-status { grid-template-columns: repeat(2, 1fr); }
  }
</style>
