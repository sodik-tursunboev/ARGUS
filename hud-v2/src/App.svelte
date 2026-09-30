<script lang="ts">
  import { onMount, tick } from 'svelte';
  import Header from './components/Header.svelte'; import Tabs from './components/Tabs.svelte'; import SystemOverview from './components/SystemOverview.svelte'; import ProcessOverview from './components/ProcessOverview.svelte'; import LocalAI from './components/LocalAI.svelte'; import NetworkPanel from './components/NetworkPanel.svelte'; import ArgusCore from './components/ArgusCore.svelte'; import SecurityStatus from './components/SecurityStatus.svelte'; import ThreatMonitor from './components/ThreatMonitor.svelte'; import CurrentObjective from './components/CurrentObjective.svelte'; import EventTimeline from './components/EventTimeline.svelte'; import QuickActions from './components/QuickActions.svelte'; import CommandInput from './components/CommandInput.svelte'; import BootSequence from './components/BootSequence.svelte'; import Modules from './components/Modules.svelte';  import Agents from './components/Agents.svelte';
  import AgentOffice from './components/AgentOffice.svelte'; import AICity from './components/AICity.svelte'; import SettingsPanel from './components/SettingsPanel.svelte'; import AppFooter from './components/AppFooter.svelte'; import CommandPalette from './components/CommandPalette.svelte';
  import PageRail from './components/PageRail.svelte'; import TaskLifecycle from './components/TaskLifecycle.svelte'; import SecurityMatrix from './components/SecurityMatrix.svelte'; import Architecture from './components/Architecture.svelte'; import Diagnostics from './components/Diagnostics.svelte';
  import Cockpit from './components/Cockpit.svelte';
  import Operations from './components/Operations.svelte';
  import Capabilities from './components/Capabilities.svelte';
  import AuditLog from './components/AuditLog.svelte';
  import AgentJobHistory from './components/AgentJobHistory.svelte';
  import Authentication from './components/Authentication.svelte';
  import DashSystem from './components/dash/DashSystem.svelte'; import DashLocalAI from './components/dash/DashLocalAI.svelte'; import DashNetwork from './components/dash/DashNetwork.svelte';
  import DashSecurity from './components/dash/DashSecurity.svelte'; import DashThreat from './components/dash/DashThreat.svelte'; import DashAlerts from './components/dash/DashAlerts.svelte';
  import { startSnapshotPolling } from './stores/snapshot'; import { startLiveEvents } from './stores/liveEvents'; import { snapshotStatus } from './stores/snapshotView';
  import { requestAuthFromBackend, pendingAuth } from './stores/authFlow';
  /* AUTO-OPEN of the Authentication page. The triggers are all authoritative
     BACKEND signals, mirrored into authFlow.pendingAuth: a /command answer with
     auth_required / confirmation_required, a WS auth.state required|expired
     (liveEvents.ts), and a snapshot that reports a pending PIN (right below).
     The session merely being LOCKED is deliberately NOT a trigger -- that is
     ARGUS's normal baseline, not a verification demand. */
  type Page='dashboard'|'tasks'|'agents'|'operations'|'modules'|'security'|'authentication'|'logs'|'tools'|'about'|'settings'; let page:Page='dashboard'; let booting=true; let taskTab='active'; let agentTab='active'; let moduleTab='overview'; let securityTab='overview'; let logsTab='events'; let toolsTab='quick actions'; let paletteOpen=false;
  onMount(()=>{const a=startSnapshotPolling(),b=startLiveEvents();const shortcuts=(event:KeyboardEvent)=>{if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='k'){event.preventDefault();paletteOpen=true;} else if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==='l'){event.preventDefault();page='logs';} else if((event.ctrlKey||event.metaKey)&&event.shiftKey&&event.key.toLowerCase()==='s'){event.preventDefault();page='security';} else if((event.ctrlKey||event.metaKey)&&event.key===','){event.preventDefault();page='settings';} else if(event.key==='Escape')paletteOpen=false;};window.addEventListener('keydown',shortcuts);return()=>{window.removeEventListener('keydown',shortcuts);b();a();};});
  $: if ($snapshotStatus?.pin_pending) requestAuthFromBackend('pending backend confirmation');
  /* A challenge surfaces the Authentication page and remembers where the person was, so a
     resolved challenge can hand them straight back. The only reactive dependency here is
     $pendingAuth, so navigating away while one is pending is respected (it stays pending,
     and the Authentication tab stays marked) instead of being undone on every render. */
  let authReturn: Page | null = null;
  $: if ($pendingAuth) { if (page !== 'authentication') authReturn = page; page = 'authentication'; }
  let returnTimer: number | undefined;
  function authResolved(outcome: 'verified' | 'cancelled'): void {
    window.clearTimeout(returnTimer);
    // VERIFIED stays on screen for a beat before the person is returned to what they were doing
    returnTimer = window.setTimeout(() => { if (page === 'authentication' && authReturn) page = authReturn; authReturn = null; }, outcome === 'verified' ? 1400 : 0);
  }
  /* New page navigations start at the top: the ONLY reactive dependency in
     this statement is `page`, so it fires once per navigation. `tick()` runs
     AFTER Svelte has swapped the #key page DOM, so the scroll reset lands on
     the freshly mounted container rather than the outgoing one. */
  $: if (page) tick().then(() => document.querySelector<HTMLElement>('.page-content')?.scrollTo(0, 0));
</script>
<svelte:head><meta name="theme-color" content="#03090b" /></svelte:head>
{#if booting}<BootSequence on:complete={()=>booting=false}/>{/if}
<Cockpit>
<main class:boot-hidden={booting} class:dashboard-active={page==='dashboard'} class="app-shell" aria-label="ARGUS desktop application">
  <Header {page} on:navigate={(e)=>page=e.detail}/>
  <div class="page-content">
  {#key page}
  <div class="page-enter">
  {#if page==='dashboard'}
    <!-- The Dashboard is a single-screen OVERVIEW: three columns, nothing below
         the fold. Detail lives on the dedicated pages -- Current Objective on
         Tasks, Event Timeline on Logs / Security, Quick Actions on Tools -- and
         the command console is the same slim dock every page carries. -->
    <section class="dash" aria-label="Command overview">
      <aside class="dash-rail dash-left" data-testid="rail-left" aria-label="System, local AI and network"><DashSystem/><DashLocalAI/><DashNetwork/></aside>
      <section class="identity-core dash-core" data-testid="argus-core"><ArgusCore/></section>
      <aside class="dash-rail dash-right" data-testid="rail-right" aria-label="Security, threats and alerts"><DashSecurity/><DashThreat/><DashAlerts on:navigate={(event)=>page=event.detail as typeof page}/></aside>
    </section>
  {:else if page==='operations'}
    <Operations/>
  {:else if page==='tasks'}
    <Tabs title="TASKS" group="tasks" items={['active','plan','history']} active={taskTab} on:select={(e)=>taskTab=e.detail}/>
    <div class="page-body">
      {#key taskTab}<section class="page-main tab-enter">
        {#if taskTab==='history'}
          <TaskLifecycle/>
          <section class="panel compact-unavailable"><div class="panel-title"><h2>PERSISTED HISTORY</h2><span class="status unknown">NOT EXPOSED</span></div><p class="rail-note">No validated backend task-history contract is available. Only this session's live task activity is shown above.</p></section>
        {:else if taskTab==='plan'}
          <CurrentObjective/>
          <TaskLifecycle/>
        {:else}
          <TaskLifecycle/>
          <CurrentObjective/>
        {/if}
      </section>{/key}
      <PageRail/>
    </div>
  {:else if page==='agents'}
    <Tabs title="AGENTS OFFICE // LOCAL OPERATIONS" group="agents" items={['office','city','active','planner','history']} active={agentTab} on:select={(e)=>agentTab=e.detail}/>
    <!-- The AI City runs full-bleed: the 272px context rail steals width the 3D
     view needs, and everything the rail shows (backend, security, active team,
     model queue) is already on the city's own compact status strip. Every
     other tab keeps the rail. -->
<div class="page-body" class:city-body={agentTab==='city'}>{#key agentTab}<section class="page-main tab-enter page-scroll">{#if agentTab==='office'}<AgentOffice/>{:else if agentTab==='city'}<AICity/>{:else}<Agents tab={agentTab}/>{/if}</section>{/key}{#if agentTab!=='city'}<PageRail/>{/if}</div>
  {:else if page==='modules'}
    <Tabs title="MODULES" group="modules" items={['overview','core','ai','voice','security','system','automation','integrations']} active={moduleTab} on:select={(e)=>moduleTab=e.detail}/>
    <div class="page-body">{#key moduleTab}<section class="page-main tab-enter"><Modules tab={moduleTab}/></section>{/key}<PageRail/></div>
  {:else if page==='security'}
    <Tabs title="SECURITY" group="security" items={['overview','threats','audit','session','policy']} active={securityTab} on:select={(e)=>securityTab=e.detail}/>
    <div class="page-body">
      {#key securityTab}<section class="page-main tab-enter" data-page="security">
        {#if securityTab==='overview'}<div class="security-grid"><SecurityStatus/><ThreatMonitor/><SecurityMatrix/></div>
        {:else if securityTab==='session'}<div class="security-grid"><SecurityStatus/><SecurityMatrix/></div>
        {:else if securityTab==='threats'}<div class="security-grid"><ThreatMonitor/><SecurityMatrix/></div>
        {:else if securityTab==='audit'}<EventTimeline/>
        {:else}<section class="panel"><div class="panel-title"><h2>POLICY CONFIGURATION</h2><span class="status">VIEW ONLY</span></div><p class="rail-note">The enforced state of every security control is live in the matrix below — read straight from the backend's security report. The rule text itself is not exposed by design: visibility never grants authority.</p></section><SecurityMatrix/>
        {/if}
      </section>{/key}
      <PageRail/>
    </div>
  {:else if page==='authentication'}
    <div class="page-body auth-body"><section class="page-main"><Authentication on:resolved={(event)=>authResolved(event.detail.outcome)}/></section></div>
  {:else if page==='logs'}
    <Tabs title="LOGS" group="logs" items={['events','system','agent']} active={logsTab} on:select={(e)=>logsTab=e.detail}/>
    <div class="page-body">{#key logsTab}<section class="page-main tab-enter">{#if logsTab==='events'}<EventTimeline/>{:else if logsTab==='system'}<AuditLog/>{:else}<AgentJobHistory/>{/if}</section>{/key}<PageRail/></div>
  {:else if page==='tools'}
    <Tabs title="TOOLS" group="tools" items={['quick actions','system','capabilities']} active={toolsTab} on:select={(e)=>toolsTab=e.detail}/>
    <div class="page-body">
      {#key toolsTab}<section class="page-main tab-enter">
        {#if toolsTab==='quick actions'}<div class="tools-grid"><QuickActions on:navigate={(event)=>page=event.detail as typeof page}/><Diagnostics/><EventTimeline/></div>
        {:else if toolsTab==='system'}<div class="tools-grid"><SystemOverview/><ProcessOverview/><LocalAI/><NetworkPanel/><Diagnostics/></div>        {:else}<Capabilities/>{/if}
      </section>{/key}
      <PageRail/>
    </div>
  {:else if page==='about'}
    <div class="page-body about-body">
      <section class="page-main">
        <section class="about-page panel"><h2>ARGUS</h2><h1>Autonomous Reconnaissance and Guardian Unified System</h1><p>Local-first tactical intelligence interface for a Windows operator.</p><dl><div><dt>VERSION</dt><dd>{$snapshotStatus?.version ?? 'UNKNOWN'}</dd></div><div><dt>RUNTIME</dt><dd>FASTAPI · PYWEBVIEW / WEBVIEW2</dd></div><div><dt>LOCAL SERVICES</dt><dd>MODEL · FASTER-WHISPER STT · PIPER TTS</dd></div><div><dt>SECURITY MODEL</dt><dd>BACKEND POLICY AND AUTHORIZATION</dd></div></dl><small>Created by Sodik Tursunboev. No credentials or private configuration are displayed here.</small></section>
        <Architecture/>
      </section>
      <PageRail/>
    </div>
  {:else}
    <div class="page-body"><section class="page-main"><SettingsPanel/></section><PageRail/></div>
  {/if}
  </div>
  {/key}
  </div>
  <section class="command-dock" aria-label="Command dock"><CommandInput dock={true}/></section>
  <AppFooter on:navigate={(event)=>page=event.detail}/>
</main>
</Cockpit>
<CommandPalette open={paletteOpen} on:close={()=>paletteOpen=false} on:navigate={(event)=>page=event.detail}/>
