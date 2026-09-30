<script lang="ts">
  // The agent pipeline as a chain of status nodes. Each node's state is a
  // direct read of a store the backend populates; a subsystem the backend
  // exposes no contract for (workers, watchers, scheduler) is shown as a
  // single honest NOT EXPOSED row -- never as an invented agent.
  import { agent } from '../stores/agent'; import { tasks, taskProgress } from '../stores/tasks'; import { connection } from '../stores/connection';
  import { security } from '../stores/security'; import { pendingAuth } from '../stores/authFlow'; import { snapshotStatus } from '../stores/snapshotView'; import { timeline } from '../stores/events';
  import TaskPlan from './TaskPlan.svelte';
  export let tab='active';
  const up = (v: unknown) => v === null || v === undefined || v === '' ? 'UNKNOWN' : String(v).toUpperCase();
  type Node = { key: string; label: string; state: string; active: boolean; detail: string };
  $: nodes = [
    { key: 'voice', label: 'VOICE', state: up($snapshotStatus?.voice_state ?? $agent.voice), active: $agent.state === 'listening' || $agent.voice === 'listening', detail: $snapshotStatus?.muted ? 'MUTED' : `MODE ${up($agent.voice)}` },
    { key: 'router', label: 'ROUTER', state: $agent.state === 'understanding' ? 'CLASSIFYING' : 'READY', active: $agent.state === 'understanding', detail: `ENGINE ${up($snapshotStatus?.engine)}` },
    { key: 'planner', label: 'PLANNER', state: $agent.state === 'planning' ? 'PLANNING' : $tasks.goal ? up($tasks.status) : 'IDLE', active: $agent.state === 'planning', detail: $tasks.goal ? `REV ${$tasks.revision} · ${$taskProgress.totalSteps} STEPS` : 'NO ACTIVE PLAN' },
    { key: 'policy', label: 'POLICY', state: up($security.decision?.policy ?? $security.fields.policyEngine), active: $security.decision?.status === 'blocked', detail: $security.decision?.capability ? `CAP ${$security.decision.capability}` : `ENGINE ${$security.fields.policyEngine}` },
    { key: 'auth', label: 'AUTH', state: $pendingAuth ? 'REQUIRED' : up($security.auth), active: $agent.state === 'waiting_auth' || !!$pendingAuth, detail: $pendingAuth ? `${$pendingAuth.mode.toUpperCase()} · ${$pendingAuth.level}` : `LEVEL ${$security.fields.authLevel}` },
    { key: 'executor', label: 'EXECUTOR', state: $agent.state === 'executing' ? 'RUNNING' : up($security.decision?.executor ?? $security.fields.executor), active: $agent.state === 'executing', detail: $agent.activeCapability ? `CAP ${$agent.activeCapability}` : 'NO ACTIVE CAPABILITY' },
    { key: 'verify', label: 'VERIFY', state: $agent.state === 'verifying' ? 'CHECKING' : $tasks.status === 'completed' ? 'PASSED' : $tasks.status === 'failed' ? 'FAILED' : 'IDLE', active: $agent.state === 'verifying', detail: $taskProgress.totalSteps ? `${$taskProgress.completedSteps}/${$taskProgress.totalSteps} STEPS` : 'NO STEPS' },
  ] satisfies Node[];
  $: recent = $timeline.filter((e) => ['AGENT','MODEL','EXECUTE','VERIFY','POLICY','AUTH'].includes(e.category)).slice(0, 10);
  const stamp = (t: number) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const notExposed = ['WORKERS','WATCHERS','SCHEDULER'] as const;
</script>
<section class="agents-page" aria-label="ARGUS agents and task architecture">
  {#if tab==='active' || tab==='planner'}
    <section class="panel pipeline">
      <div class="panel-title"><h2>AGENT PIPELINE</h2><span class="status">{up($agent.state)}</span></div>
      <ol class="node-chain">
        {#each nodes as node (node.key)}
          <li class:active={node.active} class:highlight={tab==='planner' && node.key==='planner'}>
            <i class="node-dot"></i><b>{node.label}</b><span class="node-state">{node.state}</span><small>{node.detail}</small>
          </li>
        {/each}
      </ol>
    </section>
    <div class="agents-lower">
      <section class="panel">
        <div class="panel-title"><h2>{tab==='planner' ? 'CURRENT PLAN' : 'TASK RELATIONSHIP'}</h2><span class:unknown={!$tasks.goal} class="status">{$tasks.goal ? up($tasks.status) : 'NO TASK'}</span></div>
        {#if $tasks.goal}
          <p class="goal-line">{$tasks.goal}</p>
          <TaskPlan task={$tasks} progress={$taskProgress}/>
        {:else}
          <div class="signal-grid">
            <div><span>AGENT</span><b>{up($agent.state)}</b></div>
            <div><span>CONNECTION</span><b>{up($connection.source)}</b></div>
            <div><span>CAPABILITY</span><b>{$agent.activeCapability ?? '—'}</b></div>
            <div><span>PLAN</span><b>AWAITING OBJECTIVE</b></div>
          </div>
        {/if}
      </section>
      <section class="panel">
        <div class="panel-title"><h2>SUBSYSTEMS</h2><span class="status">BACKEND CONTRACT</span></div>
        <div class="rail-kv"><span>PLANNER</span><b class="ok"><i class="dot"></i>ACTIVE STATE ONLY</b></div>
        {#each notExposed as name}<div class="rail-kv"><span>{name}</span><b class="dim"><i class="dot"></i>NOT EXPOSED</b></div>{/each}
        <p class="rail-note">ARGUS reports only the live agent and its active task. It does not invent autonomous agents, scheduled work, or a history the backend has not sent.</p>
      </section>
    </div>
  {:else if tab==='history'}
    <section class="panel">
      <div class="panel-title"><h2>RECENT AGENT ACTIVITY</h2><span class:unknown={!recent.length} class="status">{recent.length ? `${recent.length} EVENTS` : 'NONE THIS SESSION'}</span></div>
      {#if recent.length}<div class="mini-events">{#each recent as e (e.id)}<div class:warning={e.severity==='warning'} class:critical={e.severity==='critical'}><time>{stamp(e.timestamp)}</time><b class={`chip chip-${e.category.toLowerCase()}`}>{e.category}</b><span>{e.message}</span></div>{/each}</div>{:else}<p class="rail-note">No agent events have been received in this session. A persisted history is not exposed by the backend.</p>{/if}
    </section>
  {:else}
    <section class="panel compact-unavailable"><div class="panel-title"><h2>{tab.toUpperCase()}</h2><span class="status unknown">NOT EXPOSED</span></div><p class="rail-note">The backend exposes no bounded, safe {tab} contract. Nothing is shown rather than something invented.</p></section>
  {/if}
</section>
