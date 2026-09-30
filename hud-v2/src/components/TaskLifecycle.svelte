<script lang="ts">
  // Linear task lifecycle, positioned from the real task + agent state. The
  // stage list is the fixed vocabulary of ArgusTask.status / AgentState;
  // which node lights is derived, never guessed from wall-clock time.
  import { tasks, taskProgress } from '../stores/tasks'; import { agent } from '../stores/agent'; import { timeline } from '../stores/events'; import { IconTasks } from '../lib/ui/icons';
  const STAGES = ['CREATED','PLANNING','AUTH','EXECUTING','VERIFYING','COMPLETE'] as const;
  $: position = (() => {
    const s = $tasks.status, a = $agent.state;
    if (s === 'idle' || s === 'unknown') return -1;
    if (s === 'completed') return 5;
    if (a === 'verifying') return 4;
    if (s === 'executing' || a === 'executing') return 3;
    if (s === 'waiting_auth' || a === 'waiting_auth') return 2;
    if (s === 'created' || s === 'replanned' || a === 'planning' || a === 'understanding') return 1;
    return 0;
  })();
  $: halted = $tasks.status === 'blocked' || $tasks.status === 'failed';
  $: current = $tasks.steps.find((step) => step.id === $tasks.currentStepId);
  $: recent = $timeline.filter((e) => ['AGENT','EXECUTE','VERIFY','POLICY','AUTH'].includes(e.category)).slice(0, 8);
  const stamp = (t: number) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
</script>
<section class="panel lifecycle" aria-label="Task lifecycle">
  <div class="panel-title"><h2><IconTasks size={12} class="h2-icon" aria-hidden="true"/>TASK LIFECYCLE</h2><span class:unknown={position<0} class:bad={halted} class="status">{halted ? $tasks.status.toUpperCase() : position < 0 ? 'IDLE' : STAGES[position]}</span></div>
  <ol class="lifecycle-rail" class:halted>
    {#each STAGES as stage, i}
      <li class:done={i<position} class:active={i===position} class:halt={halted && i===position}><i></i><span>{stage}</span></li>
    {/each}
  </ol>
  <div class="signal-grid">
    <div><span>GOAL</span><b>{$tasks.goal ?? 'NONE'}</b></div>
    <div><span>STATUS</span><b>{$tasks.status.toUpperCase()}</b></div>
    <div><span>CURRENT STEP</span><b>{current ? current.label : '—'}</b></div>
    <div><span>PROGRESS</span><b>{$taskProgress.totalSteps ? `${$taskProgress.completedSteps} / ${$taskProgress.totalSteps} · ${Math.round($taskProgress.percent)}%` : '— / —'}</b></div>
    <div><span>CAPABILITY</span><b>{$tasks.activeCapability ?? $agent.activeCapability ?? '—'}</b></div>
    <div><span>REVISION</span><b>{$tasks.revision}{$tasks.replanAvailable ? ' · REPLAN AVAILABLE' : ''}</b></div>
    {#if $tasks.reason}<div class="wide"><span>REASON</span><b>{$tasks.reason}</b></div>{/if}
  </div>
  <div class="progress rail-progress" aria-hidden="true"><i style={`width:${$taskProgress.percent}%`}></i></div>
  <h3 class="sub">RECENT TASK ACTIVITY</h3>
  {#if recent.length}
    <div class="mini-events">{#each recent as e (e.id)}<div class:warning={e.severity==='warning'} class:critical={e.severity==='critical'}><time>{stamp(e.timestamp)}</time><b class={`chip chip-${e.category.toLowerCase()}`}>{e.category}</b><span>{e.message}</span></div>{/each}</div>
  {:else}
    <p class="rail-note">No task events received in this session.</p>
  {/if}
</section>
