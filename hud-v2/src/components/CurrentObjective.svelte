<script lang="ts">
  import { tasks, taskProgress } from '../stores/tasks';
  import TaskPlan from './TaskPlan.svelte';
  import { IconObjective } from '../lib/ui/icons';
  $: active = $tasks.goal !== null && $tasks.status !== 'idle' && $tasks.status !== 'unknown';
  $: lastCompleted = [...$tasks.steps].reverse().find((step) => step.status === 'complete');
</script>

<section class="panel objective" aria-label="Current objective" data-testid="objective">
  <h2>CURRENT OBJECTIVE</h2>
  {#if !active}
    <div class="objective-copy empty"><span class="target"><IconObjective size={24} aria-hidden="true"/></span><div><p>No active task</p><small>ARGUS is standing by.</small></div></div>
    <div class="objective-idle"><div><span>PLAN</span><b>AWAITING OBJECTIVE</b></div><p>○ A backend task plan has not been received.</p><p>○ Voice and command surfaces remain available.</p></div>
  {:else}
    <div class="objective-copy"><span class="target"><IconObjective size={24} aria-hidden="true"/></span><p>{$tasks.goal}</p></div>
    {#if $tasks.status === 'completed'}
      <div class="task-outcome complete"><b>MISSION COMPLETE</b>{#if lastCompleted}<span>LAST STEP · {lastCompleted.label}</span>{/if}</div>
    {:else if $tasks.status === 'failed'}
      <div class="task-outcome failed"><b>MISSION FAILED</b><span>{ $tasks.reason ?? 'A safe failure reason is unavailable.' }</span>{#if $tasks.replanAvailable}<em>REPLAN AVAILABLE</em>{/if}</div>
    {/if}
    <TaskPlan task={$tasks} progress={$taskProgress} />
  {/if}
</section>
