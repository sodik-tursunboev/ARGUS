<script lang="ts">
  import type { ArgusTask } from '../types/argus';
  import type { Component } from 'svelte';
  import { IconTaskPending, IconTaskActive, IconTaskComplete, IconTaskBlocked, IconTaskAuthWait, IconTaskFailed, IconTaskSkipped } from '../lib/ui/icons';
  export let task: ArgusTask;
  export let progress: { totalSteps: number; completedSteps: number; currentIndex: number; percent: number };
  // Step-status glyphs are semantic icons (Phosphor), each tied to a distinct
  // state so the step marker reads at a glance. The number cell stays tabular.
  const symbol: Record<ArgusTask['steps'][number]['status'], Component> = {
    pending: IconTaskPending, active: IconTaskActive, complete: IconTaskComplete,
    blocked: IconTaskBlocked, waiting_auth: IconTaskAuthWait, failed: IconTaskFailed,
    skipped: IconTaskSkipped,
  };
  const label = { pending: 'PENDING', active: 'ACTIVE', complete: 'COMPLETE', blocked: 'BLOCKED', waiting_auth: 'WAITING FOR AUTH', failed: 'FAILED', skipped: 'SKIPPED' } as const;
</script>

<div class="plan-title"><span>PLAN</span><b>{progress.totalSteps ? `STEP ${Math.max(1, progress.currentIndex + 1)} / ${progress.totalSteps}` : 'STEP — / —'}</b></div>
{#if task.status === 'replanned'}<div class="replan-note">REPLAN APPLIED · COMPLETED STEPS PRESERVED</div>{/if}
<ol class="task-plan" aria-label="Task execution plan">
  {#each task.steps as step, index (step.id)}
    {@const S = symbol[step.status]}
    <li class:inserted={step.inserted} class={`step-${step.status}`}>
      <span class="step-number">{String(index + 1).padStart(2, '0')}</span><i><S size={12} aria-hidden="true"/></i><span class="step-label">{step.label}</span><small>{label[step.status]}</small>
    </li>
  {/each}
</ol>
<div class="progress" aria-label={`${progress.completedSteps} of ${progress.totalSteps} steps complete`}><i style={`width:${progress.percent}%`}></i></div>
