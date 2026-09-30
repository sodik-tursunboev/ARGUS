<script lang="ts">
  /* AGENT JOB HISTORY — the real /api/agents/jobs contract (bounded,
     redacted job records straight from the coordinator). Complements the
     live activity feed: this is what the backend still remembers, not what
     the WS stream happened to deliver this session. */
  import { onMount } from 'svelte';
  import { fetchAgentJobs, type OfficeJobDTO } from '../services/api';
  import { agentOffice } from '../stores/agentOffice';

  let jobs: OfficeJobDTO[] = [];
  let loaded = false;
  let error = '';

  const stateClass: Record<string, string> = {
    queued: 'st-queued', running: 'st-thinking', thinking: 'st-thinking',
    waiting_auth: 'st-queued', completed: 'st-ok', failed: 'st-critical',
    cancelled: 'st-idle', blocked: 'st-critical',
  };
  const stateLabel = (s: string) => s.replace('_', ' ').toUpperCase();
  const stamp = (ts: number) => new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  async function load(): Promise<void> {
    try {
      const data = await fetchAgentJobs();
      jobs = data.jobs ?? [];
      error = '';
    } catch (e) {
      error = e instanceof Error ? e.message : 'Job history unavailable';
    } finally {
      loaded = true;
    }
  }

  onMount(() => {
    void load();
    const timer = window.setInterval(load, 6000);
    return () => window.clearInterval(timer);
  });
</script>

<section class="panel history-panel" aria-label="Agent job history">
  <div class="panel-title"><h2>AGENT JOB HISTORY</h2>
    <span class="status" class:unknown={!loaded || !!error}>
      {loaded ? (error ? 'UNAVAILABLE' : jobs.length ? `${jobs.length} RECORDS` : 'NO JOBS YET') : 'LOADING'}
    </span>
  </div>
  {#if error}
    <p class="rail-note">{error}</p>
  {:else if loaded && !jobs.length}
    <p class="rail-note">No agent jobs yet this session. Submit one from the Agents Office, or turn autonomy on and the specialists will start cycling.</p>
  {:else}
    <div class="office-queue">
      <div class="office-queue-row office-queue-head"><span>TIME</span><span>AGENT</span><span>OBJECTIVE</span><span>STATE</span></div>
      {#each jobs.slice(0, 14) as j (j.job_id)}
        <div class="office-queue-row">
          <span>{stamp(j.created_at)}</span>
          <b>{j.agent_id.toUpperCase()}</b>
          <span class="office-queue-objective">{j.objective || '—'}</span>
          <span class={stateClass[j.state] ?? ''}>{stateLabel(j.state)}</span>
        </div>
      {/each}
    </div>
  {/if}
</section>
