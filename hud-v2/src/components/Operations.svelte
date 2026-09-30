<script lang="ts">
  import { agent } from '../stores/agent';
  import { security } from '../stores/security';
  import { tasks, taskProgress } from '../stores/tasks';
  import { connection } from '../stores/connection';
  import { telemetry, metric } from '../stores/telemetry';
  import { snapshotStatus, securityReport, threatReport } from '../stores/snapshotView';
  import { timeline } from '../stores/events';
  import type { BackendProcess } from '../types/argus';
  import ProcessOverview from './ProcessOverview.svelte';
  import SecurityStatus from './SecurityStatus.svelte';
  import ThreatMonitor from './ThreatMonitor.svelte';
  import EventTimeline from './EventTimeline.svelte';
  import Diagnostics from './Diagnostics.svelte';
  import {
    IconOperations, IconSystem, IconProcess, IconAI, IconNetwork,
    IconThreat, IconObjective, IconTimeline, IconTools,
    IconCPU, IconMemory, IconGPU, IconDisk,
    IconSuccess, IconWarning, IconCritical, IconInfo, IconOffline,
  } from '../lib/ui/icons';

  const percent = (v: number | null | undefined) => v == null ? '—' : `${Math.round(v)}%`;
  const gb = (v: number | undefined) => typeof v === 'number' ? `${v.toFixed(2)} GB` : '—';
  const known = (v: string | undefined | null) => v?.toUpperCase() || 'UNKNOWN';

  /* Status strip classes */
  $: argusOk = !['error','lockdown','blocked'].includes($agent.state);
  $: backendOk = $connection.source === 'live' || $connection.source === 'partial';
  $: wsOk = $connection.socket === 'connected';
  $: authOk = $security.auth !== 'locked';
  $: secOk = ['normal','unknown'].includes($security.posture);
  $: modelOk = !!$snapshotStatus?.model;
  $: taskLabel = $tasks.status.toUpperCase();

  /* Expanded process table */
  $: processes = ($telemetry?.top_processes ?? []) as BackendProcess[];
  $: anomalyCount = Array.isArray($telemetry?.anomalies) ? $telemetry!.anomalies!.length : 0;
  $: detectionCount = Array.isArray($telemetry?.detections) ? $telemetry!.detections!.length : 0;

  /* Security alerts from threat report */
  $: recentThreats = ($threatReport?.recent ?? []) as Array<{severity?:string;detector?:string;name?:string;at?:string}>;
</script>

<section class="operations-page" aria-label="Operations">
  <!-- TOP STATUS STRIP -->
  <div class="ops-status-strip panel">
    <span class="status-item" class:ok={argusOk} class:crit={!argusOk}>ARGUS <b>{known($agent.state)}</b></span>
    <span class="status-item" class:ok={backendOk} class:warn={!backendOk}>BACKEND <b>{known($connection.source)}</b></span>
    <span class="status-item" class:ok={wsOk} class:crit={$connection.socket==='failed'}>WS <b>{known($connection.socket)}</b></span>
    <span class="status-item" class:ok={authOk} class:crit={!authOk}>AUTH <b>{$security.auth.toUpperCase()}</b></span>
    <span class="status-item" class:ok={secOk} class:crit={!secOk && $security.posture!=='unknown'} class:warn={$security.posture==='unknown'}>SECURITY <b>{$security.posture.toUpperCase()}</b></span>
    <span class="status-item" class:ok={modelOk} class:dim={!modelOk}>MODEL <b>{known($snapshotStatus?.model)}</b></span>
    <span class="status-item">TASK <b>{taskLabel}</b></span>
  </div>

  <!-- A. LIVE SYSTEM -->
  <section class="ops-section panel">
    <h2><IconSystem size={14} class="h2-icon" aria-hidden="true"/>LIVE SYSTEM</h2>
    <div class="ops-metric-grid">
      <div class="ops-metric-card">
        <div class="metric-label"><IconCPU size={12} aria-hidden="true"/>CPU</div>
        <div class="metric-value">{percent($metric.cpu)}</div>
        <div class="metric-detail">{$metric.cpu == null ? 'UNAVAILABLE' : 'LIVE SAMPLE'}</div>
      </div>
      <div class="ops-metric-card">
        <div class="metric-label"><IconMemory size={12} aria-hidden="true"/>MEMORY</div>
        <div class="metric-value">{percent($metric.memory)}</div>
        <div class="metric-detail">{typeof $telemetry?.mem_used_gb === 'number' ? `${$telemetry.mem_used_gb} / ${$telemetry.mem_total_gb} GB` : 'UNAVAILABLE'}</div>
      </div>
      <div class="ops-metric-card">
        <div class="metric-label"><IconGPU size={12} aria-hidden="true"/>GPU</div>
        <div class="metric-value">{percent($metric.gpu)}</div>
        <div class="metric-detail">{typeof $telemetry?.gpu_pct === 'number' ? `${$telemetry.gpu_pct}%` : $telemetry?.gpu_available ? 'AVAILABLE' : 'UNAVAILABLE'}</div>
      </div>
      <div class="ops-metric-card">
        <div class="metric-label"><IconDisk size={12} aria-hidden="true"/>DISK</div>
        <div class="metric-value">{percent($metric.disk)}</div>
        <div class="metric-detail">{typeof $telemetry?.disk_free_gb === 'number' ? `${$telemetry.disk_free_gb} GB FREE` : 'UNAVAILABLE'}</div>
      </div>
    </div>
    {#if anomalyCount > 0 || detectionCount > 0}
      <div class="ops-note">
        {#if anomalyCount > 0}<span class="ops-anomaly">{anomalyCount} anomal{anomalyCount === 1 ? 'y' : 'ies'}</span>{/if}
        {#if detectionCount > 0}<span class="ops-detect">{detectionCount} detection{detectionCount === 1 ? '' : 's'}</span>{/if}
      </div>
    {/if}
  </section>

  <!-- B. PROCESS ACTIVITY -->
  <section class="ops-section panel">
    <h2><IconProcess size={14} class="h2-icon" aria-hidden="true"/>PROCESS ACTIVITY</h2>
    <ProcessOverview/>
    {#if processes.length > 0}
      <div class="ops-process-table">
        <span class="proc-head">NAME</span>
        <span class="proc-head">PID</span>
        <span class="proc-head">CPU %</span>
        <span class="proc-head">MEM MB</span>
        <span class="proc-head">THREADS</span>
        {#each processes as proc (proc.pid ?? proc.name)}
          <div class="proc-row">
            <span>{proc.name ?? '—'}</span>
            <span>{proc.pid ?? '—'}</span>
            <span>{typeof proc.cpu === 'number' ? `${proc.cpu.toFixed(1)}` : '—'}</span>
            <span>{typeof proc.mb === 'number' ? proc.mb.toFixed(0) : '—'}</span>
            <span>{proc.threads ?? '—'}</span>
          </div>
        {/each}
      </div>
    {:else}
      <p class="ops-empty">No process data available.</p>
    {/if}
  </section>

  <!-- C. NETWORK OPERATIONS -->
  <section class="ops-section panel">
    <h2><IconNetwork size={14} class="h2-icon" aria-hidden="true"/>NETWORK OPERATIONS</h2>
    <div class="ops-network-detail">
      <dl class="ops-dl">
        <div><dt>RECEIVED</dt><dd>{$telemetry ? gb($telemetry.net_recv_gb) : '—'}</dd></div>
        <div><dt>SENT</dt><dd>{$telemetry ? gb($telemetry.net_sent_gb) : '—'}</dd></div>
        <div><dt>EGRESS POLICY</dt><dd>{$securityReport?.network?.egress_policy ?? 'NOT REPORTED'}</dd></div>
        <div><dt>BACKEND LINK</dt><dd>{$connection.source.toUpperCase()}</dd></div>
        <div><dt>LOCAL AI</dt><dd>{$telemetry ? 'CONNECTED' : 'UNAVAILABLE'}</dd></div>
      </dl>
    </div>
  </section>

  <!-- D. AGENT / EXECUTION -->
  <section class="ops-section panel">
    <h2><IconObjective size={14} class="h2-icon" aria-hidden="true"/>AGENT / EXECUTION</h2>
    <div class="ops-agent-grid">
      <dl class="ops-dl">
        <div><dt>STATE</dt><dd>{$agent.state.toUpperCase()}</dd></div>
        <div><dt>CAPABILITY</dt><dd>{known($agent.activeCapability ?? $tasks.activeCapability)}</dd></div>
        <div><dt>VOICE</dt><dd>{$agent.voice.toUpperCase()}</dd></div>
        <div><dt>MISSION</dt><dd>{$taskProgress.totalSteps ? `${$taskProgress.completedSteps} / ${$taskProgress.totalSteps} (${Math.round($taskProgress.percent)}%)` : '—'}</dd></div>
      </dl>
      <dl class="ops-dl">
        <div><dt>TASK STATUS</dt><dd>{$tasks.status.toUpperCase()}</dd></div>
        <div><dt>SECURITY</dt><dd>{$security.posture.toUpperCase()}</dd></div>
        <div><dt>AUTH LEVEL</dt><dd>{$security.fields.authLevel}</dd></div>
        <div><dt>EXECUTOR</dt><dd>{$security.fields.executor}</dd></div>
      </dl>
    </div>
    {#if $tasks.goal}
      <div class="ops-objective">
        <b>CURRENT OBJECTIVE</b>
        <p>{$tasks.goal}</p>
      </div>
    {/if}
  </section>

  <!-- E. SECURITY EVENTS -->
  <section class="ops-section panel">
    <h2><IconThreat size={14} class="h2-icon" aria-hidden="true"/>SECURITY EVENTS</h2>
    <div class="ops-two-col">
      <SecurityStatus/>
      <ThreatMonitor/>
    </div>
  </section>

  <!-- F. TIMELINE / AUDIT -->
  <section class="ops-section panel ops-timeline">
    <h2><IconTimeline size={14} class="h2-icon" aria-hidden="true"/>TIMELINE / AUDIT</h2>
    <EventTimeline/>
  </section>

  <!-- G. DIAGNOSTICS -->
  <section class="ops-section panel ops-diagnostics">
    <h2><IconTools size={14} class="h2-icon" aria-hidden="true"/>DIAGNOSTICS</h2>
    <Diagnostics/>
  </section>
</section>
