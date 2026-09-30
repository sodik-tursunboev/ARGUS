<script lang="ts">
  // Compact context rail shown beside every secondary page. Every value is
  // read from a store the dashboard already renders -- nothing here is a new
  // data source, and nothing is estimated. Where the backend has not reported
  // a value the rail says so rather than filling the slot.
  import { agent } from '../stores/agent'; import { connection } from '../stores/connection'; import { security } from '../stores/security';
  import { snapshotStatus, threatReport } from '../stores/snapshotView'; import { tasks, taskProgress } from '../stores/tasks';
  import { telemetry, metric } from '../stores/telemetry';
  const pct = (v: number | null) => v === null ? null : Math.max(0, Math.min(100, Math.round(v)));
  $: meters = [['CPU', pct($metric.cpu)], ['MEMORY', pct($metric.memory)], ['DISK', pct($metric.disk)], ['GPU', pct($metric.gpu)]] as const;
  $: procs = ($telemetry?.top_processes ?? []).filter((p) => p && p.name).slice(0, 4);
  const RUNGS = [['standby','STANDBY'],['listening','LISTENING'],['understanding','THINKING'],['planning','PLANNING'],['waiting_auth','AUTH WAIT'],['executing','EXECUTING'],['verifying','VERIFYING']] as const;
  const up = (v: string | number | null | undefined) => v === null || v === undefined || v === '' ? 'UNKNOWN' : String(v).toUpperCase();
  function uptime(seconds: number | undefined): string { if (typeof seconds !== 'number') return 'UNKNOWN'; const h = Math.floor(seconds / 3600), m = Math.floor((seconds % 3600) / 60); return h ? `${h}H ${m}M` : `${m}M`; }
  $: tone = (v: string) => /normal|valid|live|connected|online|ready|healthy|enforced|verified|confirmed|low/i.test(v) ? 'ok' : /unknown|unavailable|loading|offline|disconnected|stale/i.test(v) ? 'dim' : /degraded|warning|required|reconnecting|partial|medium|expired/i.test(v) ? 'warn' : /critical|blocked|lockdown|failed|high|error/i.test(v) ? 'bad' : 'ok';
  $: threatLevel = up($threatReport?.level ?? $security.fields.threatState);
</script>
<aside class="page-rail" aria-label="Live context">
  <section class="rail-block">
    <h3>AGENT LIFECYCLE</h3>
    <ul class="rail-ladder">{#each RUNGS as [key, label]}<li class:active={$agent.state===key}><i></i>{label}</li>{/each}</ul>
    {#if !RUNGS.some(([key]) => key===$agent.state)}<p class="rail-note">STATE · {up($agent.state)}</p>{/if}
    <div class="rail-kv"><span>CAPABILITY</span><b>{up($agent.activeCapability ?? $tasks.activeCapability)}</b></div>
    <div class="rail-kv"><span>VOICE</span><b>{up($agent.voice)}</b></div>
  </section>
  <section class="rail-block">
    <h3>LINK</h3>
    <div class="rail-kv"><span>BACKEND</span><b class={tone(up($connection.source))}><i class="dot"></i>{up($connection.source)}</b></div>
    <div class="rail-kv"><span>SOCKET</span><b class={tone(up($connection.socket))}><i class="dot"></i>{up($connection.socket)}</b></div>
    <div class="rail-kv"><span>SNAPSHOT</span><b class={tone(up($security.freshness))}><i class="dot"></i>{up($security.freshness)}</b></div>
    {#if $connection.retryCount}<div class="rail-kv"><span>RETRIES</span><b>{$connection.retryCount}</b></div>{/if}
  </section>
  <section class="rail-block">
    <h3>SECURITY</h3>
    <div class="rail-kv"><span>POSTURE</span><b class={tone(up($security.posture))}><i class="dot"></i>{up($security.posture)}</b></div>
    <div class="rail-kv"><span>AUTH</span><b class={tone(up($security.auth))}><i class="dot"></i>{up($security.auth)} · {$security.fields.authLevel}</b></div>
    <div class="rail-kv"><span>THREAT</span><b class={tone(threatLevel)}><i class="dot"></i>{threatLevel}</b></div>
    <div class="rail-kv"><span>EXECUTOR</span><b>{$security.fields.executor}</b></div>
  </section>
  <section class="rail-block">
    <h3>TELEMETRY</h3>
    {#each meters as [label, value]}
      <div class="rail-meter" class:dim={value===null}><span>{label}</span><i><b style={`width:${value ?? 0}%`}></b></i><em>{value === null ? '—' : `${value}%`}</em></div>
    {/each}
    {#if procs.length}
      <h3 class="rail-sub">TOP PROCESSES</h3>
      {#each procs as p (p.pid ?? p.name)}
        <div class="rail-kv proc"><span>{p.name}</span><b>{typeof p.cpu === 'number' ? `${p.cpu.toFixed(0)}%` : '—'} · {typeof p.mb === 'number' ? `${Math.round(p.mb)} MB` : '—'}</b></div>
      {/each}
    {/if}
  </section>
  <section class="rail-block">
    <h3>RUNTIME</h3>
    <div class="rail-kv"><span>MODEL</span><b>{up($snapshotStatus?.model)}</b></div>
    <div class="rail-kv"><span>ENGINE</span><b>{up($snapshotStatus?.engine)}</b></div>
    <div class="rail-kv"><span>UPTIME</span><b>{uptime($snapshotStatus?.uptime_seconds)}</b></div>
    <div class="rail-kv"><span>VERSION</span><b>{up($snapshotStatus?.version)}</b></div>
    {#if $tasks.goal}<div class="rail-kv"><span>TASK</span><b>{$taskProgress.completedSteps}/{$taskProgress.totalSteps} · {up($tasks.status)}</b></div>{/if}
  </section>
</aside>
