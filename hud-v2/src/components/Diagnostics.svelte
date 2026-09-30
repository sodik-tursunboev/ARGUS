<script lang="ts">
  // Self-test readout for the Tools page: the link, snapshot and integrity
  // facts the HUD already holds, presented as a checklist. Each row is a
  // reported value; nothing is probed or simulated from the frontend.
  import { connection } from '../stores/connection'; import { security } from '../stores/security'; import { snapshotStatus, securityReport } from '../stores/snapshotView'; import { telemetry } from '../stores/telemetry';
  const up = (v: unknown) => v === null || v === undefined || v === '' ? 'UNKNOWN' : String(v).toUpperCase();
  const ago = (t: number | null) => t === null ? 'NEVER' : `${Math.max(0, Math.round((Date.now() - t) / 1000))}S AGO`;
  let now = Date.now(); const timer = setInterval(() => now = Date.now(), 1000);
  import { onDestroy } from 'svelte'; onDestroy(() => clearInterval(timer));
  const tone = (s: string) => /live|connected|verified|intact|valid|normal|ok|yes|hardened|enabled|active/i.test(s) ? 'ok' : /unknown|never|loading|unavailable|disconnected/i.test(s) ? 'dim' : /stale|partial|reconnecting|degraded|warning|no\b/i.test(s) ? 'warn' : 'bad';
  $: rows = [
    ['BACKEND LINK', up($connection.source)],
    ['LIVE CHANNEL', up($connection.socket)],
    ['LAST SNAPSHOT', now ? ago($connection.lastSuccessAt) : '—'],
    ['LAST SOCKET EVENT', now ? ago($connection.lastSocketEventAt) : '—'],
    ['SNAPSHOT FRESHNESS', up($security.freshness)],
    ['RETRIES', String($connection.retryCount)],
    ['TELEMETRY SAMPLER', $telemetry ? 'ACTIVE' : 'UNAVAILABLE'],
    ['INTEGRITY', $securityReport?.integrity?.ok === true ? 'VERIFIED' : $securityReport?.integrity?.ok === false ? 'DEGRADED' : 'UNKNOWN'],
    ['AUDIT CHAIN', $securityReport?.audit?.chain_intact === true ? 'INTACT' : $securityReport?.audit?.chain_intact === false ? 'BROKEN' : 'UNKNOWN'],
    ['BACKEND VERSION', up($snapshotStatus?.version)],
  ];
</script>
<section class="panel diagnostics" aria-label="Diagnostics">
  <div class="panel-title"><h2>DIAGNOSTICS / SELF-TEST</h2><span class:unknown={$connection.source!=='live'} class="status">{up($connection.source)}</span></div>
  <div class="matrix-grid two">{#each rows as [label, value]}<div class={tone(value)}><i class="dot"></i><span>{label}</span><b>{value}</b></div>{/each}</div>
  {#if $connection.message}<p class="rail-note">{$connection.message}</p>{/if}
</section>
