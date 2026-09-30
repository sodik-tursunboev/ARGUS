<script lang="ts">
  import { metric, telemetry } from '../stores/telemetry';
  import { IconCPU, IconMemory, IconGPU, IconDisk } from '../lib/ui/icons';
  // The four telemetry cards (CPU / MEMORY / GPU / DISK), shared by the
  // Dashboard panel (dash/DashSystem.svelte) and the Tools page
  // (SystemOverview.svelte). DATA is untouched: every value still comes from
  // the same $metric / $telemetry fields. Anything the backend did not report
  // reads NOT REPORTED (same wording as the Security and Local AI panels),
  // never a placeholder number, and nothing is invented: no clock speed, no
  // VRAM, no disk capacity -- only fields the backend actually reports.
  const SEGMENTS = 16;
  const NOT_REPORTED = 'NOT REPORTED';
  // Segments lit = share of the bar actually used (100% fills all 16).
  const lit = (value: number | null): number => value === null ? 0 : Math.max(0, Math.min(SEGMENTS, Math.round(value / 100 * SEGMENTS)));
  $: metrics = [
    { key: 'cpu', label: 'CPU', pct: $metric.cpu, sub: $metric.cpu === null ? NOT_REPORTED : 'LIVE SAMPLE', icon: IconCPU },
    { key: 'memory', label: 'MEMORY', pct: $metric.memory, sub: typeof $telemetry?.mem_used_gb === 'number' && typeof $telemetry?.mem_total_gb === 'number' ? `${$telemetry.mem_used_gb} / ${$telemetry.mem_total_gb} GB` : NOT_REPORTED, icon: IconMemory },
    { key: 'gpu', label: 'GPU', pct: $metric.gpu, sub: $metric.gpu === null ? NOT_REPORTED : 'LIVE SAMPLE', icon: IconGPU },
    { key: 'disk', label: 'DISK', pct: $metric.disk, sub: typeof $telemetry?.disk_free_gb === 'number' ? `${$telemetry.disk_free_gb} GB FREE` : NOT_REPORTED, icon: IconDisk }
  ];
</script>

<div class="cards">
  {#each metrics as m (m.key)}{@const I = m.icon}
    <article class="card" class:na={m.pct === null} data-metric={m.key}>
      <div class="in">
        <span class="ico"><I weight="duotone" aria-hidden="true"/></span>
        <span class="lbl">{m.label}</span>
        <b class="val">{#if m.pct === null}<span class="num">—</span>{:else}<span class="num">{Math.round(m.pct)}</span><span class="unit">%</span>{/if}</b>
        <small class="cap" title={m.sub}>{m.sub}</small>
        <div class="bar" role="meter" aria-label="{m.label} usage" aria-valuemin="0" aria-valuemax="100" aria-valuenow={m.pct === null ? undefined : Math.round(m.pct)} aria-valuetext={m.pct === null ? NOT_REPORTED : `${Math.round(m.pct)} percent`}>{#each Array(SEGMENTS) as _, i}<i class:on={i < lit(m.pct)}></i>{/each}</div>
      </div>
    </article>
  {/each}
</div>

<style>
  /* 2x2 that takes whatever height the panel gives it, but never squeezes a
     card below its own content (min-content floor): cards can not overlap. */
  .cards {
    display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); grid-auto-rows: minmax(min-content, 1fr);
    gap: var(--ds-gap, 8px); flex: 1 1 auto; min-width: 0; min-height: 0;
  }

  /* Each card is its own size container: layout follows the CARD width, so the
     same component is right in the 143-205px dashboard cards and the ~300px
     Tools-page cards. */
  .card {
    container-type: inline-size; position: relative; display: grid; min-width: 0;
    background: linear-gradient(160deg, rgba(11, 30, 36, .8), rgba(4, 13, 17, .62));
    border: 1px solid rgba(0, 234, 242, .18);
    box-shadow: inset 0 1px 0 rgba(210, 245, 250, .05), inset 0 0 26px rgba(0, 234, 242, .035);
    /* opposite corners cut (TR + BL): the panel's chamfer language, one step in */
    clip-path: polygon(0 0, calc(100% - 8px) 0, 100% 8px, 100% 100%, 8px 100%, 0 calc(100% - 8px));
  }
  .card::before { content: ''; position: absolute; left: 9px; top: 0; width: 20px; height: 2px; background: var(--cyan); opacity: .9; }

  /* Narrow card (dashboard): icon anchors the left, LABEL over VALUE beside
     it, the real secondary value and the usage bar full-width underneath. */
  .in {
    --ico: clamp(32px, 22cqi, 42px);
    display: grid; align-content: center; align-items: center; min-width: 0;
    padding: clamp(7px, .95vh, 11px) clamp(9px, .85vw, 12px);
    grid-template-columns: var(--ico) minmax(0, 1fr); column-gap: 9px; row-gap: 2px;
    grid-template-areas: 'ico lbl' 'ico val' 'cap cap' 'bar bar';
  }
  .ico { grid-area: ico; align-self: center; display: block; line-height: 0; font-size: var(--ico); color: var(--cyan-soft); filter: drop-shadow(0 0 8px rgba(0, 234, 242, .3)); }
  .ico :global(svg) { display: block; }
  .lbl { grid-area: lbl; align-self: end; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font: 700 var(--ds-label, 15px)/1.1 var(--font-ui); letter-spacing: .09em; text-transform: uppercase; color: var(--secondary); }
  .val {
    grid-area: val; align-self: start; display: flex; align-items: baseline; gap: 3px; min-width: 0;
    font: 700 var(--ds-value, 26px)/1.02 var(--font-data); letter-spacing: -.02em; font-variant-numeric: tabular-nums; color: var(--text);
  }
  .val .unit { font-size: .52em; letter-spacing: 0; color: var(--secondary); }
  /* .cap, not .sub: the legacy global .sub { font-size:13px !important } (core-readability.css) would win */
  .cap {
    grid-area: cap; margin-top: 4px; min-width: 0; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    font: 700 var(--ds-sec, 11px)/1.15 var(--font-data); letter-spacing: .05em; text-transform: uppercase; color: var(--secondary);
  }
  .bar { grid-area: bar; display: flex; gap: 2px; height: clamp(9px, 1.25vh, 12px); margin-top: 5px; padding-inline: 2px; }
  .bar i { flex: 1 1 0; min-width: 0; background: rgba(23, 110, 122, .32); border-radius: 1px; transform: skewX(-18deg); }
  .bar i.on { background: var(--cyan); box-shadow: 0 0 8px rgba(0, 234, 242, .45); }

  /* Wide card (Tools page): the sketch layout -- icon | LABEL ... VALUE / secondary / bar. */
  @container (min-width: 236px) {
    .in { grid-template-columns: var(--ico) minmax(0, 1fr) auto; grid-template-areas: 'ico lbl val' 'ico cap cap' 'ico bar bar'; column-gap: 12px; }
    .lbl { align-self: center; }
    .val { align-self: center; justify-self: end; }
    .cap { margin-top: 0; }
  }

  /* NOT REPORTED: quiet, never an alert colour, never a fake number. */
  .card.na .ico { color: var(--muted); filter: none; opacity: .75; }
  .card.na .val { color: var(--muted); }
  .card.na .cap { color: color-mix(in srgb, var(--secondary) 62%, var(--muted)); }
  .card.na::before { opacity: .4; }
</style>
