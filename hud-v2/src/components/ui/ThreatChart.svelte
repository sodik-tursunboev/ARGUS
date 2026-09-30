<script lang="ts">
  // Detections over time, as a stacked histogram: one bar per time bin, one
  // segment per detection, coloured by that detection's severity (worst on top).
  // Height = HOW MANY, colour = HOW BAD. Every bar is a count of real detections
  // whose real timestamp fell in that bin (lib/threat.ts) -- nothing is sampled,
  // smoothed or drawn for effect, and when there is no timestamped detection the
  // plot says so instead of drawing a series.
  //
  // Responsive without measuring: the plot is an SVG in a fixed 10-units-per-bin
  // coordinate space stretched to its box (preserveAspectRatio="none", rects and
  // hairlines only, non-scaling strokes), and every piece of TEXT is plain HTML
  // positioned by percentage, so type never scales with the chart and never
  // touches a bar. `compact` is the Dashboard summary; `full` adds the y axis,
  // five time labels and a hover readout for the Security page.
  import { SEVERITIES, axisLabel, describeBin, spanLabel, type Series, type Severity } from '../../lib/threat';
  export let series: Series | null = null;
  export let variant: 'compact' | 'full' = 'compact';
  export let message = 'NO THREAT SERIES AVAILABLE';
  export let reason = '';

  /* bottom -> top */
  const STACK: readonly Severity[] = ['low', 'medium', 'high', 'critical'];
  let hover = -1;

  $: bins = series?.bins ?? [];
  $: windowMs = series ? series.end - series.start : 0;
  // compact: never fewer than 3 rows tall, so a lone detection is a short bar, not a full one.
  // full: whole-number ticks (4, 8, 12 ...) so every gridline is a real count.
  $: yMax = series ? (variant === 'full' ? Math.max(4, Math.ceil(series.max / 4) * 4) : Math.max(3, series.max)) : 1;
  $: unit = 96 / yMax;
  $: bars = bins.flatMap((bin, i) => {
    let base = 100;
    return STACK.flatMap((sev) => {
      const n = bin.counts[sev];
      if (!n) return [];
      const h = n * unit;
      base -= h;
      return [{ key: `${i}:${sev}`, sev, x: i * 10 + 1.7, y: base + .5, h: Math.max(.8, h - 1) }];
    });
  });
  $: yTicks = variant === 'full' ? [0, 1, 2, 3, 4].map((k) => ({ v: Math.round((yMax * k) / 4), top: 100 - (k / 4) * 96 })) : [];
  $: xTicks = series && variant === 'full' ? [0, .25, .5, .75, 1].map((f) => ({ f, label: f === 1 ? 'NOW' : axisLabel(series!.start + f * windowMs, windowMs) })) : [];
  $: summary = series ? `${series.plotted} detection${series.plotted === 1 ? '' : 's'} over the last ${spanLabel(windowMs)}` : message;
</script>

<div class="chart {variant}" class:empty={!series}>
  {#if variant === 'full' && series}
    <div class="yaxis" aria-hidden="true">{#each yTicks as t (t.top)}<span style="top:{t.top}%">{t.v}</span>{/each}</div>
  {/if}
  <div class="plot" role="img" aria-label={summary}>
    <svg viewBox="0 0 {Math.max(1, bins.length) * 10} 100" preserveAspectRatio="none" aria-hidden="true" focusable="false">
      <g class="grid">{#each [25, 50, 75] as y}<line x1="0" x2={Math.max(1, bins.length) * 10} y1={100 - (y / 100) * 96} y2={100 - (y / 100) * 96} vector-effect="non-scaling-stroke"/>{/each}</g>
      {#if series}
        {#if hover >= 0}<rect class="hl" x={hover * 10} y="0" width="10" height="100"/>{/if}
        {#each bars as b (b.key)}<rect class="bar {b.sev}" x={b.x} y={b.y} width="6.6" height={b.h} shape-rendering="crispEdges"/>{/each}
        {#each bins as bin, i}<rect class="hit" x={i * 10} y="0" width="10" height="100" role="presentation" on:pointerenter={() => (hover = i)} on:pointerleave={() => (hover = -1)}><title>{describeBin(bin, windowMs)}</title></rect>{/each}
      {/if}
      <line class="base" x1="0" x2={Math.max(1, bins.length) * 10} y1="100" y2="100" vector-effect="non-scaling-stroke"/>
    </svg>
    {#if !series}
      <div class="none"><b>{message}</b>{#if reason}<span>{reason}</span>{/if}</div>
    {/if}
  </div>
  {#if variant === 'full'}
    <div class="corner" aria-hidden="true"></div>
    <div class="xaxis" aria-hidden="true">{#each xTicks as t (t.f)}<span class:first={t.f === 0} class:last={t.f === 1} style="left:{t.f * 100}%">{t.label}</span>{/each}</div>
  {:else if series}
    <div class="axis" aria-hidden="true"><span>−{spanLabel(windowMs)}</span><span>NOW</span></div>
  {/if}
  {#if variant === 'full' && series}
    <p class="readout" aria-live="polite">{hover >= 0 ? describeBin(bins[hover], windowMs) : `${series.plotted} plotted${series.older ? ` · ${series.older} older than this window` : ''}${series.undated ? ` · ${series.undated} without a timestamp` : ''}`}</p>
  {/if}
</div>

<style>
  .chart { position: relative; display: flex; flex-direction: column; flex: 1 1 auto; min-width: 0; min-height: 0; }
  /* compact: the plot takes the panel's leftover height, never less than 44-72px by window height */
  .compact .plot { flex: 1 1 0; min-height: clamp(44px, 6.4vh, 72px); }
  .plot { position: relative; min-width: 0; }
  svg { position: absolute; inset: 0; width: 100%; height: 100%; display: block; overflow: visible; }
  .grid line { stroke: rgba(223, 251, 255, .075); stroke-width: 1; }
  .base { stroke: rgba(0, 234, 242, .4); stroke-width: 1; }
  .bar { opacity: .95; }
  .bar.low { fill: var(--sev-low, #38e0ff); }
  .bar.medium { fill: var(--sev-medium, #ffc24d); }
  .bar.high { fill: var(--sev-high, #ff8f4d); }
  .bar.critical { fill: var(--sev-critical, #ff4a63); }
  .hl { fill: rgba(0, 234, 242, .07); }
  .hit { fill: transparent; }

  /* no series: the message sits in the plot's own box, over gridlines only (there are no bars to touch) */
  .none { position: absolute; inset: 0; display: grid; place-content: center; justify-items: center; gap: 4px; padding: 0 8px; text-align: center; }
  .none b { font: 700 var(--ds-data, 12px)/1.25 var(--font-data); letter-spacing: .08em; color: var(--secondary, #94bcc5); }
  .none span { font: 500 var(--ds-sec, 11px)/1.3 var(--font-ui); color: var(--muted, #6b93a0); }

  .axis { display: flex; justify-content: space-between; margin-top: 4px; font: 600 var(--ds-micro, 10px)/1 var(--font-data); letter-spacing: .08em; color: var(--muted, #6b93a0); }

  /* full: y axis | plot, and a time axis + readout under it */
  .full { display: grid; grid-template-columns: auto minmax(0, 1fr); grid-template-rows: minmax(0, 1fr) auto auto; column-gap: 10px; row-gap: 0; }
  .full .plot { grid-column: 2; grid-row: 1; min-height: clamp(240px, 33vh, 340px); }
  .yaxis { grid-column: 1; grid-row: 1; position: relative; min-width: 1.6em; }
  .yaxis span { position: absolute; right: 0; transform: translateY(-50%); font: 600 var(--ds-data, 12px)/1 var(--font-data); font-variant-numeric: tabular-nums; color: var(--muted, #6b93a0); }
  .corner { grid-column: 1; grid-row: 2; }
  .xaxis { grid-column: 2; grid-row: 2; position: relative; height: 22px; margin-top: 6px; }
  .xaxis span { position: absolute; top: 0; transform: translateX(-50%); white-space: nowrap; font: 600 var(--ds-data, 12px)/1 var(--font-data); letter-spacing: .04em; color: var(--secondary, #94bcc5); }
  .xaxis span.first { transform: none; }
  .xaxis span.last { transform: translateX(-100%); color: var(--cyan-soft, #6ef3fb); }
  .readout { grid-column: 2; grid-row: 3; margin: 6px 0 0; min-height: 1.3em; font: 600 var(--ds-data, 12px)/1.3 var(--font-data); letter-spacing: .04em; color: var(--secondary, #94bcc5); }
</style>
