<script lang="ts">
  import { onMount } from 'svelte';
  import Panel from './ui/Panel.svelte';
  import ThreatChart from './ui/ThreatChart.svelte';
  import { security } from '../stores/security';
  import { threatReport } from '../stores/snapshotView';
  import { IconThreat, IconCritical, IconWarning, IconInfo, IconSuccess, IconOffline } from '../lib/ui/icons';
  import { SEVERITIES, SEVERITY_LABEL, TIMEFRAMES, autoBinMs, buildSeries, clock, normalizeDetections, spanLabel, tally, type Severity, type Timeframe } from '../lib/threat';

  /* THREAT MONITOR. `full` is the Security page's centrepiece: severity summary,
     a large time-binned chart, a legend with real time-frame controls, and the
     detections behind it. `compact` (the Operations page embeds this) keeps the
     summary and a small chart.

     DATA: /threat-report `recent` (threatmon's last-10 detection buffer, newest
     first) and `counts` (detections per MITRE technique this session), both
     shown as reported. Nothing is sampled or invented: each bar is a count of
     real detections whose real timestamp (at_epoch / ts, see lib/threat.ts) fell
     in that bin, and with no timestamped detection the chart says
     NO THREAT SERIES AVAILABLE. Because the backend hands over ten records, a
     window wider than their age simply has empty bins -- the readout under the
     chart says how many detections are plotted, older or undated. The time-frame
     control re-bins those same detections; it never asks the backend for more. */
  export let variant: 'full' | 'compact' = 'full';

  const ICON: Record<Severity, typeof IconThreat> = { critical: IconCritical, high: IconThreat, medium: IconWarning, low: IconInfo };
  let timeframe: Timeframe['key'] = 'auto';
  let now = Date.now();
  onMount(() => { const id = window.setInterval(() => { now = Date.now(); }, 30_000); return () => window.clearInterval(id); });

  $: unavailable = $security.freshness === 'unavailable';
  $: critical = $security.posture === 'critical' || $security.posture === 'lockdown';
  $: detections = normalizeDetections($threatReport?.recent);
  $: counts = tally(detections);
  $: tf = TIMEFRAMES.find((t) => t.key === timeframe) ?? TIMEFRAMES[0];
  $: binMs = tf.key === 'auto' ? autoBinMs(detections, now, tf.bins) : tf.binMs;
  $: series = detections.some((d) => d.at !== null) ? buildSeries(detections, now, variant === 'full' ? tf.bins : 24, variant === 'full' ? binMs : autoBinMs(detections, now, 24)) : null;
  $: reason = unavailable ? 'THREAT DATA UNAVAILABLE' : !$threatReport ? 'NO THREAT REPORT YET' : detections.length === 0 ? 'NO DETECTIONS REPORTED' : 'DETECTIONS CARRY NO TIMESTAMP';
  $: range = series ? `LAST ${spanLabel(series.end - series.start)}` : '';
  $: techniques = Object.entries($threatReport?.counts ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  $: total = detections.length;
</script>

<Panel title="THREAT MONITOR" icon={IconThreat} testid="threat-monitor" tone={critical ? 'critical' : 'normal'}>
  <span slot="end">{#if range}<span class="dchip info">{range}</span>{/if}</span>
  <div class="summary" class:compact={variant === 'compact'}>
    {#each SEVERITIES as key (key)}
      <div class="scell {key}" class:zero={!unavailable && counts[key] === 0}>
        <span class="sico" aria-hidden="true"><svelte:component this={ICON[key]} weight="fill" /></span>
        <b class="n">{unavailable ? '—' : counts[key]}</b>
        <em>{SEVERITY_LABEL[key]}</em>
      </div>
    {/each}
  </div>

  <div class="chartbox" class:full={variant === 'full'}><ThreatChart {series} variant={variant === 'full' ? 'full' : 'compact'} {reason} /></div>

  {#if variant === 'full'}
    <div class="controls">
      <ul class="legend" aria-label="Severity legend">
        {#each SEVERITIES as key (key)}<li class={key}><i aria-hidden="true"></i>{SEVERITY_LABEL[key]}</li>{/each}
      </ul>
      {#if series}<span class="unit">1 BAR = {spanLabel(series.binMs)}</span>{/if}
      <div class="tf" role="radiogroup" aria-label="Time frame">
        {#each TIMEFRAMES as t (t.key)}<button type="button" role="radio" aria-checked={timeframe === t.key} class:on={timeframe === t.key} on:click={() => (timeframe = t.key)}>{t.label}</button>{/each}
      </div>
    </div>

    <div class="lists">
      <section class="detections" aria-label="Recent detections">
        <h3>RECENT DETECTIONS<span>{total ? `${total} REPORTED` : ''}</span></h3>
        {#if detections.length}
          <ul>
            {#each detections as d (d.id)}
              <li class={d.severity} title={`${d.severity.toUpperCase()} · ${d.detector ? d.detector + ' · ' : ''}${d.label}${d.stamp ? ' · ' + d.stamp : ''}`}>
                <time>{d.at === null ? '—' : clock(d.at)}</time>
                <span class="sev"><i aria-hidden="true"></i>{d.severity}</span>
                <span class="what">{d.detector ? `${d.detector} · ` : ''}{d.label}</span>
                <span class="tech">{d.technique}</span>
              </li>
            {/each}
          </ul>
        {:else}
          <p class="none"><span class="ni" class:ok={!unavailable} aria-hidden="true">{#if unavailable}<IconOffline weight="bold" />{:else}<IconSuccess weight="fill" />{/if}</span>{reason}</p>
        {/if}
      </section>
      <section class="techniques" aria-label="Techniques seen this session">
        <h3>TECHNIQUES THIS SESSION</h3>
        {#if techniques.length}
          <ul class="tchips">{#each techniques as [id, n] (id)}<li><b>{id}</b><em>×{n}</em></li>{/each}</ul>
        {:else}
          <p class="none plain">{$threatReport ? 'NO TECHNIQUES REPORTED' : 'NO THREAT REPORT YET'}</p>
        {/if}
      </section>
    </div>
  {/if}
</Panel>

<style>
  /* ---- severity summary: important values, so large ---- */
  .summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); min-width: 0; }
  .scell { display: grid; grid-template-columns: auto minmax(0, 1fr); grid-template-areas: 'ico n' 'ico lbl'; align-items: center; column-gap: 12px; row-gap: 1px; min-width: 0; padding: 2px clamp(10px, 1.1vw, 20px); border-left: 1px solid rgba(223, 251, 255, .09); }
  .scell:first-child { padding-left: 0; border-left: 0; }
  .sico { grid-area: ico; display: grid; place-items: center; width: clamp(30px, 2.6vw, 42px); height: clamp(30px, 2.6vw, 42px); }
  .sico :global(svg) { display: block; width: 100%; height: 100%; }
  .n { grid-area: n; align-self: end; font: 700 var(--ds-value, 26px)/1 var(--font-data); font-variant-numeric: tabular-nums; color: var(--text, #edf8fa); }
  .scell em { grid-area: lbl; align-self: start; font: 700 var(--ds-label, 15px)/1.1 var(--font-ui); font-style: normal; letter-spacing: .08em; text-transform: uppercase; color: var(--secondary, #94bcc5); }
  .scell.critical .sico { color: var(--sev-critical, #ff4a63); }
  .scell.high .sico { color: var(--sev-high, #ff8f4d); }
  .scell.medium .sico { color: var(--sev-medium, #ffc24d); }
  .scell.low .sico { color: var(--sev-low, #38e0ff); }
  .scell.critical:not(.zero) .n { color: var(--sev-critical, #ff4a63); }
  .scell.zero .sico { opacity: .55; }
  .scell.zero .n { color: var(--muted, #6b93a0); }
  .summary.compact .sico { width: 26px; height: 26px; }
  .summary.compact .n { font-size: var(--ds-label, 16px); }
  .summary.compact .scell em { font-size: var(--ds-sec, 12px); }

  /* ---- chart ---- */
  .chartbox { display: flex; flex-direction: column; min-width: 0; margin-top: clamp(10px, 1.6vh, 16px); }
  .chartbox:not(.full) { min-height: 96px; }

  /* ---- legend + time frame ---- */
  .controls { display: flex; flex-wrap: wrap; align-items: center; gap: 10px 22px; min-width: 0; margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(223, 251, 255, .075); }
  .legend { display: flex; flex-wrap: wrap; gap: 6px 18px; margin: 0; padding: 0; list-style: none; }
  .legend li { display: inline-flex; align-items: center; gap: 8px; font: 600 var(--ds-ui, 13px)/1 var(--font-ui); letter-spacing: .04em; color: var(--text, #edf8fa); }
  .legend i { width: 12px; height: 12px; background: currentColor; }
  .legend .critical i { color: var(--sev-critical, #ff4a63); } .legend .high i { color: var(--sev-high, #ff8f4d); }
  .legend .medium i { color: var(--sev-medium, #ffc24d); } .legend .low i { color: var(--sev-low, #38e0ff); }
  .unit { font: 600 var(--ds-data, 12px)/1 var(--font-data); letter-spacing: .06em; color: var(--secondary, #94bcc5); }
  .tf { display: inline-flex; margin-left: auto; border: 1px solid rgba(0, 234, 242, .28); }
  .tf button { min-width: 52px; height: 32px; padding: 0 12px; border: 0; border-left: 1px solid rgba(0, 234, 242, .18); background: transparent; cursor: pointer; font: 700 var(--ds-data, 12px)/1 var(--font-data); letter-spacing: .08em; color: var(--secondary, #94bcc5); }
  .tf button:first-child { border-left: 0; }
  .tf button:hover { color: var(--text, #edf8fa); background: rgba(0, 234, 242, .07); }
  .tf button.on { color: var(--cyan-soft, #6ef3fb); background: rgba(0, 234, 242, .16); }
  .tf button:focus-visible { outline: 2px solid var(--cyan, #00eaf2); outline-offset: -2px; }

  /* ---- detections + techniques ---- */
  .lists { display: grid; grid-template-columns: minmax(0, 2.1fr) minmax(0, 1fr); gap: clamp(14px, 1.6vw, 26px); min-width: 0; margin-top: 14px; padding-top: 12px; border-top: 1px solid rgba(223, 251, 255, .075); }
  @media (max-width: 1099px) { .lists { grid-template-columns: minmax(0, 1fr); } }
  h3 { display: flex; justify-content: space-between; align-items: baseline; gap: 10px; margin: 0 0 6px; font: 700 var(--ds-label, 15px)/1.1 var(--font-ui); letter-spacing: .08em; text-transform: uppercase; color: var(--secondary, #94bcc5); }
  h3 span { font: 600 var(--ds-sec, 12px)/1 var(--font-data); letter-spacing: .08em; color: var(--muted, #6b93a0); }
  .detections ul { margin: 0; padding: 0; list-style: none; }
  .detections li { display: grid; grid-template-columns: 4.4em 6.4em minmax(0, 1fr) auto; align-items: center; column-gap: 12px; min-width: 0; min-height: var(--ds-row, 30px); border-top: 1px solid rgba(223, 251, 255, .075); }
  .detections li:first-child { border-top: 0; }
  time { font: 600 var(--ds-data, 12px)/1 var(--font-data); font-variant-numeric: tabular-nums; color: var(--muted, #6b93a0); }
  .sev { display: inline-flex; align-items: center; gap: 7px; min-width: 0; font: 700 var(--ds-data, 12px)/1 var(--font-data); letter-spacing: .07em; text-transform: uppercase; color: var(--secondary, #94bcc5); }
  .sev i { flex: 0 0 auto; width: 8px; height: 8px; background: currentColor; box-shadow: 0 0 6px currentColor; transform: rotate(45deg); }
  li.critical .sev { color: var(--sev-critical, #ff4a63); } li.high .sev { color: var(--sev-high, #ff8f4d); }
  li.medium .sev { color: var(--sev-medium, #ffc24d); } li.low .sev { color: var(--sev-low, #38e0ff); }
  .what { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font: 500 var(--ds-ui, 13px)/1.2 var(--font-ui); color: var(--text, #edf8fa); }
  .tech { font: 600 var(--ds-data, 12px)/1 var(--font-data); letter-spacing: .05em; color: var(--muted, #6b93a0); }
  .none { display: flex; align-items: center; gap: 9px; margin: 0; padding: 6px 0; font: 700 var(--ds-data, 12px)/1.3 var(--font-data); letter-spacing: .06em; color: var(--secondary, #94bcc5); }
  .none.plain { display: block; }
  .ni { display: grid; place-items: center; flex: 0 0 auto; width: 20px; height: 20px; color: var(--muted, #6b93a0); }
  .ni.ok { color: var(--green, #2df0a6); }
  .ni :global(svg) { display: block; width: 100%; height: 100%; }
  .tchips { display: flex; flex-wrap: wrap; gap: 8px; margin: 0; padding: 0; list-style: none; }
  .tchips li { display: inline-flex; align-items: baseline; gap: 7px; padding: 6px 10px; border: 1px solid rgba(0, 234, 242, .28); background: rgba(0, 234, 242, .06); }
  .tchips b { font: 700 var(--ds-data, 12px)/1 var(--font-data); letter-spacing: .04em; color: var(--text, #edf8fa); }
  .tchips em { font: 700 var(--ds-data, 12px)/1 var(--font-data); font-style: normal; color: var(--cyan-soft, #6ef3fb); }
</style>
