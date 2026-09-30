<script lang="ts">
  import DashPanel from '../ui/Panel.svelte';
  import ThreatChart from '../ui/ThreatChart.svelte';
  import { security } from '../../stores/security';
  import { threatReport } from '../../stores/snapshotView';
  import { IconThreat, IconCritical, IconWarning, IconInfo } from '../../lib/ui/icons';
  import { SEVERITIES, SEVERITY_LABEL, autoBinMs, buildSeries, normalizeDetections, spanLabel, tally, type Severity } from '../../lib/threat';
  // Dashboard threat summary: a severity tally and ONE compact chart of
  // detections over time, both built from the backend's real recent-detections
  // list (lib/threat.ts) -- the same last-10 the Recent Alerts panel lists, with
  // their real timestamps. Nothing is sampled, smoothed or invented, and with no
  // timestamped detection the chart says NO THREAT SERIES AVAILABLE instead of
  // drawing one. The overall threat LEVEL is not repeated here: the Security
  // Status verdict above owns it. The full monitor is the Security page's.
  const ICON: Record<Severity, typeof IconThreat> = { critical: IconCritical, high: IconThreat, medium: IconWarning, low: IconInfo };
  const BINS = 24;
  $: unavailable = $security.freshness === 'unavailable';
  $: detections = normalizeDetections($threatReport?.recent);
  $: counts = tally(detections);
  // `now` is read when the report changes, so the window ends at the moment the data was last refreshed
  $: series = detections.some((d) => d.at !== null) ? buildSeries(detections, Date.now(), BINS, autoBinMs(detections, Date.now(), BINS)) : null;
  $: reason = unavailable ? 'THREAT DATA UNAVAILABLE'
    : !$threatReport ? 'NO THREAT REPORT YET'
    : detections.length === 0 ? 'NO DETECTIONS REPORTED'
    : 'DETECTIONS CARRY NO TIMESTAMP';
  $: range = series ? `LAST ${spanLabel(series.end - series.start)}` : '';
</script>

<DashPanel title="THREAT MONITOR" icon={IconThreat} testid="threat-monitor" tone={$security.posture === 'critical' || $security.posture === 'lockdown' ? 'critical' : 'normal'} grow={1}>
  <span slot="end">{#if range}<span class="dchip info">{range}</span>{/if}</span>
  <div class="sev">
    {#each SEVERITIES as key (key)}
      <span class="cell {key}"><span class="top"><span class="si" aria-hidden="true"><svelte:component this={ICON[key]} weight="fill" /></span><b>{unavailable ? '—' : counts[key]}</b></span><em>{SEVERITY_LABEL[key]}</em></span>
    {/each}
  </div>
  <div class="chartbox"><ThreatChart {series} variant="compact" {reason} /></div>
</DashPanel>

<style>
  /* four cells: [icon] COUNT over the severity word -- the word sits on its own
     line so it can never be squeezed by the count or the neighbouring cell */
  .sev { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 6px; min-width: 0; }
  .cell { display: grid; justify-items: start; gap: 3px; min-width: 0; }
  .top { display: inline-flex; align-items: center; gap: 6px; min-width: 0; }
  .si { display: grid; place-items: center; flex: 0 0 auto; width: var(--ds-icon-row, 17px); height: var(--ds-icon-row, 17px); }
  .si :global(svg) { display: block; width: 100%; height: 100%; }
  .cell b { font: 700 var(--ds-label, 15px)/1 var(--font-data); font-variant-numeric: tabular-nums; color: var(--text, #edf8fa); }
  .cell em { font: 600 var(--ds-sec, 11px)/1 var(--font-ui); font-style: normal; letter-spacing: .04em; color: var(--secondary, #94bcc5); white-space: nowrap; }
  .cell.critical .si { color: var(--sev-critical, #ff4a63); }
  .cell.high .si { color: var(--sev-high, #ff8f4d); }
  .cell.medium .si { color: var(--sev-medium, #ffc24d); }
  .cell.low .si { color: var(--sev-low, #38e0ff); }

  /* The chart takes the panel's leftover height and scales with it: its natural height is the
     plot (44-72px by window height) plus the 14px axis row (or the empty-state message). */
  .chartbox { display: flex; flex-direction: column; flex: 1 1 auto; min-width: 0; min-height: calc(clamp(44px, 6.4vh, 72px) + 14px); margin-top: clamp(6px, .9vh, 10px); }
</style>
