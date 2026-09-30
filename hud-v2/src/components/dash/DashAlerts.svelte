<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import DashPanel from '../ui/Panel.svelte';
  import { security } from '../../stores/security';
  import { IconAlerts, IconGo, IconSuccess, IconOffline } from '../../lib/ui/icons';
  // Dashboard recent alerts: the newest few detections, each with severity,
  // event and time -- no forensic detail (that is the Security page). The panel
  // is exactly as tall as the rows it shows: 3 up to 979px of window height,
  // 4 from 980px (1080p), 5 from 1200px (chosen in CSS by viewport height,
  // below), so a row is never cut and no measuring is involved. The bands are
  // deliberately conservative: measured, 4 rows at 900px leave the right rail
  // ~2px of slack in a critical posture.
  const dispatch = createEventDispatcher<{ navigate: string }>();
  const MAX_ROWS = 5;
  const SEV_CLASS: Record<string, string> = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };
  // four-letter severity codes keep the event column wide; the row tooltip
  // carries the full word, severity colour + marker carry the rest
  const SEV_CODE: Record<string, string> = { CRITICAL: 'CRIT', MEDIUM: 'MED' };
  const code = (severity: string): string => SEV_CODE[severity.toUpperCase()] ?? severity.toUpperCase();
  // HH:MM (24h): the full timestamp is in the row tooltip
  const stamp = (ts: string | null): string => {
    if (!ts) return '—';
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return ts.length > 5 ? ts.slice(-5) : ts;
    const p = (n: number): string => String(n).padStart(2, '0');
    return `${p(d.getHours())}:${p(d.getMinutes())}`;
  };
  $: alerts = $security.alerts;
  $: unavailable = $security.freshness === 'unavailable';
  $: shown = alerts.slice(0, MAX_ROWS);
</script>

<DashPanel title="RECENT ALERTS" icon={IconAlerts} testid="recent-alerts" grow={.9}>
  <span slot="end">{#if alerts.length}<button type="button" class="all" on:click={() => dispatch('navigate', 'security')}>VIEW ALL<span class="go" aria-hidden="true"><IconGo weight="bold" /></span></button>{/if}</span>
  <div class="list">
    {#if shown.length}
      {#each shown as alert (alert.id)}
        <div class="drow row" title={`${alert.severity} · ${alert.label}${alert.timestamp ? ` · ${alert.timestamp}` : ''}`}>
          <span class="sev {SEV_CLASS[alert.severity.toUpperCase()] ?? 'info'}"><i aria-hidden="true"></i>{code(alert.severity)}</span>
          <span class="what">{alert.label}</span>
          <time>{stamp(alert.timestamp)}</time>
        </div>
      {/each}
    {:else}
      <div class="none"><span class="ni" class:ok={!unavailable} aria-hidden="true">{#if unavailable}<IconOffline weight="bold" />{:else}<IconSuccess weight="fill" />{/if}</span><span>{unavailable ? 'Alert data unavailable' : 'No backend alerts reported'}</span></div>
    {/if}
  </div>
</DashPanel>

<style>
  .list { display: grid; grid-auto-rows: minmax(var(--ds-row, 26px), 1fr); align-content: stretch; flex: 1 1 auto; min-width: 0; min-height: 0; }
  /* whole rows only: the band decides how many, the panel's height follows */
  @media (max-height: 1199px) { .row:nth-child(n+5) { display: none; } }
  @media (max-height: 979px) { .row:nth-child(n+4) { display: none; } }

  /* fixed severity column so every event label starts at the same x */
  .row { grid-template-columns: 4.6em minmax(0, 1fr) max-content; column-gap: 10px; font-size: var(--ds-sec, 11px); }
  .sev { display: inline-flex; align-items: center; gap: 6px; min-width: 0; font: 700 var(--ds-sec, 11px)/1 var(--font-data); letter-spacing: .07em; text-transform: uppercase; color: var(--secondary, #94bcc5); }
  .sev i { flex: 0 0 auto; width: 7px; height: 7px; border-radius: 1px; background: currentColor; box-shadow: 0 0 6px currentColor; transform: rotate(45deg); }
  .sev.critical { color: var(--sev-critical, #ff4a63); }
  .sev.high { color: var(--sev-high, #ff8f4d); }
  .sev.medium { color: var(--sev-medium, #ffc24d); }
  .sev.low { color: var(--sev-low, #38e0ff); }
  .what { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font: 500 var(--ds-ui, 13px)/1.1 var(--font-ui); color: var(--text, #edf8fa); }
  time { font: 600 var(--ds-data, 12px)/1 var(--font-data); font-variant-numeric: tabular-nums; color: var(--muted, #537a84); }
  .none { display: flex; align-items: center; gap: 9px; align-self: center; min-width: 0; padding-block: 4px; font: 500 var(--ds-ui, 13px)/1.25 var(--font-ui); color: var(--secondary, #94bcc5); }
  .ni { display: grid; place-items: center; flex: 0 0 auto; width: calc(var(--ds-icon-row, 17px) + 2px); height: calc(var(--ds-icon-row, 17px) + 2px); color: var(--muted, #537a84); }
  .ni.ok { color: var(--green, #2df0a6); }
  .ni :global(svg) { display: block; width: 100%; height: 100%; }
  .all { display: inline-flex; align-items: center; gap: 5px; padding: 2px 0; border: 0; background: transparent; cursor: pointer; font: 700 var(--ds-sec, 11px)/1 var(--font-data); letter-spacing: .08em; color: var(--cyan-soft, #6ef3fb); white-space: nowrap; }
  .all:hover { color: var(--text, #edf8fa); }
  .all:focus-visible { outline: 1px solid var(--cyan-soft, #6ef3fb); outline-offset: 3px; }
  .go { display: grid; width: 12px; height: 12px; }
  .go :global(svg) { display: block; width: 100%; height: 100%; }
</style>
