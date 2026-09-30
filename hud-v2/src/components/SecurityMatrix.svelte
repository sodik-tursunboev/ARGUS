<script lang="ts">
  // Security page depth from the reports the backend already sends
  // (/security-report, /telemetry) plus the live security store. Every cell is a
  // reported value or an explicit UNKNOWN. The threat SEVERITY and DETECTIONS
  // views used to be repeated here as a third panel; they live in one place now,
  // the Threat Monitor, which draws them from the same /threat-report data.
  import PanelTitle from './ui/PanelTitle.svelte';
  import { securityReport } from '../stores/snapshotView'; import { telemetry } from '../stores/telemetry'; import { timeline } from '../stores/events';
  import { IconDeviceTrust, IconTimeline } from '../lib/ui/icons';
  const yn = (v: boolean | null | undefined, ok = 'OK', bad = 'FAIL') => v === true ? ok : v === false ? bad : 'UNKNOWN';
  const up = (v: unknown) => v === null || v === undefined || v === '' ? 'UNKNOWN' : String(v).toUpperCase();
  const stamp = (t: number) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  // Numbers are neutral unless the label makes a non-zero count a concern
  // (detections, violations); "NOT ARMED" is lockdown's normal resting state.
  const tone = (s: string, label = '') => /^\d+$/.test(s) ? (/detection|violation/i.test(label) && s !== '0' ? 'warn' : 'dim') : /^(ok|verified|sealed|signed|valid|intact|hardened|enabled|read-only|enforced|none|low|normal|unlocked|not armed)/i.test(s) ? (/not armed/i.test(s) ? 'dim' : 'ok') : /unknown|—/i.test(s) ? 'dim' : /degraded|warning|medium|locked|writable|open|disabled/i.test(s) ? 'warn' : 'bad';
  $: cells = [
    ['INTEGRITY', yn($securityReport?.integrity?.ok, 'VERIFIED', 'DEGRADED')],
    ['MANIFEST SEALED', yn($securityReport?.integrity?.sealed, 'SEALED', 'UNSEALED')],
    ['MANIFEST SIGNED', yn($securityReport?.integrity?.signed, 'SIGNED', 'UNSIGNED')],
    ['SIGNATURE', yn($securityReport?.integrity?.signature_valid, 'VALID', 'INVALID')],
    ['AUDIT CHAIN', yn($securityReport?.audit?.chain_intact, 'INTACT', 'BROKEN')],
    ['ACL HARDENING', yn($securityReport?.sandbox?.acls_hardened, 'HARDENED', 'OPEN')],
    ['INSTALL DIR', yn($securityReport?.sandbox?.install_dir_writable, 'WRITABLE', 'READ-ONLY')],
    ['PRIVILEGES HELD', typeof $securityReport?.sandbox?.privileges_held === 'number' ? String($securityReport.sandbox.privileges_held) : 'UNKNOWN'],
    ['AUTH ENABLED', yn($securityReport?.authentication?.enabled, 'ENABLED', 'DISABLED')],
    ['SESSION', yn($securityReport?.authentication?.unlocked, 'UNLOCKED', 'LOCKED')],
    ['EGRESS POLICY', up($securityReport?.network?.egress_policy)],
    ['CLOUD', yn($securityReport?.network?.cloud_enabled, 'ENABLED', 'DISABLED')],
    ['SKILLS ALLOWLISTED', typeof $securityReport?.skills?.allowlisted === 'number' ? String($securityReport.skills.allowlisted) : 'UNKNOWN'],
    ['SKILL VIOLATIONS', typeof $securityReport?.skills?.violations === 'number' ? ($securityReport.skills.violations ? String($securityReport.skills.violations) : 'NONE') : 'UNKNOWN'],
    ['LOCKDOWN ARMED', yn($telemetry?.lockdown?.armed, 'ARMED', 'NOT ARMED')],
    ['DETECTIONS', String($telemetry?.detections?.length ?? 0)],
  ];
  $: secEvents = $timeline.filter((e) => ['SECURITY','DETECT','AUTH','POLICY','ERROR'].includes(e.category)).slice(0, 10);
</script>
<section class="panel sec-matrix" aria-label="Detector and control health">
  <PanelTitle title="CONTROL MATRIX" icon={IconDeviceTrust}><span class:unknown={!$securityReport} class="status">{$securityReport ? 'SECURITY REPORT' : 'AWAITING REPORT'}</span></PanelTitle>
  <div class="matrix-grid">{#each cells as [label, value]}<div class={tone(value, label)} title={`${label}: ${value}`}><i class="dot"></i><span>{label}</span><b>{value}</b></div>{/each}</div>
</section>
<section class="panel sec-timeline" aria-label="Security timeline">
  <PanelTitle title="SECURITY TIMELINE" icon={IconTimeline}><span class:unknown={!secEvents.length} class="status">{secEvents.length ? `${secEvents.length} EVENTS` : 'QUIET'}</span></PanelTitle>
  {#if secEvents.length}<div class="mini-events">{#each secEvents as e (e.id)}<div class:warning={e.severity==='warning'} class:critical={e.severity==='critical'}><time>{stamp(e.timestamp)}</time><b class={`chip chip-${e.category.toLowerCase()}`}>{e.category}</b><span>{e.message}</span></div>{/each}</div>{:else}<p class="rail-note">No security, auth, policy or detection events in this session.</p>{/if}
</section>
