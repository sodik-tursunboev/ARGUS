<script lang="ts">
  import DashPanel from '../ui/Panel.svelte';
  import { security } from '../../stores/security';
  import { IconSecurity, IconLockdown, IconDeviceTrust, IconPolicyEngine, IconAuth, IconUserPresence, IconExecutor, IconNetworkPolicy, IconAuditChain } from '../../lib/ui/icons';
  // Dashboard summary of the security posture: the seven control states plus
  // the one-line verdict. Values come straight from the adapter layer
  // (lib/adapters.ts) through the security store -- this component renders
  // states, it does not derive them. THREAT STATE is not repeated here: the
  // Threat Monitor directly beneath carries it in its header. The full report
  // (matrix, action request detail, long diagnostics) is the Security page's
  // SecurityStatus / SecurityMatrix.
  const tone = (value: string): string =>
    value === 'DISCONNECTED' || value === 'NOT REPORTED' || value === 'UNKNOWN' || value === 'UNAVAILABLE' ? 'dim'
    : /BROKEN|DRIFT|VIOLATION|LOCKED OUT|CRITICAL/.test(value) ? 'bad'
    : /UNSEALED|LOCKED|UNMONITORED|ELEVATED|EAGER/.test(value) ? 'warn'
    : /SEALED|ENFORCING|ENFORCED|UNLOCKED|INTACT|WATCHING|MINIMUM PRIVS|NOMINAL|IDLE LOCK/.test(value) ? 'ok' : '';
  $: rows = [
    { label: 'DEVICE TRUST', value: $security.fields.deviceTrust, icon: IconDeviceTrust },
    { label: 'POLICY ENGINE', value: $security.fields.policyEngine, icon: IconPolicyEngine },
    { label: 'AUTH LEVEL', value: $security.fields.authLevel, icon: IconAuth },
    { label: 'USER PRESENCE', value: $security.fields.userPresence, icon: IconUserPresence },
    { label: 'EXECUTOR', value: $security.fields.executor, icon: IconExecutor },
    { label: 'NETWORK POLICY', value: $security.fields.networkPolicy, icon: IconNetworkPolicy },
    { label: 'AUDIT CHAIN', value: $security.fields.auditChain, icon: IconAuditChain },
  ];
  $: critical = ['critical', 'blocked', 'lockdown'].includes($security.posture);
  $: freshness = $security.freshness;
  $: decision = $security.decision;
  // the chip states FRESHNESS of the data (live / stale / unavailable); the
  // critical posture is carried by the red frame and the verdict block
  $: chipTone = freshness === 'live' ? 'ok' : 'warn';
  // verdict wording is the legacy SecurityStatus wording, verbatim
  $: headline = critical ? ($security.posture === 'lockdown' ? 'LOCKDOWN ACTIVE' : `SYSTEM ${$security.posture.toUpperCase()}`)
    : freshness === 'unavailable' ? 'BACKEND DISCONNECTED' : `SYSTEM ${$security.posture === 'normal' ? 'SECURE' : $security.posture.toUpperCase()}`;
  $: subline = critical ? ($security.recoveryPossible === true ? 'OWNER RECOVERY MAY BE AVAILABLE' : $security.recoveryPossible === false ? 'RECOVERY NOT AVAILABLE' : 'RECOVERY STATUS UNKNOWN')
    : freshness === 'unavailable' ? 'Security state cannot be verified without the backend'
    : $security.posture === 'normal' ? 'No active threats reported' : $security.posture === 'unknown' ? 'Threat state not yet reported' : `Posture ${$security.posture.toUpperCase()}`;
  $: summaryTone = critical ? 'bad' : freshness === 'unavailable' || $security.posture === 'unknown' ? 'warn' : 'ok';
</script>

<DashPanel title="SECURITY STATUS" icon={IconSecurity} testid="security-status" tone={critical ? 'critical' : 'normal'} grow={1.25}>
  <span slot="end" class="dchip {chipTone}">{freshness.toUpperCase()}</span>
  <div class="drows rows">
    {#each rows as row (row.label)}{@const tn = tone(row.value)}
      <div class="drow row"><span class="ri {tn}" aria-hidden="true"><svelte:component this={row.icon} weight="regular" /></span><span class="dk">{row.label}</span><b class="dv {tn}" title={row.value}>{row.value}</b></div>
    {/each}
  </div>
  {#if decision}
    <div class="decision" title={[decision.capability, decision.resource, `policy ${decision.policy}`, `auth ${decision.auth}`].filter(Boolean).join(' · ')}><span class="dk warn">ACTION REQUEST</span><b class="dv warn">{decision.status.toUpperCase()}</b></div>
  {/if}
  <div class="summary {summaryTone}">
    <span class="shield" aria-hidden="true"><svelte:component this={critical ? IconLockdown : IconSecurity} weight="fill" /></span>
    <div class="txt"><b>{headline}</b><small>{subline}</small></div>
  </div>
</DashPanel>

<style>
  .rows { flex: 1 1 auto; }
  .row { grid-template-columns: calc(var(--ds-icon-row, 17px) + 1px) minmax(0, 1fr) auto; }
  /* value column may shrink (ellipsis + tooltip) before the label does */
  .row .dv { max-width: 100%; text-align: right; }
  .ri { display: grid; place-items: center; width: calc(var(--ds-icon-row, 17px) + 1px); height: calc(var(--ds-icon-row, 17px) + 1px); color: var(--cyan-soft, #6ef3fb); opacity: .9; }
  .ri :global(svg) { display: block; width: 100%; height: 100%; }
  .ri.bad { color: var(--red, #ff4a63); opacity: 1; }
  .ri.warn { color: var(--amber, #ffc24d); opacity: 1; }
  .ri.dim { color: var(--muted, #537a84); }

  .decision { display: flex; align-items: center; justify-content: space-between; gap: 8px; min-width: 0; margin-top: clamp(4px, .6vh, 7px); padding: 5px 8px; border: 1px solid rgba(255, 194, 77, .4); background: rgba(255, 194, 77, .07); }

  .summary {
    display: flex; align-items: center; gap: 10px; min-width: 0; margin-top: clamp(5px, .8vh, 9px);
    padding: clamp(6px, .9vh, 9px) 10px; border: 1px solid rgba(45, 240, 166, .28);
    background: linear-gradient(90deg, rgba(45, 240, 166, .08), transparent 75%);
  }
  .summary.warn { border-color: rgba(255, 194, 77, .34); background: linear-gradient(90deg, rgba(255, 194, 77, .08), transparent 75%); }
  .summary.bad { border-color: rgba(255, 62, 92, .4); background: linear-gradient(90deg, rgba(255, 62, 92, .1), transparent 75%); }
  .shield { flex: 0 0 auto; display: block; width: var(--ds-icon-card, 32px); height: var(--ds-icon-card, 32px); color: var(--green, #2df0a6); }
  .shield :global(svg) { display: block; width: 100%; height: 100%; }
  .warn .shield { color: var(--amber, #ffc24d); }
  .bad .shield { color: var(--red, #ff4a63); }
  .txt { display: grid; gap: 2px; min-width: 0; }
  .txt b { font: 700 var(--ds-label, 15px)/1.1 var(--font-ui); letter-spacing: .06em; color: var(--green, #2df0a6); overflow-wrap: anywhere; }
  .warn .txt b { color: var(--amber, #ffc24d); }
  .bad .txt b { color: var(--red, #ff4a63); }
  .txt small { font: 500 var(--ds-sec, 12px)/1.3 var(--font-ui); color: var(--secondary, #94bcc5); overflow-wrap: anywhere; }
</style>
