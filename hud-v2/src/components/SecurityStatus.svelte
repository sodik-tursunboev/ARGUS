<script lang="ts">
  import PanelTitle from './ui/PanelTitle.svelte';
  import { security } from '../stores/security';
  import { securityReport } from '../stores/snapshotView';
  import { IconDeviceTrust, IconPolicyEngine, IconAuth, IconUserPresence, IconExecutor, IconNetworkPolicy, IconAuditChain, IconThreatState, IconSecurity, IconLockdown } from '../lib/ui/icons';

  // Every row value now comes from the adapter layer (lib/adapters.ts),
  // which maps the four REST reports to one of six explicit conditions
  // (real value / NOT REPORTED / UNKNOWN / DISCONNECTED / UNAVAILABLE /
  // ERROR-free absence). This component renders states, it does not derive
  // them. Long diagnostic strings (e.g. netpolicy.describe()) stay on the
  // Security page — the dashboard row shows the enforced STATE.
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
    { label: 'THREAT STATE', value: $security.fields.threatState, icon: IconThreatState }
  ];
  $: critical = ['critical', 'blocked', 'lockdown'].includes($security.posture);
  $: freshness = $security.freshness;
</script>
<section class:critical class="panel security" aria-label="Security status" data-testid="security-status">
  <PanelTitle title="SECURITY STATUS" icon={IconSecurity} tone={critical ? 'critical' : 'normal'}><span class:unknown={!critical && freshness !== 'live'} class="status">{freshness.toUpperCase()}</span></PanelTitle>
  {#each rows as row}{@const I = row.icon}<div class="security-row"><span class="row-label"><i class="row-icon" aria-hidden="true"><I size={12}/></i>{row.label}</span><b class={tone(row.value)}>{row.value}</b></div>{/each}
  {#if $security.decision}
    <div class="security-decision"><h3>ACTION REQUEST</h3>{#if $security.decision.capability}<div><span>CAPABILITY</span><b>{$security.decision.capability}</b></div>{/if}{#if $security.decision.resource}<div><span>RESOURCE</span><b>{$security.decision.resource}</b></div>{/if}<div><span>POLICY</span><b>{$security.decision.policy.toUpperCase()}</b></div><div><span>AUTH</span><b>{$security.decision.auth.toUpperCase()}</b></div><div><span>STATUS</span><b>{$security.decision.status.toUpperCase()}</b></div></div>
  {/if}
  {#if critical}<div class="security-summary critical"><IconLockdown size={34} weight="fill" class="shield-lg" aria-hidden="true"/><div><b>{ $security.posture === 'lockdown' ? 'LOCKDOWN ACTIVE' : `SYSTEM ${$security.posture.toUpperCase()}` }</b><small>{ $security.recoveryPossible === true ? 'OWNER RECOVERY MAY BE AVAILABLE' : $security.recoveryPossible === false ? 'RECOVERY NOT AVAILABLE' : 'RECOVERY STATUS UNKNOWN' }</small></div></div>{:else}<div class:unknown={freshness === 'unavailable'} class="security-summary"><IconSecurity size={34} weight="fill" class="shield-lg" aria-hidden="true"/><div><b>{ freshness === 'unavailable' ? 'BACKEND DISCONNECTED' : `SYSTEM ${$security.posture === 'normal' ? 'SECURE' : $security.posture.toUpperCase()}` }</b><small>{ freshness === 'unavailable' ? 'Security state cannot be verified without the backend' : $security.posture === 'normal' ? 'No active threats reported' : $security.posture === 'unknown' ? 'Threat state not yet reported' : `Posture ${$security.posture.toUpperCase()}` }</small></div></div>{/if}
</section>
