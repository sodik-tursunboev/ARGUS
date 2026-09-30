<script lang="ts">
  // Module matrix. Every status/mode/dependency here is read from the snapshot
  // stores; a module the backend reports nothing for is shown as a compact
  // NOT EXPOSED tile with the reason, not as a giant empty card.
  import { snapshotStatus, securityReport, threatReport } from '../stores/snapshotView';
  import { telemetry } from '../stores/telemetry'; import { connection } from '../stores/connection'; import { agent } from '../stores/agent'; import { security } from '../stores/security'; import { timeline } from '../stores/events';
  import DetailDrawer from './DetailDrawer.svelte';
  import type { Component } from 'svelte';
  import { IconModuleAI, IconModuleVoice, IconModuleTelemetry, IconModuleAuth, IconModuleIntegrity, IconModuleThreat, IconModuleNetwork, IconModuleAudit, IconModuleSandbox, IconModuleSkills, IconModuleIntegrations } from '../lib/ui/icons';
  export let tab='overview';
  type Module = { key: string; icon: Component; name: string; group: string[]; status: string; mode: string; depends: string; activity: string; fields: { label: string; value: string }[] };
  const up = (v: unknown) => v === null || v === undefined || v === '' ? 'UNKNOWN' : String(v).toUpperCase();
  const yn = (v: boolean | null | undefined) => v === true ? 'YES' : v === false ? 'NO' : 'UNKNOWN';
  const stamp = (t: number) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const lastEvent = (cats: string[]) => { const e = $timeline.find((row) => cats.includes(row.category)); return e ? `${stamp(e.timestamp)} · ${e.message.slice(0, 40)}` : 'NO EVENTS THIS SESSION'; };
  $: unavailable = $connection.source === 'unavailable' || $connection.source === 'loading';
  $: modules = [
    { key: 'ai', icon: IconModuleAI, name: 'LOCAL AI', group: ['core','ai'], status: $snapshotStatus?.model ? 'ONLINE' : unavailable ? 'OFFLINE' : 'UNKNOWN', mode: up($snapshotStatus?.engine ?? 'local') + ($snapshotStatus?.cloud_enabled ? ' · CLOUD ENABLED' : ''), depends: 'MODEL RUNTIME', activity: lastEvent(['MODEL','AGENT']),
      fields: [{ label: 'MODEL', value: up($snapshotStatus?.model) }, { label: 'ENGINE', value: up($snapshotStatus?.engine) }, { label: 'CLOUD ENABLED', value: yn($snapshotStatus?.cloud_enabled) }, { label: 'HISTORY', value: $snapshotStatus?.history_msgs !== undefined ? `${$snapshotStatus.history_msgs} / ${$snapshotStatus.history_max ?? '—'} MESSAGES` : 'UNKNOWN' }] },
    { key: 'voice', icon: IconModuleVoice, name: 'VOICE', group: ['core','voice'], status: $snapshotStatus?.voice_state ? up($snapshotStatus.voice_state) : 'UNKNOWN', mode: $snapshotStatus?.muted ? 'MUTED' : up($agent.voice), depends: 'LOCAL AI', activity: lastEvent(['AGENT']),
      fields: [{ label: 'VOICE STATE', value: up($snapshotStatus?.voice_state) }, { label: 'MUTED', value: yn($snapshotStatus?.muted) }, { label: 'HUD VOICE MODE', value: up($agent.voice) }, { label: 'STT / TTS / WAKE HEALTH', value: 'NO PER-COMPONENT CONTRACT EXPOSED' }] },
    { key: 'telemetry', icon: IconModuleTelemetry, name: 'TELEMETRY', group: ['core','system'], status: $telemetry ? 'ACTIVE' : 'UNAVAILABLE', mode: $telemetry ? 'SAMPLER' : '—', depends: 'BACKEND LINK', activity: lastEvent(['SYSTEM']),
      fields: [{ label: 'CPU', value: typeof $telemetry?.cpu === 'number' ? `${Math.round($telemetry.cpu)}%` : 'UNKNOWN' }, { label: 'MEMORY', value: typeof $telemetry?.mem_pct === 'number' ? `${Math.round($telemetry.mem_pct)}%` : 'UNKNOWN' }, { label: 'DISK', value: typeof $telemetry?.disk_pct === 'number' ? `${Math.round($telemetry.disk_pct)}%` : 'UNKNOWN' }, { label: 'GPU', value: $telemetry?.gpu_available ? `${$telemetry.gpu_pct ?? '—'}%` : 'NOT AVAILABLE' }, { label: 'TOP PROCESSES', value: String($telemetry?.top_processes?.length ?? 0) }] },
    { key: 'auth', icon: IconModuleAuth, name: 'AUTHENTICATION', group: ['core','security'], status: $securityReport?.authentication?.enabled === true ? ($securityReport.authentication.unlocked ? 'UNLOCKED' : 'LOCKED') : $securityReport ? 'DISABLED' : 'UNKNOWN', mode: `LEVEL ${$security.fields.authLevel}`, depends: 'SESSION', activity: lastEvent(['AUTH']),
      fields: [{ label: 'ENABLED', value: yn($securityReport?.authentication?.enabled) }, { label: 'UNLOCKED', value: yn($securityReport?.authentication?.unlocked) }, { label: 'AUTH STATE', value: up($security.auth) }, { label: 'USER PRESENCE', value: $security.fields.userPresence }] },
    { key: 'integrity', icon: IconModuleIntegrity, name: 'INTEGRITY', group: ['core','security'], status: $securityReport?.integrity?.ok === true ? 'VERIFIED' : $securityReport?.integrity?.ok === false ? 'DEGRADED' : 'UNKNOWN', mode: $securityReport?.integrity?.signed ? 'SIGNED' : $securityReport?.integrity?.sealed ? 'SEALED' : '—', depends: 'MANIFEST', activity: $securityReport?.integrity?.summary ?? 'NO SUMMARY',
      fields: [{ label: 'OK', value: yn($securityReport?.integrity?.ok) }, { label: 'SEALED', value: yn($securityReport?.integrity?.sealed) }, { label: 'SIGNED', value: yn($securityReport?.integrity?.signed) }, { label: 'SIGNATURE VALID', value: yn($securityReport?.integrity?.signature_valid) }, { label: 'SUMMARY', value: $securityReport?.integrity?.summary ?? 'UNKNOWN' }] },
    { key: 'threat', icon: IconModuleThreat, name: 'THREAT MONITOR', group: ['security'], status: $threatReport?.level ? up($threatReport.level) : $telemetry?.threat ? 'ACTIVE' : 'UNAVAILABLE', mode: $threatReport?.counts ? `${Object.values($threatReport.counts).reduce((a, b) => a + b, 0)} FINDINGS` : '—', depends: 'TELEMETRY', activity: lastEvent(['DETECT','SECURITY']),
      fields: [{ label: 'LEVEL', value: up($threatReport?.level) }, ...Object.entries($threatReport?.counts ?? {}).map(([k, v]) => ({ label: k.toUpperCase(), value: String(v) })), { label: 'RECENT', value: String($threatReport?.recent?.length ?? 0) }] },
    { key: 'network', icon: IconModuleNetwork, name: 'NETWORK POLICY', group: ['security','system'], status: $securityReport?.network?.egress_policy ? 'ENFORCED' : 'UNKNOWN', mode: up($securityReport?.network?.egress_policy ?? $security.fields.networkPolicy), depends: 'POLICY ENGINE', activity: typeof $telemetry?.net_recv_gb === 'number' ? `RX ${$telemetry.net_recv_gb.toFixed(2)} GB · TX ${($telemetry.net_sent_gb ?? 0).toFixed(2)} GB` : 'NO COUNTERS',
      fields: [{ label: 'EGRESS POLICY', value: up($securityReport?.network?.egress_policy) }, { label: 'CLOUD ENABLED', value: yn($securityReport?.network?.cloud_enabled) }, { label: 'NETWORK POLICY', value: $security.fields.networkPolicy }] },
    { key: 'audit', icon: IconModuleAudit, name: 'AUDIT CHAIN', group: ['security'], status: $securityReport?.audit?.chain_intact === true ? 'INTACT' : $securityReport?.audit?.chain_intact === false ? 'BROKEN' : 'UNKNOWN', mode: 'HMAC CHAIN', depends: 'INTEGRITY', activity: lastEvent(['SECURITY','AUTH']),
      fields: [{ label: 'CHAIN INTACT', value: yn($securityReport?.audit?.chain_intact) }, { label: 'AUDIT CHAIN', value: $security.fields.auditChain }] },
    { key: 'sandbox', icon: IconModuleSandbox, name: 'SANDBOX', group: ['security','system'], status: $securityReport?.sandbox?.acls_hardened === true ? 'HARDENED' : $securityReport?.sandbox ? 'OPEN' : 'UNKNOWN', mode: typeof $securityReport?.sandbox?.privileges_held === 'number' ? `${$securityReport.sandbox.privileges_held} PRIVILEGES HELD` : '—', depends: 'OS TOKEN', activity: $securityReport?.sandbox?.install_dir_writable === true ? 'INSTALL DIR WRITABLE' : $securityReport?.sandbox?.install_dir_writable === false ? 'INSTALL DIR READ-ONLY' : 'UNKNOWN',
      fields: [{ label: 'ACLS HARDENED', value: yn($securityReport?.sandbox?.acls_hardened) }, { label: 'PRIVILEGES HELD', value: String($securityReport?.sandbox?.privileges_held ?? 'UNKNOWN') }, { label: 'INSTALL DIR WRITABLE', value: yn($securityReport?.sandbox?.install_dir_writable) }] },
    { key: 'skills', icon: IconModuleSkills, name: 'SKILLS', group: ['automation','system'], status: $securityReport?.skills ? ($securityReport.skills.violations ? 'VIOLATIONS' : 'ALLOWLISTED') : 'UNKNOWN', mode: typeof $securityReport?.skills?.allowlisted === 'number' ? `${$securityReport.skills.allowlisted} ALLOWLISTED` : '—', depends: 'POLICY ENGINE', activity: typeof $securityReport?.skills?.violations === 'number' ? `${$securityReport.skills.violations} VIOLATIONS` : 'UNKNOWN',
      fields: [{ label: 'ALLOWLISTED', value: String($securityReport?.skills?.allowlisted ?? 'UNKNOWN') }, { label: 'VIOLATIONS', value: String($securityReport?.skills?.violations ?? 'UNKNOWN') }, { label: 'CAPABILITY CATALOG', value: 'NOT EXPOSED BY BACKEND' }] },
    { key: 'integrations', icon: IconModuleIntegrations, name: 'INTEGRATIONS', group: ['integrations','automation'], status: 'NOT EXPOSED', mode: '—', depends: '—', activity: 'NO SAFE CONTRACT',
      fields: [{ label: 'CONTRACT', value: 'The backend exposes no integration inventory. Visibility never grants authority.' }] },
  ] satisfies Module[];
  $: visible = tab === 'overview' ? modules : modules.filter((m) => m.group.includes(tab));
  let selected: Module | null = null;
  const tone = (s: string) => /online|active|verified|intact|hardened|allowlisted|unlocked|enforced|low|ready|standby|listening/i.test(s) ? 'ok' : /unknown|unavailable|not exposed|offline|disabled|—/i.test(s) ? 'dim' : /degraded|locked|open|medium|warning|muted/i.test(s) ? 'warn' : /broken|violations|critical|high|blocked|lockdown/i.test(s) ? 'bad' : 'ok';
</script>
<section class="module-page" aria-label="ARGUS module health">
  <div class="matrix-head"><h2>MODULES / {tab.toUpperCase()}</h2><span class="status">BACKEND-DERIVED · {visible.length} MODULES</span></div>
  {#if visible.length}
    <div class="module-matrix">
      {#each visible as m (m.key)}
        {@const I = m.icon}
        <button type="button" class={`module-tile ${tone(m.status)}`} on:click={()=>selected=m} aria-label={`${m.name} detail`}>
          <span class="tile-icon"><I size={20} aria-hidden="true"/></span>
          <b class="tile-name">{m.name}</b>
          <span class="tile-status"><i class="dot"></i>{m.status}</span>
          <small class="tile-row"><span>MODE</span><em>{m.mode}</em></small>
          <small class="tile-row"><span>DEPENDS</span><em>{m.depends}</em></small>
          <small class="tile-activity">{m.activity}</small>
        </button>
      {/each}
    </div>
  {:else}
    <section class="panel compact-unavailable"><div class="panel-title"><h2>{tab.toUpperCase()}</h2><span class="status unknown">NOT EXPOSED</span></div><p class="rail-note">No safe backend module contract is exposed for this category.</p></section>
  {/if}
</section>
<DetailDrawer open={selected!==null} title={selected ? `${selected.name} · INSPECTOR` : 'MODULE'} fields={selected ? [{ label: 'STATUS', value: selected.status }, { label: 'MODE', value: selected.mode }, { label: 'DEPENDS ON', value: selected.depends }, { label: 'LAST ACTIVITY', value: selected.activity }, ...selected.fields] : []} on:close={()=>selected=null}/>
