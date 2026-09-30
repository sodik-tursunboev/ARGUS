<script lang="ts">
  // Restrained schematic of the real ARGUS pipeline. The node names are the
  // actual components (listener -> router -> agent kernel -> auth/policy ->
  // capability -> execution -> verification); the lit node follows the live
  // agent state so the diagram is a readout, not decoration.
  import { agent } from '../stores/agent'; import { security } from '../stores/security'; import { snapshotStatus, securityReport } from '../stores/snapshotView'; import { connection } from '../stores/connection';
  const NODES = [
    { key: 'voice', label: 'VOICE', sub: 'STT · WAKE WORD', states: ['listening'] },
    { key: 'router', label: 'ROUTER', sub: 'INTENT', states: ['understanding'] },
    { key: 'agent', label: 'PLANNER', sub: 'AGENT KERNEL', states: ['planning'] },
    { key: 'policy', label: 'POLICY', sub: 'ALLOWLIST · LEVELS', states: [] },
    { key: 'auth', label: 'AUTH', sub: 'PIN · GRANTS', states: ['waiting_auth'] },
    { key: 'capability', label: 'CAPABILITY', sub: 'SKILL CONTRACT', states: [] },
    { key: 'execution', label: 'EXECUTION', sub: 'SANDBOXED', states: ['executing'] },
    { key: 'verify', label: 'VERIFY', sub: 'OBSERVE · AUDIT', states: ['verifying', 'completed'] },
  ];
  const W = 1040, H = 150, step = W / NODES.length;
  const up = (v: unknown) => v === null || v === undefined || v === '' ? 'UNKNOWN' : String(v).toUpperCase();
  const yn = (v: boolean | null | undefined) => v === true ? 'YES' : v === false ? 'NO' : 'UNKNOWN';
</script>
<section class="panel architecture" aria-label="ARGUS architecture">
  <div class="panel-title"><h2>ARCHITECTURE</h2><span class="status">LIVE STATE · {up($agent.state)}</span></div>
  <svg class="arch-svg" viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Voice to router to agent planner to policy to auth to capability to execution to verify">
    <defs><marker id="arch-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0.5 L7 4 L0 7.5" fill="none" stroke="currentColor" stroke-width="1.2"/></marker></defs>
    {#each NODES as node, i}
      {@const cx = step * i + step / 2}
      {@const active = node.states.includes($agent.state)}
      {#if i < NODES.length - 1}<line class="arch-link" class:active x1={cx + 46} y1={62} x2={cx + step - 46} y2={62} marker-end="url(#arch-arrow)"/>{/if}
      <g class="arch-node" class:active>
        <rect x={cx - 46} y={40} width={92} height={44} rx={2}/>
        <path class="arch-cut" d={`M${cx - 46} ${47} L${cx - 39} ${40} M${cx + 46} ${77} L${cx + 39} ${84}`}/>
        <circle cx={cx - 38} cy={48} r={2.4}/>
        <text x={cx} y={58} text-anchor="middle" class="arch-label">{node.label}</text>
        <text x={cx} y={73} text-anchor="middle" class="arch-sub">{node.sub}</text>
        <text x={cx} y={112} text-anchor="middle" class="arch-tick">{i === 0 ? up($agent.voice) : i === 3 ? $security.fields.policyEngine : i === 4 ? `${up($security.auth)} · ${$security.fields.authLevel}` : i === 6 ? $security.fields.executor : i === 7 ? $security.fields.auditChain : active ? 'ACTIVE' : '·'}</text>
      </g>
    {/each}
    <line class="arch-base" x1={20} y1={132} x2={W - 20} y2={132}/>
    <text x={20} y={146} class="arch-foot">INTELLIGENCE PROPOSES · POLICY DECIDES · AUTH PROVES · EXECUTION PERFORMS · OBSERVATION VERIFIES · AUDIT RECORDS</text>
  </svg>
  <div class="stack-grid">
    <div><span>RUNTIME</span><b>FASTAPI · PYWEBVIEW / WEBVIEW2</b></div>
    <div><span>FRONTEND</span><b>SVELTE 5 · VITE · SIGNED DIST</b></div>
    <div><span>MODEL</span><b>{up($snapshotStatus?.model)} · {up($snapshotStatus?.engine)}</b></div>
    <div><span>VOICE</span><b>FASTER-WHISPER STT · PIPER TTS</b></div>
    <div><span>VERSION</span><b>{up($snapshotStatus?.version)}</b></div>
    <div><span>LINK</span><b>{up($connection.source)} · WS {up($connection.socket)}</b></div>
    <div><span>INTEGRITY</span><b>{$securityReport?.integrity?.summary ? $securityReport.integrity.summary.toUpperCase() : `SEALED ${yn($securityReport?.integrity?.sealed)} · SIGNED ${yn($securityReport?.integrity?.signed)}`}</b></div>
    <div><span>AUDIT</span><b>HMAC CHAIN · {yn($securityReport?.audit?.chain_intact) === 'YES' ? 'INTACT' : yn($securityReport?.audit?.chain_intact) === 'NO' ? 'BROKEN' : 'UNKNOWN'}</b></div>
    <div><span>SANDBOX</span><b>ACLS {yn($securityReport?.sandbox?.acls_hardened) === 'YES' ? 'HARDENED' : yn($securityReport?.sandbox?.acls_hardened) === 'NO' ? 'OPEN' : 'UNKNOWN'} · PRIVILEGES {$securityReport?.sandbox?.privileges_held ?? '—'}</b></div>
    <div><span>NETWORK</span><b>{up($securityReport?.network?.egress_policy ?? $security.fields.networkPolicy)}</b></div>
  </div>
</section>
