<script lang="ts">
  /* Agent Town — 2D SVG fallback for the Agents Office.
     Pure Svelte + SVG + CSS: no WebGL, no Three.js. Real state only:
     node colors derive from each agent's actual lifecycle state; a REAL
     handoff event (agent.handoff) highlights the trace between the two
     agents. Decorative geometry, zero fabricated telemetry. */
  import type { OfficeAgent } from '../types/argus';

  export let agents: OfficeAgent[] = [];
  export let handoff: { from: string; to: string; ts: number } | null = null;
  export let onSelect: (id: string) => void = () => {};

  const stateClass: Record<string, string> = {
    idle: 'is-idle', queued: 'is-queued', preparing: 'is-busy', thinking: 'is-thinking',
    responding: 'is-busy', waiting_auth: 'is-queued', executing: 'is-ok',
    verifying: 'is-busy', completed: 'is-ok', warning: 'is-warn', blocked: 'is-critical',
    error: 'is-critical', disabled: 'is-idle',
  };

  // Fixed decagon layout around the core — geometry is design, not data.
  // Ten stations evenly spaced on the ring (36° apart, first at top).
  const ring: Record<string, { x: number; y: number }> = Object.fromEntries(
    ['security', 'threat', 'assistant', 'system', 'network',
     'verifier', 'planner', 'diagnostics', 'forensics', 'response'].map((id, i) => {
      const angle = -Math.PI / 2 + (i * 2 * Math.PI) / 10;
      return [id, { x: Math.round(200 + 165 * Math.cos(angle)), y: Math.round(210 + 165 * Math.sin(angle)) }];
    }));
  const R = 400, C = 200, CX = 200, CY = 210;

  $: nodes = agents.map((a) => ({ ...a, pos: ring[a.id] ?? { x: 60, y: 60 } }));
  $: traceClass = (a: OfficeAgent) => `trace ${stateClass[a.state] ?? 'is-idle'}${handoff && (handoff.from === a.id || handoff.to === a.id) ? ' trace-handoff' : ''}`;
  const short = (name: string) => name.replace(' Agent', '').toUpperCase();
</script>

<svg class="agent-town" viewBox="0 0 400 420" role="img" aria-label="Agent Town: the registered agents around the ARGUS core">
  <defs>
    <radialGradient id="town-core" cx="50%" cy="45%" r="60%">
      <stop offset="0%" stop-color="rgba(56,224,255,.28)"/>
      <stop offset="60%" stop-color="rgba(56,224,255,.06)"/>
      <stop offset="100%" stop-color="rgba(3,9,11,0)"/>
    </radialGradient>
  </defs>

  {#each nodes as a (a.id)}
    <line class={traceClass(a)} x1={CX} y1={CY} x2={a.pos.x} y2={a.pos.y}/>
  {/each}

  <circle cx={CX} cy={CY} r="64" fill="url(#town-core)"/>
  <circle class="core-ring" cx={CX} cy={CY} r={R / 2}/>
  <circle class="core-ring core-ring-inner" cx={CX} cy={CY} r={R / 2 - 26}/>
  <circle class="core-dot" cx={CX} cy={CY} r="7"/>
  <text class="core-label" x={CX} y={CY + 30}>ARGUS CORE</text>

  {#each nodes as a (a.id)}
    <g class="town-node {stateClass[a.state] ?? 'is-idle'}"
       class:selected={false} role="button" tabindex="0"
       on:click={() => onSelect(a.id)}
       on:keydown={(e) => (e.key === 'Enter' || e.key === ' ') && onSelect(a.id)}
       transform={`translate(${a.pos.x}, ${a.pos.y})`}>
      <circle class="node-halo" r="22"/>
      <circle class="node-dot" r="7"/>
      {#if a.state === 'thinking' || a.state === 'queued'}
        <circle class="node-pulse" r="7"/>
      {/if}
      <text class="node-name" y="38">{short(a.name)}</text>
    </g>
  {/each}

  {#if handoff}
    <g class="handoff-flag">
      <text x={CX} y="26">{handoff.from.toUpperCase()} → {handoff.to.toUpperCase()}</text>
    </g>
  {/if}
</svg>

<style>
  .agent-town { width: 100%; height: auto; display: block; }
  .trace { stroke: rgba(56, 224, 255, .10); stroke-width: 1; stroke-dasharray: 3 5; }
  .trace.is-thinking, .trace.is-busy { stroke: rgba(56, 224, 255, .5); stroke-dasharray: none; }
  .trace.is-queued { stroke: rgba(255, 178, 68, .5); }
  .trace.is-ok { stroke: rgba(74, 222, 158, .45); }
  .trace.is-warn { stroke: rgba(255, 178, 68, .6); }
  .trace.is-critical { stroke: rgba(255, 92, 92, .6); }
  .trace-handoff { stroke: rgba(56, 224, 255, .95); stroke-width: 2; stroke-dasharray: 6 4; animation: trace-flow 1.2s linear infinite; }
  @keyframes trace-flow { to { stroke-dashoffset: -20; } }
  .core-ring { fill: none; stroke: rgba(56, 224, 255, .22); stroke-width: 1; }
  .core-ring-inner { stroke-dasharray: 2 6; stroke: rgba(56, 224, 255, .14); }
  .core-dot { fill: #38e0ff; }
  .core-label { fill: rgba(214, 238, 245, .85); font-size: 9px; letter-spacing: .18em; text-anchor: middle; }
  .town-node { cursor: pointer; }
  .node-halo { fill: rgba(56, 224, 255, .05); stroke: rgba(56, 224, 255, .28); stroke-width: 1; }
  .node-dot { fill: rgba(140, 176, 190, .8); }
  .is-thinking .node-dot, .is-busy .node-dot { fill: #a78bfa; }
  .is-thinking .node-halo, .is-busy .node-halo { stroke: rgba(167, 139, 250, .6); }
  .is-queued .node-dot, .is-warn .node-dot { fill: #ffb244; }
  .is-queued .node-halo, .is-warn .node-halo { stroke: rgba(255, 178, 68, .55); }
  .is-ok .node-dot { fill: #4ade9e; }
  .is-ok .node-halo { stroke: rgba(74, 222, 158, .5); }
  .is-critical .node-dot { fill: #ff5c5c; }
  .is-critical .node-halo { stroke: rgba(255, 92, 92, .55); }
  .node-pulse { fill: none; stroke: currentColor; opacity: .5; animation: node-pulse 1.6s ease-out infinite; }
  .is-thinking .node-pulse { stroke: #a78bfa; }
  .is-queued .node-pulse { stroke: #ffb244; }
  @keyframes node-pulse { 0% { r: 7; opacity: .55; } 100% { r: 20; opacity: 0; } }
  .node-name { fill: rgba(214, 238, 245, .78); font-size: 8.5px; letter-spacing: .16em; text-anchor: middle; }
  .handoff-flag text { fill: #38e0ff; font-size: 9px; letter-spacing: .14em; text-anchor: middle; }
  @media (prefers-reduced-motion: reduce) { .trace-handoff, .node-pulse { animation: none; } }
</style>
