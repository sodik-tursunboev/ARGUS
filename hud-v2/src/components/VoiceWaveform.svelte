<script lang="ts">
  // Waveform under the core. Two honest sources only: a real backend voice
  // level when one has been reported (voice.level events), or a clearly
  // labelled state-driven pattern. The HUD has no microphone capture route,
  // so there is no AnalyserNode to draw from -- pretending otherwise would be
  // fake telemetry. The pattern's motion follows the agent state (idle
  // baseline / listening wave / processing pulse) and stops entirely under
  // prefers-reduced-motion via CSS.
  import type { VoiceMode } from '../stores/agent';
  export let mode: VoiceMode = 'idle';
  export let level: number | null = null;
  export let state: string = 'standby';
  // 41 bars; the seed shape is a symmetric envelope so the idle baseline reads
  // as a signal at rest rather than random noise.
  const N = 41;
  const seed = Array.from({ length: N }, (_, i) => { const x = (i - (N - 1) / 2) / ((N - 1) / 2); return Math.max(0.12, Math.cos(x * Math.PI / 2) * (0.55 + 0.45 * Math.abs(Math.sin(i * 1.7)))); });
  $: live = level !== null;
  $: motion = mode === 'disabled' ? 'off' : live ? 'live' : mode === 'listening' || state === 'listening' ? 'listen' : mode === 'speaking' ? 'speak' : mode === 'processing' || ['understanding','planning','verifying'].includes(state) ? 'process' : state === 'executing' ? 'execute' : state === 'waiting_auth' ? 'hold' : 'idle';
</script>
<div class={`voice-waveform wave-${motion}`} class:active={motion!=='idle'&&motion!=='off'} class:disabled={mode==='disabled'} aria-label={`Voice state: ${mode}`} data-testid="waveform">
  <div class="wave-bars" aria-hidden="true">{#each seed as s, i}<i style={`--h:${live ? Math.max(0.08, s * Math.min(1, level ?? 0)) : s};--d:${(i * 37) % 100}`}></i>{/each}</div>
  <span class="wave-caption">{live ? 'LIVE LEVEL' : `SIGNAL · ${motion.toUpperCase()}`}</span>
</div>
