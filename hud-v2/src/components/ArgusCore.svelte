<script lang="ts">
  import { onMount } from 'svelte';
  import { agent } from '../stores/agent';
  import { security } from '../stores/security';
  import { tasks, taskProgress } from '../stores/tasks';
  import { voiceSession } from '../stores/voice';
  import AgentState from './AgentState.svelte';
  import VoiceWaveform from './VoiceWaveform.svelte';
  const ticks = Array.from({ length: 48 });
  // Core microdetail geometry (decorative structural elements only -- these
  // carry no telemetry). 96 micro-ticks over 12 majors, 6 radial dividers,
  // 3 orbit dots on a slow carrier, 6 ring labels at honest capability names,
  // and A/B/C sector indexes as pure coordinate markers.
  const micro = Array.from({ length: 96 }, (_, i) => ({ deg: i * 3.75, major: i % 8 === 0 }));
  const dividers = [0, 60, 120, 180, 240, 300];
  const orbitPhase = [0, 140, 235];
  const ringLabels: Array<{ t: string; x: number; y: number }> = [
    { t: 'SECURITY', x: 300, y: 22 }, { t: 'POLICY', x: 512, y: 118 }, { t: 'AUTH', x: 538, y: 330 },
    { t: 'VOICE', x: 420, y: 530 }, { t: 'AGENT', x: 172, y: 534 }, { t: 'LOCAL AI', x: 66, y: 330 },
  ];
  const pol = (deg: number, r: number): [number, number] => {
    const a = ((deg - 90) * Math.PI) / 180;
    return [300 + r * Math.cos(a), 300 + r * Math.sin(a)];
  };
  const indexes = ['A1', 'A2', 'B1', 'B2', 'C1', 'C2'].map((t, i) => ({ t, ...(() => { const [x, y] = pol(30 + i * 60, 268); return { x, y }; })() }));
  $: alertImage = ['warning', 'blocked', 'lockdown', 'error'].includes($agent.state);
  /* Original JPG always (Core Bay pass): the flood-fill PNG alpha asset is
     retired. The JPG's black canvas is placed inside the near-black CORE BAY
     (#000508) and rendered with mix-blend-mode:normal — black meets black,
     so the rectangle edge is invisible and every armour pixel stays opaque
     (core-robot.css). Only a top-only fade keeps the face crisp while the
     lower canvas melts into the lane boundary. */
  $: coreBase = import.meta.env.BASE_URL + 'assets/';
  $: coreSrc = `${coreBase}${alertImage ? 'core-alert' : 'core-idle'}.jpg`;

  /* ---- Zone C status band: MISSION + VOICE only ----
     The band used to carry four chips. LOCAL (model online) and LINK (backend
     link) repeated the Local AI and Network panels and the header clock, so they
     are gone; what stays is the one thing nowhere else on the Dashboard shows --
     the mission (task) progress -- and the voice SESSION, straight from the
     backend's voice_state / muted (stores/voice.ts), not the agent's derived mode. */
  $: missionState = $taskProgress.totalSteps ? `${$taskProgress.completedSteps}/${$taskProgress.totalSteps}` : 'IDLE';

  /* ---- Development-only collision audit ---------------------------------
     Verifies the rebuilt lanes: the robot visual, the hero stack, the
     waveform and the status strip each own non-overlapping physical regions
     (getBoundingClientRect). Runs only under `vite dev`; the production
     bundle never executes it, so no stray console noise ships. */
  onMount(() => {
    if (!import.meta.env.DEV) return;
    const audit = (): void => {
      const probe = document.querySelector('.identity-core');
      if (!probe) return;
      const box = (sel: string): DOMRect | null => probe.querySelector<HTMLElement>(sel)?.getBoundingClientRect() ?? null;
      const key = (sel: string): DOMRect | null => probe.closest<HTMLElement>(sel)?.getBoundingClientRect() ?? box(sel);
      const visual = key('.core-visual');
      if (!visual) return;
      const protectedBoxes: Array<[string, DOMRect | null]> = [
        ['state', key('.agent-state')], ['waveform', key('.voice-waveform')],
        ['sentence', key('.core-status-line')], ['strip', key('.core-status-band')],
        ['ladder-left', key('.state-ladder')],
      ];
      const overlaps = (a: DOMRect, b: DOMRect, pad = 4): boolean =>
        a.right - pad > b.left && b.right - pad > a.left && a.bottom - pad > b.top && b.bottom - pad > a.top;
      for (const [label, rect] of protectedBoxes) {
        if (rect && overlaps(visual, rect)) {
          console.warn(`[core-collision] "${label}" overlaps the robot visual zone`, { visual, rect });
        }
      }
    };
    const run = (): void => requestAnimationFrame(() => requestAnimationFrame(audit));
    const t = window.setTimeout(run, 600);
    run();
    return () => window.clearTimeout(t);
  });

  // Reference's left-hand vertical state ladder. 'understanding' displays as
  // THINKING here (matching the reference's wording) while still keying off
  // the real AgentState value -- a display label, not a fabricated state.
  // States outside this list of 6 (booting/waiting_auth/completed/warning/
  // blocked/lockdown/error) light no rung, honestly, rather than guessing
  // the nearest one.
  // One-line status under the waveform, ONLY where it adds a cause the hero word
  // does not already say. 'Standing by.' under STANDBY, 'Executing…' under
  // EXECUTING and the like were the hero repeated as a sentence, so they are gone.
  const STATUS_LINE: Record<string, string> = {
    warning: 'Attention needed.', blocked: 'Blocked by policy.', error: 'Backend unavailable.',
  };
  const STATE_RUNGS: { key: string; label: string }[] = [
    { key: 'standby', label: 'STANDBY' },
    { key: 'listening', label: 'LISTENING' },
    { key: 'understanding', label: 'THINKING' },
    { key: 'planning', label: 'PLANNING' },
    { key: 'executing', label: 'EXECUTING' },
    { key: 'verifying', label: 'VERIFYING' },
  ];
</script>

<section class="argus-core state-{$agent.state} posture-{$security.posture}" aria-label="ARGUS core state">
  <!-- core-stage: a size container the .core-visual fills (styles/dashboard.css).
       The STATE / SECURITY strip that used to sit above it is gone: both values
       are already shown by the hero state word and the Security Status panel. -->
  <div class="core-stage">
  <ul class="state-ladder" aria-label="Agent state ladder" data-testid="state-ladder">
    {#each STATE_RUNGS as rung (rung.key)}
      <li class:active={$agent.state === rung.key}><i></i>{rung.label}</li>
    {/each}
  </ul>
  <div class="core-visual">
    <div class="halo"></div>
    <svg class="tactical-rings" viewBox="0 0 600 600" aria-hidden="true" focusable="false">
      <circle class="ring ring-perimeter" cx="300" cy="300" r="282" />
      <circle class="ring ring-dash" cx="300" cy="300" r="264" />
      <circle class="ring ring-fine" cx="300" cy="300" r="239" />
      <circle class="ring ring-segment ring-segment-a" cx="300" cy="300" r="225" />
      <circle class="ring ring-segment ring-segment-b" cx="300" cy="300" r="197" />
      <circle class="ring ring-inner" cx="300" cy="300" r="167" />
      <path class="ring-path path-a" d="M 97 221 A 218 218 0 0 1 283 74" />
      <path class="ring-path path-b" d="M 421 483 A 218 218 0 0 1 502 343" />
      <g class="ring-markers"><circle cx="95" cy="221" r="4" /><circle cx="502" cy="343" r="4" /><circle cx="300" cy="74" r="3" /></g>
      <g class="ring-micro" aria-hidden="true">
        {#each micro as t (t.deg)}
          {@const [x1, y1] = pol(t.deg, 282)}{@const [x2, y2] = pol(t.deg, t.major ? 272 : 277)}
          <line class:major={t.major} x1={x1} y1={y1} x2={x2} y2={y2} />
        {/each}
        {#each dividers as d (d)}
          {@const [x1, y1] = pol(d, 167)}{@const [x2, y2] = pol(d, 282)}
          <line class="divider" x1={x1} y1={y1} x2={x2} y2={y2} />
        {/each}
        <circle class="dot-inner" cx="300" cy="300" r="156" />
        {#each orbitPhase as p (p)}
          <circle class="orbit-dot" cx="300" cy="134" r="2.4" style={`--phase:${p}deg`} />
        {/each}
        {#each ringLabels as l (l.t)}<text class="ring-label" x={l.x} y={l.y}>{l.t}</text>{/each}
        {#each indexes as ix (ix.t)}<text class="ring-index" x={ix.x} y={ix.y}>{ix.t}</text>{/each}
        <g class="reticle" aria-hidden="true">
          <path d="M 254 254 h 14 M 254 254 v 14 M 346 254 h -14 M 346 254 v 14 M 254 346 h 14 M 254 346 v -14 M 346 346 h -14 M 346 346 v -14" />
          <circle class="reticle-dot" cx="300" cy="300" r="1.4" />
          <line x1="196" y1="300" x2="246" y2="300" /><line x1="354" y1="300" x2="404" y2="300" />
        </g>
      </g>
    </svg>
    <div class="ring-rays" aria-hidden="true"></div><div class="outer-ring">{#each ticks as _, i}<i style={`--r:${i * 7.5}deg`}></i>{/each}</div><div class="middle-ring"></div><div class="inner-ring"></div><div class="ring-arc ring-arc-a" aria-hidden="true"></div><div class="ring-arc ring-arc-b" aria-hidden="true"></div>
    <div class="core-ambient" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div>
    <img class:alert={alertImage} src={coreSrc} alt="ARGUS robot core" />
  </div>
  </div>
  <div class="core-text" aria-label="Core state and status">
    <AgentState state={$agent.state} capability={$agent.activeCapability ?? $tasks.activeCapability} />
    <VoiceWaveform mode={$agent.voice} level={$agent.voiceLevel ?? null} state={$agent.state} />
    {#if STATUS_LINE[$agent.state]}<p class="core-status-line" aria-live="polite">{STATUS_LINE[$agent.state]}</p>{/if}
    <div class="core-status-band" aria-label="Core status summary">
      <span>MISSION <b class:ok={missionState!=='IDLE'}>{missionState}</b></span>
      <span title={$voiceSession.detail}>VOICE <b class:ok={$voiceSession.key==='listening'||$voiceSession.key==='speaking'||$voiceSession.key==='processing'} class:warn={$voiceSession.key==='disabled'}>{$voiceSession.label}</b></span>
    </div>
  </div>
</section>
