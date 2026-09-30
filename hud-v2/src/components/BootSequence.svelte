<script lang="ts">
  /* The wake sequence: ARGUS's wake video WITH its narration, then the HUD --
     the V1 behaviour (hud/index.html: initbtn, signalAwake), restored.

     - The clip carries its own narration, so it plays with sound. WebView2
       usually allows that on load; when a browser refuses audible autoplay, a
       WAKE ARGUS button starts it from a real click, the one thing autoplay
       policy always accepts. Silent playback is only the last resort.
     - A page that is momentarily hidden (the pywebview window still being
       created and maximised) makes Chromium abort playback "to save power".
       That is not a failure: wait until the window is visible, then play.
       This was the bug -- one aborted play() skipped the whole video.
     - Only a real media error falls back to the splash image.
     - Every way out (end, skip, Escape, error, reduced motion, stall) tells
       the backend the HUD is awake (/hud-awake), so ARGUS greets right after
       the video instead of on its 90-second fallback timer. */
  import { createEventDispatcher, onMount } from 'svelte';
  import { agent, setAgentSnapshot } from '../stores/agent';
  import { connection } from '../stores/connection';
  import { notifyHudAwake } from '../services/api';

  const dispatch = createEventDispatcher<{ complete: void }>();
  let done = false;
  let video: HTMLVideoElement | undefined;
  let failed = false;
  let needsClick = false;
  const asset = (name: string) => `${import.meta.env.BASE_URL}assets/${name}`;

  function releaseVideo() {
    if (!video) return;
    video.pause();
    video.removeAttribute('src');
    video.load();
    video = undefined;
  }

  /* End the narration by easing it out rather than cutting it mid-word.
     setInterval, not requestAnimationFrame: rAF does not fire at all in a
     non-painting webview (measured), and a setTimeout backstop guarantees
     silence even if the interval is throttled. */
  function duck(ms: number): Promise<void> {
    const v = video;
    if (!v || v.muted || !v.volume) return Promise.resolve();
    const from = v.volume, t0 = performance.now();
    return new Promise((resolve) => {
      const id = window.setInterval(() => {
        const k = Math.min(1, (performance.now() - t0) / ms);
        try { v.volume = Math.max(0, from * 0.5 * (1 + Math.cos(Math.PI * k))); } catch { /* element gone */ }
        if (k >= 1) { window.clearInterval(id); resolve(); }
      }, 25);
      window.setTimeout(() => { window.clearInterval(id); try { v.volume = 0; } catch { /* gone */ } resolve(); }, ms + 120);
    });
  }

  async function finish(skipped = false) {
    if (done) return;
    done = true;
    void notifyHudAwake();
    if (skipped) await duck(260);
    if ($connection.source !== 'unavailable') setAgentSnapshot({ ...$agent, state: $agent.state === 'booting' ? 'standby' : $agent.state });
    releaseVideo();
    dispatch('complete');
  }

  function fail() {
    if (done) return;
    failed = true;
    window.setTimeout(() => void finish(), 900);
  }

  async function play() {
    if (!video || done || needsClick || document.hidden) return;
    video.muted = false;
    video.volume = 1;
    try {
      await video.play();
      return;
    } catch (error) {
      const name = error instanceof DOMException ? error.name : '';
      // Hidden or interrupted: not a failure; visibilitychange retries.
      if (document.hidden || name === 'AbortError') return;
      // Sound needs a click: offer one rather than skip the narration.
      if (name === 'NotAllowedError') { needsClick = true; return; }
    }
    try { video.muted = true; await video.play(); } catch { fail(); }
  }

  async function wake() {
    needsClick = false;
    if (!video) return;
    video.muted = false;
    video.volume = 1;
    try { await video.play(); }
    catch { video.muted = true; video.play().catch(fail); }
  }

  onMount(() => {
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) { void finish(); return; }
    const onVisible = () => { if (!document.hidden && video?.paused && !done) void play(); };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') void finish(true); };
    document.addEventListener('visibilitychange', onVisible);
    window.addEventListener('keydown', onKey);
    void play();
    // Backstop: a video that never starts, with nobody there to click, must
    // not hold the HUD hostage. Waiting for a click is the one legitimate
    // pause (the V1 wake screen did the same).
    const stall = window.setInterval(() => {
      if (!done && !needsClick && !document.hidden && video && video.currentTime === 0) void finish();
    }, 20000);
    return () => {
      document.removeEventListener('visibilitychange', onVisible);
      window.removeEventListener('keydown', onKey);
      window.clearInterval(stall);
      releaseVideo();
    };
  });
</script>

<section class="boot" class:failed aria-label="ARGUS startup stage">
  <div class="boot-media">
    {#if !done}
      <!-- No caption track exists for the ~5 s wake narration (no transcript
           ships with the clip); it is decorative and always skippable. Add a
           <track kind="captions"> here if a transcript is ever written. -->
      <!-- svelte-ignore a11y_media_has_caption -->
      <video bind:this={video} src={asset('argus-waking.mp4')} playsinline preload="auto"
        on:error={fail} on:ended={() => void finish()}></video>
      {#if failed}<img src={asset('splash.png')} alt="ARGUS startup fallback" />{/if}
    {/if}
  </div>
  {#if needsClick && !failed}
    <button type="button" class="boot-wake" on:click={wake}>▸ WAKE ARGUS</button>
  {/if}
  {#if !failed}<button type="button" on:click={() => void finish(true)}>SKIP PRESENTATION</button>{/if}
</section>
