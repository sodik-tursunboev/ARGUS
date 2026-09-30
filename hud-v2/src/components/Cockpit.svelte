<script lang="ts">
  // ARGUS cockpit host -- fluid, not scaled.
  //
  // Earlier iterations scaled a fixed 1920x1080 canvas uniformly
  // (transform: scale(min(vw/1920, vh/1080))). Measured on real targets that
  // made 6.5px micro-labels render at ~4.6px on 1366x768 and inflated every
  // surface 133% on 2560x1440: text must not scale with the chassis.
  //
  // This pass the host is simply the real viewport: the dashboard grid
  // (shell.css) flexes via clamp()/minmax() with a size floor at 1280x720,
  // below which the page scrolls rather than shrink-wraps. Type keeps its
  // designed pixel size at every target. The core column keeps priority
  // (min 480px) so the robot stays the dominant element.
  //
  // The verification surface (PIN/face/auth modal) intentionally renders
  // OUTSIDE this component (App.svelte keeps <VerificationCenter/> at the
  // root), so critical authentication UI stays viewport-native and easy to
  // use; it auto-opens whenever the backend demands verification.

  /**
   * Legacy export kept so any importer still reads a meaningful constant:
   * the design's width floor (the old canvas no longer exists).
   */
  export const CANVAS_W = 1920;
</script>

<div class="hud-viewport">
  <slot />
</div>
