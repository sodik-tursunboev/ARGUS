<script lang="ts">
  // The shared panel frame: chamfered plate, 1px gradient edge, and one title
  // bar (PanelTitle). The Dashboard's summary panels and the Security /
  // Authentication pages are all built on this, so frame, padding and title
  // hierarchy are identical by construction. The frame is exactly as tall as its
  // content; `grow` claims a share of leftover rail height (Dashboard rails only,
  // see .dash-rail in styles/dashboard.css) and is 0 everywhere else.
  import PanelTitle from './PanelTitle.svelte';
  export let title: string;
  /** A Phosphor component, rendered duotone at the title-icon token size. */
  export let icon: any = null;
  export let testid: string | undefined = undefined;
  /** critical: red edge + tinted fill. warn: amber (an action is being asked of the person). */
  export let tone: 'normal' | 'critical' | 'warn' = 'normal';
  export let grow = 0;
</script>

<section class="dpanel" class:critical={tone === 'critical'} class:warn={tone === 'warn'} style="--grow:{grow}" data-testid={testid} aria-label={title}>
  <div class="dfill" aria-hidden="true"></div>
  <PanelTitle {title} {icon} {tone}><slot name="end" /></PanelTitle>
  <div class="dbody"><slot /></div>
</section>

<style>
  /* Frame = two stacked clipped layers, so the chamfer carries a true 1px edge
     (a border can not follow a clip-path diagonal): the section paints the edge
     gradient, .dfill paints the plate inset by 1px with its chamfer shortened by
     0.59px, keeping the diagonal exactly 1px too. */
  .dpanel {
    --edge-a: rgba(0, 234, 242, .40); --edge-b: rgba(0, 234, 242, .13); --edge-c: rgba(0, 234, 242, .22);
    --plate-a: rgba(9, 24, 30, .96); --plate-b: rgba(4, 12, 16, .94); --tick: var(--cyan, #00eaf2);
    position: relative; isolation: isolate; display: flex; flex-direction: column; min-width: 0; min-height: 0;
    padding: var(--ds-pad-y, 10px) var(--ds-pad-x, 12px);
    background: linear-gradient(135deg, var(--edge-a), var(--edge-b) 42%, var(--edge-c));
    clip-path: polygon(0 10px, 10px 0, calc(100% - 10px) 0, 100% 10px, 100% calc(100% - 10px), calc(100% - 10px) 100%, 10px 100%, 0 calc(100% - 10px));
  }
  .dfill {
    position: absolute; inset: 1px; z-index: -1;
    background: linear-gradient(150deg, var(--plate-a), var(--plate-b));
    clip-path: polygon(0 9.4px, 9.4px 0, calc(100% - 9.4px) 0, 100% 9.4px, 100% calc(100% - 9.4px), calc(100% - 9.4px) 100%, 9.4px 100%, 0 calc(100% - 9.4px));
  }
  /* accent tick, the panel language's one bright mark (sits inside the padding box) */
  .dpanel::before { content: ''; position: absolute; left: 12px; top: 1px; width: 34px; height: 2px; background: var(--tick); opacity: .9; }
  .dpanel.critical {
    --edge-a: rgba(255, 62, 92, .62); --edge-b: rgba(255, 62, 92, .28); --edge-c: rgba(255, 62, 92, .40);
    --plate-a: rgba(45, 12, 20, .95); --plate-b: rgba(14, 12, 16, .93); --tick: var(--red, #ff4a63);
  }
  .dpanel.warn {
    --edge-a: rgba(255, 194, 77, .58); --edge-b: rgba(255, 194, 77, .22); --edge-c: rgba(255, 194, 77, .36);
    --plate-a: rgba(38, 27, 8, .95); --plate-b: rgba(13, 12, 10, .93); --tick: var(--amber, #ffc24d);
  }
  .dbody { display: flex; flex-direction: column; flex: 1 1 auto; min-width: 0; min-height: 0; }
</style>
