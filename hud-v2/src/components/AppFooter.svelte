<script lang="ts">
  // The application footer: notices on the left, the build's version in the
  // middle, and the author credit on the right -- and nothing else.
  //
  // It used to repeat the state of everything already on screen (ARGUS state,
  // backend, websocket, auth, security, model, task: seven chips at 9.5px).
  // Each of those has a primary home now: ARGUS state = the core, backend link =
  // the header clock, auth = the Authentication tab (which lights when a
  // challenge is pending), security = Security Status, model = Local AI, task =
  // the Mission chip in the core. The credit is real text the person must be
  // able to read: 13px bold, never clipped, never replaced.
  import { createEventDispatcher } from 'svelte';
  import { snapshotStatus } from '../stores/snapshotView';
  import NotificationCenter from './NotificationCenter.svelte';
  const dispatch = createEventDispatcher<{ navigate: string }>();
  // the version the RUNNING backend reports (/status), never a constant in the bundle
  $: version = typeof $snapshotStatus?.version === 'string' && $snapshotStatus.version ? $snapshotStatus.version : null;
</script>

<footer class="app-foot" data-testid="footer">
  <div class="foot-left"><NotificationCenter on:navigate={(event) => dispatch('navigate', event.detail)} /></div>
  <div class="foot-mid">{#if version}<span class="ver">ARGUS <b>V{version}</b></span>{/if}</div>
  <div class="foot-right"><b class="credit">BUILT BY SODIK TURSUNBOEV</b><i class="pipe" aria-hidden="true"></i><span class="slogan">A SAFER TOMORROW</span></div>
</footer>

<style>
  .app-foot {
    display: grid; grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr); align-items: center; column-gap: 16px;
    min-width: 0; min-height: 30px; padding: 0 14px;
    border-top: 1px solid rgba(0, 234, 242, .22);
    background: linear-gradient(180deg, rgba(4, 13, 17, .55), rgba(3, 9, 11, .9));
    font-family: var(--font-ui); color: var(--secondary);
  }
  @media (max-height: 820px) { .app-foot { min-height: 28px; } }
  .foot-left { display: flex; align-items: center; min-width: 0; justify-self: start; }
  .foot-mid { justify-self: center; min-width: 0; }
  .foot-right { display: flex; align-items: center; justify-content: flex-end; gap: 12px; min-width: 0; justify-self: end; white-space: nowrap; }

  .ver { font: 600 12px/1 var(--font-data); letter-spacing: .1em; color: var(--muted); }
  .ver b { font-weight: 700; color: var(--secondary); }
  .credit { font: 700 13px/1 var(--font-ui); letter-spacing: .12em; color: var(--text, #edf8fa); }
  .pipe { width: 1px; height: 14px; background: rgba(0, 234, 242, .35); }
  .slogan { font: 600 12px/1 var(--font-ui); letter-spacing: .12em; color: var(--cyan-soft, #6ef3fb); }
  /* the slogan is the first thing to go when the strip runs out of room; the credit never does */
  @media (max-width: 1100px) { .pipe, .slogan { display: none; } }

  /* NOTICES trigger: the legacy footer rules (8-9.5px) are not applied to this component, so it is styled here.
     The popover opens upwards from the left edge (the legacy default is right-anchored and ran off the viewport). */
  .foot-left :global(.notification-center summary) {
    display: inline-flex; align-items: center; min-height: 22px; padding: 0 2px; list-style: none; cursor: pointer;
    font: 700 12px/1 var(--font-ui); letter-spacing: .12em; color: var(--secondary);
  }
  .foot-left :global(.notification-center summary:hover) { color: var(--text, #edf8fa); }
  .foot-left :global(.notification-center summary b) { display: inline-grid; place-items: center; min-width: 16px; height: 16px; margin-left: 7px; border-radius: 50%; background: var(--amber, #ffc24d); color: #020607; font: 800 10px/1 var(--font-data); }
  .foot-left :global(.notice-popover) { left: 0; right: auto; }
</style>
