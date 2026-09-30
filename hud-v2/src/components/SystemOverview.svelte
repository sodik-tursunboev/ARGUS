<script lang="ts">
  import SystemCards from './SystemCards.svelte';
  import { IconSystemOverview } from '../lib/ui/icons';
  // SYSTEM OVERVIEW as it appears on the Tools page (legacy panel frame). The
  // Dashboard uses the same cards inside the dense dashboard frame instead --
  // see dash/DashSystem.svelte.
</script>
<section class="panel system" data-testid="system-overview">
  <div class="panel-title"><h2><IconSystemOverview size={12} class="h2-icon" aria-hidden="true"/>SYSTEM OVERVIEW</h2></div>
  <SystemCards />
</section>

<style>
  /* The panel is a title row + a card row in EVERY context: a grid, so the card
     area is the remaining height and can never overflow the panel (a
     `height:100%` card grid did, wherever the panel was stretched). */
  .system { display: grid; grid-template-rows: auto minmax(0, 1fr); min-height: 0; }
</style>
