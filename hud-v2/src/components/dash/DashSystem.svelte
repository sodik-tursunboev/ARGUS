<script lang="ts">
  import DashPanel from '../ui/Panel.svelte';
  import SystemCards from '../SystemCards.svelte';
  import { IconSystemOverview } from '../../lib/ui/icons';
</script>

<DashPanel title="SYSTEM OVERVIEW" icon={IconSystemOverview} testid="system-overview" grow={1.15}>
  <SystemCards />
</DashPanel>
