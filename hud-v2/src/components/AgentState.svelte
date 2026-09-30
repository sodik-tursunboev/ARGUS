<script lang="ts">
  import type { AgentState as AgentStateValue } from '../stores/agent';
  import { stateLabels } from '../stores/agent';
  export let state: AgentStateValue;
  export let capability: string | null = null;
</script>

<div class="agent-state state-{state}" aria-live="polite">
  <span>ARGUS // CORE</span>
  <h1>{stateLabels[state]}</h1>
  <p>{capability ?? 'NO ACTIVE CAPABILITY'}</p>
</div>
