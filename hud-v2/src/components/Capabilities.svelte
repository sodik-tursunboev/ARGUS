<script lang="ts">
  /* ARGUS CAPABILITIES — the real /skills contract (main.py list_skills):
     the skill groups ARGUS can actually be asked to do, built from
     intent.py's declared fast paths. Discoverability, not authority:
     listing a capability grants nothing. */
  import { onMount } from 'svelte';
  import { fetchSkills } from '../services/api';
  import { connection } from '../stores/connection';

  let groups: { skill: string; actions: string[] }[] = [];
  let note = '';
  let count = 0;
  let loaded = false;
  let error = '';

  onMount(async () => {
    try {
      const data = await fetchSkills();
      groups = data.groups ?? [];
      note = data.note ?? '';
      count = data.count ?? 0;
    } catch (e) {
      error = e instanceof Error ? e.message : 'Capabilities unavailable';
    } finally {
      loaded = true;
    }
  });

  const up = (v: unknown) => (v === null || v === undefined || v === '' ? '—' : String(v).toUpperCase());
</script>

<section class="panel caps-panel" aria-label="ARGUS capability catalog">
  <div class="panel-title"><h2>CAPABILITIES</h2>
    <span class="status" class:unknown={!loaded || !!error}>{loaded ? (error ? 'UNAVAILABLE' : `${count} ACTIONS`) : 'LOADING'}</span>
  </div>
  {#if error}
    <p class="rail-note">{$connection.source === 'offline' ? 'The backend is unreachable — capabilities appear when the link is restored.' : error}</p>
  {:else if loaded && !groups.length}
    <p class="rail-note">The backend reported no capability groups.</p>
  {:else}
    <div class="caps-grid">
      {#each groups as g (g.skill)}
        <div class="caps-group">
          <b>{up(g.skill)}</b>
          <span>{g.actions.length} ACTIONS</span>
          <small>{g.actions.join(' · ')}</small>
        </div>
      {/each}
    </div>
    {#if note}<p class="rail-note">{note}</p>{/if}
  {/if}
</section>

<style>
  .caps-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 10px; }
  .caps-group { background: rgba(10, 22, 26, .55); border: 1px solid rgba(56, 224, 255, .1); border-radius: 8px; padding: 10px 12px; display: grid; gap: 3px; }
  .caps-group b { font-size: 12.5px; letter-spacing: .08em; color: var(--text-strong, #e6f2f5); }
  .caps-group span { font-size: 9.5px; letter-spacing: .14em; color: rgba(56, 224, 255, .75); }
  .caps-group small { font-size: 11px; line-height: 1.5; color: rgba(190, 214, 222, .72); }
</style>
