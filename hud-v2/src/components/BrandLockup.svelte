<script lang="ts" context="module">
  // Gradient ids must be unique per mount (the lockup can be rendered by more
  // than one surface), so they are numbered rather than fixed.
  let instances = 0;
</script>
<script lang="ts">
  // ARGUS identity lockup: angular emblem + "ARGUS // CORE" + subtitle.
  //
  // Emblem: a hexagonal frame around the ARGUS "A" (the open crossbar of the
  // old wordmark, kept as brand DNA) whose crossbar is a diamond -- the eye of
  // the many-eyed watchman the name comes from. Everything is straight lines
  // and 45/60-degree cuts; nothing is rounded, nothing is a font.
  //
  // The eye is the ONE live element: it is lit only while the backend link is
  // live (`live`, driven by the real connection store in Header.svelte). It is
  // a signal, not a chip -- there is deliberately no LOCAL / SEALED / status
  // text anywhere in this lockup, because nothing here is backed by data.
  //
  // Type: Space Grotesk throughout (--font-ui). Weight contrast does the
  // "custom" work: ARGUS bold, the slashes hairline cyan, CORE medium.
  export let live = false;
  const id = `emb${++instances}`;
</script>

<!-- No role="img" on the wrapper: it also hosts the interactive micro strip
     (slot), and children of an img role are presentational to assistive tech.
     The emblem is decorative (aria-hidden); the two text lines speak for
     themselves, and the slash pair is hidden so it reads "ARGUS CORE". -->
<div class="lockup" class:live>
  <svg class="emblem" viewBox="0 0 48 48" width="54" height="54" aria-hidden="true" focusable="false">
    <defs>
      <linearGradient id="{id}-edge" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stop-color="#8ff7fd"/><stop offset=".55" stop-color="#12a9b5"/><stop offset="1" stop-color="#0d5560"/>
      </linearGradient>
      <linearGradient id="{id}-a" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#a9eef3"/>
      </linearGradient>
      <radialGradient id="{id}-plate" cx=".5" cy=".42" r=".7">
        <stop offset="0" stop-color="#0b3138"/><stop offset="1" stop-color="#040d10"/>
      </radialGradient>
    </defs>
    <!-- frame: pointy-top hexagon, plate fill + gradient edge -->
    <polygon class="frame" points="24,1.6 44.1,12.8 44.1,35.2 24,46.4 3.9,35.2 3.9,12.8" fill="url(#{id}-plate)" stroke="url(#{id}-edge)" stroke-width="1.7" stroke-linejoin="miter"/>
    <!-- machined inner line, upper-left only: light comes from one side -->
    <polyline class="rim" points="7.4,33.6 7.4,14.4 24,5.1 40.6,14.4" fill="none" stroke="#6ef3fb" stroke-opacity=".22" stroke-width=".8"/>
    <!-- the A: two legs, flat feet, open crossbar -->
    <polygon class="glyph" points="24,10.6 35.6,36 30.1,36 24,22.6 17.9,36 12.4,36" fill="url(#{id}-a)"/>
    <!-- the eye: a diamond where the crossbar would be -->
    <polygon class="eye" points="24,28.2 27.2,31.4 24,34.6 20.8,31.4"/>
  </svg>
  <div class="text">
    <span class="name"><b>ARGUS</b><i aria-hidden="true">//</i><em>CORE</em></span>
    <span class="tag">TACTICAL INTELLIGENCE GRID</span>
    <slot />
  </div>
</div>

<style>
  /* The lockup is one compact plate: a chamfered cockpit shape (top-right cut,
     the same 45-degree language as the panels and the System Overview cards)
     with a 1px gradient edge. The edge is a second layer, not a border,
     because a border can not follow a clip-path diagonal: ::before is the
     full-size edge colour, ::after the fill inset by 1px with its chamfer
     shortened by 0.59px so the diagonal edge is also exactly 1px thick. */
  /* Scale steps (the emblem anchors the brand, so it leads every step):
       header 72px  emblem 54 / wordmark 27 / subtitle 10.5
       tall screens emblem 56 / wordmark 28 / subtitle 11
       header 60px  emblem 44 / wordmark 24 / subtitle 10  (max-height 820px)
     The plate is padded 4px top and bottom around the taller of emblem / text
     column, so the frame hugs its content instead of floating around it. */
  .lockup {
    /* --tgls: the subtitle's tracking, measured per step so its ink width equals the wordmark's */
    --emb: 54px; --wm: 27px; --tg: 10.5px; --tgls: .348em;
    position: relative; isolation: isolate; display: inline-flex; align-items: center; gap: 13px; min-width: 0; max-width: 100%;
    padding: 3px 18px 3px 8px;
  }
  @media (min-height: 1000px) { .lockup { --emb: 56px; --wm: 28px; --tg: 11px; --tgls: .338em; } }
  @media (max-height: 820px) { .lockup { --emb: 44px; --wm: 24px; --tg: 10px; --tgls: .288em; padding-block: 3px; } }
  @media (max-width: 1440px) { .lockup { --wm: 25px; --tg: 10.5px; --tgls: .281em; gap: 11px; } }
  @media (max-width: 1440px) and (max-height: 820px) { .lockup { --emb: 44px; --wm: 23px; --tg: 10px; --tgls: .253em; } }
  .lockup::before {
    content: ''; position: absolute; inset: 0; z-index: -2;
    background: linear-gradient(100deg, rgba(0, 234, 242, .6), rgba(0, 234, 242, .16) 55%, rgba(0, 234, 242, .34));
    clip-path: polygon(0 0, calc(100% - 12px) 0, 100% 12px, 100% 100%, 0 100%);
  }
  .lockup::after {
    content: ''; position: absolute; inset: 1px; z-index: -1;
    background: linear-gradient(100deg, rgba(9, 28, 34, .97), rgba(4, 13, 17, .95));
    clip-path: polygon(0 0, calc(100% - 11.4px) 0, 100% 11.4px, 100% 100%, 0 100%);
  }
  .emblem { display: block; flex: 0 0 auto; width: var(--emb); height: var(--emb); overflow: visible; filter: drop-shadow(0 0 9px rgba(0, 234, 242, .16)); }
  .eye { fill: #35595f; transition: fill 300ms ease; }
  .live .eye { fill: var(--cyan, #00eaf2); filter: drop-shadow(0 0 3px rgba(0, 234, 242, .9)); }
  /* flex-shrink 0: the text column is the plate's content, so the PLATE grows to
     contain it -- the column can never be squeezed narrower than its own lines
     (that is how the tactical strip used to cross the plate's right edge). */
  .text { display: grid; gap: 2px; flex: 0 0 auto; min-width: 0; align-content: center; justify-items: start; }
  /* Name and subtitle are tracked so both lines land on the SAME measured
     width (a justified block, not a ragged one); the subtitle's tracking is
     tuned to the name at each scale step below. */
  .name {
    position: relative; display: inline-flex; align-items: baseline; gap: .3em; padding-bottom: 3px;
    font: 700 var(--wm)/1 var(--font-ui); letter-spacing: .2em; text-transform: uppercase; white-space: nowrap;
    color: var(--hud-ink, #f0f9fb);
  }
  .name b {
    font-weight: 700;
    background: linear-gradient(180deg, #ffffff 0%, #b9edf1 100%);
    -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
  }
  .name i { font-style: normal; font-weight: 300; letter-spacing: .02em; color: var(--cyan, #00eaf2); }
  .name em { font-style: normal; font-weight: 500; color: var(--cyan-soft, #6ef3fb); }
  .name::after {
    content: ''; position: absolute; left: 0; right: 0; bottom: 0; height: 1px;
    background: linear-gradient(90deg, rgba(0, 234, 242, .6), rgba(0, 234, 242, .12) 78%, transparent);
  }
  .tag {
    font: 600 var(--tg)/1 var(--font-ui); letter-spacing: var(--tgls); text-transform: uppercase; white-space: nowrap;
    color: color-mix(in srgb, var(--secondary, #94bcc5) 92%, transparent);
  }
</style>
