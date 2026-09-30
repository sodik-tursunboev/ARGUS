<script lang="ts" context="module">
  // Each instance needs its own gradient/mask ids (the About page and the
  // header can both be mounted), so ids are numbered per mount.
  let instances = 0;
</script>
<script lang="ts">
  // The ARGUS signature wordmark. Bespoke geometry, not a font: five
  // letterforms drawn on a 100-unit cap-height grid with 20-unit stems.
  //   A -- sharp apex, open crossbar (the single cyan accent segment)
  //   R -- full-height stem, compact chamfered bowl, straight diagonal leg
  //   G -- chamfered octagonal body, open on the right, stubbed terminal bar
  //   U -- wide flat mechanical bottom with 14-unit corner cuts, 4-unit top cuts
  //   S -- segmented block construction with stepped terminals
  // One hairline machining cut passes through R and G only. The registration
  // ticks and the crosshair are coordinate marks (no values). The status node
  // is the one live element: it is lit when the backend link is live -- a real
  // signal, never decoration pretending to be data.
  export let height = 34;
  /** Real link state for the status node. */
  export let live = false;
  export let label = 'ARGUS';
  const id = `wm${++instances}`;
  // Letter origins on the shared baseline grid (letter widths 92/80/88/86/82, gap 26).
  const LETTERS = {
    a: 'M46,0 L0,100 L24,100 L46,34 Z M46,0 L92,100 L68,100 L46,34 Z',
    r: 'M0,0 L60,0 L80,20 L80,40 L62,58 L80,100 L60,100 L40,58 L20,58 L20,100 L0,100 Z M20,18 L58,18 L62,22 L62,36 L58,40 L20,40 Z',
    g: 'M22,0 L66,0 L84,18 L30,18 L20,28 L20,72 L30,82 L68,82 L68,62 L56,62 L56,68 L48,68 L48,44 L88,44 L88,78 L66,100 L22,100 L0,78 L0,22 Z',
    u: 'M0,4 L4,0 L20,0 L20,76 L24,80 L62,80 L66,76 L66,0 L82,0 L86,4 L86,86 L72,100 L14,100 L0,86 Z',
    s: 'M14,0 L82,0 L82,14 L78,14 L78,18 L20,18 L20,42 L68,42 L82,56 L82,86 L68,100 L0,100 L0,86 L4,86 L4,82 L62,82 L62,58 L14,58 L0,44 L0,14 Z',
  };
  const X = { r: 118, g: 224, u: 338, s: 450 };
  // Crossbar: left leg inner edge to a cut parallel to the right leg.
  const ACCENT = 'M37.3,60 L43.7,60 L49.7,78 L31.3,78 Z';
  // viewBox: 566 x 118 with the marks; cap height 100 -> `height` px * 100/118.
  $: width = Math.round(height * (566 / 118));
</script>

<svg class="wordmark" class:live viewBox="-12 -8 566 118" {width} {height} role="img" aria-label={label} focusable="false">
  <defs>
    <linearGradient id="{id}-fill" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#bdfcff"/><stop offset=".5" stop-color="#62e9ec"/><stop offset="1" stop-color="#a2fbff"/>
    </linearGradient>
    <mask id="{id}-cut"><rect x="-20" y="-20" width="620" height="160" fill="#fff"/><rect x="116" y="47" width="200" height="3.2" fill="#000"/></mask>
  </defs>
  <g class="wm-plate" transform="translate(0 2.4)">
    <path d={LETTERS.a}/>
    <path fill-rule="evenodd" transform="translate({X.r} 0)" d={LETTERS.r}/>
    <path transform="translate({X.g} 0)" d={LETTERS.g}/>
    <path transform="translate({X.u} 0)" d={LETTERS.u}/>
    <path transform="translate({X.s} 0)" d={LETTERS.s}/>
  </g>
  <g class="wm-face" fill="url(#{id}-fill)" mask="url(#{id}-cut)">
    <path d={LETTERS.a}/>
    <path fill-rule="evenodd" transform="translate({X.r} 0)" d={LETTERS.r}/>
    <path transform="translate({X.g} 0)" d={LETTERS.g}/>
    <path transform="translate({X.u} 0)" d={LETTERS.u}/>
    <path transform="translate({X.s} 0)" d={LETTERS.s}/>
  </g>
  <path class="wm-accent" d={ACCENT}/>
  <g class="wm-marks" fill="none" stroke-width="1.2">
    <path d="M-8,100 h6 M-5,97 v6"/>
    <path d="M540,100 h6 M543,97 v6"/>
  </g>
  <g class="wm-node"><rect x="546" y="0" width="7" height="7"/><rect class="wm-node-ring" x="544" y="-2" width="11" height="11"/></g>
</svg>

<style>
  .wordmark { display: block; overflow: visible; filter: drop-shadow(0 0 7px rgba(0, 234, 242, .18)); }
  .wm-plate { fill: #0a3a41; opacity: .9; }
  .wm-accent { fill: var(--cyan, #00eaf2); }
  .wm-marks { stroke: #3d8f99; }
  .wm-node rect { fill: #33555c; transition: fill 300ms ease; }
  .wm-node .wm-node-ring { fill: none; stroke: #33555c; stroke-opacity: .5; stroke-width: 1; }
  .live .wm-node rect { fill: var(--cyan, #00eaf2); }
  .live .wm-node .wm-node-ring { stroke: var(--cyan, #00eaf2); stroke-opacity: .35; }
</style>
