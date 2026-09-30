/* ARGUS AI City -- the shared visual kit.
   ==========================================================================

   Pure Three.js. No Svelte, no stores, no backend: everything here builds or
   poses GEOMETRY, and the caller decides what (if anything) that geometry is
   allowed to mean. That separation is deliberate -- CityScene.svelte owns
   every line that reads real ARGUS state, so "does the city invent activity?"
   stays answerable by reading one file.

   Split out of CityScene.svelte during CITY-4: the component had grown past
   2000 lines and the architecture kit, city props and robot rig are all pure
   functions with no component dependency. */

import * as THREE from 'three';

/* ==========================================================================
   1. MATERIAL SYSTEM
   ========================================================================== */

/** The whole city's color vocabulary, in one place. Roughly 75% of surface
 *  area draws from the structural band, 15% from grey/glass, and only the
 *  last group is ever allowed to light up.
 *
 *  The structural band is a cool slate, not near-black: the first values
 *  here (asphalt 0x0b0f12, sidewalk 0x1a2024) sat within a few percent of
 *  the navy background, so streets and blocks vanished into it no matter
 *  how the lights were set. */
export const PALETTE = {
  GRAPHITE_METAL: 0x243040,
  DARK_COMPOSITE: 0x17202b,
  BLACK_GLASS: 0x131c26,
  STRUCTURAL_STEEL: 0x3a4757,
  CONCRETE: 0x232c37,
  ASPHALT: 0x19212c,
  SIDEWALK: 0x344150,
  CURB: 0x465566,
  CYAN_EMISSIVE: 0x38e0ff,
  WHITE_EMISSIVE: 0xdcecff,
  PURPLE_ACCENT: 0xa78bfa,
  WARM_WINDOW: 0xffb877,
  AMBER_STATE: 0xffb244,
  RED_STATE: 0xff4a4a,
  FOLIAGE: 0x2f7a5c,
  FOLIAGE_DEEP: 0x236149,
} as const;

// Kept as bare consts too -- these three names are used heavily enough that
// PALETTE.GRAPHITE_METAL at every call site would only add noise.
export const GRAPHITE = PALETTE.GRAPHITE_METAL;
export const SILVER = PALETTE.STRUCTURAL_STEEL;
export const CONCRETE = PALETTE.CONCRETE;

type MatOpts = Partial<THREE.MeshStandardMaterialParameters>;

const materialCache = new Map<string, THREE.MeshStandardMaterial>();
const geometryCache = new Map<string, THREE.BufferGeometry>();

/** Materials whose emissiveIntensity is above this are treated as "live":
 *  CityScene registers them as a district's glow meshes and then MUTATES
 *  their emissive color and intensity every frame (ambient pulse) and on
 *  every backend state change (activity tint). Handing two districts the
 *  same instance would make one district's critical-red bleed into another,
 *  so anything at/above this threshold is always allocated fresh. */
const LIVE_EMISSIVE_THRESHOLD = 0.8;

function matKey(color: number, o: MatOpts): string {
  return [
    color, o.emissive ?? '', o.emissiveIntensity ?? '', o.roughness ?? '', o.metalness ?? '',
    o.transparent ?? '', o.opacity ?? '', o.side ?? '', o.depthWrite ?? '', o.flatShading ?? '',
  ].join('|');
}

/** Shared dark structural material. Cached by its full parameter set, so the
 *  several hundred slabs/columns/bodies a dense city builds collapse onto a
 *  couple of dozen material instances. */
export function structure(color: number, opts: MatOpts = {}): THREE.MeshStandardMaterial {
  return cachedMat(color, { metalness: 0.6, roughness: 0.55, ...opts });
}

/** Emissive accent material -- a ring, a strip, a visor line. Never a whole
 *  wall (state color is an accent, not a paint job). */
export function trim(accent: number, intensity = 1.2): THREE.MeshStandardMaterial {
  return cachedMat(accent, { color: accent, emissive: accent, emissiveIntensity: intensity });
}

function cachedMat(color: number, opts: MatOpts): THREE.MeshStandardMaterial {
  const params: MatOpts = { color, ...opts };
  if ((opts.emissiveIntensity ?? 0) >= LIVE_EMISSIVE_THRESHOLD) {
    // Runtime-mutated: must not be shared. See LIVE_EMISSIVE_THRESHOLD.
    return new THREE.MeshStandardMaterial(params);
  }
  const key = matKey(color, opts);
  let m = materialCache.get(key);
  if (!m) { m = new THREE.MeshStandardMaterial(params); materialCache.set(key, m); }
  return m;
}

function cachedGeo<T extends THREE.BufferGeometry>(key: string, make: () => T): T {
  let g = geometryCache.get(key) as T | undefined;
  if (!g) { g = make(); geometryCache.set(key, g); }
  return g;
}

/** Called from the scene's unmount path. The caches outlive any single
 *  component instance, so disposal has to be explicit -- CityScene's own
 *  scene.traverse() disposal would otherwise dispose a shared material that a
 *  remounted scene still expects to be alive. */
export function disposeKit(): void {
  for (const m of materialCache.values()) m.dispose();
  materialCache.clear();
  for (const g of geometryCache.values()) g.dispose();
  geometryCache.clear();
  spinningParts.length = 0;
}

/** Diagnostics for the material-sharing gate and the perf overlay. */
export function kitStats(): { materials: number; geometries: number } {
  return { materials: materialCache.size, geometries: geometryCache.size };
}

/* ==========================================================================
   2. PRIMITIVES
   ========================================================================== */

const UNIT_BOX = new THREE.BoxGeometry(1, 1, 1);
const UNIT_PLANE = new THREE.PlaneGeometry(1, 1);

/** A box sitting ON the ground (origin at its base), built from the ONE
 *  shared unit cube and scaled -- never a fresh BoxGeometry per call. */
export function box(w: number, h: number, d: number, material: THREE.Material): THREE.Mesh {
  const m = new THREE.Mesh(UNIT_BOX, material);
  m.scale.set(w, h, d);
  m.position.y = h / 2;
  return m;
}

/** A box centered on its own origin -- for limbs and parts hung off a pivot,
 *  where "sitting on the ground" is the wrong default. */
export function part(w: number, h: number, d: number, material: THREE.Material): THREE.Mesh {
  const m = new THREE.Mesh(UNIT_BOX, material);
  m.scale.set(w, h, d);
  return m;
}

/** A flat ground-plane quad (paving, road surface, lane marking). */
export function pad(w: number, d: number, material: THREE.Material, y = 0.02, rotY = 0): THREE.Mesh {
  const m = new THREE.Mesh(UNIT_PLANE, material);
  m.scale.set(w, d, 1);
  m.rotation.x = -Math.PI / 2;
  m.rotation.z = rotY;
  m.position.y = y;
  return m;
}

export function cylinder(rTop: number, rBottom: number, h: number, seg: number, material: THREE.Material): THREE.Mesh {
  return new THREE.Mesh(cachedGeo(`cyl:${rTop}:${rBottom}:${h}:${seg}`, () => new THREE.CylinderGeometry(rTop, rBottom, h, seg)), material);
}

export function torus(r: number, tube: number, rs: number, ts: number, material: THREE.Material): THREE.Mesh {
  return new THREE.Mesh(cachedGeo(`tor:${r}:${tube}:${rs}:${ts}`, () => new THREE.TorusGeometry(r, tube, rs, ts)), material);
}

export function sphere(r: number, w: number, h: number, material: THREE.Material): THREE.Mesh {
  return new THREE.Mesh(cachedGeo(`sph:${r}:${w}:${h}`, () => new THREE.SphereGeometry(r, w, h)), material);
}

/** Deterministic pseudo-random in [0,1) from an integer seed. Fixed per
 *  cell/prop, never re-rolled, so nothing in the city flickers or shuffles
 *  between frames ("no random flashing"). This is NOT a source of
 *  simulated activity -- it only varies static geometry. */
export function seeded01(seed: number): number {
  const x = Math.sin(seed * 12.9898) * 43758.5453;
  return x - Math.floor(x);
}

/** Canvas-texture text sprite. `color` is a full CSS color when supplied. */
export function createLabel(text: string, fontSize: number, bold: boolean, color?: string): THREE.Sprite {
  const canvas = document.createElement('canvas');
  canvas.width = 512;
  canvas.height = 128;
  const ctx = canvas.getContext('2d');
  if (ctx) {
    ctx.font = `${bold ? '800' : '600'} ${fontSize}px "Space Grotesk", "Segoe UI", system-ui, sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = color ?? 'rgba(232, 244, 255, 0.99)';
    ctx.fillText(text, canvas.width / 2, canvas.height / 2 + 2);
  }
  const texture = new THREE.CanvasTexture(canvas);
  texture.minFilter = THREE.LinearFilter;
  const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: texture, transparent: true, depthWrite: false, toneMapped: false }));
  sprite.scale.set(bold ? 10 : 8, bold ? 2.4 : 1.9, 1);
  return sprite;
}

/** Objects tagged here get a slow constant rotation from the scene's animate
 *  loop -- cosmetic infrastructure motion only (fans, antennas,
 *  halos). Nothing tagged here may imply an agent is working. */
export const spinningParts: { obj: THREE.Object3D; speed: number }[] = [];

/** One InstancedMesh from a list of placements, or null for an empty list.
 *  Every repeated city prop goes through this -- a street's worth of trees or
 *  bollards costs one draw call, not one per prop. */
export function instanceProps(
  geo: THREE.BufferGeometry,
  material: THREE.Material,
  placements: { x: number; y: number; z: number; ry?: number; s?: number }[],
): THREE.InstancedMesh | null {
  if (!placements.length) return null;
  const inst = new THREE.InstancedMesh(geo, material, placements.length);
  const dummy = new THREE.Object3D();
  placements.forEach((p, i) => {
    dummy.position.set(p.x, p.y, p.z);
    dummy.rotation.set(0, p.ry ?? 0, 0);
    const s = p.s ?? 1;
    dummy.scale.set(s, s, s);
    dummy.updateMatrix();
    inst.setMatrixAt(i, dummy.matrix);
  });
  inst.instanceMatrix.needsUpdate = true;
  return inst;
}

/* ==========================================================================
   3. MODULAR ARCHITECTURE KIT
   ========================================================================== */

/** A thin glowing ring flush to a drum's radius -- one crisp belt-course
 *  light line instead of a whole glowing surface. */
export function trimRing(radius: number, y: number, accent: number, tube = 0.07, intensity = 1.1): THREE.Mesh {
  const ring = torus(radius, tube, 6, 32, trim(accent, intensity));
  ring.rotation.x = Math.PI / 2;
  ring.position.y = y;
  return ring;
}

/** A recessed facade panel: dark structural frame, slightly inset lit inner
 *  face. Depth from two overlapping boxes rather than one flat tinted wall. */
export function facadePanel(w: number, h: number, depth: number, color: number, accent: number, glow = 0.08): THREE.Group {
  const g = new THREE.Group();
  g.add(box(w, h, depth, structure(PALETTE.DARK_COMPOSITE, { roughness: 0.7 })));
  const panel = box(w * 0.8, h * 0.82, depth * 0.5, structure(color, { emissive: accent, emissiveIntensity: glow }));
  panel.position.z = depth * 0.3;
  panel.position.y = h * 0.41;
  g.add(panel);
  return g;
}

const DARK_GLASS = new THREE.MeshStandardMaterial({ color: PALETTE.BLACK_GLASS, emissive: 0x0d1a22, emissiveIntensity: 0.22, roughness: 0.25, metalness: 0.35 });
const WARM_GLASS = new THREE.MeshStandardMaterial({ color: PALETTE.WARM_WINDOW, emissive: PALETTE.WARM_WINDOW, emissiveIntensity: 1.25 });
const COOL_GLASS = new THREE.MeshStandardMaterial({ color: 0x7fd2ea, emissive: 0x7fd2ea, emissiveIntensity: 0.85 });

/** A window band across one facade: one InstancedMesh of dark glass for every
 *  cell, plus two sparser seeded subsets re-drawn warm-lit and cool-lit --
 *  four draw calls at most, and never every window uniformly on.
 *  The lit/unlit choice is seeded and permanent, so nothing blinks. */
export function windowBand(w: number, h: number, cols: number, rows: number, seedBase: number): THREE.Group {
  const g = new THREE.Group();
  const cw = (w / cols) * 0.62, ch = (h / rows) * 0.58;
  const dummy = new THREE.Object3D();
  const base = new THREE.InstancedMesh(UNIT_BOX, DARK_GLASS, cols * rows);
  const warm: THREE.Vector3[] = [];
  const cool: THREE.Vector3[] = [];
  let i = 0;
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const px = -w / 2 + (c + 0.5) * (w / cols), py = (r + 0.5) * (h / rows);
      dummy.position.set(px, py, 0);
      dummy.scale.set(cw, ch, 0.08);
      dummy.updateMatrix();
      base.setMatrixAt(i, dummy.matrix);
      const roll = seeded01(r * 37 + c * 13 + seedBase);
      if (roll > 0.82) warm.push(new THREE.Vector3(px, py, 0.012));
      else if (roll < 0.1) cool.push(new THREE.Vector3(px, py, 0.012));
      i++;
    }
  }
  base.instanceMatrix.needsUpdate = true;
  g.add(base);
  for (const [slots, material] of [[warm, WARM_GLASS], [cool, COOL_GLASS]] as const) {
    if (!slots.length) continue;
    const lit = new THREE.InstancedMesh(UNIT_BOX, material, slots.length);
    slots.forEach((p, li) => {
      dummy.position.copy(p);
      dummy.scale.set(cw, ch, 0.09);
      dummy.updateMatrix();
      lit.setMatrixAt(li, dummy.matrix);
    });
    lit.instanceMatrix.needsUpdate = true;
    g.add(lit);
  }
  return g;
}

/** world scale: 1 unit = 1 metre, a floor is 3.3-3.7m. Every height
 *  in the city is derived from this, which is what stops buildings reading as
 *  toys of unrelated size. */
export const FLOOR_H = 3.4;
export const DOOR_H = 2.3;
export const ROBOT_H = 1.75;
/** Kerb height. Every raised pavement in the city -- block sidewalks and
 *  street sidewalks alike -- sits on this, so the two meet flush instead of
 *  stepping over each other at a block corner. */
export const KERB_H = 0.22;

/** The kit's workhorse: stacks `floors` real floor slabs -- slab, body, two
 *  windowed faces -- inside four continuous corner columns, capped with a
 *  roof and (optionally) a ground-floor entrance and a mounted sign. This is
 *  what makes every building read as having floors rather than being one
 *  undifferentiated extruded volume. */
export function buildTower(floors: number, w: number, d: number, accent: number, opts: {
  taper?: number;
  roof?: 'crown' | 'antenna' | 'halo' | 'flat' | 'equipment';
  signText?: string;
  windowed?: boolean;
  seed?: number;
  entrance?: boolean;
  fins?: boolean;
} = {}): THREE.Group {
  const g = new THREE.Group();
  const taper = opts.taper ?? 0;
  const totalH = Math.max(1, floors) * FLOOR_H;
  const windowed = opts.windowed ?? true;
  const seed = opts.seed ?? w * 7 + d * 3;

  const columnMat = structure(PALETTE.DARK_COMPOSITE, { emissive: accent, emissiveIntensity: 0.35, metalness: 0.7, roughness: 0.35 });
  ([[-1, -1], [1, -1], [-1, 1], [1, 1]] as const).forEach(([sx, sz]) => {
    const col = box(0.4, totalH + 0.3, 0.4, columnMat);
    col.position.set(sx * (w / 2 - 0.25), 0, sz * (d / 2 - 0.25));
    g.add(col);
  });

  const slabMat = structure(SILVER, { roughness: 0.5 });
  const bodyMat = structure(GRAPHITE, { roughness: 0.45 });
  let y = 0;
  for (let i = 0; i < floors; i++) {
    const t = floors > 1 ? i / (floors - 1) : 0;
    const fw = w * (1 - taper * t), fd = d * (1 - taper * t);
    const slab = box(fw, 0.28, fd, slabMat);
    slab.position.y = y;
    g.add(slab);
    const bodyH = FLOOR_H - 0.28;
    const body = box(fw * 0.97, bodyH, fd * 0.97, bodyMat);
    body.position.y = y + 0.28 + bodyH / 2;
    g.add(body);
    if (windowed && fw > 2.4 && !(i === 0 && opts.entrance)) {
      const cols = Math.max(2, Math.round(fw / 2.4));
      for (const [zSign, rot] of [[1, 0], [-1, Math.PI]] as const) {
        const band = windowBand(fw * 0.8, bodyH * 0.72, cols, 1, seed + i * 97 + (zSign > 0 ? 0 : 500));
        band.rotation.y = rot;
        band.position.set(0, y + 0.28 + bodyH * 0.56, zSign * fd / 2 * 0.985);
        g.add(band);
      }
      // Side elevations get a narrower band so the building doesn't read as
      // a flat billboard from a 45-degree isometric angle.
      if (fd > 4) {
        const sideCols = Math.max(2, Math.round(fd / 2.6));
        for (const [xSign, rot] of [[1, Math.PI / 2], [-1, -Math.PI / 2]] as const) {
          const band = windowBand(fd * 0.78, bodyH * 0.72, sideCols, 1, seed + i * 61 + (xSign > 0 ? 900 : 1300));
          band.rotation.y = rot;
          band.position.set(xSign * fw / 2 * 0.985, y + 0.28 + bodyH * 0.56, 0);
          g.add(band);
        }
      }
    }
    y += FLOOR_H;
  }

  if (opts.entrance) g.add(entrance(Math.min(w * 0.42, 5), accent, d / 2));

  if (opts.fins) {
    const finMat = structure(SILVER, { roughness: 0.4, metalness: 0.75 });
    for (let s = -1; s <= 1; s += 2) {
      const fin = box(0.35, totalH * 0.92, 1.1, finMat);
      fin.position.set(s * (w / 2 + 0.1), 0, 0);
      g.add(fin);
    }
  }

  // Roof.
  const roofSlab = box(w * (1 - taper) * 1.02, 0.35, d * (1 - taper) * 1.02, structure(SILVER, { roughness: 0.4 }));
  roofSlab.position.y = y;
  g.add(roofSlab);
  const rw = w * (1 - taper), rd = d * (1 - taper);
  const kind = opts.roof ?? 'flat';
  if (kind === 'crown') {
    const crown = new THREE.Mesh(cachedGeo(`cone:${Math.min(w, d)}`, () => new THREE.ConeGeometry(Math.min(w, d) * 0.32, 2.6, 8)), trim(accent, 1.6));
    crown.position.y = y + 1.6;
    g.add(crown);
  } else if (kind === 'halo') {
    const halo = torus(Math.min(w, d) * 0.32, 0.06, 8, 28, trim(accent, 1.3));
    halo.rotation.x = Math.PI / 2;
    halo.position.y = y + 0.6;
    g.add(halo);
    spinningParts.push({ obj: halo, speed: 0.05 });
  } else if (kind === 'antenna') {
    [-1, 1].forEach((sx) => {
      const a = roofAntenna(2.4, accent);
      a.position.set(sx * w * 0.22, y + 0.35, 0);
      g.add(a);
    });
  } else {
    g.add(roofEquipment(rw, rd, accent, y + 0.35, seed));
  }

  if (opts.signText) g.add(signPanel(opts.signText, accent, Math.max(y * 0.66, FLOOR_H * 1.4), d / 2 + 0.2));
  return g;
}

/** Rooftop plant: HVAC blocks, a vent stack and a slow-turning fan. Cosmetic
 *  infrastructure motion only. */
export function roofEquipment(w: number, d: number, accent: number, y: number, seed: number): THREE.Group {
  const g = new THREE.Group();
  const shell = structure(0x171d21, { roughness: 0.5, emissive: accent, emissiveIntensity: 0.12 });
  const units = w > 7 ? 3 : 2;
  for (let i = 0; i < units; i++) {
    const hv = box(1.1 + seeded01(seed + i) * 0.5, 0.65, 1.3, shell);
    hv.position.set(-w * 0.24 + (i * w * 0.48) / Math.max(1, units - 1), y, d * (seeded01(seed + i * 5) - 0.5) * 0.5);
    g.add(hv);
    const fan = cylinder(0.26, 0.26, 0.06, 8, structure(SILVER, { roughness: 0.4 }));
    fan.position.set(hv.position.x, y + 0.68, hv.position.z);
    g.add(fan);
    spinningParts.push({ obj: fan, speed: 0.6 + i * 0.15 });
  }
  const vent = cylinder(0.3, 0.36, 1.1, 8, shell);
  vent.position.set(w * 0.3, y + 0.55, -d * 0.28);
  g.add(vent);
  return g;
}

/** Mast + dish + beacon tip. */
export function roofAntenna(h: number, accent: number, ringed = true): THREE.Group {
  const g = new THREE.Group();
  const mast = cylinder(0.08, 0.11, h, 6, structure(0x171d21, { roughness: 0.4 }));
  mast.position.y = h / 2;
  g.add(mast);
  if (ringed) {
    const dish = torus(0.34, 0.035, 6, 16, trim(accent, 1.3));
    dish.rotation.x = 0.5;
    dish.position.y = h * 0.8;
    g.add(dish);
  }
  const tip = sphere(0.07, 8, 8, trim(accent, 1.8));
  tip.position.y = h;
  g.add(tip);
  return g;
}

/** A ground-floor entrance: recessed doorway at real door height, a canopy,
 *  and a light strip. This is the scale reference that tells a viewer how big
 *  the building actually is. */
export function entrance(width: number, accent: number, zFace: number): THREE.Group {
  const g = new THREE.Group();
  const recess = box(width, DOOR_H + 0.5, 0.5, structure(PALETTE.DARK_COMPOSITE, { roughness: 0.8 }));
  recess.position.set(0, 0, zFace - 0.1);
  g.add(recess);
  const door = box(width * 0.62, DOOR_H, 0.16, structure(0x0d181e, { emissive: PALETTE.WARM_WINDOW, emissiveIntensity: 0.45 }));
  door.position.set(0, 0, zFace + 0.16);
  g.add(door);
  const canopy = box(width + 1.2, 0.18, 1.5, structure(SILVER, { roughness: 0.45 }));
  canopy.position.set(0, DOOR_H + 0.55, zFace + 0.5);
  g.add(canopy);
  const strip = box(width + 1.0, 0.07, 0.07, trim(accent, 1.0));
  strip.position.set(0, DOOR_H + 0.5, zFace + 1.2);
  g.add(strip);
  return g;
}

/** An emissive sign mounted flat against a facade. */
export function signPanel(text: string, accent: number, y: number, z: number): THREE.Group {
  const g = new THREE.Group();
  const label = createLabel(text, 26, true, `#${accent.toString(16).padStart(6, '0')}`);
  label.scale.set(9, 2.2, 1);
  label.position.set(0, y, z + 0.06);
  g.add(label);
  const backing = box(9.4, 2.0, 0.14, structure(PALETTE.DARK_COMPOSITE, { roughness: 0.75 }));
  backing.position.set(0, y - 1.0, z);
  g.add(backing);
  return g;
}

/** N thin structural fins radiating from a center point. */
export function finRing(count: number, radius: number, h: number, w: number, depth: number, color: number, yOffset = 0): THREE.Group {
  const g = new THREE.Group();
  const m = structure(color, { roughness: 0.4, metalness: 0.75 });
  for (let i = 0; i < count; i++) {
    const a = (i / count) * Math.PI * 2;
    const fin = box(w, h, depth, m);
    fin.position.set(Math.sin(a) * radius, yOffset, Math.cos(a) * radius);
    fin.rotation.y = a;
    g.add(fin);
  }
  return g;
}

/** A ring of short bollard posts -- used sparingly, always instanced. */
export function bollardRing(count: number, radius: number, accent: number): THREE.InstancedMesh | null {
  const places = Array.from({ length: count }, (_, i) => {
    const a = (i / count) * Math.PI * 2;
    return { x: Math.sin(a) * radius, y: 0.35, z: Math.cos(a) * radius };
  });
  return instanceProps(cachedGeo('bollard', () => new THREE.CylinderGeometry(0.08, 0.09, 0.7, 6)), trim(accent, 0.9), places);
}

/** A wide matte paved plaza with one thin edge-light ring. */
export function plaza(radius: number, accent: number, y = 0.05): THREE.Group {
  const g = new THREE.Group();
  const floor = cylinder(radius, radius + 1, 0.5, 28, structure(0x0d1114, { roughness: 0.85, metalness: 0.2 }));
  floor.position.y = y;
  g.add(floor);
  g.add(trimRing(radius + 0.3, y + 0.28, accent, 0.05, 0.8));
  return g;
}

/* ==========================================================================
   4. CITY BLOCKS, STREET PROPS AND LANDSCAPING
   ========================================================================== */

/** The ground a building actually stands on: a paved block pad, a raised
 *  kerbed sidewalk around it, and a service apron. Without this every tower
 *  reads as an isolated object dropped on empty terrain, so the city reads as a coherent place. */
export function cityBlock(halfW: number, halfD: number, accent: number, ground = 0x1c2531): THREE.Group {
  const g = new THREE.Group();
  const sw = 2.0;   // sidewalk width, 1.5-2.5 units
  const kerb = KERB_H;

  // Kerb: a low slab slightly larger than the sidewalk, so the sidewalk
  // surface reads as raised above the asphalt rather than painted on it.
  const kerbSlab = box((halfW + sw) * 2 + 0.5, kerb, (halfD + sw) * 2 + 0.5, structure(PALETTE.CURB, { roughness: 0.9, metalness: 0.05 }));
  kerbSlab.position.y = 0;
  g.add(kerbSlab);

  g.add(pad((halfW + sw) * 2, (halfD + sw) * 2, structure(PALETTE.SIDEWALK, { roughness: 0.9, metalness: 0.05 }), kerb + 0.01));
  // The block's own paving carries its district's tint, so the district
  // reads as a coloured PLACE from above, not only as a lit building.
  g.add(pad(halfW * 2, halfD * 2, structure(ground, { roughness: 0.85, metalness: 0.1 }), kerb + 0.02));

  // Two thin light strips flush with the kerb line -- the block's own
  // perimeter lighting, bright enough to outline the district at city zoom.
  const stripMat = trim(accent, 1.1);
  for (const s of [-1, 1]) {
    const a = box((halfW + sw) * 2, 0.05, 0.08, stripMat);
    a.position.set(0, kerb, s * (halfD + sw));
    g.add(a);
    const b = box(0.08, 0.05, (halfD + sw) * 2, stripMat);
    b.position.set(s * (halfW + sw), kerb, 0);
    g.add(b);
  }
  return g;
}

const TREE_TRUNK = () => new THREE.CylinderGeometry(0.1, 0.14, 1.5, 5);
const TREE_CROWN = () => new THREE.ConeGeometry(0.95, 2.3, 6);
const BENCH_GEO = () => new THREE.BoxGeometry(1.6, 0.12, 0.5);
const PLANTER_GEO = () => new THREE.BoxGeometry(1.5, 0.5, 1.5);
const UTILITY_GEO = () => new THREE.BoxGeometry(0.8, 1.0, 0.6);
const LAMP_POST = () => new THREE.CylinderGeometry(0.06, 0.08, 4.6, 6);
const LAMP_HEAD = () => new THREE.BoxGeometry(0.45, 0.12, 0.3);

export interface Placement { x: number; y: number; z: number; ry?: number; s?: number }

/** Every repeated street prop in the city, emitted as one InstancedMesh per
 *  prop type. The caller collects placements while laying out blocks and
 *  calls this ONCE, so the whole city's street furniture costs about eight
 *  draw calls. */
export function buildStreetProps(sets: {
  trees?: Placement[]; benches?: Placement[]; planters?: Placement[];
  utility?: Placement[]; lamps?: Placement[]; bollards?: Placement[];
}): THREE.Group {
  const g = new THREE.Group();
  const add = (m: THREE.InstancedMesh | null) => { if (m) g.add(m); };

  if (sets.trees?.length) {
    add(instanceProps(cachedGeo('trunk', TREE_TRUNK), structure(0x1b1a16, { roughness: 0.95, metalness: 0 }),
      sets.trees.map((p) => ({ ...p, y: p.y + 0.75 }))));
    // Two stacked crowns at different scales read as stylized low-poly
    // foliage rather than a single cone-on-a-stick.
    add(instanceProps(cachedGeo('crown', TREE_CROWN), structure(PALETTE.FOLIAGE, { roughness: 0.95, metalness: 0, flatShading: true }),
      sets.trees.map((p) => ({ ...p, y: p.y + 2.3 }))));
    add(instanceProps(cachedGeo('crown', TREE_CROWN), structure(PALETTE.FOLIAGE_DEEP, { roughness: 0.95, metalness: 0, flatShading: true }),
      sets.trees.map((p) => ({ ...p, y: p.y + 3.3, s: (p.s ?? 1) * 0.62 }))));
  }
  if (sets.benches?.length) {
    add(instanceProps(cachedGeo('bench', BENCH_GEO), structure(0x1e262b, { roughness: 0.8 }),
      sets.benches.map((p) => ({ ...p, y: p.y + 0.45 }))));
  }
  if (sets.planters?.length) {
    add(instanceProps(cachedGeo('planter', PLANTER_GEO), structure(0x191f23, { roughness: 0.9 }),
      sets.planters.map((p) => ({ ...p, y: p.y + 0.25 }))));
    add(instanceProps(cachedGeo('crown', TREE_CROWN), structure(PALETTE.FOLIAGE_DEEP, { roughness: 0.95, flatShading: true }),
      sets.planters.map((p) => ({ ...p, y: p.y + 0.85, s: (p.s ?? 1) * 0.45 }))));
  }
  if (sets.utility?.length) {
    add(instanceProps(cachedGeo('utility', UTILITY_GEO), structure(0x161c20, { roughness: 0.75, emissive: PALETTE.CYAN_EMISSIVE, emissiveIntensity: 0.1 }),
      sets.utility.map((p) => ({ ...p, y: p.y + 0.5 }))));
  }
  if (sets.lamps?.length) {
    // Street lights at scale (4-6 units): post, arm-head, and a
    // small emissive lens. Three instanced meshes for the whole city.
    add(instanceProps(cachedGeo('lamppost', LAMP_POST), structure(0x171d21, { roughness: 0.6 }),
      sets.lamps.map((p) => ({ ...p, y: p.y + 2.3 }))));
    add(instanceProps(cachedGeo('lamphead', LAMP_HEAD), structure(0x1b2227, { roughness: 0.5 }),
      sets.lamps.map((p) => ({ ...p, y: p.y + 4.6 }))));
    add(instanceProps(cachedGeo('lamplens', () => new THREE.SphereGeometry(0.13, 8, 6)), trim(PALETTE.WHITE_EMISSIVE, 1.4),
      sets.lamps.map((p) => ({ ...p, y: p.y + 4.48 }))));
  }
  if (sets.bollards?.length) {
    add(instanceProps(cachedGeo('bollard', () => new THREE.CylinderGeometry(0.08, 0.09, 0.7, 6)), trim(PALETTE.CYAN_EMISSIVE, 0.7),
      sets.bollards.map((p) => ({ ...p, y: p.y + 0.35 }))));
  }
  return g;
}

/** Cheap background architecture: an arc of dark instanced blocks
 *  on the far side of the city only, well past the boundary. They are scenery
 *  -- nothing here is raycastable, labelled, or claimed to be an ARGUS
 *  building. Restricted to the far half-plane because an orthographic camera
 *  gives no size falloff, so a "distant" block placed on the NEAR side would
 *  render at full size in front of the city. */
export function distantSkyline(seed = 7): THREE.Group {
  const g = new THREE.Group();
  const places: Placement[] = [];
  const scales: number[] = [];
  for (let i = 0; i < 90; i++) {
    const a = seeded01(seed + i * 3.1) * Math.PI * 2;
    const r = 122 + seeded01(seed + i * 7.7) * 78;
    const x = Math.cos(a) * r, z = Math.sin(a) * r + 6;
    if (x + z > -80) continue; // near half-plane -- see the note above.
    places.push({ x, y: 0, z, ry: seeded01(seed + i * 11.3) * 0.9 });
    scales.push(10 + seeded01(seed + i * 5.5) * 36);
  }
  const dummy = new THREE.Object3D();
  const inst = new THREE.InstancedMesh(UNIT_BOX, structure(0x0f1828, { roughness: 1, metalness: 0 }), places.length);
  places.forEach((p, i) => {
    const h = scales[i];
    dummy.position.set(p.x, h / 2, p.z);
    dummy.rotation.set(0, p.ry ?? 0, 0);
    dummy.scale.set(7 + seeded01(seed + i) * 9, h, 7 + seeded01(seed + i * 2) * 9);
    dummy.updateMatrix();
    inst.setMatrixAt(i, dummy.matrix);
  });
  inst.instanceMatrix.needsUpdate = true;
  inst.userData.scenery = true;
  g.add(inst);
  return g;
}

/* ==========================================================================
   5. THE ARGUS MINI ROBOT
   ========================================================================== */

export type RobotPose = 'idle' | 'walk' | 'work' | 'think' | 'wait' | 'verify' | 'failed';

export interface Robot {
  group: THREE.Group;
  head: THREE.Group;
  torso: THREE.Mesh;
  /** Hip and shoulder pivots -- [left, right]. Limbs hang off these so a
   *  rotation at the joint swings the whole limb, no skinning required. */
  hips: [THREE.Group, THREE.Group];
  knees: [THREE.Group, THREE.Group];
  shoulders: [THREE.Group, THREE.Group];
  elbows: [THREE.Group, THREE.Group];
  /** The two emissive parts a caller may recolor to show REAL state. Always
   *  per-robot instances, never from the shared material cache. */
  visor: THREE.MeshStandardMaterial;
  core: THREE.MeshStandardMaterial;
  /** Fixed per-robot phase offset so a group of robots never moves in
   *  lockstep. Derived from the robot's own identity by the caller. */
  phase: number;
}

// Light armour plates over darker steel joints: under office lighting a
// graphite robot read as a black silhouette; a pale shell shows the pose
// (seated, typing, thinking) and lets the coloured visor carry the state.
const BODY_MAT = () => structure(0x9aa7b4, { roughness: 0.45, metalness: 0.55 });
const JOINT_MAT = () => structure(0x2e3640, { roughness: 0.45, metalness: 0.8 });
const PLATE_MAT = () => structure(0xd5dde6, { roughness: 0.35, metalness: 0.45 });

/** A compact armored ARGUS unit built from 16 boxes: helmet + visor strip,
 *  armored torso with a core light, shoulder plates, two-segment arms, two-
 *  segment legs, feet, and a back compute pack. ~1.75 units tall.
 *  Deliberately NOT a humanoid stick figure and NOT a cartoon -- the shape
 *  language is angular plate armor, and the ONLY colored parts are the visor
 *  line and the chest core (do not recolor the whole robot). */
export function buildRobot(accent: number, phase = 0): Robot {
  const group = new THREE.Group();
  const body = BODY_MAT(), joint = JOINT_MAT(), plate = PLATE_MAT();
  const visor = new THREE.MeshStandardMaterial({ color: accent, emissive: accent, emissiveIntensity: 1.5 });
  const core = new THREE.MeshStandardMaterial({ color: accent, emissive: accent, emissiveIntensity: 1.1 });

  // Torso + back pack.
  const torso = part(0.46, 0.52, 0.30, body);
  torso.position.y = 1.08;
  group.add(torso);
  const pelvis = part(0.38, 0.16, 0.26, joint);
  pelvis.position.y = 0.80;
  group.add(pelvis);
  const packMesh = part(0.30, 0.30, 0.14, plate);
  packMesh.position.set(0, 1.12, -0.20);
  group.add(packMesh);
  const coreMesh = part(0.11, 0.11, 0.05, core);
  coreMesh.position.set(0, 1.14, 0.16);
  group.add(coreMesh);

  // Head: angular helmet with a single thin visor line.
  const head = new THREE.Group();
  head.position.y = 1.44;
  group.add(head);
  const helmet = part(0.29, 0.25, 0.27, plate);
  helmet.position.y = 0.13;
  head.add(helmet);
  const visorMesh = part(0.25, 0.055, 0.03, visor);
  visorMesh.position.set(0, 0.14, 0.14);
  head.add(visorMesh);

  const hips: THREE.Group[] = [];
  const knees: THREE.Group[] = [];
  const shoulders: THREE.Group[] = [];
  const elbows: THREE.Group[] = [];

  for (const side of [-1, 1]) {
    // Leg: hip pivot -> thigh -> knee pivot -> shin -> foot.
    const hip = new THREE.Group();
    hip.position.set(side * 0.12, 0.78, 0);
    group.add(hip);
    const thigh = part(0.16, 0.40, 0.17, body);
    thigh.position.y = -0.20;
    hip.add(thigh);
    const knee = new THREE.Group();
    knee.position.y = -0.40;
    hip.add(knee);
    const shin = part(0.14, 0.36, 0.15, joint);
    shin.position.y = -0.18;
    knee.add(shin);
    const foot = part(0.16, 0.09, 0.26, plate);
    foot.position.set(0, -0.38, 0.04);
    knee.add(foot);
    hips.push(hip); knees.push(knee);

    // Arm: shoulder plate + shoulder pivot -> upper arm -> elbow -> forearm.
    const pauldron = part(0.15, 0.15, 0.23, plate);
    pauldron.position.set(side * 0.28, 1.26, 0);
    group.add(pauldron);
    const shoulder = new THREE.Group();
    shoulder.position.set(side * 0.27, 1.22, 0);
    group.add(shoulder);
    const upper = part(0.11, 0.28, 0.12, body);
    upper.position.y = -0.14;
    shoulder.add(upper);
    const elbow = new THREE.Group();
    elbow.position.y = -0.28;
    shoulder.add(elbow);
    const fore = part(0.10, 0.26, 0.11, joint);
    fore.position.y = -0.13;
    elbow.add(fore);
    shoulders.push(shoulder); elbows.push(elbow);
  }

  group.userData.robotHeight = ROBOT_H;
  return {
    group, head, torso,
    hips: hips as [THREE.Group, THREE.Group],
    knees: knees as [THREE.Group, THREE.Group],
    shoulders: shoulders as [THREE.Group, THREE.Group],
    elbows: elbows as [THREE.Group, THREE.Group],
    visor, core, phase,
  };
}

/** How far the whole robot drops when seated so its hips rest on a chair
 *  seat at cityInterior.SEAT_Y (hip pivot 0.78 standing -> ~0.54 seated). */
export const SEATED_DROP = -0.24;

/** Seated at a desk: thighs forward on the seat, shins down, hands to the
 *  keyboard when working, on the lap when idle. Same honesty rule as the
 *  standing poses -- `pose` comes from real backend state only. */
function poseSeated(r: Robot, pose: RobotPose, t: number): void {
  const p = r.phase;
  const [hipL, hipR] = r.hips;
  const [kneeL, kneeR] = r.knees;
  const [shL, shR] = r.shoulders;
  const [elL, elR] = r.elbows;
  hipL.rotation.x = -1.5; hipR.rotation.x = -1.5;
  kneeL.rotation.x = 1.45; kneeR.rotation.x = 1.45;
  r.group.position.y = SEATED_DROP;
  r.torso.rotation.y = 0;
  r.torso.scale.y = 1;
  switch (pose) {
    case 'work': {
      const s = t * 6 + p;
      shL.rotation.x = -0.95 + Math.sin(s) * 0.06;
      shR.rotation.x = -0.95 + Math.sin(s + 1.9) * 0.06;
      elL.rotation.x = -0.55; elR.rotation.x = -0.55;
      r.head.rotation.x = 0.12;
      r.head.rotation.y = Math.sin(t * 0.4 + p) * 0.12;
      break;
    }
    case 'think': {
      const s = t * 0.9 + p;
      shL.rotation.x = -0.35; shR.rotation.x = -1.35;
      elL.rotation.x = -0.9; elR.rotation.x = -1.6;       // hand toward the chin
      r.head.rotation.x = -0.05 + Math.sin(s * 0.7) * 0.05;
      r.head.rotation.y = Math.sin(s) * 0.35;
      break;
    }
    case 'failed': {
      shL.rotation.x = -0.3; shR.rotation.x = -0.3;
      elL.rotation.x = -0.5; elR.rotation.x = -0.5;
      r.head.rotation.x = 0.4; r.head.rotation.y = 0;
      break;
    }
    case 'wait': {
      shL.rotation.x = -0.45; shR.rotation.x = -0.45;
      elL.rotation.x = -0.7; elR.rotation.x = -0.7;
      r.head.rotation.x = 0; r.head.rotation.y = Math.sin(t * 0.5 + p) * 0.2;
      break;
    }
    default: {
      // idle: hands resting on the thighs, a slow breath, a glance around
      const s = t * 1.1 + p;
      shL.rotation.x = -0.55 + Math.sin(s) * 0.02; shR.rotation.x = -0.55 - Math.sin(s) * 0.02;
      elL.rotation.x = -0.75; elR.rotation.x = -0.75;
      r.torso.scale.y = 1 + Math.sin(s) * 0.012;
      r.head.rotation.x = 0.05;
      r.head.rotation.y = Math.sin(s * 0.33) * 0.35;
      break;
    }
  }
}

/** Procedural posing. Cheap trig on ~10 joints, no animation clips, no
 *  skinning, no per-frame allocation. The caller picks the pose from REAL
 *  backend state -- this function only draws whatever it is told. `seated`
 *  puts the robot on a chair (every pose but walking and verifying, which
 *  are done standing). */
export function poseRobot(r: Robot, pose: RobotPose, t: number, seated = false): void {
  if (seated && pose !== 'walk' && pose !== 'verify') { poseSeated(r, pose, t); return; }
  const p = r.phase;
  const [hipL, hipR] = r.hips;
  const [kneeL, kneeR] = r.knees;
  const [shL, shR] = r.shoulders;
  const [elL, elR] = r.elbows;

  switch (pose) {
    case 'walk': {
      // Leg swing with a counter-swinging arm and a small body bob; the knee
      // bends only on the forward half of the stride so the foot does not
      // scythe through the pavement.
      const s = t * 7.5 + p;
      const swing = Math.sin(s) * 0.62;
      hipL.rotation.x = swing;
      hipR.rotation.x = -swing;
      kneeL.rotation.x = -Math.max(0, Math.sin(s + 1.2)) * 0.85;
      kneeR.rotation.x = -Math.max(0, Math.sin(s + 1.2 + Math.PI)) * 0.85;
      shL.rotation.x = -swing * 0.55;
      shR.rotation.x = swing * 0.55;
      elL.rotation.x = -0.25 - Math.max(0, -swing) * 0.3;
      elR.rotation.x = -0.25 - Math.max(0, swing) * 0.3;
      r.group.position.y = Math.abs(Math.sin(s)) * 0.045;
      r.head.rotation.y = 0;
      r.torso.rotation.y = Math.sin(s) * 0.05;
      break;
    }
    case 'work': {
      // Standing at a terminal: arms forward and down, small typing motion,
      // head pitched toward the screen.
      const s = t * 5.5 + p;
      hipL.rotation.x = 0; hipR.rotation.x = 0;
      kneeL.rotation.x = 0; kneeR.rotation.x = 0;
      shL.rotation.x = -1.05 + Math.sin(s) * 0.07;
      shR.rotation.x = -1.05 + Math.sin(s + 1.7) * 0.07;
      elL.rotation.x = -0.75; elR.rotation.x = -0.75;
      r.group.position.y = 0;
      r.head.rotation.x = 0.22;
      r.head.rotation.y = 0;
      r.torso.rotation.y = 0;
      break;
    }
    case 'verify': {
      // One arm raised to a verification station, the other at rest.
      const s = t * 2.2 + p;
      hipL.rotation.x = 0; hipR.rotation.x = 0;
      kneeL.rotation.x = 0; kneeR.rotation.x = 0;
      shL.rotation.x = -0.15;
      shR.rotation.x = -1.6 + Math.sin(s) * 0.12;
      elL.rotation.x = -0.2; elR.rotation.x = -0.55;
      r.group.position.y = 0;
      r.head.rotation.x = 0.1;
      r.head.rotation.y = -0.3;
      r.torso.rotation.y = -0.15;
      break;
    }
    case 'think': {
      const s = t * 0.9 + p;
      hipL.rotation.x = 0; hipR.rotation.x = 0;
      kneeL.rotation.x = 0; kneeR.rotation.x = 0;
      shL.rotation.x = -0.12; shR.rotation.x = -0.12;
      elL.rotation.x = -0.35; elR.rotation.x = -0.35;
      r.group.position.y = 0;
      r.head.rotation.y = Math.sin(s) * 0.45;
      r.head.rotation.x = Math.sin(s * 0.7) * 0.08;
      r.torso.rotation.y = 0;
      break;
    }
    case 'failed': {
      // A controlled error posture -- head down, still. No flailing.
      hipL.rotation.x = 0; hipR.rotation.x = 0;
      kneeL.rotation.x = 0; kneeR.rotation.x = 0;
      shL.rotation.x = 0.1; shR.rotation.x = 0.1;
      elL.rotation.x = -0.1; elR.rotation.x = -0.1;
      r.group.position.y = 0;
      r.head.rotation.x = 0.38;
      r.head.rotation.y = 0;
      r.torso.rotation.y = 0;
      break;
    }
    case 'wait': {
      hipL.rotation.x = 0; hipR.rotation.x = 0;
      kneeL.rotation.x = 0; kneeR.rotation.x = 0;
      shL.rotation.x = -0.06; shR.rotation.x = -0.06;
      elL.rotation.x = -0.15; elR.rotation.x = -0.15;
      r.group.position.y = 0;
      r.head.rotation.set(0, 0, 0);
      r.torso.rotation.y = 0;
      break;
    }
    default: {
      // Idle: a slow breath in the torso and an occasional head turn.
      const s = t * 1.1 + p;
      hipL.rotation.x = 0; hipR.rotation.x = 0;
      kneeL.rotation.x = 0; kneeR.rotation.x = 0;
      shL.rotation.x = -0.05 + Math.sin(s) * 0.03;
      shR.rotation.x = -0.05 - Math.sin(s) * 0.03;
      elL.rotation.x = -0.12; elR.rotation.x = -0.12;
      r.group.position.y = 0;
      r.torso.scale.y = 1 + Math.sin(s) * 0.012;
      r.head.rotation.y = Math.sin(s * 0.33) * 0.3;
      r.head.rotation.x = 0;
      break;
    }
  }
}

/** Free a pooled/destroyed robot's own (non-cached) materials. Body, joint
 *  and plate materials are shared and are freed by disposeKit(). */
export function disposeRobot(r: Robot): void {
  r.visor.dispose();
  r.core.dispose();
  r.group.removeFromParent();
}
