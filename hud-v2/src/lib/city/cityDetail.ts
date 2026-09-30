/* ARGUS AI City -- the detail layer.
   ==========================================================================

   Pure geometry, like cityKit.ts: nothing here reads a store or knows what an
   agent is doing. It adds the small things that make a grid of blocks read as
   a lived-in city:

   - street furniture along every sidewalk: bins, hydrants, street-name signs,
     utility cabinets, transit shelters, charging posts and parking bays. The
     PLACEMENTS are a pure function of the street network (so the layout
     self-check can prove none lands on a carriageway or inside a building);
     the GEOMETRY is one InstancedMesh per part.
   - roof machinery (HVAC units, vents, antennas, solar panels) dropped onto
     scenery roofs by raycasting the loaded model, so nothing floats.
   - four procedural environment buildings the GLB set has no model for:
     an energy substation, a storage warehouse, a repair bay and a parking
     structure, each baked to one mesh per material.

   All of it is scenery: no districtId, never raycast for selection, no
   status, no telemetry. */

import * as THREE from 'three';
import {
  DISTRICTS, SCENERY, STREETS, INTERSECTIONS, streetRect, districtRect, plotRect, inside,
  type Street, type Rect,
} from './cityLayout';
import { structure, trim, box, instanceProps, seeded01, KERB_H, type Placement } from './cityKit';
import { mergeStatic } from './cityInterior';
import { parkedSlots } from './cityTraffic';

/* ==========================================================================
   1. STREET FURNITURE -- placements (pure) + instanced geometry
   ========================================================================== */

export interface DetailSets {
  bins: Placement[]; hydrants: Placement[]; signs: Placement[]; cabinets: Placement[];
  shelters: Placement[]; chargers: Placement[]; bays: Placement[];
}

/** Everything a prop must stay out of: every carriageway, every district
 *  block (with its sidewalk ring) and every scenery plot. */
export function keepOutRects(streets: Street[] = STREETS): Rect[] {
  return [
    ...streets.map((s, i) => streetRect(s, i)),
    ...DISTRICTS.filter((d) => d.kind !== 'gate').map((d) => districtRect(d, 0.6)),
    ...SCENERY.map((p) => plotRect(p, 0.4)),
  ];
}

function nearIntersection(x: number, z: number, margin: number): boolean {
  return INTERSECTIONS.some((it) => Math.abs(x - it.x) < it.size / 2 + margin
    && Math.abs(z - it.z) < it.size / 2 + margin);
}

/** Where every street prop goes. Deterministic; a function of the street
 *  network alone. A candidate that would stand on asphalt, inside a block or
 *  plot, or in an intersection's crossing zone is simply not placed. */
export function detailPlacements(streets: Street[] = STREETS): DetailSets {
  const out: DetailSets = { bins: [], hydrants: [], signs: [], cabinets: [], shelters: [], chargers: [], bays: [] };
  const blocked = keepOutRects(streets);
  const free = (x: number, z: number, r: number) =>
    !blocked.some((b) => inside(x - r, z, b) || inside(x + r, z, b) || inside(x, z - r, b) || inside(x, z + r, b));
  // Mid-block props also stay out of an intersection's crossing zone; the
  // corner props below are meant to stand there and use `free` alone.
  const push = (set: Placement[], p: Placement, r = 0.45) => {
    if (!nearIntersection(p.x, p.z, 2.2) && free(p.x, p.z, r)) set.push(p);
  };
  // A long, shallow prop (a transit shelter) tested on its own footprint:
  // `along` metres either way down the street, `across` toward the kerb.
  const pushLong = (set: Placement[], p: Placement, ux: number, uz: number, along: number, across: number) => {
    const corners = [[1, 1], [1, -1], [-1, 1], [-1, -1]].map(([a, c]) =>
      [p.x + ux * a * along - uz * c * across, p.z + uz * a * along + ux * c * across]);
    if (corners.every(([x, z]) => !nearIntersection(x, z, 2.2) && free(x, z, 0.05))) set.push(p);
  };

  streets.forEach((s, si) => {
    const dx = s.x2 - s.x1, dz = s.z2 - s.z1;
    const len = Math.hypot(dx, dz);
    if (len < 8) return;
    const ux = dx / len, uz = dz / len;
    const nx = -uz, nz = ux;                        // left-hand normal
    const at = (t: number, side: number, off: number) =>
      ({ x: s.x1 + ux * t * len + nx * side * off, z: s.z1 + uz * t * len + nz * side * off });
    // Facing the street from the sidewalk on `side`.
    const face = (side: number) => Math.atan2(-nx * side, -nz * side);
    const walk = s.width / 2 + 1.75;                // outer half of the sidewalk
    const kerb = s.width / 2 + 0.45;                // just behind the kerb line

    if (s.kind === 'service') {
      // Parking bays: a painted line either side of every slot a vehicle
      // actually parks in (Traffic's own parkedSlots), and charging posts on
      // the long south lanes for the working fleet.
      const lane = s.width / 2 - 1.2;
      for (const slot of parkedSlots(s)) {
        for (const d of [slot.s - 2.7, slot.s + 2.7]) {
          if (d < 0.5 || d > len - 0.5) continue;
          out.bays.push({ ...at(d / len, slot.side, lane), y: 0.05, ry: face(slot.side) });
        }
      }
      if (len > 40) {
        for (let d = 6; d < len - 4; d += 11) {
          const p = at(d / len, si % 2 ? 1 : -1, kerb);
          push(out.chargers, { ...p, y: KERB_H, ry: face(si % 2 ? 1 : -1) });
        }
      }
      return;
    }
    const nBins = Math.max(2, Math.floor(len / 16));
    for (let i = 0; i < nBins; i++) {
      const side = i % 2 ? 1 : -1;
      push(out.bins, { ...at((i + 0.3) / nBins, side, walk), y: KERB_H });
    }
    const nHyd = Math.max(1, Math.floor(len / 26));
    for (let i = 0; i < nHyd; i++) {
      push(out.hydrants, { ...at((i + 0.72) / nHyd, -1, kerb), y: KERB_H }, 0.3);
    }
    if (s.kind === 'avenue') {
      // Transit shelters for the shuttle line: two per avenue, far side from
      // the street lights, facing the carriageway.
      for (const t of [0.34, 0.68]) {
        pushLong(out.shelters, { ...at(t, -1, s.width / 2 + 1.5), y: KERB_H, ry: face(-1) }, ux, uz, 1.75, 0.8);
      }
    }
  });

  // One street-name sign and one utility cabinet per intersection corner.
  for (const it of INTERSECTIONS) {
    const o = it.size / 2 + 1.6;
    if (free(it.x + o, it.z + o, 0.2)) out.signs.push({ x: it.x + o, y: KERB_H, z: it.z + o, ry: Math.PI / 4 });
    if (free(it.x - o, it.z - o, 0.5)) out.cabinets.push({ x: it.x - o, y: KERB_H, z: it.z - o, ry: Math.PI / 4 });
  }
  return out;
}

/** A multi-part prop placed at each of `ps`: every part's local offset is
 *  rotated by the placement's yaw, then instanced. */
function parts(ps: Placement[], lx: number, ly: number, lz: number): Placement[] {
  return ps.map((p) => {
    const c = Math.cos(p.ry ?? 0), s = Math.sin(p.ry ?? 0);
    return { x: p.x + lx * c + lz * s, y: p.y + ly, z: p.z - lx * s + lz * c, ry: p.ry, s: p.s };
  });
}

const geoCache = new Map<string, THREE.BufferGeometry>();
function g(key: string, make: () => THREE.BufferGeometry): THREE.BufferGeometry {
  let x = geoCache.get(key);
  if (!x) { x = make(); geoCache.set(key, x); }
  return x;
}
const boxGeo = (w: number, h: number, d: number) => g(`b:${w}:${h}:${d}`, () => new THREE.BoxGeometry(w, h, d));
const cylGeo = (r: number, h: number, seg = 8) => g(`c:${r}:${h}:${seg}`, () => new THREE.CylinderGeometry(r, r, h, seg));

/** The whole city's street furniture as ~14 InstancedMeshes. */
export function buildDetailProps(sets: DetailSets): THREE.Group {
  const out = new THREE.Group();
  out.name = 'city-detail-props';
  out.userData.scenery = true;
  const add = (geo: THREE.BufferGeometry, mat: THREE.Material, ps: Placement[]) => {
    const m = instanceProps(geo, mat, ps);
    if (m) { m.userData.scenery = true; out.add(m); }
  };
  const metal = structure(0x3c4752, { roughness: 0.55, metalness: 0.5 });
  add(cylGeo(0.28, 0.82, 10), structure(0x2f5a4a, { roughness: 0.7 }), parts(sets.bins, 0, 0.41, 0));
  add(cylGeo(0.3, 0.06, 10), metal, parts(sets.bins, 0, 0.85, 0));
  add(cylGeo(0.14, 0.62, 8), structure(0xc23b3b, { roughness: 0.5 }), parts(sets.hydrants, 0, 0.31, 0));
  add(cylGeo(0.05, 3.1, 6), metal, parts(sets.signs, 0, 1.55, 0));
  add(boxGeo(1.25, 0.26, 0.04), trim(0x1f7a58, 0.35), parts(sets.signs, 0.5, 2.85, 0));
  add(boxGeo(0.04, 0.26, 1.25), trim(0x1f7a58, 0.35), parts(sets.signs, 0, 2.55, 0.5));
  add(boxGeo(0.8, 1.1, 0.5), structure(0x4b5a55, { roughness: 0.7 }), parts(sets.cabinets, 0, 0.55, 0));
  // Transit shelter: roof, glazed back, two posts, bench.
  add(boxGeo(3.4, 0.1, 1.5), structure(0xdfe6ee, { roughness: 0.4 }), parts(sets.shelters, 0, 2.5, 0));
  add(boxGeo(3.4, 2.0, 0.05), structure(0x9fd8ff, { roughness: 0.1, transparent: true, opacity: 0.35 }), parts(sets.shelters, 0, 1.4, -0.7));
  add(boxGeo(0.1, 2.4, 0.1), metal, [...parts(sets.shelters, -1.6, 1.25, -0.65), ...parts(sets.shelters, 1.6, 1.25, -0.65)]);
  add(boxGeo(2.4, 0.1, 0.45), structure(0x6b4e3a, { roughness: 0.7 }), parts(sets.shelters, 0, 0.5, -0.4));
  add(boxGeo(0.7, 0.3, 0.06), trim(0x38e0ff, 0.6), parts(sets.shelters, 1.2, 2.2, 0.72));
  // Charging post: body + a dim ring that never pulses (it implies nothing).
  add(boxGeo(0.34, 1.3, 0.26), structure(0xe8edf2, { roughness: 0.4 }), parts(sets.chargers, 0, 0.65, 0));
  add(boxGeo(0.26, 0.08, 0.02), trim(0x38e0ff, 0.55), parts(sets.chargers, 0, 1.05, 0.14));
  add(boxGeo(0.1, 0.02, 2.3), structure(0xd6dde4, { roughness: 0.8 }), sets.bays);
  return out;
}

/* ==========================================================================
   2. ROOF MACHINERY -- raycast onto the real roof, instanced
   ========================================================================== */

const ROOF_CAP = 220;

/** Instanced rooftop equipment with room for ROOF_CAP of each part; add()
 *  drops a deterministic set onto one loaded building. */
export class RoofKit {
  group = new THREE.Group();
  private hvac: THREE.InstancedMesh;
  private fan: THREE.InstancedMesh;
  private vent: THREE.InstancedMesh;
  private mast: THREE.InstancedMesh;
  private solar: THREE.InstancedMesh;
  private n = { hvac: 0, fan: 0, vent: 0, mast: 0, solar: 0 };
  private m = new THREE.Matrix4();
  private q = new THREE.Quaternion();
  private e = new THREE.Euler();
  private ray = new THREE.Raycaster();

  constructor() {
    this.group.name = 'city-roof-kit';
    this.group.userData.scenery = true;
    const mk = (geo: THREE.BufferGeometry, mat: THREE.Material) => {
      const im = new THREE.InstancedMesh(geo, mat, ROOF_CAP);
      im.count = 0;
      im.userData.scenery = true;
      im.frustumCulled = false;
      this.group.add(im);
      return im;
    };
    this.hvac = mk(boxGeo(2.2, 1.0, 1.5), structure(0xb9c2cb, { roughness: 0.45, metalness: 0.6 }));
    this.fan = mk(cylGeo(0.5, 0.08, 14), structure(0x2a3138, { roughness: 0.6 }));
    this.vent = mk(cylGeo(0.18, 1.3, 8), structure(0x8c969f, { roughness: 0.5, metalness: 0.6 }));
    this.mast = mk(cylGeo(0.05, 3.2, 5), structure(0x9aa5ae, { roughness: 0.5, metalness: 0.7 }));
    this.solar = mk(boxGeo(2.8, 0.08, 1.7), structure(0x1c3a66, { roughness: 0.25, metalness: 0.4 }));
  }

  private put(im: THREE.InstancedMesh, key: keyof RoofKit['n'], x: number, y: number, z: number, ry = 0, tilt = 0): void {
    if (this.n[key] >= ROOF_CAP) return;
    this.e.set(tilt, ry, 0);
    this.q.setFromEuler(this.e);
    this.m.compose(new THREE.Vector3(x, y, z), this.q, new THREE.Vector3(1, 1, 1));
    im.setMatrixAt(this.n[key]++, this.m);
    im.count = this.n[key];
    im.instanceMatrix.needsUpdate = true;
  }

  /** Probe the building's roof at a few deterministic points; wherever the
   *  probe lands on a flat roof, put a piece of equipment there. */
  add(root: THREE.Object3D, seed: number): number {
    root.updateMatrixWorld(true);
    const bb = new THREE.Box3().setFromObject(root);
    if (bb.isEmpty()) return 0;
    const sx = (bb.max.x - bb.min.x) * 0.32, sz = (bb.max.z - bb.min.z) * 0.32;
    const cx = (bb.max.x + bb.min.x) / 2, cz = (bb.max.z + bb.min.z) / 2;
    const kinds = ['hvac', 'hvac', 'vent', 'solar', 'mast', 'hvac'] as const;
    let placed = 0;
    for (let i = 0; i < kinds.length; i++) {
      const px = cx + (seeded01(seed * 13 + i * 7) * 2 - 1) * sx;
      const pz = cz + (seeded01(seed * 29 + i * 11) * 2 - 1) * sz;
      this.ray.set(new THREE.Vector3(px, bb.max.y + 5, pz), new THREE.Vector3(0, -1, 0));
      const hit = this.ray.intersectObject(root, true)[0];
      // A flat roof only (not a wall, not the ground, not a sloped canopy).
      if (!hit || !hit.face || hit.point.y < 3) continue;
      const n = hit.face.normal.clone().transformDirection(hit.object.matrixWorld);
      if (n.y < 0.92) continue;
      const y = hit.point.y, ry = seeded01(seed + i) > 0.5 ? 0 : Math.PI / 2;
      const k = kinds[i];
      if (k === 'hvac') {
        this.put(this.hvac, 'hvac', px, y + 0.5, pz, ry);
        this.put(this.fan, 'fan', px, y + 1.04, pz, ry);
      } else if (k === 'vent') {
        this.put(this.vent, 'vent', px, y + 0.65, pz);
        this.put(this.vent, 'vent', px + 0.6, y + 0.65, pz + 0.3);
      } else if (k === 'solar') {
        this.put(this.solar, 'solar', px, y + 0.5, pz, ry, -0.35);
      } else {
        this.put(this.mast, 'mast', px, y + 1.6, pz);
      }
      placed++;
    }
    return placed;
  }

  get count(): number {
    return Object.values(this.n).reduce((a, b) => a + b, 0);
  }
}

/* ==========================================================================
   2b. NEON ROOF TRIM -- the owner's reference city (2026-09-24) outlines
   every roofline in neon. One InstancedMesh for the whole city.
   ========================================================================== */

const TRIM_CAP = 560;       // ~60 roofs + ~35 plots, four bars each

export class NeonTrim {
  group = new THREE.Group();
  private bars: THREE.InstancedMesh;
  private n = 0;
  private m = new THREE.Matrix4();
  private c = new THREE.Color();

  constructor() {
    this.group.name = 'city-neon-trim';
    this.group.userData.scenery = true;
    this.bars = new THREE.InstancedMesh(boxGeo(1, 1, 1),
      new THREE.MeshBasicMaterial({ color: 0xffffff, toneMapped: false }), TRIM_CAP);
    this.bars.count = 0;
    this.bars.frustumCulled = false;
    this.group.add(this.bars);
  }

  /** The main roof of a loaded building: the highest level of upward-facing
   *  faces that covers a real share of its footprint. The very top vertex is
   *  often a mast or a fan, and a trim around THAT floats in mid-air. */
  static roofRect(root: THREE.Object3D): { y: number; x0: number; x1: number; z0: number; z1: number } | null {
    root.updateMatrixWorld(true);
    const bb = new THREE.Box3().setFromObject(root);
    if (bb.isEmpty()) return null;
    const faces: { y: number; area: number; x0: number; x1: number; z0: number; z1: number }[] = [];
    const a = new THREE.Vector3(), b = new THREE.Vector3(), c = new THREE.Vector3();
    const ab = new THREE.Vector3(), ac = new THREE.Vector3();
    root.traverse((o) => {
      const mesh = o as THREE.Mesh;
      if (!mesh.isMesh || (o as THREE.InstancedMesh).isInstancedMesh) return;
      const pos = mesh.geometry.getAttribute('position');
      const idx = mesh.geometry.index;
      const tris = idx ? idx.count / 3 : pos.count / 3;
      for (let t = 0; t < tris; t++) {
        const i0 = idx ? idx.getX(t * 3) : t * 3, i1 = idx ? idx.getX(t * 3 + 1) : t * 3 + 1, i2 = idx ? idx.getX(t * 3 + 2) : t * 3 + 2;
        a.fromBufferAttribute(pos, i0).applyMatrix4(mesh.matrixWorld);
        b.fromBufferAttribute(pos, i1).applyMatrix4(mesh.matrixWorld);
        c.fromBufferAttribute(pos, i2).applyMatrix4(mesh.matrixWorld);
        ab.subVectors(b, a).cross(ac.subVectors(c, a));
        const area = ab.length() / 2;
        if (area < 1e-4 || ab.y / (area * 2) < 0.95 || a.y < 2) continue;      // flat, facing up, not the ground
        faces.push({ y: (a.y + b.y + c.y) / 3, area,
          x0: Math.min(a.x, b.x, c.x), x1: Math.max(a.x, b.x, c.x), z0: Math.min(a.z, b.z, c.z), z1: Math.max(a.z, b.z, c.z) });
      }
    });
    faces.sort((p, q) => q.y - p.y);
    const need = 0.15 * (bb.max.x - bb.min.x) * (bb.max.z - bb.min.z);
    let sum = 0;
    const r = { y: 0, x0: Infinity, x1: -Infinity, z0: Infinity, z1: -Infinity };
    for (const f of faces) {
      sum += f.area;
      r.y = f.y;
      r.x0 = Math.min(r.x0, f.x0); r.x1 = Math.max(r.x1, f.x1);
      r.z0 = Math.min(r.z0, f.z0); r.z1 = Math.max(r.z1, f.z1);
      if (sum >= need) return r;
    }
    return null;
  }

  /** A neon rectangle at height `y`, bars `t` thick. */
  rect(r: { x0: number; x1: number; z0: number; z1: number }, y: number, color: number, t = 0.16): void {
    const cx = (r.x0 + r.x1) / 2, cz = (r.z0 + r.z1) / 2, w = r.x1 - r.x0 + t, d = r.z1 - r.z0 + t;
    for (const [x, z, sx, sz] of [[cx, r.z0, w, t], [cx, r.z1, w, t], [r.x0, cz, t, d], [r.x1, cz, t, d]]) {
      if (this.n >= TRIM_CAP) return;
      this.m.makeScale(sx, t, sz).setPosition(x, y, z);
      this.bars.setMatrixAt(this.n, this.m);
      this.bars.setColorAt(this.n, this.c.set(color));
      this.bars.count = ++this.n;
    }
    this.bars.instanceMatrix.needsUpdate = true;
    if (this.bars.instanceColor) this.bars.instanceColor.needsUpdate = true;
  }

  /** Outline a loaded building's roof in `color`. Returns false if it has
   *  no flat roof to outline (a dome, a canopy). */
  add(root: THREE.Object3D, color: number): boolean {
    const r = NeonTrim.roofRect(root);
    if (!r) return false;
    this.rect(r, r.y + 0.1, color);
    return true;
  }

  get count(): number { return this.n; }
}

/* ==========================================================================
   3. PROCEDURAL ENVIRONMENT BUILDINGS
   ========================================================================== */

const CONCRETE = () => structure(0x8a939c, { roughness: 0.85, metalness: 0.05 });
const STEEL = () => structure(0x6f7a85, { roughness: 0.5, metalness: 0.7 });
const DARK = () => structure(0x232b33, { roughness: 0.7, metalness: 0.2 });

function at(parent: THREE.Object3D, o: THREE.Object3D, x: number, y: number, z: number, ry = 0): THREE.Object3D {
  o.position.set(x, y + o.position.y, z);
  if (ry) o.rotation.y = ry;
  parent.add(o);
  return o;
}

/** A fenced yard: gantries, insulators, two transformers and a control house. */
function substation(): THREE.Group {
  const gp = new THREE.Group();
  at(gp, box(17, 0.12, 13, structure(0x5c5f52, { roughness: 0.95 })), 0, 0, 0);
  const fence = STEEL();
  for (const [w, d, x, z] of [[17, 0.06, 0, -6.5], [17, 0.06, 0, 6.5], [0.06, 13, -8.5, 0], [0.06, 13, 8.5, 0]] as const) {
    at(gp, box(w, 0.05, d, fence), x, 1.9, z);
    at(gp, box(w, 0.05, d, fence), x, 0.9, z);
  }
  for (let i = -8; i <= 8; i += 2) { at(gp, box(0.08, 2.1, 0.08, fence), i, 0, -6.5); at(gp, box(0.08, 2.1, 0.08, fence), i, 0, 6.5); }
  for (let i = -6; i <= 6; i += 2) { at(gp, box(0.08, 2.1, 0.08, fence), -8.5, 0, i); at(gp, box(0.08, 2.1, 0.08, fence), 8.5, 0, i); }
  const olive = structure(0x6d7a5c, { roughness: 0.6, metalness: 0.3 });
  for (const x of [-3.2, 1.6]) {
    at(gp, box(2.6, 2.3, 1.9, olive), x, 0, 1.6);
    for (let f = -1; f <= 1; f += 0.5) at(gp, box(0.06, 1.8, 2.3, olive), x + f, 0.2, 1.6);
    for (const ox of [-0.7, 0, 0.7]) {
      const ins = new THREE.Mesh(cylGeo(0.12, 0.9, 8), structure(0xc9b89a, { roughness: 0.4 }));
      at(gp, ins, x + ox, 2.75, 1.6);
    }
  }
  const gantry = STEEL();
  for (const x of [-6, 6]) for (const z of [-4, 4]) at(gp, box(0.3, 7, 0.3, gantry), x, 0, z);
  for (const z of [-4, 4]) at(gp, box(12.3, 0.3, 0.3, gantry), 0, 6.8, z);
  for (const x of [-6, 0, 6]) at(gp, box(0.3, 0.3, 8.3, gantry), x, 6.8, 0);
  at(gp, box(5, 3.2, 3.6, CONCRETE()), 5.2, 0, -3.6);
  at(gp, box(1.1, 2.1, 0.06, DARK()), 5.2, 0, -1.78);
  at(gp, box(5.1, 0.12, 0.08, trim(0xffb244, 0.6)), 5.2, 3.0, -1.76);
  at(gp, box(0.9, 0.6, 0.04, structure(0xf2c230, { roughness: 0.5 })), -2, 1.2, 6.55);
  return gp;
}

/** Long low shed, a sawtooth roof, three loading docks with pallets. */
function warehouse(): THREE.Group {
  const gp = new THREE.Group();
  const wall = structure(0x9aa3ab, { roughness: 0.75, metalness: 0.25 });
  at(gp, box(16, 5.6, 10, wall), 0, 0, -0.5);
  const roof = structure(0x5d6670, { roughness: 0.6, metalness: 0.4 });
  for (let i = 0; i < 4; i++) {
    const slab = box(16.2, 0.2, 2.9, roof);
    slab.rotation.x = -0.32;
    at(gp, slab, 0, 5.8, -4.2 + i * 2.6);
    at(gp, box(16.2, 0.9, 0.12, structure(0x9fd8ff, { roughness: 0.1, metalness: 0.2 })), 0, 5.8, -5.5 + i * 2.6);
  }
  const door = structure(0xc9cfd5, { roughness: 0.6, metalness: 0.3 });
  for (const x of [-5, 0, 5]) {
    at(gp, box(3.6, 3.4, 0.08, door), x, 0.9, 4.55);
    for (let y = 1.2; y < 4.2; y += 0.45) at(gp, box(3.6, 0.03, 0.1, DARK()), x, y, 4.58);
    at(gp, box(0.5, 0.14, 0.06, trim(0xffb244, 0.55)), x, 4.55, 4.62);
  }
  at(gp, box(16, 0.9, 2.2, CONCRETE()), 0, 0, 5.6);
  const wood = structure(0x9a7a52, { roughness: 0.85 });
  const crate = structure(0xb89a6a, { roughness: 0.8 });
  for (const [x, z] of [[-6.6, 6.1], [-3.4, 6.2], [3.6, 6.0], [6.8, 6.2]] as const) {
    at(gp, box(1.2, 0.14, 1.0, wood), x, 0.9, z);
    at(gp, box(1.0, 0.8, 0.9, crate), x, 1.04, z);
  }
  return gp;
}

/** A garage with three open service bays and a lift in one of them. */
function repairBay(): THREE.Group {
  const gp = new THREE.Group();
  const wall = structure(0xe4e8ec, { roughness: 0.6 });
  at(gp, box(15, 5.2, 9, wall), 0, 0, -1);
  const recess = DARK();
  for (const x of [-4.8, 0, 4.8]) {
    at(gp, box(3.8, 3.8, 0.4, recess), x, 0, 3.4);
    at(gp, box(4.1, 0.25, 0.3, STEEL()), x, 3.8, 3.6);
  }
  // A thin red/white band -- the only red here, a trade colour, not a state.
  for (let i = 0; i < 10; i++) {
    at(gp, box(1.5, 0.35, 0.06, structure(i % 2 ? 0xf0f0f0 : 0xc8323c, { roughness: 0.5 })), -6.75 + i * 1.5, 4.4, 3.56);
  }
  at(gp, box(0.2, 1.7, 2.6, STEEL()), -4.8, 0, 1.6);
  at(gp, box(2.2, 0.12, 2.8, STEEL()), -4.8, 1.6, 1.6);
  for (const x of [5.6, 6.3]) at(gp, box(0.6, 1.4, 0.5, structure(0xc8323c, { roughness: 0.5 })), x, 0, -4.9);
  at(gp, box(15.2, 0.3, 9.2, structure(0x5d6670, { roughness: 0.6 })), 0, 5.2, -1);
  return gp;
}

/** A four-deck parking structure with a ramp, edge walls and parked cars. */
function parkingStructure(): THREE.Group {
  const gp = new THREE.Group();
  const deck = CONCRETE();
  for (let lvl = 0; lvl < 4; lvl++) {
    const y = lvl * 3.1;
    at(gp, box(17, 0.35, 12.5, deck), 0, y, 0);
    if (lvl > 0) {
      for (const z of [-6.1, 6.1]) at(gp, box(17, 0.9, 0.2, deck), 0, y + 0.35, z);
      at(gp, box(0.2, 0.9, 12.5, deck), -8.4, y + 0.35, 0);
      at(gp, box(17.1, 0.1, 0.08, trim(0x38e0ff, 0.5)), 0, y + 1.3, 6.2);
    }
    for (const x of [-7.8, -2.6, 2.6, 7.8]) for (const z of [-5.6, 0, 5.6]) {
      if (lvl < 3) at(gp, box(0.45, 2.75, 0.45, deck), x, y + 0.35, z);
    }
    if (lvl > 0 && lvl < 4) {
      const paint = [0x2d5fa8, 0xe8eaed, 0x8e2530, 0x4a5058, 0xc9b28a];
      for (let c = 0; c < 4; c++) {
        const col = paint[(lvl * 3 + c) % paint.length];
        at(gp, box(1.8, 0.6, 4.1, structure(col, { roughness: 0.35, metalness: 0.5 })), -5.6 + c * 3.7, y + 0.35, -3.2);
        at(gp, box(1.5, 0.45, 2.1, structure(0x14202c, { roughness: 0.1, metalness: 0.6 })), -5.6 + c * 3.7, y + 0.95, -3.4);
      }
    }
  }
  const ramp = box(3.4, 0.3, 11, deck);
  ramp.rotation.x = -0.28;
  at(gp, ramp, 10.2, 1.2, 0);
  at(gp, box(3.4, 1.0, 1.4, structure(0x1f6f78, { roughness: 0.5 })), 10.2, 0, 6.2);
  return gp;
}

const BUILDERS: Record<string, () => THREE.Group> = {
  substation, warehouse, repair: repairBay, parking: parkingStructure,
};

/** A procedural environment building by kind (`proc:<kind>` in cityLayout),
 *  baked to one mesh per material. Null for an unknown kind. */
export function buildProcBuilding(kind: string): THREE.Group | null {
  const make = BUILDERS[kind];
  if (!make) return null;
  const gp = make();
  gp.userData.scenery = true;
  mergeStatic(gp);
  return gp;
}

export const PROC_KINDS = Object.keys(BUILDERS);

export function disposeDetail(): void {
  for (const x of geoCache.values()) x.dispose();
  geoCache.clear();
}
