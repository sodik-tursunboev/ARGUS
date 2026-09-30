/* ARGUS AI City -- office interiors: the furniture kit.
   ==========================================================================

   Pure geometry, like cityKit.ts: nothing here reads a store or knows what
   an agent is doing. CityScene decides who sits where and what their screen
   state means; this module only builds furniture that looks like a real
   office -- desks with dual monitors, keyboards and PC towers, office chairs
   with a five-star base, bookshelves with books, plants, a meeting table, a
   lounge, a water cooler, printers, server racks, glass partitions.

   Scale: 1 unit = 1 metre, matching the robots (1.75 m) -- a desk top is at
   0.74, a chair seat at 0.48, a monitor top at ~1.25.

   Cost: a furnished floor is hundreds of small parts. `mergeStatic` bakes a
   finished group's static meshes into ONE mesh per material, so ten
   workstations cost a few dozen draw calls rather than several hundred.
   Anything that must stay individually addressable (a screen whose colour
   reflects state, the robot) is tagged `userData.keep` and left alone. */

import * as THREE from 'three';
import { mergeGeometries } from 'three/examples/jsm/utils/BufferGeometryUtils.js';
import { seeded01, spinningParts } from './cityKit';

/* ---- materials (cached; interiors share them) ------------------------- */
const mats = new Map<string, THREE.Material>();
function mat(key: string, make: () => THREE.Material): THREE.Material {
  let m = mats.get(key);
  if (!m) { m = make(); mats.set(key, m); }
  return m;
}
const std = (key: string, color: number, roughness = 0.7, metalness = 0, extra: Partial<THREE.MeshStandardMaterialParameters> = {}) =>
  mat(key, () => new THREE.MeshStandardMaterial({ color, roughness, metalness, ...extra })) as THREE.MeshStandardMaterial;

export const OFFICE = {
  walnut: () => std('walnut', 0x7a5236, 0.55),
  oak: () => std('oak', 0xb48a5e, 0.6),
  laminate: () => std('laminate', 0xe4e7ea, 0.45),
  steel: () => std('steel', 0x9aa4ad, 0.35, 0.85),
  darkSteel: () => std('darksteel', 0x2c3238, 0.4, 0.8),
  plastic: () => std('plastic', 0x1a1d21, 0.5, 0.1),
  bezel: () => std('bezel', 0x0e1013, 0.35, 0.3),
  keycap: () => std('keycap', 0x2a2e33, 0.6),
  fabric: (color: number) => std(`fabric:${color}`, color, 0.9),
  leather: (color: number) => std(`leather:${color}`, color, 0.5, 0.05),
  wall: () => std('wall', 0xa7b0ba, 0.85),
  wallDark: () => std('walldark', 0x3b4450, 0.8),
  carpet: (color: number) => std(`carpet:${color}`, color, 0.97),
  wood: () => std('floorwood', 0x5e4432, 0.65),
  glass: () => mat('glass', () => new THREE.MeshStandardMaterial({
    color: 0x9fd8ff, roughness: 0.05, metalness: 0.1, transparent: true, opacity: 0.18,
    depthWrite: false })) as THREE.MeshStandardMaterial,
  leaf: () => std('leaf', 0x3f9160, 0.8),
  leafDark: () => std('leafdark', 0x2e7048, 0.85),
  pot: () => std('pot', 0xd6d2cc, 0.6),
  soil: () => std('soil', 0x3a2a1e, 1),
  paper: () => std('paper', 0xf2f2ee, 0.9),
  ceramic: () => std('ceramic', 0xf5f5f2, 0.3),
  water: () => mat('water', () => new THREE.MeshStandardMaterial({
    color: 0x7cc8ff, roughness: 0.1, transparent: true, opacity: 0.55 })) as THREE.MeshStandardMaterial,
  led: (color: number) => mat(`led:${color}`, () => new THREE.MeshBasicMaterial({ color, toneMapped: false })),
  window: () => mat('window', () => new THREE.MeshBasicMaterial({ map: nightWindowTexture(), toneMapped: false })),
};

/* ---- canvas textures: screens and the night view -------------------- */
const textures = new Map<string, THREE.CanvasTexture>();
/** Keys for one-off textures, so disposeInterior() still frees them. */
let texSeq = 0;

function hexCss(c: number): string { return `#${c.toString(16).padStart(6, '0')}`; }

/** A believable application screen in the agent's accent colour: title bar,
 *  side panel, chart, list rows. Cached per (accent, variant). */
export function screenTexture(accent: number, variant = 0): THREE.CanvasTexture {
  const key = `screen:${accent}:${variant % 4}`;
  const hit = textures.get(key);
  if (hit) return hit;
  const c = document.createElement('canvas');
  c.width = 256; c.height = 160;
  const g = c.getContext('2d');
  if (g) {
    const a = hexCss(accent);
    // Bright enough to read as a lit monitor across a dark office: a light
    // app window with an accent title bar, not a black rectangle.
    const bg = g.createLinearGradient(0, 0, 0, 160);
    bg.addColorStop(0, '#2a4468'); bg.addColorStop(1, '#16263f');
    g.fillStyle = bg; g.fillRect(0, 0, 256, 160);
    g.fillStyle = a; g.fillRect(0, 0, 256, 15);
    g.fillStyle = '#0d1626'; g.fillRect(8, 4, 60, 7);
    g.fillStyle = '#34507a'; g.fillRect(0, 15, 54, 145);
    for (let i = 0; i < 7; i++) {
      g.fillStyle = i === (variant % 7) ? a : '#6f8db8';
      g.fillRect(8, 26 + i * 17, 38, 7);
    }
    g.fillStyle = 'rgba(230, 240, 255, 0.10)'; g.fillRect(60, 20, 190, 134);
    if (variant % 4 === 0 || variant % 4 === 2) {
      g.strokeStyle = a; g.lineWidth = 2; g.beginPath();
      for (let x = 0; x <= 180; x += 12) {
        const y = 70 - Math.sin((x + variant * 30) / 22) * 22 - seeded01(x + variant) * 12;
        if (x === 0) g.moveTo(64 + x, y); else g.lineTo(64 + x, y);
      }
      g.stroke();
      for (let i = 0; i < 8; i++) {
        const h = 10 + seeded01(i * 7 + variant) * 34;
        g.fillStyle = i % 3 === 0 ? a : '#9fb8dc';
        g.fillRect(66 + i * 22, 150 - h, 14, h);
      }
    } else {
      for (let i = 0; i < 9; i++) {
        g.fillStyle = i % 4 === 0 ? a : '#a9bddb';
        g.fillRect(64, 24 + i * 14, 120 + seeded01(i + variant * 3) * 60, 8);
      }
      g.fillStyle = a; g.globalAlpha = 0.25; g.fillRect(64, 24 + (variant % 9) * 14 - 2, 186, 12);
      g.globalAlpha = 1;
    }
  }
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  t.anisotropy = 4;
  textures.set(key, t);
  return t;
}

/** A night skyline seen through the office glass: lit windows of the city
 *  outside. One shared texture for every window pane. */
function nightWindowTexture(): THREE.CanvasTexture {
  const hit = textures.get('night');
  if (hit) return hit;
  const c = document.createElement('canvas');
  c.width = 256; c.height = 128;
  const g = c.getContext('2d');
  if (g) {
    const grad = g.createLinearGradient(0, 0, 0, 128);
    grad.addColorStop(0, '#0c1a33'); grad.addColorStop(1, '#1d3354');
    g.fillStyle = grad; g.fillRect(0, 0, 256, 128);
    for (let b = 0; b < 14; b++) {
      const x = b * 19 + seeded01(b) * 6, w = 12 + seeded01(b * 3) * 10;
      const h = 40 + seeded01(b * 5) * 70;
      g.fillStyle = '#101a2a'; g.fillRect(x, 128 - h, w, h);
      for (let wy = 128 - h + 4; wy < 124; wy += 6) {
        for (let wx = x + 2; wx < x + w - 2; wx += 4) {
          if (seeded01(wx * 13 + wy * 7) > 0.55) {
            g.fillStyle = seeded01(wx + wy) > 0.8 ? '#8fd8ff' : '#ffcf8a';
            g.fillRect(wx, wy, 2, 3);
          }
        }
      }
    }
  }
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  textures.set('night', t);
  return t;
}

/* ---- primitives ------------------------------------------------------- */
const UNIT = new THREE.BoxGeometry(1, 1, 1);
const geos = new Map<string, THREE.BufferGeometry>();
function geo(key: string, make: () => THREE.BufferGeometry): THREE.BufferGeometry {
  let g = geos.get(key);
  if (!g) { g = make(); geos.set(key, g); }
  return g;
}

/** A box whose CENTRE is at (x, y, z). */
function blk(parent: THREE.Object3D, w: number, h: number, d: number, m: THREE.Material,
  x = 0, y = 0, z = 0): THREE.Mesh {
  const mesh = new THREE.Mesh(UNIT, m);
  mesh.scale.set(w, h, d);
  mesh.position.set(x, y, z);
  parent.add(mesh);
  return mesh;
}

function cyl(parent: THREE.Object3D, rt: number, rb: number, h: number, m: THREE.Material,
  x = 0, y = 0, z = 0, seg = 12): THREE.Mesh {
  const mesh = new THREE.Mesh(geo(`cyl:${rt}:${rb}:${h}:${seg}`, () => new THREE.CylinderGeometry(rt, rb, h, seg)), m);
  mesh.position.set(x, y, z);
  parent.add(mesh);
  return mesh;
}

/* ---- furniture -------------------------------------------------------- */

export const SEAT_Y = 0.48;
export const DESK_Y = 0.74;

/** Task chair, facing +z (a sitter's knees point +z). Five-star base with
 *  casters, gas lift, cushioned seat, curved backrest, armrests. */
export function officeChair(fabric = 0x2b3038): THREE.Group {
  const g = new THREE.Group();
  const cloth = OFFICE.fabric(fabric), metal = OFFICE.darkSteel(), plastic = OFFICE.plastic();
  for (let i = 0; i < 5; i++) {
    const a = (i / 5) * Math.PI * 2;
    const leg = blk(g, 0.05, 0.04, 0.3, metal, Math.sin(a) * 0.15, 0.07, Math.cos(a) * 0.15);
    leg.rotation.y = a;
    cyl(g, 0.028, 0.028, 0.04, plastic, Math.sin(a) * 0.29, 0.03, Math.cos(a) * 0.29, 8);
  }
  cyl(g, 0.03, 0.035, 0.34, metal, 0, 0.26, 0, 8);
  blk(g, 0.5, 0.08, 0.48, cloth, 0, SEAT_Y - 0.04, 0);
  const back = blk(g, 0.46, 0.52, 0.07, cloth, 0, SEAT_Y + 0.34, -0.23);
  back.rotation.x = 0.08;
  blk(g, 0.06, 0.28, 0.05, metal, 0, SEAT_Y + 0.08, -0.25);
  for (const s of [-1, 1]) {
    blk(g, 0.04, 0.2, 0.04, metal, s * 0.24, SEAT_Y + 0.1, -0.02);
    blk(g, 0.06, 0.03, 0.26, plastic, s * 0.24, SEAT_Y + 0.21, 0.02);
  }
  return g;
}

export interface DeskOpts {
  width?: number;
  accent?: number;
  variant?: number;
  top?: 'walnut' | 'oak' | 'laminate';
  monitors?: 1 | 2;
  lamp?: boolean;
}

/** Workstation desk. The sitter is on the +z side; monitors sit toward -z
 *  and face +z. Returns the group and the screen meshes (kept separate so a
 *  caller may dim or tint them to REAL state). */
export function workDesk(o: DeskOpts = {}): { group: THREE.Group; screens: THREE.Mesh[] } {
  const w = o.width ?? 1.6, d = 0.8;
  const accent = o.accent ?? 0x38e0ff;
  const g = new THREE.Group();
  const top = o.top === 'oak' ? OFFICE.oak() : o.top === 'laminate' ? OFFICE.laminate() : OFFICE.walnut();
  const metal = OFFICE.steel(), plastic = OFFICE.plastic(), bezel = OFFICE.bezel();
  blk(g, w, 0.04, d, top, 0, DESK_Y - 0.02, 0);
  for (const s of [-1, 1]) {
    blk(g, 0.05, DESK_Y - 0.04, 0.06, metal, s * (w / 2 - 0.08), (DESK_Y - 0.04) / 2, -d / 2 + 0.08);
    blk(g, 0.05, DESK_Y - 0.04, 0.06, metal, s * (w / 2 - 0.08), (DESK_Y - 0.04) / 2, d / 2 - 0.08);
    blk(g, 0.05, 0.04, d - 0.1, metal, s * (w / 2 - 0.08), 0.06, 0);
  }
  blk(g, w - 0.2, 0.34, 0.02, plastic, 0, DESK_Y - 0.25, -d / 2 + 0.06);
  // monitors
  const screens: THREE.Mesh[] = [];
  const n = o.monitors ?? 2;
  for (let i = 0; i < n; i++) {
    const x = n === 2 ? (i - 0.5) * 0.62 : 0;
    const yaw = n === 2 ? (i === 0 ? 0.18 : -0.18) : 0;
    const mon = new THREE.Group();
    mon.position.set(x, DESK_Y, -0.2);
    mon.rotation.y = yaw;
    g.add(mon);
    blk(mon, 0.22, 0.015, 0.16, bezel, 0, 0.008, 0);
    blk(mon, 0.04, 0.26, 0.03, bezel, 0, 0.14, -0.02);
    blk(mon, 0.6, 0.36, 0.03, bezel, 0, 0.42, 0);
    const scr = new THREE.Mesh(geo('plane:screen', () => new THREE.PlaneGeometry(0.56, 0.32)),
      new THREE.MeshBasicMaterial({ map: screenTexture(accent, (o.variant ?? 0) + i), toneMapped: false }));
    scr.position.set(0, 0.42, 0.016);
    scr.userData.keep = true;
    mon.add(scr);
    screens.push(scr);
  }
  // keyboard, mouse, tower, papers, mug
  blk(g, 0.44, 0.02, 0.14, plastic, 0, DESK_Y + 0.01, 0.17);
  blk(g, 0.41, 0.012, 0.11, OFFICE.keycap(), 0, DESK_Y + 0.026, 0.17);
  blk(g, 0.06, 0.025, 0.1, plastic, 0.32, DESK_Y + 0.012, 0.18);
  const tower = new THREE.Group();
  tower.position.set(w / 2 - 0.26, 0, -0.05);
  g.add(tower);
  blk(tower, 0.2, 0.44, 0.44, plastic, 0, 0.24, 0);
  blk(tower, 0.012, 0.3, 0.004, OFFICE.led(accent), -0.07, 0.3, 0.221);
  blk(g, 0.21, 0.004, 0.29, OFFICE.paper(), -w / 2 + 0.24, DESK_Y + 0.002, 0.12).rotation.y = 0.2;
  cyl(g, 0.04, 0.035, 0.1, OFFICE.ceramic(), -w / 2 + 0.3, DESK_Y + 0.05, -0.18, 10);
  if (o.lamp) {
    cyl(g, 0.07, 0.08, 0.02, OFFICE.darkSteel(), w / 2 - 0.2, DESK_Y + 0.01, -0.28, 10);
    const arm = blk(g, 0.02, 0.4, 0.02, OFFICE.darkSteel(), w / 2 - 0.2, DESK_Y + 0.2, -0.22);
    arm.rotation.x = 0.35;
    blk(g, 0.14, 0.04, 0.1, OFFICE.darkSteel(), w / 2 - 0.2, DESK_Y + 0.38, -0.12);
    blk(g, 0.11, 0.01, 0.07, OFFICE.led(0xfff1d6), w / 2 - 0.2, DESK_Y + 0.357, -0.12);
  }
  return { group: g, screens };
}

/** Bookcase with books of seeded colours and heights, and a few binders. */
export function bookshelf(w = 1.8, h = 2.0, seed = 1): THREE.Group {
  const g = new THREE.Group();
  const frame = OFFICE.oak();
  const d = 0.36;
  blk(g, 0.04, h, d, frame, -w / 2, h / 2, 0);
  blk(g, 0.04, h, d, frame, w / 2, h / 2, 0);
  blk(g, w, 0.03, d, frame, 0, h, 0);
  blk(g, w, 0.02, 0.02, frame, 0, h / 2, -d / 2);
  const back = blk(g, w, h, 0.02, OFFICE.wallDark(), 0, h / 2, -d / 2 + 0.01);
  back.userData.keepFlat = true;
  const shelves = 5;
  const colors = [0x9b2f35, 0x2f5f9b, 0x2f8a5c, 0xd9a441, 0x6a4c93, 0xe7e2d6, 0x1f2a36, 0xc0602f];
  for (let s = 0; s < shelves; s++) {
    const y = 0.05 + (s * (h - 0.1)) / shelves;
    blk(g, w - 0.04, 0.025, d, frame, 0, y, 0);
    let x = -w / 2 + 0.06;
    let k = 0;
    while (x < w / 2 - 0.1) {
      const r = seeded01(seed * 101 + s * 13 + k * 7);
      if (r < 0.08) { x += 0.12; k++; continue; }      // a gap on the shelf
      const bw = 0.03 + r * 0.04;
      const bh = (h / shelves) * (0.55 + seeded01(seed + s * 3 + k) * 0.35);
      const book = blk(g, bw, bh, d * 0.78, OFFICE.fabric(colors[Math.floor(r * 97) % colors.length]),
        x + bw / 2, y + 0.012 + bh / 2, 0.02);
      if (r > 0.93) book.rotation.z = 0.25;
      x += bw + 0.004;
      k++;
    }
  }
  return g;
}

/** Potted plant: ceramic pot, soil, layered leaves. */
export function plant(scale = 1, seed = 1): THREE.Group {
  const g = new THREE.Group();
  cyl(g, 0.2, 0.15, 0.38, OFFICE.pot(), 0, 0.19, 0, 14);
  cyl(g, 0.18, 0.18, 0.02, OFFICE.soil(), 0, 0.37, 0, 14);
  const leaves = [OFFICE.leaf(), OFFICE.leafDark()];
  for (let i = 0; i < 7; i++) {
    const a = (i / 7) * Math.PI * 2 + seeded01(seed + i) * 0.4;
    const len = 0.45 + seeded01(seed * 3 + i) * 0.35;
    const leaf = new THREE.Mesh(geo('leaf', () => new THREE.ConeGeometry(0.09, 1, 5)), leaves[i % 2]);
    leaf.scale.set(1, len, 0.45);
    leaf.position.set(Math.sin(a) * 0.1, 0.38 + len * 0.45, Math.cos(a) * 0.1);
    leaf.rotation.set(Math.cos(a) * 0.55, 0, -Math.sin(a) * 0.55);
    g.add(leaf);
  }
  const bush = new THREE.Mesh(geo('bush', () => new THREE.IcosahedronGeometry(0.22, 0)), leaves[0]);
  bush.position.y = 0.62;
  g.add(bush);
  g.scale.setScalar(scale);
  return g;
}

export function meetingTable(w = 3.2, d = 1.3, chairColor = 0x2b3038): THREE.Group {
  const g = new THREE.Group();
  blk(g, w, 0.05, d, OFFICE.walnut(), 0, DESK_Y - 0.025, 0);
  cyl(g, 0.08, 0.1, DESK_Y - 0.05, OFFICE.steel(), -w / 3, (DESK_Y - 0.05) / 2, 0, 10);
  cyl(g, 0.08, 0.1, DESK_Y - 0.05, OFFICE.steel(), w / 3, (DESK_Y - 0.05) / 2, 0, 10);
  blk(g, w * 0.8, 0.03, 0.5, OFFICE.steel(), 0, 0.02, 0);
  const per = Math.max(1, Math.round(w / 1.05));
  for (let i = 0; i < per; i++) {
    const x = (i - (per - 1) / 2) * (w / per);
    for (const s of [-1, 1]) {
      const c = officeChair(chairColor);
      c.position.set(x, 0, s * (d / 2 + 0.38));
      c.rotation.y = s > 0 ? Math.PI : 0;
      g.add(c);
    }
  }
  cyl(g, 0.12, 0.12, 0.05, OFFICE.darkSteel(), 0, DESK_Y + 0.025, 0, 16);
  return g;
}

export function sofa(w = 2.2, color = 0x3b556e): THREE.Group {
  const g = new THREE.Group();
  const cloth = OFFICE.fabric(color);
  blk(g, w, 0.22, 0.9, cloth, 0, 0.24, 0);
  blk(g, w, 0.16, 0.8, OFFICE.fabric(color + 0x080808), 0, 0.43, 0.04);
  blk(g, w, 0.55, 0.2, cloth, 0, 0.62, -0.36);
  for (const s of [-1, 1]) blk(g, 0.18, 0.45, 0.9, cloth, s * (w / 2 - 0.09), 0.45, 0);
  for (const s of [-1, 1]) for (const t of [-1, 1]) blk(g, 0.05, 0.13, 0.05, OFFICE.darkSteel(), s * (w / 2 - 0.1), 0.065, t * 0.35);
  return g;
}

export function coffeeTable(): THREE.Group {
  const g = new THREE.Group();
  blk(g, 1.1, 0.04, 0.6, OFFICE.oak(), 0, 0.42, 0);
  for (const s of [-1, 1]) for (const t of [-1, 1]) blk(g, 0.04, 0.4, 0.04, OFFICE.darkSteel(), s * 0.5, 0.2, t * 0.25);
  blk(g, 0.3, 0.02, 0.22, OFFICE.paper(), -0.2, 0.45, 0.05);
  cyl(g, 0.04, 0.035, 0.1, OFFICE.ceramic(), 0.25, 0.49, -0.05, 10);
  return g;
}

export function waterCooler(): THREE.Group {
  const g = new THREE.Group();
  blk(g, 0.34, 1.0, 0.34, OFFICE.laminate(), 0, 0.5, 0);
  cyl(g, 0.15, 0.15, 0.42, OFFICE.water(), 0, 1.22, 0, 14);
  blk(g, 0.1, 0.06, 0.05, OFFICE.led(0x38a8ff), -0.06, 0.82, 0.18);
  blk(g, 0.1, 0.06, 0.05, OFFICE.led(0xff6b5a), 0.06, 0.82, 0.18);
  return g;
}

export function coffeeMachine(): THREE.Group {
  const g = new THREE.Group();
  blk(g, 1.2, 0.9, 0.6, OFFICE.laminate(), 0, 0.45, 0);
  blk(g, 0.4, 0.45, 0.35, OFFICE.darkSteel(), -0.2, 1.12, 0);
  blk(g, 0.12, 0.05, 0.02, OFFICE.led(0x7fe9ff), -0.2, 1.22, 0.18);
  cyl(g, 0.04, 0.035, 0.1, OFFICE.ceramic(), 0.25, 0.95, 0.05, 10);
  cyl(g, 0.04, 0.035, 0.1, OFFICE.ceramic(), 0.38, 0.95, -0.05, 10);
  return g;
}

export function printer(): THREE.Group {
  const g = new THREE.Group();
  blk(g, 0.7, 0.7, 0.55, OFFICE.laminate(), 0, 0.35, 0);
  blk(g, 0.62, 0.28, 0.5, OFFICE.plastic(), 0, 0.84, 0);
  blk(g, 0.4, 0.02, 0.3, OFFICE.paper(), 0, 1.0, 0.05);
  blk(g, 0.14, 0.06, 0.02, OFFICE.led(0x4ade9e), 0.2, 0.9, 0.26);
  return g;
}

export function filingCabinet(): THREE.Group {
  const g = new THREE.Group();
  blk(g, 0.5, 1.3, 0.6, OFFICE.steel(), 0, 0.65, 0);
  for (let i = 0; i < 4; i++) blk(g, 0.16, 0.03, 0.03, OFFICE.darkSteel(), 0, 0.2 + i * 0.31, 0.31);
  return g;
}

export function serverRack(accent = 0x38e0ff, seed = 1): THREE.Group {
  const g = new THREE.Group();
  blk(g, 0.62, 2.0, 0.9, OFFICE.plastic(), 0, 1.0, 0);
  for (let u = 0; u < 12; u++) {
    blk(g, 0.54, 0.1, 0.02, OFFICE.darkSteel(), 0, 0.25 + u * 0.14, 0.455);
    for (let l = 0; l < 3; l++) {
      if (seeded01(seed * 31 + u * 7 + l) > 0.45) {
        blk(g, 0.03, 0.02, 0.01, OFFICE.led(l === 0 && seeded01(seed + u) > 0.7 ? 0x4ade9e : accent),
          -0.2 + l * 0.05, 0.25 + u * 0.14, 0.467);
      }
    }
  }
  return g;
}

export function whiteboard(w = 2.2, h = 1.1): THREE.Group {
  const g = new THREE.Group();
  blk(g, w, h, 0.04, OFFICE.laminate(), 0, 1.0 + h / 2, 0);
  blk(g, w + 0.06, 0.05, 0.06, OFFICE.steel(), 0, 1.0, 0.02);
  const marks = [0x2f5f9b, 0x9b2f35, 0x2f8a5c];
  for (let i = 0; i < 6; i++) {
    blk(g, 0.3 + seeded01(i) * 0.6, 0.02, 0.005, OFFICE.fabric(marks[i % 3]),
      -w / 2 + 0.5 + seeded01(i * 3) * (w - 1), 1.15 + i * 0.13, 0.025);
  }
  return g;
}

/** A glass partition with a slim metal frame -- the Manager's office walls. */
export function glassWall(w: number, h = 2.4): THREE.Group {
  const g = new THREE.Group();
  const pane = blk(g, w, h, 0.02, OFFICE.glass(), 0, h / 2, 0);
  pane.userData.keep = true;               // transparent: never merged
  pane.renderOrder = 3;
  blk(g, w, 0.05, 0.06, OFFICE.darkSteel(), 0, h, 0);
  blk(g, w, 0.05, 0.06, OFFICE.darkSteel(), 0, 0.025, 0);
  for (const s of [-1, 1]) blk(g, 0.05, h, 0.06, OFFICE.darkSteel(), s * w / 2, h / 2, 0);
  return g;
}

export function rug(w: number, d: number, color: number): THREE.Mesh {
  const m = new THREE.Mesh(geo('plane:unit', () => new THREE.PlaneGeometry(1, 1)), OFFICE.carpet(color));
  m.scale.set(w, d, 1);
  m.rotation.x = -Math.PI / 2;
  m.position.y = 0.012;
  return m;
}

/** A wall-mounted display whose texture the caller owns (live numbers). */
export function wallDisplay(w: number, h: number, texture: THREE.Texture): THREE.Group {
  const g = new THREE.Group();
  blk(g, w + 0.08, h + 0.08, 0.06, OFFICE.bezel(), 0, 0, 0);
  const s = new THREE.Mesh(new THREE.PlaneGeometry(w, h), new THREE.MeshBasicMaterial({ map: texture, toneMapped: false }));
  s.position.z = 0.032;
  s.userData.keep = true;
  s.userData.ownGeometry = true;
  g.add(s);
  return g;
}

/* ---- a CLOSED building, cut away toward the camera ---------------------
   The owner (2026-09-24): the classroom and the HQ "must be closed, now there
   is no roof". So every interior is a real box -- four walls and a roof --
   and the view cuts it open the way a dollhouse game does: a wall between
   the camera and the room drops to a low neon-capped lip, the other walls
   stand full height with windows onto the night city, and the roof is there
   whenever you pull back far enough to see the building whole. Zoom in and
   it lifts off. `updateCutaway` re-decides this every frame, so orbiting
   round the room always cuts the side you are looking through. */

/** Tall enough for a neon sign between the window band and the ceiling. */
export const WALL_H = 3.8;
/** Zoom (view half-height) where the roof is fully off / fully on. */
const ROOF_OPEN = 24, ROOF_SHUT = 32;

export interface Cutaway {
  walls: { full: THREE.Object3D; stub: THREE.Object3D; nx: number; nz: number }[];
  roof: THREE.Object3D;
  roofMats: { m: THREE.Material; base: number }[];
  /** 0 = open (cut away), 1 = closed. Last value applied. */
  closed: number;
}

export interface ShellOpts {
  x0: number; x1: number; z0: number; z1: number;
  /** Neon along the wall tops and the roof edge; `trim` along the skirting. */
  accent: number; trim: number;
  wall: number;
  /** Floor tiles: base and grout colours. Omit for no floor (the caller has one). */
  floor?: [string, string];
  /** Pendant lamps stop short of this x (the HQ's lift core and restrooms
   *  are solid to the ceiling). */
  lampX1?: number;
  /** The lit name sign standing on the roof. */
  name?: string;
}

/** Dark floor tiles with lit grout lines -- the reference city's interiors. */
function tileTexture(base: string, line: string, repX: number, repZ: number): THREE.CanvasTexture {
  const src = textures.get(`tile:${base}:${line}`) ?? (() => {
    const c = document.createElement('canvas');
    c.width = c.height = 128;
    const g = c.getContext('2d');
    if (g) {
      g.fillStyle = base; g.fillRect(0, 0, 128, 128);
      g.fillStyle = 'rgba(255,255,255,0.035)'; g.fillRect(0, 0, 64, 64); g.fillRect(64, 64, 64, 64);
      g.strokeStyle = line; g.lineWidth = 2;
      g.strokeRect(1, 1, 126, 126);
      g.beginPath(); g.moveTo(64, 0); g.lineTo(64, 128); g.moveTo(0, 64); g.lineTo(128, 64); g.stroke();
    }
    const t = new THREE.CanvasTexture(c);
    t.colorSpace = THREE.SRGBColorSpace;
    textures.set(`tile:${base}:${line}`, t);
    return t;
  })();
  const t = src.clone();                     // own repeat, shared image
  t.wrapS = t.wrapT = THREE.RepeatWrapping;
  t.repeat.set(repX, repZ);
  t.needsUpdate = true;
  textures.set(`tile:${base}:${line}:${repX}:${repZ}`, t);
  return t;
}

/** The night city through a window band `len` metres long. */
function windowBand(len: number, h: number): THREE.Mesh {
  const t = nightWindowTexture().clone();
  t.wrapS = THREE.RepeatWrapping;
  t.repeat.set(len / 5, 1);
  t.needsUpdate = true;
  textures.set(`night:${++texSeq}`, t);
  const m = new THREE.Mesh(new THREE.PlaneGeometry(len, h), new THREE.MeshBasicMaterial({ map: t, toneMapped: false }));
  m.userData.keep = true;
  m.userData.ownGeometry = true;
  return m;
}

export function closedShell(o: ShellOpts): { group: THREE.Group; cut: Cutaway } {
  const g = new THREE.Group();
  g.name = 'closed-shell';
  const H = WALL_H, T = 0.3;
  const W = o.x1 - o.x0, D = o.z1 - o.z0, cx = (o.x0 + o.x1) / 2, cz = (o.z0 + o.z1) / 2;
  if (o.floor) {
    const floor = new THREE.Mesh(new THREE.PlaneGeometry(W, D),
      new THREE.MeshStandardMaterial({ map: tileTexture(o.floor[0], o.floor[1], W / 3, D / 3), roughness: 0.55, metalness: 0.15 }));
    floor.rotation.x = -PI / 2;
    floor.position.set(cx, 0, cz);
    floor.userData.keep = true;
    floor.userData.ownGeometry = true;
    g.add(floor);
  }
  const wallMat = std(`shellwall:${o.wall}`, o.wall, 0.8, 0.1);
  const neon = OFFICE.led(o.accent), skirt = OFFICE.led(o.trim);
  const outerLit = OFFICE.led(0xffcf8a);
  const walls: Cutaway['walls'] = [];
  // Each side: outward normal, the centre of its line, and its length.
  for (const [nx, nz, len] of [[0, -1, W], [0, 1, W], [-1, 0, D], [1, 0, D]] as const) {
    const px = nx ? (nx < 0 ? o.x0 : o.x1) + nx * T / 2 : cx;
    const pz = nz ? (nz < 0 ? o.z0 : o.z1) + nz * T / 2 : cz;
    const side = new THREE.Group();
    side.position.set(px, 0, pz);
    side.rotation.y = nx ? -nx * PI / 2 : nz > 0 ? PI : 0;     // local -z = outward
    g.add(side);
    // Local frame: the wall runs along x, the room is at +z.
    const full = new THREE.Group();
    blk(full, len + T * 2, H, T, wallMat, 0, H / 2, 0);
    blk(full, len, 0.05, 0.04, neon, 0, H - 0.12, T / 2 + 0.02);          // inner top neon
    blk(full, len, 0.05, 0.04, skirt, 0, 0.07, T / 2 + 0.02);             // inner skirting neon
    blk(full, len + T * 2, 0.07, 0.05, neon, 0, H - 0.04, -T / 2 - 0.03);  // outer cornice neon
    blk(full, len * 0.86, 1.1, 0.02, outerLit, 0, 1.9, -T / 2 - 0.012);   // lit windows, outside
    for (let x = -len * 0.43; x <= len * 0.43 + 0.01; x += 1.6) {
      blk(full, 0.09, 1.18, 0.05, OFFICE.darkSteel(), x, 1.9, -T / 2 - 0.03);
      blk(full, 0.06, 1.62, 0.05, OFFICE.darkSteel(), x, 1.95, T / 2 + 0.03);
    }
    mergeStatic(full);
    const band = windowBand(len * 0.86, 1.55);                           // the view, inside
    band.position.set(0, 1.95, T / 2 + 0.012);
    full.add(band);
    const stub = new THREE.Group();
    blk(stub, len + T * 2, 0.45, T, wallMat, 0, 0.225, 0);
    blk(stub, len + T * 2, 0.05, T + 0.04, neon, 0, 0.47, 0);
    mergeStatic(stub);
    side.add(full, stub);
    walls.push({ full, stub, nx, nz });
  }

  // Ceiling rails with light strips and pendant lamps (always there -- they
  // are what make the open view still read as a room with a ceiling).
  const ceiling = new THREE.Group();
  // Seen from above a dark shade is a black dot on the floor, so the shades
  // glow: from this camera a lamp has to read as a lamp.
  const rail = OFFICE.darkSteel(), glow = OFFICE.led(0xfff4e0), shade = OFFICE.led(0xffd9a0);
  for (let z = o.z0 + 5; z < o.z1 - 3; z += 8) {
    blk(ceiling, W - 1, 0.1, 0.14, rail, cx, H - 0.25, z);
    blk(ceiling, W - 1.2, 0.02, 0.08, glow, cx, H - 0.31, z);
    for (let x = o.x0 + 3; x < (o.lampX1 ?? o.x1 - 2); x += 5) {
      blk(ceiling, 0.015, 0.7, 0.015, rail, x, H - 0.65, z);
      cyl(ceiling, 0.06, 0.22, 0.16, shade, x, H - 1.06, z, 10);
    }
  }
  mergeStatic(ceiling);
  g.add(ceiling);

  // The roof: a slab, a neon edge, and roof plant -- faded in and out as one.
  const roof = new THREE.Group();
  const fade = (m: THREE.Material) => { m.transparent = true; return m; };
  const slabMat = fade(new THREE.MeshStandardMaterial({ color: 0x232845, roughness: 0.85, metalness: 0.1 }));
  const plantMat = fade(new THREE.MeshStandardMaterial({ color: 0x5a6378, roughness: 0.6, metalness: 0.4 }));
  const solarMat = fade(new THREE.MeshStandardMaterial({ color: 0x1b2f63, roughness: 0.25, metalness: 0.6, emissive: 0x0d1b44, emissiveIntensity: 0.6 }));
  const edgeMat = fade(new THREE.MeshBasicMaterial({ color: o.accent, toneMapped: false }));
  blk(roof, W + T * 2 + 0.4, 0.34, D + T * 2 + 0.4, slabMat, cx, H + 0.17, cz);
  for (const [w, d, x, z] of [[W + T * 2 + 0.5, 0.14, cx, o.z0 - T - 0.2], [W + T * 2 + 0.5, 0.14, cx, o.z1 + T + 0.2],
    [0.14, D + T * 2 + 0.5, o.x0 - T - 0.2, cz], [0.14, D + T * 2 + 0.5, o.x1 + T + 0.2, cz]] as const) {
    blk(roof, w, 0.16, d, edgeMat, x, H + 0.4, z);
  }
  for (let i = 0; i < 4; i++) {
    const x = o.x0 + W * (0.18 + i * 0.2), z = o.z0 + D * 0.3;
    blk(roof, 2.2, 1.2, 1.6, plantMat, x, H + 0.94, z);                         // HVAC units
    cyl(roof, 0.5, 0.5, 0.1, plantMat, x, H + 1.6, z, 14);
  }
  for (let r = 0; r < 2; r++) for (let i = 0; i < 5; i++) {
    const p = blk(roof, 2.6, 0.08, 1.4, solarMat, o.x0 + W * (0.16 + i * 0.17), H + 0.62, o.z0 + D * (0.62 + r * 0.16));
    p.rotation.x = -0.35;
  }
  const fading = [slabMat, plantMat, solarMat, edgeMat];
  if (o.name) {
    const s = neonSign(o.name, o.accent, 3.6);
    s.position.set(cx, H + 2.3, o.z1 - 1.2);
    roof.add(s);
    fading.push(s.material as THREE.Material);
  }
  g.add(roof);

  // The plot it stands on, outlined in neon like every block in the city.
  const plot = new THREE.Group();
  blk(plot, W + 6, 0.08, D + 6, std('plot', 0x1a1633, 0.9), cx, -0.05, cz);
  for (const [w, d, x, z] of [[W + 6, 0.1, cx, o.z0 - 3], [W + 6, 0.1, cx, o.z1 + 3],
    [0.1, D + 6, o.x0 - 3, cz], [0.1, D + 6, o.x1 + 3, cz]] as const) blk(plot, w, 0.03, d, OFFICE.led(o.trim), x, 0.0, z);
  mergeStatic(plot);
  g.add(plot);

  const roofMats = fading.map((m) => ({ m, base: 1 }));
  return { group: g, cut: { walls, roof, roofMats, closed: -1 } };
}

/** Cut the shell for this camera: `fwd` is the camera's view direction. */
export function updateCutaway(c: Cutaway, fwd: THREE.Vector3, zoom: number): void {
  const closed = THREE.MathUtils.clamp((zoom - ROOF_OPEN) / (ROOF_SHUT - ROOF_OPEN), 0, 1);
  if (Math.abs(closed - c.closed) > 0.001) {
    c.closed = closed;
    c.roof.visible = closed > 0.01;
    for (const { m, base } of c.roofMats) m.opacity = base * closed;
  }
  for (const w of c.walls) {
    // A wall whose outside faces the camera stands between it and the room.
    const between = w.nx * -fwd.x + w.nz * -fwd.z > 0.05;
    const up = !between || closed > 0.5;
    w.full.visible = up;
    w.stub.visible = !up;
  }
}

/** A room divider: a solid lower panel with a neon floor line, glass up to
 *  the ceiling -- closed rooms you can still see into from above. */
export function partition(w: number, trim: number): THREE.Group {
  const g = glassWall(w, WALL_H);
  blk(g, w, 1.0, 0.12, OFFICE.wallDark(), 0, 0.5, 0);
  blk(g, w, 0.04, 0.16, OFFICE.darkSteel(), 0, 1.02, 0);
  blk(g, w, 0.015, 0.05, OFFICE.led(trim), 0, 0.008, 0.12);
  blk(g, w, 0.015, 0.05, OFFICE.led(trim), 0, 0.008, -0.12);
  return g;
}

/** A glowing neon sign: `text` in `color`, `h` metres tall. */
export function neonSign(text: string, color: number, h = 0.7): THREE.Mesh {
  const c = document.createElement('canvas');
  const fs = 72;
  c.height = 128;
  const g0 = c.getContext('2d');
  const font = `800 ${fs}px "Space Grotesk", "Segoe UI", system-ui, sans-serif`;
  if (g0) g0.font = font;
  c.width = Math.ceil((g0?.measureText(text).width ?? text.length * 44) + 64);
  const g = c.getContext('2d');
  if (g) {
    g.font = font;
    g.textAlign = 'center'; g.textBaseline = 'middle';
    const css = hexCss(color);
    g.shadowColor = css; g.shadowBlur = 22;
    g.strokeStyle = css; g.lineWidth = 3;
    g.strokeText(text, c.width / 2, 66);
    g.shadowBlur = 10;
    g.fillStyle = '#ffffff';
    g.fillText(text, c.width / 2, 66);
  }
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  textures.set(`neon:${++texSeq}`, t);
  const m = new THREE.Mesh(new THREE.PlaneGeometry(h * c.width / c.height, h),
    new THREE.MeshBasicMaterial({ map: t, transparent: true, depthWrite: false, toneMapped: false }));
  m.userData.keep = true;
  m.userData.ownGeometry = true;
  return m;
}

/** The reference Institute's teaching wall: a dark smart board with a sine
 *  wave, a vector and a small graph drawn in neon. */
export function lessonBoard(w = 5.2, h = 2.1): THREE.Group {
  const key = 'lessonboard';
  let t = textures.get(key);
  if (!t) {
    const c = document.createElement('canvas');
    c.width = 512; c.height = 208;
    const g = c.getContext('2d');
    if (g) {
      g.fillStyle = '#070a14'; g.fillRect(0, 0, 512, 208);
      g.lineWidth = 3; g.shadowBlur = 8;
      g.strokeStyle = g.shadowColor = '#7fefff';
      g.beginPath();
      for (let x = 0; x <= 230; x += 4) { const y = 104 - Math.sin(x / 26) * 46; if (x) g.lineTo(30 + x, y); else g.moveTo(30, y); }
      g.stroke();
      g.strokeStyle = g.shadowColor = '#ff4fd8';
      g.beginPath(); g.moveTo(60, 160); g.lineTo(200, 160); g.lineTo(188, 152); g.moveTo(200, 160); g.lineTo(188, 168); g.stroke();
      g.strokeStyle = g.shadowColor = '#b9a4ff';
      const pts = [[320, 60], [370, 110], [420, 70], [460, 140], [400, 170]];
      g.beginPath(); pts.forEach(([x, y], i) => (i ? g.lineTo(x, y) : g.moveTo(x, y))); g.stroke();
      g.fillStyle = '#e8e0ff';
      for (const [x, y] of pts) { g.beginPath(); g.arc(x, y, 5, 0, PI * 2); g.fill(); }
    }
    t = new THREE.CanvasTexture(c);
    t.colorSpace = THREE.SRGBColorSpace;
    textures.set(key, t);
  }
  const b = wallDisplay(w, h, t);
  blk(b, w + 0.2, 0.05, 0.05, OFFICE.led(0x7fefff), 0, h / 2 + 0.08, 0.02);
  return b;
}

/** A holographic globe on a pedestal: the reference classroom's teaching
 *  prop, and the ops room's table centrepiece. It turns slowly. */
export function holoGlobe(color: number): THREE.Group {
  const g = new THREE.Group();
  cyl(g, 0.32, 0.42, 0.9, OFFICE.darkSteel(), 0, 0.45, 0, 14);
  cyl(g, 0.36, 0.36, 0.03, OFFICE.led(color), 0, 0.91, 0, 20);
  const globe = new THREE.Mesh(new THREE.IcosahedronGeometry(0.5, 1),
    new THREE.MeshBasicMaterial({ color, wireframe: true, transparent: true, opacity: 0.85, toneMapped: false }));
  globe.position.y = 1.55;
  globe.userData.keep = true;
  globe.userData.ownGeometry = true;
  g.add(globe);
  spinningParts.push({ obj: globe, speed: 0.6 });
  return g;
}

/** Bake a finished furniture group: every static mesh (not tagged `keep`)
 *  is transformed into the group's space and merged into one mesh per
 *  material. Shared unit geometries are cloned before transforming, so the
 *  cache is never mutated. */
export function mergeStatic(root: THREE.Group): THREE.Group {
  root.updateMatrixWorld(true);
  const inv = new THREE.Matrix4().copy(root.matrixWorld).invert();
  const buckets = new Map<THREE.Material, THREE.BufferGeometry[]>();
  const doomed: THREE.Mesh[] = [];
  root.traverse((o) => {
    const m = o as THREE.Mesh;
    if (!(o instanceof THREE.Mesh) || o instanceof THREE.InstancedMesh || m.userData.keep) return;
    if (Array.isArray(m.material)) return;
    const g = m.geometry.clone();
    g.applyMatrix4(new THREE.Matrix4().multiplyMatrices(inv, m.matrixWorld));
    if (g.index) {
      const ng = g.toNonIndexed();
      g.dispose();
      buckets.set(m.material, [...(buckets.get(m.material) ?? []), ng]);
    } else {
      buckets.set(m.material, [...(buckets.get(m.material) ?? []), g]);
    }
    doomed.push(m);
  });
  for (const m of doomed) m.removeFromParent();
  // Drop now-empty helper groups (keeps the scene graph small).
  const empties: THREE.Object3D[] = [];
  root.traverse((o) => { if (o !== root && o.type === 'Group' && o.children.length === 0) empties.push(o); });
  for (const e of empties) e.removeFromParent();
  for (const [material, list] of buckets) {
    const merged = mergeGeometries(list.map((g) => { g.deleteAttribute('uv'); return g; }), false);
    for (const g of list) g.dispose();
    if (!merged) continue;
    const mesh = new THREE.Mesh(merged, material);
    mesh.userData.ownGeometry = true;
    root.add(mesh);
  }
  return root;
}

/* ==========================================================================
   The Agent HQ floor plan
   ========================================================================== */

/** Where someone sits: the chair position and which way they face (yaw; 0
 *  = facing -z, i.e. toward the back wall, desk in front of them). */
export interface Seat { x: number; z: number; face: number }

export interface OfficePlan {
  halfW: number;
  halfD: number;
  stations: Record<string, Seat>;
  manager: Seat;
  managerDisplay: { x: number; y: number; z: number; w: number; h: number };
  /** The Team Operations Room's wall screen (the live task graph). */
  opsDisplay: { x: number; y: number; z: number; w: number; h: number; ry: number };
  tempSeats: Seat[];
  zones: { label: string; x: number; z: number }[];
  /** ROOM camera mode targets: the ops room and the service annex. `yaw`
   *  (degrees) turns the view to face the room's main wall. */
  rooms: Record<'ops' | 'core', { x: number; z: number; zoom: number; yaw?: number }>;
  overviewTarget: [number, number, number];
}

const PI = Math.PI;
/** Two desks back to back around a pod centre: [+z sitter, -z sitter]. */
function pod(x: number, z: number): [Seat, Seat] {
  return [{ x, z: z + 1.25, face: 0 }, { x, z: z - 1.25, face: PI }];
}

export function hqOfficePlan(): OfficePlan {
  // 44 x 32 m: dense enough to read as a working floor, not a hangar.
  const [sec, thr] = pod(-16, -9);
  const [fore, resp] = pod(-9, -9);
  const [sys, net] = pod(10, -9);
  const [plan, asst] = pod(-6, 2);
  const temps: Seat[] = [];
  for (const x of [-4, 2, 8]) temps.push(...pod(x, 10));
  return {
    halfW: 22, halfD: 16,
    stations: {
      security: sec, threat: thr, forensics: fore, response: resp,
      system: sys, network: net, diagnostics: { x: 16, z: -7.75, face: 0 },
      planner: plan, assistant: asst, verifier: { x: 3, z: 0.75, face: PI },
    },
    manager: { x: 2, z: -13.3, face: PI },
    managerDisplay: { x: 2, y: 2.0, z: -15.86, w: 3.8, h: 1.7 },
    opsDisplay: { x: -21.86, y: 1.75, z: 7.5, w: 5.4, h: 2.3, ry: PI / 2 },
    tempSeats: temps,
    zones: [
      { label: 'SECURITY WING', x: -12.5, z: -3.6 },
      { label: 'OPERATIONS WING', x: 13, z: -3.6 },
      { label: 'AGENT MANAGER OFFICE', x: 2, z: -7.9 },
      { label: 'TEAM OPERATIONS ROOM', x: -17.5, z: 13.2 },
      { label: 'LOUNGE', x: 16, z: 15.2 },
      { label: 'TEMPORARY SPECIALISTS', x: 2, z: 14 },
      { label: 'PLANNING', x: -6, z: 5.6 },
      { label: 'VERIFICATION DESK', x: 3, z: 4.0 },
      // The service annex, through the glass on the right.
      { label: 'LIFTS + STAIRS', x: 28, z: -8.4 },
      { label: 'RESTROOMS', x: 32, z: -3.6 },
      { label: 'LOCKERS', x: 25.5, z: -5.6 },
      { label: 'BREAK ROOM · KITCHENETTE', x: 28, z: 7.6 },
      { label: 'CHARGING BAY', x: 28, z: 15.6 },
    ],
    // The ops room faces its task-graph screen on the left wall (x=-22).
    rooms: { ops: { x: -19.5, z: 7.5, zoom: 7.5, yaw: 131 }, core: { x: 28, z: 1, zoom: 12 } },
    overviewTarget: [5, 0.5, -1],
  };
}

/** A seat's desk + chair (no occupant). Returns the unmerged group and its
 *  screens; the caller may bake it. The desk is in FRONT of the seat. */
export function seatFurniture(seat: Seat, desk: DeskOpts, chairColor: number):
  { group: THREE.Group; screens: THREE.Mesh[] } {
  const g = new THREE.Group();
  g.position.set(seat.x, 0, seat.z);
  g.rotation.y = seat.face;
  const d = workDesk(desk);
  d.group.position.z = -0.85;
  g.add(d.group);
  const chair = officeChair(chairColor);
  chair.rotation.y = PI;                 // knees toward the desk (-z)
  g.add(chair);
  return { group: g, screens: d.screens };
}

/** Everything static in the HQ: the room, zone carpets, pod dividers, the
 *  Manager's glass office and its furniture, the meeting room, the lounge,
 *  the server row, shelves, plants, printers -- and the six temporary
 *  hot-desks (empty until a real specialist is assigned one). */
export function buildHQDecor(plan: OfficePlan): { group: THREE.Group; tempScreens: THREE.Mesh[][]; cut: Cutaway } {
  const root = new THREE.Group();
  root.name = 'hq-decor';
  // One closed box round the office floor AND the service annex beside it.
  const shell = closedShell({ x0: -plan.halfW, x1: 34, z0: -plan.halfD, z1: plan.halfD,
    accent: 0x38e0ff, trim: 0xffc24a, wall: 0x2c3850, floor: ['#222a3b', '#3d5070'], lampX1: 22, name: 'AGENT HQ' });
  root.add(shell.group);
  const decor = new THREE.Group();
  root.add(decor);
  const at = (o: THREE.Object3D, x: number, z: number, ry = 0) => {
    o.position.set(x, 0, z);
    o.rotation.y = ry;
    decor.add(o);
    return o;
  };
  // zone carpets (world-space placement: a rug is rotated flat, so its own
  // local axes are not the floor's)
  const carpet = (w: number, d: number, color: number, x: number, z: number) => {
    const r = rug(w, d, color);
    r.position.set(x, 0.012, z);
    decor.add(r);
  };
  carpet(13, 10, 0x2e3a4a, -12.5, -9);
  carpet(12, 10, 0x3a3830, 13, -9);
  carpet(10, 7.5, 0x33304a, -5, 2.2);
  carpet(17, 7, 0x2d3a42, 2, 10);
  carpet(10, 9, 0x4a3c33, 16, 10.5);
  carpet(9, 6, 0x4f3e30, 2, -12.5);

  // pod dividers (frosted panels between back-to-back desks)
  const divider = OFFICE.fabric(0x5b6b7c);
  for (const [x, z] of [[-16, -9], [-9, -9], [10, -9], [-6, 2], [-4, 10], [2, 10], [8, 10]]) {
    blk(decor, 1.7, 0.42, 0.04, divider, x, DESK_Y + 0.21, z);
  }

  // Manager's glass office: x -3..7, z -16..-9 (door gap on the front).
  // Rooms are glazed floor to ceiling now -- closed, but see-through.
  const glass = (w: number, x: number, z: number, ry = 0, solid = false) => {
    const g = solid ? partition(w, 0xffc24a) : glassWall(w, WALL_H);
    g.position.set(x, 0, z);
    g.rotation.y = ry;
    decor.add(g);
  };
  glass(7.8, 0.9, -9);
  glass(1.0, 6.5, -9);
  glass(7, -3, -12.5, PI / 2);
  glass(7, 7, -12.5, PI / 2);
  at(bookshelf(2.6, 2.2, 7), -1.4, -15.6);
  at(bookshelf(1.6, 2.2, 11), 5.6, -15.6);
  for (const x of [1.3, 2.7]) at(officeChair(0x6b4e3a), x, -11.3, PI);   // guests face the Manager
  at(plant(1.2, 3), 6.4, -9.7);
  at(sofa(2.2, 0x6b4e3a), -2.3, -11.6, PI / 2);

  // Security wing: shelves on the back wall, cabinets on the left, a board
  for (const x of [-20, -17.6, -15.2]) at(bookshelf(2.2, 2.1, x), x, -15.6);
  for (let i = 0; i < 3; i++) at(filingCabinet(), -21.5, -13 + i * 0.7, PI / 2);
  at(whiteboard(3.0, 1.1), -10, -15.85);

  // Operations wing: a server row along the back wall, more on the right
  for (let i = 0; i < 7; i++) at(serverRack(0x38e0ff, i + 1), 9 + i * 0.7, -15.1);
  for (let i = 0; i < 3; i++) at(serverRack(0xffb244, i + 20), 21.5, -13 + i * 1.0, -PI / 2);

  // Team Operations Room (glass), front-left: the ops table, and on the left
  // wall the live task-graph screen CityScene mounts at plan.opsDisplay.
  at(meetingTable(3.4, 1.3, 0x3b4b5c), -17.5, 7.5);
  glass(9, -17.5, 3, 0, true);
  glass(9, -13, 7.5, PI / 2, true);
  at(holoGlobe(0x7fefff), -14.4, 11);

  buildServiceAnnex(root, decor, at);

  // The reference city's look: neon signs over the window glass, a lit wall
  // of graphs over the operations wing, a gold inlay line down the main aisle.
  const sign = (text: string, color: number, x: number, z: number, h = 0.5) => {
    const s = neonSign(text, color, h);
    s.position.set(x, 3.2, z);
    root.add(s);
  };
  sign('ARGUS · AGENT HQ', 0x7fefff, -12.5, -15.82, 0.46);
  sign('OPERATIONS', 0xffb244, 14.5, -15.82);
  sign('BREAK ROOM', 0xff8fd8, 28, -15.82, 0.36);
  const opsWall = wallDisplay(3.4, 1.5, screenTexture(0xffb244, 2));
  opsWall.position.set(17.4, 1.85, -15.82);
  root.add(opsWall);
  blk(decor, 42, 0.012, 0.07, OFFICE.led(0xffc24a), 0, 0.012, -4.1);

  // Lounge, front-right
  at(sofa(2.6, 0x3b556e), 16, 13.6, PI);
  at(sofa(2.2, 0x3b556e), 12.4, 10.2, PI / 2);
  at(coffeeTable(), 16, 10.6);
  at(waterCooler(), 21.3, 6.5);
  at(coffeeMachine(), 21.2, 9.2, -PI / 2);

  // Printers, plants around the floor
  at(printer(), -21.3, -3, PI / 2);
  at(printer(), 7.6, -5.8);
  let seed = 1;
  for (const [x, z, s] of [[-21, -15, 1.3], [-7.5, -15, 1.1], [8.2, -15.2, 1.1], [21, 3.5, 1.4],
    [-21, 1.5, 1.1], [-12, 14.5, 1.2], [10.5, 15, 1.1], [-7.8, -4.4, 1], [7.8, -4.4, 1],
    [-1, -4.4, 0.9], [11, 1.5, 1.2], [-11, 3, 1]] as const) {
    at(plant(s, seed++), x, z);
  }

  // Temporary hot-desks: built now, lit only while a real specialist is
  // assigned (CityScene powers the screens up/down from the backend list).
  const tempScreens: THREE.Mesh[][] = [];
  for (const seat of plan.tempSeats) {
    const f = seatFurniture(seat, { accent: 0x7fe9ff, top: 'laminate', monitors: 1 }, 0x3b4b5c);
    tempScreens.push(f.screens);
    decor.add(f.group);
  }

  mergeStatic(decor);
  return { group: root, tempScreens, cut: shell.cut };
}

/* ---- the service annex: x 22..34 beside the operations floor ----------
   Lifts and stairs, restrooms, lockers, a kitchenette and break room, and a
   charging bay -- what a real office floor has around its desks.
   For robots the break room and bay mean rest and charging; the docks stay
   dim, because no backend state says anyone is charging. */

/** A bank of `n` full-height lockers, fronts facing +z. */
export function lockerBank(n: number, color = 0x5b7a99): THREE.Group {
  const g = new THREE.Group();
  const body = OFFICE.fabric(color), dark = OFFICE.darkSteel();
  for (let i = 0; i < n; i++) {
    const x = (i - (n - 1) / 2) * 0.62;
    blk(g, 0.6, 1.9, 0.5, body, x, 0.95, 0);
    blk(g, 0.02, 1.8, 0.01, dark, x + 0.3, 0.95, 0.255);
    for (let v = 0; v < 3; v++) blk(g, 0.34, 0.02, 0.01, dark, x, 1.65 + v * 0.06, 0.255);
    blk(g, 0.03, 0.14, 0.03, OFFICE.steel(), x + 0.2, 1.0, 0.27);
  }
  return g;
}

/** Kitchen counter run facing +z: base cabinets, worktop, sink, upper
 *  cabinets, a fridge at one end, a microwave and kettle on top. */
export function kitchenette(w = 4.2): THREE.Group {
  const g = new THREE.Group();
  const cab = OFFICE.laminate(), top = OFFICE.walnut(), steel = OFFICE.steel();
  blk(g, w, 0.86, 0.62, cab, 0, 0.43, 0);
  blk(g, w + 0.04, 0.04, 0.66, top, 0, 0.88, 0);
  blk(g, 0.62, 0.02, 0.42, steel, -w / 4, 0.9, 0.02);
  blk(g, 0.04, 0.26, 0.04, steel, -w / 4, 1.02, -0.2);
  for (let i = 0; i < 4; i++) blk(g, 0.01, 0.7, 0.01, OFFICE.darkSteel(), -w / 2 + (i + 0.5) * (w / 4), 0.45, 0.315);
  blk(g, w, 0.7, 0.36, cab, 0, 1.9, -0.13);
  blk(g, 0.8, 1.85, 0.66, steel, w / 2 + 0.44, 0.93, 0);
  blk(g, 0.5, 0.3, 0.36, OFFICE.plastic(), w / 4, 1.05, -0.06);
  cyl(g, 0.08, 0.09, 0.22, steel, w / 4 + 0.55, 1.01, 0);
  return g;
}

/** A round break table with four chairs. */
export function breakTable(chair = 0x6b8a7a): THREE.Group {
  const g = new THREE.Group();
  cyl(g, 0.55, 0.55, 0.04, OFFICE.oak(), 0, DESK_Y, 0, 24);
  cyl(g, 0.05, 0.05, DESK_Y, OFFICE.darkSteel(), 0, DESK_Y / 2, 0);
  cyl(g, 0.3, 0.3, 0.03, OFFICE.darkSteel(), 0, 0.015, 0, 16);
  for (let i = 0; i < 4; i++) {
    const c = new THREE.Group();
    blk(c, 0.42, 0.05, 0.42, OFFICE.fabric(chair), 0, SEAT_Y, 0);
    blk(c, 0.42, 0.42, 0.05, OFFICE.fabric(chair), 0, SEAT_Y + 0.23, -0.2);
    for (const [x, z] of [[-0.18, -0.18], [0.18, -0.18], [-0.18, 0.18], [0.18, 0.18]]) blk(c, 0.03, SEAT_Y, 0.03, OFFICE.darkSteel(), x, SEAT_Y / 2, z);
    c.position.set(Math.sin(i * PI / 2) * 0.85, 0, Math.cos(i * PI / 2) * 0.85);
    c.rotation.y = i * PI / 2 + PI;
    g.add(c);
  }
  return g;
}

/** A robot charging dock: floor pad, a dim ring, a post with a small panel. */
export function chargingDock(accent = 0x1f5c6b): THREE.Group {
  const g = new THREE.Group();
  cyl(g, 0.62, 0.66, 0.06, OFFICE.darkSteel(), 0, 0.03, 0, 24);
  cyl(g, 0.5, 0.5, 0.012, OFFICE.led(accent), 0, 0.066, 0, 24);
  cyl(g, 0.44, 0.44, 0.014, OFFICE.darkSteel(), 0, 0.068, 0, 24);
  blk(g, 0.22, 1.5, 0.16, OFFICE.laminate(), 0, 0.75, -0.7);
  blk(g, 0.16, 0.1, 0.02, OFFICE.led(accent), 0, 1.25, -0.61);
  return g;
}

/** A drinks/snack vending machine. */
export function vendingMachine(): THREE.Group {
  const g = new THREE.Group();
  blk(g, 0.9, 1.85, 0.75, std('vend', 0xc23b3b, 0.4, 0.2), 0, 0.93, 0);
  blk(g, 0.6, 1.2, 0.02, OFFICE.glass(), -0.08, 1.15, 0.38);
  for (let r = 0; r < 4; r++) blk(g, 0.56, 0.02, 0.3, OFFICE.steel(), -0.08, 0.7 + r * 0.3, 0.22);
  blk(g, 0.16, 0.5, 0.02, OFFICE.led(0x9fd8ff), 0.33, 1.3, 0.38);
  return g;
}

/** A small wall sign with a pictogram (restrooms, lifts, stairs), drawn once. */
function signTexture(kind: 'wc' | 'lift' | 'stairs'): THREE.CanvasTexture {
  const key = `sign:${kind}`;
  const hit = textures.get(key);
  if (hit) return hit;
  const c = document.createElement('canvas');
  c.width = 256; c.height = 128;
  const g = c.getContext('2d');
  if (g) {
    g.fillStyle = '#1d3a5c'; g.fillRect(0, 0, 256, 128);
    g.fillStyle = '#eef6ff'; g.strokeStyle = '#eef6ff'; g.lineWidth = 6;
    const person = (x: number, dress: boolean) => {
      g.beginPath(); g.arc(x, 30, 11, 0, PI * 2); g.fill();
      if (dress) { g.beginPath(); g.moveTo(x, 44); g.lineTo(x - 18, 92); g.lineTo(x + 18, 92); g.closePath(); g.fill(); }
      else g.fillRect(x - 11, 44, 22, 48);
      g.fillRect(x - 8, 92, 6, 24); g.fillRect(x + 2, 92, 6, 24);
    };
    if (kind === 'wc') { person(80, false); person(176, true); g.fillRect(126, 18, 4, 96); }
    else if (kind === 'lift') {
      g.strokeRect(70, 16, 116, 96); g.beginPath(); g.moveTo(128, 16); g.lineTo(128, 112); g.stroke();
      g.beginPath(); g.moveTo(96, 50); g.lineTo(110, 34); g.lineTo(124, 50); g.fill();
      g.beginPath(); g.moveTo(132, 78); g.lineTo(146, 94); g.lineTo(160, 78); g.fill();
    } else {
      g.beginPath(); g.moveTo(60, 110);
      for (let i = 0; i < 5; i++) { g.lineTo(60 + i * 28, 110 - i * 20); g.lineTo(88 + i * 28, 110 - i * 20); }
      g.stroke();
    }
  }
  const t = new THREE.CanvasTexture(c);
  t.colorSpace = THREE.SRGBColorSpace;
  textures.set(key, t);
  return t;
}

function wallSign(kind: 'wc' | 'lift' | 'stairs'): THREE.Mesh {
  const m = new THREE.Mesh(geo('plane:sign', () => new THREE.PlaneGeometry(0.62, 0.31)),
    mat(`signmat:${kind}`, () => new THREE.MeshBasicMaterial({ map: signTexture(kind), toneMapped: false })));
  m.userData.keep = true;
  return m;
}

function buildServiceAnnex(root: THREE.Group, decor: THREE.Group,
  at: (o: THREE.Object3D, x: number, z: number, ry?: number) => THREE.Object3D): void {
  // Floor, back wall with windows, and the glass partition (two door gaps).
  const floor = new THREE.Mesh(geo('plane:unit', () => new THREE.PlaneGeometry(1, 1)), OFFICE.carpet(0x6b6358));
  floor.scale.set(12, 32, 1);
  floor.rotation.x = -PI / 2;
  floor.position.set(28, 0.006, 0);
  decor.add(floor);
  // (The back wall is the building's own shell now.)
  for (const [w, z] of [[8.2, -11.9], [7.2, 3.4], [8, 12]] as const) {
    const gw = glassWall(w, WALL_H);
    gw.position.set(22, 0, z);
    gw.rotation.y = PI / 2;
    decor.add(gw);
  }
  // Lift + stair core against the back wall.
  const concrete = std('core', 0x8a939c, 0.8);
  blk(decor, 5.6, 3.0, 5.0, concrete, 25.6, 1.5, -13.5);
  for (const x of [24.4, 26.8]) {
    blk(decor, 1.1, 2.15, 0.04, OFFICE.steel(), x, 1.08, -10.98);
    blk(decor, 0.01, 2.1, 0.01, OFFICE.darkSteel(), x, 1.08, -10.95);
    blk(decor, 1.3, 0.1, 0.06, OFFICE.darkSteel(), x, 2.22, -10.97);
    blk(decor, 0.1, 0.18, 0.02, OFFICE.led(0x9fd8ff), x + 0.72, 1.2, -10.96);
  }
  const lift = wallSign('lift');
  lift.position.set(25.6, 2.55, -10.97);
  root.add(lift);
  // A stair flight rising toward the back wall, with a handrail.
  for (let i = 0; i < 9; i++) blk(decor, 2.4, 0.18 * (i + 1), 0.34, concrete, 30.4, 0.09 * (i + 1), -10.6 - i * 0.34);
  blk(decor, 0.04, 0.04, 3.4, OFFICE.steel(), 29.15, 2.05, -12.1);
  const stairs = wallSign('stairs');
  stairs.position.set(32.8, 2.3, -15.88);
  root.add(stairs);
  // Restrooms: a small block with two doors facing the corridor.
  blk(decor, 3.6, 3.0, 4.2, OFFICE.wall(), 32.2, 1.5, -5.4);
  for (const z of [-6.5, -4.3]) {
    blk(decor, 0.04, 2.1, 0.9, OFFICE.oak(), 30.38, 1.05, z);
    blk(decor, 0.03, 0.03, 0.14, OFFICE.steel(), 30.34, 1.0, z + 0.3);
  }
  const wc = wallSign('wc');
  wc.position.set(30.37, 2.45, -5.4);
  wc.rotation.y = -PI / 2;
  root.add(wc);
  // Lockers facing the lift lobby, a clear walkway from the partition door.
  at(lockerBank(8), 25.8, -7.2);
  // Kitchenette + fridge along the right, break tables, vending, a plant.
  at(kitchenette(4.2), 33.5, 1.2, -PI / 2);
  at(breakTable(), 26.2, 0.4);
  at(breakTable(0x7a6b8a), 26.2, 5.2);
  at(breakTable(), 30.2, 7.6);
  at(vendingMachine(), 23.0, 9.4, PI / 2);
  at(coffeeMachine(), 33.3, 5.4, -PI / 2);
  at(plant(1.3, 21), 33.2, 9.6);
  at(sofa(2.2, 0x7a5b4a), 30.6, 3.2, PI);
  // Charging bay along the front: docks for standby, dim unless the backend
  // ever reports a robot charging (it does not today).
  for (let i = 0; i < 5; i++) at(chargingDock(), 23.6 + i * 2.2, 14.2);
}

/* ==========================================================================
   The Academy: a real school floor
   ========================================================================== */

/** A classroom desk with its chair, the student facing -z (toward the board).
 *  With `monitor` (an accent colour) it carries a small screen facing the
 *  student, left in `userData.screen` for the caller to power. */
export function studentDesk(chair = 0x5c4f8a, monitor?: number): THREE.Group {
  const g = new THREE.Group();
  if (monitor !== undefined) {
    blk(g, 0.46, 0.3, 0.03, OFFICE.bezel(), 0, DESK_Y + 0.26, -0.14);
    blk(g, 0.04, 0.12, 0.03, OFFICE.bezel(), 0, DESK_Y + 0.06, -0.16);
    const scr = new THREE.Mesh(geo('plane:studentscreen', () => new THREE.PlaneGeometry(0.42, 0.26)),
      new THREE.MeshBasicMaterial({ map: screenTexture(monitor, 1), toneMapped: false }));
    scr.position.set(0, DESK_Y + 0.26, -0.122);
    scr.userData.keep = true;
    g.add(scr);
    g.userData.screen = scr;
  }
  blk(g, 1.0, 0.04, 0.55, OFFICE.oak(), 0, DESK_Y - 0.02, 0);
  blk(g, 0.96, 0.3, 0.02, OFFICE.laminate(), 0, DESK_Y - 0.2, -0.26);
  for (const s of [-1, 1]) blk(g, 0.04, DESK_Y - 0.04, 0.5, OFFICE.darkSteel(), s * 0.46, (DESK_Y - 0.04) / 2, 0);
  const c = new THREE.Group();
  c.position.z = 0.55;
  blk(c, 0.44, 0.05, 0.42, OFFICE.fabric(chair), 0, SEAT_Y, 0);
  blk(c, 0.44, 0.4, 0.05, OFFICE.fabric(chair), 0, SEAT_Y + 0.24, 0.2);
  for (const [x, z] of [[-0.19, -0.18], [0.19, -0.18], [-0.19, 0.18], [0.19, 0.18]]) blk(c, 0.03, SEAT_Y, 0.03, OFFICE.darkSteel(), x, SEAT_Y / 2, z);
  g.add(c);
  blk(g, 0.26, 0.015, 0.2, OFFICE.paper(), 0.2, DESK_Y + 0.008, 0.05);
  return g;
}

export interface AcademyPlan {
  halfW: number; halfD: number;
  zones: { label: string; x: number; z: number }[];
  /** The classroom's 15 student desks (desk centre; the chair is +0.55 z,
   *  facing the board at -z). Students are seated here by role. */
  classDesks: { x: number; z: number }[];
}

export const ACADEMY_PLAN: AcademyPlan = {
  halfW: 26, halfD: 20,
  classDesks: Array.from({ length: 15 }, (_, i) => ({ x: -23 + (i % 5) * 2.5, z: -14.8 + Math.floor(i / 5) * 2.1 })),
  zones: [
    { label: 'CLASSROOM', x: -18, z: -6.4 },
    { label: 'COMPUTE CLASSROOM', x: -2, z: -6.4 },
    { label: 'SIMULATION LAB', x: 16, z: -6.4 },
    { label: 'EXAM ROOM', x: -19, z: 9.2 },
    { label: 'LIBRARY', x: -3, z: 9.2 },
    { label: 'ROBOT TRAINING ROOM', x: 16, z: 9.2 },
    { label: 'LOBBY', x: -18, z: 19.4 },
    { label: 'CAFETERIA · REST', x: 8, z: 19.4 },
  ],
};

/** The whole school floor: classrooms, compute classroom, simulation lab,
 *  exam room, library, robot training room, lockers along the corridor, a
 *  lobby and a cafeteria. Every screen here is a dim desktop -- no training
 *  backend exists, so nothing shows a lesson in progress. */
export function buildAcademyDecor(): { group: THREE.Group; screens: THREE.Mesh[]; cut: Cutaway } {
  const P = ACADEMY_PLAN;
  const root = new THREE.Group();
  root.name = 'academy-decor';
  // The reference Institute: indigo walls, cyan neon along the top, pink
  // along the floor, dark tiles.
  const shell = closedShell({ x0: -P.halfW, x1: P.halfW, z0: -P.halfD, z1: P.halfD,
    accent: 0x7fefff, trim: 0xff4fd8, wall: 0x2f2750, floor: ['#241e36', '#473a78'], name: 'ARGUS ACADEMY' });
  root.add(shell.group);
  const decor = new THREE.Group();
  root.add(decor);
  const screens: THREE.Mesh[] = [];
  const at = (o: THREE.Object3D, x: number, z: number, ry = 0) => {
    o.position.set(x, 0, z); o.rotation.y = ry; decor.add(o); return o;
  };
  const carpet = (w: number, d: number, color: number, x: number, z: number) => {
    const r = rug(w, d, color); r.position.set(x, 0.012, z); decor.add(r);
  };
  const glass = (w: number, x: number, z: number, ry = 0) => {
    const gw = partition(w, 0xff4fd8); gw.position.set(x, 0, z); gw.rotation.y = ry; decor.add(gw);
  };
  const sign = (text: string, color: number, x: number, z: number, ry = 0, h = 0.5) => {
    const s = neonSign(text, color, h);
    s.position.set(x, 3.2, z);
    s.rotation.y = ry;
    root.add(s);
  };
  /** A workstation whose sitter faces -z (ry 0) or +z (ry PI); its screens
      are collected so the caller keeps them all dim. */
  const desk = (o: DeskOpts, x: number, z: number, ry = 0) => {
    const d = workDesk(o);
    d.group.position.set(x, 0, z);
    d.group.rotation.y = ry;
    decor.add(d.group);
    screens.push(...d.screens);
  };
  // Room floors (cream / warm / indigo), and the glass that divides them.
  carpet(15, 11, 0x6b5f86, -18, -14);
  carpet(15, 11, 0x5a6478, -2, -14);
  carpet(19, 11, 0x3c3a66, 16, -14);
  carpet(13, 11, 0x7a6c58, -19, 2);
  carpet(17, 11, 0x6e5a44, -3, 2);
  carpet(19, 11, 0x3a4a5c, 16, 2);
  carpet(15, 7, 0x8a7a64, -18, 16);
  carpet(33, 7, 0x7e6e5a, 8, 16);
  for (const x of [-10.5, 6.5]) { glass(11.4, x, -14, PI / 2); glass(11.4, x, 2, PI / 2); }
  for (const [w, x] of [[5.4, -22.8], [5.4, -13.2], [5.4, -4.8], [5.4, 3.8], [8, 11], [8, 22]] as const) {
    glass(w, x, -8.2);
    glass(w, x, 7.8);
  }

  // CLASSROOM: a board and instructor station at the back wall, three rows
  // of student desks facing it.
  const board = lessonBoard(4.8, 1.9);
  board.position.set(-18, 1.75, -19.8);
  root.add(board);
  sign('ARGUS ACADEMY', 0x7fefff, -18, -19.78, 0, 0.46);
  const lesson = wallDisplay(2.4, 1.35, screenTexture(0x9578ff, 1));
  lesson.position.set(-12.9, 1.8, -19.86);
  root.add(lesson);
  desk({ accent: 0x9578ff, monitors: 1, top: 'walnut', variant: 2 }, -18, -17.2, PI);
  at(officeChair(0x4a3a6b), -18, -18.1);          // the instructor faces the class
  // Student monitors alternate violet/cyan, like the reference classroom;
  // they are powered from the real Academy state (CityScene.setScreens).
  P.classDesks.forEach((d, i) => {
    const sd = at(studentDesk(0x5c4f8a, i % 2 ? 0x7fefff : 0xb98cff), d.x, d.z);
    screens.push(sd.userData.screen as THREE.Mesh);
  });
  at(holoGlobe(0xb98cff), -23.2, -17.6);
  at(bookshelf(2.2, 2.1, 90), -25.5, -13.2, PI / 2);
  at(plant(1.1, 91), -11.6, -19.2);
  at(plant(1.0, 92), -25, -9.4);

  // COMPUTE CLASSROOM: workstation rows and a rack wall.
  for (let r = 0; r < 2; r++) for (let c = 0; c < 3; c++) {
    const f = seatFurniture({ x: -6.5 + c * 4.2, z: -13.6 + r * 3.2, face: 0 },
      { accent: 0x7fefff, monitors: 1, top: 'laminate', variant: r * 3 + c }, 0x3b4b5c);
    screens.push(...f.screens);
    decor.add(f.group);
  }
  for (let i = 0; i < 6; i++) at(serverRack(0x9578ff, i + 40), -7 + i * 0.7, -19.1);

  // SIMULATION LAB: three sim pods -- platform, ring, a screen on a stand.
  for (const x of [9.5, 16, 22.5]) {
    cyl(decor, 1.3, 1.4, 0.12, OFFICE.darkSteel(), x, 0.06, -15.2, 28);
    cyl(decor, 1.18, 1.18, 0.02, OFFICE.led(0x4b3f8a), x, 0.13, -15.2, 28);
    const stand = wallDisplay(1.4, 0.8, screenTexture(0x9578ff, 3));
    stand.position.set(x, 1.5, -17.2);
    root.add(stand);
    blk(decor, 0.08, 1.1, 0.08, OFFICE.darkSteel(), x, 0.55, -17.25);
  }
  desk({ accent: 0x9578ff, monitors: 2, variant: 5 }, 16, -10.4);   // control desk faces the pods

  // Corridor lockers on both sides of the lobby door.
  at(lockerBank(10), -18, -7.5);
  at(lockerBank(10), 16, -7.5);

  // EXAM ROOM: widely spaced single desks and a wall clock.
  for (let r = 0; r < 3; r++) for (let c = 0; c < 4; c++) at(studentDesk(0x6b5f4a), -24 + c * 3, -1.4 + r * 2.8);
  desk({ monitors: 1, top: 'walnut', variant: 6 }, -19, -2.9, PI);     // invigilator faces the room

  // LIBRARY: stacks and reading tables.
  let seed = 60;
  for (let r = 0; r < 3; r++) for (let c = 0; c < 3; c++) at(bookshelf(2.4, 2.1, seed++), -9 + c * 3.1, -2.4 + r * 2.6);
  at(meetingTable(3.0, 1.2, 0x6b4e3a), -3.2, 5.6);
  at(meetingTable(3.0, 1.2, 0x6b4e3a), 2.2, 5.6);

  // ROBOT TRAINING ROOM: calibration pads and a gantry frame.
  for (const [x, z] of [[10, -1.6], [14, -1.6], [10, 3.4], [14, 3.4]] as const) {
    blk(decor, 3.0, 0.05, 3.0, OFFICE.darkSteel(), x, 0.025, z);
    blk(decor, 3.02, 0.012, 0.06, OFFICE.led(0x6a5acd), x, 0.056, z - 1.49);
    blk(decor, 3.02, 0.012, 0.06, OFFICE.led(0x6a5acd), x, 0.056, z + 1.49);
  }
  for (const [x, z] of [[18.5, -2], [24, -2], [18.5, 4], [24, 4]] as const) blk(decor, 0.18, 3.0, 0.18, OFFICE.steel(), x, 1.5, z);
  blk(decor, 5.7, 0.16, 0.16, OFFICE.steel(), 21.25, 3.0, -2);
  blk(decor, 5.7, 0.16, 0.16, OFFICE.steel(), 21.25, 3.0, 4);
  desk({ accent: 0x9578ff, monitors: 2, variant: 7 }, 21.2, 6.4);    // instructor faces the pads

  // LOBBY: reception, sofas, plants.
  blk(decor, 3.6, 1.05, 0.8, OFFICE.walnut(), -18, 0.53, 14.2);
  blk(decor, 3.7, 0.05, 0.9, OFFICE.laminate(), -18, 1.08, 14.2);
  at(sofa(2.4, 0x5c4f8a), -22.5, 17.6);
  at(sofa(2.4, 0x5c4f8a), -14, 17.6);
  at(plant(1.4, 71), -25, 13.2);
  at(plant(1.2, 72), -11.4, 13.2);

  // CAFETERIA · REST: tables, a serving counter, vending.
  for (let c = 0; c < 5; c++) at(breakTable(c % 2 ? 0x6b8a7a : 0x8a6b5c), -5 + c * 4.4, 15.8);
  at(kitchenette(6.4), 12, 19.3, PI);
  at(vendingMachine(), 24.6, 14, -PI / 2);
  at(vendingMachine(), 24.6, 15.2, -PI / 2);
  at(plant(1.3, 73), -8.6, 19);

  // Neon signs over the glass, cyan inlay lines down both corridors.
  sign('COMPUTE LAB', 0xb98cff, -2, -19.78);
  sign('SIMULATION', 0x7fefff, 16, -19.78);
  sign('EXAM HALL', 0xff8fd8, -25.78, 2, PI / 2);
  sign('LOBBY', 0xffc24a, -25.78, 16, PI / 2, 0.36);
  for (const z of [-5.9, 10.1]) blk(decor, 50, 0.012, 0.07, OFFICE.led(0x7fefff), 0, 0.012, z);

  mergeStatic(decor);
  return { group: root, screens, cut: shell.cut };
}

/** Unmount: the caches outlive a component instance. */
export function disposeInterior(): void {
  for (const m of mats.values()) m.dispose();
  mats.clear();
  for (const g of geos.values()) g.dispose();
  geos.clear();
  for (const t of textures.values()) t.dispose();
  textures.clear();
}
