/* ARGUS AI City -- layout data. Pure data, no Three.js here, so it's cheap
   to read/adjust without touching the renderer.

   CITY-4: the dense 3x3(+2) neighborhood grid, now with a real street
   network laid out BETWEEN the blocks rather than point-to-point lines
   through them. Column/row spacing, block footprints and street widths are
   tuned against each other so every carriageway lands in the gap between two
   blocks with a metre or two of verge -- that tightness is what makes the
   city read as dense instead of as towers on open ground.

   Core Tower anchors the north row with Security/Academy flanking it; Agent
   HQ anchors the middle row; the Policy/Auth Gate straddles the southern
   spine with the Capability Center behind it; Cloud Embassy sits alone,
   further north, OUTSIDE the secure grid -- reachable only by one service
   road to Core Tower, with no route of any kind toward the Gate. */

export type BuildingKind =
  | 'core' | 'cluster' | 'academy' | 'fortress' | 'operations'
  | 'institute' | 'specialists' | 'plant' | 'embassy' | 'gate'
  | 'capability' | 'vault';

/** District colour category (Phase B). This is what stops the whole city
 *  reading as one cyan mass: each category owns a hue band, and the runtime
 *  looks up its accent/label/selection colours from cityPalette.ts. It
 *  matches the Blender asset families one-for-one. */
export type DistrictCategory =
  | 'command' | 'hq' | 'security' | 'research' | 'operations' | 'verification'
  | 'specialist' | 'civic' | 'industrial' | 'cloud' | 'residential' | 'utility';

/** One placed building model inside a district's block. `asset` is the GLB
 *  basename under public/assets/city/buildings/. */
export interface PlacedAsset {
  asset: string;
  x?: number;          // offset from the district origin
  z?: number;
  ry?: number;         // yaw, radians
  /** Uniform scale. Every placed model must stay inside its block: the door
   *  row where robots stand is on the sidewalk just outside it, so a model
   *  poking past the block edge stands ON the robots (the owner saw this as
   *  "agents overlaid with buildings"). Measured in the browser with
   *  `__argusCity.clearance()`. */
  s?: number;
  label?: string;      // sub-building name, shown at building zoom
}

export interface District {
  id: string;
  name: string;
  purpose: string;
  kind: BuildingKind;
  category: DistrictCategory;
  /** What actually happens here -- shown in the selection panel (Phase I). */
  role: string;
  x: number;
  z: number;
  footprint: number;   // half-width of the buildable block (sidewalk sits outside it)
  height: number;      // silhouette height, for camera framing before the GLB loads
  color: number;       // primary massing color (fallback before assets load)
  accent: number;      // emissive/glass accent color
  secure: boolean;     // false only for Cloud Embassy -- outside the inner grid
  assets: PlacedAsset[];
}

const COL_L = -44, COL_C = 0, COL_R = 44;
const COLS = [COL_L, COL_C, COL_R];
const ROW_A = -74, ROW_B = -32, ROW_C = 14, ROW_GATE = 58, ROW_CAP = 94;
const ROWS = [ROW_A, ROW_B, ROW_C];
const EMBASSY_Z = -128;

// A one-line purpose per district, shown on hover/select -- no fake runtime
// values, just what CITY-2/3 mean here (or "future home of" for districts
// with no interior yet).
export const DISTRICTS: District[] = [
  {
    id: 'core-tower', name: 'ARGUS CORE TOWER',
    purpose: 'The central landmark -- where every request is decided.',
    role: 'Routing, policy evaluation and the decision path every request takes.',
    kind: 'core', category: 'command', x: COL_C, z: ROW_A, footprint: 14, height: 48,
    color: 0x16305a, accent: 0x38e0ff, secure: true,
    assets: [{ asset: 'core_tower' }],
  },
  {
    id: 'agent-hq', name: 'AGENT HQ',
    purpose: 'The 10 core agents’ operations floor -- click to enter.',
    role: 'Home of the 10 permanent agents. Enter to see the operations floor.',
    kind: 'cluster', category: 'hq', x: COL_C, z: ROW_B, footprint: 17, height: 26,
    color: 0x22364a, accent: 0x6cc8ff, secure: true,
    assets: [{ asset: 'agent_hq' }],
  },
  {
    id: 'academy', name: 'ARGUS ACADEMY',
    purpose: 'Agent learning and simulation campus -- click to enter.',
    role: 'Training, simulation and exam halls. Agents study synthetic lessons here, one at a time on the shared model; a verifier checks every lesson.',
    kind: 'academy', category: 'research', x: COL_R, z: ROW_A, footprint: 15, height: 24,
    color: 0x2a2340, accent: 0x9578ff, secure: true,
    assets: [
      // The lab used to sit at z 19 -- on the cross street, so traffic drove
      // through it. Now a small annex in the front yard, beside the door row.
      { asset: 'academy', s: 0.9 },
      { asset: 'lab_block_a', x: 10, z: 11.6, s: 0.55, label: 'RESEARCH LAB' },
    ],
  },
  {
    id: 'security-district', name: 'SECURITY DISTRICT',
    purpose: 'Security Command, Threat Lab, Forensics and Response.',
    role: 'Threat detection, forensics and incident response.',
    kind: 'fortress', category: 'security', x: COL_L, z: ROW_A, footprint: 14, height: 20,
    color: 0x2a3033, accent: 0x2ad4bd, secure: true,
    assets: [
      { asset: 'security_command', x: -1, z: -3.5 },
      { asset: 'threat_lab', x: -9.5, z: 10.1, s: 0.7, label: 'THREAT LAB' },
      { asset: 'response_center', x: 9.5, z: 10.1, s: 0.7, label: 'RESPONSE' },
      { asset: 'forensics_center', x: 10.4, z: -8.7, s: 0.7, label: 'FORENSICS' },
    ],
  },
  {
    id: 'operations-center', name: 'OPERATIONS CENTER',
    purpose: 'The System, Network and Diagnostics technical campus.',
    role: 'System health, network state and diagnostics.',
    kind: 'operations', category: 'operations', x: COL_L, z: ROW_B, footprint: 14, height: 18,
    color: 0x33291d, accent: 0xffb244, secure: true,
    assets: [
      { asset: 'operations_center', z: -2.5 },
      { asset: 'utility_shed_a', x: -10.5, z: 9.5, label: 'SERVICE' },
      { asset: 'lab_block_b', x: 9.4, z: 9.0, s: 0.75, label: 'DIAGNOSTICS LAB' },
    ],
  },
  {
    id: 'verification-institute', name: 'VERIFICATION INSTITUTE',
    purpose: 'Where the Verifier checks results -- click to enter.',
    role: 'Independent verification of every result before it is accepted.',
    kind: 'institute', category: 'verification', x: COL_R, z: ROW_B, footprint: 15, height: 26,
    color: 0x3a4552, accent: 0xe8f4ff, secure: true,
    assets: [{ asset: 'verification_institute' }],
  },
  {
    id: 'model-plant', name: 'MODEL COMPUTE CENTER',
    purpose: 'The shared local model, its compute halls and its queue.',
    role: 'The local model, its compute halls and the shared inference queue.',
    kind: 'plant', category: 'industrial', x: COL_L, z: ROW_C, footprint: 17, height: 14,
    color: 0x35291a, accent: 0xffb244, secure: true,
    assets: [{ asset: 'model_compute' }],
  },
  {
    id: 'specialist-district', name: 'SPECIALIST DISTRICT',
    purpose: 'Where temporary local specialists spin up (Hermes is not integrated).',
    role: 'Spin-up yard for temporary specialists. Empty until one is spawned.',
    kind: 'specialists', category: 'specialist', x: COL_C, z: ROW_C, footprint: 13, height: 10,
    color: 0x262e5a, accent: 0x8a93ff, secure: true,
    assets: [{ asset: 'specialist_yard' }],
  },
  {
    id: 'data-vault', name: 'DATA VAULT',
    purpose: 'Local-private data, profile and evidence -- sealed.',
    role: 'Sealed local storage for profile, evidence and private data.',
    kind: 'vault', category: 'industrial', x: COL_R, z: ROW_C, footprint: 13, height: 8,
    color: 0x35291a, accent: 0xa78bfa, secure: true,
    assets: [{ asset: 'data_vault' }],
  },
  {
    id: 'policy-gate', name: 'POLICY + AUTH GATE',
    purpose: 'The checkpoint between the intelligence city and machine control.',
    role: 'Every machine action stops here until policy and auth approve it.',
    kind: 'gate', category: 'civic', x: COL_C, z: ROW_GATE, footprint: 12, height: 15,
    color: 0x2c3540, accent: 0xffffff, secure: true,
    assets: [{ asset: 'policy_gate' }],
  },
  {
    id: 'capability-center', name: 'CAPABILITY CENTER',
    purpose: 'Windows execution and the capability bus -- behind the gate.',
    role: 'Real Windows execution. Reachable only through the Policy Gate.',
    kind: 'capability', category: 'industrial', x: COL_C, z: ROW_CAP, footprint: 15, height: 17,
    color: 0x35291a, accent: 0xffb244, secure: true,
    assets: [{ asset: 'capability_center', x: -3.5 }],
  },
  {
    id: 'cloud-embassy', name: 'CLOUD EMBASSY',
    purpose: 'Outside the secure city -- intelligence only, never authority.',
    role: 'Cloud workers may think here. They never gain machine authority.',
    kind: 'embassy', category: 'cloud', x: COL_C, z: EMBASSY_Z, footprint: 14, height: 19,
    color: 0x3b3a52, accent: 0xc4b5fd, secure: false,
    assets: [{ asset: 'cloud_embassy' }],
  },
];

/** Environment buildings. These fill the blocks around the
 *  campus so ARGUS sits IN a city rather than on empty ground. They are
 *  scenery: never raycastable, never labelled with a capability, never in
 *  the district registry, and a gate checks that stays true. */
export interface SceneryPlacement {
  /** A GLB basename, or `proc:<kind>` for a procedural building built by
   *  cityDetail.ts (substation, warehouse, repair bay, parking structure). */
  asset: string;
  x: number;
  z: number;
  ry?: number;
  quarter: 'residential' | 'service' | 'commercial' | 'industrial' | 'utility';
  /** Environment name shown at building zoom. A name, never a
   *  status: nothing here is backed by an ARGUS system. */
  name?: string;
}

/** Every scenery building sits on a 19 x 15 plot (SCENERY_PLOT); positions are
 *  chosen so no plot touches a carriageway, a district block or another plot,
 *  and the layout keeps routes clear. */
export const SCENERY_PLOT = { halfW: 9.5, halfD: 7.5 };

export const SCENERY: SceneryPlacement[] = [
  // RESIDENTIAL / REST QUARTER, east of the campus beyond the perimeter avenue.
  { asset: 'residential_a', x: 80, z: -62, quarter: 'residential', name: 'RESIDENTIAL MODULES' },
  { asset: 'residential_b', x: 80, z: -44, quarter: 'residential' },
  { asset: 'residential_tower', x: 80, z: -14, quarter: 'residential' },
  { asset: 'residential_c', x: 80, z: 12, quarter: 'residential' },
  { asset: 'residential_b', x: 102, z: -52, ry: Math.PI, quarter: 'residential' },
  { asset: 'residential_a', x: 102, z: -26, ry: Math.PI, quarter: 'residential' },
  { asset: 'residential_c', x: 102, z: 2, ry: Math.PI, quarter: 'residential' },
  { asset: 'residential_b', x: 102, z: 30, ry: Math.PI, quarter: 'residential', name: 'REST · CHARGING LODGE' },
  { asset: 'shop_cafe', x: 80, z: 30, quarter: 'residential', name: 'FOOD · RECHARGE' },
  // Commercial blocks west of the campus.
  { asset: 'office_block_a', x: -80, z: -62, quarter: 'commercial' },
  { asset: 'office_block_b', x: -80, z: -44, quarter: 'commercial' },
  { asset: 'office_block_c', x: -80, z: -12, quarter: 'commercial' },
  { asset: 'office_block_d', x: -102, z: -52, ry: Math.PI, quarter: 'commercial' },
  { asset: 'office_block_e', x: -102, z: -24, ry: Math.PI, quarter: 'commercial' },
  { asset: 'office_block_a', x: -102, z: 4, ry: Math.PI, quarter: 'commercial' },
  { asset: 'office_block_d', x: -102, z: 30, ry: Math.PI, quarter: 'commercial' },
  // North commercial strip, behind Core Tower (clear of the north street).
  { asset: 'office_block_c', x: -38, z: -108, quarter: 'commercial' },
  { asset: 'office_block_e', x: 38, z: -108, quarter: 'commercial' },
  // UTILITY DISTRICT: the service yards south-west of Model Compute...
  { asset: 'utility_shed_b', x: -80, z: 18, quarter: 'utility' },
  { asset: 'utility_shed_a', x: -80, z: 34, quarter: 'utility' },
  { asset: 'office_block_c', x: -80, z: 56, quarter: 'utility' },
  // ...and the south-west band behind the gate, on its own service lane.
  { asset: 'shop_charging', x: -33, z: 49, quarter: 'service', name: 'ROBOT CHARGING STATION' },
  { asset: 'shop_parts', x: -61, z: 49, quarter: 'service', name: 'PARTS DEPOT' },
  { asset: 'shop_maintenance', x: -33, z: 67, quarter: 'utility', name: 'MAINTENANCE GARAGE' },
  { asset: 'proc:substation', x: -61, z: 67, quarter: 'utility', name: 'ENERGY SUBSTATION' },
  { asset: 'utility_shed_b', x: -33, z: 85, quarter: 'utility' },
  { asset: 'proc:warehouse', x: -61, z: 85, quarter: 'utility', name: 'STORAGE WAREHOUSE' },
  // South-east band: the service and civic side.
  { asset: 'shop_cafe', x: 33, z: 49, quarter: 'service', name: 'ARGUS DATA CAFÉ' },
  { asset: 'shop_supply', x: 61, z: 49, quarter: 'service', name: 'SUPPLY CENTER' },
  { asset: 'research_annex', x: 33, z: 67, quarter: 'commercial', name: 'RESEARCH ANNEX' },
  { asset: 'proc:repair', x: 61, z: 67, quarter: 'service', name: 'REPAIR BAY' },
  { asset: 'office_block_c', x: 33, z: 85, quarter: 'commercial', name: 'CITY SERVICES' },
  { asset: 'proc:parking', x: 61, z: 85, quarter: 'commercial', name: 'PARKING STRUCTURE' },
  { asset: 'transit_pavilion', x: 80, z: 48, quarter: 'service', name: 'TRANSIT STATION' },
];

/** Environment districts: named areas of scenery with their own
 *  architectural family. No backend concept lives in them, so they carry no
 *  status, no telemetry and no agents, and they are never in DISTRICTS. */
export interface EnvDistrict {
  id: string;
  name: string;
  category: DistrictCategory;
  purpose: string;
  x: number;
  z: number;
}

export const ENV_DISTRICTS: EnvDistrict[] = [
  { id: 'utility-district', name: 'UTILITY DISTRICT', category: 'utility',
    purpose: 'Power, parts, maintenance and storage yards. Environment only.', x: -62, z: 58 },
  { id: 'residential-quarter', name: 'RESIDENTIAL · REST QUARTER', category: 'residential',
    purpose: 'Robot rest, charging and standby housing. Environment only.', x: 91, z: -20 },
];

/* ---- the street network ------------------------------------------------
   Real carriageways laid in the gaps between blocks. `width` is
   the asphalt width in world units -- 6-7 is two ~3-unit lanes, matching the
   scale standard. Sidewalks are generated alongside every segment by the
   renderer, so they are not repeated here.

   DERIVED, not hand-tuned: avenues sit at the midpoint between adjacent
   column centres and cross streets at the midpoint between adjacent row
   centres, with a perimeter ring one half-spacing beyond. Hand-placing these
   is how a carriageway ends up buried under a building the moment a footprint
   changes -- computing them keeps every street in a real gap by construction. */

export type StreetKind = 'avenue' | 'street' | 'service';

export interface Street {
  x1: number; z1: number; x2: number; z2: number;
  width: number;
  kind: StreetKind;
}

const mid = (a: number, b: number) => (a + b) / 2;

/** N-S avenue centres: between each pair of columns, plus a perimeter ring. */
export const AVENUE_X: number[] = (() => {
  const inner = COLS.slice(0, -1).map((c, i) => mid(c, COLS[i + 1]));
  const halfSpan = (COLS[1] - COLS[0]) / 2;
  return [COLS[0] - halfSpan, ...inner, COLS[COLS.length - 1] + halfSpan];
})();

/** E-W cross-street centres: between each pair of rows, plus a perimeter
 *  street beyond the first AND the last row. (The south perimeter used to be
 *  `last - halfSpan`, i.e. two units from the inner street, which left the
 *  south row facing no street and ran the gate spine through the Specialist
 *  District's block; the layout keeps it clear.) */
export const CROSS_Z: number[] = (() => {
  const inner = ROWS.slice(0, -1).map((r, i) => mid(r, ROWS[i + 1]));
  const halfSpan = (ROWS[1] - ROWS[0]) / 2;
  return [ROWS[0] - halfSpan, ...inner, ROWS[ROWS.length - 1] + halfSpan];
})();

const NORTH_Z = CROSS_Z[0];
const SOUTH_Z = CROSS_Z[CROSS_Z.length - 1];

export const STREETS: Street[] = [
  // North-south avenues, running the depth of the campus.
  ...AVENUE_X.map((x, i): Street => ({
    x1: x, z1: NORTH_Z, x2: x, z2: SOUTH_Z,
    width: i === 0 || i === AVENUE_X.length - 1 ? 6 : 7,
    kind: i === 0 || i === AVENUE_X.length - 1 ? 'street' : 'avenue',
  })),
  // East-west cross streets, spanning the full campus width.
  ...CROSS_Z.map((z): Street => ({
    x1: AVENUE_X[0] - 4, z1: z, x2: AVENUE_X[AVENUE_X.length - 1] + 4, z2: z,
    width: z === SOUTH_Z ? 7 : 6,
    kind: z === SOUTH_Z ? 'avenue' : 'street',
  })),
  // The southern spine: the ONLY road to the Capability Center, and it runs
  // straight through the Policy + Auth Gate's arch by design.
  { x1: COL_C, z1: SOUTH_Z - 3, x2: COL_C, z2: ROW_CAP - 17, width: 7, kind: 'avenue' },
  // The one service road out to the Cloud Embassy. Nothing connects it to
  // the southern spine -- "outside the secure city" is stated by the road
  // network, not only by distance.
  { x1: COL_C, z1: NORTH_Z + 3, x2: COL_C, z2: EMBASSY_Z + 16, width: 5, kind: 'service' },
  // Service lanes serving the scenery quarters either side of the campus.
  { x1: AVENUE_X[0] - 4, z1: ROW_B, x2: AVENUE_X[0] - 26, z2: ROW_B, width: 5, kind: 'service' },
  { x1: AVENUE_X[AVENUE_X.length - 1] + 4, z1: ROW_B, x2: AVENUE_X[AVENUE_X.length - 1] + 26, z2: ROW_B, width: 5, kind: 'service' },
  // The south bands' own lanes, between their two columns of buildings. Like
  // every service street they are parking and deliveries, not through roads:
  // neither touches the spine, so nothing reaches the Capability Center except
  // through the gate.
  { x1: -47, z1: SOUTH_Z + 3.5, x2: -47, z2: 94, width: 5, kind: 'service' },
  { x1: 47, z1: SOUTH_Z + 3.5, x2: 47, z2: 94, width: 5, kind: 'service' },
];

// Where avenues meet cross streets -- the renderer paves these as proper
// intersections (no lane markings, pedestrian crossings on the approaches)
// instead of letting two carriageways z-fight.
export const INTERSECTIONS: { x: number; z: number; size: number }[] = [];
for (const x of AVENUE_X) {
  for (const z of CROSS_Z) INTERSECTIONS.push({ x, z, size: 7.6 });
}
INTERSECTIONS.push({ x: COL_C, z: SOUTH_Z, size: 8.4 });


// Which districts are adjacent for ROUTE purposes. CITY-2 uses this to
// brighten a route when the backend reports both endpoints busy, and CITY-4
// reuses it as the robot walking graph -- one graph, so a robot
// can never take a path the city has no street for. Cloud Embassy connects
// ONLY to Core Tower; no edge anywhere reaches the Gate/Capability side from
// it ("no route may bypass the gate").
export const ROADS: [string, string][] = [
  ['security-district', 'core-tower'], ['core-tower', 'academy'],
  ['security-district', 'operations-center'], ['core-tower', 'agent-hq'], ['academy', 'verification-institute'],
  ['operations-center', 'agent-hq'], ['agent-hq', 'verification-institute'],
  ['operations-center', 'model-plant'], ['agent-hq', 'specialist-district'], ['verification-institute', 'data-vault'],
  ['model-plant', 'specialist-district'], ['specialist-district', 'data-vault'],
  ['specialist-district', 'policy-gate'], ['policy-gate', 'capability-center'],
  ['core-tower', 'cloud-embassy'],
];

/* ---- ground rectangles (shared by cityDetail.ts and the layout check) --- */
export interface Rect { x0: number; x1: number; z0: number; z1: number; what: string }

/** A street's asphalt (carriageway only -- not its sidewalks). */
export function streetRect(s: Street, i = 0): Rect {
  const h = s.width / 2;
  return { x0: Math.min(s.x1, s.x2) - (s.x1 === s.x2 ? h : 0), x1: Math.max(s.x1, s.x2) + (s.x1 === s.x2 ? h : 0),
           z0: Math.min(s.z1, s.z2) - (s.z1 === s.z2 ? h : 0), z1: Math.max(s.z1, s.z2) + (s.z1 === s.z2 ? h : 0),
           what: `street#${i}(${s.kind})` };
}

/** A district's buildable block (the gate has none: it straddles the spine). */
export function districtRect(d: District, pad = 0): Rect {
  const f = d.footprint + pad;
  return { x0: d.x - f, x1: d.x + f, z0: d.z - f, z1: d.z + f, what: d.id };
}

/** A scenery building's plot. */
export function plotRect(p: SceneryPlacement, pad = 0): Rect {
  return { x0: p.x - SCENERY_PLOT.halfW - pad, x1: p.x + SCENERY_PLOT.halfW + pad,
           z0: p.z - SCENERY_PLOT.halfD - pad, z1: p.z + SCENERY_PLOT.halfD + pad,
           what: `${p.name ?? p.asset}@${p.x},${p.z}` };
}

export function overlaps(a: Rect, b: Rect, eps = 0.01): boolean {
  return a.x0 < b.x1 - eps && b.x0 < a.x1 - eps && a.z0 < b.z1 - eps && b.z0 < a.z1 - eps;
}

export function inside(x: number, z: number, r: Rect): boolean {
  return x > r.x0 && x < r.x1 && z > r.z0 && z < r.z1;
}

export function findDistrict(id: string): District | undefined {
  return DISTRICTS.find((d) => d.id === id);
}

/** Adjacency list form of ROADS -- built once, used by the robot pathfinder. */
export const ROAD_GRAPH: Record<string, string[]> = (() => {
  const g: Record<string, string[]> = {};
  for (const [a, b] of ROADS) {
    (g[a] ??= []).push(b);
    (g[b] ??= []).push(a);
  }
  return g;
})();

/** Shortest district-to-district route over the real street graph (BFS --
 *  the graph has 12 nodes, so anything cleverer would be ceremony). Returns
 *  the full node list including both ends, or null when unreachable, which
 *  is itself meaningful: nothing can reach the Capability Center without
 *  passing through the Policy + Auth Gate. */
export function routeBetween(fromId: string, toId: string): string[] | null {
  if (fromId === toId) return [fromId];
  const prev = new Map<string, string>([[fromId, '']]);
  const queue = [fromId];
  while (queue.length) {
    const at = queue.shift()!;
    for (const next of ROAD_GRAPH[at] ?? []) {
      if (prev.has(next)) continue;
      prev.set(next, at);
      if (next === toId) {
        const path = [toId];
        let cur = toId;
        while (prev.get(cur)) { cur = prev.get(cur)!; path.unshift(cur); }
        return path;
      }
      queue.push(next);
    }
  }
  return null;
}
