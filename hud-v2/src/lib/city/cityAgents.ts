/* ARGUS AI City -- robot citizens.
   ==========================================================================

   CORE LAW: the city visualises ARGUS, it never invents ARGUS.

   Everything an agent robot does here is a pure function of a state string
   the backend actually reported:

     destinationFor(role, state) -> where it walks
     clipFor(state)              -> which animation it plays

   Idle agents remain in their home district. No clock-driven operational
   movement is invented when the backend has not reported work.

   No agent is ever shown studying, working or verifying unless the backend
   said so. There is no filler population: the inhabitants are the real ten
   core agents plus whatever temporary specialists genuinely exist.
*/

import * as THREE from 'three';
import { AVENUE_X, CROSS_Z, findDistrict, type District } from './cityLayout';
import { instantiate, type LoadedModel } from './cityAssets';
import { ROLE_ACCENT } from './cityPalette';
import type { SceneLabel } from './cityLabels';

export const WALK_SPEED = 6.0;        // units/second at 1 unit = 1 metre
export const KERB_H = 0.22;
/** Robots are drawn larger than life -- 1.5x, the Manager 1.9x. At true
 *  scale a 1.75m robot was ~5px tall in the city overview: present, but not
 *  visible. The ground halo does the rest at wide zoom. */
export const AGENT_SCALE = 1.5;
export const MANAGER_SCALE = 1.9;

/** Where an agent stands when it has arrived: its own spot on the pavement
 *  outside the door, in the door's local frame (x along the frontage, z
 *  toward the building). Before this every robot at a district stood on the
 *  SAME point -- ten robots and ten labels stacked into one blob. */
export function slotOffset(kind: AgentKind, index: number): [number, number] {
  if (kind === 'manager') return [0, 1.4];
  // 3 units apart: with the name tags staggered on two heights, neighbours'
  // tags clear each other from building zoom inward.
  if (kind === 'core') return [(index < 5 ? -(index + 1) : index - 4) * 3.0, 0];
  // Specialists (at most 6 shown) stand a step nearer the building, either
  // side of the Manager's spot at the door. Any wider and they reached the
  // frontage annexes; any nearer and they stood on the block itself.
  const i = Math.max(0, index - 10);
  return [(i % 2 ? 1 : -1) * (1.6 + Math.floor(i / 2) * 1.8), 1.4];
}

/* ==========================================================================
   1. PEDESTRIAN NAVIGATION NETWORK
   ========================================================================== */

export interface NavNode {
  id: string;
  pos: THREE.Vector3;
  links: string[];
  /** Set when this node is a building's doorway rather than a street corner. */
  districtId?: string;
}

export interface NavGraph {
  nodes: Map<string, NavNode>;
  /** districtId -> the door node standing outside that building. */
  doors: Map<string, string>;
}

/** Build the sidewalk graph from the street grid. Nodes sit at every
 *  avenue/cross-street junction; edges run along the streets that actually
 *  exist. Each district then gets a door node, wired straight out to the
 *  street it faces and along it to the junctions either side.
 *
 *  A robot can therefore only ever travel on pavement the city has drawn --
 *  which is what stops it walking diagonally through a building. */
export function buildNavGraph(districts: District[]): NavGraph {
  const nodes = new Map<string, NavNode>();
  const doors = new Map<string, string>();

  const key = (ix: number, iz: number) => `j${ix}_${iz}`;
  for (let ix = 0; ix < AVENUE_X.length; ix++) {
    for (let iz = 0; iz < CROSS_Z.length; iz++) {
      nodes.set(key(ix, iz), {
        id: key(ix, iz),
        pos: new THREE.Vector3(AVENUE_X[ix], KERB_H, CROSS_Z[iz]),
        links: [],
      });
    }
  }
  // Orthogonal links only: the grid has no diagonal streets.
  for (let ix = 0; ix < AVENUE_X.length; ix++) {
    for (let iz = 0; iz < CROSS_Z.length; iz++) {
      const n = nodes.get(key(ix, iz))!;
      if (ix + 1 < AVENUE_X.length) link(n, nodes.get(key(ix + 1, iz))!);
      if (iz + 1 < CROSS_Z.length) link(n, nodes.get(key(ix, iz + 1))!);
    }
  }

  for (const d of districts) {
    // The doorway sits on the block's own sidewalk, on the side facing the
    // street the entrance was modelled on (+Z for everything except the
    // Capability Center, which faces back north toward the Policy Gate).
    const side = d.id === 'capability-center' ? -1 : 1;
    const doorPos = new THREE.Vector3(d.x, KERB_H, d.z + side * (d.footprint + 2.4));
    const door: NavNode = { id: `door_${d.id}`, pos: doorPos, links: [], districtId: d.id };
    nodes.set(door.id, door);
    doors.set(d.id, door.id);

    // Door -> straight out to the street it faces -> along that street to the
    // junction either side. The old diagonal door-to-nearest-junction links
    // cut across the front yard, through whatever stood on it.
    const iz = CROSS_Z.reduce((best, z, i) => (Math.abs(z - doorPos.z) < Math.abs(CROSS_Z[best] - doorPos.z) ? i : best), 0);
    const kerb: NavNode = { id: `kerb_${d.id}`, pos: new THREE.Vector3(d.x, KERB_H, CROSS_Z[iz]), links: [] };
    nodes.set(kerb.id, kerb);
    link(door, kerb);
    const ix = AVENUE_X.findIndex((x) => x > d.x);
    for (const i of [ix - 1, ix]) {
      const j = nodes.get(key(i, iz));
      if (j) link(kerb, j);
    }
  }

  return { nodes, doors };
}

function link(a: NavNode, b: NavNode): void {
  if (!a.links.includes(b.id)) a.links.push(b.id);
  if (!b.links.includes(a.id)) b.links.push(a.id);
}

/** A* over the sidewalk graph. The graph has ~40 nodes, so this is instant;
 *  it is A* rather than BFS because the edges have real, unequal lengths and
 *  a shortest-hop path would happily send a robot the long way round. */
export function findPath(graph: NavGraph, fromId: string, toId: string): THREE.Vector3[] {
  if (fromId === toId) return [];
  const start = graph.nodes.get(fromId);
  const goal = graph.nodes.get(toId);
  if (!start || !goal) return [];

  const open = new Set<string>([fromId]);
  const cameFrom = new Map<string, string>();
  const g = new Map<string, number>([[fromId, 0]]);
  const f = new Map<string, number>([[fromId, start.pos.distanceTo(goal.pos)]]);

  while (open.size) {
    let current = '';
    let best = Infinity;
    for (const id of open) {
      const score = f.get(id) ?? Infinity;
      if (score < best) { best = score; current = id; }
    }
    if (current === toId) {
      const out: THREE.Vector3[] = [];
      let at: string | undefined = current;
      while (at) {
        out.unshift(graph.nodes.get(at)!.pos.clone());
        at = cameFrom.get(at);
      }
      out.shift();          // drop the node we are already standing on
      return out;
    }
    open.delete(current);
    const node = graph.nodes.get(current)!;
    for (const nextId of node.links) {
      const next = graph.nodes.get(nextId)!;
      const tentative = (g.get(current) ?? Infinity) + node.pos.distanceTo(next.pos);
      if (tentative < (g.get(nextId) ?? Infinity)) {
        cameFrom.set(nextId, current);
        g.set(nextId, tentative);
        f.set(nextId, tentative + next.pos.distanceTo(goal.pos));
        open.add(nextId);
      }
    }
  }
  return [];
}

/* ==========================================================================
   2. BACKEND STATE -> BEHAVIOUR  (the only source of agent meaning)
   ========================================================================== */

/** Which district each core agent works in when the backend says it is
 *  actually executing. Straight from the ARGUS role map. */
export const AGENT_HOME: Record<string, string> = {
  security: 'security-district',
  threat: 'security-district',
  forensics: 'security-district',
  response: 'security-district',
  system: 'operations-center',
  network: 'operations-center',
  diagnostics: 'operations-center',
  verifier: 'verification-institute',
  planner: 'agent-hq',
  assistant: 'agent-hq',
};

/** Animation clip, as a pure function of the reported state. */
export function clipFor(state: string, walking: boolean): string {
  if (walking) return 'WALK';
  switch (state) {
    case 'thinking': return 'THINK';
    case 'verifying': return 'VERIFY';
    case 'executing': case 'responding': return 'TYPE';
    case 'preparing': case 'active': return 'WORK_AT_DESK';
    case 'queued': case 'waiting_auth': case 'waiting': case 'proposed': case 'validating':
      return 'WAIT';
    case 'training': case 'studying': return 'STUDY';
    case 'enrolled': return 'WAIT';
    case 'error': case 'blocked': case 'failed': return 'WAIT';
    default: return 'IDLE';
  }
}

/** Destination district, as a pure function of the reported state.
 *
 *  An agent lives in its own department (the backend's own city_location,
 *  agents/agent_manager.CITY_HOME -- the same place "where is SECURITY?"
 *  answers). It walks to Agent HQ, where the team operations room and its
 *  desk are, only while the backend reports it working; to the Institute
 *  while verifying; and home to execute in its own district. When the work
 *  ends it walks back. Nothing else moves it. */
export function destinationFor(role: string, state: string): string {
  const home = AGENT_HOME[role] ?? 'agent-hq';
  if (state === 'verifying') return 'verification-institute';
  if (state === 'executing') return home;
  if (WORKING_STATES.has(state) || state === 'queued' || state === 'waiting_auth') return 'agent-hq';
  // At the Academy (agents/academy.py): 'studying' while its lesson runs,
  // 'enrolled' while it waits its turn on the shared model -- both are there.
  if (state === 'training' || state === 'studying' || state === 'enrolled') return 'academy';
  return home;
}

/* ==========================================================================
   3. THE AGENT INSTANCES
   ========================================================================== */

export type AgentKind = 'core' | 'temp' | 'cloud' | 'manager';

export interface CityAgent {
  id: string;
  role: string;
  kind: AgentKind;
  index: number;
  root: THREE.Group;
  mixer: THREE.AnimationMixer;
  actions: Map<string, THREE.AnimationAction>;
  currentClip: string;
  /** Per-instance emissive materials -- visor and chest core. Cloned, so
   *  recolouring one robot never tints the rest. */
  accents: THREE.MeshStandardMaterial[];
  /** Flat ring on the pavement in the role colour: what makes an agent
   *  findable as a coloured dot in the city overview. */
  halo: THREE.Mesh;
  /** Invisible, cheap raycast volume -- hover/click test this instead of the
   *  skinned mesh, which would have to be re-skinned on the CPU per test. */
  hit: THREE.Mesh;
  atDistrict: string;
  goalDistrict: string;
  path: THREE.Vector3[];
  /** Backend state as last reported. Displayed verbatim; never inferred. */
  state: string;
  label: SceneLabel | null;
}

/** Reported states that mean "doing something right now". */
export const WORKING_STATES = new Set([
  'thinking', 'responding', 'executing', 'preparing', 'active', 'verifying', 'running', 'coordinating',
]);
const FAULT_STATES = new Set(['error', 'blocked', 'failed']);
const DARK_STATES = new Set(['disabled', 'offline', 'expired', 'destroyed']);

const HALO_GEO = new THREE.RingGeometry(0.62, 1.08, 40);
const HIT_GEO = new THREE.CylinderGeometry(0.95, 0.95, 2.6, 8);
const HIT_MAT = new THREE.MeshBasicMaterial();

export class AgentPool {
  private model: LoadedModel;
  private graph: NavGraph;
  private group: THREE.Group;
  agents = new Map<string, CityAgent>();
  private free: CityAgent[] = [];
  private scratch = new THREE.Vector3();

  constructor(model: LoadedModel, graph: NavGraph, parent: THREE.Group) {
    this.model = model;
    this.graph = graph;
    this.group = new THREE.Group();
    this.group.name = 'city-agents';
    parent.add(this.group);
  }

  private makeInstance(accent: number): CityAgent {
    // Skinned clone: a plain clone would leave every robot bound to the
    // source skeleton and they would all animate in lockstep.
    const root = instantiate(this.model, { skinned: true, isolateMaterials: true });
    root.scale.setScalar(1);
    const mixer = new THREE.AnimationMixer(root);
    const actions = new Map<string, THREE.AnimationAction>();
    for (const clip of this.model.animations) {
      const action = mixer.clipAction(clip);
      action.setLoop(THREE.LoopRepeat, Infinity);
      actions.set(clip.name, action);
    }
    const accents: THREE.MeshStandardMaterial[] = [];
    root.traverse((child: THREE.Object3D) => {
      if (!(child instanceof THREE.Mesh)) return;
      const mats = Array.isArray(child.material) ? child.material : [child.material];
      for (const m of mats) {
        const std = m as THREE.MeshStandardMaterial;
        if (std?.name?.includes('Visor')) accents.push(std);
      }
    });
    for (const m of accents) {
      m.color.set(accent);
      m.emissive.set(accent);
    }
    // Unlit and not tone-mapped, so the halo keeps its exact role colour
    // under any lighting; depthWrite off so it never z-fights the pavement.
    const halo = new THREE.Mesh(HALO_GEO, new THREE.MeshBasicMaterial({
      color: accent, transparent: true, opacity: 0.8, depthWrite: false, toneMapped: false,
      side: THREE.DoubleSide,
    }));
    halo.rotation.x = -Math.PI / 2;
    halo.position.y = 0.04;
    halo.renderOrder = 2;
    root.add(halo);
    const hit = new THREE.Mesh(HIT_GEO, HIT_MAT);
    hit.position.y = 1.3;
    hit.visible = false;     // never drawn; Raycaster ignores `visible`
    root.add(hit);
    this.group.add(root);
    return {
      id: '', role: '', kind: 'core', index: 0, root, mixer, actions,
      currentClip: '', accents, halo, hit, atDistrict: 'agent-hq', goalDistrict: 'agent-hq',
      path: [], state: 'idle', label: null,
    };
  }

  /** The agent's own standing spot outside a district's door. */
  slotPos(agent: CityAgent, districtId: string): THREE.Vector3 | null {
    const door = this.graph.nodes.get(this.graph.doors.get(districtId) ?? '');
    if (!door) return null;
    const d = findDistrict(districtId);
    const side = d && door.pos.z < d.z ? -1 : 1;
    const [sx, sz] = slotOffset(agent.kind, agent.index);
    return door.pos.clone().add(new THREE.Vector3(sx, 0, -side * sz));
  }

  spawn(id: string, role: string, kind: AgentKind, index: number, startDistrict: string): CityAgent {
    const accent = ROLE_ACCENT[role] ?? 0x38e0ff;
    const agent = this.free.pop() ?? this.makeInstance(accent);
    agent.id = id;
    agent.role = role;
    agent.kind = kind;
    agent.index = index;
    agent.atDistrict = startDistrict;
    agent.goalDistrict = startDistrict;
    agent.path = [];
    agent.root.visible = true;
    agent.root.scale.setScalar(kind === 'manager' ? MANAGER_SCALE : AGENT_SCALE);
    this.setState(agent, 'idle');
    const at = this.slotPos(agent, startDistrict);
    if (at) agent.root.position.copy(at);
    this.play(agent, 'IDLE', 0);
    this.agents.set(id, agent);
    return agent;
  }

  /** Record a reported state and colour the robot from it. Idle wears the
   *  ROLE colour (identity, no claim); working wears the reported state's
   *  colour; faults go red, a dead link goes grey. */
  setState(agent: CityAgent, state: string, stateColor?: number): void {
    agent.state = state;
    const role = ROLE_ACCENT[agent.role] ?? 0x38e0ff;
    const fault = FAULT_STATES.has(state);
    const dark = DARK_STATES.has(state);
    // The visor reports state (grey on a dead link); the halo is IDENTITY and
    // keeps the role colour -- dimmed, not greyed, by update() -- so the
    // agent stays findable while its tag says DISCONNECTED. Only a real
    // fault takes the halo over, because that is a signal worth seeing.
    const visor = fault ? 0xff4a4a : dark ? 0x8793a0 : state === 'idle' ? role : (stateColor ?? role);
    for (const m of agent.accents) { m.color.set(visor); m.emissive.set(visor); }
    (agent.halo.material as THREE.MeshBasicMaterial).color.set(fault ? 0xff4a4a : role);
  }

  despawn(id: string): void {
    const agent = this.agents.get(id);
    if (!agent) return;
    this.agents.delete(id);
    agent.root.visible = false;
    agent.path = [];
    agent.mixer.stopAllAction();
    // Pooled, not destroyed: a team that spawns and reaps specialists must
    // not churn skinned geometry every cycle.
    this.free.push(agent);
  }

  /** Cross-fade to a clip. No-op when already playing it, so a store update
   *  at 10Hz does not restart the animation ten times a second. */
  play(agent: CityAgent, clipName: string, fade = 0.25): void {
    if (agent.currentClip === clipName) return;
    const next = agent.actions.get(clipName);
    if (!next) return;
    const prev = agent.actions.get(agent.currentClip);
    next.reset();
    next.enabled = true;
    next.setEffectiveWeight(1);
    next.play();
    if (prev && fade > 0) prev.crossFadeTo(next, fade, false);
    else if (prev) prev.stop();
    agent.currentClip = clipName;
  }

  /** Point an agent at a district. Recomputes the pavement path via A*. */
  setGoal(agent: CityAgent, districtId: string): void {
    if (agent.goalDistrict === districtId) return;
    agent.goalDistrict = districtId;
    const fromDoor = this.graph.doors.get(agent.atDistrict);
    const toDoor = this.graph.doors.get(districtId);
    if (!fromDoor || !toDoor) { agent.atDistrict = districtId; return; }
    agent.path = findPath(this.graph, fromDoor, toDoor);
    // Finish on the agent's own spot, not on the shared door node.
    const slot = this.slotPos(agent, districtId);
    if (agent.path.length && slot) agent.path[agent.path.length - 1] = slot;
    if (!agent.path.length) agent.atDistrict = districtId;
  }

  update(dt: number, t: number): void {
    for (const agent of this.agents.values()) {
      // Halo: steady when idle, a slow breath while the backend reports the
      // agent working, dim when the link is down. Opacity only -- the colour
      // is owned by setState().
      const halo = agent.halo.material as THREE.MeshBasicMaterial;
      halo.opacity = DARK_STATES.has(agent.state) ? 0.45
        : WORKING_STATES.has(agent.state) || FAULT_STATES.has(agent.state)
          ? 0.6 + 0.4 * Math.abs(Math.sin(t * 2.4 + agent.index))
          : 0.75;
      if (agent.path.length) {
        const target = agent.path[0];
        this.scratch.subVectors(target, agent.root.position);
        this.scratch.y = 0;
        const dist = this.scratch.length();
        if (dist < 0.4) {
          agent.path.shift();
          if (!agent.path.length) agent.atDistrict = agent.goalDistrict;
        } else {
          this.scratch.multiplyScalar(Math.min(1, (WALK_SPEED * dt) / dist));
          agent.root.position.add(this.scratch);
          // Face the direction of travel; the asset is modelled facing +Z.
          const want = Math.atan2(target.x - agent.root.position.x, target.z - agent.root.position.z);
          agent.root.rotation.y = shortestAngle(agent.root.rotation.y, want, dt * 9);
        }
        this.play(agent, 'WALK');
      } else {
        this.play(agent, clipFor(agent.state, false));
        const d = findDistrict(agent.atDistrict);
        if (d) {
          // Stand facing the street, away from the building: a robot that
          // faces its door shows the default camera nothing but its back.
          const want = agent.root.position.z >= d.z ? 0 : Math.PI;
          agent.root.rotation.y = shortestAngle(agent.root.rotation.y, want, dt * 4);
        }
      }
      agent.mixer.update(dt);
    }
  }

  /** The live agents' raycast volumes, for hover/click. */
  hitTargets(): THREE.Object3D[] {
    return [...this.agents.values()].map((a) => a.hit);
  }

  agentForHit(obj: THREE.Object3D): CityAgent | null {
    for (const a of this.agents.values()) if (a.hit === obj) return a;
    return null;
  }

  setVisible(v: boolean): void { this.group.visible = v; }

  dispose(): void {
    for (const agent of [...this.agents.values(), ...this.free]) {
      agent.mixer.stopAllAction();
      agent.accents.forEach((m) => m.dispose());
      (agent.halo.material as THREE.Material).dispose();
      agent.label?.obj.removeFromParent();
      agent.root.removeFromParent();
    }
    this.agents.clear();
    this.free.length = 0;
    this.group.removeFromParent();
  }
}

/** Rotate `from` toward `to` the short way round, at most `step` radians.
 *  Without the wrap a robot turning past PI spins the long way and reads as
 *  a glitch. */
export function shortestAngle(from: number, to: number, step: number): number {
  let delta = (to - from) % (Math.PI * 2);
  if (delta > Math.PI) delta -= Math.PI * 2;
  if (delta < -Math.PI) delta += Math.PI * 2;
  return from + THREE.MathUtils.clamp(delta, -step, step);
}
