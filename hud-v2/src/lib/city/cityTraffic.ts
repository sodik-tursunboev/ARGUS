/* ARGUS AI City -- street traffic.
   ==========================================================================

   SCENERY, NOT DATA. Vehicles are what make a grid of streets read as a city;
   they carry no meaning about ARGUS -- no agent rides in one, no job moves
   because of one, and nothing in the HUD counts them. That is the same
   status the trees, benches and street lamps have (cityKit.buildStreetProps),
   and it is why this module never imports a store.

   Every vehicle drives the REAL street network from cityLayout.STREETS:
   right-hand lanes 1.6 m either side of the centre line, turning back at the
   end of its street onto the opposite lane. Parked vehicles line the service
   roads, where no moving traffic runs.

   Five vehicle classes -- city car, compact, ARGUS maintenance van,
   utility truck, autonomous shuttle -- share the same instanced parts, scaled
   per class, plus a livery stripe and a roof beacon: seven InstancedMeshes for
   the whole fleet, matrices rewritten each frame, no allocation.

   Right of way: a vehicle keeps its distance from the one ahead in its lane
   and waits at an intersection another vehicle is crossing, so traffic never
   drives through itself. */

import * as THREE from 'three';
import { seeded01 } from './cityKit';
import type { Street } from './cityLayout';

const PAINTS = [0xe8eaed, 0xaeb5bd, 0x1c1f24, 0x4a5058, 0x1f3a5f, 0x8e2530,
                0x1f6f78, 0xc9b28a, 0x2d5fa8, 0xf0f0f0, 0x5c6b73];

const LANE_OFFSET = 1.6;
const FOLLOW_GAP = 3.2;       // metres of clear road kept to the vehicle ahead
const YIELD_RANGE = 5.5;      // how far before an intersection a vehicle checks it

export type VehicleClass = 'car' | 'compact' | 'van' | 'truck' | 'shuttle';

/** Per-class proportions, in metres. `cab` is the glazed part: its length is
 *  a fraction of the body, `cz` shifts it toward the front (+) or back (-). */
interface ClassSpec {
  len: number; width: number; bodyH: number; bodyY: number;
  cabLen: number; cabH: number; cabY: number; cz: number; cabW: number;
  wheelR: number; speed: [number, number]; paint?: number;
  stripe?: number; beacon?: number;
}
export const VEHICLES: Record<VehicleClass, ClassSpec> = {
  car:     { len: 4.3, width: 1.8, bodyH: 0.62, bodyY: 0.55, cabLen: 0.52, cabH: 0.5, cabY: 1.08, cz: -0.2, cabW: 0.87, wheelR: 0.34, speed: [7, 12] },
  compact: { len: 3.4, width: 1.6, bodyH: 0.6, bodyY: 0.52, cabLen: 0.6, cabH: 0.55, cabY: 1.05, cz: -0.05, cabW: 0.88, wheelR: 0.3, speed: [6, 10] },
  // ARGUS maintenance van: tall white box, glazed front, cyan livery stripe.
  van:     { len: 4.9, width: 1.95, bodyH: 1.55, bodyY: 1.0, cabLen: 0.2, cabH: 0.62, cabY: 1.35, cz: 0.42, cabW: 0.92, wheelR: 0.36, speed: [6, 9], paint: 0xf3f5f7, stripe: 0x38e0ff },
  // Utility truck: long service bed, glazed cab up front, amber roof beacon.
  truck:   { len: 6.4, width: 2.1, bodyH: 1.3, bodyY: 0.95, cabLen: 0.26, cabH: 0.7, cabY: 1.95, cz: 0.36, cabW: 0.9, wheelR: 0.42, speed: [5, 8], paint: 0xe0a93a, beacon: 0xffb244 },
  // Autonomous shuttle: glass all round, white skirt, cyan stripe, slow.
  shuttle: { len: 6.0, width: 2.2, bodyH: 0.85, bodyY: 0.62, cabLen: 0.92, cabH: 1.15, cabY: 1.62, cz: 0, cabW: 0.97, wheelR: 0.36, speed: [4, 5.5], paint: 0xf5f7fa, stripe: 0x38e0ff },
};

interface Vehicle {
  cls: VehicleClass;
  street: number;
  dir: 1 | -1;            // +1 = x1->x2 / z1->z2
  s: number;              // distance along the street
  speed: number;          // cruise speed, m/s
  parked: boolean;
  x: number; z: number; yaw: number;
}

export const PARKED_PER_SERVICE = 7;

/** Where vehicles park along a service street: distance along it, and which
 *  side of the centre line (+1 = left of x1->x2 travel). One definition, used
 *  by Traffic and by cityDetail's painted bays. */
export function parkedSlots(s: Street, perService = PARKED_PER_SERVICE): { s: number; side: 1 | -1; dir: 1 | -1 }[] {
  const len = Math.hypot(s.x2 - s.x1, s.z2 - s.z1);
  const k = Math.min(perService, Math.floor(len / 6.5));
  const out: { s: number; side: 1 | -1; dir: 1 | -1 }[] = [];
  for (let p = 0; p < k; p++) {
    const dir: 1 | -1 = p % 2 === 0 ? 1 : -1;
    out.push({ s: 4 + p * ((len - 8) / Math.max(1, k - 1)), side: dir, dir });
  }
  return out;
}

/** Deterministic class mix for the n-th moving vehicle: mostly cars, a few
 *  vans and trucks, and shuttles only on the avenues. */
function movingClass(n: number, avenue: boolean): VehicleClass {
  if (avenue && n % 11 === 4) return 'shuttle';
  if (n % 7 === 3) return 'van';
  if (n % 9 === 5) return 'truck';
  if (n % 3 === 1) return 'compact';
  return 'car';
}

export class Traffic {
  group = new THREE.Group();
  private cars: Vehicle[] = [];
  private streets: Street[];
  private intersections: { x: number; z: number; size: number }[];
  private body!: THREE.InstancedMesh;
  private cabin!: THREE.InstancedMesh;
  private wheels!: THREE.InstancedMesh;
  private heads!: THREE.InstancedMesh;
  private tails!: THREE.InstancedMesh;
  private stripes!: THREE.InstancedMesh;
  private beacons!: THREE.InstancedMesh;
  private part = new THREE.Object3D();

  constructor(streets: Street[], intersections: { x: number; z: number; size: number }[] = [],
    moving = 30, parkedPerService = PARKED_PER_SERVICE) {
    this.group.name = 'city-traffic';
    this.group.userData.scenery = true;
    this.streets = streets;
    this.intersections = intersections;
    const driveable = streets.map((s, i) => ({ s, i })).filter(({ s }) => s.kind !== 'service');
    const service = streets.map((s, i) => ({ s, i })).filter(({ s }) => s.kind === 'service');
    // Moving vehicles spread along the driveable streets, deterministic so the
    // city looks the same every time it opens (no random flicker).
    for (let n = 0; n < moving && driveable.length; n++) {
      const { s, i } = driveable[n % driveable.length];
      const len = Math.hypot(s.x2 - s.x1, s.z2 - s.z1);
      const cls = movingClass(n, s.kind === 'avenue');
      const [lo, hi] = VEHICLES[cls].speed;
      const car: Vehicle = { cls, street: i, dir: n % 2 === 0 ? 1 : -1,
        s: 2 + seeded01(n * 17 + 3) * (len - 4), speed: lo + seeded01(n * 5) * (hi - lo), parked: false,
        x: 0, z: 0, yaw: 0 };
      // Never spawn on top of another vehicle in the same lane: step along
      // the street until the spot is clear (wrapping round the ends).
      for (let tries = 0; tries < 40 && !this.laneClear(car, car.dir); tries++) {
        car.s = 2 + ((car.s - 2 + 9) % (len - 4));
      }
      this.cars.push(car);
    }
    for (const { s, i } of service) {
      const len = Math.hypot(s.x2 - s.x1, s.z2 - s.z1);
      parkedSlots(s, parkedPerService).forEach((slot, p) => {
        // Service lanes park the working fleet too: a van or truck in four.
        const cls: VehicleClass = p % 4 === 1 ? 'van' : p % 4 === 3 && len > 40 ? 'truck'
          : p % 2 ? 'compact' : 'car';
        this.cars.push({ cls, street: i, dir: slot.dir, s: slot.s, speed: 0, parked: true,
          x: 0, z: 0, yaw: 0 });
      });
    }
    this.build();
    this.update(0);
  }

  private build(): void {
    const n = this.cars.length;
    const paint = new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.32, metalness: 0.55 });
    const glass = new THREE.MeshStandardMaterial({ color: 0x14202c, roughness: 0.08, metalness: 0.6 });
    const rubber = new THREE.MeshStandardMaterial({ color: 0x15171a, roughness: 0.85 });
    const head = new THREE.MeshBasicMaterial({ color: 0xfff4d6, toneMapped: false });
    const tail = new THREE.MeshBasicMaterial({ color: 0xff3b3b, toneMapped: false });
    const livery = new THREE.MeshBasicMaterial({ color: 0xffffff, toneMapped: false });
    const box = new THREE.BoxGeometry(1, 1, 1);
    const wheel = new THREE.CylinderGeometry(1, 1, 0.24, 12);
    wheel.rotateZ(Math.PI / 2);
    this.body = new THREE.InstancedMesh(box, paint, n);
    this.cabin = new THREE.InstancedMesh(box, glass, n);
    this.wheels = new THREE.InstancedMesh(wheel, rubber, n * 4);
    this.heads = new THREE.InstancedMesh(box, head, n * 2);
    this.tails = new THREE.InstancedMesh(box, tail, n * 2);
    // Stripe + beacon exist for every vehicle; classes without one get a
    // zero-scale instance (cheaper than a second index map).
    this.stripes = new THREE.InstancedMesh(box, livery, n);
    this.beacons = new THREE.InstancedMesh(box, livery, n);
    const c = new THREE.Color();
    this.cars.forEach((car, i) => {
      const spec = VEHICLES[car.cls];
      c.set(spec.paint ?? PAINTS[Math.floor(seeded01(i * 29 + 7) * PAINTS.length) % PAINTS.length]);
      this.body.setColorAt(i, c);
      c.set(spec.stripe ?? 0x000000);
      this.stripes.setColorAt(i, c);
      c.set(spec.beacon ?? 0x000000);
      this.beacons.setColorAt(i, c);
    });
    for (const m of this.meshes()) {
      m.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
      m.frustumCulled = false;       // instances roam the whole city
      m.userData.scenery = true;
      this.group.add(m);
    }
  }

  private meshes(): THREE.InstancedMesh[] {
    return [this.body, this.cabin, this.wheels, this.heads, this.tails, this.stripes, this.beacons];
  }

  /** How far this vehicle may advance this frame: never into the one ahead
   *  in its own lane, never into an intersection another vehicle occupies. */
  private allowance(car: Vehicle, want: number): number {
    const len = VEHICLES[car.cls].len;
    let room = want;
    for (const o of this.cars) {
      if (o === car || o.parked || o.street !== car.street || o.dir !== car.dir) continue;
      const ahead = (o.s - car.s) * car.dir;
      if (ahead > 0) room = Math.min(room, Math.max(0, ahead - (len + VEHICLES[o.cls].len) / 2 - FOLLOW_GAP));
    }
    if (room <= 0) return 0;
    const s = this.streets[car.street];
    const dx = s.x2 - s.x1, dz = s.z2 - s.z1;
    const L = Math.hypot(dx, dz) || 1;
    const ux = dx / L, uz = dz / L;
    const nose = car.s + car.dir * (len / 2 + YIELD_RANGE);
    const nx = s.x1 + ux * nose, nz = s.z1 + uz * nose;
    for (const it of this.intersections) {
      const h = it.size / 2 + 0.5;
      if (Math.abs(nx - it.x) > h || Math.abs(nz - it.z) > h) continue;
      // Already inside it ourselves? Keep going -- never stall in the box.
      if (Math.abs(car.x - it.x) <= h && Math.abs(car.z - it.z) <= h) continue;
      const busy = this.cars.some((o) => o !== car && !o.parked && o.street !== car.street
        && Math.abs(o.x - it.x) <= h && Math.abs(o.z - it.z) <= h);
      if (busy) return 0;
    }
    return room;
  }

  /** Is the `dir` lane of this vehicle's street free around its position? */
  private laneClear(car: Vehicle, dir: 1 | -1): boolean {
    const len = VEHICLES[car.cls].len;
    return !this.cars.some((o) => o !== car && !o.parked && o.street === car.street && o.dir === dir
      && Math.abs(o.s - car.s) < (len + VEHICLES[o.cls].len) / 2 + FOLLOW_GAP);
  }

  /** Advance moving vehicles by dt seconds and rewrite every instance matrix. */
  update(dt: number): void {
    const step = Math.min(dt, 0.1);
    this.cars.forEach((car, i) => {
      const s = this.streets[car.street];
      const dx = s.x2 - s.x1, dz = s.z2 - s.z1;
      const len = Math.hypot(dx, dz) || 1;
      if (!car.parked && step > 0) {
        car.s += this.allowance(car, car.speed * step) * car.dir;
        // End of the street: turn onto the opposite lane -- but only once
        // that lane is clear here, or the turn would land on another vehicle.
        const atEnd = car.dir > 0 ? car.s > len - 2 : car.s < 2;
        if (atEnd) {
          car.s = car.dir > 0 ? len - 2 : 2;
          if (this.laneClear(car, car.dir > 0 ? -1 : 1)) car.dir = car.dir > 0 ? -1 : 1;
        }
      }
      const ux = dx / len, uz = dz / len;
      // Right-hand traffic: the lane sits to the right of the direction of travel.
      const rx = -uz * car.dir, rz = ux * car.dir;
      const off = car.parked ? s.width / 2 - 1.2 : LANE_OFFSET;
      car.x = s.x1 + ux * car.s + rx * off;
      car.z = s.z1 + uz * car.s + rz * off;
      car.yaw = Math.atan2(ux * car.dir, uz * car.dir);
      this.place(i, car);
    });
    for (const m of this.meshes()) m.instanceMatrix.needsUpdate = true;
  }

  private put(mesh: THREE.InstancedMesh, index: number, car: Vehicle,
    lx: number, ly: number, lz: number, sx: number, sy: number, sz: number): void {
    const cos = Math.cos(car.yaw), sin = Math.sin(car.yaw);
    this.part.position.set(car.x + lx * cos + lz * sin, ly, car.z - lx * sin + lz * cos);
    this.part.rotation.set(0, car.yaw, 0);
    this.part.scale.set(sx, sy, sz);
    this.part.updateMatrix();
    mesh.setMatrixAt(index, this.part.matrix);
  }

  private place(i: number, car: Vehicle): void {
    const v = VEHICLES[car.cls];
    const L = v.len, W = v.width;
    this.put(this.body, i, car, 0, v.bodyY, 0, W, v.bodyH, L);
    this.put(this.cabin, i, car, 0, v.cabY, v.cz * L, W * v.cabW, v.cabH, L * v.cabLen);
    let w = 0;
    for (const sx of [-(W / 2 - 0.08), W / 2 - 0.08]) {
      for (const sz of [-L * 0.31, L * 0.31]) {
        this.put(this.wheels, i * 4 + w++, car, sx, v.wheelR, sz, v.wheelR, v.wheelR, v.wheelR);
      }
    }
    const lampY = v.bodyY + v.bodyH * 0.12;
    for (const [k, sx] of [[0, -W / 3], [1, W / 3]] as const) {
      this.put(this.heads, i * 2 + k, car, sx, lampY, L / 2 + 0.01, 0.36, 0.12, 0.04);
      this.put(this.tails, i * 2 + k, car, sx, lampY + 0.04, -L / 2 - 0.01, 0.34, 0.1, 0.04);
    }
    const s = v.stripe ? 1 : 0;
    this.put(this.stripes, i, car, 0, v.bodyY + v.bodyH * 0.18, 0, (W + 0.02) * s, 0.12 * s, (L * 0.9) * s);
    const b = v.beacon ? 1 : 0;
    this.put(this.beacons, i, car, 0, v.cabY + v.cabH / 2 + 0.1, v.cz * L, 0.7 * b, 0.14 * b, 0.22 * b);
  }

  get count(): { moving: number; parked: number; classes: Record<string, number> } {
    const parked = this.cars.filter((c) => c.parked).length;
    const classes: Record<string, number> = {};
    for (const c of this.cars) classes[c.cls] = (classes[c.cls] ?? 0) + 1;
    return { moving: this.cars.length - parked, parked, classes };
  }

  /** Every vehicle's current ground position (for the layout self-check). */
  positions(): { x: number; z: number; parked: boolean; cls: VehicleClass }[] {
    return this.cars.map((c) => ({ x: c.x, z: c.z, parked: c.parked, cls: c.cls }));
  }

  dispose(): void {
    for (const m of this.meshes()) {
      m.geometry.dispose();
      (m.material as THREE.Material).dispose();
      m.removeFromParent();
    }
    this.group.removeFromParent();
  }
}
