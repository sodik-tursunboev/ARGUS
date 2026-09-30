<script lang="ts">
  /* ARGUS AI CITY -- CITY-1: procedural world foundation.

     A view of nothing but geometry: no backend state, no agents[], no
     team/security/voice/cloud data. Every district is fixed, intentional
     layout (cityLayout.ts), not randomized. CITY-2 is what wires this to
     runtime truth -- this scene renders a clean idle world only.

     Structure mirrors lib/3d/AgentOffice3D.svelte on purpose (renderer
     setup, pixel-ratio cap, 30fps render interval, GSAP for restrained
     motion, canvas-sprite labels, lerp-based camera, full disposal on
     unmount) -- the same proven, performance-budgeted pattern, not a
     second one invented for this scene. */
  import { onMount } from 'svelte';
  import * as THREE from 'three';
  import { gsap } from 'gsap';
  import {
    DISTRICTS, SCENERY, ENV_DISTRICTS, ROADS, STREETS, INTERSECTIONS, AVENUE_X, CROSS_Z,
    findDistrict, type District,
  } from './cityLayout';
  import { detailPlacements, buildDetailProps, buildProcBuilding, RoofKit, NeonTrim, disposeDetail } from './cityDetail';
  // CITY-5: the production layer. Hero architecture and the robot are
  // authored in Blender (tools/blender/) and loaded as GLB; the camera,
  // district colour system and agent life each live in their own module so
  // this component stays the place that wires REAL backend state to the
  // scene, and nothing else.
  import { CSS2DRenderer, CSS2DObject } from 'three/examples/jsm/renderers/CSS2DRenderer.js';
  import { RoomEnvironment } from 'three/examples/jsm/environments/RoomEnvironment.js';
  import { loadManifest, loadModel, instantiate, assetStats, disposeAssets } from './cityAssets';
  import {
    categoryStyle, hexToCss, QUARTER_FILL, ROLE_ACCENT, ROLE_TITLE, ROLE_NAME, ROLE_DESCRIPTION,
    MANAGER_ACCENT, CEO_ACCENT, WORKER_TITLE,
  } from './cityPalette';
  import {
    CityCameraRig, attachCameraControls, makeClickGuard, keyNudge, PRESETS, DEFAULT_LIMITS, type CameraPreset, type DragMode,
  } from './cityCamera';
  import {
    AgentPool, buildNavGraph, destinationFor, AGENT_HOME, WORKING_STATES,
    type NavGraph, type CityAgent,
  } from './cityAgents';
  import { makeLabel, setLabelText, setCompact, fanOut, declutter, type SceneLabel } from './cityLabels';
  import { tasks } from '../../stores/tasks';
  // CITY-4: the shared visual kit (materials, modular architecture, city
  // props, the ARGUS mini-robot rig). Pure geometry -- it reads no store and
  // knows nothing about ARGUS state, which is what keeps "does the city
  // invent activity?" answerable by reading this file alone.
  import {
    PALETTE, GRAPHITE, SILVER, FLOOR_H, DOOR_H, KERB_H, ROBOT_H,
    structure, trim, trimRing, plaza, finRing, bollardRing, buildTower,
    roofAntenna, entrance, signPanel, cityBlock, buildStreetProps,
    distantSkyline, instanceProps, box, pad, cylinder,
    seeded01, spinningParts, buildRobot, poseRobot, disposeRobot, disposeKit,
    kitStats, type Placement, type Robot, type RobotPose,
  } from './cityKit';
  import {
    hqOfficePlan, seatFurniture, mergeStatic, wallDisplay, buildHQDecor, buildAcademyDecor, ACADEMY_PLAN,
    disposeInterior, closedShell, updateCutaway, neonSign, type Cutaway,
  } from './cityInterior';
  import { Traffic } from './cityTraffic';
  import CeoInbox from './CeoInbox.svelte';
  import AgentThread from './AgentThread.svelte';
  import { agentManager, releaseSpecialist, sendChat } from '../../stores/agentManager';
  import { academyState } from '../../stores/academy';
  import type { DistrictLive } from '../../stores/cityState';


  import { agentOffice, selectAgent, selectedAgent } from '../../stores/agentOffice';
  import { teamOffice, selectTeamEntity, clearTeamSelection, selectedDynamicAgent, selectedTeamMember, cancelActiveTeam, refreshDynamicAgents } from '../../stores/teamOffice';
  import { security } from '../../stores/security';
  import type { OfficeAgent, DynamicAgentView, TeamDetail, ManagerState } from '../../types/argus';

  type CameraMode = 'overview' | 'district' | 'landmark' | 'street' | 'interior' | 'hq-overview' | 'hq-agent' | 'hq-team' | 'hq-room';

  // CITY-2: real backend state, keyed by district id (cityState.ts derives
  // it; this component only renders it -- no fetching, no WS, no invented
  // activity of its own). null/missing entries render exactly like CITY-1
  // (idle, ambient pulse only).
  export let liveState: Record<string, DistrictLive> | null = null;

  const ACTIVITY_TINT: Record<string, number | null> = {
    idle: null, active: null, attention: 0xffb244, critical: 0xff4a4a, offline: 0x4a5560,
  };
  const ACTIVITY_PULSE: Record<string, number> = { idle: 1, active: 1.4, attention: 1.25, critical: 1.5, offline: 0.4 };

  let container: HTMLDivElement;
  let renderer: THREE.WebGLRenderer | null = null;
  let envTexture: THREE.Texture | null = null;
  let scene: THREE.Scene;
  let camera: THREE.OrthographicCamera;
  let raycaster: THREE.Raycaster;
  let mouse: THREE.Vector2;
  let clock: THREE.Clock;
  let animationFrameId = 0;
  let resizeObserver: ResizeObserver | null = null;
  let currentAspect = 1.6;

  let lastRenderTime = 0;
  const RENDER_INTERVAL = 33; // ~30fps cap, matches the Agent Office budget

  // Everything outdoor-city (districts, roads, ground, labels) lives under
  // ONE group so entering the HQ interior can hide the whole exterior in a
  // single toggle -- otherwise a heavily-fogged but not fully-occluded
  // district can bleed into an interior-zoom frustum (an orthographic
  // camera has no perspective falloff to hide it the way a normal
  // building-focus shot's greater depth difference does).
  let cityGroup: THREE.Group;
  const buildingRegistry: Map<string, { group: THREE.Group; district: District; glow: THREE.Mesh[] }> = new Map();
  const roadRegistry: Map<string, THREE.Line> = new Map();
  // District + sub-building name tags (screen-space HTML, see cityLabels.ts).
  const labelRegistry: Map<string, SceneLabel> = new Map();
  let labelRenderer: CSS2DRenderer | null = null;
  let appliedLiveState: Record<string, DistrictLive> | null = null;
  let hoveredId: string | null = null;
  let selectedId: string | null = null;

  let cameraMode: CameraMode = 'overview';

  /* ---- camera rig --------------------------------------------------------
     CITY-5: the fixed isometric direction is gone. cityCamera.ts owns an
     orbit rig (target + yaw + pitch + zoom) with real limits, five presets,
     and exact orthographic box framing. Everything that used to call
     setFocus(target, halfHeight) now either applies a preset or frames a
     measured Box3, so "the camera cut into the building" stops being a
     tuning problem and becomes arithmetic. */
  let rig: CityCameraRig;
  /** The whole campus, measured once the layout exists -- CITY_OVERVIEW
      frames THIS rather than a hand-guessed zoom number, so the city fills
      the viewport at any aspect ratio. */
  const cityBounds = new THREE.Box3();
  const clickGuard = makeClickGuard();
  let detachControls: (() => void) | null = null;
  /** Set while the user is driving the camera, so an incoming store update
      never yanks the view out from under them. */
  let userDrivingCamera = false;

  // Svelte-reactive mirrors of the hover/select state, for the label overlay.
  let hoverLabel: { name: string; purpose: string; x: number; y: number } | null = null;
  let focusedDistrict: District | null = null;

  /* ---- CITY-4: city props collected during layout -----------------------
     Street furniture is what gives a city scale, but one Mesh per bench is
     how a scene ends up with two thousand draw calls. Builders push
     PLACEMENTS here while laying out their block; buildStreetProps() turns
     the whole city's worth into about eight InstancedMeshes at the end. */
  const props: {
    trees: Placement[]; benches: Placement[]; planters: Placement[];
    utility: Placement[]; lamps: Placement[]; bollards: Placement[];
  } = { trees: [], benches: [], planters: [], utility: [], lamps: [], bollards: [] };

  /** Where a robot stands when it arrives at a district: just outside the
      building's own door, on the block's sidewalk. Never inside geometry --
      this is what keeps robots from walking through walls. */
  const districtEntrances = new Map<string, THREE.Vector3>();

  // Only these four carry a label at full city zoom; everything else fades
  // in as the camera comes down (reduce label clutter).
  const LANDMARKS = new Set(['core-tower', 'agent-hq', 'academy', 'policy-gate']);
  const ENV_IDS = new Set(ENV_DISTRICTS.map((e) => e.id));

  // Entrances face the cross street south of their row; the Capability
  // Center is the deliberate exception, facing NORTH back toward the Policy
  // Gate it sits behind.
  function entranceSide(d: District): number {
    return d.id === 'capability-center' ? -1 : 1;
  }

  /** A ring of street furniture around a block: lamps at the corners, trees
      and benches along the frontage, a utility cabinet at the service
      corner. Skipped for the Gate, which straddles a carriageway and has no
      block of its own to dress. */
  function dressBlock(d: District): void {
    if (d.kind === 'gate') return;
    const r = d.footprint + 1.2;
    const side = entranceSide(d);
    for (const sx of [-1, 1]) {
      for (const sz of [-1, 1]) props.lamps.push({ x: d.x + sx * r, y: KERB_H, z: d.z + sz * r * 0.86 });
    }
    const span = d.footprint * 0.8;
    for (let i = -2; i <= 2; i++) {
      if (i === 0) continue; // leave the doorway clear
      const x = d.x + (i / 2) * span;
      const z = d.z + side * r * 0.86;
      const s = 0.8 + seeded01(d.x * 3 + d.z * 7 + i * 11) * 0.45;
      if (i % 2 === 0) props.trees.push({ x, y: KERB_H, z, s });
      else props.benches.push({ x, y: KERB_H, z: z - side * 0.9, ry: side > 0 ? 0 : Math.PI });
    }
    props.utility.push({ x: d.x - r * 0.75, y: KERB_H, z: d.z - side * r * 0.86, ry: 0.3 });
    props.planters.push({ x: d.x + r * 0.78, y: KERB_H, z: d.z + side * r * 0.5 });
  }

  /* ---- districts: real Blender-authored architecture ---------------------
     The hero buildings are no longer extruded here. They are modelled in
     tools/blender/ and shipped as GLB; this only places them, lights them,
     and wires the parts the backend is allowed to colour.

     Loading is async and non-blocking: the block, its paving and its label
     exist immediately, and each building drops in when its GLB arrives. A
     slow disk therefore shows an empty lit plot for a moment rather than a
     blank canvas. */

  const districtStyles = new Map<string, ReturnType<typeof categoryStyle>>();

  /** Collect the meshes a district is allowed to recolour from live state.
      Only genuinely emissive parts qualify -- tinting a whole building is
      what made the old city unreadable. */
  function collectGlow(root: THREE.Object3D): THREE.Mesh[] {
    const glow: THREE.Mesh[] = [];
    root.traverse((child: THREE.Object3D) => {
      if (!(child instanceof THREE.Mesh)) return;
      const material = child.material as THREE.MeshStandardMaterial;
      if (!material || material.emissiveIntensity === undefined) return;
      if (material.emissiveIntensity <= 0.8) return;
      // Captured ONCE: the animate loop pulses relative to this fixed
      // baseline. Re-reading the already-pulsed value each frame would
      // compound instead of oscillating.
      child.userData.baseIntensity = material.emissiveIntensity;
      child.userData.baseEmissive = material.emissive.clone();
      glow.push(child);
    });
    return glow;
  }

  function buildDistrict(d: District): void {
    const style = categoryStyle(d.category);
    districtStyles.set(d.id, style);

    const group = new THREE.Group();
    // The block comes first: paving, kerb and raised sidewalk under
    // everything, so no building stands on bare ground. Its paving and edge
    // light take the district's own category colour, which is what makes one
    // block read as a different PLACE from the next one.
    if (d.kind !== 'gate') group.add(cityBlock(d.footprint, d.footprint * 0.88, style.accent, style.ground));
    group.position.set(d.x, 0, d.z);
    group.userData.districtId = d.id;
    cityGroup.add(group);

    dressBlock(d);
    districtEntrances.set(d.id, new THREE.Vector3(d.x, KERB_H, d.z + entranceSide(d) * (d.footprint + 2.4)));

    const label = makeLabel('district', d.id, style.accent);
    setLabelText(label, d.name, style.label);
    label.obj.position.set(d.x, d.height + 3, d.z);
    label.priority = LANDMARKS.has(d.id) ? 80 : 60;
    cityGroup.add(label.obj);
    labelRegistry.set(d.id, label);

    // A district fill light, tinted to the category: a coloured pool of light
    // over the block. Intensity is in real units (three r155+ dropped the
    // old x PI light scaling), so with decay 2 it has to be in the hundreds
    // to reach the ground from 14 units up -- the old 0.85 lit nothing
    // further than a metre away.
    const fill = new THREE.PointLight(style.fill, 210, d.footprint * 3.6, 2);
    fill.position.set(d.x, 14, d.z);
    cityGroup.add(fill);
    districtFills.push(fill);

    const entry = { group, district: d, glow: [] as THREE.Mesh[] };
    buildingRegistry.set(d.id, entry);

    for (const placed of d.assets) {
      loadModel('buildings', placed.asset).then((model) => {
        if (!model || !renderer) return;
        // Materials are isolated per district so live state can recolour one
        // building's accents without tinting every other copy of that asset.
        const inst = instantiate(model, { isolateMaterials: true });
        inst.position.set(placed.x ?? 0, 0, placed.z ?? 0);
        if (placed.ry) inst.rotation.y = placed.ry;
        const s = placed.s ?? 1;
        inst.scale.setScalar(s);
        inst.userData.districtId = d.id;
        inst.traverse((c: THREE.Object3D) => { c.userData.districtId = d.id; });
        group.add(inst);
        entry.glow.push(...collectGlow(inst));
        if (appliedLiveState) applyLiveState(appliedLiveState);

        if (placed.label) {
          const sub = makeLabel('sub', `${d.id}:${placed.label}`, style.secondary);
          setLabelText(sub, placed.label);
          sub.obj.position.set(d.x + (placed.x ?? 0), (model.size.y ?? 6) * s + 1.2, d.z + (placed.z ?? 0));
          sub.priority = 40;
          cityGroup.add(sub.obj);
          labelRegistry.set(`${d.id}:${placed.label}`, sub);
        } else {
          // The main building: pin the district's name tag just above the
          // REAL roofline now that it is known, not the layout's guess.
          label.obj.position.y = model.size.y * s + 2;
          if (d.id === 'core-tower') placeCeoNode(model.size.y);
        }
        // The roofline in neon, and on the main building its name in lit
        // letters just under the roof, facing the street its door is on --
        // up there it clears the annexes in front (the reference city's big
        // building signs).
        group.updateMatrixWorld(true);
        const roof = NeonTrim.roofRect(inst);
        if (roof) neonTrim?.rect(roof, roof.y + 0.1, style.accent);
        if (!placed.label) {
          const bb = new THREE.Box3().setFromObject(inst);
          const top = roof ?? { y: bb.max.y, x0: bb.min.x, x1: bb.max.x, z0: bb.min.z, z1: bb.max.z };
          const side = entranceSide(d);
          const sign = neonSign(d.name, style.accent, 2.2);
          sign.position.set((top.x0 + top.x1) / 2, top.y - 1.5, side > 0 ? top.z1 + 0.25 : top.z0 - 0.25);
          if (side < 0) sign.rotation.y = Math.PI;
          cityGroup.add(sign);
        }
        if (SHADOW_CASTERS.has(d.id)) {
          inst.traverse((c: THREE.Object3D) => {
            if (c instanceof THREE.Mesh && !(c instanceof THREE.InstancedMesh)) {
              c.castShadow = true;
              c.receiveShadow = true;
            }
          });
        }
      });
    }
  }

  // Only these cast shadows: the landmarks the eye goes to.
  // Every other building stays shadow-free to keep one 1024 map enough.
  const SHADOW_CASTERS = new Set(['core-tower', 'agent-hq', 'academy', 'verification-institute']);
  const districtFills: THREE.PointLight[] = [];

  /* ---- environment buildings ---------------------------------------------
     Scenery. These exist so ARGUS sits IN a city instead of on empty ground.
     They are NOT operational facilities and the code guarantees it: they
     never enter buildingRegistry, never get a districtId, are marked
     `scenery` in userData, and the hover/click raycast only ever tests
     buildingRegistry -- so they cannot be selected or mistaken for an ARGUS
     capability. A gate checks these invariants. */
  let sceneryGroup: THREE.Group;
  let roofKit: RoofKit | null = null;
  /** Neon roof outlines and plot outlines, the reference city's signature
      (cityDetail.NeonTrim): one instanced mesh for the whole city. */
  let neonTrim: NeonTrim | null = null;
  const SCENERY_NEON = [0xff4fd8, 0x7fefff, 0xb98cff, 0xffc24a, 0x4ade9e];
  let detailCount = 0;

  /** An environment building's name tag: a plain name at building zoom,
      never a status -- nothing behind it is an ARGUS system. */
  function sceneryLabel(id: string, name: string, x: number, y: number, z: number, accent: number): void {
    const l = makeLabel('sub', `scenery:${id}`, accent);
    setLabelText(l, name);
    l.obj.position.set(x, y, z);
    l.priority = 30;
    cityGroup.add(l.obj);
    labelRegistry.set(`scenery:${id}`, l);
  }

  function buildScenery(): void {
    sceneryGroup = new THREE.Group();
    sceneryGroup.name = 'city-scenery';
    cityGroup.add(sceneryGroup);
    roofKit = new RoofKit();
    sceneryGroup.add(roofKit.group);

    SCENERY.forEach((s, i) => {
      const place = (inst: THREE.Object3D, height: number) => {
        inst.position.set(s.x, 0, s.z);
        if (s.ry) inst.rotation.y = s.ry;
        inst.userData.scenery = true;
        sceneryGroup.add(inst);
        roofKit?.add(inst, i + 1);
        neonTrim?.add(inst, SCENERY_NEON[i % SCENERY_NEON.length]);
        if (s.name) sceneryLabel(`${s.asset}:${i}`, s.name, s.x, height + 1.4, s.z,
          QUARTER_FILL[s.quarter] ?? 0x9fb3c8);
      };
      if (s.asset.startsWith('proc:')) {
        // No GLB for this one: a procedural building (cityDetail.ts).
        const built = buildProcBuilding(s.asset.slice(5));
        if (built) place(built, new THREE.Box3().setFromObject(built).max.y);
      } else {
        // Scenery shares materials across every copy (no isolateMaterials):
        // background blocks cost one draw call each against one set of
        // buffers, and nothing here ever changes colour at runtime.
        loadModel('buildings', s.asset).then((model) => {
          if (!model || !renderer) return;
          place(instantiate(model), model.size.y);
        });
      }
      // A dim quarter-tinted plot under each scenery block, so the
      // surrounding city still has structure rather than floating in black.
      const plot = pad(19, 15, structure(0x201a3c, { roughness: 0.94, metalness: 0.05 }), 0.04);
      plot.position.set(s.x, 0.04, s.z);
      plot.userData.scenery = true;
      sceneryGroup.add(plot);
      // ...outlined in neon, like every plot in the reference city.
      neonTrim?.rect({ x0: s.x - 9.5, x1: s.x + 9.5, z0: s.z - 7.5, z1: s.z + 7.5 }, 0.1,
        SCENERY_NEON[i % SCENERY_NEON.length], 0.1);
      props.lamps.push({ x: s.x - 10.5, y: KERB_H, z: s.z - 8.4 });
      props.lamps.push({ x: s.x + 10.5, y: KERB_H, z: s.z + 8.4 });
    });

    // The two environment districts: a name over each, in its
    // own colour family, and nothing else -- no status, no telemetry.
    for (const e of ENV_DISTRICTS) {
      const style = categoryStyle(e.category);
      const l = makeLabel('district', e.id, style.accent);
      setLabelText(l, e.name, 'ENVIRONMENT');
      l.obj.position.set(e.x, 22, e.z);
      l.priority = 50;
      cityGroup.add(l.obj);
      labelRegistry.set(e.id, l);
    }

    // One quarter-coloured ground wash per scenery quarter -- a very cheap
    // way to make the residential side read warm-blue and the industrial
    // side read amber from the city overview.
    const byQuarter = new Map<string, { x: number; z: number; n: number }>();
    for (const s of SCENERY) {
      const q = byQuarter.get(s.quarter) ?? { x: 0, z: 0, n: 0 };
      q.x += s.x; q.z += s.z; q.n += 1;
      byQuarter.set(s.quarter, q);
    }
    for (const [quarter, q] of byQuarter) {
      // Real light units again: a quarter-wide wash from 24 up needs a few
      // hundred candela to register (the old 0.55 was invisible).
      const light = new THREE.PointLight(QUARTER_FILL[quarter] ?? 0x3f6296, 420, 110, 2);
      light.position.set(q.x / q.n, 24, q.z / q.n);
      sceneryGroup.add(light);
    }
  }

  /* ---- streets ------------------------------------------------------------
     Real carriageways with kerbs, raised sidewalks, lane markings, paved
     intersections and pedestrian crossings. Every repeated
     element (dashes, crossing stripes, lamps) is collected and instanced. */

  // AVENUE_X / CROSS_Z now come from cityLayout, which DERIVES them from the
  // column/row grid -- the hard-coded copies that used to live here silently
  // went stale every time a footprint changed.
  const nearestOf = (vals: number[], v: number) => vals.reduce((a, b) => (Math.abs(b - v) < Math.abs(a - v) ? b : a));

  function buildStreets(): void {
    const asphalt = structure(PALETTE.ASPHALT, { roughness: 0.94, metalness: 0.05 });
    const walk = structure(PALETTE.SIDEWALK, { roughness: 0.9, metalness: 0.05 });
    const kerbMat = structure(PALETTE.CURB, { roughness: 0.9, metalness: 0.05 });
    const dashes: Placement[] = [];
    const stripes: Placement[] = [];

    for (const s of STREETS) {
      const dx = s.x2 - s.x1, dz = s.z2 - s.z1;
      const len = Math.hypot(dx, dz);
      if (len < 1) continue;
      const vertical = Math.abs(dx) < 0.001;
      const cx = (s.x1 + s.x2) / 2, cz = (s.z1 + s.z2) / 2;
      const rot = vertical ? Math.PI / 2 : 0;

      const surface = pad(len, s.width, asphalt, 0.03, rot);
      surface.position.set(cx, 0.03, cz);
      cityGroup.add(surface);

      for (const sign of [-1, 1]) {
        const off = s.width / 2 + 1.1;
        const kerb = vertical ? box(2.4, KERB_H, len, kerbMat) : box(len, KERB_H, 2.4, kerbMat);
        kerb.position.set(cx + (vertical ? sign * off : 0), 0, cz + (vertical ? 0 : sign * off));
        cityGroup.add(kerb);
        const sidewalk = pad(len, 2.2, walk, KERB_H + 0.01, rot);
        sidewalk.position.set(cx + (vertical ? sign * off : 0), KERB_H + 0.01, cz + (vertical ? 0 : sign * off));
        cityGroup.add(sidewalk);
      }

      if (s.kind !== 'service') {
        const count = Math.max(1, Math.floor(len / 7));
        for (let i = 0; i < count; i++) {
          const t = (i + 0.5) / count;
          dashes.push({ x: s.x1 + dx * t, y: 0.05, z: s.z1 + dz * t, ry: vertical ? Math.PI / 2 : 0 });
        }
      }

      // Street lights down every carriageway but the service road.
      if (s.kind !== 'service') {
        const n = Math.max(2, Math.floor(len / 26));
        for (let i = 0; i < n; i++) {
          const t = (i + 0.5) / n;
          const off = s.width / 2 + 1.4;
          props.lamps.push({
            x: s.x1 + dx * t + (vertical ? off : 0), y: KERB_H,
            z: s.z1 + dz * t + (vertical ? 0 : off),
          });
        }
      }
    }

    // Paved intersections over the top of the carriageways, plus pedestrian
    // crossings on each approach.
    const interMat = structure(0x1f2834, { roughness: 0.93, metalness: 0.05 });
    for (const it of INTERSECTIONS) {
      const p = pad(it.size, it.size, interMat, 0.045);
      p.position.set(it.x, 0.045, it.z);
      cityGroup.add(p);
      for (const [ox, oz, ry] of [[0, it.size * 0.74, 0], [0, -it.size * 0.74, 0], [it.size * 0.74, 0, Math.PI / 2], [-it.size * 0.74, 0, Math.PI / 2]] as const) {
        for (let i = -2; i <= 2; i++) {
          stripes.push({ x: it.x + ox + (ry ? 0 : i * 1.15), y: 0.055, z: it.z + oz + (ry ? i * 1.15 : 0), ry });
        }
      }
    }

    // Glowing lane lines: the street grid is the city's map, so it has to be
    // legible from the overview -- the old 0x39454c dashes were invisible.
    const dashMesh = instanceProps(new THREE.BoxGeometry(3, 0.02, 0.22), structure(0x7fe9ff, { emissive: 0x38e0ff, emissiveIntensity: 0.75, metalness: 0, roughness: 0.6 }), dashes);
    if (dashMesh) cityGroup.add(dashMesh);
    const stripeMesh = instanceProps(new THREE.BoxGeometry(0.55, 0.02, 1.9), structure(0xc9d6e2, { emissive: 0xc9d6e2, emissiveIntensity: 0.35, metalness: 0, roughness: 0.7 }), stripes);
    if (stripeMesh) cityGroup.add(stripeMesh);
  }

  /** The live route line between two districts, routed along the street grid
      so an active link never cuts diagonally through a city block. Purely a
      rendering of CITY-2's existing both-endpoints-busy signal (see
      applyLiveState) -- nothing here invents a route. */
  function routePoints(a: District, b: District): THREE.Vector3[] {
    const y = 0.26;
    const v = (x: number, z: number) => new THREE.Vector3(x, y, z);
    // The centre column has a real carriageway at x=0 only south of the last
    // cross street (the gate spine) and north of the perimeter street (the
    // embassy service road); everywhere else it is solid blocks.
    const centreRun = Math.abs(a.x) < 1 && Math.abs(b.x) < 1
      && ((a.z > 0 && b.z > 0) || (a.z < -60 && b.z < -60));
    if (centreRun) return [v(a.x, a.z), v(b.x, b.z)];
    if (Math.abs(a.x - b.x) < 1) {
      const av = nearestOf(AVENUE_X, a.x || 20);
      return [v(a.x, a.z), v(av, a.z), v(av, b.z), v(b.x, b.z)];
    }
    const cz = nearestOf(CROSS_Z, (a.z + b.z) / 2);
    return [v(a.x, a.z), v(a.x, cz), v(b.x, cz), v(b.x, b.z)];
  }

  function buildRoutes(): void {
    ROADS.forEach(([fromId, toId]) => {
      const from = findDistrict(fromId);
      const to = findDistrict(toId);
      if (!from || !to) return;
      const material = new THREE.LineBasicMaterial({ color: 0x2f7d8f, transparent: true, opacity: 0.5, toneMapped: false });
      const geo = new THREE.BufferGeometry().setFromPoints(routePoints(from, to));
      const line = new THREE.Line(geo, material);
      cityGroup.add(line);
      roadRegistry.set(`${fromId}|${toId}`, line);
    });
  }

  let groundMesh: THREE.Mesh | null = null;

  /** A top-to-bottom colour ramp, used as the screen-space sky. */
  function verticalGradient(stops: string[]): THREE.CanvasTexture {
    const c = document.createElement('canvas');
    c.width = 4; c.height = 256;
    const g = c.getContext('2d');
    if (g) {
      const grad = g.createLinearGradient(0, 0, 0, 256);
      stops.forEach((s, i) => grad.addColorStop(i / (stops.length - 1), s));
      g.fillStyle = grad; g.fillRect(0, 0, 4, 256);
    }
    const t = new THREE.CanvasTexture(c);
    t.colorSpace = THREE.SRGBColorSpace;
    return t;
  }

  /** The ground's tile: violet base, a faint 4 m grid and one dashed light
      line per 16 m tile -- the reference city's glowing ground. */
  function groundGrid(): THREE.CanvasTexture {
    const c = document.createElement('canvas');
    c.width = c.height = 256;
    const g = c.getContext('2d');
    if (g) {
      g.fillStyle = '#1a1434'; g.fillRect(0, 0, 256, 256);
      g.strokeStyle = 'rgba(120, 96, 230, 0.2)'; g.lineWidth = 2;
      for (let i = 0; i <= 256; i += 64) {
        g.beginPath(); g.moveTo(i, 0); g.lineTo(i, 256); g.moveTo(0, i); g.lineTo(256, i); g.stroke();
      }
      g.strokeStyle = 'rgba(190, 150, 255, 0.42)'; g.lineWidth = 3;
      g.setLineDash([18, 22]);
      g.beginPath(); g.moveTo(0, 128); g.lineTo(256, 128); g.moveTo(128, 0); g.lineTo(128, 256); g.stroke();
    }
    const t = new THREE.CanvasTexture(c);
    t.colorSpace = THREE.SRGBColorSpace;
    t.wrapS = t.wrapT = THREE.RepeatWrapping;
    t.repeat.set(30, 30);
    t.anisotropy = 4;
    return t;
  }

  function buildGround(): void {
    // Dark violet with a faint neon grid and dashed light lines, a clear step
    // above the background: the ground is what the streets and blocks are
    // read AGAINST, so it cannot be the void colour.
    const ground = new THREE.Mesh(new THREE.PlaneGeometry(480, 480),
      new THREE.MeshStandardMaterial({ map: groundGrid(), roughness: 0.96, metalness: 0.02 }));
    ground.rotation.x = -Math.PI / 2;
    cityGroup.add(ground);
    groundMesh = ground;

    // A boundary marker around the secure inner grid. Cloud Embassy sits at
    // z=-104, outside it, reachable only by the one service road -- "outside
    // the secure city" is stated by position and by the road network.
    const boundary = new THREE.Mesh(new THREE.RingGeometry(78, 79.4, 72),
      new THREE.MeshStandardMaterial({ color: 0x38e0ff, emissive: 0x38e0ff, emissiveIntensity: 0.5, side: THREE.DoubleSide, transparent: true, opacity: 0.32 }));
    boundary.rotation.x = -Math.PI / 2;
    boundary.position.set(0, 0.02, -12);
    cityGroup.add(boundary);

    // Cheap background architecture so the city does not end at a hard edge
    // of empty black. Scenery only -- not raycastable, not
    // labelled, never claimed to be an ARGUS building.
    cityGroup.add(distantSkyline());
  }

  /* ---- CITY-2: live backend state -> material/color updates only --------
     Never rebuilds geometry: a district's group is built
     once by buildDistrict(); a state change only recolors its already-built
     glow meshes and, for roads whose both endpoints are non-idle, brightens
     the already-built road line. Runs once per cityState recompute (a few
     times a second at most on live WS traffic), not per animation frame. */
  const scratchColor = new THREE.Color();

  function applyLiveState(state: Record<string, DistrictLive>): void {
    appliedLiveState = state;
    const w = window as unknown as Record<string, unknown>;
    if (w.__argusCity) (w.__argusCity as Record<string, unknown>).lastActivity =
      Object.fromEntries(Object.entries(state).map(([id, v]) => [id, v.activity]));
    for (const [id, entry] of buildingRegistry) {
      const activity = state[id]?.activity ?? 'idle';
      const tint = ACTIVITY_TINT[activity];
      for (const mesh of entry.glow) {
        const material = mesh.material as THREE.MeshStandardMaterial;
        const base = mesh.userData.baseEmissive as THREE.Color;
        if (tint !== null && tint !== undefined) { scratchColor.set(tint); material.emissive.copy(base).lerp(scratchColor, 0.6); }
        else material.emissive.copy(base);
        mesh.userData.pulseMul = ACTIVITY_PULSE[activity] ?? 1;
      }
    }
    if (w.__argusCity) {
      const coreGlow = buildingRegistry.get('core-tower')?.glow[0];
      (w.__argusCity as Record<string, unknown>).coreTowerEmissiveHex =
        coreGlow ? '#' + (coreGlow.material as THREE.MeshStandardMaterial).emissive.getHexString() : null;
    }
    const hot = new Set(Object.entries(state)
      .filter(([, v]) => v.activity !== 'idle' && v.activity !== 'offline')
      .map(([id]) => id));
    activeRoutes.clear();
    for (const [key, line] of roadRegistry) {
      const [fromId, toId] = key.split('|');
      const material = line.material as THREE.LineBasicMaterial;
      const active = hot.has(fromId) && hot.has(toId);
      if (active) activeRoutes.add(line);
      material.opacity = active ? 0.95 : 0.5;
      material.color.set(active ? 0x7fefff : 0x2f7d8f);
    }
  }
  /** Routes whose BOTH ends the backend reports busy -- the only lines that
      pulse. An idle city has no moving light on its streets. */
  const activeRoutes = new Set<THREE.Line>();

  $: if (renderer && liveState) applyLiveState(liveState);

  // CITY-3: HQ interior state application. Runs whenever the underlying
  // store changes, same trigger discipline as CITY-2's own liveState line
  // above; each apply* function is itself signature-diffed so an unrelated
  // store recompute (e.g. a security tick) doesn't churn GSAP for the HQ
  // agents that didn't change.
  $: if (renderer && hqGroup) { void $academyState; applyHQAgents($agentOffice.snapshot, $agentOffice.link); }
  $: if (renderer && hqGroup) applyHQDynamic($teamOffice.dynamicAgents);
  $: if (renderer && hqGroup) applyHQTeam($teamOffice.activeTeam);
  $: if (renderer && hqGroup) applyHQCriticalSecurity($security.posture);
  $: if (renderer && hqGroup) applyHandoffPulses($agentOffice.handoff, $teamOffice.lastHandoff);
  $: if (renderer && hqGroup) applyHQActivity($teamOffice.activeTeam);
  $: if (renderer && hqGroup) applyVerifierOutcome($teamOffice.activeTeam);
  // CITY-4: the Institute's readout, from the same real verifier/team fields.
  $: if (renderer && hqGroup) applyVerifyInterior($agentOffice.snapshot, $teamOffice.activeTeam);

  /* ---- camera ------------------------------------------------------------
     Every view change goes through the rig: either a named preset or an
     exact Box3 fit. Nothing sets a camera position directly, which is what
     makes all five modes share one smooth transition. */

  const focusBox = new THREE.Box3();
  let activePreset: CameraPreset = 'CITY_OVERVIEW';

  /** Measure the campus once the districts exist, so CITY_OVERVIEW frames
      what is actually there rather than a hard-coded zoom. */
  /** Where the camera's look-at point may go while outdoors: the campus plus
      its scenery ring, and no further -- panning off into empty ground was
      one of the ways the old rig got "lost". */
  const cityPanBounds = new THREE.Box3();

  function measureCity(): void {
    cityBounds.makeEmpty();
    for (const entry of buildingRegistry.values()) {
      const d = entry.district;
      cityBounds.expandByPoint(new THREE.Vector3(d.x - d.footprint * 1.4, 0, d.z - d.footprint * 1.4));
      cityBounds.expandByPoint(new THREE.Vector3(d.x + d.footprint * 1.4, d.height, d.z + d.footprint * 1.4));
    }
    cityPanBounds.set(
      new THREE.Vector3(cityBounds.min.x - 40, 0, cityBounds.min.z - 20),
      new THREE.Vector3(cityBounds.max.x + 40, 40, cityBounds.max.z + 20),
    );
    rig.setBounds(cityPanBounds);
  }

  function focusOverview(): void {
    cameraMode = 'overview';
    activePreset = 'CITY_OVERVIEW';
    selectedId = null;
    focusedDistrict = null;
    userDrivingCamera = false;
    rig.applyPreset('CITY_OVERVIEW');
    if (!cityBounds.isEmpty()) rig.frameBox(cityBounds, 1.04, 24);
  }

  /** The clean "get me back" action: overview, nothing selected, nothing
      followed. */
  function resetView(): void {
    followingAgentId = null;
    selectedAgentId = null;
    focusOverview();
  }

  /* ---- the camera without a mouse ----------------------------------------
     The owner found mouse-only 3D control uncomfortable (2026-09-24). So:
     an on-screen pad (turn / move / zoom / tilt / home, hold to repeat), the
     keyboard (cityCamera.keyNudge), double-click to zoom in, and a switch
     for what a left drag does -- ROTATE, or map-style MOVE. Every step goes
     through rig.nudge, so it glides like a preset. */
  const PAD_TURN = Math.PI / 8, PAD_MOVE = 0.22, PAD_TILT = THREE.MathUtils.degToRad(6);
  let dragLeft: DragMode = 'orbit';
  try { if (localStorage.getItem('argus.city.drag') === 'pan') dragLeft = 'pan'; } catch { /* storage blocked */ }
  function toggleDragLeft(): void {
    dragLeft = dragLeft === 'orbit' ? 'pan' : 'orbit';
    try { localStorage.setItem('argus.city.drag', dragLeft); } catch { /* storage blocked */ }
  }
  function camStep(step: Parameters<CityCameraRig['nudge']>[0]): void {
    rig?.nudge(step);
    userDrivingCamera = true;
    followingAgentId = null;
    followingTeam = false;
  }
  function camHome(): void {
    if (currentInterior) enterInterior(currentInterior);
    else resetView();
  }
  function onCityKey(e: KeyboardEvent): void {
    // Only while the city is on screen, and never while typing (the command
    // bar, the inbox, an agent thread) or on a shortcut chord.
    if (e.ctrlKey || e.metaKey || e.altKey || !container?.offsetParent) return;
    const t = e.target as HTMLElement | null;
    if (t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName))) return;
    const step = keyNudge(e.key);
    if (!step) return;
    e.preventDefault();          // arrows would also scroll the page
    camStep(step);
  }
  /** Press-and-hold repeat for a pad button. Keyboard activation (a click
      with detail 0) steps once, so the pad works without a pointer too. */
  function hold(node: HTMLElement, fn: () => void) {
    let delay = 0, rep = 0;
    const stop = () => { clearTimeout(delay); clearInterval(rep); };
    const start = (e: PointerEvent) => {
      if (e.button !== 0) return;
      e.preventDefault();
      fn();
      delay = window.setTimeout(() => { rep = window.setInterval(fn, 110); }, 320);
    };
    const key = (e: MouseEvent) => { if (e.detail === 0) fn(); };
    node.addEventListener('pointerdown', start);
    node.addEventListener('click', key);
    for (const ev of ['pointerup', 'pointerleave', 'pointercancel']) node.addEventListener(ev, stop);
    return {
      update(next: () => void) { fn = next; },
      destroy() {
        stop();
        node.removeEventListener('pointerdown', start);
        node.removeEventListener('click', key);
        for (const ev of ['pointerup', 'pointerleave', 'pointercancel']) node.removeEventListener(ev, stop);
      },
    };
  }

  function applyPreset(preset: CameraPreset): void {
    activePreset = preset;
    userDrivingCamera = false;
    if (preset === 'CITY_OVERVIEW') { focusOverview(); return; }
    // Anchor on what the user is looking at: the focused building, else the
    // selected agent, else wherever the camera already is. Every preset
    // works from anywhere -- they used to be disabled until a click.
    const agent = selectedAgentId ? agentPool?.agents.get(selectedAgentId) : null;
    const anchor = focusedDistrict
      ? new THREE.Vector3(focusedDistrict.x, 2, focusedDistrict.z)
      : agent ? agent.root.position.clone().setY(1.5) : rig.desiredTarget.clone();
    rig.applyPreset(preset, anchor);
    cameraMode = preset === 'STREET_LEVEL' ? 'street' : preset === 'DISTRICT' ? 'district' : 'landmark';
  }

  /** Frame a district's real, built geometry. Uses the measured bounds of
      whatever GLBs have actually loaded, falling back to the layout's
      nominal footprint while they are still in flight. */
  function focusDistrict(id: string, preset: CameraPreset = 'DISTRICT'): void {
    const entry = buildingRegistry.get(id);
    if (!entry) return;
    const d = entry.district;
    selectedId = id;
    focusedDistrict = d;
    activePreset = preset;
    userDrivingCamera = false;
    cameraMode = preset === 'BUILDING_FOCUS' ? 'landmark' : 'district';

    focusBox.setFromObject(entry.group);
    if (focusBox.isEmpty()) {
      focusBox.setFromCenterAndSize(
        new THREE.Vector3(d.x, d.height / 2, d.z),
        new THREE.Vector3(d.footprint * 2.4, d.height, d.footprint * 2.4),
      );
    }
    rig.applyPreset(preset);
    // Pad enough that the district's floating label still fits in frame.
    rig.frameBox(focusBox, preset === 'BUILDING_FOCUS' ? 1.26 : 1.5, 12);
  }

  /* ---- CITY-3: Agent HQ interior ---------------------------------------
     Built once at mount, translated to HQ_ORIGIN (far outside the city's
     ground plane/fog range) and kept `hqGroup.visible = false` until
     enterAgentHQ() -- so it costs nothing while the city overview is shown
     (an invisible Object3D, including its lights, is skipped by the
     renderer) and never collides with city district geometry. Station
     layout is the same proven, already-shipped arrangement
     lib/3d/AgentOffice3D.svelte uses for the same 10 roles -- reused as
     local offsets within this group rather than re-derived. */

  const HQ_ORIGIN = new THREE.Vector3(0, 0, -260);

  const ALL_AGENTS = ['security', 'threat', 'assistant', 'system', 'network', 'verifier',
                      'planner', 'diagnostics', 'forensics', 'response'] as const;
  type CoreRole = typeof ALL_AGENTS[number];

  // The HQ is a real office floor now (cityInterior.hqOfficePlan): each core
  // agent has a seat at a desk in its wing, the Agent Manager an office.
  const HQ_PLAN = hqOfficePlan();
  const STATION_POSITIONS = Object.fromEntries(ALL_AGENTS.map((r) =>
    [r, [HQ_PLAN.stations[r].x, 0, HQ_PLAN.stations[r].z]])) as Record<CoreRole, [number, number, number]>;
  const STATION_LABELS: Record<CoreRole, string> = {
    security: 'SECURITY', threat: 'THREAT', assistant: 'ASSISTANT', system: 'SYSTEM',
    network: 'NETWORK', verifier: 'VERIFIER', planner: 'PLANNER', diagnostics: 'DIAGNOSTICS',
    forensics: 'FORENSICS', response: 'RESPONSE',
  };
  // One colour per role, everywhere: the HQ desk robots wear the same §18
  // accents as their city counterparts (cityPalette.ROLE_ACCENT).
  const AGENT_COLORS = Object.fromEntries(ALL_AGENTS.map((r) => [r, ROLE_ACCENT[r]])) as Record<CoreRole, number>;
  const CRITICAL_ROLES = new Set<CoreRole>(['security', 'threat', 'response', 'verifier']);

  // Real state vocabulary only (agentOffice.ts's LABEL_STATE + dynamic_spec.py
  // AgentStatus, lowercased, per lib/3d/AgentOffice3D.svelte's own proven
  // STATE_COLORS) -- reused, not re-derived.
  const STATE_COLORS: Record<string, number> = {
    idle: 0x2e6d78, queued: 0xf59e0b, preparing: 0x00d4ff, thinking: 0x8b5cf6,
    responding: 0x00d4ff, waiting_auth: 0xf59e0b, executing: 0x10b981, verifying: 0x14b8a6,
    completed: 0x10b981, warning: 0xf59e0b, blocked: 0xef4444, error: 0xef4444, disabled: 0x1e293b,
    proposed: 0xf59e0b, validating: 0xf59e0b, approved: 0xf59e0b, active: 0x10b981,
    waiting: 0xf59e0b, failed: 0xef4444, expired: 0x1e293b, destroyed: 0x1e293b,
    // At the Academy (agents/academy.py): violet, the Academy's own family.
    studying: 0x9578ff, enrolled: 0x6f63b8, training: 0x9578ff,
  };
  // Real-state -> the design's §3 vocabulary, for the on-station text label
  // only (STATE_COLORS above still drives the actual light color from the
  // real string, this is display text). No state this doesn't cover is ever
  // actually emitted by the backend (see docs' state-mapping table).
  function visualState(raw: string | undefined, isStale: boolean): string {
    if (isStale) return 'DISCONNECTED';
    const s = (raw ?? 'idle').toLowerCase();
    if (['queued', 'proposed', 'validating', 'approved'].includes(s)) return 'QUEUED';
    if (['thinking', 'preparing'].includes(s)) return 'THINKING';
    if (['responding', 'executing', 'active'].includes(s)) return 'WORKING';
    if (['waiting_auth', 'waiting', 'warning'].includes(s)) return 'WAITING';
    if (s === 'verifying') return 'VERIFYING';
    if (s === 'completed') return 'COMPLETED';
    if (['error', 'blocked', 'failed'].includes(s)) return 'FAILED';
    if (['expired', 'destroyed', 'disabled'].includes(s)) return 'DISCONNECTED';
    return s === 'idle' ? 'IDLE' : s.toUpperCase();
  }

  const TEMP_SLOTS = 6;
  const TEMP_SLOT_POSITIONS: [number, number, number][] = HQ_PLAN.tempSeats.slice(0, TEMP_SLOTS)
    .map((s) => [s.x, 0, s.z]);
  /** Hot-desk screens per temp slot, from buildHQDecor: lit only while a real
      specialist is assigned the desk. */
  let hqTempScreens: THREE.Mesh[][] = [];
  const ORIGIN_LABEL: Record<string, string> = { EPHEMERAL_LOCAL: 'TEMP LOCAL', EPHEMERAL_CLOUD: 'CLOUD', CORE: 'LOCAL' };
  const ORIGIN_COLOR: Record<string, number> = { EPHEMERAL_LOCAL: 0x38e0ff, EPHEMERAL_CLOUD: 0xffb244, CORE: 0x38e0ff };

  interface HQAgent {
    role: CoreRole; group: THREE.Group; robot: Robot; pose: RobotPose; indicator: THREE.Mesh;
    taskLabel: THREE.Sprite; stateLabel: THREE.Sprite; teamRing: THREE.Mesh; verifierGlow?: THREE.PointLight;
    screens: THREE.Mesh[];
  }
  interface HQTemp {
    id: string; group: THREE.Group; robot: Robot; pose: RobotPose; indicator: THREE.Mesh;
    stateLabel: THREE.Sprite; ttlLabel: THREE.Sprite; position: THREE.Vector3; slot: number;
  }

  /** Monitor brightness from REAL state: working lights the screen fully,
      idle leaves it on a dimmed desktop, a dead link turns it nearly off. A
      lit screen is never shown for an agent the backend says is not there. */
  function setScreens(screens: THREE.Mesh[], level: 'work' | 'idle' | 'off'): void {
    const v = level === 'work' ? 1 : level === 'idle' ? 0.42 : 0.07;
    for (const s of screens) (s.material as THREE.MeshBasicMaterial).color.setScalar(v);
  }

  let hqGroup: THREE.Group;
  const hqStations: Map<CoreRole, HQAgent> = new Map();
  const hqTemps: Map<string, HQTemp> = new Map();
  let hqTeamLines: THREE.Line[] = [];
  let hqPulses: { sprite: THREE.Sprite; tween: gsap.core.Tween }[] = [];
  let hqDisconnectedBadge: THREE.Sprite | null = null;
  let hqEntered = false;
  let hqLastAgentSig = '';
  let hqLastTempSig = '';
  let hqLastTeamSig = '';
  let hqWasCritical = false;

  function hqLabel(text: string, fontSize: number, bold: boolean, color = 'rgba(232, 244, 255, 0.99)'): THREE.Sprite {
    const canvas = document.createElement('canvas');
    canvas.width = 512; canvas.height = 128;
    const ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.font = `${bold ? '800' : '600'} ${fontSize}px "Space Grotesk", "Segoe UI", system-ui, sans-serif`;
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      ctx.fillStyle = color;
      ctx.fillText(text, canvas.width / 2, canvas.height / 2 + 2);
    }
    const texture = new THREE.CanvasTexture(canvas);
    texture.minFilter = THREE.LinearFilter;
    // toneMapped:false -- text is UI, its colour must not shift with exposure.
    const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: texture, transparent: true, depthWrite: false, toneMapped: false }));
    sprite.scale.set(bold ? 3.6 : 3, bold ? 0.9 : 0.75, 1);
    return sprite;
  }
  function hqRedrawLabel(sprite: THREE.Sprite, text: string, color = 'rgba(232, 244, 255, 0.95)'): void {
    const canvas = sprite.material.map?.image as HTMLCanvasElement | undefined;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.font = '600 20px "Space Grotesk", system-ui, sans-serif';
    ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillStyle = color;
    ctx.fillText(text.replace(/_/g, ' '), canvas.width / 2, canvas.height / 2 + 2);
    sprite.material.map!.needsUpdate = true;
  }

  // CITY-4: the HQ's occupants are the same ARGUS mini robot the streets
  // use (cityKit.buildRobot) -- one design, one scale, one rig, so an agent
  // that walks out of HQ into the city is recognisably the same unit. The
  // old sphere-and-cylinder figure is gone.

  function buildWorkstation(role: CoreRole): HQAgent {
    const seat = HQ_PLAN.stations[role];
    const color = AGENT_COLORS[role];
    const group = new THREE.Group();
    group.position.set(seat.x, 0, seat.z);
    group.rotation.y = seat.face;

    // A real workstation: desk, dual monitors (lit from real state -- see
    // setScreens), keyboard, PC tower, lamp, task chair. Baked to a few
    // meshes; the screens stay separate so state can dim them.
    const furniture = seatFurniture({ x: 0, z: 0, face: 0 },
      { accent: color, variant: ALL_AGENTS.indexOf(role), lamp: true,
        top: CRITICAL_ROLES.has(role) ? 'walnut' : 'oak' }, 0x2b3038);
    mergeStatic(furniture.group);
    group.add(furniture.group);
    setScreens(furniture.screens, 'idle');

    // Seated at the desk, facing it (the kit robot faces +z; the desk is -z).
    const robot = buildRobot(color, seat.x * 0.7 + seat.z * 0.3);
    robot.group.rotation.y = Math.PI;
    group.add(robot.group);

    // Status LED on the desk -- the one light that carries the state colour.
    const indicator = new THREE.Mesh(new THREE.SphereGeometry(0.06, 10, 8),
      new THREE.MeshStandardMaterial({ color, emissive: color, emissiveIntensity: 0.8 }));
    indicator.position.set(0.55, 0.78, -1.1);
    group.add(indicator);

    const roleLabel = hqLabel(STATION_LABELS[role], 30, true);
    roleLabel.position.set(0, 2.55, 0);
    group.add(roleLabel);
    const stateLabel = hqLabel('IDLE', 22, false, 'rgba(160, 190, 200, 0.9)');
    stateLabel.position.set(0, 2.18, 0);
    group.add(stateLabel);
    const taskLabel = hqLabel('NO ACTIVE TASK', 18, false, 'rgba(214, 238, 245, 0.75)');
    taskLabel.scale.set(4.4, 1.1, 1);
    taskLabel.position.set(0, 1.85, 0);
    group.add(taskLabel);

    // Team-membership ring: invisible (scale 0) until a real active team
    // includes this station.
    const teamRing = new THREE.Mesh(new THREE.RingGeometry(1.3, 1.4, 24),
      new THREE.MeshStandardMaterial({ color: 0x38e0ff, emissive: 0x38e0ff, emissiveIntensity: 1.0, side: THREE.DoubleSide, transparent: true, opacity: 0.7 }));
    teamRing.rotation.x = -Math.PI / 2;
    teamRing.position.y = 0.02;
    teamRing.scale.set(0.001, 0.001, 0.001);
    group.add(teamRing);

    let verifierGlow: THREE.PointLight | undefined;
    if (role === 'verifier') {
      verifierGlow = new THREE.PointLight(color, 0, 6);
      verifierGlow.position.set(0, 1.6, 0);
      group.add(verifierGlow);
    }

    group.userData.hqRole = role;
    hqGroup.add(group);
    return { role, group, robot, pose: 'idle', indicator, taskLabel, stateLabel, teamRing, verifierGlow,
             screens: furniture.screens };
  }

  /* The Agent Manager's own office inside HQ: an executive desk, the Manager
     seated at it (its posture from the REAL manager state), and a wall
     display drawn from the REAL /api/agents/manager numbers. */
  let hqManager: { robot: Robot; pose: RobotPose; screens: THREE.Mesh[];
                   canvas: HTMLCanvasElement; texture: THREE.CanvasTexture; sig: string } | null = null;

  function buildManagerOffice(): void {
    const seat = HQ_PLAN.manager;
    const group = new THREE.Group();
    group.position.set(seat.x, 0, seat.z);
    group.rotation.y = seat.face;
    const f = seatFurniture({ x: 0, z: 0, face: 0 },
      { accent: MANAGER_ACCENT, width: 2.3, top: 'walnut', lamp: true, variant: 3 }, 0x4a3426);
    mergeStatic(f.group);
    group.add(f.group);
    setScreens(f.screens, 'idle');
    const robot = buildRobot(MANAGER_ACCENT, 0.5);
    robot.group.rotation.y = Math.PI;
    robot.group.scale.setScalar(1.08);
    group.add(robot.group);
    const title = hqLabel('AGENT MANAGER', 30, true, 'rgba(255, 226, 154, 0.98)');
    title.position.set(0, 2.6, 0);
    group.add(title);
    hqGroup.add(group);

    const canvas = document.createElement('canvas');
    canvas.width = 640; canvas.height = 280;
    const texture = new THREE.CanvasTexture(canvas);
    texture.colorSpace = THREE.SRGBColorSpace;
    const d = HQ_PLAN.managerDisplay;
    const display = wallDisplay(d.w, d.h, texture);
    display.position.set(d.x, d.y, d.z);
    hqGroup.add(display);
    hqManager = { robot, pose: 'idle', screens: f.screens, canvas, texture, sig: '' };
    drawManagerDisplay(null);
  }

  /** Redraw the office wall display from the real manager state. */
  function drawManagerDisplay(st: ManagerState | null): void {
    if (!hqManager) return;
    const sig = st ? JSON.stringify([st.workforce, st.pending_hires, st.active_teams,
      st.hiring_log.slice(-3).map((h) => [h.name, h.state])]) : 'offline';
    if (sig === hqManager.sig) return;
    hqManager.sig = sig;
    const g = hqManager.canvas.getContext('2d');
    if (!g) return;
    g.fillStyle = '#0b1424'; g.fillRect(0, 0, 640, 280);
    g.fillStyle = '#ffd166'; g.font = '800 30px "Space Grotesk", system-ui, sans-serif';
    g.fillText('AGENT MANAGEMENT CENTER', 24, 44);
    if (!st) {
      g.fillStyle = '#8a97a6'; g.font = '600 24px "Space Grotesk", system-ui, sans-serif';
      g.fillText('Manager offline -- no live numbers', 24, 110);
    } else {
      const cells: [string, number][] = [
        ['WORKERS', st.workforce.total], ['ACTIVE', st.workforce.active],
        ['IDLE', st.workforce.idle], ['TEMPORARY', st.workforce.temporary],
        ['HIRE REQUESTS', st.pending_hires], ['TEAMS', st.active_teams],
        ['QUEUED', st.workforce.queued_work],
      ];
      cells.forEach(([k, v], i) => {
        const x = 24 + (i % 4) * 152, y = 92 + Math.floor(i / 4) * 78;
        g.fillStyle = '#7f93ad'; g.font = '700 15px "Space Grotesk", system-ui, sans-serif';
        g.fillText(k, x, y);
        g.fillStyle = v > 0 && k !== 'IDLE' && k !== 'WORKERS' ? '#7fefff' : '#eef6ff';
        g.font = '800 38px "Space Grotesk", system-ui, sans-serif';
        g.fillText(String(v), x, y + 40);
      });
      const last = st.hiring_log.slice(-1)[0];
      g.fillStyle = '#9fb2c8'; g.font = '600 17px "Space Grotesk", system-ui, sans-serif';
      g.fillText(last ? `LAST HIRE: ${last.name} -- ${last.state}` : 'NO HIRES YET', 24, 262);
    }
    hqManager.texture.needsUpdate = true;
  }

  /* The Team Operations Room's wall screen: the running team's
     task graph as the orchestrator reports it -- one column per dependency
     depth, every task a card in its real state, an edge per real dependency.
     With no team running the screen says so and nothing else. */
  let opsScreen: { canvas: HTMLCanvasElement; texture: THREE.CanvasTexture; sig: string } | null = null;

  function buildOpsScreen(): void {
    const canvas = document.createElement('canvas');
    canvas.width = 1024; canvas.height = 436;
    const texture = new THREE.CanvasTexture(canvas);
    texture.colorSpace = THREE.SRGBColorSpace;
    const d = HQ_PLAN.opsDisplay;
    const display = wallDisplay(d.w, d.h, texture);
    display.position.set(d.x, d.y, d.z);
    display.rotation.y = d.ry;
    hqGroup.add(display);
    opsScreen = { canvas, texture, sig: '' };
    drawOpsScreen(null);
  }

  const OPS_STATE_COLOR: Record<string, string> = {
    RUNNING: '#38e0ff', COMPLETED: '#4ade9e', FAILED: '#ff6b6b', TIMED_OUT: '#ff6b6b',
    CANCELLED: '#8a97a6', SKIPPED: '#8a97a6', QUEUED: '#ffb244', WAITING: '#ffb244',
  };

  function drawOpsScreen(team: TeamDetail | null): void {
    if (!opsScreen) return;
    const live = !!team && !HQ_TEAM_TERMINAL.has(team.state);
    const sig = team ? JSON.stringify([team.team_id, team.state, Math.round(team.progress * 100),
      team.tasks.map((x) => [x.task_id, x.state])]) : 'idle';
    if (sig === opsScreen.sig) return;
    opsScreen.sig = sig;
    const g = opsScreen.canvas.getContext('2d');
    if (!g) return;
    const W = 1024, H = 436;
    g.fillStyle = '#0a1322'; g.fillRect(0, 0, W, H);
    g.fillStyle = '#7fefff'; g.font = '800 30px "Space Grotesk", system-ui, sans-serif';
    g.fillText('TEAM OPERATIONS', 28, 46);
    if (!team) {
      g.fillStyle = '#8a97a6'; g.font = '600 24px "Space Grotesk", system-ui, sans-serif';
      g.fillText('NO ACTIVE TEAM -- screens idle', 28, 110);
      opsScreen.texture.needsUpdate = true;
      return;
    }
    g.fillStyle = '#dce9f5'; g.font = '700 20px "Space Grotesk", system-ui, sans-serif';
    const goal = (team.goal || team.playbook.replace(/_/g, ' ')).toUpperCase();
    g.fillText(`${team.team_id} · ${goal.length > 58 ? `${goal.slice(0, 57)}…` : goal}`, 290, 44);
    g.fillStyle = live ? '#7fefff' : '#8a97a6';
    g.fillText(`${team.state} · ${Math.round(team.progress * 100)}%`, W - 230, 44);
    // progress bar
    g.fillStyle = '#1b2a40'; g.fillRect(28, 60, W - 56, 8);
    g.fillStyle = live ? '#38e0ff' : '#4ade9e'; g.fillRect(28, 60, (W - 56) * team.progress, 8);
    // depth of each task = longest dependency chain above it
    const byId = new Map(team.tasks.map((x) => [x.task_id, x]));
    const depth = new Map<string, number>();
    const dOf = (id: string, seen = new Set<string>()): number => {
      if (depth.has(id)) return depth.get(id)!;
      if (seen.has(id)) return 0;
      seen.add(id);
      const t = byId.get(id);
      const d = t && t.dependencies.length ? 1 + Math.max(...t.dependencies.map((x) => dOf(x, seen))) : 0;
      depth.set(id, d);
      return d;
    };
    team.tasks.forEach((x) => dOf(x.task_id));
    const cols = Math.max(1, ...[...depth.values()].map((d) => d + 1));
    const colW = (W - 56) / cols;
    const rows = new Map<number, number>();
    const pos = new Map<string, { x: number; y: number }>();
    for (const x of team.tasks) {
      const c = depth.get(x.task_id) ?? 0;
      const r = rows.get(c) ?? 0;
      rows.set(c, r + 1);
      pos.set(x.task_id, { x: 28 + c * colW + 10, y: 92 + r * 66 });
    }
    // edges first, so cards draw over them
    g.strokeStyle = 'rgba(127, 239, 255, 0.45)'; g.lineWidth = 2;
    for (const x of team.tasks) {
      const to = pos.get(x.task_id)!;
      for (const dep of x.dependencies) {
        const from = pos.get(dep);
        if (!from) continue;
        g.beginPath(); g.moveTo(from.x + colW - 30, from.y + 26); g.lineTo(to.x, to.y + 26); g.stroke();
      }
    }
    for (const x of team.tasks) {
      const p = pos.get(x.task_id)!;
      const col = OPS_STATE_COLOR[x.state] ?? '#5d6f86';
      g.fillStyle = '#12213a'; g.fillRect(p.x, p.y, colW - 40, 52);
      g.fillStyle = col; g.fillRect(p.x, p.y, 6, 52);
      g.fillStyle = '#eef6ff'; g.font = '800 17px "Space Grotesk", system-ui, sans-serif';
      const who = (x.agent_id && !x.agent_id.startsWith('dyn-') ? x.agent_id : x.role).replace(/_/g, ' ').toUpperCase();
      g.fillText(who.slice(0, 22), p.x + 14, p.y + 22);
      g.fillStyle = col; g.font = '700 14px "Space Grotesk", system-ui, sans-serif';
      g.fillText(x.state, p.x + 14, p.y + 42);
    }
    opsScreen.texture.needsUpdate = true;
  }
  $: if (renderer && opsScreen) drawOpsScreen($teamOffice.activeTeam);

  function buildHQRoom(): void {
    hqGroup = new THREE.Group();
    hqGroup.position.copy(HQ_ORIGIN);
    hqGroup.visible = false;

    // The office itself: walls with night-city windows, zone carpets, the
    // Manager's glass office, meeting room, lounge, server row, shelves,
    // plants, printers and the six temporary hot-desks (cityInterior.ts).
    const decor = buildHQDecor(HQ_PLAN);
    hqGroup.add(decor.group);
    interiorCuts.set('agent-hq', decor.cut);
    hqTempScreens = decor.tempScreens;
    for (const screens of hqTempScreens) setScreens(screens, 'off');

    // Office lighting: a bright neutral ambient (it is an office, not a
    // cave), one warm key from the windows' side, and ceiling-style fills
    // over each wing. Children of hqGroup: nothing lights the city.
    hqGroup.add(new THREE.HemisphereLight(0xeef4ff, 0x3a3f48, 2.4));
    const key = new THREE.DirectionalLight(0xfff2e0, 2.2);
    key.position.set(18, 30, 22);
    hqGroup.add(key);
    for (const [x, z, c] of [[-18, -12, 0xdfeaff], [19, -12, 0xfff0d8], [-5, 4, 0xeaf2ff],
      [4, 13, 0xeaf2ff], [3, -17, 0xffe7c2], [-22, 10, 0xeaf2ff], [21, 14, 0xffe2c0],
      [28, -8, 0xfff0d8], [28, 6, 0xffe2c0]] as const) {
      const p = new THREE.PointLight(c, 55, 22, 2);
      p.position.set(x, 3.4, z);
      hqGroup.add(p);
    }

    ALL_AGENTS.forEach((role) => hqStations.set(role, buildWorkstation(role)));
    buildManagerOffice();
    buildOpsScreen();

    for (const zone of HQ_PLAN.zones) {
      const l = hqLabel(zone.label, 18, true, 'rgba(214, 232, 245, 0.85)');
      l.position.set(zone.x, 3.3, zone.z);
      l.scale.set(5.2, 1.3, 1);
      hqGroup.add(l);
    }

    scene.add(hqGroup);
    interiorGroups.set('agent-hq', hqGroup);
  }

  /* ---- CITY-4: the Academy and Verification interiors --------------------
     Real rooms, built once, parked at their own far origin and shown only
     when entered. Both are ARCHITECTURE ONLY where no backend signal exists:
     the Academy has no learning state to show yet and says so on its own
     floor rather than animating an invented one ("No fake
     training state yet"); the Institute's readout is driven by the same real
     verifier/team fields the HQ already reads. */

  /** A furnished room shell: floor plate, low perimeter wall, grid, and the
      restrained three-light rig every interior shares. */
  function interiorShell(id: InteriorId, origin: THREE.Vector3, halfW: number, halfD: number, accent: number, title: string): THREE.Group {
    const g = new THREE.Group();
    g.position.copy(origin);
    g.visible = false;
    const floor = new THREE.Mesh(new THREE.PlaneGeometry(halfW * 2, halfD * 2),
      new THREE.MeshStandardMaterial({ color: 0x090f12, roughness: 0.92, metalness: 0.08 }));
    floor.rotation.x = -Math.PI / 2;
    g.add(floor);
    const grid = new THREE.GridHelper(Math.max(halfW, halfD) * 2, 24, 0x1c3038, 0x0c1418);
    grid.position.y = 0.015;
    g.add(grid);
    // A closed hall like the HQ and the Academy: four walls and a roof, cut
    // away toward the camera (cityInterior.closedShell).
    const shell = closedShell({ x0: -halfW, x1: halfW, z0: -halfD, z1: halfD, accent, trim: 0x7fefff, wall: 0x1e2c38,
      name: 'VERIFICATION' });
    g.add(shell.group);
    interiorCuts.set(id, shell.cut);
    g.add(new THREE.HemisphereLight(0x9fd8ff, 0x0a0e10, 0.7));
    const key = new THREE.DirectionalLight(0xffffff, 0.85);
    key.position.set(18, 28, 14);
    g.add(key);
    const fill = new THREE.PointLight(accent, 0.7, 60);
    fill.position.set(0, 9, 0);
    g.add(fill);
    const heading = hqLabel(title, 26, true, 'rgba(232, 244, 255, 0.95)');
    heading.position.set(0, 5.4, -halfD + 0.6);
    heading.scale.set(14, 3.5, 1);
    g.add(heading);
    scene.add(g);
    return g;
  }

  /** Desks + terminal screens + seats: the furniture that makes a floor
      plate read as a room people work in. Stylized low-poly, shared
      materials, no imported assets. */
  function roomZone(label: string, x: number, z: number, w: number, d: number, accent: number, desks: number): THREE.Group {
    const g = new THREE.Group();
    g.position.set(x, 0, z);
    const plate = pad(w, d, structure(0x0e161a, { roughness: 0.88 }), 0.03);
    g.add(plate);
    const edge = trim(accent, 0.6);
    for (const [ox, oz, bw, bd] of [[0, d / 2, w, 0.1], [0, -d / 2, w, 0.1], [w / 2, 0, 0.1, d], [-w / 2, 0, 0.1, d]] as const) {
      const bar = box(bw, 0.06, bd, edge);
      bar.position.set(ox, 0.04, oz);
      g.add(bar);
    }
    const deskMat = structure(0x141c20, { roughness: 0.6, emissive: accent, emissiveIntensity: 0.12 });
    const screenMat = structure(0x080e11, { emissive: accent, emissiveIntensity: 0.4 });
    const seatMat = structure(0x1b2329, { roughness: 0.7 });
    for (let i = 0; i < desks; i++) {
      const col = i % 2, row = Math.floor(i / 2);
      const dx = (col - 0.5) * (w * 0.44), dz = (row - (Math.ceil(desks / 2) - 1) / 2) * 1.9;
      const desk = box(1.7, 0.52, 0.85, deskMat);
      desk.position.set(dx, 0.04, dz);
      g.add(desk);
      const screen = box(1.05, 0.62, 0.06, screenMat);
      screen.position.set(dx, 0.56, dz - 0.34);
      screen.rotation.x = -0.12;
      g.add(screen);
      const seat = box(0.55, 0.42, 0.55, seatMat);
      seat.position.set(dx, 0.04, dz + 0.75);
      g.add(seat);
    }
    const l = hqLabel(label, 20, true, 'rgba(157, 234, 255, 0.9)');
    l.position.set(0, 2.5, 0);
    l.scale.set(6.4, 1.6, 1);
    g.add(l);
    return g;
  }

  const ACADEMY_ORIGIN = new THREE.Vector3(0, 0, -420);
  const VERIFY_ORIGIN = new THREE.Vector3(0, 0, -560);
  let academyScreens: THREE.Mesh[] = [];
  interface Student { robot: Robot; pose: RobotPose; label: THREE.Sprite; shown: string }
  const academyStudents = new Map<string, Student>();

  /* An agent is AT the Academy from the moment the backend enrols it
     (SCHEDULED/QUEUED -- waiting its turn on the one shared model) until its
     session ends. Only the running student is STUDYING; the verifier's check
     is EVALUATING. Every state here is the backend's own. */
  type StudyState = 'SCHEDULED' | 'QUEUED' | 'ACTIVE' | 'EVALUATING';
  const OPEN_STUDY = new Set(['SCHEDULED', 'QUEUED', 'ACTIVE', 'EVALUATING']);
  function studying(role: string): StudyState | null {
    if ($academyState.link !== 'online') return null;
    const session = $academyState.snapshot?.sessions.find((s) => s.agent_id === role && OPEN_STUDY.has(s.state));
    return (session?.state as StudyState | undefined) ?? null;
  }
  /** The robot's state string for a study state (cityAgents sends both to the Academy). */
  const studyRaw = (s: StudyState) => (s === 'ACTIVE' || s === 'EVALUATING' ? 'studying' : 'enrolled');
  const STUDY_TEXT: Record<StudyState, string> = {
    SCHEDULED: 'WAITING FOR THE MODEL', QUEUED: 'WAITING FOR THE MODEL',
    ACTIVE: 'STUDYING', EVALUATING: 'BEING CHECKED',
  };
  const academySigOf = () => $academyState.snapshot?.sessions.filter((s) => OPEN_STUDY.has(s.state))
    .map((s) => `${s.agent_id}:${s.state}`).join('|') ?? '';

  function applyAcademyStudents(): void {
    if (!renderer || !academyStudents.size) return;
    let active = false;
    for (const [role, st] of academyStudents) {
      const state = studying(role);
      st.robot.group.visible = !!state;
      if (!state) continue;
      st.pose = state === 'EVALUATING' ? 'verify' : state === 'ACTIVE' ? 'work' : 'idle';
      poseRobot(st.robot, st.pose, 0, true);
      if (st.shown !== state) {
        st.shown = state;
        hqRedrawLabel(st.label, STUDY_TEXT[state], state === 'ACTIVE' ? 'rgba(185, 164, 255, 0.98)'
          : state === 'EVALUATING' ? 'rgba(157, 234, 255, 0.95)' : 'rgba(200, 200, 215, 0.85)');
      }
      if (state === 'ACTIVE') active = true;
    }
    setScreens(academyScreens, active ? 'work' : 'idle');
  }

  function buildAcademyInterior(): void {
    // A real school floor (cityInterior.buildAcademyDecor): classroom,
    // compute classroom, simulation lab, exam room, library, robot training
    // room, corridor lockers, lobby and cafeteria. Lit like a building people
    // use, not a server hall.
    const g = new THREE.Group();
    g.position.copy(ACADEMY_ORIGIN);
    g.visible = false;
    const decor = buildAcademyDecor();
    g.add(decor.group);
    interiorCuts.set('academy', decor.cut);
    academyScreens = decor.screens;
    setScreens(academyScreens, 'idle');
    g.add(new THREE.HemisphereLight(0xf4eeff, 0x3a3548, 2.3));
    const key = new THREE.DirectionalLight(0xfff2e0, 2.0);
    key.position.set(18, 30, 22);
    g.add(key);
    for (const [x, z, c] of [[-18, -14, 0xf0e8ff], [-2, -14, 0xeaf2ff], [16, -14, 0xe0d8ff],
      [-19, 2, 0xfff0d8], [-3, 2, 0xfff0d8], [16, 2, 0xeaf2ff], [-18, 16, 0xffe7c2], [8, 16, 0xffe7c2]] as const) {
      const p = new THREE.PointLight(c, 50, 20, 2);
      p.position.set(x, 3.4, z);
      g.add(p);
    }
    for (const zone of ACADEMY_PLAN.zones) {
      const l = hqLabel(zone.label, 18, true, 'rgba(232, 222, 255, 0.9)');
      l.position.set(zone.x, 3.3, zone.z);
      l.scale.set(5.2, 1.3, 1);
      g.add(l);
    }
    const heading = hqLabel(INTERIOR_TITLE.academy, 26, true, 'rgba(232, 244, 255, 0.95)');
    heading.position.set(0, 5.4, -ACADEMY_PLAN.halfD + 0.6);
    heading.scale.set(14, 3.5, 1);
    g.add(heading);
    // Each student is visible only while the backend has an open session for
    // it, seated at its own classroom desk (stable by role), facing the board.
    ALL_AGENTS.forEach((role, i) => {
      const desk = ACADEMY_PLAN.classDesks[i];
      const robot = buildRobot(ROLE_ACCENT[role] ?? 0x9578ff, i * 0.6);
      robot.group.position.set(desk.x, 0, desk.z + 0.55);
      robot.group.rotation.y = Math.PI;
      robot.group.visible = false;
      g.add(robot.group);
      // Same tag sizes as the HQ desks, so a student reads as well as a worker.
      const name = hqLabel(role.toUpperCase(), 32, true);
      name.position.set(0, 2.6, 0);
      name.scale.set(3.4, 0.85, 1);
      robot.group.add(name);
      const label = hqLabel('', 22, false);
      label.position.set(0, 2.15, 0);
      label.scale.set(4.2, 1.05, 1);
      robot.group.add(label);
      academyStudents.set(role, { robot, pose: 'idle', label, shown: '' });
    });
    scene.add(g);
    interiorGroups.set('academy', g);
    applyAcademyStudents();
  }

  let verifyStatusLabel: THREE.Sprite;
  let verifySubLabel: THREE.Sprite;
  let verifyBeam: THREE.Mesh;

  function buildVerifyInterior(): void {
    const g = interiorShell('verification-institute', VERIFY_ORIGIN, 17, 14, 0x9deaff, INTERIOR_TITLE['verification-institute']);
    // The validation chamber: a raised dais, a containment ring and the
    // beam whose brightness tracks the REAL verifier state (see
    // applyVerifyInterior -- it is off unless the backend says verifying).
    const dais = cylinder(4.2, 4.6, 0.35, 24, structure(0x0d151a, { roughness: 0.4, emissive: 0x9deaff, emissiveIntensity: 0.2 }));
    dais.position.y = 0.17;
    g.add(dais);
    g.add(trimRing(4.3, 0.36, 0x9deaff, 0.06, 0.9));
    verifyBeam = cylinder(0.5, 0.5, 5.2, 12, new THREE.MeshStandardMaterial({ color: 0x9deaff, emissive: 0x9deaff, emissiveIntensity: 0, transparent: true, opacity: 0.55 }));
    verifyBeam.position.y = 2.9;
    g.add(verifyBeam);
    // Containment frame: four uprights and a ring, the "validation chamber"
    // the exterior's rooftop frame echoes.
    const postMat = structure(SILVER, { roughness: 0.45 });
    for (let i = 0; i < 4; i++) {
      const a = (i / 4) * Math.PI * 2 + Math.PI / 4;
      const post = box(0.25, 5.6, 0.25, postMat);
      post.position.set(Math.sin(a) * 4.3, 0.35, Math.cos(a) * 4.3);
      g.add(post);
    }
    const cap = trimRing(4.3, 5.95, 0x9deaff, 0.08, 1.0);
    g.add(cap);
    spinningParts.push({ obj: cap, speed: 0.04 });
    g.add(roomZone('EVIDENCE BENCH', -11, 6, 10, 9, 0x9deaff, 4));
    g.add(roomZone('RESULT REVIEW', 11, 6, 10, 9, 0x9deaff, 4));
    verifyStatusLabel = hqLabel('NO VERIFICATION RUNNING', 24, true, 'rgba(160, 190, 200, 0.85)');
    verifyStatusLabel.position.set(0, 7.4, 0);
    verifyStatusLabel.scale.set(13, 3.2, 1);
    g.add(verifyStatusLabel);
    verifySubLabel = hqLabel('VERIFIER IDLE', 18, false, 'rgba(214, 238, 245, 0.7)');
    verifySubLabel.position.set(0, 6.5, 0);
    verifySubLabel.scale.set(10, 2.5, 1);
    g.add(verifySubLabel);
    interiorGroups.set('verification-institute', g);
  }

  /** Drives the Institute's readout from the SAME real fields the HQ reads:
      the verifier agent's own state and the active team's phase/verdict.
      Nothing here is simulated -- with no team running and an idle verifier
      the hall reads "NO VERIFICATION RUNNING" and the beam stays dark. */
  let verifyLastSig = '';
  function applyVerifyInterior(snapshot: typeof $agentOffice.snapshot, team: TeamDetail | null): void {
    if (!verifyStatusLabel) return;
    const vState = snapshot?.agents.find((a) => a.id === 'verifier')?.state ?? 'idle';
    const phase = team?.current_phase ?? '';
    const sig = `${vState}:${phase}:${team?.verdict ?? ''}:${team?.team_id ?? ''}`;
    if (sig === verifyLastSig) return;
    verifyLastSig = sig;
    const running = vState === 'verifying' || phase === 'verifying';
    hqRedrawLabel(verifyStatusLabel, running ? 'VERIFICATION IN PROGRESS' : 'NO VERIFICATION RUNNING',
      running ? 'rgba(157, 234, 255, 0.95)' : 'rgba(160, 190, 200, 0.85)');
    hqRedrawLabel(verifySubLabel,
      running ? `TEAM ${team?.team_id ?? '—'} · ${hqStateLabel(vState)}`
        : team?.verdict ? `LAST VERDICT · ${team.verdict.toUpperCase()}` : `VERIFIER ${hqStateLabel(vState)}`,
      'rgba(214, 238, 245, 0.7)');
    gsap.to(verifyBeam.material as THREE.MeshStandardMaterial, { emissiveIntensity: running ? 1.4 : 0, duration: 0.5, overwrite: true });
  }

  /* ---- CITY-3: HQ state application -------------------------------------
     Signature-diffed like CITY-1/2's own applyLiveState and
     AgentOffice3D.svelte's applySnapshot -- runs once per store recompute
     (bounded by real WS/poll volume), never rebuilds geometry, never
     touches GSAP unless the underlying signature actually changed. */
  const hqScratch = new THREE.Color();

  /** Backend state -> interior station posture. The HQ interior still uses
   *  cityKit's procedural rig (it is a fixed, seated-scale room where a full
   *  animation mixer per station would buy nothing), so it needs the pose
   *  vocabulary rather than the GLB clip names the street agents use. Same
   *  discipline either way: pure function of the reported state, no guessing. */
  function poseFor(state: string): RobotPose {
    switch (state) {
      case 'thinking': return 'think';
      case 'verifying': return 'verify';
      case 'executing': case 'responding': case 'preparing': case 'active': return 'work';
      case 'queued': case 'waiting_auth': case 'waiting': case 'proposed': case 'validating': return 'wait';
      case 'error': case 'blocked': case 'failed': return 'failed';
      default: return 'idle';
    }
  }

  function disposeSprite(s: THREE.Sprite): void {
    s.material.map?.dispose();
    s.material.dispose();
  }

  function applyHQAgents(snapshot: typeof $agentOffice.snapshot, link: string): void {
    if (!renderer || hqStations.size === 0) return;
    const isStale = link !== 'online' && link !== 'degraded';
    setHQDisconnectedBadge(isStale || $teamOffice.link === 'offline');
    const sig = `${snapshot ? snapshot.agents.map((a) => `${a.id}:${a.state}:${a.queue_position}:${a.current_job_id}`).join('|') : 'offline'}:${link}:${academySigOf()}`;
    if (sig === hqLastAgentSig) return;
    hqLastAgentSig = sig;

    ALL_AGENTS.forEach((role) => {
      const station = hqStations.get(role);
      if (!station) return;
      const a: OfficeAgent | undefined = snapshot?.agents.find((x) => x.id === role);
      const study = studying(role);
      const raw = isStale ? 'disabled' : study ? studyRaw(study) : (a?.state ?? 'idle');
      station.robot.group.visible = !studying(role);
      const colorHex = isStale ? 0x1e293b : (STATE_COLORS[raw] ?? STATE_COLORS.idle);
      hqScratch.set(colorHex);
      gsap.to(station.indicator.material, { emissive: hqScratch, emissiveIntensity: raw === 'idle' ? 0.6 : 1.15, duration: 0.4, overwrite: true });
      // The robot's visor line is the ONE part that takes the state colour
      // -- the body stays graphite (never recolour the whole
      // robot). Its posture comes from the same state, via poseFor.
      station.robot.visor.color.set(colorHex);
      station.robot.visor.emissive.set(colorHex);
      gsap.to(station.robot.visor, { emissiveIntensity: raw === 'thinking' ? 2.2 : 1.5, duration: 0.4, overwrite: true });
      station.pose = poseFor(raw);
      setScreens(station.screens, isStale || raw === 'disabled' ? 'off'
        : WORKING_STATES.has(raw) || raw === 'queued' ? 'work' : 'idle');
      if (station.verifierGlow) {
        const verifying = raw === 'verifying';
        gsap.to(station.verifierGlow, { intensity: verifying ? 3.2 : 0, duration: 0.35, overwrite: true });
      }
      hqRedrawLabel(station.stateLabel, visualState(a?.state, isStale), isStale ? 'rgba(138,151,160,0.85)' : undefined);
      const task = isStale ? 'LINK DOWN'
        : a?.current_job_id ? `JOB ${a.current_job_id}`
        : a && a.queue_position > 0 ? 'WAITING FOR MODEL'
        : 'NO ACTIVE TASK';
      hqRedrawLabel(station.taskLabel, task);
    });
  }

  /** First hot-desk no live specialist occupies (a stable seat per agent --
      re-sorting the list must not make robots swap desks). */
  function freeTempSlot(): number {
    const used = new Set([...hqTemps.values()].map((t) => t.slot));
    for (let i = 0; i < TEMP_SLOTS; i++) if (!used.has(i)) return i;
    return -1;
  }

  function spawnHQTemp(a: DynamicAgentView, slotIndex: number): void {
    const pos = TEMP_SLOT_POSITIONS[slotIndex % TEMP_SLOTS];
    const seat = HQ_PLAN.tempSeats[slotIndex % TEMP_SLOTS];
    const color = ORIGIN_COLOR[a.type] ?? 0x94a3b8;
    const robot = buildRobot(color, slotIndex * 1.9);
    robot.group.rotation.y = Math.PI;              // face the hot-desk
    const group = new THREE.Group();
    group.add(robot.group);
    group.position.set(pos[0], pos[1], pos[2]);
    group.rotation.y = seat.face;
    group.scale.set(0.001, 0.001, 0.001);
    group.userData.hqTempId = a.id;
    hqGroup.add(group);
    // The workstation powers up for the assigned specialist.
    setScreens(hqTempScreens[slotIndex] ?? [], 'idle');

    const indicator = new THREE.Mesh(new THREE.SphereGeometry(0.06, 10, 8),
      new THREE.MeshStandardMaterial({ color, emissive: color, emissiveIntensity: 0.9 }));
    indicator.position.set(0.5, 0.78, -1.1);
    indicator.userData.ownGeometry = true;   // see destroyHQTemp: safe to dispose
    group.add(indicator);
    const nameLabel = hqLabel(a.name.toUpperCase().slice(0, 22), 16, true);
    nameLabel.position.y = 2.55;
    nameLabel.scale.set(3.4, 0.85, 1);
    group.add(nameLabel);
    const originLabel = hqLabel(ORIGIN_LABEL[a.type] ?? 'LOCAL', 13, false, 'rgba(214,238,245,0.7)');
    originLabel.position.y = 2.28;
    group.add(originLabel);
    const stateLabel = hqLabel(visualState(a.state, false), 15, false, 'rgba(160,190,200,0.85)');
    stateLabel.position.y = 1.95;
    group.add(stateLabel);
    const ttlLabel = hqLabel(a.ttl_remaining_s > 0 ? `TTL ${Math.round(a.ttl_remaining_s)}S` : '', 12, false, 'rgba(125,230,255,0.75)');
    ttlLabel.position.y = 1.7;
    ttlLabel.scale.set(2.6, 0.65, 1);
    group.add(ttlLabel);

    gsap.to(group.scale, { x: 1, y: 1, z: 1, duration: 0.4, ease: 'back.out(1.6)' });
    hqTemps.set(a.id, { id: a.id, group, robot, pose: poseFor(a.state.toLowerCase()), indicator, stateLabel, ttlLabel, position: new THREE.Vector3(...pos), slot: slotIndex });
  }

  function destroyHQTemp(id: string): void {
    const t = hqTemps.get(id);
    if (!t) return;
    // Lifecycle over: the hot-desk powers down.
    setScreens(hqTempScreens[t.slot] ?? [], 'off');
    gsap.killTweensOf(t.group.scale);
    gsap.to(t.group.scale, {
      x: 0.001, y: 0.001, z: 0.001, duration: 0.28, ease: 'power1.in',
      onComplete: () => {
        hqGroup.remove(t.group);
        // Only this temp's OWN resources: its sprites' canvas textures, its
        // pod/indicator, and its robot's two per-unit emissive materials.
        // The robot's body/joint/plate materials and every geometry the kit
        // hands out are SHARED across the whole city -- disposing them here
        // would blank every other building and robot (they are freed once,
        // by disposeKit(), on unmount).
        disposeRobot(t.robot);
        t.group.traverse((obj) => {
          if (obj instanceof THREE.Sprite) disposeSprite(obj);
          else if (obj instanceof THREE.Mesh && obj.userData.ownGeometry) {
            obj.geometry.dispose();
            (obj.material as THREE.Material).dispose();
          }
        });
      },
    });
    hqTemps.delete(id);
  }

  function applyHQDynamic(list: DynamicAgentView[]): void {
    if (!renderer || hqStations.size === 0) return;
    const sig = list.map((a) => `${a.id}:${a.state}:${Math.round(a.ttl_remaining_s ?? 0)}`).sort().join('|');
    if (sig === hqLastTempSig) return;
    hqLastTempSig = sig;

    const liveIds = new Set(list.map((a) => a.id));
    for (const id of Array.from(hqTemps.keys())) if (!liveIds.has(id)) destroyHQTemp(id);

    list.slice(0, TEMP_SLOTS).forEach((a) => {
      const existing = hqTemps.get(a.id);
      if (!existing) {
        const slot = freeTempSlot();
        if (slot >= 0) spawnHQTemp(a, slot);
        return;
      }
      setScreens(hqTempScreens[existing.slot] ?? [], WORKING_STATES.has(a.state.toLowerCase()) ? 'work' : 'idle');
      const color = new THREE.Color(STATE_COLORS[a.state.toLowerCase()] ?? ORIGIN_COLOR[a.type] ?? 0x94a3b8);
      gsap.to(existing.indicator.material, { emissive: color, duration: 0.35, overwrite: true });
      existing.robot.visor.color.copy(color);
      existing.robot.visor.emissive.copy(color);
      existing.pose = poseFor(a.state.toLowerCase());
      hqRedrawLabel(existing.stateLabel, visualState(a.state, false), 'rgba(160,190,200,0.85)');
      hqRedrawLabel(existing.ttlLabel, a.ttl_remaining_s > 0 ? `TTL ${Math.round(a.ttl_remaining_s)}S` : 'EXPIRING', 'rgba(125,230,255,0.75)');
    });
  }

  function clearHQTeamLines(): void {
    for (const line of hqTeamLines) { hqGroup.remove(line); line.geometry.dispose(); (line.material as THREE.Material).dispose(); }
    hqTeamLines = [];
    for (const station of hqStations.values()) station.teamRing.scale.set(0.001, 0.001, 0.001);
  }
  function hqLineBetween(a: THREE.Vector3, b: THREE.Vector3, color: number): THREE.Line {
    const geometry = new THREE.BufferGeometry().setFromPoints([
      new THREE.Vector3(a.x, a.y + 1.6, a.z), new THREE.Vector3(b.x, b.y + 1.2, b.z),
    ]);
    const material = new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.6 });
    const line = new THREE.Line(geometry, material);
    hqGroup.add(line);
    return line;
  }

  // PLANNER is the visual team coordinator -- links run FROM
  // planner (when planner itself is a member) to every other involved core
  // station, and from a temp/cloud member's own parent core station to its
  // slot, exactly as agents/orchestrator.py's real tree already has it.
  function applyHQTeam(team: TeamDetail | null): void {
    if (!renderer || hqStations.size === 0) return;
    const sig = team ? `${team.team_id}:${team.state}:${team.members.map((m) => `${m.member_id}:${m.state}`).join(',')}` : '';
    if (sig === hqLastTeamSig) return;
    hqLastTeamSig = sig;
    clearHQTeamLines();
    if (!team) return;

    const involvedCore = team.members.filter((m) => m.kind === 'core').map((m) => m.role as CoreRole).filter((r) => hqStations.has(r));
    const hub = involvedCore.includes('planner') ? 'planner' : null;
    for (const role of involvedCore) {
      hqStations.get(role)!.teamRing.scale.set(1, 1, 1);
      if (hub && role !== hub) {
        const color = role === 'verifier' && team.state === 'VERIFYING' ? 0x14b8a6 : 0x38e0ff;
        hqTeamLines.push(hqLineBetween(hqStations.get(hub)!.group.position, hqStations.get(role)!.group.position, color));
      }
    }
    if (!hub && involvedCore.length) {
      // Defensive fallback only (every real team includes planner) -- hub at
      // the ops table so involvement is still legible.
      for (const role of involvedCore) hqTeamLines.push(hqLineBetween(new THREE.Vector3(0, 0, 0), hqStations.get(role)!.group.position, 0x38e0ff));
    }
    for (const member of team.members) {
      if (member.kind !== 'temp') continue;
      const parent = hqStations.get(member.parent as CoreRole);
      const temp = hqTemps.get(member.agent_id);
      if (!parent || !temp) continue;
      hqTeamLines.push(hqLineBetween(parent.group.position, temp.position, 0xffb244));
    }
  }

  function applyHQCriticalSecurity(posture: string | undefined): void {
    if (!renderer || hqStations.size === 0) return;
    const critical = posture === 'critical' || posture === 'blocked' || posture === 'lockdown';
    if (critical) {
      for (const role of CRITICAL_ROLES) {
        const station = hqStations.get(role);
        if (!station) continue;
        gsap.to(station.indicator.material, { emissive: new THREE.Color(0xff3b3b), emissiveIntensity: 1.3, duration: 0.3, overwrite: true });
      }
    }
    if (critical !== hqWasCritical) {
      hqWasCritical = critical;
      if (!critical) { hqLastAgentSig = ''; applyHQAgents($agentOffice.snapshot, $agentOffice.link); }
    }
  }

  function setHQDisconnectedBadge(show: boolean): void {
    if (show && !hqDisconnectedBadge) {
      hqDisconnectedBadge = hqLabel('AGENT LINK DISCONNECTED', 24, true, 'rgba(255,92,92,0.95)');
      hqDisconnectedBadge.scale.set(7, 1.75, 1);
      hqDisconnectedBadge.position.set(0, 6.5, 0);
      hqGroup.add(hqDisconnectedBadge);
    } else if (!show && hqDisconnectedBadge) {
      hqGroup.remove(hqDisconnectedBadge);
      disposeSprite(hqDisconnectedBadge);
      hqDisconnectedBadge = null;
    }
  }

  // A single transient pulse mechanism for both HANDOFF and
  // EVIDENCE/VERIFICATION flow -- a small bright packet tweened
  // along the line between two real station positions, self-disposing.
  // Metadata label only, never raw evidence content, per .
  function firePulse(fromPos: THREE.Vector3, toPos: THREE.Vector3, label: string, color: number): void {
    const sprite = hqLabel(label, 18, true, `#${color.toString(16).padStart(6, '0')}`);
    sprite.scale.set(2.4, 0.6, 1);
    sprite.position.copy(fromPos).setY(fromPos.y + 1.4);
    hqGroup.add(sprite);
    const tween = gsap.to(sprite.position, {
      x: toPos.x, y: toPos.y + 1.4, z: toPos.z, duration: 0.7, ease: 'power1.inOut',
      onComplete: () => {
        hqGroup.remove(sprite);
        disposeSprite(sprite);
        hqPulses = hqPulses.filter((p) => p.sprite !== sprite);
      },
    });
    hqPulses.push({ sprite, tween });
  }

  let hqLastCoreHandoffTs = 0;
  let hqLastTeamHandoffTs = 0;
  function applyHandoffPulses(coreHandoff: typeof $agentOffice.handoff, teamHandoff: typeof $teamOffice.lastHandoff): void {
    if (!renderer || hqStations.size === 0) return;
    if (coreHandoff && coreHandoff.ts !== hqLastCoreHandoffTs) {
      hqLastCoreHandoffTs = coreHandoff.ts;
      const from = hqStations.get(coreHandoff.from as CoreRole)?.group.position;
      const to = hqStations.get(coreHandoff.to as CoreRole)?.group.position ?? hqStations.get('verifier')!.group.position;
      if (from) firePulse(from, to, 'HANDOFF', 0xffb244);
    }
    if (teamHandoff && teamHandoff.ts !== hqLastTeamHandoffTs) {
      hqLastTeamHandoffTs = teamHandoff.ts;
      const from = hqStations.get(teamHandoff.from as CoreRole)?.group.position ?? hqTemps.get(teamHandoff.from)?.position;
      const to = hqStations.get(teamHandoff.to as CoreRole)?.group.position ?? hqTemps.get(teamHandoff.to)?.position;
      if (from && to) firePulse(from, to, 'HANDOFF', 0xffb244);
    }
  }

  // Evidence flow -- metadata-only packets for real activity
  // codes only (agents/team_run.py's run.note() vocabulary, verified against
  // source: task_started/task_completed/verified are the ones with a real
  // owning task+role to draw from). Never the raw `detail` text.
  const ACTIVITY_PULSE_LABEL: Record<string, string> = {
    task_started: 'TELEMETRY', task_completed: 'RESULT', verified: 'VERIFICATION',
  };
  let hqLastActivityTs = 0;
  function applyHQActivity(team: TeamDetail | null): void {
    if (!team?.activity?.length) return;
    let latest: TeamDetail['activity'][number] | null = null;
    for (const entry of team.activity) if (!latest || entry.ts > latest.ts) latest = entry;
    if (!latest || latest.ts <= hqLastActivityTs) return;
    hqLastActivityTs = latest.ts;
    const label = ACTIVITY_PULSE_LABEL[latest.code];
    if (!label) return;
    const task = team.tasks.find((t) => t.task_id === latest!.task_id);
    const station = task ? hqStations.get(task.role as CoreRole) : undefined;
    if (!station) return;
    firePulse(station.group.position, new THREE.Vector3(0, 0.4, 0), label, 0x7de6ff);
  }

  // "Result returns to Core Tower" is represented as a pulse to
  // the ops table's own uplink point, not a literal cross-scene traversal
  // into the outdoor city's separate coordinate space (a
  // data-linked representation over unneeded pathfinding/scene-spanning
  let hqLastVerdictSig = '';
  function applyVerifierOutcome(team: TeamDetail | null): void {
    if (!team) { hqLastVerdictSig = ''; return; }
    const sig = `${team.team_id}:${team.state}:${team.verdict}`;
    if (sig === hqLastVerdictSig) return;
    hqLastVerdictSig = sig;
    const verifier = hqStations.get('verifier');
    if (!verifier) return;
    const TERMINAL_WITH_VERDICT = new Set(['FAILED', 'PARTIAL', 'CANCELLED', 'TIMED_OUT']);
    if (TERMINAL_WITH_VERDICT.has(team.state) && team.verdict) {
      firePulse(verifier.group.position, new THREE.Vector3(0, 0, 0), 'REJECTED', 0xff5c5c);
    } else if (team.state === 'COMPLETED') {
      firePulse(verifier.group.position, new THREE.Vector3(0, 0, 0), 'VERIFIED', 0x4ade9e);
      // Straight up off the ops table -- an "uplink to Core Tower" cue, not
      // a literal traversal into the city's own separate coordinate space.
      firePulse(new THREE.Vector3(0, 0.4, 0), new THREE.Vector3(0, 9, 0), 'RESULT → CORE', 0x38e0ff);
    }
  }

  /* ---- CITY-3: HQ camera + selection ------------------------------------
     Selecting a core station vs. a temp/cloud/team-member entity is
     mutually exclusive -- one detail panel at a time, same discipline as
     the existing components/AgentOffice.svelte's pickCore/pickDynamic. */
  const HQ_OVERVIEW_LOCAL_TARGET = new THREE.Vector3(...HQ_PLAN.overviewTarget);
  const HQ_OVERVIEW_ZOOM = 20;   // the floor plus the service annex

  function reportHQInstrumentation(): void {
    const w = window as unknown as Record<string, unknown>;
    if (w.__argusCity) Object.assign(w.__argusCity as Record<string, unknown>, {
      hq: { agents: hqStations.size, entered: hqEntered, mode: cameraMode },
      interior: currentInterior,
    });
  }

  /* ---- CITY-4: the cutaway interior system ------------------------------
     Three buildings open into a real room: Agent HQ, the Academy and the
     Verification Institute. Every one lives in the SAME scene, the same
     renderer and the same camera as the city -- each is a group parked at
     its own far-away origin and shown only while entered, which is the
     "cutaway" the design asks for without a second WebGL context.

     The whole outdoor city is hidden on entry rather than relied on to fall
     outside the frustum: an orthographic camera applies no size falloff, so
     a distant building can otherwise land inside an interior-zoom frustum at
     full size and render as a ghost over the room. */
  type InteriorId = 'agent-hq' | 'academy' | 'verification-institute';
  const INTERIOR_IDS: InteriorId[] = ['agent-hq', 'academy', 'verification-institute'];
  const interiorGroups = new Map<InteriorId, THREE.Group>();
  const interiorCuts = new Map<InteriorId, Cutaway>();
  const INTERIOR_FRAMING: Record<InteriorId, { target: THREE.Vector3; zoom: number }> = {
    'agent-hq': { target: HQ_OVERVIEW_LOCAL_TARGET, zoom: HQ_OVERVIEW_ZOOM },
    academy: { target: new THREE.Vector3(0, 1.5, 0), zoom: 21 },
    'verification-institute': { target: new THREE.Vector3(0, 1.5, 0), zoom: 15 },
  };
  const INTERIOR_TITLE: Record<InteriorId, string> = {
    'agent-hq': 'AGENT HQ — OPERATIONS FLOOR',
    academy: 'ARGUS ACADEMY — CAMPUS INTERIOR',
    'verification-institute': 'VERIFICATION INSTITUTE — VALIDATION HALL',
  };
  let currentInterior: InteriorId | null = null;

  function enterInterior(id: InteriorId): void {
    const group = interiorGroups.get(id);
    if (!group) return;
    currentInterior = id;
    hqEntered = id === 'agent-hq';
    for (const [key, g] of interiorGroups) g.visible = key === id;
    cityGroup.visible = false;
    selectedId = null;
    focusedDistrict = null;
    hoveredId = null;
    hoverLabel = null;
    cameraMode = id === 'agent-hq' ? 'hq-overview' : 'interior';
    selectedAgentId = null;
    followingAgentId = null;
    const f = INTERIOR_FRAMING[id];
    // The rig's pan box moves with us. Interiors are parked at z=-260..-560,
    // outside the city's box -- clamping to the city (as the old fixed +/-200
    // radius did) aimed the camera at empty ground: the Academy and the
    // Institute rendered as a black void.
    rig.setBounds(new THREE.Box3(
      group.position.clone().add(new THREE.Vector3(-45, -5, -45)),
      group.position.clone().add(new THREE.Vector3(45, 20, 45)),
    ));
    // Indoors you may lean in on one desk (a 10 m view); outdoors the
    // default floor of 9 stays -- a city close-up that tight is a wall.
    rig.limits = { ...DEFAULT_LIMITS, minZoom: 5 };
    // Teleport rather than sweep: an interior is parked hundreds of units
    // away, so interpolating there would fly the camera across the whole map.
    // Arrive outside the closed building (zoom 38: roof on, see
    // cityInterior.updateCutaway), then glide in -- the roof lifts off.
    rig.teleportTo(new THREE.Vector3().copy(group.position).add(f.target), 'INTERIOR', 38);
    rig.lookAtPoint(new THREE.Vector3().copy(group.position).add(f.target), f.zoom);
    reportHQInstrumentation();
  }

  function exitInterior(): void {
    currentInterior = null;
    hqEntered = false;
    for (const g of interiorGroups.values()) g.visible = false;
    cityGroup.visible = true;
    selectAgent(null);
    clearTeamSelection();
    rig.setBounds(cityPanBounds);
    rig.limits = DEFAULT_LIMITS;
    focusOverview();
    reportHQInstrumentation();
  }

  const enterAgentHQ = () => enterInterior('agent-hq');
  const exitAgentHQ = exitInterior;

  function focusHQAgent(role: CoreRole): void {
    const station = hqStations.get(role);
    if (!station) return;
    cameraMode = 'hq-agent';
    const p = station.group.position;
    rig.lookAtPoint(new THREE.Vector3().copy(HQ_ORIGIN).add(new THREE.Vector3(p.x, p.y + 1.1, p.z)), 6.0, false,
      PRESETS.INTERIOR.yaw);
    reportHQInstrumentation();
  }

  function focusHQTeam(): void {
    cameraMode = 'hq-team';
    reportHQInstrumentation();
    const involved = $teamOffice.activeTeam?.members.filter((m) => m.kind === 'core').map((m) => m.role as CoreRole) ?? [];
    const pts = involved.map((r) => hqStations.get(r)?.group.position).filter((p): p is THREE.Vector3 => !!p);
    const yaw = PRESETS.INTERIOR.yaw;
    if (!pts.length) { rig.lookAtPoint(new THREE.Vector3().copy(HQ_ORIGIN).add(HQ_OVERVIEW_LOCAL_TARGET), HQ_OVERVIEW_ZOOM, false, yaw); return; }
    const cx = pts.reduce((s, p) => s + p.x, 0) / pts.length;
    const cz = pts.reduce((s, p) => s + p.z, 0) / pts.length;
    rig.lookAtPoint(new THREE.Vector3().copy(HQ_ORIGIN).add(new THREE.Vector3(cx * 0.5, 1, cz * 0.5)), 18, false, yaw);
  }

  /** ROOM mode: frame one room of the HQ floor -- the Team
      Operations Room, or the service core (break room, lockers, charging). */
  let roomFocus: 'ops' | 'core' = 'ops';
  function focusHQRoom(kind: 'ops' | 'core'): void {
    cameraMode = 'hq-room';
    roomFocus = kind;
    const r = HQ_PLAN.rooms[kind];
    rig.lookAtPoint(new THREE.Vector3().copy(HQ_ORIGIN).add(new THREE.Vector3(r.x, 1, r.z)), r.zoom, false,
      r.yaw !== undefined ? THREE.MathUtils.degToRad(r.yaw) : PRESETS.INTERIOR.yaw);
    reportHQInstrumentation();
  }

  function pickHQCore(role: CoreRole): void { clearTeamSelection(); selectAgent(role); }
  function pickHQTemp(id: string): void { selectAgent(null); selectTeamEntity('temp', id); }
  function pickHQTeamMember(id: string): void { selectAgent(null); selectTeamEntity('team_member', id); }

  let hqCancelling = false;
  async function onCancelHQTeam(): Promise<void> {
    if (hqCancelling) return;
    hqCancelling = true;
    await cancelActiveTeam();
    hqCancelling = false;
  }

  /* ---- CITY-5: robot citizens --------------------------------------------
     The inhabitants are the REAL ARGUS agents and nothing else: the ten core
     agents, plus one robot per temporary specialist the backend genuinely
     spawned. There is no filler crowd.

     All behaviour comes from cityAgents.ts, which is deliberately store-free:
     this component reads the stores and hands it plain state strings, and
     cityAgents maps them to a destination and an animation clip through pure
     functions. So "does the city invent activity?" is answerable by reading
     destinationFor/clipFor/ambientGoal in one file.

     Idle agents stay home; movement follows backend work only. */

  let navGraph: NavGraph;
  let agentPool: AgentPool | null = null;
  let agentsReady = false;

  /* ---- chain of command: CEO -> Agent Manager -> agents ------------------
     Three tiers, every one of them real:
     - CEO: the owner, i.e. the user. Every directive enters at the Core Tower,
       so that is where the CEO node stands.
     - AGENT MANAGER: agents/orchestrator.py -- it plans a team, assigns core
       agents and spawns temporary specialists (Architect proposes, Governor
       rules). Its state is read from teamOffice, never inferred.
     - Workers: the ten core agents and whatever specialists genuinely exist.
     Report lines are drawn only from real structure: a core agent that is a
     member of the running team -> Manager; a specialist -> its parent. */
  const MANAGER_ID = 'manager';
  const MANAGER_DESCRIPTION = 'Coordinates agent teams: plans the work, assigns core agents, and spawns '
    + 'temporary specialists (proposed by the Architect, approved by the Governor). It reports to you.';

  interface AgentMeta {
    name: string;
    title: string;
    description: string;
    parent: string;
    createdBy: string;
    home: string;
  }
  /** Display metadata per robot id, from the backend wherever it has it. */
  let agentMeta = new Map<string, AgentMeta>();
  const agentLabels: SceneLabel[] = [];
  let selectedAgentId: string | null = null;
  let hoveredAgentId: string | null = null;

  const isCoreRole = (r: string): r is CoreRole => (ALL_AGENTS as readonly string[]).includes(r);

  const CHIP_CLASS: Record<string, string> = {
    IDLE: 'st-idle', QUEUED: 'st-queued', WAITING: 'st-queued', THINKING: 'st-thinking',
    WORKING: 'st-busy', VERIFYING: 'st-busy', COMPLETED: 'st-ok', FAILED: 'st-critical',
    DISCONNECTED: 'st-off', 'STANDING BY': 'st-idle', OFFLINE: 'st-off', 'NOT WIRED': 'st-off',
    INITIALIZING: 'st-queued', COORDINATING: 'st-busy', 'AWAITING CEO': 'st-queued', CONNECTING: 'st-idle',
    STUDYING: 'st-thinking', ENROLLED: 'st-queued', TRAINING: 'st-thinking',
  };

  function attachAgentLabel(agent: CityAgent): void {
    if (!agent.label) {
      const label = makeLabel(agent.kind === 'manager' ? 'manager' : 'agent', agent.id, ROLE_ACCENT[agent.role] ?? 0x38e0ff);
      agent.root.add(label.obj);
      agent.label = label;
      agentLabels.push(label);
    }
    // Local units (the root is scaled): just above the head. Neighbours are
    // spread sideways per frame by cityLabels.fanOut.
    agent.label.obj.position.set(0, 2.15, 0);
    agent.label.id = agent.id;
    agent.label.el.style.setProperty('--c', hexToCss(ROLE_ACCENT[agent.role] ?? 0x38e0ff));
  }

  function refreshAgentLabel(agent: CityAgent, chipText?: string): void {
    if (!agent.label) return;
    const meta = agentMeta.get(agent.id);
    // A just-approved specialist has a robot but no job yet: INITIALIZING,
    // exactly the lifecycle step the backend reports (APPROVED).
    const chip = chipText ?? ((agent.kind === 'temp' || agent.kind === 'cloud') && agent.state === 'approved'
      ? 'INITIALIZING' : visualState(agent.state, false));
    // NAME on top, what kind of worker it is underneath.
    setLabelText(agent.label, tagName(agent, meta?.name), WORKER_TITLE[agent.kind] ?? '', chip,
      CHIP_CLASS[chip] ?? CHIP_CLASS[chip.split(' · ')[0]] ?? 'st-idle');
  }

  /** The short name on a robot's tag: "SYSTEM", "LOG ANALYSIS", "RESEARCH-27".
      A cloud worker's number is a stable digest of its real backend id, so
      the same worker always carries the same tag. */
  function tagName(agent: CityAgent, full?: string): string {
    const name = (full ?? ROLE_NAME[agent.role] ?? agent.id).replace(/ (Agent|Specialist)$/, '');
    if (agent.kind !== 'cloud') return name.toUpperCase();
    let h = 0;
    for (const ch of agent.id) h = (h * 31 + ch.charCodeAt(0)) % 97;
    const word = name.replace(/^Cloud\s+/i, '').split(/\s+/)[0] || 'CLOUD';
    return `${word.toUpperCase()}-${String(h + 2).padStart(2, '0')}`;
  }

  async function buildAgents(): Promise<void> {
    navGraph = buildNavGraph(DISTRICTS);
    const model = await loadModel('robots', 'argus_robot');
    if (!model || !renderer) return;
    agentPool = new AgentPool(model, navGraph, cityGroup);
    ALL_AGENTS.forEach((role, i) => {
      const agent = agentPool!.spawn(role, role, 'core', i, AGENT_HOME[role] ?? 'agent-hq');
      attachAgentLabel(agent);
    });
    const manager = agentPool.spawn(MANAGER_ID, 'manager', 'manager', 0, 'agent-hq');
    agentMeta.set(MANAGER_ID, {
      name: 'AGENT MANAGER', title: ROLE_TITLE.manager, description: MANAGER_DESCRIPTION,
      parent: 'CEO (you)', createdBy: '', home: 'agent-hq',
    });
    attachAgentLabel(manager);
    manager.label!.priority = 90;
    agentsReady = true;
    buildCommandLink();
    // Apply whatever the stores already hold; the snapshot almost always
    // arrives before the GLB does.
    syncCoreAgents($agentOffice.snapshot, $agentOffice.link);
    syncTempAgents($teamOffice.dynamicAgents);
    applyManager(managerStatus($teamOffice));
    reportHQInstrumentation();
  }

  let agentCoreSig = '';
  function syncCoreAgents(snapshot: typeof $agentOffice.snapshot, link: string): void {
    if (!agentsReady || !agentPool) return;
    const stale = link !== 'online' && link !== 'degraded';
    const sig = `${snapshot ? snapshot.agents.map((a) => `${a.id}:${a.state}`).join('|') : 'off'}:${link}:${academySigOf()}`;
    if (sig === agentCoreSig) return;
    agentCoreSig = sig;
    for (const role of ALL_AGENTS) {
      const agent = agentPool.agents.get(role);
      if (!agent) continue;
      // The state string is taken verbatim from the backend. When the link is
      // down we show `disabled` rather than guessing at the last known state.
      const info = snapshot?.agents.find((x) => x.id === role);
      const study = studying(role);
      const raw = stale ? 'disabled' : study ? studyRaw(study) : (info?.state ?? 'idle');
      agentPool.setState(agent, raw, STATE_COLORS[raw]);
      agentMeta.set(role, {
        name: info?.name ?? ROLE_NAME[role], title: ROLE_TITLE[role],
        description: info?.description || ROLE_DESCRIPTION[role], parent: MANAGER_ID, createdBy: '',
        home: AGENT_HOME[role] ?? 'agent-hq',
      });
      refreshAgentLabel(agent);
      agentPool.setGoal(agent, destinationFor(role, raw));
    }
    agentMeta = agentMeta;
  }

  let agentTempSig = '';
  function syncTempAgents(list: DynamicAgentView[]): void {
    if (!agentsReady || !agentPool) return;
    const sig = list.map((a) => `${a.id}:${a.state}:${a.type}`).sort().join('|');
    if (sig === agentTempSig) return;
    agentTempSig = sig;
    const live = new Set<string>();
    let n = 0;
    for (const a of hiresOf(list).slice(0, MAX_TEMP_AGENTS)) {
      const cloud = a.type === 'EPHEMERAL_CLOUD';
      const key = `temp:${a.id}`;
      live.add(key);
      // Cloud workers stay at the Embassy, physically outside the secure
      // city. They never walk a street and never approach Capability.
      const home = cloud ? 'cloud-embassy' : 'specialist-district';
      let agent = agentPool.agents.get(key);
      if (!agent) {
        // A specialist wears its PARENT's colour -- it is that agent's hire.
        const accentRole = cloud ? 'cloud' : isCoreRole(a.parent) ? a.parent : 'assistant';
        agent = agentPool.spawn(key, accentRole, cloud ? 'cloud' : 'temp', 10 + n, home);
        attachAgentLabel(agent);
        hirePulse(agent.root.position, ROLE_ACCENT[accentRole] ?? MANAGER_ACCENT);
      }
      agentPool.setState(agent, a.state.toLowerCase(), STATE_COLORS[a.state.toLowerCase()]);
      agentMeta.set(key, {
        name: a.name || (cloud ? 'Cloud Specialist' : 'Specialist'),
        title: cloud ? 'Cloud Specialist · thinks, never controls' : `Temp Specialist · ${a.role || 'temporary'}`,
        description: a.description || a.current_task || '',
        parent: a.parent, createdBy: a.created_by, home,
      });
      refreshAgentLabel(agent);
      // A local specialist spins up in the Specialist District and walks to
      // Agent HQ (its hot desk, the team room) only while the backend reports
      // it ACTIVE. A cloud specialist never walks: it stays in the Embassy.
      if (!cloud) agentPool.setGoal(agent, a.state === 'ACTIVE' ? 'agent-hq' : 'specialist-district');
      n++;
    }
    for (const key of [...agentPool.agents.keys()]) {
      if (key.startsWith('temp:') && !live.has(key)) {
        agentPool.despawn(key);
        agentMeta.delete(key);
        if (selectedAgentId === key) selectedAgentId = null;
      }
    }
    agentMeta = agentMeta;
  }

  const MAX_TEMP_AGENTS = 6;

  /** The Manager's status: the backend Manager's own state when it answers
      (agents/agent_manager.state()), else derived from the team store. */
  function managerStatus(t: typeof $teamOffice, m: ManagerState | null): { state: string; text: string } {
    if (m) {
      if (m.manager.state === 'awaiting_ceo') {
        return { state: 'waiting', text: `AWAITING CEO · ${m.pending_hires} HIRE REQUEST${m.pending_hires === 1 ? '' : 'S'}` };
      }
      if (m.manager.state === 'coordinating') {
        const team = m.teams.find((x) => !HQ_TEAM_TERMINAL.has(x.state));
        return { state: 'coordinating', text: `COORDINATING · ${team?.state ?? 'TEAM'}` };
      }
      return { state: 'idle', text: 'STANDING BY' };
    }
    if (t.link === 'offline') return { state: 'offline', text: 'OFFLINE' };
    if (t.link === 'loading') return { state: 'idle', text: 'CONNECTING' };
    if (t.statusMeta && !t.statusMeta.wired) return { state: 'disabled', text: 'NOT WIRED' };
    const team = t.activeTeam;
    if (team && !HQ_TEAM_TERMINAL.has(team.state)) return { state: 'coordinating', text: `COORDINATING · ${team.state}` };
    return { state: 'idle', text: 'STANDING BY' };
  }
  $: managerNow = managerStatus($teamOffice, $agentManager.link === 'online' ? $agentManager.manager : null);

  /** The HQ office Manager: seated posture + monitors + wall display, all
      from the same real state the city Manager robot shows. */
  function applyHQManager(status: { state: string }, st: ManagerState | null): void {
    if (!hqManager) return;
    hqManager.pose = status.state === 'coordinating' ? 'work'
      : status.state === 'waiting' ? 'wait' : status.state === 'offline' ? 'failed' : 'idle';
    setScreens(hqManager.screens, status.state === 'coordinating' ? 'work'
      : status.state === 'offline' || status.state === 'disabled' ? 'off' : 'idle');
    drawManagerDisplay(st);
  }
  $: if (renderer && hqManager) applyHQManager(managerNow, $agentManager.link === 'online' ? $agentManager.manager : null);

  function applyManager(status: { state: string; text: string }): void {
    const m = agentPool?.agents.get(MANAGER_ID);
    if (!m || !agentPool) return;
    agentPool.setState(m, status.state, MANAGER_ACCENT);
    refreshAgentLabel(m, status.text);
  }
  $: if (agentsReady) applyManager(managerNow);

  /* Report lines: one LineSegments with a small dynamic buffer, rewritten
     each frame from the live robot positions (robots walk). */
  const MAX_REPORT_LINES = 20;
  let reportLines: THREE.LineSegments | null = null;
  let reportPairs: [string, string][] = [];
  $: reportPairs = computeReportPairs($teamOffice.activeTeam, $teamOffice.dynamicAgents);

  function computeReportPairs(team: TeamDetail | null, dyn: DynamicAgentView[]): [string, string][] {
    const pairs: [string, string][] = [];
    if (team && !HQ_TEAM_TERMINAL.has(team.state)) {
      for (const m of team.members) if (m.kind === 'core' && isCoreRole(m.role)) pairs.push([MANAGER_ID, m.role]);
    }
    for (const a of hiresOf(dyn).slice(0, MAX_TEMP_AGENTS)) {
      pairs.push([isCoreRole(a.parent) ? a.parent : MANAGER_ID, `temp:${a.id}`]);
    }
    return pairs;
  }

  function buildReportLines(): void {
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(MAX_REPORT_LINES * 6), 3));
    geo.setDrawRange(0, 0);
    reportLines = new THREE.LineSegments(geo, new THREE.LineBasicMaterial({
      color: MANAGER_ACCENT, transparent: true, opacity: 0.6, toneMapped: false, depthWrite: false,
    }));
    // The buffer starts empty, so its bounding sphere is a point at the
    // origin -- culling would throw the lines away.
    reportLines.frustumCulled = false;
    cityGroup.add(reportLines);
  }

  function updateReportLines(t: number): void {
    if (!reportLines || !agentPool) return;
    const pos = reportLines.geometry.getAttribute('position') as THREE.BufferAttribute;
    let n = 0;
    for (const [a, b] of reportPairs) {
      const A = agentPool.agents.get(a), B = agentPool.agents.get(b);
      if (!A || !B || n >= MAX_REPORT_LINES) continue;
      pos.setXYZ(n * 2, A.root.position.x, A.root.position.y + 1.5 * A.root.scale.y, A.root.position.z);
      pos.setXYZ(n * 2 + 1, B.root.position.x, B.root.position.y + 1.5 * B.root.scale.y, B.root.position.z);
      n++;
    }
    reportLines.geometry.setDrawRange(0, n * 2);
    pos.needsUpdate = true;
    (reportLines.material as THREE.LineBasicMaterial).opacity = 0.45 + 0.25 * Math.sin(t * 2.2);
  }

  /* The CEO node: a gold beacon on the Core Tower roof, and a command link
     arcing down to the Manager at Agent HQ. The link only animates while a
     real directive ($tasks.goal) is in flight. */
  let ceoGroup: THREE.Group | null = null;
  let ceoGem: THREE.Mesh | null = null;
  let ceoLabel: SceneLabel | null = null;
  let commandLink: THREE.Line | null = null;

  function buildCeoNode(): void {
    const d = findDistrict('core-tower');
    if (!d) return;
    ceoGroup = new THREE.Group();
    ceoGroup.position.set(d.x, d.height, d.z);
    const gold = (opacity: number) => new THREE.MeshBasicMaterial({
      color: CEO_ACCENT, transparent: true, opacity, depthWrite: false, toneMapped: false,
      blending: THREE.AdditiveBlending,
    });
    const beam = new THREE.Mesh(new THREE.CylinderGeometry(0.28, 0.5, 22, 12, 1, true), gold(0.28));
    beam.position.y = 11;
    ceoGroup.add(beam);
    const ring = new THREE.Mesh(new THREE.TorusGeometry(2.4, 0.13, 8, 48), gold(0.9));
    ring.rotation.x = Math.PI / 2;
    ring.position.y = 0.8;
    ceoGroup.add(ring);
    ceoGem = new THREE.Mesh(new THREE.OctahedronGeometry(1.0), new THREE.MeshStandardMaterial({
      color: CEO_ACCENT, emissive: CEO_ACCENT, emissiveIntensity: 1.4, metalness: 0.3, roughness: 0.3,
    }));
    ceoGem.position.y = 3.2;
    ceoGroup.add(ceoGem);
    ceoLabel = makeLabel('ceo', 'ceo', CEO_ACCENT);
    setLabelText(ceoLabel, '★ CEO · YOU', 'Core Tower · every directive starts here');
    ceoLabel.obj.position.set(0, 5.2, 0);
    ceoLabel.priority = 95;
    ceoGroup.add(ceoLabel.obj);
    cityGroup.add(ceoGroup);
  }

  function placeCeoNode(roofY: number): void {
    if (!ceoGroup) return;
    ceoGroup.position.y = roofY + 0.4;
    buildCommandLink();
  }

  function buildCommandLink(): void {
    const manager = agentPool?.agents.get(MANAGER_ID);
    if (!ceoGroup || !manager) return;
    if (commandLink) { commandLink.geometry.dispose(); commandLink.removeFromParent(); }
    const from = ceoGroup.position.clone().add(new THREE.Vector3(0, 2.2, 0));
    const to = manager.root.position.clone().add(new THREE.Vector3(0, 3.8, 0));
    const mid = from.clone().lerp(to, 0.5).add(new THREE.Vector3(0, 10, 0));
    const pts = new THREE.QuadraticBezierCurve3(from, mid, to).getPoints(40);
    const material = (commandLink?.material as THREE.LineDashedMaterial | undefined)
      ?? new THREE.LineDashedMaterial({
        color: CEO_ACCENT, dashSize: 1.4, gapSize: 0.9, transparent: true, opacity: 0.55, toneMapped: false,
      });
    commandLink = new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), material);
    commandLink.computeLineDistances();
    cityGroup.add(commandLink);
  }

  /** A one-shot gold ring where a specialist was genuinely just spawned --
      the "new hire" moment, driven by the real dynamic-agent list. */
  function hirePulse(at: THREE.Vector3, color: number): void {
    const ring = new THREE.Mesh(new THREE.RingGeometry(0.8, 1.1, 40), new THREE.MeshBasicMaterial({
      color, transparent: true, opacity: 0.95, depthWrite: false, toneMapped: false, side: THREE.DoubleSide,
    }));
    ring.rotation.x = -Math.PI / 2;
    ring.position.copy(at).setY(at.y + 0.08);
    cityGroup.add(ring);
    const mat = ring.material as THREE.MeshBasicMaterial;
    gsap.to(ring.scale, { x: 7, y: 7, duration: 1.6, ease: 'power2.out' });
    gsap.to(mat, {
      opacity: 0, duration: 1.6, ease: 'power1.in',
      onComplete: () => { ring.removeFromParent(); ring.geometry.dispose(); mat.dispose(); },
    });
  }

  let inboxOpen = false;

  /* The Agent Management Center board over Agent HQ: the Manager's REAL
     numbers and the hiring pipeline as the backend reports it. Built from
     DOM text nodes only (no markup from data). */
  let officeBoard: { obj: CSS2DObject; el: HTMLDivElement; sig: string } | null = null;
  let traffic: Traffic | null = null;
  const HIRE_STAGE: Record<string, [string, string]> = {
    PENDING: ['HIRE REQUEST · AWAITING CEO', 'st-queued'],
    REQUESTED: ['GOVERNOR REVIEW', 'st-thinking'],
    HIRED: ['APPROVED · ON DUTY', 'st-ok'],
    RELEASED: ['RELEASED', 'st-off'],
    DENIED: ['DENIED BY GOVERNOR', 'st-critical'],
    CANCELLED: ['STOPPED', 'st-off'],
  };

  function buildOfficeBoard(): void {
    const d = findDistrict('agent-hq');
    if (!d) return;
    const el = document.createElement('div');
    el.className = 'cl cl-board';
    el.style.setProperty('--c', hexToCss(MANAGER_ACCENT));
    const obj = new CSS2DObject(el);
    obj.center.set(0, 1);
    obj.position.set(d.x + d.footprint + 1.5, 14, d.z + 2);
    cityGroup.add(obj);
    officeBoard = { obj, el, sig: '' };
    drawOfficeBoard(null);
  }

  function drawOfficeBoard(st: ManagerState | null): void {
    if (!officeBoard) return;
    const pending = st ? st.hire_requests.filter((h) => h.state === 'PENDING') : [];
    const sig = st ? JSON.stringify([st.workforce, st.active_teams, pending.map((h) => h.hire_id),
      st.hiring_log.slice(-3).map((h) => [h.name, h.state])]) : 'off';
    if (sig === officeBoard.sig) return;
    officeBoard.sig = sig;
    const el = officeBoard.el;
    el.replaceChildren();
    const title = document.createElement('b');
    title.textContent = 'AGENT MANAGEMENT CENTER';
    el.append(title);
    if (!st) {
      const off = document.createElement('span');
      off.textContent = 'Manager offline — no live numbers';
      el.append(off);
      return;
    }
    const grid = document.createElement('div');
    grid.className = 'bd-grid';
    for (const [k, v] of [['WORKERS', st.workforce.total], ['ACTIVE', st.workforce.active],
      ['IDLE', st.workforce.idle], ['TEMP', st.workforce.temporary], ['HIRE REQ', st.pending_hires],
      ['TEAMS', st.active_teams], ['QUEUED', st.workforce.queued_work]] as [string, number][]) {
      const cell = document.createElement('div');
      const n = document.createElement('em');
      n.textContent = String(v);
      if (v > 0 && (k === 'ACTIVE' || k === 'HIRE REQ' || k === 'TEAMS')) n.className = 'hot';
      const l = document.createElement('small');
      l.textContent = k;
      cell.append(n, l);
      grid.append(cell);
    }
    el.append(grid);
    const rows: [string, string][] = [
      ...pending.flatMap((h) => h.specialists.map((s) => [s.name, 'PENDING'] as [string, string])),
      ...st.hiring_log.slice(-3).reverse().map((h) => [h.name, h.state] as [string, string]),
    ].slice(0, 3);
    for (const [name, state] of rows) {
      const row = document.createElement('span');
      row.className = 'bd-row';
      const chip = document.createElement('i');
      const [text, cls] = HIRE_STAGE[state] ?? [state, 'st-idle'];
      chip.textContent = text;
      chip.className = cls;
      row.append(document.createTextNode(name), chip);
      el.append(row);
    }
  }
  $: if (renderer && officeBoard) drawOfficeBoard($agentManager.link === 'online' ? $agentManager.manager : null);

  /** The backend Manager's live view of one worker (current assignment,
      backend, TTL, track record). Robot ids for temps carry a "temp:" key. */
  function managerAgentView(key: string, st: ManagerState | null) {
    if (!st || key === MANAGER_ID) return null;
    const id = key.replace(/^temp:/, '');
    return st.agents.find((a) => a.id === id) ?? st.temporaries.find((a) => a.id === id) ?? null;
  }

  /** "Show me who sent this": leave any interior, select and frame the robot. */
  function openAgentFromInbox(agentId: string): void {
    const key = agentPool?.agents.has(agentId) ? agentId
      : agentPool?.agents.has(`temp:${agentId}`) ? `temp:${agentId}` : '';
    if (!key) return;
    if (currentInterior) exitInterior();
    inboxOpen = false;
    selectCityAgent(key);
  }

  /** CEO cancels a temporary specialist: a REQUEST (DELETE
      /api/agents/dynamic/{id}); the robot leaves only when the backend's
      authoritative list no longer has it. */
  async function onReleaseSpecialist(key: string): Promise<void> {
    await releaseSpecialist(key.replace(/^temp:/, ''));
    await refreshDynamicAgents();
  }

  function selectCityAgent(id: string | null): void {
    selectedAgentId = id;
    if (!id) return;
    teamPanelOpen = false;
    const agent = agentPool?.agents.get(id);
    if (!agent) return;
    selectedId = null;
    focusedDistrict = null;
    userDrivingCamera = false;
    rig.lookAtPoint(agent.root.position.clone().setY(1.5), Math.min(rig.currentZoom, 24));
  }

  /* ---- panels: agent card + chain-of-command summary --------------------
     Both take their store inputs as ARGUMENTS so the template re-evaluates
     them when those change (Svelte only tracks what the markup references).
     `uiTick` adds a once-a-second refresh for what only the robots know --
     where each one is standing right now. */
  let commandOpen = true;
  let uiTick = 0;

  const DISTRICT_SHORT: Record<string, string> = {
    'agent-hq': 'HQ', 'security-district': 'SECURITY', 'operations-center': 'OPERATIONS',
    'verification-institute': 'VERIFICATION', 'specialist-district': 'SPECIALISTS',
    'cloud-embassy': 'EMBASSY', academy: 'ACADEMY',
  };

  /** Temporary hires only -- the dynamic list's type field can also say CORE. */
  const hiresOf = (list: DynamicAgentView[]) => list.filter((a) => a.type !== 'CORE');

  function commandStats(meta: Map<string, AgentMeta>, office: typeof $agentOffice,
                        team: typeof $teamOffice, mgr: ManagerState | null) {
    const base = commandStatsLocal(meta, office, team);
    if (!mgr) return { ...base, pending: 0, queued: office.snapshot?.queue_depth ?? 0 };
    return {
      ...base,
      total: mgr.workforce.total, active: mgr.workforce.active,
      specialists: mgr.workforce.temporary - mgr.workforce.cloud, cloud: mgr.workforce.cloud,
      teams: mgr.active_teams, pending: mgr.pending_hires, queued: mgr.workforce.queued_work,
    };
  }

  function commandStatsLocal(meta: Map<string, AgentMeta>, office: typeof $agentOffice, team: typeof $teamOffice) {
    const stale = office.link !== 'online' && office.link !== 'degraded';
    const hires = hiresOf(team.dynamicAgents);
    const coreActive = stale ? 0
      : (office.snapshot?.agents ?? []).filter((a) => WORKING_STATES.has(a.state.toLowerCase())).length;
    const hireActive = hires.filter((a) => WORKING_STATES.has(a.state.toLowerCase())).length;
    const byHome = new Map<string, string[]>();
    for (const [id, m] of meta) {
      if (id === MANAGER_ID) continue;
      byHome.set(m.home, [...(byHome.get(m.home) ?? []), m.name]);
    }
    const districts = [...byHome].map(([id, names]) => {
      const d = findDistrict(id);
      return {
        id, short: DISTRICT_SHORT[id] ?? d?.name ?? id, count: names.length, members: names.join(', '),
        accent: hexToCss(d ? categoryStyle(d.category).accent : 0x38e0ff),
      };
    }).sort((a, b) => b.count - a.count);
    return {
      total: ALL_AGENTS.length + hires.length,
      active: coreActive + hireActive,
      specialists: hires.filter((a) => a.type === 'EPHEMERAL_LOCAL').length,
      cloud: hires.filter((a) => a.type === 'EPHEMERAL_CLOUD').length,
      teamHires: team.activeTeam?.temporary_count ?? 0,
      teams: team.statusMeta?.active_teams ?? 0,
      districts,
    };
  }

  function agentCard(
    id: string, meta: Map<string, AgentMeta>, _office: typeof $agentOffice,
    team: typeof $teamOffice, mgr: { state: string; text: string }, _tick = uiTick,
  ) {
    const agent = agentPool?.agents.get(id);
    if (!agent) return null;
    const m = meta.get(id);
    const isManager = id === MANAGER_ID;
    const status = isManager ? mgr.text.split(' · ')[0] : visualState(agent.state, false);
    const home = findDistrict(m?.home ?? '');
    const t = team.activeTeam;
    const running = !!t && !HQ_TEAM_TERMINAL.has(t.state);
    const member = running && t!.members.some((x) =>
      (agent.kind === 'core' && x.kind === 'core' && x.role === agent.role) || x.agent_id === id.replace('temp:', ''));
    const parent = m?.parent ?? '';
    return {
      name: m?.name ?? ROLE_NAME[agent.role] ?? id,
      title: m?.title ?? ROLE_TITLE[agent.role] ?? '',
      description: m?.description ?? '',
      status,
      chipClass: CHIP_CLASS[status] ?? (isManager && mgr.state === 'coordinating' ? 'st-busy' : 'st-idle'),
      accent: hexToCss(ROLE_ACCENT[agent.role] ?? 0x38e0ff),
      reportsTo: isManager ? 'CEO (you)'
        : agent.kind === 'core' ? 'Agent Manager'
        : isCoreRole(parent) ? `${ROLE_NAME[parent]} → Manager` : 'Agent Manager',
      tier: isManager ? 'MANAGEMENT' : agent.kind === 'core' ? 'CORE AGENT' : agent.kind === 'cloud' ? 'CLOUD WORKER' : 'SPECIALIST',
      home: home?.name ?? '—',
      homeId: home?.id ?? '',
      location: agent.path.length
        ? `→ ${findDistrict(agent.goalDistrict)?.name ?? agent.goalDistrict}`
        : findDistrict(agent.atDistrict)?.name ?? agent.atDistrict,
      team: isManager
        ? (running ? `${t!.team_id} · ${t!.state}` : 'No team running')
        : member ? `${t!.team_id} · ${t!.state}` : 'Not in a running team',
      hiredBy: agent.kind === 'temp' || agent.kind === 'cloud' ? (m?.createdBy || 'Agent Manager') : '',
      inTeam: isManager ? running : member,
      kind: agent.kind,
    };
  }

  /** Per-frame label policy. Tiers decide what MAY show at this zoom;
      declutter() then drops whatever would still overlap. */
  function updateLabels(zoomNow: number): void {
    for (const [id, label] of labelRegistry) {
      const focused = id === selectedId || id === hoveredId || id.startsWith(`${selectedId}:`);
      label.el.classList.toggle('focused', focused);
      label.want = focused
        || (label.kind === 'district' && (LANDMARKS.has(id) || zoomNow < 70))
        || (label.kind === 'sub' && zoomNow < 26);
      // Scenery names and environment districts rank below every operational
      // label: when space runs out, the city's working parts keep their tags.
      label.priority = focused ? 100 : label.kind === 'sub' ? (id.startsWith('scenery:') ? 30 : 40)
        : LANDMARKS.has(id) ? 80 : ENV_IDS.has(id) ? 50 : 60;
    }
    for (const label of agentLabels) {
      const agent = agentPool?.agents.get(label.id);
      if (!agent) { label.want = false; continue; }
      const focused = label.id === selectedAgentId || label.id === hoveredAgentId || label.id === followingAgentId;
      const working = WORKING_STATES.has(agent.state);
      label.el.classList.toggle('focused', focused);
      // Name only until the camera is close enough for the role line to fit.
      // NAME + ROLE from building zoom inward; name only further out.
      setCompact(label, !focused && agent.kind !== 'manager' && zoomNow > 28);
      label.want = focused || agent.kind === 'manager' || zoomNow < (working ? 60 : 44);
      // At city zoom the landmark names (80) win; closer in, the Manager's
      // tag outranks every building so the chain of command stays readable.
      label.priority = focused ? 100 : agent.kind === 'manager' ? (zoomNow < 70 ? 90 : 72) : working ? 70 : 50;
      // Robots standing at the same doorway form one cluster to fan out.
      label.group = agent.path.length ? '' : agent.atDistrict;
    }
    if (ceoLabel) ceoLabel.want = true;
    // The Management Center board: at district zoom and closer, or whenever
    // a hire request is waiting for the CEO (that is when it matters most).
    if (officeBoard) {
      officeBoard.obj.visible = zoomNow < 58 || selectedId === 'agent-hq'
        || ($agentManager.manager?.pending_hires ?? 0) > 0;
    }
    if (!renderer || !container) return;
    const w = container.clientWidth, h = container.clientHeight;
    fanOut(agentLabels, rig.camera, w, h);
    const all = [...labelRegistry.values(), ...agentLabels];
    if (ceoLabel) all.push(ceoLabel);
    declutter(all, rig.camera, w, h);
  }

  function updateAgents(dt: number, t: number): void {
    if (!agentsReady || !agentPool) return;
    agentPool.update(dt, t);
  }

  /** Follow a specific agent -- the design's FOLLOW_AGENT camera mode. Reads
      the robot's live world position each frame while active. */
  let followingAgentId: string | null = null;
  function followAgent(id: string | null): void {
    followingAgentId = id;
    if (id) {
      userDrivingCamera = false;
      activePreset = 'STREET_LEVEL';
      rig.applyPreset('STREET_LEVEL');
    }
  }

  function updateFollow(): void {
    if (!agentPool || userDrivingCamera) return;
    if (followingTeam) {
      const bots = teamRobots($teamOffice);
      if (!bots.length) { followingTeam = false; return; }
      const c = new THREE.Vector3();
      for (const b of bots) c.add(b.root.position);
      c.divideScalar(bots.length).setY(1.2);
      rig.lookAtPoint(c, undefined, true);
      return;
    }
    if (!followingAgentId) return;
    const agent = agentPool.agents.get(followingAgentId);
    if (!agent) { followingAgentId = null; return; }
    rig.lookAtPoint(agent.root.position.clone().setY(agent.root.position.y + 1.1), undefined, true);
  }

  /* ---- FOLLOW TEAM + the team panel (§29) -------------------
     The team is teamOffice.activeTeam -- the orchestrator's own TeamDetail,
     re-pulled on every structural WS event and on reconnect. The robots it
     follows are exactly the members the backend lists: core members by role,
     specialists by their real agent id. */
  let followingTeam = false;
  let teamPanelOpen = false;

  /** The running team, named over Agent HQ where its members gather: team id, goal and the orchestrator's own progress. Hidden when no
      team runs -- a finished team leaves no banner behind. */
  /* The running team is named on Agent HQ's own landmark label, where its
     members gather: team id and progress as the chip, the goal underneath.
     One label, already the landmark there -- a separate floating banner
     only fought the Manager's tag for the same pixels. With no team running
     the label is the plain district name again. */
  function syncTeamBanner(t: typeof $teamOffice): void {
    const label = labelRegistry.get('agent-hq');
    const hq = findDistrict('agent-hq');
    if (!label || !hq) return;
    const at = t.activeTeam;
    if (at && teamLive(t)) {
      const goal = (at.goal || at.playbook.replace(/_/g, ' ')).toUpperCase();
      setLabelText(label, hq.name, goal.length > 40 ? `${goal.slice(0, 39)}…` : goal,
        `TEAM ${at.team_id} · ${Math.round(at.progress * 100)}%`, 'st-busy');
    } else {
      setLabelText(label, hq.name, categoryStyle(hq.category).label);
    }
  }
  $: if (renderer) syncTeamBanner($teamOffice);

  const teamLive = (t: typeof $teamOffice) => !!t.activeTeam && !HQ_TEAM_TERMINAL.has(t.activeTeam.state);

  function teamRobots(t: typeof $teamOffice): CityAgent[] {
    if (!agentPool || !t.activeTeam) return [];
    const out: CityAgent[] = [];
    for (const m of t.activeTeam.members) {
      const a = m.kind === 'core' ? agentPool.agents.get(m.role) : agentPool.agents.get(`temp:${m.agent_id}`);
      if (a) out.push(a);
    }
    return out;
  }

  function followTeam(on: boolean): void {
    followingTeam = on && teamLive($teamOffice);
    if (!followingTeam) return;
    followingAgentId = null;
    userDrivingCamera = false;
    activePreset = 'DISTRICT';
    rig.applyPreset('DISTRICT');
  }

  /** "Ask the Manager about this agent": the SAME org question the owner
      could type, sent to the Manager's thread -- answered from state. */
  async function askManagerAbout(name: string, kind: string): Promise<void> {
    const subject = kind === 'core' ? `the ${name.replace(/ Agent$/, '')} agent` : `the ${name}`;
    await sendChat(MANAGER_ID, `Tell me about ${subject}`);
    selectCityAgent(MANAGER_ID);
  }

  /** One row per task of the running team, in the orchestrator's order, with
      what each waits on -- the DAG as the backend reports it, never inferred. */
  function teamGraph(t: TeamDetail) {
    const byId = new Map(t.tasks.map((x) => [x.task_id, x]));
    const who = (x: TeamDetail['tasks'][number]) => (x.agent_id && !x.agent_id.startsWith('dyn-')
      ? x.agent_id : x.role).replace(/_/g, ' ').toUpperCase();
    return t.tasks.map((x) => ({
      id: x.task_id, who: who(x), title: x.title, state: x.state,
      after: x.dependencies.map((d) => byId.get(d)).filter(Boolean).map((d) => who(d!)),
      verify: x.kind === 'VERIFY',
    }));
  }

  $: if (renderer && agentsReady) { void $academyState; syncCoreAgents($agentOffice.snapshot, $agentOffice.link); }
  $: if (renderer) { void $academyState; applyAcademyStudents(); }
  $: if (renderer && agentsReady) syncTempAgents($teamOffice.dynamicAgents);

  /** Which real agents are standing in a district right now -- read straight
      off the live robot positions, so the panel can never claim someone is
      somewhere the city is not actually drawing them. Recomputed from
      $agentOffice so the panel refreshes when real state changes. */
  function agentsHere(districtId: string): { id: string; name: string; state: string }[] {
    void $agentOffice;
    void agentMeta;
    if (!agentPool) return [];
    return [...agentPool.agents.values()]
      .filter((a) => a.atDistrict === districtId && !a.path.length)
      .map((a) => ({ id: a.id, name: agentMeta.get(a.id)?.name ?? ROLE_NAME[a.role] ?? a.role, state: a.state }));
  }

  /* ---- interaction ----------------------------------------------------- */

  // CITY-3: which HQ entity (if any) is under the pointer right now --
  // recomputed each move, read by onPointerDown. Raycasting is scoped to
  // hqEntered so city-overview clicks never test the (possibly large,
  // always-present) HQ interior geometry.
  let hqHoverRole: CoreRole | null = null;
  let hqHoverTempId: string | null = null;

  function onPointerMove(event: PointerEvent): void {
    if (!renderer) return;
    const rect = renderer.domElement.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
    raycaster.setFromCamera(mouse, rig.camera);
    clickGuard.move(event);
    // Mid-drag, nothing can be clicked -- skip the raycast (the buildings are
    // ~200k triangles) so panning stays smooth.
    if (container.dataset.drag) { hoverLabel = null; return; }

    if (currentInterior && !hqEntered) { container.style.cursor = 'default'; return; }

    if (hqEntered) {
      hqHoverRole = null; hqHoverTempId = null;
      for (const [role, station] of hqStations) {
        if (raycaster.intersectObject(station.group, true).length > 0) { hqHoverRole = role; break; }
      }
      if (!hqHoverRole) {
        for (const [id, temp] of hqTemps) {
          if (raycaster.intersectObject(temp.group, true).length > 0) { hqHoverTempId = id; break; }
        }
      }
      container.style.cursor = (hqHoverRole || hqHoverTempId) ? 'pointer' : 'default';
      return;
    }

    // Agents first: a robot standing in front of a building is what the
    // pointer is on, not the building behind it.
    const px = event.clientX - rect.left, py = event.clientY - rect.top;
    const agentHit = agentPool ? raycaster.intersectObjects(agentPool.hitTargets(), false)[0] : undefined;
    const agent = agentHit && agentPool ? agentPool.agentForHit(agentHit.object) : null;
    hoveredAgentId = agent?.id ?? null;
    if (agent) {
      const meta = agentMeta.get(agent.id);
      hoveredId = null;
      hoverLabel = {
        name: meta?.name ?? ROLE_NAME[agent.role] ?? agent.id,
        purpose: `${meta?.title ?? ROLE_TITLE[agent.role] ?? ''} · ${agent.id === MANAGER_ID ? managerNow.text : visualState(agent.state, false)}`,
        x: px, y: py,
      };
      container.style.cursor = 'pointer';
      return;
    }

    let hit: string | null = null;
    for (const [id, entry] of buildingRegistry) {
      if (raycaster.intersectObject(entry.group, true).length > 0) { hit = id; break; }
    }
    container.style.cursor = hit ? 'pointer' : '';
    hoveredId = hit;
    if (hit) {
      const d = buildingRegistry.get(hit)!.district;
      hoverLabel = { name: d.name, purpose: d.purpose, x: px, y: py };
    } else {
      hoverLabel = null;
    }
  }

  function onPointerDownStart(event: PointerEvent): void { clickGuard.start(event); }

  function onPointerDown(): void {
    // An orbit drag must never also select a building.
    if (!clickGuard.isClick()) return;
    if (hqEntered) {
      if (hqHoverRole) { pickHQCore(hqHoverRole); focusHQAgent(hqHoverRole); }
      else if (hqHoverTempId) pickHQTemp(hqHoverTempId);
      return;
    }
    if (currentInterior) return;
    if (hoveredAgentId) { selectCityAgent(hoveredAgentId); return; }
    // A click FRAMES a building and opens its panel -- entering an interior
    // is the panel's ENTER button. A single click used to teleport straight
    // inside, which is disorienting when all you wanted was a closer look.
    if (hoveredId) { selectedAgentId = null; focusDistrict(hoveredId); return; }
    selectedAgentId = null;
  }

  function onResize(): void {
    if (!renderer || !container) return;
    const width = Math.max(1, container.clientWidth);
    const height = Math.max(1, container.clientHeight);
    renderer.setSize(width, height);
    labelRenderer?.setSize(width, height);
    currentAspect = width / height;
    rig.setAspect(currentAspect);
    // Re-fit the city on resize, so the overview keeps filling the viewport
    // instead of drifting to a fixed zoom that only suited one window size.
    if (activePreset === 'CITY_OVERVIEW' && !cityBounds.isEmpty() && !userDrivingCamera && !currentInterior) {
      rig.frameBox(cityBounds, 1.04, 24);
    }
  }

  /** One frame: scene, then the label layer on top. Shared by the loop and
      the `step()` verification hook so they can never render differently. */
  const camFwd = new THREE.Vector3();
  function renderFrame(t: number): void {
    if (!renderer) return;
    // Closed interiors: cut the walls between the camera and the room, and
    // lift the roof off once the camera is close (cityInterior.updateCutaway).
    const cut = currentInterior ? interiorCuts.get(currentInterior) : undefined;
    if (cut) updateCutaway(cut, rig.camera.getWorldDirection(camFwd), rig.currentZoom);
    renderer.render(scene, rig.camera);
    if (!currentInterior) {
      updateReportLines(t);
      updateLabels(rig.currentZoom);
    }
    labelRenderer?.render(scene, rig.camera);
  }

  /* ---- lifecycle --------------------------------------------------------- */

  // Real measured frame rate off the render loop ('s 30fps budget).
  let framesRendered = 0;
  let fpsWindowStart = 0;
  let measuredFps = 0;

  function animate(): void {
    const now = performance.now();
    // 30fps budget while the view is still; every frame while the camera is
    // moving, so a drag tracks the mouse instead of stepping at 30Hz.
    const moving = !rig.settled() || !!container?.dataset.drag;
    if (moving || now - lastRenderTime >= RENDER_INTERVAL) {
      const dt = clock.getDelta();
      const t = clock.getElapsedTime();

      // Restrained ambient motion only: slow pulses, nothing that reads as
      // "working" -- there is no backend state here yet to justify that.
      for (const entry of buildingRegistry.values()) {
        const pulse = 0.85 + Math.sin(t * 0.6 + entry.district.x * 0.05) * 0.15;
        for (const mesh of entry.glow) {
          const pulseMul = (mesh.userData.pulseMul as number | undefined) ?? 1;
          (mesh.material as THREE.MeshStandardMaterial).emissiveIntensity = mesh.userData.baseIntensity * pulse * pulseMul;
        }
      }

      // CITY-3.5: the design "restrained rotating outer ring" (§4) --
      // a handful of tagged decorative rings/halos, nothing that implies
      // live activity.
      for (const { obj, speed } of spinningParts) obj.rotation.z += speed * 0.016;
      if (ceoGem) ceoGem.rotation.y = t * 0.7;
      // The command link breathes only while the CEO has a live directive.
      if (commandLink) (commandLink.material as THREE.LineDashedMaterial).opacity =
        $tasks.goal ? 0.55 + 0.35 * Math.abs(Math.sin(t * 1.8)) : 0.4;
      // Only routes whose both ends are reported busy pulse (applyLiveState).
      for (const line of activeRoutes) (line.material as THREE.LineBasicMaterial).opacity = 0.65 + 0.3 * Math.sin(t * 3);

      // Robot animation. Interior stations only while their room is visible
      // (no cost during the city overview); the street agents move and
      // animate whenever the city itself is shown.
      if (hqEntered) {
        // Seated at their desks; a verifier checking a result stands up
        // beside its chair (poseRobot keeps 'verify' standing).
        for (const station of hqStations.values()) {
          station.robot.group.position.z = station.pose === 'verify' ? 0.55 : 0;
          poseRobot(station.robot, station.pose, t, true);
        }
        for (const temp of hqTemps.values()) poseRobot(temp.robot, temp.pose, t, true);
        if (hqManager) poseRobot(hqManager.robot, hqManager.pose, t, true);
      } else if (currentInterior === 'academy') {
        // Students at their desks: the studying one works, the rest wait.
        for (const st of academyStudents.values()) {
          if (st.robot.group.visible) poseRobot(st.robot, st.pose, t, true);
        }
      } else if (!currentInterior) {
        updateAgents(Math.min(dt, 0.1), t);
        updateFollow();
        traffic?.update(dt);
      }

      // Measured frame interval, for the performance gate -- a real reading
      // off the render loop, not an estimate.
      framesRendered++;
      if (now - fpsWindowStart >= 1000) {
        measuredFps = Math.round((framesRendered * 1000) / (now - fpsWindowStart));
        framesRendered = 0;
        fpsWindowStart = now;
        if (selectedAgentId) uiTick++;
        const w = window as unknown as Record<string, unknown>;
        if (w.__argusCity) Object.assign(w.__argusCity as Record<string, unknown>, {
          fps: measuredFps, drawCalls: renderer?.info.render.calls ?? 0,
          triangles: renderer?.info.render.triangles ?? 0,
          geometries: renderer?.info.memory.geometries ?? 0,
          textures: renderer?.info.memory.textures ?? 0,
          kit: kitStats(), agents: agentPool?.agents.size ?? 0,
          assets: assetStats(), preset: activePreset, zoom: Math.round(rig.currentZoom),
        });
      }

      rig.update(dt);
      renderFrame(t);
      lastRenderTime = now;
    }
    animationFrameId = requestAnimationFrame(animate);
  }

  onMount(() => {
    if (!container) return;
    scene = new THREE.Scene();
    // Deep navy, not black: the Agents city is allowed more light and colour
    // than the rest of the HUD, and the background is what everything reads
    // against. Fog matches it so the far scenery dissolves instead of ending.
    // 2026-09-24: the owner's reference city is a purple synthwave night --
    // indigo overhead, violet toward the horizon (the bottom of the screen).
    scene.background = verticalGradient(['#090a22', '#170e3c', '#2e1257']);
    // Fog MUST be sized against the camera rig's own standoff distance, not
    // against world distance from the origin. An orthographic camera has no
    // other notion of depth: every fragment renders at roughly
    // RIG_DISTANCE - (point - target)·viewDir. The rig stands 400 units off,
    // and the campus plus its scenery ring spans about +/-150, so real depths
    // land in 250..600. Sizing the band by hand for a different standoff is
    // exactly how this scene went fully black once before -- deriving it from
    // CityCameraRig.standoff is what stops that recurring.
    const fogNear = CityCameraRig.standoff + 40;
    scene.fog = new THREE.Fog(0x1b1142, fogNear, fogNear + 380);
    clock = new THREE.Clock();
    fpsWindowStart = performance.now();

    currentAspect = Math.max(1, container.clientWidth) / Math.max(1, container.clientHeight);
    rig = new CityCameraRig(currentAspect);
    camera = rig.camera;

    // Night-campus lighting. A cool sky/ground hemisphere, one shadow-casting
    // moonlight key, a cyan rim and a warm counter-fill so the amber quarters
    // do not all collapse back to blue. Per-district point lights are added
    // by buildDistrict -- they are what separates one district's colour from
    // the next.
    //
    // Intensities are in three's physical units (r155+). The old values
    // (hemisphere 0.72, key 1.15) were tuned for the legacy x PI scale, so
    // they came out about a third as bright as intended -- one of the three
    // reasons the city went near-black. The other two: no environment map
    // for the metallic materials (fixed below, after the renderer exists)
    // and near-black surface albedos (fixed in cityKit's PALETTE).
    scene.add(new THREE.HemisphereLight(0xb6b0ff, 0x281a44, 2.1));
    // A magenta rim from behind the city: the reference's pink edge light.
    const rim = new THREE.DirectionalLight(0xff4fd8, 0.55);
    rim.position.set(70, 50, -110);
    scene.add(rim);
    const key1 = new THREE.DirectionalLight(0xe2ecff, 2.6);
    key1.position.set(90, 130, 70);
    key1.castShadow = true;
    key1.shadow.mapSize.set(2048, 2048);
    key1.shadow.camera.left = -120; key1.shadow.camera.right = 120;
    key1.shadow.camera.top = 120; key1.shadow.camera.bottom = -120;
    key1.shadow.camera.near = 10; key1.shadow.camera.far = 400;
    key1.shadow.bias = -0.0012;
    key1.shadow.normalBias = 0.02;
    scene.add(key1);
    const key2 = new THREE.DirectionalLight(0x38e0ff, 1.1);
    key2.position.set(-90, 60, -80);
    scene.add(key2);
    const warm = new THREE.DirectionalLight(0xffb877, 0.7);
    warm.position.set(40, 30, 120);
    scene.add(warm);

    raycaster = new THREE.Raycaster();
    mouse = new THREE.Vector2();

    cityGroup = new THREE.Group();
    scene.add(cityGroup);
    neonTrim = new NeonTrim();
    cityGroup.add(neonTrim.group);
    buildGround();
    buildStreets();
    DISTRICTS.forEach(buildDistrict);
    buildScenery();
    buildRoutes();
    // Every bench, tree, planter, cabinet and street light in the city, as
    // about eight InstancedMeshes.
    cityGroup.add(buildStreetProps(props));
    // The detail layer (cityDetail.ts): bins, hydrants, signs, cabinets,
    // transit shelters, charging posts and parking bays on every sidewalk --
    // placements kept off the asphalt.
    const detail = detailPlacements();
    detailCount = Object.values(detail).reduce((n, ps) => n + ps.length, 0);
    cityGroup.add(buildDetailProps(detail));
    // Ambient traffic on the real street network (scenery, like the trees --
    // see cityTraffic.ts): five vehicle classes, seven draw calls.
    traffic = new Traffic(STREETS, INTERSECTIONS);
    cityGroup.add(traffic.group);
    buildCeoNode();
    buildReportLines();
    buildOfficeBoard();
    buildHQRoom();
    buildAcademyInterior();
    buildVerifyInterior();

    measureCity();
    if (groundMesh) groundMesh.receiveShadow = true;

    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false, powerPreference: 'high-performance' });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.4));
    renderer.setSize(Math.max(1, container.clientWidth), Math.max(1, container.clientHeight));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    // Khronos PBR Neutral keeps the district hues true (ACES/AgX would push
    // the saturated accents toward white) while rolling off the bright
    // emissive windows instead of clipping them.
    renderer.toneMapping = THREE.NeutralToneMapping;
    renderer.toneMappingExposure = 1.15;
    renderer.shadowMap.enabled = true;
    // PCFSoft was removed in recent three; PCF is the supported soft option.
    renderer.shadowMap.type = THREE.PCFShadowMap;
    container.appendChild(renderer.domElement);

    // An environment for the metals to reflect. The Blender assets' steel,
    // alloy and graphite are 55-72% metallic and the kit defaults to 60%: a
    // metal with no environment reflects nothing and renders black, which
    // was the single biggest reason the city looked like a void. A neutral
    // studio room, prefiltered once, at a restrained intensity so it reads
    // as night-lit metal rather than daylight.
    const pmrem = new THREE.PMREMGenerator(renderer);
    envTexture = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
    pmrem.dispose();
    scene.environment = envTexture;
    scene.environmentIntensity = 0.55;

    // The label layer: real DOM text pinned to world points, over the canvas.
    labelRenderer = new CSS2DRenderer();
    labelRenderer.setSize(Math.max(1, container.clientWidth), Math.max(1, container.clientHeight));
    labelRenderer.domElement.className = 'city-labels';
    container.appendChild(labelRenderer.domElement);

    // The command summary starts folded on short screens, where it would
    // cover a third of the city.
    commandOpen = container.clientHeight > 620;

    // Assets stream in after the layout exists, so the scene is never blank.
    loadManifest().then(() => { void buildAgents(); });

    focusOverview();
    rig.sync(1);

    animate();
    resizeObserver = new ResizeObserver(onResize);
    resizeObserver.observe(container);
    container.addEventListener('pointermove', onPointerMove);
    container.addEventListener('pointerdown', onPointerDownStart);
    container.addEventListener('pointerup', onPointerDown);
    detachControls = attachCameraControls(container, rig, {
      onInteract: () => { userDrivingCamera = true; followingAgentId = null; followingTeam = false; },
      isDragBlocked: () => false,
      leftDrag: () => dragLeft,
    });
    window.addEventListener('keydown', onCityKey);

    (window as unknown as Record<string, unknown>).__argusCity = {
      districts: buildingRegistry.size, webgl: !!renderer,
      hq: { agents: hqStations.size, entered: hqEntered, mode: cameraMode },
      interiors: [...interiorGroups.keys()], agents: 0,
      // Verification hook: forces one frame and reports real counters.
      // Needed because this environment throttles requestAnimationFrame when
      // the browser pane is hidden, which would otherwise leave every visual
      // check reading a stale frame.
      step: (steps = 1, dt = 1 / 30) => {
        for (let i = 0; i < steps; i++) {
          const t = performance.now() / 1000;
          if (!currentInterior) { updateAgents(dt, t); traffic?.update(dt); }
          if (hqEntered) {
            for (const station of hqStations.values()) poseRobot(station.robot, station.pose, t, true);
            if (hqManager) poseRobot(hqManager.robot, hqManager.pose, t, true);
          }
          if (currentInterior === 'academy') {
            for (const st of academyStudents.values()) if (st.robot.group.visible) poseRobot(st.robot, st.pose, t, true);
          }
          rig.sync(1);
          renderFrame(t);
        }
        return {
          drawCalls: renderer?.info.render.calls ?? 0,
          triangles: renderer?.info.render.triangles ?? 0,
          geometries: renderer?.info.memory.geometries ?? 0,
          agents: agentPool?.agents.size ?? 0,
          preset: activePreset,
          zoom: Math.round(rig.currentZoom),
          interior: currentInterior,
          labelsShown: [...container.querySelectorAll('.city-labels .cl')]
            .filter((e) => (e as HTMLElement).style.display !== 'none')
            .map((e) => (e as HTMLElement).innerText.replace(/\n/g, ' / ')),
        };
      },
      focus: (id: string, preset?: CameraPreset) => { focusDistrict(id, preset ?? 'DISTRICT'); },
      enter: (id: string) => enterInterior(id as InteriorId),
      exit: () => exitInterior(),
      overview: () => focusOverview(),
      applyPreset: (p: CameraPreset) => applyPreset(p),
      selectAgent: (id: string | null) => selectCityAgent(id),
      zoomAt: (dy: number, x = 0, y = 0) => rig.zoomAt(dy, x, y),
      pan: (dx: number, dy: number) => rig.pan(dx, dy, container.clientHeight),
      orbit: (dx: number, dy: number) => rig.orbit(dx, dy),
      target: () => rig.currentTarget.toArray().map((v) => Math.round(v * 10) / 10),
      lookAt: (x: number, y: number, z: number, zoom?: number) => rig.lookAtPoint(new THREE.Vector3(x, y, z), zoom),
      hqOrigin: () => HQ_ORIGIN.toArray(),
      traffic: () => traffic?.count ?? null,
      detail: () => ({ streetProps: detailCount, roofPieces: roofKit?.count ?? 0 }),
      // Robots vs the district models, whose real sizes only exist here
      // (the layout keeps other paths clear). [] = nobody stands in
      // a building, now or at any district they could be sent to.
      clearance: () => {
        const boxes = [...buildingRegistry.values()].flatMap((e) => e.group.children
          .filter((c) => c.userData.districtId && c.type !== 'Mesh')
          .map((c) => new THREE.Box3().setFromObject(c).expandByVector(new THREE.Vector3(0.5, 0, 0.5))));
        const pool = agentPool;
        if (!pool) return ['agents not built'];
        const spots = [...pool.agents.values()].flatMap((a) => [
          { id: `${a.id} now`, p: a.root.position },
          ...[...navGraph.doors.keys()].map((d) => ({ id: `${a.id} @${d}`, p: pool.slotPos(a, d) })),
        ]);
        return spots.filter((s) => s.p && boxes.some((b) => b.containsPoint(s.p!))).map((s) => s.id);
      },
      kit: kitStats(), fps: 0,
    };

    return () => {
      cancelAnimationFrame(animationFrameId);
      resizeObserver?.disconnect();
      container.removeEventListener('pointermove', onPointerMove);
      container.removeEventListener('pointerdown', onPointerDownStart);
      container.removeEventListener('pointerup', onPointerDown);
      window.removeEventListener('keydown', onCityKey);
      detachControls?.();
      for (const p of hqPulses) p.tween.kill();
      hqPulses = [];
      hqStations.clear();
      hqTemps.clear();
      scene.traverse((child) => {
        // Sprite (the district labels) does NOT extend Mesh/Line -- it's
        // its own class -- and each one owns a real CanvasTexture, so it
        // needs the same map+material disposal or every label leaks a
        // canvas + texture on unmount.
        if (child instanceof THREE.Mesh || child instanceof THREE.Line || child instanceof THREE.Sprite) {
          (child as THREE.Mesh).geometry?.dispose();
          const m = child.material as THREE.Material | THREE.Material[];
          (Array.isArray(m) ? m : [m]).forEach((mat2) => {
            (mat2 as THREE.SpriteMaterial | THREE.MeshStandardMaterial).map?.dispose?.();
            mat2.dispose();
          });
        }
      });
      renderer?.dispose();
      if (renderer?.domElement.parentNode === container) container.removeChild(renderer.domElement);
      renderer = null;
      envTexture?.dispose();
      envTexture = null;
      (scene.background as THREE.Texture | null)?.dispose?.();
      labelRenderer?.domElement.remove();
      labelRenderer = null;
      agentLabels.length = 0;
      traffic?.dispose();
      traffic = null;
      roofKit = null;
      neonTrim = null;
      disposeDetail();
      officeBoard = null;
      hqManager = null;
      opsScreen = null;
      disposeInterior();
      ceoLabel = null;
      ceoGroup = null;
      ceoGem = null;
      commandLink = null;
      reportLines = null;
      activeRoutes.clear();
      buildingRegistry.clear();
      roadRegistry.clear();
      labelRegistry.clear();
      agentPool?.dispose();
      agentPool = null;
      agentsReady = false;
      disposeAssets();
      districtFills.length = 0;
      interiorGroups.clear();
      interiorCuts.clear();
      groundMesh = null;
      // The kit's caches outlive any one component instance, so they must be
      // emptied explicitly here. The traverse above may already have called
      // dispose() on some of the shared resources (dispose is idempotent);
      // what matters is that the maps end up EMPTY, so a remounted scene
      // builds fresh objects instead of handing out disposed ones. This also
      // clears spinningParts.
      disposeKit();
      delete (window as unknown as Record<string, unknown>).__argusCity;
    };
  });

  // CITY-3 detail-panel formatting -- deliberately duplicated from
  // components/AgentOffice.svelte's own local (unexported) helpers rather
  // than factored into a shared module: ~3 trivial pure functions, and that
  // component is proven/working (do not touch it for this).
  const HQ_STATE_CLASS: Record<string, string> = {
    idle: 'st-idle', queued: 'st-queued', preparing: 'st-busy', thinking: 'st-thinking',
    responding: 'st-busy', waiting_auth: 'st-queued', executing: 'st-ok', verifying: 'st-busy',
    completed: 'st-ok', warning: 'st-queued', blocked: 'st-critical', error: 'st-critical', disabled: 'st-idle',
    proposed: 'st-queued', validating: 'st-queued', approved: 'st-queued', active: 'st-ok',
    waiting: 'st-queued', failed: 'st-critical', expired: 'st-idle', destroyed: 'st-idle',
  };
  const HQ_TEAM_TERMINAL = new Set(['COMPLETED', 'FAILED', 'CANCELLED', 'TIMED_OUT', 'PARTIAL']);
  const hqStateLabel = (s: string) => s.replace(/_/g, ' ').toUpperCase();
  const hqAgo = (sec: number) => {
    if (!sec) return '—';
    if (sec < 60) return `${Math.round(sec)}S AGO`;
    if (sec < 3600) return `${Math.round(sec / 60)}M AGO`;
    return `${Math.round(sec / 3600)}H AGO`;
  };
  const hqElapsed = (s: number) => {
    if (!s) return '0S';
    if (s < 60) return `${Math.round(s)}S`;
    if (s < 3600) return `${Math.round(s / 60)}M ${Math.round(s % 60)}S`;
    return `${Math.floor(s / 3600)}H ${Math.round((s % 3600) / 60)}M`;
  };
</script>

<div class="city-wrap">
  <div bind:this={container} class="city-container" aria-hidden="true"></div>

  {#if !currentInterior}
    <!-- Phase C: camera presets, and the places you can actually go. -->
    <div class="city-nav" role="group" aria-label="City navigation">
      <div class="city-cam">
        {#each (['CITY_OVERVIEW', 'DISTRICT', 'BUILDING_FOCUS', 'STREET_LEVEL'] as CameraPreset[]) as p}
          <button
            class:active={activePreset === p && !userDrivingCamera}
            title={PRESETS[p].hint}
            on:click={() => applyPreset(p)}
          >{PRESETS[p].label}</button>
        {/each}
        <button class:active={followingTeam} disabled={!teamLive($teamOffice)}
          title="Keep the running team's robots in frame" on:click={() => followTeam(!followingTeam)}>FOLLOW TEAM</button>
        <button class="city-cam-reset" title="Back to the whole city, nothing selected" on:click={resetView}>⟲ RESET</button>
      </div>
      <div class="city-cam city-cam-places">
        <button on:click={() => enterInterior('agent-hq')}>HQ INTERIOR</button>
        <button on:click={() => enterInterior('academy')}>ACADEMY</button>
        <button on:click={() => enterInterior('verification-institute')}>VERIFICATION</button>
      </div>
    </div>
  {:else if !hqEntered}
    <div class="city-cam" role="group" aria-label="Interior navigation">
      <button class="active">{INTERIOR_TITLE[currentInterior]}</button>
      <button class="city-cam-back" on:click={exitInterior}>← BACK TO CITY</button>
    </div>
  {:else}
    <div class="city-cam" role="group" aria-label="Agent HQ camera mode">
      <button class:active={cameraMode === 'hq-overview'} on:click={enterAgentHQ}>HQ OVERVIEW</button>
      <button class:active={cameraMode === 'hq-agent'} disabled={!$selectedAgent} on:click={() => $selectedAgent && focusHQAgent($selectedAgent.id as CoreRole)}>SELECTED AGENT</button>
      <button class:active={cameraMode === 'hq-team'} disabled={!$teamOffice.activeTeam} on:click={focusHQTeam}>ACTIVE TEAM</button>
      <button class:active={cameraMode === 'hq-room' && roomFocus === 'ops'} on:click={() => focusHQRoom('ops')}>OPS ROOM</button>
      <button class:active={cameraMode === 'hq-room' && roomFocus === 'core'} on:click={() => focusHQRoom('core')}>SERVICE CORE</button>
      <button class="city-cam-back" on:click={exitAgentHQ}>← BACK TO CITY</button>
    </div>
  {/if}

  <!-- Camera pad: everything the mouse does, as buttons (hold to repeat). -->
  <div class="city-pad" role="group" aria-label="Camera controls">
    <div class="pad-help">
      <span>{dragLeft === 'orbit' ? 'Drag: rotate · right-drag: move' : 'Drag: move · right-drag: rotate'} · wheel: zoom · keys WASD QE RF</span>
      <button class="pad-drag" on:click={toggleDragLeft} aria-pressed={dragLeft === 'pan'}
        title="Switch what a left-drag does">DRAG: {dragLeft === 'orbit' ? 'ROTATE' : 'MOVE'}</button>
    </div>
    <span class="pad-cap">TURN</span>
    <button use:hold={() => camStep({ yaw: -PAD_TURN })} title="Turn left (Q)" aria-label="Turn left">⟲</button>
    <button use:hold={() => camStep({ yaw: PAD_TURN })} title="Turn right (E)" aria-label="Turn right">⟳</button>
    <span class="pad-cap">MOVE</span>
    <button use:hold={() => camStep({ right: -PAD_MOVE })} title="Move left (A)" aria-label="Move left">◀</button>
    <button use:hold={() => camStep({ forward: PAD_MOVE })} title="Move forward (W)" aria-label="Move forward">▲</button>
    <button use:hold={() => camStep({ forward: -PAD_MOVE })} title="Move back (S)" aria-label="Move back">▼</button>
    <button use:hold={() => camStep({ right: PAD_MOVE })} title="Move right (D)" aria-label="Move right">▶</button>
    <span class="pad-cap">ZOOM</span>
    <button use:hold={() => camStep({ zoom: 0.85 })} title="Zoom in (+)" aria-label="Zoom in">+</button>
    <button use:hold={() => camStep({ zoom: 1 / 0.85 })} title="Zoom out (−)" aria-label="Zoom out">−</button>
    <span class="pad-cap">TILT</span>
    <button use:hold={() => camStep({ pitch: PAD_TILT })} title="Look more from above (R)" aria-label="Tilt toward top-down">↑</button>
    <button use:hold={() => camStep({ pitch: -PAD_TILT })} title="Look more from the side (F)" aria-label="Tilt toward the horizon">↓</button>
    <button class="pad-home" on:click={camHome} title={currentInterior ? 'Frame the whole floor again' : 'Back to the whole city'} aria-label="Home view">⌂</button>
  </div>

  <!-- The CEO inbox: available everywhere, city or interior. -->
  <CeoInbox bind:open={inboxOpen} onOpenAgent={openAgentFromInbox} />

  {#if !currentInterior && teamPanelOpen && !inboxOpen}
    <!-- Team panel: the orchestrator's own TeamDetail -- goal,
         workers, the task graph with what each task waits on, verifier,
         budget. Actions are requests; nothing here edits team state. -->
    {@const t = $teamOffice.activeTeam}
    <div class="city-focus-panel city-team-panel" style="--cat:#7fefff">
      <div class="cfp-head">
        <h3>{t ? `TEAM ${t.team_id}` : 'NO TEAM'}</h3>
        <span class="cfp-cat {t && !HQ_TEAM_TERMINAL.has(t.state) ? 'st-busy' : 'st-idle'}">{t?.state ?? 'IDLE'}</span>
      </div>
      {#if t}
        {@const graph = teamGraph(t)}
        {@const verify = graph.find((g) => g.verify)}
        <p class="cap-role">{t.goal || t.playbook.replace(/_/g, ' ')}</p>
        <div class="cfp-meta">
          <div><span>PROGRESS</span><b>{Math.round(t.progress * 100)}%</b></div>
          <div><span>PHASE</span><b>{(t.current_phase || '—').toUpperCase()}</b></div>
          <div><span>MANAGER</span><b>Agent Manager</b></div>
          <div><span>VERIFIER</span><b>{verify ? verify.state : t.verdict || 'NOT STARTED'}</b></div>
          <div><span>CREATED</span><b>{new Date(t.created_at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} · {hqElapsed(t.elapsed_s)}</b></div>
          <div><span>BUDGET USED</span><b>{t.model_calls} model calls · {t.replans} replans</b></div>
        </div>
        <div class="team-graph" aria-label="Task graph">
          {#each graph as g (g.id)}
            <div class="tg-row tg-{g.state.toLowerCase()}">
              <b>{g.who}</b><span>{g.title}</span>
              <em>{g.state}{g.after.length ? ` · after ${g.after.join(', ')}` : ''}</em>
            </div>
          {/each}
        </div>
        <p class="cfp-agents"><span>WORKERS</span>
          {#each t.members as mb (mb.member_id)}
            <button class="cfp-agent" on:click={() => { teamPanelOpen = false; selectCityAgent(mb.kind === 'core' ? mb.role : `temp:${mb.agent_id}`); }}>
              {(mb.role || 'specialist').replace(/_/g, ' ').toUpperCase()} · {hqStateLabel(mb.state || 'idle')}
            </button>
          {/each}
        </p>
      {:else}
        <p>No team has run in this session. A team appears here when the Agent Manager forms one.</p>
      {/if}
      <div class="cfp-actions">
        {#if t && !HQ_TEAM_TERMINAL.has(t.state)}
          <button on:click={() => followTeam(true)}>FOLLOW TEAM</button>
          <button on:click={() => { teamPanelOpen = false; selectCityAgent(MANAGER_ID); }}>MESSAGE MANAGER</button>
          <button class="cfp-release" on:click={onCancelHQTeam} disabled={hqCancelling}>{hqCancelling ? 'CANCELLING…' : 'CANCEL TEAM'}</button>
        {/if}
        <button on:click={() => (teamPanelOpen = false)}>✕</button>
      </div>
    </div>
  {:else if !currentInterior && selectedAgentId && !inboxOpen}
    {@const card = agentCard(selectedAgentId, agentMeta, $agentOffice, $teamOffice, managerNow, uiTick)}
    {@const live = managerAgentView(selectedAgentId, $agentManager.manager)}
    {#if card}
      <!-- Agent communication panel: who this agent is, what it is doing now,
           where it sits in the chain of command, and a direct line to it --
           every field read from real state. -->
      <div class="city-focus-panel city-agent-panel" style={`--cat:${card.accent}`}>
        <div class="cfp-head">
          <h3>{card.name}</h3>
          <span class="cfp-cat {card.chipClass}">{card.status}</span>
        </div>
        <p class="cap-role">{card.title}</p>
        {#if card.description}<p>{card.description}</p>{/if}
        <div class="cfp-meta">
          <div class="cfp-wide"><span>CURRENT ASSIGNMENT</span><b>{live?.current_task || (live?.current_job_id ? `Job ${live.current_job_id}` : 'None -- idle')}</b></div>
          <div><span>REPORTS TO</span><b>{card.reportsTo}</b></div>
          <div><span>TYPE</span><b>{live?.worker_type?.replace('_', ' ') ?? card.tier}</b></div>
          <div><span>DISTRICT</span><b>{card.home}</b></div>
          <div><span>LOCATION</span><b>{card.location}</b></div>
          <div class="cfp-wide"><span>TEAM</span><b>{card.team}</b></div>
          {#if card.hiredBy}<div class="cfp-wide"><span>HIRED BY</span><b>{card.hiredBy}</b></div>{/if}
          {#if live}
            <div><span>BACKEND</span><b>{live.backend.replace(/_/g, ' ')}</b></div>
            <div><span>SPECIALIZATION</span><b>{live.specialization || live.role || '—'}</b></div>
            <div><span>PROVIDER</span><b>{live.provider === 'cloud' ? 'CLOUD' : 'LOCAL'}</b></div>
            <div><span>MODEL</span><b>{live.model || (live.provider === 'cloud' ? 'Chosen per call' : '—')}</b></div>
          {/if}
          {#if live && live.kind !== 'core'}
            <div><span>CREATED</span><b>{live.created_at ? new Date(live.created_at * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—'}</b></div>
            <div><span>TIME LEFT</span><b>{live.ttl_remaining_s ? `${Math.round(live.ttl_remaining_s / 60)} min` : '—'}</b></div>
          {/if}
          {#if live?.performance && (live.performance.tasks_completed || live.performance.tasks_failed)}
            <div class="cfp-wide"><span>TRACK RECORD (REAL JOBS)</span><b>{live.performance.tasks_completed} done · {live.performance.tasks_failed} failed{live.performance.verification_pass_rate !== null ? ` · ${Math.round(live.performance.verification_pass_rate * 100)}% verified` : ''}</b></div>
          {/if}
        </div>
        <div class="cfp-actions">
          <button on:click={() => followAgent(selectedAgentId)}>FOLLOW</button>
          {#if card.homeId}<button on:click={() => { const h = card.homeId; selectedAgentId = null; focusDistrict(h); }}>DISTRICT</button>{/if}
          {#if card.inTeam}<button on:click={() => { selectedAgentId = null; teamPanelOpen = true; }}>VIEW TEAM</button>{/if}
          {#if selectedAgentId !== MANAGER_ID}
            <button title="The Manager answers from real state" on:click={() => askManagerAbout(card.name, card.kind)}>ASK MANAGER</button>
          {/if}
          {#if selectedAgentId.startsWith('temp:')}
            <button class="cfp-release" on:click={() => onReleaseSpecialist(selectedAgentId)}>CANCEL</button>
          {/if}
          <button on:click={() => (selectedAgentId = null)}>✕</button>
        </div>
        <AgentThread agentId={selectedAgentId.replace(/^temp:/, '')} agentName={card.name}
          canWork={!selectedAgentId.startsWith('temp:')} />
      </div>
    {/if}
  {:else if !currentInterior && focusedDistrict && !inboxOpen}
    {@const live = liveState?.[focusedDistrict.id]}
    {@const style = categoryStyle(focusedDistrict.category)}
    {@const here = agentsHere(focusedDistrict.id)}
    <!-- Phase I: name, type, role, status, what happens here, and which real
         agents are actually present right now. -->
    <div class="city-focus-panel" style={`--cat:${hexToCss(style.accent)}`}>
      <div class="cfp-head">
        <h3>{focusedDistrict.name}</h3>
        <span class="cfp-cat">{style.label}</span>
      </div>
      <p>{focusedDistrict.role}</p>
      {#if live}
        <div class="city-focus-live" class:attention={live.activity === 'attention'} class:critical={live.activity === 'critical'} class:offline={live.activity === 'offline'}>
          <b>{live.status}</b>
          {#each live.detail as line}<span>{line}</span>{/each}
        </div>
      {:else}
        <div class="city-focus-live"><b>IDLE</b><span>No live signal reported for this district.</span></div>
      {/if}
      <div class="cfp-meta">
        <div><span>SECURE ZONE</span><b>{focusedDistrict.secure ? 'INSIDE' : 'OUTSIDE'}</b></div>
        <div><span>STRUCTURES</span><b>{focusedDistrict.assets.length}</b></div>
      </div>
      {#if here.length}
        <p class="cfp-agents"><span>AGENTS PRESENT</span>
          {#each here as a}
            <button class="cfp-agent" on:click={() => selectCityAgent(a.id)}>{a.name.replace(/ Agent$/, '').toUpperCase()} · {hqStateLabel(a.state)}</button>
          {/each}
        </p>
      {/if}
      <div class="cfp-actions">
        <button on:click={() => focusDistrict(focusedDistrict.id, 'BUILDING_FOCUS')}>BUILDING</button>
        {#if INTERIOR_IDS.includes(focusedDistrict.id as InteriorId)}
          <button on:click={() => enterInterior(focusedDistrict.id as InteriorId)}>ENTER →</button>
        {/if}
        <button on:click={focusOverview}>← CITY</button>
      </div>
    </div>
  {/if}

  {#if followingAgentId}
    <div class="city-follow">
      <span>FOLLOWING</span><b>{followingAgentId.replace('temp:', '').toUpperCase()}</b>
      <button on:click={() => followAgent(null)}>STOP</button>
    </div>
  {/if}

  {#if !currentInterior}
    {@const cmd = commandStats(agentMeta, $agentOffice, $teamOffice, $agentManager.link === 'online' ? $agentManager.manager : null)}
    <!-- The chain of command, at a glance: you, the Manager, and the workforce
         it runs. Counts are real (the Manager's own state when it answers,
         else agentOffice / teamOffice), never estimated. -->
    <div class="city-command" class:collapsed={!commandOpen}>
      <button class="cc-toggle" on:click={() => (commandOpen = !commandOpen)} aria-expanded={commandOpen}>
        CHAIN OF COMMAND <span>{commandOpen ? '▾' : '▸'}</span>
      </button>
      {#if commandOpen}
        <button class="cc-tier cc-ceo" on:click={() => focusDistrict('core-tower', 'BUILDING_FOCUS')}>
          <span>CEO</span><b>YOU · OWNER</b>
          <em>{$tasks.goal ? `Directive: ${$tasks.goal}` : 'No active directive'}</em>
        </button>
        <button class="cc-tier cc-manager" on:click={() => selectCityAgent(MANAGER_ID)}>
          <span>AGENT MANAGER</span><b>{managerNow.text}</b>
          <em>{$teamOffice.activeTeam && !HQ_TEAM_TERMINAL.has($teamOffice.activeTeam.state) ? ($teamOffice.activeTeam.goal || 'Running a team') : 'Team orchestrator · hires specialists'}</em>
        </button>
        <div class="cc-grid">
          <div><span>TOTAL AGENTS</span><b>{cmd.total}</b></div>
          <div><span>ACTIVE NOW</span><b class:hot={cmd.active > 0}>{cmd.active}</b></div>
          <div><span>SPECIALISTS</span><b>{cmd.specialists}</b></div>
          <div><span>CLOUD WORKERS</span><b>{cmd.cloud}</b></div>
          <div><span>NEW HIRES · TEAM</span><b>{cmd.teamHires}</b></div>
          <button class="cc-cell" title="Open the team panel" on:click={() => { selectedAgentId = null; teamPanelOpen = true; }}>
            <span>ACTIVE TEAMS</span><b class:hot={cmd.teams > 0}>{cmd.teams}</b></button>
          <div><span>HIRE REQUESTS</span><b class:hot={cmd.pending > 0}>{cmd.pending}</b></div>
          <div><span>QUEUED WORK</span><b>{cmd.queued}</b></div>
        </div>
        {#if $agentManager.link === 'online' && $agentManager.manager}
          <!-- Every worker backend and whether it is really there: Hermes
               reads NOT MERGED, a switched-off cloud reads OFF. -->
          <div class="cc-backends">
            {#each $agentManager.manager.backends as b (b.id)}
              <span class:off={!b.available} title={b.note}>{b.id.replace(/^ARGUS_/, '').replace(/_/g, ' ')}{b.available ? '' : b.status === 'NOT_MERGED' ? ' · NOT MERGED' : ' · OFF'}</span>
            {/each}
          </div>
        {/if}
        {#if cmd.pending > 0}
          <button class="cc-ask" on:click={() => (inboxOpen = true)}>
            {cmd.pending} hire request{cmd.pending === 1 ? '' : 's'} waiting for you →
          </button>
        {/if}
        <div class="cc-districts">
          {#each cmd.districts as d}
            <button style={`--c:${d.accent}`} title={d.members} on:click={() => focusDistrict(d.id)}>{d.short} <b>{d.count}</b></button>
          {/each}
        </div>
      {/if}
    </div>
  {/if}

  {#if !currentInterior && hoverLabel}
    {@const live = liveState?.[hoveredId ?? '']}
    <div class="city-hover" style={`left:${hoverLabel.x + 14}px; top:${hoverLabel.y + 10}px;`}>
      <b>{hoverLabel.name}</b>
      <span>{hoverLabel.purpose}</span>
      {#if live}<em>{live.status}</em>{/if}
    </div>
  {/if}

  {#if hqEntered}
    <!-- Team Operations Room: real TeamDetail fields only, same
         contract components/AgentOffice.svelte's own ACTIVE TEAM panel
         already uses. -->
    <div class="hq-ops-panel">
      <div class="hq-ops-head">
        <h3>TEAM OPERATIONS</h3>
        {#if $teamOffice.link === 'offline'}<span class="status critical">DISCONNECTED</span>
        {:else if $teamOffice.activeTeam}<span class="status">{$teamOffice.activeTeam.state}</span>
        {:else}<span class="status">NO ACTIVE TEAM</span>{/if}
        {#if $teamOffice.activeTeam && !HQ_TEAM_TERMINAL.has($teamOffice.activeTeam.state)}
          <button class="hq-cancel-btn" on:click={onCancelHQTeam} disabled={hqCancelling}>{hqCancelling ? 'CANCELLING…' : 'CANCEL TEAM'}</button>
        {/if}
      </div>
      {#if $teamOffice.activeTeam}
        {@const t = $teamOffice.activeTeam}
        {@const activeRoles = t.members.filter((m) => m.kind === 'core' && ['thinking', 'responding', 'executing', 'active'].includes(m.state.toLowerCase()))}
        {@const waitingRoles = t.members.filter((m) => m.kind === 'core' && ['queued', 'waiting_auth', 'waiting', 'proposed'].includes(m.state.toLowerCase()))}
        <p class="hq-ops-mission"><span>MISSION</span>{t.goal || 'No goal text available.'}</p>
        <div class="hq-ops-grid">
          <div><span>PHASE</span><b>{t.current_phase || '—'}</b></div>
          <div><span>PROGRESS</span><b>{Math.round(t.progress * 100)}%</b></div>
          <div><span>ELAPSED</span><b>{hqElapsed(t.elapsed_s)}</b></div>
          <div><span>VERIFYING</span><b class={t.current_phase === 'verifying' ? 'st-busy' : ''}>{t.current_phase === 'verifying' ? 'YES' : 'NO'}</b></div>
        </div>
        {#if activeRoles.length}<p class="hq-ops-roles"><span>ACTIVE</span>{activeRoles.map((m) => m.role.toUpperCase()).join(', ')}</p>{/if}
        {#if waitingRoles.length}<p class="hq-ops-roles"><span>WAITING</span>{waitingRoles.map((m) => m.role.toUpperCase()).join(', ')}</p>{/if}
      {:else}
        <p class="rail-note">{$teamOffice.link === 'offline' ? ($teamOffice.lastError ?? 'The agent team control link is unreachable.') : 'No investigation is currently running.'}</p>
      {/if}
    </div>
  {/if}

  {#if hqEntered && $selectedAgent && !inboxOpen}
    <div class="hq-detail-panel">
      <div class="hq-ops-head"><h3>{$selectedAgent.name.toUpperCase()}</h3><span class="status {HQ_STATE_CLASS[$selectedAgent.state] ?? ''}">{hqStateLabel($selectedAgent.state)}</span></div>
      <div class="hq-ops-grid">
        <div><span>ROLE</span><b>{$selectedAgent.role}</b></div>
        <div><span>TYPE</span><b>CORE</b></div>
        <div><span>CURRENT JOB</span><b>{$selectedAgent.current_job_id || '—'}</b></div>
        <div><span>QUEUE POSITION</span><b>{$selectedAgent.queue_position || '—'}</b></div>
        <div><span>LAST ACTIVITY</span><b>{hqAgo(Math.max(0, Date.now() / 1000 - ($selectedAgent.last_activity_at || 0)))}</b></div>
        <div><span>COMPLETED / FAILED</span><b>{$selectedAgent.completed_jobs} / {$selectedAgent.failed_jobs}</b></div>
      </div>
      <p class="rail-note">{$selectedAgent.description}</p>
    </div>
  {:else if hqEntered && $selectedDynamicAgent}
    {@const d = $selectedDynamicAgent}
    <div class="hq-detail-panel">
      <div class="hq-ops-head"><h3>{d.name.toUpperCase()}</h3><span class="status">{hqStateLabel(d.state)}</span></div>
      <div class="hq-ops-grid">
        <div><span>TYPE</span><b>{d.type === 'EPHEMERAL_CLOUD' ? 'CLOUD — INTELLIGENCE WORKER' : 'TEMP LOCAL'}</b></div>
        <div><span>CURRENT TASK</span><b>{d.current_task || '—'}</b></div>
        <div><span>PARENT</span><b>{d.parent.toUpperCase()}</b></div>
        <div><span>QUEUE POSITION</span><b>{d.queue_state.queue_position || '—'}</b></div>
        <div><span>MODEL</span><b>{d.type === 'EPHEMERAL_CLOUD' ? 'CLOUD PROVIDER' : (d.model || '—')}</b></div>
        <div><span>TTL</span><b>{d.ttl_remaining_s > 0 ? `${Math.round(d.ttl_remaining_s)}S` : 'EXPIRED'}</b></div>
      </div>
      <p class="rail-note">{d.result_summary || 'No result yet.'}</p>
    </div>
  {:else if hqEntered && $selectedTeamMember}
    {@const m = $selectedTeamMember}
    <div class="hq-detail-panel">
      <div class="hq-ops-head"><h3>{m.role.toUpperCase()}</h3><span class="status">{hqStateLabel(m.state)}</span></div>
      <div class="hq-ops-grid">
        <div><span>TYPE</span><b>{m.kind === 'core' ? 'CORE' : m.worker_type.toUpperCase()}</b></div>
        <div><span>CURRENT TASK</span><b>{m.current_task || '—'}</b></div>
        <div><span>PARENT</span><b>{m.parent.toUpperCase()}</b></div>
        <div><span>TEAM</span><b>{$teamOffice.activeTeam?.team_id ?? '—'}</b></div>
        <div><span>TTL</span><b>{m.ttl_remaining_s > 0 ? `${Math.round(m.ttl_remaining_s)}S` : '—'}</b></div>
      </div>
      <p class="rail-note">{m.result_summary || 'No result yet.'}</p>
    </div>
  {/if}
</div>

<style>
  .city-wrap { position: relative; }
  .city-container {
    position: relative;
    width: 100%;
    /* Phase C/§35: the city gets the screen. Tall enough that an isometric
       campus reads as a place, capped so it never pushes the page controls
       off a 768px-high laptop. */
    height: clamp(460px, calc(100vh - 210px), 880px);
    border-radius: 10px;
    overflow: hidden;
    background: #140c30;
    cursor: grab;
    touch-action: none;
  }
  /* :global -- the attribute is set by cityCamera.ts, where Svelte's CSS
     scoping cannot see it and would strip the rule as unused. */
  .city-container:global([data-drag='pan']) { cursor: move; }
  .city-container:global([data-drag='orbit']) { cursor: grabbing; }
  .city-container :global(canvas) { display: block; }

  /* ---- screen-space labels (cityLabels.ts) -------------------------------
     A solid dark plate + a colour edge: readable over bright windows and
     over the dark ground alike, which bare coloured text never is. */
  /* z-index 0 makes the layer its own stacking context: CSS2DRenderer gives
     every label a z-index, and without a context those escape and paint over
     the detail panels. */
  .city-container :global(.city-labels) { position: absolute; inset: 0; z-index: 0; pointer-events: none; }
  .city-container :global(.cl) {
    pointer-events: none; display: grid; justify-items: center; gap: 1px;
    padding: 3px 8px 4px; border-radius: 5px; white-space: nowrap; line-height: 1.2;
    background: rgba(8, 15, 28, .86);
    border: 1px solid color-mix(in srgb, var(--c) 55%, transparent);
    box-shadow: 0 3px 12px rgba(0, 0, 0, .45);
    font-family: 'Space Grotesk', 'Segoe UI', system-ui, sans-serif;
  }
  .city-container :global(.cl b) { font-size: 11px; font-weight: 700; letter-spacing: .05em; color: #f1f7ff; }
  .city-container :global(.cl span) {
    display: flex; align-items: center; gap: 5px;
    font-size: 9.5px; letter-spacing: .03em; color: rgba(212, 228, 242, .8);
  }
  .city-container :global(.cl i) {
    font-style: normal; font-size: 8.5px; font-weight: 700; letter-spacing: .08em;
    padding: 0 4px; border-radius: 3px; background: rgba(255, 255, 255, .08);
  }
  .city-container :global(.cl-agent b::before) {
    content: ''; display: inline-block; width: 7px; height: 7px; margin-right: 5px;
    border-radius: 50%; background: var(--c); box-shadow: 0 0 6px var(--c); vertical-align: 1px;
  }
  .city-container :global(.cl.compact span) { display: none; }
  .city-container :global(.cl-district) { border-top: 2px solid var(--c); }
  .city-container :global(.cl-district b) { color: var(--c); font-size: 11.5px; letter-spacing: .08em; }
  .city-container :global(.cl-district span) { font-size: 8.5px; letter-spacing: .14em; color: rgba(212, 228, 242, .6); }
  .city-container :global(.cl-sub) { padding: 2px 6px; background: rgba(8, 15, 28, .72); }
  .city-container :global(.cl-sub b) { font-size: 9.5px; font-weight: 600; color: color-mix(in srgb, var(--c) 70%, white); }
  .city-container :global(.cl-manager) {
    background: linear-gradient(180deg, rgba(58, 44, 10, .92), rgba(20, 16, 6, .92));
    border: 1px solid var(--c); box-shadow: 0 0 16px rgba(255, 209, 102, .35);
  }
  .city-container :global(.cl-manager b) { color: #ffe29a; font-size: 12px; letter-spacing: .1em; }
  .city-container :global(.cl-ceo) {
    background: linear-gradient(180deg, rgba(74, 58, 18, .94), rgba(24, 19, 7, .94));
    border: 1px solid var(--c); box-shadow: 0 0 22px rgba(255, 231, 163, .4);
  }
  .city-container :global(.cl-ceo b) { color: #fff1c7; font-size: 12.5px; letter-spacing: .12em; }
  .city-container :global(.cl-board) {
    display: grid; gap: 4px; justify-items: stretch; min-width: 214px; padding: 8px 10px;
    background: linear-gradient(180deg, rgba(40, 32, 12, .94), rgba(12, 16, 26, .94));
    border: 1px solid rgba(255, 209, 102, .7); border-radius: 7px;
    box-shadow: 0 0 20px rgba(255, 209, 102, .22), 0 8px 24px rgba(0, 0, 0, .45);
  }
  .city-container :global(.cl-board > b) { font-size: 10.5px; letter-spacing: .14em; color: #ffe29a; }
  .city-container :global(.cl-board .bd-grid) { display: grid; grid-template-columns: repeat(4, 1fr); gap: 3px 8px; }
  .city-container :global(.cl-board .bd-grid div) { display: grid; }
  .city-container :global(.cl-board .bd-grid em) { font-style: normal; font-size: 14px; font-weight: 800; color: #eef6ff; }
  .city-container :global(.cl-board .bd-grid em.hot) { color: #7fefff; }
  .city-container :global(.cl-board .bd-grid small) { font-size: 7.5px; letter-spacing: .12em; color: rgba(214, 228, 240, .6); }
  .city-container :global(.cl-board .bd-row) {
    display: flex; justify-content: space-between; gap: 8px; font-size: 10px; color: #eef6ff;
    border-top: 1px solid rgba(255, 255, 255, .08); padding-top: 3px;
  }
  .city-container :global(.cl-board .bd-row i) { font-style: normal; font-size: 8.5px; font-weight: 800; letter-spacing: .06em; }
  .city-container :global(.cl-board i.st-ok) { color: #4ade9e; }
  .city-container :global(.cl-board i.st-queued) { color: #ffd166; }
  .city-container :global(.cl-board i.st-thinking) { color: #b9a4ff; }
  .city-container :global(.cl-board i.st-critical) { color: #ff8f8f; }
  .city-container :global(.cl-board i.st-off) { color: #8a97a6; }
  .cfp-release { border-color: rgba(255, 138, 106, .55) !important; color: #ffab94 !important; }
  .cc-ask {
    all: unset; cursor: pointer; margin-left: 12px; padding: 5px 8px; border-radius: 5px;
    font-size: 10px; font-weight: 700; color: #1a1406; background: #ffd166; text-align: center;
  }
  .cc-ask:focus-visible { outline: 2px solid #fff; outline-offset: 1px; }
  .city-container :global(.cl.focused) {
    border-color: var(--c);
    box-shadow: 0 0 0 1px var(--c), 0 0 18px color-mix(in srgb, var(--c) 45%, transparent);
  }
  .city-container :global(.cl i.st-idle) { color: rgba(170, 200, 215, .85); }
  .city-container :global(.cl i.st-busy) { color: #38e0ff; background: rgba(56, 224, 255, .14); }
  .city-container :global(.cl i.st-thinking) { color: #b9a4ff; background: rgba(149, 120, 255, .16); }
  .city-container :global(.cl i.st-queued) { color: #ffb244; background: rgba(255, 178, 68, .14); }
  .city-container :global(.cl i.st-ok) { color: #4ade9e; background: rgba(74, 222, 158, .14); }
  .city-container :global(.cl i.st-critical) { color: #ff6b6b; background: rgba(255, 74, 74, .16); }
  .city-container :global(.cl i.st-off) { color: #8a97a6; }

  .city-cam-reset { border-color: rgba(255, 209, 102, .4) !important; color: #ffe29a !important; }

  /* ---- chain of command ---------------------------------------------------- */
  /* Bottom-left: the right edge belongs to the building/agent detail panel,
     and the two must never stack on top of each other. */
  .city-command {
    position: absolute; left: 10px; bottom: 10px; width: 250px;
    display: grid; gap: 6px; padding: 8px 10px 10px;
    background: rgba(8, 15, 28, .86); border: 1px solid rgba(255, 209, 102, .35);
    border-radius: 8px; backdrop-filter: blur(4px);
  }
  .city-command.collapsed { width: auto; padding: 6px 10px; }
  .cc-toggle {
    all: unset; cursor: pointer; display: flex; justify-content: space-between;
    font-size: 9.5px; font-weight: 700; letter-spacing: .14em; color: #ffe29a;
  }
  .cc-tier {
    all: unset; cursor: pointer; display: grid; gap: 1px; padding: 6px 8px; border-radius: 6px;
    border: 1px solid transparent;
  }
  .cc-tier:hover { border-color: rgba(255, 209, 102, .45); }
  .cc-tier span { font-size: 8.5px; letter-spacing: .14em; color: rgba(255, 226, 154, .7); }
  .cc-tier b { font-size: 12px; letter-spacing: .06em; color: #fff1c7; }
  .cc-tier em { font-size: 10px; font-style: normal; color: rgba(214, 228, 240, .72); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .cc-ceo { background: linear-gradient(90deg, rgba(255, 231, 163, .14), rgba(255, 231, 163, .03)); }
  .cc-manager { background: linear-gradient(90deg, rgba(255, 209, 102, .1), rgba(255, 209, 102, .02)); margin-left: 12px; position: relative; }
  .cc-manager::before {
    content: ''; position: absolute; left: -9px; top: -6px; width: 7px; height: 22px;
    border-left: 1px solid rgba(255, 209, 102, .45); border-bottom: 1px solid rgba(255, 209, 102, .45);
  }
  .cc-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4px 10px; margin-left: 12px; }
  .cc-grid span { display: block; font-size: 8.5px; letter-spacing: .1em; color: rgba(160, 190, 205, .7); }
  .cc-grid b { font-size: 13px; color: #e6f2f5; }
  .cc-grid b.hot { color: #38e0ff; }
  .cc-grid .cc-cell { all: unset; cursor: pointer; display: block; border-radius: 3px; }
  .cc-grid .cc-cell:hover b, .cc-grid .cc-cell:focus-visible b { text-decoration: underline; }
  .cc-backends { display: flex; flex-wrap: wrap; gap: 3px; margin-left: 12px; }
  .cc-backends span {
    font-size: 8.5px; letter-spacing: .08em; padding: 1px 5px; border-radius: 3px;
    color: #9deaff; border: 1px solid rgba(56, 224, 255, .3);
  }
  .cc-backends span.off { color: rgba(160, 175, 190, .7); border-color: rgba(160, 175, 190, .25); }

  /* ---- the team panel ---- */
  .city-team-panel { width: 320px; max-width: 320px !important; border-color: #7fefff !important; }
  .city-team-panel h3 { color: #7fefff !important; }
  .team-graph { display: grid; gap: 3px; margin: 2px 0 8px; }
  .tg-row {
    display: grid; grid-template-columns: auto 1fr; gap: 0 6px; align-items: baseline;
    padding: 4px 6px; border-radius: 4px; border-left: 3px solid rgba(160, 175, 190, .35);
    background: rgba(255, 255, 255, .03);
  }
  .tg-row b { font-size: 10px; letter-spacing: .06em; color: #e6f2f5; }
  .tg-row span { font-size: 10.5px; color: rgba(214, 238, 245, .78); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .tg-row em { grid-column: 1 / -1; font-style: normal; font-size: 9px; letter-spacing: .06em; color: rgba(160, 190, 200, .7); }
  .tg-row.tg-running { border-left-color: #38e0ff; background: rgba(56, 224, 255, .08); }
  .tg-row.tg-completed { border-left-color: #4ade9e; }
  .tg-row.tg-failed, .tg-row.tg-timed_out { border-left-color: #ff6b6b; }
  .tg-row.tg-pending, .tg-row.tg-blocked, .tg-row.tg-queued, .tg-row.tg-ready { opacity: .72; }
  .cc-districts { display: flex; flex-wrap: wrap; gap: 4px; margin-left: 12px; }
  .cc-districts button {
    all: unset; cursor: pointer; font-size: 9px; letter-spacing: .08em; padding: 2px 6px; border-radius: 4px;
    color: var(--c); border: 1px solid color-mix(in srgb, var(--c) 45%, transparent);
    background: color-mix(in srgb, var(--c) 10%, transparent);
  }
  .cc-districts button b { color: #f1f7ff; margin-left: 3px; }
  /* `all: unset` also removes the focus ring -- put a visible one back. */
  .cc-toggle:focus-visible, .cc-tier:focus-visible, .cc-districts button:focus-visible {
    outline: 2px solid #ffd166; outline-offset: 2px;
  }

  .city-agent-panel { max-width: 300px !important; width: 300px; border-color: var(--cat) !important; box-shadow: 0 0 22px color-mix(in srgb, var(--cat) 22%, transparent); }
  .city-agent-panel h3 { color: var(--cat) !important; }
  .cap-role { margin: -2px 0 6px !important; font-size: 10.5px !important; letter-spacing: .1em; text-transform: uppercase; color: rgba(214, 238, 245, .6) !important; }
  .cfp-wide { grid-column: 1 / -1; }
  .cfp-cat.st-busy { color: #38e0ff; } .cfp-cat.st-thinking { color: #b9a4ff; }
  .cfp-cat.st-queued { color: #ffb244; } .cfp-cat.st-ok { color: #4ade9e; }
  .cfp-cat.st-critical { color: #ff6b6b; } .cfp-cat.st-off { color: #8a97a6; }
  .cfp-cat.st-idle { color: rgba(170, 200, 215, .9); }

  .city-nav { position: absolute; top: 10px; left: 10px; display: flex; flex-direction: column; gap: 6px; }
  .city-nav .city-cam { position: static; }
  .city-cam-places button { border-color: rgba(149, 120, 255, .35); color: rgba(214, 226, 255, .8); }
  .city-cam-places button:hover { border-color: rgba(149, 120, 255, .7); color: #c9baff; }
  /* Bottom centre: the corners belong to the chain of command (left) and the
     detail panels (right). Wraps rather than running under either. */
  .city-pad {
    position: absolute; left: 50%; bottom: 10px; transform: translateX(-50%);
    max-width: calc(100% - 540px); min-width: 300px;
    display: flex; flex-wrap: wrap; justify-content: center; align-items: center; gap: 4px;
    padding: 6px 8px; border-radius: 9px;
    background: rgba(12, 8, 30, .82); border: 1px solid rgba(157, 120, 255, .38);
    box-shadow: 0 0 18px rgba(149, 120, 255, .18), 0 6px 18px rgba(0, 0, 0, .4);
    backdrop-filter: blur(4px);
  }
  .pad-help {
    flex-basis: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; margin-bottom: 2px;
    font-size: 9.5px; letter-spacing: .05em; color: rgba(214, 206, 245, .72); white-space: nowrap;
  }
  .pad-cap { margin: 0 1px 0 6px; font-size: 8.5px; font-weight: 700; letter-spacing: .14em; color: rgba(190, 176, 245, .7); }
  .pad-cap:first-of-type { margin-left: 0; }
  .city-pad button {
    min-width: 26px; height: 26px; padding: 0 6px; border-radius: 6px; cursor: pointer;
    background: rgba(40, 26, 84, .7); border: 1px solid rgba(157, 120, 255, .45);
    color: #e4dcff; font-size: 13px; font-weight: 700; line-height: 1;
    touch-action: none; user-select: none;
  }
  .city-pad button:hover { border-color: #b9a4ff; background: rgba(90, 60, 180, .55); box-shadow: 0 0 10px rgba(185, 164, 255, .45); }
  .city-pad button:active { background: rgba(127, 239, 255, .22); border-color: #7fefff; }
  .city-pad button:focus-visible { outline: 2px solid #7fefff; outline-offset: 1px; }
  .city-pad .pad-home { margin-left: 6px; color: #ffe29a; border-color: rgba(255, 209, 102, .5); }
  .city-pad .pad-drag { height: 20px; white-space: nowrap; font-size: 9px; letter-spacing: .1em; color: #9deaff; border-color: rgba(56, 224, 255, .5); }
  .city-follow {
    position: absolute; left: 50%; transform: translateX(-50%); top: 10px;
    display: flex; align-items: center; gap: 8px; padding: 6px 12px;
    background: rgba(6, 16, 20, .88); border: 1px solid rgba(56, 224, 255, .45); border-radius: 6px;
  }
  .city-follow span { font-size: 9px; letter-spacing: .12em; color: rgba(160, 190, 200, .7); }
  .city-follow b { font-size: 11.5px; letter-spacing: .06em; color: #9deaff; }
  .city-follow button {
    background: none; border: 1px solid rgba(255, 178, 68, .45); color: #ffcf85;
    border-radius: 4px; padding: 2px 8px; font-size: 9.5px; font-weight: 700; cursor: pointer;
  }

  .cfp-head { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
  .cfp-cat {
    font-size: 9px; letter-spacing: .12em; font-weight: 700;
    color: var(--cat, #9deaff); border: 1px solid currentColor; border-radius: 3px; padding: 1px 5px;
  }
  .cfp-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 4px 10px; margin: 0 0 8px; }
  .cfp-meta span { display: block; font-size: 9px; letter-spacing: .1em; color: rgba(160, 190, 200, .65); }
  .cfp-meta b { font-size: 11.5px; color: #e6f2f5; }
  .cfp-agents { margin: 0 0 8px; display: flex; flex-wrap: wrap; gap: 4px; }
  .cfp-agents > span { flex: 1 0 100%; font-size: 9px; letter-spacing: .12em; color: rgba(160, 190, 200, .65); }
  .cfp-agent {
    background: rgba(56, 224, 255, .08); border: 1px solid rgba(56, 224, 255, .28);
    color: #9deaff; border-radius: 4px; padding: 2px 7px; font-size: 9.5px;
    font-weight: 700; letter-spacing: .05em; cursor: pointer;
  }
  .cfp-agent:hover { background: rgba(56, 224, 255, .2); }
  .cfp-actions { display: flex; gap: 6px; flex-wrap: wrap; }
  .cfp-actions button { flex: 1 1 auto; }

  .city-cam { position: absolute; top: 10px; left: 10px; display: flex; gap: 6px; }
  .city-cam button { background: rgba(6, 16, 20, .82); border: 1px solid rgba(56, 224, 255, .3); color: rgba(214, 238, 245, .75); border-radius: 5px; padding: 5px 10px; font-size: 10.5px; font-weight: 700; letter-spacing: .1em; cursor: pointer; }
  .city-cam button:not(:disabled):hover { border-color: rgba(56, 224, 255, .6); color: #9deaff; }
  .city-cam button.active { background: rgba(56, 224, 255, .18); border-color: rgba(56, 224, 255, .75); color: #9deaff; }
  .city-cam button:disabled { opacity: .55; cursor: default; }

  .city-focus-panel {
    /* top 46px: the CEO inbox button owns the top-right corner. */
    position: absolute; right: 10px; top: 46px; max-width: 230px;
    max-height: calc(100% - 58px); overflow-y: auto;
    background: rgba(6, 14, 18, .78); border: 1px solid rgba(56, 224, 255, .3);
    border-radius: 7px; padding: 10px 12px; backdrop-filter: blur(3px);
  }
  .city-focus-panel h3 { margin: 0 0 4px; font-size: 13px; letter-spacing: .04em; color: #e6f2f5; }
  .city-focus-panel p { margin: 0 0 8px; font-size: 11.5px; line-height: 1.4; color: rgba(214, 238, 245, .78); }
  .city-focus-panel button { background: rgba(56, 224, 255, .1); border: 1px solid rgba(56, 224, 255, .4); color: #9deaff; border-radius: 5px; padding: 6px 10px; font-size: 10.5px; font-weight: 700; letter-spacing: .08em; cursor: pointer; }
  .city-focus-panel button:hover { background: rgba(56, 224, 255, .2); }

  .city-focus-live { margin: -2px 0 10px; padding: 7px 9px; border-radius: 6px; background: rgba(56, 224, 255, .08); border: 1px solid rgba(56, 224, 255, .25); display: grid; gap: 2px; }
  .city-focus-live b { font-size: 11px; letter-spacing: .08em; color: #9deaff; }
  .city-focus-live span { font-size: 10.5px; color: rgba(214, 238, 245, .7); line-height: 1.4; }
  .city-focus-live.attention { background: rgba(255, 178, 68, .1); border-color: rgba(255, 178, 68, .35); }
  .city-focus-live.attention b { color: #ffb244; }
  .city-focus-live.critical { background: rgba(255, 74, 74, .1); border-color: rgba(255, 74, 74, .4); }
  .city-focus-live.critical b { color: #ff6b6b; }
  .city-focus-live.offline { background: rgba(74, 85, 96, .12); border-color: rgba(74, 85, 96, .4); }
  .city-focus-live.offline b { color: #8a97a0; }

  .city-hover {
    position: absolute; pointer-events: none; max-width: 240px;
    background: rgba(4, 10, 12, .92); border: 1px solid rgba(56, 224, 255, .3);
    border-radius: 6px; padding: 8px 10px; display: grid; gap: 3px;
  }
  .city-hover b { font-size: 12px; letter-spacing: .06em; color: #9deaff; }
  .city-hover span { font-size: 11px; color: rgba(214, 238, 245, .75); line-height: 1.4; }
  .city-hover em { font-size: 10px; font-style: normal; letter-spacing: .07em; color: #7de6ff; }

  .city-cam-back { margin-left: 4px; border-color: rgba(255, 178, 68, .4) !important; color: #ffcf85 !important; }
  .city-cam-back:hover { border-color: rgba(255, 178, 68, .7) !important; background: rgba(255, 178, 68, .12) !important; }

  /* CITY-3: Agent HQ overlay panels -- compact, bounded, never covering most
     of the 3D view. Reuses the global .status/.rail-note classes
     the rest of the app already relies on (styles/type.css, ux.css). */
  .hq-ops-panel, .hq-detail-panel {
    position: absolute; max-width: 300px;
    background: rgba(6, 16, 20, .9); border: 1px solid rgba(56, 224, 255, .35);
    border-radius: 8px; padding: 12px 14px; backdrop-filter: blur(2px);
  }
  .hq-ops-panel { left: 10px; bottom: 10px; }
  .hq-detail-panel { right: 10px; top: 46px; }
  .hq-ops-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 6px; }
  .hq-ops-head h3 { margin: 0; font-size: 13.5px; letter-spacing: .05em; color: #e6f2f5; }
  .hq-cancel-btn { margin-left: auto; background: rgba(255, 92, 92, .12); border: 1px solid rgba(255, 92, 92, .5); color: #ff8f8f; border-radius: 5px; padding: 4px 10px; font-size: 10px; font-weight: 700; letter-spacing: .08em; cursor: pointer; }
  .hq-cancel-btn:hover:not(:disabled) { background: rgba(255, 92, 92, .22); }
  .hq-cancel-btn:disabled { opacity: .5; cursor: default; }
  .hq-ops-mission { margin: 0 0 8px; font-size: 12px; line-height: 1.4; color: rgba(214, 238, 245, .85); }
  .hq-ops-mission span, .hq-ops-roles span { display: block; font-size: 9.5px; letter-spacing: .12em; color: rgba(160, 190, 200, .65); margin-bottom: 2px; }
  .hq-ops-roles { margin: 0 0 4px; font-size: 11.5px; color: rgba(214, 238, 245, .85); }
  .hq-ops-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 6px 14px; margin-bottom: 6px; }
  .hq-ops-grid span { display: block; font-size: 9px; letter-spacing: .1em; color: rgba(160, 190, 200, .65); }
  .hq-ops-grid b { font-size: 12px; font-weight: 600; color: var(--text-strong, #e6f2f5); }

  .status.critical { color: #ff5c5c; }
  .st-idle { color: rgba(140, 190, 205, .8); } .st-thinking { color: #a78bfa; }
  .st-busy { color: #38e0ff; } .st-queued { color: #ffb244; }
  .st-ok { color: #4ade9e; } .st-critical { color: #ff5c5c; }

  @media (max-width: 1000px) {
    .city-pad { max-width: calc(100% - 20px); min-width: 0; }
    .pad-help span, .pad-cap { display: none; }
  }
  @media (max-width: 700px) {
    .city-container { height: 420px; }
    .city-focus-panel { max-width: 200px; font-size: 11px; }
    .city-agent-panel { width: auto; max-width: calc(100% - 20px) !important; }
    .city-command { width: 196px; }
    .hq-ops-panel, .hq-detail-panel { max-width: 220px; font-size: 11px; padding: 10px 12px; }
    .hq-ops-grid { grid-template-columns: 1fr; }
  }
</style>
