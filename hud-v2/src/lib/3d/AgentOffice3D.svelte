<script lang="ts">

  import { onMount } from 'svelte';
  import { agentOffice, selectAgent } from '../../stores/agentOffice';
  import { teamOffice, selectTeamEntity } from '../../stores/teamOffice';
  import { security } from '../../stores/security';
  import * as THREE from 'three';
  import { GLTFLoader } from 'three/examples/jsm/loaders/GLTFLoader.js';
  import { gsap } from 'gsap';
  import type { DynamicAgentView, TeamDetail } from '../../types/argus';

  // The 10 CORE stations -- same roster agents/definitions.py registers and
  // AgentOffice.svelte / AgentTown.svelte already use. A team's PLANNER/
  // VERIFIER/etc roles are these same core agents at work, not a second set.
  const ALL_AGENTS = ['security', 'threat', 'assistant', 'system', 'network', 'verifier',
                      'planner', 'diagnostics', 'forensics', 'response'] as const;

  // Workstations arranged around the ops center perimeter. The four slots
  // that used to hold placeholder analyst/observer/monitor agents now carry
  // real core roles (planner/diagnostics/forensics/response) at the same
  // physical positions -- no prop layout changed, only who sits there.
  const STATION_POSITIONS: Record<string, [number, number, number]> = {
    security: [-18, 0.5, 12],
    threat: [18, 0.5, 12],
    assistant: [-18, 0.5, -8],
    system: [18, 0.5, -8],
    network: [-8, 0.5, 20],
    verifier: [8, 0.5, 20],
    planner: [-12, 0.5, -18],
    diagnostics: [12, 0.5, -18],
    forensics: [-24, 0.5, 0],
    response: [24, 0.5, 0],
  };

  const STATION_LABELS: Record<string, string> = {
    security: 'SECURITY', threat: 'THREAT', assistant: 'ASSISTANT',
    system: 'SYSTEM', network: 'NETWORK', verifier: 'VERIFIER',
    planner: 'PLANNER', diagnostics: 'DIAGNOSTICS', forensics: 'FORENSICS',
    response: 'RESPONSE',
  };

  const AGENT_COLORS: Record<string, number> = {
    security: 0x00c8ff, threat: 0xff8c00, assistant: 0x00a8ff,
    system: 0x00b4d8, network: 0x00d4b8, verifier: 0x00c9a7,
    planner: 0xf472b6, diagnostics: 0x6ee7b7, forensics: 0xfbbf24, response: 0xa78bfa,
  };

  const STATE_COLORS: Record<string, number> = {
    idle: 0x2e6d78, queued: 0xf59e0b, preparing: 0x00d4ff,
    thinking: 0x8b5cf6, responding: 0x00d4ff, waiting_auth: 0xf59e0b,
    executing: 0x10b981, verifying: 0x14b8a6, completed: 0x10b981,
    warning: 0xf59e0b, blocked: 0xef4444, error: 0xef4444, disabled: 0x1e293b,
    // Dynamic (temp local/cloud) agent vocabulary -- agents/dynamic_spec.py
    // AgentStatus, lowercased. Distinct enum from the core OfficeAgent one
    // above; mapped onto the same color buckets rather than a second table.
    proposed: 0xf59e0b, validating: 0xf59e0b, approved: 0xf59e0b,
    active: 0x10b981, waiting: 0xf59e0b, failed: 0xef4444,
    expired: 0x1e293b, destroyed: 0x1e293b,
  };
  const CRITICAL_COLOR = 0xff3b3b;
  const CRITICAL_ROLES = new Set(['security', 'threat', 'response', 'verifier']);

  // Temp / cloud specialist area -- a small fixed grid, north wall. Slots
  // activate only when a real dynamic agent occupies them; nothing is
  // pre-built as "dozens of empty desks".
  const TEMP_SLOTS = 6;
  const TEMP_SLOT_POSITIONS: [number, number, number][] = Array.from({ length: TEMP_SLOTS }, (_, i) => {
    const col = i % 3, row = Math.floor(i / 3);
    return [-9 + col * 9, 0.5, -24 - row * 4.5];
  });

  const ORIGIN_LABEL: Record<string, string> = {
    EPHEMERAL_LOCAL: 'LOCAL', EPHEMERAL_CLOUD: 'CLOUD', CORE: 'LOCAL',
  };
  const ORIGIN_COLOR: Record<string, number> = {
    EPHEMERAL_LOCAL: 0x38e0ff, EPHEMERAL_CLOUD: 0xf59e0b, CORE: 0x38e0ff,
  };

  type CameraMode = 'overview' | 'selected' | 'team' | 'security';

  interface Agent {
    role: string;
    mesh: THREE.Group;
    currentState: string;
    position: THREE.Vector3;
    targetPosition: THREE.Vector3;
    isWalking: boolean;
    walkSpeed: number;
    stateIndicator: THREE.Mesh;
    stateLabel: THREE.Sprite;
    verifierGlow?: THREE.PointLight;
  }
  interface TempAgent {
    mesh: THREE.Group;
    stateIndicator: THREE.Mesh;
    stateLabel: THREE.Sprite;
    originLabel: THREE.Sprite;
    position: THREE.Vector3;
  }

  let container: HTMLDivElement;
  let renderer: THREE.WebGLRenderer | null = null;
  let scene: THREE.Scene;
  let camera: THREE.PerspectiveCamera;
  let raycaster: THREE.Raycaster;
  let mouse: THREE.Vector2;
  let agents: Map<string, Agent> = new Map();
  let tempAgents: Map<string, TempAgent> = new Map();
  let teamLines: THREE.Line[] = [];
  let core: THREE.Group;
  let animationFrameId = 0;
  let lastSignature = '';
  let lastTempSignature = '';
  let lastTeamSignature = '';
  let resizeObserver: ResizeObserver | null = null;
  let clock: THREE.Clock;
  let disconnectedBadge: THREE.Sprite | null = null;

  let lastRenderTime = 0;
  const RENDER_INTERVAL = 33; // ~30fps cap (4GB VRAM class hardware)

  let cameraMode: CameraMode = 'overview';
  let cameraTarget = new THREE.Vector3(0, 1, 0);
  let cameraDest = new THREE.Vector3(35, 25, 40);

  const gltfLoader = new GLTFLoader();

  /* ---- Asset Loading ---- */

  async function loadGLTF(path: string, name: string): Promise<THREE.Group | null> {
    return new Promise((resolve) => {
      gltfLoader.load(
        path,
        (gltf) => {
          console.log(`✓ ${name}`);
          resolve(gltf.scene);
        },
        undefined,
        () => {
          console.warn(`✗ ${name}`);
          resolve(null);
        }
      );
    });
  }

  /* ---- Scene Construction ---- */

  async function initThree(): Promise<boolean> {
    if (!container) return false;

    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x000000);
    scene.fog = new THREE.Fog(0x000000, 80, 120);
    clock = new THREE.Clock();

    // Isometric-style camera for ops center view
    camera = new THREE.PerspectiveCamera(45, Math.max(1, container.clientWidth) / Math.max(1, container.clientHeight), 0.1, 300);
    camera.position.set(35, 25, 40);
    camera.lookAt(0, 1, 0);

    // === LIGHTING SETUP - Sci-Fi Operations Center ===

    // Base ambient for overall visibility
    const ambientLight = new THREE.AmbientLight(0xffffff, 1.2);
    scene.add(ambientLight);

    // Primary key light - white/cyan from above
    const keyLight1 = new THREE.DirectionalLight(0xffffff, 1.5);
    keyLight1.position.set(25, 35, 25);
    scene.add(keyLight1);

    // Secondary key light - from opposite side
    const keyLight2 = new THREE.DirectionalLight(0xffffff, 1.3);
    keyLight2.position.set(-25, 30, -25);
    scene.add(keyLight2);

    // Cyan fill light - sci-fi aesthetic
    const fillLight = new THREE.DirectionalLight(0x00d4ff, 0.8);
    fillLight.position.set(-30, 20, 10);
    scene.add(fillLight);

    // Blue point light - left side glow
    const blueLight = new THREE.PointLight(0x00d4ff, 1.2, 50);
    blueLight.position.set(-20, 10, -15);
    scene.add(blueLight);

    // Amber/orange accent light - right side
    const amberLight = new THREE.PointLight(0xff8c00, 1.0, 45);
    amberLight.position.set(20, 12, 15);
    scene.add(amberLight);

    // Cyan accent light - back for depth
    const cyanAccent = new THREE.PointLight(0x00ffaa, 0.9, 40);
    cyanAccent.position.set(0, 8, 25);
    scene.add(cyanAccent);

    raycaster = new THREE.Raycaster();
    mouse = new THREE.Vector2();

    console.log('[ARGUS 3D] Loading complete sci-fi ops center environment...');
    await loadCompleteEnvironment();
    createCore();
    createAllAgents();

    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.25));
    renderer.setSize(Math.max(1, container.clientWidth), Math.max(1, container.clientHeight));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.shadowMap.enabled = false;
    container.appendChild(renderer.domElement);

    console.log(`[ARGUS 3D] Scene ready with ${agents.size} agents`);

    return true;
  }

  async function loadCompleteEnvironment(): Promise<void> {
    // A hardcoded leading-slash path ignores vite.config.ts's base:'/v2/' --
    // fine in dev (BASE_URL is '/'), 404 in the real build main.py serves
    // under /v2/, which every GLB request was silently doing (all 65 of
    // them, not just the few whose ✗ warning happened to still be on screen).
    const basePath = `${import.meta.env.BASE_URL}assets/3d/environment/Models/GLB format`;

    console.log('[3D] Loading complete sci-fi ops center environment...');

    // === FLOOR BASE ===
    const floorBase = new THREE.Mesh(
      new THREE.PlaneGeometry(60, 60),
      new THREE.MeshStandardMaterial({
        color: 0x0a0d12,
        metalness: 0.5,
        roughness: 0.55,
        emissive: 0x0f1419,
        emissiveIntensity: 0.2
      })
    );
    floorBase.rotation.x = -Math.PI / 2;
    scene.add(floorBase);

    // === ANIMATED GRID ===
    const grid = new THREE.GridHelper(60, 20, 0x00d4ff, 0x001a2e);
    grid.position.y = 0.01;
    (grid.material as THREE.LineBasicMaterial).linewidth = 1;
    scene.add(grid);

    // === CORE ROOM STRUCTURE ===
    // Central room-large as the main ops center
    const mainRoom = await loadGLTF(`${basePath}/room-large.glb`, 'Main Room');
    if (mainRoom) {
      mainRoom.scale.set(1.2, 1.2, 1.2);
      mainRoom.position.set(0, 0, 0);
      scene.add(mainRoom);
    }

    // === FLOOR DETAILS ===
    const floorDetailA = await loadGLTF(`${basePath}/template-floor-detail-a.glb`, 'Floor Detail A');
    if (floorDetailA) {
      floorDetailA.scale.set(0.8, 1, 0.8);
      floorDetailA.position.set(0, 0.05, 0);
      scene.add(floorDetailA);
    }

    const floorLayer = await loadGLTF(`${basePath}/template-floor-layer.glb`, 'Floor Layer');
    if (floorLayer) {
      floorLayer.scale.set(1, 1, 1);
      floorLayer.position.set(0, 0.1, 0);
      scene.add(floorLayer);
    }

    // === WALLS & CORNERS ===
    const wallPositions = [
      { pos: [-28, 0, 0], rot: 0, asset: 'template-wall' },
      { pos: [28, 0, 0], rot: Math.PI, asset: 'template-wall' },
      { pos: [0, 0, -28], rot: Math.PI / 2, asset: 'template-wall' },
      { pos: [0, 0, 28], rot: -Math.PI / 2, asset: 'template-wall' },
    ];

    for (const { pos, rot, asset } of wallPositions) {
      const wall = await loadGLTF(`${basePath}/${asset}.glb`, `Wall`);
      if (wall) {
        wall.scale.set(0.9, 0.9, 0.9);
        wall.rotation.y = rot;
        wall.position.set(...(pos as [number, number, number]));
        scene.add(wall);
      }
    }

    // === WALL CORNERS ===
    const cornerPositions: [number, number, number][] = [
      [-28, 0, -28],
      [28, 0, -28],
      [-28, 0, 28],
      [28, 0, 28],
    ];

    for (const pos of cornerPositions) {
      const corner = await loadGLTF(`${basePath}/template-wall-corner.glb`, 'Corner');
      if (corner) {
        corner.scale.set(0.9, 0.9, 0.9);
        corner.position.set(...pos);
        scene.add(corner);
      }
    }

    // === WORKSTATIONS - Computers & Chairs at each agent position ===
    for (const role of ALL_AGENTS) {
      const [x, y, z] = STATION_POSITIONS[role];

      // Computer station
      const computer = await loadGLTF(`${basePath}/computer.glb`, `Computer-${role}`);
      if (computer) {
        computer.scale.set(0.8, 0.8, 0.8);
        computer.position.set(x, y + 0.5, z);
        scene.add(computer);
      }

      // Chair
      const chair = await loadGLTF(`${basePath}/chair-cushion.glb`, `Chair-${role}`);
      if (chair) {
        chair.scale.set(0.7, 0.7, 0.7);
        chair.position.set(x, y, z + 1.5);
        scene.add(chair);
      }
    }

    // === DISPLAY WALLS ===
    const displayWallLeft = await loadGLTF(`${basePath}/display-wall-wide.glb`, 'Display Wall Left');
    if (displayWallLeft) {
      displayWallLeft.scale.set(0.8, 1, 0.8);
      displayWallLeft.position.set(-25, 1, -26);
      scene.add(displayWallLeft);
    }

    const displayWallRight = await loadGLTF(`${basePath}/display-wall-wide.glb`, 'Display Wall Right');
    if (displayWallRight) {
      displayWallRight.scale.set(0.8, 1, 0.8);
      displayWallRight.position.set(25, 1, -26);
      scene.add(displayWallRight);
    }

    // === DOORS ===
    const doorLeft = await loadGLTF(`${basePath}/door-double.glb`, 'Door Left');
    if (doorLeft) {
      doorLeft.scale.set(0.7, 0.7, 0.7);
      doorLeft.position.set(-26, 0, 26);
      doorLeft.rotation.y = Math.PI / 2;
      scene.add(doorLeft);
    }

    const doorRight = await loadGLTF(`${basePath}/door-double.glb`, 'Door Right');
    if (doorRight) {
      doorRight.scale.set(0.7, 0.7, 0.7);
      doorRight.position.set(26, 0, 26);
      doorRight.rotation.y = Math.PI / 2;
      scene.add(doorRight);
    }

    // === ATMOSPHERIC CABLES & PIPES ===
    const cables = await loadGLTF(`${basePath}/cables.glb`, 'Cables');
    if (cables) {
      cables.scale.set(1, 1, 1);
      cables.position.set(0, 0.5, -20);
      scene.add(cables);
    }

    // Pipe network
    const pipeA = await loadGLTF(`${basePath}/pipe.glb`, 'Pipe A');
    if (pipeA) {
      pipeA.scale.set(0.6, 0.6, 0.6);
      pipeA.position.set(-24, 2, 10);
      scene.add(pipeA);
    }

    const pipeB = await loadGLTF(`${basePath}/pipe.glb`, 'Pipe B');
    if (pipeB) {
      pipeB.scale.set(0.6, 0.6, 0.6);
      pipeB.position.set(24, 2, 10);
      scene.add(pipeB);
    }

    // === CONTAINERS - Accent pieces ===
    const containerA = await loadGLTF(`${basePath}/container-wide.glb`, 'Container A');
    if (containerA) {
      containerA.scale.set(0.6, 0.6, 0.6);
      containerA.position.set(-18, 0, -24);
      scene.add(containerA);
    }

    const containerB = await loadGLTF(`${basePath}/container.glb`, 'Container B');
    if (containerB) {
      containerB.scale.set(0.6, 0.6, 0.6);
      containerB.position.set(18, 0, -24);
      scene.add(containerB);
    }

    // === GATES & ATMOSPHERIC PROPS ===
    const gate = await loadGLTF(`${basePath}/gate.glb`, 'Gate');
    if (gate) {
      gate.scale.set(0.7, 0.7, 0.7);
      gate.position.set(0, 0, -20);
      scene.add(gate);
    }

    // Laser gate accent
    const laserGate = await loadGLTF(`${basePath}/gate-lasers.glb`, 'Laser Gate');
    if (laserGate) {
      laserGate.scale.set(0.5, 0.5, 0.5);
      laserGate.position.set(0, 1, -18);
      scene.add(laserGate);
    }

    // === FLOOR PANELS & DETAILS ===
    const floorPanelPositions: [number, number, number][] = [
      [-15, 0, 15],
      [15, 0, 15],
      [-15, 0, -10],
      [15, 0, -10],
    ];

    for (const pos of floorPanelPositions) {
      const panel = await loadGLTF(`${basePath}/floor-panel.glb`, 'Floor Panel');
      if (panel) {
        panel.scale.set(0.5, 0.5, 0.5);
        panel.position.set(...pos);
        scene.add(panel);
      }
    }

    console.log('[3D] ✓ Complete ops center environment loaded');
  }

  function buildHumanoid(color: number): { group: THREE.Group; parts: THREE.Mesh[] } {
    const group = new THREE.Group();
    const parts: THREE.Mesh[] = [];

    const head = new THREE.Mesh(
      new THREE.SphereGeometry(0.35, 16, 16),
      new THREE.MeshStandardMaterial({ color, emissive: color, emissiveIntensity: 0.5 })
    );
    head.position.y = 1.6;
    group.add(head); parts.push(head);

    const body = new THREE.Mesh(
      new THREE.CylinderGeometry(0.3, 0.3, 0.9, 8),
      new THREE.MeshStandardMaterial({ color, emissive: color, emissiveIntensity: 0.3 })
    );
    body.position.y = 1.0;
    group.add(body); parts.push(body);

    const leftArm = new THREE.Mesh(
      new THREE.CylinderGeometry(0.12, 0.12, 0.9, 6),
      new THREE.MeshStandardMaterial({ color: 0x1a2a35 })
    );
    leftArm.position.set(-0.4, 1.1, 0);
    leftArm.rotation.z = Math.PI / 4;
    group.add(leftArm); parts.push(leftArm);

    const rightArm = leftArm.clone();
    rightArm.position.x = 0.4;
    rightArm.rotation.z = -Math.PI / 4;
    group.add(rightArm); parts.push(rightArm);

    const leftLeg = new THREE.Mesh(
      new THREE.CylinderGeometry(0.14, 0.14, 0.8, 6),
      new THREE.MeshStandardMaterial({ color: 0x0a1114 })
    );
    leftLeg.position.set(-0.15, 0.4, 0);
    group.add(leftLeg); parts.push(leftLeg);

    const rightLeg = leftLeg.clone();
    rightLeg.position.x = 0.15;
    group.add(rightLeg); parts.push(rightLeg);

    return { group, parts };
  }

  function createAllAgents(): void {
    ALL_AGENTS.forEach((role) => {
      const pos = STATION_POSITIONS[role];
      const color = AGENT_COLORS[role] || 0x00ffff;
      const { group: agentGroup } = buildHumanoid(color);

      agentGroup.position.set(...pos);
      scene.add(agentGroup);

      // State indicator
      const indicator = new THREE.Mesh(
        new THREE.SphereGeometry(0.25, 12, 12),
        new THREE.MeshStandardMaterial({
          color,
          emissive: color,
          emissiveIntensity: 0.9
        })
      );
      indicator.position.y = 2.4;
      agentGroup.add(indicator);

      // State label
      const stateLabel = createLabel('IDLE', 12, false, true);
      stateLabel.position.y = 2.0;
      agentGroup.add(stateLabel);

      // Role label so a viewer can identify a station without selecting it.
      const roleLabel = createLabel(STATION_LABELS[role], 13, true);
      roleLabel.position.y = 2.85;
      agentGroup.add(roleLabel);

      const agent: Agent = {
        role,
        mesh: agentGroup,
        currentState: 'idle',
        position: new THREE.Vector3(...pos),
        targetPosition: new THREE.Vector3(...pos),
        isWalking: false,
        walkSpeed: 3.5,
        stateIndicator: indicator,
        stateLabel,
      };

      if (role === 'verifier') {
        const glow = new THREE.PointLight(color, 0, 8);
        glow.position.set(0, 2, 0);
        agentGroup.add(glow);
        agent.verifierGlow = glow;
      }

      agents.set(role, agent);
    });
  }

  /* ---- Temp / cloud specialist area ----------------------
     Slots activate only for a real live dynamic agent; a destroyed/expired
     agent's slot is disposed cleanly, never left as a zombie station. */

  function spawnTempAgent(id: string, slotIndex: number, a: DynamicAgentView): void {
    const pos = TEMP_SLOT_POSITIONS[slotIndex % TEMP_SLOTS];
    const color = ORIGIN_COLOR[a.type] ?? 0x94a3b8;
    const { group } = buildHumanoid(color);
    group.position.set(pos[0], pos[1], pos[2]);
    group.scale.set(0.001, 0.001, 0.001); // restrained spawn: scale-in, no cinematic sequence
    scene.add(group);

    const podBase = new THREE.Mesh(
      new THREE.CylinderGeometry(0.6, 0.7, 0.15, 8),
      new THREE.MeshStandardMaterial({ color: 0x0d151a, metalness: 0.7, roughness: 0.4, emissive: color, emissiveIntensity: 0.25 })
    );
    podBase.position.y = 0.05;
    group.add(podBase);

    const indicator = new THREE.Mesh(
      new THREE.SphereGeometry(0.22, 12, 12),
      new THREE.MeshStandardMaterial({ color, emissive: color, emissiveIntensity: 0.9 })
    );
    indicator.position.y = 2.3;
    group.add(indicator);

    const stateLabel = createLabel(a.state.toUpperCase(), 12, false, true);
    stateLabel.position.y = 1.95;
    group.add(stateLabel);

    // Small worker-origin tag -- "INTELLIGENCE WORKER", never implies
    // machine authority.
    const originLabel = createLabel(ORIGIN_LABEL[a.type] ?? 'LOCAL', 11, false);
    originLabel.position.y = 2.6;
    group.add(originLabel);

    gsap.to(group.scale, { x: 1, y: 1, z: 1, duration: 0.45, ease: 'back.out(1.6)' });

    tempAgents.set(id, { mesh: group, stateIndicator: indicator, stateLabel, originLabel, position: new THREE.Vector3(...pos) });
  }

  function disposeGroup(group: THREE.Group): void {
    group.traverse((obj) => {
      const mesh = obj as THREE.Mesh;
      if (mesh.geometry) mesh.geometry.dispose();
      const mat = (mesh as unknown as { material?: THREE.Material | THREE.Material[] }).material;
      if (Array.isArray(mat)) mat.forEach((m) => disposeMaterial(m));
      else if (mat) disposeMaterial(mat);
    });
  }
  function disposeMaterial(mat: THREE.Material): void {
    const withMap = mat as THREE.Material & { map?: THREE.Texture | null };
    withMap.map?.dispose();
    mat.dispose();
  }

  function destroyTempAgent(id: string): void {
    const t = tempAgents.get(id);
    if (!t) return;
    gsap.killTweensOf(t.mesh.scale);
    gsap.to(t.mesh.scale, {
      x: 0.001, y: 0.001, z: 0.001, duration: 0.3, ease: 'power1.in',
      onComplete: () => { scene.remove(t.mesh); disposeGroup(t.mesh); },
    });
    tempAgents.delete(id);
  }

  function applyDynamicAgents(list: DynamicAgentView[]): void {
    if (!renderer) return;
    const signature = list.map((a) => `${a.id}:${a.state}:${a.type}`).sort().join('|');
    if (signature === lastTempSignature) return;
    lastTempSignature = signature;

    const liveIds = new Set(list.map((a) => a.id));
    for (const id of Array.from(tempAgents.keys())) if (!liveIds.has(id)) destroyTempAgent(id);

    list.slice(0, TEMP_SLOTS).forEach((a, i) => {
      const existing = tempAgents.get(a.id);
      if (!existing) { spawnTempAgent(a.id, i, a); return; }
      const color = new THREE.Color(STATE_COLORS[a.state.toLowerCase()] ?? ORIGIN_COLOR[a.type] ?? 0x94a3b8);
      gsap.to(existing.stateIndicator.material, { emissive: color, duration: 0.4, overwrite: true });
      redrawLabel(existing.stateLabel, a.state.toUpperCase());
    });
  }

  /* ---- Team connection lines ---------------------------------
     PLANNER -> core members -> their temp children, verifier drawn last.
     Rebuilt only when the active team's shape actually changes. */

  function clearTeamLines(): void {
    for (const line of teamLines) {
      scene.remove(line);
      line.geometry.dispose();
      (line.material as THREE.Material).dispose();
    }
    teamLines = [];
  }

  function lineBetween(a: THREE.Vector3, b: THREE.Vector3, color: number): THREE.Line {
    const geometry = new THREE.BufferGeometry().setFromPoints([
      new THREE.Vector3(a.x, a.y + 2, a.z), new THREE.Vector3(b.x, b.y + 1.6, b.z),
    ]);
    const material = new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.55 });
    const line = new THREE.Line(geometry, material);
    scene.add(line);
    return line;
  }

  function applyActiveTeam(team: TeamDetail | null): void {
    const signature = team ? `${team.team_id}:${team.state}:${team.members.map((m) => `${m.member_id}:${m.state}`).join(',')}` : '';
    if (signature === lastTeamSignature) return;
    lastTeamSignature = signature;
    clearTeamLines();
    if (!team || !core) return;

    const corePos = new THREE.Vector3(0, 0, 0);
    const involvedCore = new Set(team.members.filter((m) => m.kind === 'core').map((m) => m.role));
    for (const role of involvedCore) {
      const station = agents.get(role);
      if (!station) continue;
      const color = role === 'verifier' && team.state === 'VERIFYING' ? 0x14b8a6 : 0x38e0ff;
      teamLines.push(lineBetween(corePos, station.position, color));
    }
    // Temp/cloud children connect from their parent core station.
    for (const member of team.members) {
      if (member.kind !== 'temp') continue;
      const parentStation = agents.get(member.parent);
      const temp = tempAgents.get(member.agent_id);
      if (!parentStation || !temp) continue;
      teamLines.push(lineBetween(parentStation.position, temp.position, 0xf59e0b));
    }
  }

  function createCore(): void {
    core = new THREE.Group();

    const platform = new THREE.Mesh(
      new THREE.CylinderGeometry(7, 8, 0.4, 8),
      new THREE.MeshStandardMaterial({
        color: 0x0d151a,
        metalness: 0.8,
        roughness: 0.35,
        emissive: 0x00ffff,
        emissiveIntensity: 0.3
      })
    );
    platform.position.y = 0.2;
    core.add(platform);

    const base = new THREE.Mesh(
      new THREE.CylinderGeometry(5, 5.5, 1.2, 16),
      new THREE.MeshStandardMaterial({
        color: 0x1a2a35,
        metalness: 0.85,
        roughness: 0.3,
        emissive: 0x00ffff,
        emissiveIntensity: 0.2
      })
    );
    base.position.y = 1.0;
    core.add(base);

    const coreSphere = new THREE.Mesh(
      new THREE.SphereGeometry(3.0, 32, 32),
      new THREE.MeshStandardMaterial({
        color: 0x00ffff,
        emissive: 0x00ffff,
        emissiveIntensity: 1.5
      })
    );
    coreSphere.position.y = 2.2;
    core.add(coreSphere);

    for (let i = 0; i < 3; i++) {
      const radius = 3.5 + i * 1.0;
      const ring = new THREE.Mesh(
        new THREE.RingGeometry(radius - 0.15, radius + 0.15, 32),
        new THREE.MeshStandardMaterial({
          color: 0x00ffff,
          emissive: 0x00ffff,
          emissiveIntensity: 1.0,
          side: THREE.DoubleSide
        })
      );
      ring.rotation.x = Math.PI / 2 + i * 0.3;
      ring.position.y = 2.2 + i * 0.3;
      core.add(ring);
    }

    const spine = new THREE.Mesh(
      new THREE.CylinderGeometry(0.2, 0.25, 3.5, 8),
      new THREE.MeshStandardMaterial({
        color: 0x00ffff,
        emissive: 0x00ffff,
        emissiveIntensity: 1.6
      })
    );
    spine.position.y = 4.5;
    core.add(spine);

    const coreLabel = createLabel('ARGUS CORE', 36, true);
    coreLabel.position.y = 6.5;
    core.add(coreLabel);

    const modelLabel = createLabel('SHARED LOCAL MODEL', 22, false);
    modelLabel.position.y = 5.6;
    core.add(modelLabel);

    scene.add(core);
  }

  function createLabel(text: string, fontSize: number, bold: boolean, muted = false): THREE.Sprite {
    const canvas = document.createElement('canvas');
    canvas.width = 512;
    canvas.height = 128;
    const ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.font = `${bold ? '800' : '600'} ${fontSize}px "Space Grotesk", "Segoe UI", system-ui, sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = muted ? 'rgba(107, 114, 128, 0.95)' : 'rgba(232, 244, 255, 0.99)';
      ctx.fillText(text, canvas.width / 2, canvas.height / 2 + 2);
    }
    const texture = new THREE.CanvasTexture(canvas);
    texture.minFilter = THREE.LinearFilter;
    const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: texture, transparent: true }));
    sprite.scale.set(bold ? 4.5 : 3.5, bold ? 1.1 : 0.85, 1);
    return sprite;
  }

  function redrawLabel(sprite: THREE.Sprite, text: string): void {
    const canvas = sprite.material.map?.image as HTMLCanvasElement | undefined;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.font = '500 12px "Space Grotesk", system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = 'rgba(232, 244, 255, 0.95)';
    ctx.fillText(text.replace('_', ' '), canvas.width / 2, canvas.height / 2 + 2);
    sprite.material.map!.needsUpdate = true;
  }

  /* ---- honest disconnected state ---------------------------- */
  function setDisconnectedBadge(show: boolean): void {
    if (show && !disconnectedBadge) {
      disconnectedBadge = createLabel('AGENT LINK DISCONNECTED', 20, true);
      disconnectedBadge.material.color = new THREE.Color(0xff5c5c);
      disconnectedBadge.position.set(0, 9, 0);
      scene.add(disconnectedBadge);
    } else if (!show && disconnectedBadge) {
      scene.remove(disconnectedBadge);
      disposeMaterial(disconnectedBadge.material);
      disconnectedBadge.geometry.dispose();
      disconnectedBadge = null;
    }
  }

  /* ---- State Application ---- */

  $: officeLink = $agentOffice.link;
  $: teamLink = $teamOffice.link;
  $: snapshot = $agentOffice.snapshot;
  $: applySnapshot(snapshot, officeLink, teamLink);
  $: applyDynamicAgents($teamOffice.dynamicAgents);
  $: applyActiveTeam($teamOffice.activeTeam);
  $: applyCriticalSecurity($security.posture);

  function applySnapshot(next: typeof $agentOffice.snapshot, link: string, tLink: string): void {
    if (!renderer || agents.size === 0) return;
    setDisconnectedBadge(link === 'offline' || tLink === 'offline');

    const signature = `${next ? next.agents.map((a) => `${a.id}:${a.state}`).join('|') : 'offline'}:${link}`;
    if (signature === lastSignature) return;
    lastSignature = signature;

    // Every real core station gets real state -- none are left decorative.
    ALL_AGENTS.forEach((role) => {
      const agent = next?.agents.find((a) => a.id === role);
      const isStale = link !== 'online' && link !== 'degraded';
      const state = isStale ? 'disabled' : agent ? agent.state : 'offline';
      const stateColor = isStale ? 0x1e293b : agent ? (STATE_COLORS[state] ?? STATE_COLORS.idle) : 0x1e293b;

      const agentData = agents.get(role);
      if (!agentData) return;

      agentData.currentState = state;

      const targetColor = new THREE.Color(stateColor);
      gsap.to(agentData.stateIndicator.material, {
        emissive: targetColor,
        emissiveIntensity: agent ? (state === 'idle' ? 0.7 : 1.2) : 0.4,
        duration: 0.5,
        overwrite: true
      });

      if (agentData.verifierGlow) {
        const verifying = state === 'verifying';
        gsap.to(agentData.verifierGlow, { intensity: verifying ? 3.5 : 0, distance: verifying ? 10 : 8, duration: 0.4, overwrite: true });
      }

      // Walking behavior
      if (state === 'executing' || state === 'responding') {
        if (!agentData.isWalking) {
          agentData.isWalking = true;
          agentData.targetPosition.copy(new THREE.Vector3(0, 0, 0));
        }
      } else {
        const pos = STATION_POSITIONS[role];
        agentData.targetPosition.set(...pos);
      }

      redrawLabel(agentData.stateLabel, isStale ? 'STALE' : state);
    });
  }

  /* ---- Critical security mode --------------------------------
     Only SECURITY/THREAT/RESPONSE/VERIFIER shift red; SYSTEM/NETWORK/
     ASSISTANT/etc keep their normal cyan-family state color. */
  let wasCritical = false;
  function applyCriticalSecurity(posture: string | undefined): void {
    if (!renderer || agents.size === 0) return;
    const critical = posture === 'critical' || posture === 'blocked' || posture === 'lockdown';
    if (critical) {
      for (const role of CRITICAL_ROLES) {
        const agentData = agents.get(role);
        if (!agentData) continue;
        gsap.to(agentData.stateIndicator.material, { emissive: new THREE.Color(CRITICAL_COLOR), emissiveIntensity: 1.4, duration: 0.35, overwrite: true });
      }
    }
    if (critical !== wasCritical) {
      wasCritical = critical;
      if (!critical) {
        // Leaving critical: nothing else is guaranteed to re-trigger
        // applySnapshot soon (an idle office may see no further snapshot
        // change), so repaint real state colors immediately rather than
        // leaving the red tint stuck until unrelated agent activity.
        lastSignature = '';
        applySnapshot($agentOffice.snapshot, $agentOffice.link, $teamOffice.link);
      }
    }
  }

  function updateAgentMovement(deltaTime: number): void {
    agents.forEach((agent) => {
      if (agent.isWalking) {
        const direction = new THREE.Vector3().subVectors(agent.targetPosition, agent.position);
        const distance = direction.length();

        if (distance > 0.2) {
          direction.normalize();
          agent.mesh.position.addScaledVector(direction, agent.walkSpeed * deltaTime);
          agent.position.copy(agent.mesh.position);

          // Animate walking
          const time = performance.now() * 0.002;
          agent.mesh.children[2].rotation.z = Math.sin(time) * 0.5;
          agent.mesh.children[3].rotation.z = -Math.sin(time) * 0.5;
          agent.mesh.children[4].position.y = 0.4 + Math.sin(time) * 0.12;
          agent.mesh.children[5].position.y = 0.4 - Math.sin(time) * 0.12;

          agent.mesh.lookAt(agent.targetPosition.x, agent.mesh.position.y, agent.targetPosition.z);
        } else {
          agent.isWalking = false;
          agent.mesh.children[2].rotation.z = Math.PI / 4;
          agent.mesh.children[3].rotation.z = -Math.PI / 4;
          agent.mesh.children[4].position.y = 0.4;
          agent.mesh.children[5].position.y = 0.4;
          agent.mesh.rotation.y = 0;
        }
      }
    });
  }

  /* ---- Camera modes ------------------------------------------
     A small preset set; no uncontrolled/automatic movement mid-use. */
  function setCameraMode(mode: CameraMode): void {
    cameraMode = mode;
    if (mode === 'overview') { cameraDest.set(35, 25, 40); cameraTarget.set(0, 1, 0); }
    else if (mode === 'selected') {
      const sel = $agentOffice.selectedAgentId ? agents.get($agentOffice.selectedAgentId) : null;
      const pos = sel ? sel.mesh.position : new THREE.Vector3(0, 1, 0);
      cameraDest.set(pos.x + 6, pos.y + 5, pos.z + 8); cameraTarget.copy(pos);
    } else if (mode === 'team') {
      const involved = $teamOffice.activeTeam?.members.filter((m) => m.kind === 'core').map((m) => m.role) ?? [];
      if (!involved.length) { cameraDest.set(35, 25, 40); cameraTarget.set(0, 1, 0); return; }
      const pts = involved.map((r) => STATION_POSITIONS[r]).filter(Boolean);
      const cx = pts.reduce((s, p) => s + p[0], 0) / pts.length;
      const cz = pts.reduce((s, p) => s + p[2], 0) / pts.length;
      cameraDest.set(cx * 0.6, 22, cz * 0.6 + 26); cameraTarget.set(cx * 0.3, 1, cz * 0.3);
    } else if (mode === 'security') {
      cameraDest.set(-10, 16, 26); cameraTarget.set(-8, 1, 10);
    }
  }

  function onPointerMove(event: PointerEvent): void {
    if (!renderer) return;
    const rect = renderer.domElement.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
  }

  function onPointerDown(): void {
    if (!renderer) return;
    raycaster.setFromCamera(mouse, camera);
    agents.forEach((agent) => {
      const hits = raycaster.intersectObject(agent.mesh, true);
      if (hits.length > 0) selectAgent(agent.role);
    });
    tempAgents.forEach((temp, id) => {
      const hits = raycaster.intersectObject(temp.mesh, true);
      if (hits.length > 0) selectTeamEntity('temp', id);
    });
  }

  function onResize(): void {
    if (!renderer || !container) return;
    const width = Math.max(1, container.clientWidth);
    const height = Math.max(1, container.clientHeight);
    renderer.setSize(width, height);
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
  }

  function animate(): void {
    const now = performance.now();
    if (now - lastRenderTime >= RENDER_INTERVAL) {
      const deltaTime = clock.getDelta();

      if (core) core.rotation.y += 0.0003;
      updateAgentMovement(deltaTime);
      camera.position.lerp(cameraDest, 0.06);
      camera.lookAt(cameraTarget.x, cameraTarget.y, cameraTarget.z);

      renderer?.render(scene, camera);
      lastRenderTime = now;
    }
    animationFrameId = requestAnimationFrame(animate);
  }

  onMount(async () => {
    if (!await initThree()) return;
    applySnapshot($agentOffice.snapshot, $agentOffice.link, $teamOffice.link);
    applyDynamicAgents($teamOffice.dynamicAgents);
    applyActiveTeam($teamOffice.activeTeam);
    animate();

    resizeObserver = new ResizeObserver(onResize);
    resizeObserver.observe(container);
    container.addEventListener('pointermove', onPointerMove);
    container.addEventListener('pointerdown', onPointerDown);

    (window as unknown as Record<string, unknown>).__argusOffice3D = {
      agents: agents.size,
      core: !!core,
      webgl: !!renderer,
    };

    return () => {
      cancelAnimationFrame(animationFrameId);
      resizeObserver?.disconnect();
      container.removeEventListener('pointermove', onPointerMove);
      container.removeEventListener('pointerdown', onPointerDown);
      clearTeamLines();
      tempAgents.forEach((t) => { scene.remove(t.mesh); disposeGroup(t.mesh); });
      tempAgents.clear();
      setDisconnectedBadge(false);
      renderer?.dispose();
      if (renderer?.domElement.parentNode === container) container.removeChild(renderer.domElement);
      renderer = null;
      agents.clear();
      delete (window as unknown as Record<string, unknown>).__argusOffice3D;
    };
  });
</script>

<div class="office-3d-wrap">
  <div bind:this={container} class="office-3d-container" aria-hidden="true"></div>
  <div class="office-3d-cam" role="group" aria-label="Camera mode">
    {#each [['overview','OVERVIEW'],['selected','SELECTED'],['team','TEAM'],['security','SECURITY']] as [mode, label] (mode)}
      <button class:active={cameraMode === mode} on:click={() => setCameraMode(mode as CameraMode)}>{label}</button>
    {/each}
  </div>
</div>

<style>
  .office-3d-wrap { position: relative; }
  .office-3d-container {
    width: 100%;
    height: 700px;
    border-radius: 10px;
    overflow: hidden;
    background: #0a0e12;
    cursor: pointer;
  }
  .office-3d-container :global(canvas) { display: block; }
  .office-3d-cam { position: absolute; top: 10px; left: 10px; display: flex; gap: 6px; }
  .office-3d-cam button { background: rgba(6, 16, 20, .82); border: 1px solid rgba(56, 224, 255, .3); color: rgba(214, 238, 245, .75); border-radius: 5px; padding: 5px 10px; font-size: 10.5px; font-weight: 700; letter-spacing: .1em; cursor: pointer; }
  .office-3d-cam button:hover { border-color: rgba(56, 224, 255, .6); color: #9deaff; }
  .office-3d-cam button.active { background: rgba(56, 224, 255, .18); border-color: rgba(56, 224, 255, .75); color: #9deaff; }
</style>
