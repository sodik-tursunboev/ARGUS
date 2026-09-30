/* ARGUS AI City -- the district colour system.
   ==========================================================================

   The readability problem this solves: the first city painted everything
   graphite + cyan, so it sank into the navy HUD behind the canvas and every
   district looked like every other district. The fix is not more neon. It is
   giving each district CATEGORY its own hue band and its own value, so the
   city separates from the UI and the districts separate from each other,
   while all of it stays inside one premium ARGUS language.

   The HUD stays dark navy/cyan. Only the CITY uses this wider range.

   These values mirror tools/blender/argus_kit.py's FAMILY_TINTS, so the
   runtime's lights, labels, selection rings and route lines agree with the
   colours baked into the building assets. */

import type { DistrictCategory } from './cityLayout';

export interface CategoryStyle {
  /** Primary signal colour: rim light, selection ring, label underline. */
  accent: number;
  /** Secondary, for a subordinate detail on the same building. */
  secondary: number;
  /** A rim/fill light tint applied to this district's block, so a district
   *  reads as its own place even before you look at the buildings. */
  fill: number;
  /** Ground/plot tint under the block. */
  ground: number;
  /** Short human label used in the selection panel. */
  label: string;
}

// Fills are saturated on purpose: each is a coloured pool of light over its
// block, which is the single strongest cue separating one district from the
// next at city zoom. Grounds are the block's own paving tint -- lifted well
// clear of the navy background so a block never dissolves into it.
// One family per district. Accent = its signal hue, secondary =
// the family's second colour, fill = the pool of light over the block.
export const CATEGORY_STYLES: Record<DistrictCategory, CategoryStyle> = {
  command: {       // CORE: deep blue + cyan + white
    accent: 0x38e0ff, secondary: 0xf2f8ff, fill: 0x2f6fe0, ground: 0x172c4d,
    label: 'CORE',
  },
  hq: {            // AGENT HQ: steel blue + cyan + warm office light
    accent: 0x6cc8ff, secondary: 0xffc98a, fill: 0x5f8fb8, ground: 0x1d3044,
    label: 'AGENT HQ',
  },
  security: {      // SECURITY: graphite + teal + limited red
    accent: 0x2ad4bd, secondary: 0xff5a6a, fill: 0x2ab89f, ground: 0x1f2a2c,
    label: 'SECURITY',
  },
  research: {      // ACADEMY: indigo / violet + cream
    accent: 0x9578ff, secondary: 0xffe9c2, fill: 0x6a4fd8, ground: 0x28234d,
    label: 'ACADEMY',
  },
  operations: {    // OPERATIONS: steel + amber
    accent: 0xffb244, secondary: 0x9fb3c8, fill: 0xd9953a, ground: 0x2a3139,
    label: 'OPERATIONS',
  },
  verification: {  // VERIFICATION: white-gray + cyan
    accent: 0xe8f4ff, secondary: 0x38e0ff, fill: 0xa9c8e0, ground: 0x2b3642,
    label: 'VERIFICATION',
  },
  specialist: {    // SPECIALIST: blue-violet
    accent: 0x8a93ff, secondary: 0xc9ccff, fill: 0x6572e8, ground: 0x222a55,
    label: 'SPECIALIST',
  },
  civic: {         // the gate: white checkpoint
    accent: 0xf4f8ff, secondary: 0x38e0ff, fill: 0x8fb4d9, ground: 0x263444,
    label: 'CHECKPOINT',
  },
  industrial: {    // MODEL PLANT / capability: dark industrial + amber/cyan
    accent: 0xffb244, secondary: 0x38e0ff, fill: 0xc98a36, ground: 0x2a2419,
    label: 'INDUSTRIAL',
  },
  cloud: {         // CLOUD EMBASSY: silver + violet / pale blue
    accent: 0xc4b5fd, secondary: 0xa5d8ff, fill: 0x9d8ce0, ground: 0x2e2c45,
    label: 'CLOUD · EXTERNAL',
  },
  residential: {   // RESIDENTIAL: warm amber + muted blue/green
    accent: 0xffb877, secondary: 0x7fb8a0, fill: 0xd99a5a, ground: 0x2d2a26,
    label: 'RESIDENTIAL · REST',
  },
  utility: {       // UTILITY: service yellow + steel
    accent: 0xffd34d, secondary: 0x9fb3c8, fill: 0xc9a34f, ground: 0x2c2a1e,
    label: 'UTILITY',
  },
};

/** Live backend state colours. These are SIGNAL colours and are deliberately
 *  outside the district hue system -- a critical posture has to override a
 *  district's own identity, not blend into it. */
export const STATE_TINT: Record<string, number | null> = {
  idle: null,
  active: 0x4ade9e,
  attention: 0xffb244,
  critical: 0xff4a4a,
  offline: 0x55606b,
};

export const STATE_PULSE: Record<string, number> = {
  idle: 1, active: 1.45, attention: 1.3, critical: 1.6, offline: 0.35,
};

/** Agent role accents -- the visor, the ground halo and the name
 *  tag, over light graphite/silver armour. Security's red is a deep crimson,
 *  kept clear of the bright STATE_TINT critical above, so a Security robot
 *  reads as a role, not as a live incident; threat/response/diagnostics step
 *  through orange-red -> orange -> amber, all clear of the Manager's gold. */
export const ROLE_ACCENT: Record<string, number> = {
  security: 0xd8344f,     // red
  threat: 0xff5a36,       // orange-red
  system: 0x3d8bff,       // blue
  network: 0x14b8a6,      // teal
  planner: 0x9b6bff,      // violet
  diagnostics: 0xffa928,  // amber
  forensics: 0x5b63e6,    // indigo
  response: 0xff8a1f,     // orange
  verifier: 0xd8f6ff,     // white / cyan
  assistant: 0x3ff0dc,    // turquoise
  manager: 0xffd166,
  cloud: 0xc4b5fd,        // silver body, pale violet accent
};

/** How each worker type reads under its name. */
export const WORKER_TITLE: Record<string, string> = {
  core: 'Core Agent', temp: 'Temp Specialist', cloud: 'Cloud Specialist',
  hermes: 'Hermes Specialist', manager: 'Agent Manager',
};

/** The chain of command's two named tiers get their own gold, used nowhere
 *  else in the city, so they are findable at any zoom. */
export const MANAGER_ACCENT = 0xffd166;
export const CEO_ACCENT = 0xffe7a3;

/** What each core agent does, in a few words -- the second line of its name
 *  tag. Names themselves come from the backend snapshot when it has them. */
export const ROLE_TITLE: Record<string, string> = {
  security: 'Security posture',
  threat: 'Threat analysis',
  assistant: 'General assistant',
  system: 'System health',
  network: 'Network state',
  verifier: 'Result verification',
  planner: 'Task planning',
  diagnostics: 'Diagnostics',
  forensics: 'Forensic evidence',
  response: 'Incident response',
  manager: 'Team orchestrator',
};

/** Fallback job descriptions, verbatim from agents/definitions.py, for the
 *  detail panel while no snapshot is available. The live snapshot's own
 *  `description` always wins when it exists. */
export const ROLE_DESCRIPTION: Record<string, string> = {
  security: 'Analyses ARGUS security posture: policy, authentication, integrity, audit. Recommends; never changes anything.',
  threat: 'Correlates real detections and events; severity reasoning and MITRE-mapped triage. Never invents a detection.',
  assistant: 'User-facing help: explanations, summaries, status translation, safe planning. Never a privileged shortcut.',
  system: 'System-health analysis over real telemetry (CPU, memory, disk, GPU, processes). No guessed hardware values.',
  network: 'Analyses connection state, network telemetry and network-policy posture. Not a scanner.',
  verifier: 'Independent verification: objective vs observed result, evidence-based verdicts. Never re-executes.',
  planner: 'Turns complex goals into bounded explicit steps. Proposes plans; never executes.',
  diagnostics: 'Analyses errors, logs, service failures and runtime health. Read-first; changes are capability requests.',
  forensics: 'Read-only forensic analysis of approved evidence: logs, events, hashes, audit trails. Never mutates evidence.',
  response: 'Drafts containment/remediation/recovery PLANS for confirmed incidents. Does not execute -- ever.',
};

/** Fallback display names, matching agents/definitions.py, for before the
 *  first snapshot arrives or while the backend is unreachable. */
export const ROLE_NAME: Record<string, string> = {
  security: 'Security Agent', threat: 'Threat Agent', assistant: 'Assistant Agent',
  system: 'System Agent', network: 'Network Agent', verifier: 'Verifier Agent',
  planner: 'Planner Agent', diagnostics: 'Diagnostics Agent',
  forensics: 'Forensics Agent', response: 'Response Agent', manager: 'Agent Manager',
};

/** Scenery quarter tints -- environment buildings get a quarter identity too,
 *  so the surrounding city has structure instead of being grey filler. */
export const QUARTER_FILL: Record<string, number> = {
  residential: 0xd99a5a,
  service: 0xd9a54f,
  commercial: 0x6f93c4,
  industrial: 0xc98a36,
  utility: 0xc9a34f,
};

export function categoryStyle(category: DistrictCategory): CategoryStyle {
  return CATEGORY_STYLES[category] ?? CATEGORY_STYLES.civic;
}

export function hexToCss(hex: number, alpha = 1): string {
  const r = (hex >> 16) & 255, g = (hex >> 8) & 255, b = hex & 255;
  return alpha >= 1 ? `#${hex.toString(16).padStart(6, '0')}` : `rgba(${r},${g},${b},${alpha})`;
}
