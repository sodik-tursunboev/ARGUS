/* ARGUS HUD V2 — central Phosphor icon system.
   Semantic aliases over phosphor-svelte (v3, Svelte 5). View components import
   the ALIAS (e.g. IconSecurity), never a raw choice, so the mapping lives here
   once and stays consistent. Rules:
     - weight: "regular" everywhere except three deliberate exceptions: the
       security ShieldCheck (fill), the ACTIVE nav item ("duotone") and the four
       telemetry anchor icons on the System Overview cards ("duotone" — at
       36-44px the second tone gives the glyph body instead of a wire outline).
       No other mixed weights.
     - size: use the iconSize scale below (micro 12 … major 22). Never pass
       ad-hoc pixel values outside this scale. `nav` (20) is the primary
       navigation glyph and must stay visibly larger than its 13px label.
       Dashboard panels are the one exception: their icons are sized in CSS
       from the density tokens in styles/dashboard.css (title 20-24px, rows
       16-20px, System Overview anchors 30-42px following their card), so
       the whole hierarchy scales together -- see DashPanel.svelte.
     - color: icons default to currentColor and inherit the semantic UI state
       from CSS (muted default, cyan active, emerald ok, amber warn, red
       critical). Icons are NOT the carrier of meaning — the text label is. */
import {
  ArrowRight, ArrowsClockwise, BellRinging, Brain, Buildings, CaretDown, CheckCircle, Circle, ClockCounterClockwise, Cpu, Cube,
  Desktop, DesktopTower, DotsNine, Files, Fingerprint, FlowArrow, Gauge, GearSix, GraphicsCard, HardDrive, HardDrives, Hourglass, Info,
  Key, Lightning, ListBullets, ListChecks, LockKey, Memory, Microphone, MicrophoneSlash,
  Minus, Monitor, Network, PaperPlaneTilt, Password, Play, Plug, Prohibit, PuzzlePiece, Pulse, Robot,
  ScanSmiley, Scroll, SealCheck, ShieldCheck, ShieldCheckered, ShieldStar, ShieldWarning,
  SlidersHorizontal, SpeakerHigh, SquaresFour, Star, Stop, Target, Terminal, Timer, Toolbox, TreeStructure,
  UserFocus, Warning, WarningOctagon, Wrench, X,
} from 'phosphor-svelte';

/** Design-scale sizes (px). Components should pick from here. `tab` is the secondary (page sub-tab) glyph:
    it must stay visibly larger than its 13px label, exactly like `nav` (20) against the nav label. */
export const iconSize = { micro: 12, small: 14, normal: 16, tab: 18, control: 18, nav: 20, major: 22 } as const;
export type IconSizeKey = keyof typeof iconSize;

/* ---- Primary navigation ---- */
export const IconDashboard = Gauge;
export const IconTasks = ListChecks;
export const IconAgents = Robot;
export const IconOperations = Monitor;
export const IconModules = Cube;
export const IconSecurity = ShieldCheck;
/** AUTHENTICATION top-level tab: the canonical PIN / voice / face surface. */
export const IconAuthentication = Fingerprint;
export const IconLogs = Scroll;
export const IconTools = Toolbox;
export const IconAbout = Info;
export const IconSettings = GearSix;
/** The MORE trigger: a 3x3 dot grid reads as "everything else", and the caret
    beside the label carries the open/closed affordance (both Phosphor, both
    currentColor — replaces the old text-glyph triangle). */
export const IconMore = DotsNine;
export const IconCaret = CaretDown;

/* ---- Dashboard headings + telemetry ---- */
export const IconSystem = Cpu;
/** SYSTEM OVERVIEW panel title glyph. Distinct from IconCPU on purpose: the
    CPU card directly beneath the title carries the big Cpu anchor icon. */
export const IconSystemOverview = DesktopTower;
export const IconProcess = Pulse;
export const IconAI = Brain;
export const IconNetwork = Network;
export const IconThreat = ShieldWarning;
/** Recent-alerts panel title glyph (dashboard). */
export const IconAlerts = BellRinging;
/** "See the full view" affordance on dashboard summary panels. */
export const IconGo = ArrowRight;
export const IconObjective = Target;
export const IconTimeline = ClockCounterClockwise;
export const IconQuick = Lightning;
export const IconCommand = Terminal;
export const IconVoice = Microphone;

export const IconCPU = Cpu;
export const IconMemory = Memory;
export const IconGPU = GraphicsCard;
export const IconDisk = HardDrive;

/* ---- Security semantics (distinct icons per concept) ---- */
export const IconDeviceTrust = ShieldCheckered;
export const IconPolicyEngine = SlidersHorizontal;
export const IconAuth = Key;
export const IconAuthLevel = Key;
export const IconUserPresence = UserFocus;
export const IconExecutor = Terminal;
export const IconNetworkPolicy = Network;
export const IconAuditChain = Scroll;
export const IconIntegrity = Fingerprint;
export const IconThreatState = ShieldWarning;
export const IconLockdown = LockKey;
export const IconBlocked = Prohibit;
export const IconSeal = SealCheck;

/* ---- Severity / status semantics ---- */
export const IconCritical = WarningOctagon;
export const IconWarning = Warning;
export const IconInfo = Info;
export const IconSuccess = CheckCircle;
export const IconOffline = Prohibit;

/* ---- Voice / command ---- */
export const IconMic = Microphone;
export const IconMicMuted = MicrophoneSlash;
export const IconSend = PaperPlaneTilt;
export const IconSpeaker = SpeakerHigh;

/* ---- Action semantics ---- */
export const IconRefresh = ArrowsClockwise;
export const IconFavorite = Star;
export const IconPlay = Play;
export const IconStop = Stop;
export const IconCopy = Files;
export const IconLaunch = SquaresFour;
export const IconWrench = Wrench;
export const IconSecurityCenter = ShieldStar;

/* ---- Task step status ---- */
export const IconTaskPending = Circle;
export const IconTaskActive = Play;
export const IconTaskComplete = CheckCircle;
export const IconTaskBlocked = Prohibit;
export const IconTaskAuthWait = Hourglass;
export const IconTaskFailed = X;
export const IconTaskSkipped = Minus;
export const IconClose = X;

/* ---- Module matrix ---- */
export const IconModuleAI = Brain;
export const IconModuleVoice = Microphone;
export const IconModuleTelemetry = Gauge;
export const IconModuleAuth = Key;
export const IconModuleIntegrity = Fingerprint;
export const IconModuleThreat = ShieldWarning;
export const IconModuleNetwork = Network;
export const IconModuleAudit = Scroll;
export const IconModuleSandbox = Cube;
export const IconModuleSkills = ListChecks;export const IconModuleIntegrations = Plug;


export const IconModel = Cube;

/* ---- Authentication methods (Authentication page cards) ---- */
export const IconMethodPin = Password;
export const IconMethodVoice = Microphone;
export const IconMethodFace = ScanSmiley;
export const IconSession = Timer;

/* ---- Page sub-tabs: ONE registry, so no page carries its own icon logic ----
   Keyed by the Tabs `group` and the tab id. tabIcon() never returns nothing:
   an unmapped tab gets the neutral fallback, and the QA count of "sub-tabs with
   an icon" is read straight off the DOM. */
export const TAB_ICONS: Record<string, Record<string, typeof Gauge>> = {
  tasks: { active: Pulse, plan: TreeStructure, history: ClockCounterClockwise },
  agents: { office: Buildings, active: Pulse, planner: FlowArrow, history: ClockCounterClockwise },
  modules: { overview: SquaresFour, core: Cpu, ai: Brain, voice: Microphone, security: ShieldCheck, system: Desktop, automation: Lightning, integrations: Plug },
  security: { overview: SquaresFour, threats: ShieldWarning, audit: Scroll, session: Timer, policy: SlidersHorizontal },
  logs: { events: ListBullets, system: HardDrives, agent: Robot },
  tools: { 'quick actions': Lightning, system: Cpu, capabilities: PuzzlePiece },
};
export const tabIcon = (group: string, item: string): typeof Gauge => TAB_ICONS[group]?.[item] ?? SquaresFour;
