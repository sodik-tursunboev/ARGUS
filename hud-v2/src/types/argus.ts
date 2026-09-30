export interface BackendStatus { version?: string; uptime_seconds?: number; voice_state?: string; model?: string; muted?: boolean; pin_pending?: boolean; history_msgs?: number; history_max?: number; engine?: string; cloud_enabled?: boolean; /** Total time of the last completed exchange (ms); null until one has happened. */ last_latency_ms?: number | null; }
export interface BackendProcess { name?: string; pid?: number; mb?: number; cpu?: number; threads?: number; }
export interface BackendTelemetry { cpu?: number; mem_pct?: number; mem_used_gb?: number; mem_total_gb?: number; disk_pct?: number; disk_free_gb?: number; gpu_available?: boolean; gpu_pct?: number | null; net_sent_gb?: number; net_recv_gb?: number; top_processes?: BackendProcess[]; anomalies?: unknown[]; detections?: unknown[]; threat?: { severity?: string; level?: string; [key: string]: unknown }; lockdown?: { armed?: boolean }; }
export interface BackendSecurityReport {
  integrity?: { ok?: boolean; sealed?: boolean; signed?: boolean; signature_valid?: boolean; summary?: string };
  /** `factors` is main.py's list(config.AUTH_REQUIRED_FACTORS); names only, never a credential. */
  authentication?: { enabled?: boolean; unlocked?: boolean; factors?: string[]; pin_hashed?: boolean };
  /** Voice-channel security: replay guard on/off, and whether a speaker-embedding backend exists (voiceauth.speaker_available()). */
  voice?: { replay_detection?: boolean; speaker_verification?: boolean; note?: string };
  network?: { egress_policy?: string; cloud_enabled?: boolean };
  audit?: { chain_intact?: boolean };
  sandbox?: { privileges_held?: number | null; acls_hardened?: boolean; install_dir_writable?: boolean };
  skills?: { allowlisted?: number; violations?: number };
}
/* threatmon.summary_state(): `recent` is the raw detection buffer (last 10, newest first). A record carries
   `ts` (local time, %Y-%m-%dT%H:%M:%S) and `at_epoch` (unix seconds); `at` exists only on some records
   (baseline-style dumps) -- lib/threat.ts reads all three. */
export interface BackendDetection { severity?: string; detector?: string; name?: string; technique?: string; at?: string; ts?: string; at_epoch?: number }
export interface BackendThreatReport { level?: string; counts?: Record<string, number>; recent?: BackendDetection[]; }
/* Backend /auth-status contract — auth.status() documented verbatim. */
export interface BackendAuthStatus { enabled?: boolean; unlocked?: boolean; locked_out?: boolean; lockout_seconds?: number; idle_lock_seconds?: number; }
export type SnapshotSource = 'live' | 'partial' | 'unavailable' | 'stale' | 'loading';

import type { FaceStatus } from '../lib/face';
export type { FaceStatus } from '../lib/face';

export interface HudSnapshot {
  status: BackendStatus | null;
  telemetry: BackendTelemetry | null;
  security: BackendSecurityReport | null;
  threat: BackendThreatReport | null;
  auth: BackendAuthStatus | null;
  face: FaceStatus | null;
}

export type TaskLifecycleStatus = 'idle' | 'created' | 'executing' | 'completed' | 'blocked' | 'waiting_auth' | 'failed' | 'replanned' | 'unknown';
export type TaskStepStatus = 'pending' | 'active' | 'complete' | 'blocked' | 'waiting_auth' | 'failed' | 'skipped';
export interface ArgusTaskStep { id: string; label: string; status: TaskStepStatus; inserted?: boolean; }
export interface ArgusTask {
  goal: string | null; status: TaskLifecycleStatus; currentStepId: string | null;
  steps: ArgusTaskStep[]; activeCapability: string | null; reason: string | null;
  replanAvailable: boolean; revision: number;
}

export type HudEventType =
  | 'agent.state' | 'agent.message' | 'task.created' | 'task.updated' | 'task.completed'
  | 'task.step.updated' | 'task.failed' | 'task.replanned' | 'task.blocked' | 'task.waiting_auth'
  | 'security.state' | 'security.decision' | 'security.alert' | 'auth.state'
  | 'telemetry.system' | 'telemetry.network' | 'telemetry.model'
  | 'audit.event' | 'voice.state' | 'voice.level'
  | 'agent.registered' | 'agent.job_queued' | 'agent.started' | 'agent.state_changed'
  | 'agent.waiting_auth' | 'agent.completed' | 'agent.failed' | 'agent.cancelled'
  | 'agent.handoff'
  /* CEO inbox reply acknowledgement (agents/inbox.py) -- ids only. */
  | 'agent.reply'
  /* Dynamic (temporary local + cloud) agent lifecycle -- agents/events.py DYNAMIC_EVENTS. */
  | 'agent.proposed' | 'agent.approved' | 'agent.spawned' | 'agent.expired'
  | 'agent.destroyed' | 'agent.spawn_denied'

  | 'team.created' | 'team.plan_created' | 'team.started' | 'team.task_ready'
  | 'team.task_started' | 'team.task_completed' | 'team.task_failed'
  | 'team.agent_requested' | 'team.agent_spawned' | 'team.handoff'
  | 'team.verification_started' | 'team.verification_completed'
  | 'team.replan_requested' | 'team.replanned' | 'team.partial' | 'team.completed'
  | 'team.failed' | 'team.cancelled' | 'team.timed_out';

export interface HudEventEnvelope<T = Record<string, unknown>> {
  type: HudEventType;
  version: 1;
  timestamp: string;
  eventId?: string;
  payload: T;
}
export type TimelineCategory = 'AGENT' | 'SYSTEM' | 'POLICY' | 'MODEL' | 'DETECT' | 'AUTH' | 'EXECUTE' | 'VERIFY' | 'SECURITY' | 'ERROR';
export interface TimelineEvent { id: string; category: TimelineCategory; message: string; timestamp: number; severity: 'info' | 'warning' | 'critical'; }
export type ActionStatus = 'idle' | 'pending' | 'waiting_auth' | 'executing' | 'success' | 'denied' | 'failed';
export interface CommandResponse { reply?: string; skill?: string; action?: string; auth_required?: boolean; confirmation_required?: boolean; auth_level?: number | null; auth_requirement?: string; }
export interface UnlockResponse { ok?: boolean; message?: string; status?: { unlocked?: boolean; locked_out?: boolean }; }
export type BootResult = 'VERIFIED' | 'ONLINE' | 'READY' | 'DEGRADED' | 'UNAVAILABLE' | 'UNKNOWN' | 'FAILED' | 'LOADING' | 'STARTING';
export interface BootCheck { label: string; result: BootResult; }

export type SecurityPosture = 'normal' | 'degraded' | 'warning' | 'critical' | 'blocked' | 'lockdown' | 'recovery' | 'unknown';
export type SecurityFreshness = 'live' | 'partial' | 'stale' | 'unavailable' | 'loading';
export type SecurityAuthStatus = 'unknown' | 'valid' | 'required' | 'expired';
export interface SecurityFields { deviceTrust: string; policyEngine: string; authLevel: string; userPresence: string; executor: string; networkPolicy: string; auditChain: string; threatState: string; }
export interface SecurityDecision { capability: string | null; resource: string | null; policy: 'allow' | 'deny' | 'unknown'; auth: SecurityAuthStatus; executor: 'user' | 'admin' | 'sandbox' | 'unknown'; status: 'ready' | 'blocked' | 'waiting_auth' | 'unknown'; }
export interface SecurityAlert { id: string; severity: string; label: string; timestamp: string | null; }


export interface OfficeAgent {
  id: string; name: string; role: string; description: string;
  priority: number; enabled: boolean; allowed_capability_groups: string[];
  shared_model: boolean; state: string; current_job_id: string;
  queue_position: number; last_activity_at: number; completed_jobs: number;
  failed_jobs: number; last_error: string;
}
export interface OfficeModelStatus {
  model_id: string; available: boolean; busy: boolean; active_job: string;
  max_concurrency: number; timeout_s: number; calls_made: number;
  timeouts: number; errors: number; last_error: string;
}
export interface OfficeJob {
  job_id: string; agent_id: string; priority: number; state: string;
  source: string; parent_job_id: string; handoff_depth: number;
  created_at: number; age_s: number; objective: string;
}
export interface AgentOfficeSnapshot {
  agents: OfficeAgent[]; model: OfficeModelStatus; queue_depth: number;
  active_jobs: string[]; active_count: number; tiers: Record<string, string>;
}


export interface TeamSummary {
  team_id: string; request_id: string; goal: string; goal_digest: string;
  playbook: string; state: string; current_phase: string; priority: number;
  created_at: number; started_at: number; finished_at: number; deadline: number;
  elapsed_s: number; progress: number; member_count: number;
  temporary_count: number; temporary_live: number; model_calls: number;
  replans: number; handoffs: number; last_activity: number;
  verdict: string; termination_reason: string;
  budgets: Record<string, unknown>; plan_versions: number;
}
export interface TeamMemberView {
  member_id: string; role: string; kind: 'core' | 'temp'; worker_type: string;
  parent: string; agent_id: string; state: string; current_task: string;
  queue_position: number; started_at: number; last_activity: number;
  children: string[]; ttl_remaining_s: number; result_summary: string;
  tasks: string[];
}
export interface TeamTaskView {
  task_id: string; title: string; kind: string; role: string; agent_id: string;
  worker_type: string; member_id: string; state: string;
  dependency_state: string; dependencies: string[]; required: boolean;
  origin: string; attempt: number; max_attempts: number; priority: number;
  queued_at: number; started_at: number; finished_at: number;
  duration_s: number; queue_wait_s: number; timeout_s: number;
  model_calls: number; error: string; wait_reason: string; replaced_by: string;
  result_summary: string; findings: number; observed: number;
  evidence_refs: string[]; confidence: string; verification: string;
  handoff_requests: number; action_proposals: number;
}
export interface TeamTreeNode {
  id: string; role: string; kind: 'orchestrator' | 'core' | 'temp';
  state: string; current_task: string; children: TeamTreeNode[];
}
export interface TeamActivityEntry { ts: number; code: string; task_id: string; detail: string }
export interface TeamDetail extends TeamSummary {
  members: TeamMemberView[]; tasks: TeamTaskView[]; tree: TeamTreeNode;
  dependencies: [string, string][];
  activity: TeamActivityEntry[];
  verification: Record<string, unknown>;
  verifications: Record<string, unknown>[];
  result: Record<string, unknown> | null;
}
export interface TeamsListResponse {
  teams: TeamSummary[]; active_teams: number; states: Record<string, number>;
  recent_teams: number;
  limits: { max_active_teams: number; max_team_members: number;
    max_inflight_per_team: number; max_handoffs_per_team: number; tick_s: number };
  metrics: Record<string, number>; wired: boolean;
}

/* ── Dynamic (temporary local + cloud) agents -- agents/ephemeral.py's
   view()/snapshot(). GET /api/agents/dynamic ── */
export type DynamicAgentType = 'CORE' | 'EPHEMERAL_LOCAL' | 'EPHEMERAL_CLOUD';
export interface DynamicAgentView {
  id: string; name: string; role: string; description: string; parent: string;
  created_by: string; type: DynamicAgentType | string; state: string;
  runtime_state: string; current_task: string; current_job_id: string;
  spawn_depth: number; created_at: number; expires_at: number;
  ttl_remaining_s: number; model: string; model_scope: string;
  queue_state: { state: string; queue_position: number };
  children: string[]; result_summary: string; priority: number;
  allowed_capabilities: string[]; denied_capabilities: string[];
  allowed_data_classes: string[];
  budget: { model_calls_used: number; max_model_calls: number;
    handoffs_used: number; max_handoffs: number;
    children_spawned: number; max_children: number };
  termination_reason: string;
}
export interface DynamicAgentTreeNode {
  id: string; name: string; type: string; state: string; spawn_depth: number;
  children: DynamicAgentTreeNode[];
}
export interface DynamicSnapshot {
  agents: DynamicAgentView[]; recent: DynamicAgentView[]; tree: DynamicAgentTreeNode[];
}

/* ── Agent Manager + CEO inbox -- agents/agent_manager.py state() and
   agents/inbox.py AgentMessage.as_dict(). GET /api/agents/manager,
   /api/agents/inbox ── */
export type AgentMessageType = 'INFO' | 'PROGRESS' | 'QUESTION' | 'WARNING' | 'APPROVAL_REQUEST' | 'RESULT' | 'FAILURE';
export type AttentionLevel = 'INFO' | 'NORMAL' | 'IMPORTANT' | 'CRITICAL';
export type InboxSection = 'IMPORTANT' | 'QUESTIONS' | 'PROGRESS' | 'RESULTS' | 'SENT';
export interface AgentMessage {
  message_id: string; request_id: string; task_id: string; team_id: string;
  job_id: string; hire_id: string; sender_agent_id: string; sender_name: string;
  sender_role: string; recipient: string; type: AgentMessageType; title: string;
  body: string; priority: AttentionLevel; requires_reply: boolean;
  reply_options: string[]; thread: string; created_at: number; read: boolean;
  resolved: boolean; section: InboxSection;
  replies: { text: string; choice: string; at: number }[];
}
export interface InboxSummary {
  unread: number; open_questions: number; total: number;
  unread_by_section: Record<string, number>;
  stats: { posted: number; suppressed: number; replies: number };
  limits: { per_task: number; progress_per_task: number; per_minute: number };
}
/** One worker in the backend's normalized workforce snapshot (WorkerState,
 *  agents/agent_manager.state()): the same fields whatever the backend. */
export type WorkerType = 'CORE' | 'TEMP_LOCAL' | 'HERMES' | 'CLOUD';
export interface ManagerAgentView {
  id: string; name: string; kind: 'core' | 'temp' | 'cloud'; role: string; backend: string;
  display_name?: string; worker_type?: WorkerType; specialization?: string;
  state: string; current_job_id?: string; queue_position?: number; active_tasks?: number;
  queued_tasks?: number; team_id?: string; current_task: string; reports_to: string;
  manager_id?: string; parent_agent_id?: string; capabilities?: string[]; approved_scope?: string[];
  created_at?: number; expires_at?: number; city_location?: string;
  provider: string; model?: string; ttl_remaining_s: number; parent?: string; created_by?: string;
  performance?: { tasks_completed: number; tasks_failed: number; verification_pass_rate: number | null;
    average_latency_s: number | null; specializations: Record<string, number>; last_used: number };
}
/** The one shared local model runtime and who is WAITING_FOR_MODEL behind it. */
export interface ModelQueueView {
  model: string; available: boolean; busy: boolean; running_job: string; running_agent: string;
  queue_depth: number; waiting: string[];
}
export interface HireLogEntry {
  team_id: string; task_id: string; template: string; name: string; parent: string;
  backend: string; ttl_s: number; gap: string;
  state: 'REQUESTED' | 'HIRED' | 'RELEASED' | 'DENIED' | 'CANCELLED' | string;
  agent_id: string; reason: string; created_at: number; updated_at: number;
}
export interface HireRequestView {
  hire_id: string; request_id: string; state: string; playbook: string;
  specialists: { template: string; name: string; parent: string; backend: string; ttl_s: number; gap: string }[];
  existing_roles: string[]; fallback_agent: string; created_at: number; decided_at: number;
  team_id: string; job_id: string; message_id: string; reason: string;
}
export interface ManagerState {
  manager: { id: string; name: string; role: string; state: string; cannot: string[] };
  ceo: { role: string; display: string; name: string };
  workforce: { total: number; core: number; temporary: number; active: number; idle: number; cloud: number;
    queued_work: number; temp_local?: number; hermes?: number };
  agents: ManagerAgentView[]; temporaries: ManagerAgentView[];
  model_queue?: ModelQueueView; cloud_blocked_by_owner?: boolean;
  teams: { team_id: string; state: string; progress: number; goal: string; temporary_count: number; member_count: number }[];
  active_teams: number; pending_hires: number; hire_requests: HireRequestView[];
  hiring_log: HireLogEntry[];
  backends: { id: string; available: boolean; note: string; status?: string }[];
  limits: Record<string, number | boolean>;
  inbox: InboxSummary;
}
