// Shapes returned by the control-plane API (/cp/v1). Mirrors app/domain/records.py and the routers.

export type Environment = "dev" | "staging" | "production";
export type Stage = "input" | "retrieval" | "tool" | "output" | "agent";
export type Decision = "allow" | "modify" | "escalate" | "block";
export type DataClassification = "PUBLIC" | "INTERNAL" | "CONFIDENTIAL" | "PII";

export const ENVIRONMENTS: Environment[] = ["dev", "staging", "production"];
export const STAGES: Stage[] = ["input", "retrieval", "tool", "output", "agent"];
export const DECISIONS: Decision[] = ["allow", "modify", "escalate", "block"];

export type Permission =
  | "read"
  | "catalog:write"
  | "registry:write"
  | "assignments:write"
  | "publish:request"
  | "publish:approve"
  | "reviews:decide"
  | "reviews:raw"
  | "admin-keys:write";

export interface Me {
  key_id: string;
  name: string;
  roles: string[];
  tenant_id: string | null;
  platform: boolean;
  permissions: Permission[];
  environments: Environment[];
  two_person_environments: Environment[];
  review_ttl_minutes: number;
  features: { simulate: boolean; analytics: boolean };
}

export interface Tenant {
  id: string;
  name: string;
  status: "active" | "suspended";
  created_at: string;
}

export interface ApiKey {
  id: string;
  tenant_id: string;
  name: string;
  prefix: string;
  scopes: string[];
  environments: Environment[] | null;
  is_active: boolean;
  expires_at: string | null;
  created_at: string;
  revoked_at: string | null;
  rate_limit_per_minute?: number | null; // null = gateway default, 0 = unlimited
}

export interface CreatedApiKey extends ApiKey {
  key: string;
  note: string;
}

export interface Agent {
  tenant_id: string;
  agent_id: string;
  base_trust_score: number;
  allowed_tools: string[];
  owner: string | null;
  updated_at: string;
}

export interface ActionRule {
  id: string;
  tenant_id: string;
  action: string;
  resource_pattern: string;
  base_risk_score: number;
}

export interface Modifier {
  id: string;
  tenant_id: string;
  kind: "classification" | "environment";
  value: string;
  delta: number;
}

export interface Manifest {
  id: string;
  version: string;
  kind: "local" | "remote" | "model";
  stages: Stage[];
  description: string;
  owner: string;
  data_handling: string;
  config_schema: Record<string, unknown>;
  failure_mode: "fail_closed" | "fail_open";
  decisions_emitted: Decision[];
  latency_budget_ms?: number;
  capabilities?: {
    emits_modify?: boolean;
    needs_state?: boolean;
    needs_raw_payload?: boolean;
    parallel_safe?: boolean;
    supports_batch?: boolean;
    max_payload_kb?: number;
  };
  [key: string]: unknown;
}

export interface GuardrailVersion {
  guardrail_id: string;
  version: string;
  manifest: Manifest;
  status: "validated" | "deprecated";
  source: "gateway" | "api";
  conformance_report: Record<string, unknown> | null;
  created_at: string;
}

export interface Assignment {
  id: string;
  guardrail_id: string;
  guardrail_version: string;
  scope_type: "global" | "tenant" | "agent";
  scope_id: string | null;
  stages: Stage[];
  order: number;
  parallel_group: string | null;
  enabled: boolean;
  mode: "enforce" | "shadow";
  failure_mode: "fail_closed" | "fail_open" | null;
  timeout_ms: number | null;
  config: Record<string, unknown>;
}

export interface AssignmentRecord {
  environment: Environment;
  assignment: Assignment;
  updated_by: string;
  updated_at: string;
}

export interface Diff {
  base_version: string | null;
  added: string[];
  removed: string[];
  changed: string[];
  details?: Record<string, { live: Assignment | null; working: Assignment | null }>;
  at: string;
}

export interface SnapshotDoc {
  version: string;
  environment: Environment;
  assignments: Assignment[];
  published_at?: string | null;
  published_by?: string | null;
  approved_by?: string | null;
}

export interface Snapshot {
  id: string;
  environment: Environment;
  version: string;
  etag: string;
  published_at: string;
  published_by: string;
  approved_by: string | null;
  kind: "publish" | "rollback" | "import";
  rolled_back_from: string | null;
  document?: SnapshotDoc;
}

export type PublishRequestStatus = "pending" | "approved" | "rejected" | "expired" | "stale";

export interface PublishRequest {
  id: string;
  environment: Environment;
  kind: "publish" | "rollback";
  document?: SnapshotDoc;
  base_version: string | null;
  rolled_back_from: string | null;
  requested_by: string;
  requested_by_key: string;
  requested_at: string;
  note: string;
  status: PublishRequestStatus;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string;
  published_version: string | null;
}

export interface PublishOutcome {
  status: "published" | "pending_approval" | "unchanged";
  snapshot: Snapshot | null;
  request: PublishRequest | null;
  warnings: string[];
}

export type ReviewStatus = "pending" | "approved" | "rejected" | "expired";

export interface Review {
  id: string;
  tenant_id: string;
  environment: Environment;
  request_id: string;
  stage: Stage;
  agent_id: string;
  guardrail_id: string;
  reason: string;
  risk_score: number;
  preview: string;
  status: ReviewStatus;
  reviewer: string | null;
  decision_note: string;
  raw_viewed_by: string[];
  created_at: string;
  decided_at: string | null;
  expires_at: string;
  payload?: Record<string, unknown> | null;
}

export interface Gateway {
  gateway_id: string;
  environment: Environment;
  snapshot_version: string | null;
  catalog_version: string | null;
  last_error: string | null;
  installed: string[];
  last_seen: string;
  live: boolean;
}

export interface Change {
  id: number | null;
  entity: string;
  entity_id: string;
  action: string;
  actor: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  at: string;
}

export interface AdminKey {
  id: string;
  name: string;
  prefix: string;
  roles: string[];
  tenant_id: string | null;
  is_active: boolean;
  created_at: string;
}

export interface Analytics {
  environment: Environment | null;
  tenant_id: string | null;
  hours: number;
  bucket: "hour" | "day";
  summary: {
    requests: number;
    by_decision: Partial<Record<Decision, number>>;
    policy_denied: number;
    block_rate: number;
  };
  totals: {
    stage: Stage;
    decision: Decision;
    requests: number;
    avg_latency_ms: number | null;
    p95_latency_ms: number | null;
    policy_denied: number;
  }[];
  rows: {
    guardrail_id: string;
    version: string;
    stage: Stage;
    decision: Decision;
    mode: "enforce" | "shadow";
    n: number;
    avg_latency_ms: number | null;
    p95_latency_ms: number | null;
    errors: number;
  }[];
  timeseries: { bucket: string; decision: Decision; requests: number }[];
}

export interface GuardrailOutcome {
  guardrail_id: string;
  version: string;
  decision: Decision;
  reason: string;
  risk_score: number;
  latency_ms: number;
  mode: string;
  error: string | null;
  findings: { entity_type?: string; start?: number; end?: number; score?: number; path?: string }[];
}

export interface SimulationResult {
  source: "working" | "current";
  snapshot: string;
  warnings: string[];
  result: {
    simulated: boolean;
    environment: Environment;
    simulated_on: Environment;
    snapshot_version: string;
    decision: Decision;
    reason: string;
    risk_score: number;
    trust_score: number;
    policy: { allow: boolean; reason: string; obligations: string[] };
    results: GuardrailOutcome[];
    payload: Record<string, unknown> | null;
  };
}
