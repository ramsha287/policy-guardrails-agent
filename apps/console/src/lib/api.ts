// Typed client for the control-plane API. Every call sends the admin key in X-Admin-Key; the
// console never talks to any other origin (the CSP enforces connect-src 'self').

import type {
  ActionRule,
  AdminKey,
  Agent,
  Analytics,
  ApiKey,
  Assignment,
  AssignmentRecord,
  Change,
  CreatedApiKey,
  DataClassification,
  Diff,
  Environment,
  Gateway,
  GuardrailVersion,
  Me,
  Modifier,
  PublishOutcome,
  PublishRequest,
  Review,
  ReviewStatus,
  SimulationResult,
  Snapshot,
  Stage,
  Tenant,
} from "./types";

export const API_PREFIX = "/cp/v1";

export class ApiError extends Error {
  readonly status: number;
  readonly errors: string[];
  readonly warnings: string[];

  constructor(status: number, message: string, errors: string[] = [], warnings: string[] = []) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.errors = errors;
    this.warnings = warnings;
  }
}

type Fetch = (input: string, init?: RequestInit) => Promise<Response>;
type Query = Record<string, string | number | boolean | null | undefined>;

export function queryString(params: Query = {}): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  }
  const s = q.toString();
  return s ? `?${s}` : "";
}

/** Turns an error body ({error, errors, warnings} or FastAPI's {detail}) into an ApiError. */
export async function toApiError(res: Response): Promise<ApiError> {
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    // not JSON (proxy error page etc.)
  }
  const obj = (body && typeof body === "object" ? body : {}) as Record<string, unknown>;
  const raw = obj.error ?? obj.detail;
  let message: string;
  if (typeof raw === "string") message = raw;
  else if (raw && typeof raw === "object" && "error" in raw) message = String((raw as { error: unknown }).error);
  else message = res.statusText || `HTTP ${res.status}`;
  const list = (v: unknown) => (Array.isArray(v) ? v.map(String) : []);
  return new ApiError(res.status, message, list(obj.errors), list(obj.warnings));
}

export class Api {
  constructor(
    private readonly key: string,
    private readonly fetchFn: Fetch = (input, init) => fetch(input, init),
    private readonly onUnauthorized: () => void = () => {},
  ) {}

  async request<T>(method: string, path: string, body?: unknown, query?: Query): Promise<T> {
    const headers: Record<string, string> = { "X-Admin-Key": this.key, Accept: "application/json" };
    const init: RequestInit = { method, headers, credentials: "omit", cache: "no-store" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const res = await this.fetchFn(`${API_PREFIX}${path}${queryString(query)}`, init);
    if (res.status === 401) this.onUnauthorized();
    if (!res.ok) throw await toApiError(res);
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }

  private get<T>(path: string, query?: Query) {
    return this.request<T>("GET", path, undefined, query);
  }

  // ---- identity
  me() {
    return this.get<Me>("/me");
  }

  // ---- review queue
  reviews(filter: { status?: ReviewStatus | ""; tenant_id?: string } = {}) {
    return this.get<Review[]>("/reviews", filter);
  }
  review(id: string, includeRaw = false) {
    return this.get<Review>(`/reviews/${encodeURIComponent(id)}`, includeRaw ? { include_raw: true } : undefined);
  }
  decideReview(id: string, approve: boolean, note: string) {
    return this.request<Review>("POST", `/reviews/${encodeURIComponent(id)}/${approve ? "approve" : "reject"}`, {
      note,
    });
  }

  // ---- pipeline
  assignments(env: Environment) {
    return this.get<AssignmentRecord[]>(`/environments/${env}/assignments`);
  }
  putAssignment(env: Environment, a: Partial<Assignment> & { id: string }) {
    return this.request<AssignmentRecord>("PUT", `/environments/${env}/assignments/${encodeURIComponent(a.id)}`, a);
  }
  patchAssignment(env: Environment, id: string, patch: Partial<Assignment>) {
    return this.request<AssignmentRecord>("PATCH", `/environments/${env}/assignments/${encodeURIComponent(id)}`, patch);
  }
  deleteAssignment(env: Environment, id: string) {
    return this.request<void>("DELETE", `/environments/${env}/assignments/${encodeURIComponent(id)}`);
  }
  diff(env: Environment) {
    return this.get<Diff>(`/environments/${env}/diff`);
  }
  publish(env: Environment, note: string, force = false) {
    return this.request<PublishOutcome>("POST", `/environments/${env}/publish`, { note, force });
  }
  rollback(env: Environment, version: string, note: string) {
    return this.request<PublishOutcome>("POST", `/environments/${env}/rollback`, { version, note });
  }
  snapshots(env: Environment, limit = 50) {
    return this.get<Snapshot[]>(`/environments/${env}/snapshots`, { limit });
  }
  currentSnapshot(env: Environment) {
    return this.get<Snapshot>(`/environments/${env}/snapshots/current`);
  }
  snapshot(env: Environment, version: string) {
    return this.get<Snapshot>(`/environments/${env}/snapshots/${encodeURIComponent(version)}`);
  }
  publishRequests(filter: { environment?: Environment | ""; status?: string } = {}) {
    return this.get<PublishRequest[]>("/publish-requests", filter);
  }
  decidePublishRequest(id: string, approve: boolean, note: string) {
    return this.request<unknown>("POST", `/publish-requests/${encodeURIComponent(id)}/${approve ? "approve" : "reject"}`, {
      note,
    });
  }

  // ---- registry
  guardrails() {
    return this.get<GuardrailVersion[]>("/guardrails");
  }
  registerGuardrail(manifestYaml: string) {
    return this.request<GuardrailVersion>("POST", "/guardrails/versions", { manifest_yaml: manifestYaml });
  }
  deprecate(id: string, version: string) {
    return this.request<GuardrailVersion>(
      "POST",
      `/guardrails/${encodeURIComponent(id)}/versions/${encodeURIComponent(version)}/deprecate`,
    );
  }

  // ---- catalog
  tenants() {
    return this.get<Tenant[]>("/tenants");
  }
  createTenant(id: string, name: string) {
    return this.request<Tenant>("POST", "/tenants", { id, name });
  }
  setTenantStatus(id: string, status: Tenant["status"]) {
    return this.request<Tenant>("PATCH", `/tenants/${encodeURIComponent(id)}`, { status });
  }
  apiKeys(tenant: string) {
    return this.get<ApiKey[]>(`/tenants/${encodeURIComponent(tenant)}/api-keys`);
  }
  createApiKey(
    tenant: string,
    body: {
      name: string;
      scopes?: string[];
      environments?: Environment[] | null;
      expires_at?: string | null;
      rate_limit_per_minute?: number | null;
    },
  ) {
    return this.request<CreatedApiKey>("POST", `/tenants/${encodeURIComponent(tenant)}/api-keys`, body);
  }
  setApiKeyRateLimit(tenant: string, keyId: string, perMinute: number | null) {
    return this.request<ApiKey>(
      "PATCH",
      `/tenants/${encodeURIComponent(tenant)}/api-keys/${encodeURIComponent(keyId)}`,
      { rate_limit_per_minute: perMinute },
    );
  }
  revokeApiKey(tenant: string, keyId: string) {
    return this.request<ApiKey>(
      "DELETE",
      `/tenants/${encodeURIComponent(tenant)}/api-keys/${encodeURIComponent(keyId)}`,
    );
  }
  agents(tenant: string) {
    return this.get<Agent[]>(`/tenants/${encodeURIComponent(tenant)}/agents`);
  }
  putAgent(tenant: string, agentId: string, body: { base_trust_score: number; allowed_tools: string[]; owner?: string | null }) {
    return this.request<Agent>(
      "PUT",
      `/tenants/${encodeURIComponent(tenant)}/agents/${encodeURIComponent(agentId)}`,
      body,
    );
  }
  deleteAgent(tenant: string, agentId: string) {
    return this.request<void>("DELETE", `/tenants/${encodeURIComponent(tenant)}/agents/${encodeURIComponent(agentId)}`);
  }
  actions(tenant: string) {
    return this.get<ActionRule[]>(`/tenants/${encodeURIComponent(tenant)}/actions`);
  }
  putAction(tenant: string, body: { action: string; resource_pattern: string; base_risk_score: number }) {
    return this.request<ActionRule>("PUT", `/tenants/${encodeURIComponent(tenant)}/actions`, body);
  }
  deleteAction(tenant: string, id: string) {
    return this.request<void>("DELETE", `/tenants/${encodeURIComponent(tenant)}/actions/${encodeURIComponent(id)}`);
  }
  modifiers(tenant: string) {
    return this.get<Modifier[]>(`/tenants/${encodeURIComponent(tenant)}/modifiers`);
  }
  putModifier(tenant: string, body: { kind: Modifier["kind"]; value: string; delta: number }) {
    return this.request<Modifier>("PUT", `/tenants/${encodeURIComponent(tenant)}/modifiers`, body);
  }
  deleteModifier(tenant: string, id: string) {
    return this.request<void>("DELETE", `/tenants/${encodeURIComponent(tenant)}/modifiers/${encodeURIComponent(id)}`);
  }

  // ---- operations
  gateways(env: Environment) {
    return this.get<Gateway[]>(`/environments/${env}/gateways`);
  }
  changes(filter: { entity?: string; entity_id?: string; limit?: number } = {}) {
    return this.get<Change[]>("/changes", filter);
  }
  adminKeys() {
    return this.get<AdminKey[]>("/admin-keys");
  }
  createAdminKey(body: { name: string; roles: string[]; tenant_id?: string | null }) {
    return this.request<AdminKey & { key: string }>("POST", "/admin-keys", body);
  }
  revokeAdminKey(id: string) {
    return this.request<void>("DELETE", `/admin-keys/${encodeURIComponent(id)}`);
  }
  analytics(filter: { environment?: Environment | ""; tenant_id?: string; hours?: number } = {}) {
    return this.get<Analytics>("/analytics/guardrails", filter);
  }
  simulate(body: {
    environment: Environment;
    source: "working" | "current";
    tenant_id: string;
    stage: Stage;
    request: {
      agent_id: string;
      action: string;
      resource?: string | null;
      user_id?: string | null;
      data_classification: DataClassification;
      payload: Record<string, unknown>;
    };
  }) {
    return this.request<SimulationResult>("POST", "/simulate", body);
  }
}
