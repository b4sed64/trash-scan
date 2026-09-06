// Thin API client. Sends the CSRF token from the non-HttpOnly cookie on every
// unsafe request (double-submit) and always includes credentials.

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)trashscan_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && method !== "HEAD") headers["X-CSRF-Token"] = csrfToken();

  const res = await fetch(path, {
    method,
    headers,
    credentials: "include",
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const detail = data && typeof data.detail === "string" ? data.detail : res.statusText;
    throw new ApiError(res.status, detail);
  }
  return data as T;
}

function csrfHeader(): Record<string, string> {
  return { "X-CSRF-Token": csrfToken() };
}

async function downloadFile(path: string, fallbackName: string): Promise<void> {
  const res = await fetch(path, { method: "GET", credentials: "include", headers: csrfHeader() });
  if (!res.ok) {
    throw new ApiError(res.status, `download failed (${res.status})`);
  }
  const blob = await res.blob();
  const disposition = res.headers.get("Content-Disposition") ?? "";
  const match = disposition.match(/filename="?([^"]+)"?/);
  const name = match ? match[1] : fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export const api = {
  get: <T>(p: string) => request<T>("GET", p),
  post: <T>(p: string, b?: unknown) => request<T>("POST", p, b),
  patch: <T>(p: string, b?: unknown) => request<T>("PATCH", p, b),
  del: <T>(p: string, b?: unknown) => request<T>("DELETE", p, b),
  download: downloadFile,
};

export interface ReportRow {
  id: string;
  kind: string;
  format: string;
  target_id: string | null;
  execution_id: string | null;
  filename: string;
  size_bytes: number;
  created_at: string;
  requested_by_id: string | null;
}

// --- shared types ---
export interface Me {
  id: string;
  username: string;
  role: "ADMINISTRATOR" | "SCANNER";
  csrf_token: string;
}

export interface Asset {
  id: string;
  kind: string;
  value: string;
  source: string;
  approved: boolean;
  in_scope: boolean;
  first_seen_at: string;
  last_seen_at: string;
}

export interface Target {
  id: string;
  kind: string;
  value: string;
  is_public: boolean;
  is_active: boolean;
  note: string;
  created_at: string;
  attestation: { text: string; by: string; at: string } | null;
  assignments: string[];
  assets: Asset[];
}

export interface AuditEvent {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  object_type: string;
  object_id: string;
  payload: Record<string, unknown>;
  prev_hash: string;
  curr_hash: string;
}

export interface Execution {
  id: string;
  target_id: string;
  profile: string;
  classification: string;
  state: string;
  requested_by_id: string | null;
  schedule_id: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  runtime_deadline_at: string | null;
  cancel_requested: boolean;
  partial: boolean;
  error: string | null;
  stages: { stage: string; tool: string; ok: boolean; incomplete: boolean; note: string }[] | null;
  tool_versions: Record<string, string> | null;
  parser_version: string;
}

export interface ObservationRow {
  id: string;
  kind: string;
  key: string;
  value: string;
  source_tool: string;
  first_seen_at: string;
  last_seen_at: string;
}

export interface TimelineEntry {
  at: string;
  kind: string;
  detail: string;
  ref: string;
}

export interface ScheduleRow {
  id: string;
  target_id: string;
  profile: string;
  classification: string;
  recurrence: string;
  interval_minutes: number | null;
  at_time: string | null;
  timezone: string;
  enabled: boolean;
  overlap_policy: string;
  next_run_at: string | null;
  last_run_at: string | null;
  created_by_id: string | null;
}

export interface OccurrenceRow {
  id: string;
  scheduled_for: string;
  state: string;
  execution_id: string | null;
  note: string;
}

export interface ServiceRow {
  id: string;
  asset_id: string | null;
  port: number;
  protocol: string;
  state: string;
  product: string;
  version: string;
  confidence: string;
  first_seen_at: string;
  last_seen_at: string;
}

export interface Approval {
  id: string;
  execution_id: string;
  state: string;
  profile: string;
  target: { id: string; value: string; kind: string } | null;
  requested_by: string | null;
  attestation_text: string;
  requested_options: Record<string, unknown>;
  scope_at_request: {
    allowed?: boolean;
    reason?: string;
    resolved_addresses?: string[];
    matched_deny_rule?: string | null;
  };
  created_at: string;
  expires_at: string | null;
  decided_by_id: string | null;
  decided_at: string | null;
  decision_reason: string | null;
  execution_state: string | null;
  schedule_id: string | null;
}

export interface EmergencyStopStatus {
  active: {
    id: string;
    state: string;
    target_scope: string;
    note: string;
    requested_at: string;
  } | null;
  history: { id: string; state: string; note: string; requested_at: string }[];
}

export interface FindingRow {
  id: string;
  rule_id: string;
  source_tool: string;
  severity: string;
  name: string;
  description: string;
  asset_value: string;
  port: number | null;
  status: string;
  evidence_summary: string;
  first_seen_at: string;
  last_seen_at: string;
  requires_validation: boolean;
}

export interface ComparisonResult {
  execution_id: string;
  baseline_execution_id: string | null;
  eligible: boolean;
  summary: {
    counts?: Record<string, number>;
    by_severity?: Record<string, number>;
    total_findings?: number;
    note?: string;
  };
  limitations: string[];
  details: {
    finding_id: string;
    rule_id: string;
    name: string;
    severity: string;
    asset: string;
    classification: string;
    evidence_summary: string;
  }[];
  created_at?: string;
}

export interface NotificationItem {
  id: string;
  kind: string;
  title: string;
  body: string;
  created_at: string;
  read_at: string | null;
}
