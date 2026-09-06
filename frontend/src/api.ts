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

export const api = {
  get: <T>(p: string) => request<T>("GET", p),
  post: <T>(p: string, b?: unknown) => request<T>("POST", p, b),
  patch: <T>(p: string, b?: unknown) => request<T>("PATCH", p, b),
  del: <T>(p: string, b?: unknown) => request<T>("DELETE", p, b),
};

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

export interface NotificationItem {
  id: string;
  kind: string;
  title: string;
  body: string;
  created_at: string;
  read_at: string | null;
}
