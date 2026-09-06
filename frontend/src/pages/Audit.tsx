import { useCallback, useEffect, useState } from "react";
import { api, ApiError, AuditEvent } from "../api";
import { useAuth } from "../auth";

interface VerifyResult {
  ok: boolean;
  checked: number;
  total: number;
  failed_seq?: number;
  reason?: string;
}

export function Audit() {
  const { me } = useAuth();
  const isAdmin = me?.role === "ADMINISTRATOR";
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setEvents(await api.get<AuditEvent[]>("/api/audit/events?limit=200"));
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  async function runVerify() {
    setError("");
    try {
      setVerify(await api.post<VerifyResult>("/api/audit/verify"));
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Verification failed");
    }
  }

  return (
    <div>
      <h2>Audit trail</h2>
      <p className="notice">
        This chain is tamper-evident, not tamper-proof. A database or Windows administrator with
        direct storage access can still rewrite history.
      </p>

      {isAdmin && (
        <section className="card">
          <button onClick={() => void runVerify()}>Verify chain now</button>
          {error && <p className="error">{error}</p>}
          {verify && (
            <p>
              <span className={`badge ${verify.ok ? "ok" : "bad"} status-dot`}>
                {verify.ok ? "Chain intact" : "CHAIN VERIFICATION FAILED"}
              </span>{" "}
              <span className="muted">
                checked {verify.checked}/{verify.total}
                {verify.reason ? ` — ${verify.reason} (seq ${verify.failed_seq})` : ""}
              </span>
            </p>
          )}
        </section>
      )}

      <section className="card">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Time (UTC)</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Object</th>
              <th>Hash</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.seq}>
                <td>{e.seq}</td>
                <td className="muted">{new Date(e.ts).toISOString()}</td>
                <td>{e.actor}</td>
                <td>{e.action}</td>
                <td className="muted">
                  {e.object_type}
                  {e.object_id ? `:${e.object_id.slice(0, 8)}` : ""}
                </td>
                <td className="muted" title={e.curr_hash}>
                  {e.curr_hash.slice(0, 12)}…
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
