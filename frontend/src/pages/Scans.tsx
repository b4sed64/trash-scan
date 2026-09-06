import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError, Execution } from "../api";

const TERMINAL = ["COMPLETED", "FAILED", "TIMED_OUT", "DENIED", "EXPIRED", "CANCELLED"];

export function stateBadge(state: string): string {
  if (state === "COMPLETED") return "ok";
  if (["FAILED", "TIMED_OUT", "DENIED", "EXPIRED"].includes(state)) return "bad";
  if (["CANCELLED", "CANCELLING"].includes(state)) return "warn";
  return "";
}

export function Scans() {
  const [scans, setScans] = useState<Execution[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(
    () => api.get<Execution[]>("/api/scans").then(setScans).catch(() => undefined),
    [],
  );
  useEffect(() => {
    void load();
    const active = () => scans.some((s) => !TERMINAL.includes(s.state));
    const id = setInterval(() => active() && void load(), 4000);
    return () => clearInterval(id);
  }, [load, scans]);

  async function cancel(id: string) {
    try {
      await api.post(`/api/scans/${id}/cancel`, { reason: "cancelled from Scans view" });
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Cancel failed");
    }
  }

  return (
    <div>
      <h2>Scans</h2>
      {error && <p className="error">{error}</p>}
      <section className="card">
        <table>
          <thead>
            <tr>
              <th>Started</th>
              <th>Target</th>
              <th>Profile</th>
              <th>State</th>
              <th>Stages</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id}>
                <td className="muted">{new Date(s.created_at).toLocaleString()}</td>
                <td>
                  <Link to={`/targets/${s.target_id}`}>{s.target_id.slice(0, 8)}</Link>
                </td>
                <td>
                  {s.profile}
                  {s.schedule_id ? " · scheduled" : ""}
                </td>
                <td>
                  <span className={`badge ${stateBadge(s.state)} status-dot`}>{s.state}</span>
                  {s.partial && <span className="badge warn"> partial</span>}
                </td>
                <td className="muted">
                  {(s.stages ?? [])
                    .map((st) => `${st.stage}${st.ok ? "" : "✗"}`)
                    .join(", ")}
                </td>
                <td>
                  {!TERMINAL.includes(s.state) && (
                    <button className="secondary" onClick={() => void cancel(s.id)}>
                      Cancel
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {scans.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  No scans yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
