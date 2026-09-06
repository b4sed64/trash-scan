import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError, EmergencyStopStatus, Execution } from "../api";
import { useAuth } from "../auth";

const TERMINAL = ["COMPLETED", "FAILED", "TIMED_OUT", "DENIED", "EXPIRED", "CANCELLED"];

export function stateBadge(state: string): string {
  if (state === "COMPLETED") return "ok";
  if (["FAILED", "TIMED_OUT", "DENIED", "EXPIRED"].includes(state)) return "bad";
  if (["CANCELLED", "CANCELLING"].includes(state)) return "warn";
  return "";
}

export function Scans() {
  const { me } = useAuth();
  const isAdmin = me?.role === "ADMINISTRATOR";
  const [scans, setScans] = useState<Execution[]>([]);
  const [stop, setStop] = useState<EmergencyStopStatus | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setScans((await api.get<Execution[]>("/api/scans").catch(() => [])) as Execution[]);
    if (isAdmin) {
      setStop(await api.get<EmergencyStopStatus>("/api/emergency-stop").catch(() => null));
    }
  }, [isAdmin]);
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

  async function emergencyStop() {
    if (!window.confirm("Terminate all active scan process groups and block scheduled starts?"))
      return;
    try {
      await api.post("/api/emergency-stop", { scope: "ALL", note: "from Scans view" });
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Emergency stop failed");
    }
  }

  async function clearStop(id: string) {
    await api.post(`/api/emergency-stop/${id}/clear`);
    await load();
  }

  return (
    <div>
      <h2>Scans</h2>
      {error && <p className="error">{error}</p>}

      {isAdmin && (
        <section className="card">
          {stop?.active ? (
            <>
              <p>
                <span className="badge bad status-dot">
                  Emergency stop {stop.active.state}
                </span>{" "}
                <span className="muted">{stop.active.note}</span>
              </p>
              <button className="secondary" onClick={() => void clearStop(stop.active!.id)}>
                Clear emergency stop
              </button>
            </>
          ) : (
            <button className="danger" onClick={() => void emergencyStop()}>
              Emergency stop — terminate all active scans
            </button>
          )}
        </section>
      )}
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
