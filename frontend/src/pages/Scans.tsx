import { FormEvent, useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError, EmergencyStopStatus, Execution, Target } from "../api";
import { useAuth } from "../auth";

const TERMINAL = ["COMPLETED", "FAILED", "TIMED_OUT", "DENIED", "EXPIRED", "CANCELLED"];
const ACTIVE_ATTESTATION =
  "I attest this scan is authorized and will be used only for ethical, " +
  "non-exploitative reconnaissance";

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
  const [targets, setTargets] = useState<Target[]>([]);
  const [stop, setStop] = useState<EmergencyStopStatus | null>(null);
  const [error, setError] = useState("");

  const [mode, setMode] = useState<"pick" | "type">("pick");
  const [form, setForm] = useState({
    target_id: "",
    target_value: "",
    profile: "PASSIVE",
    rate_choice: "CONSERVATIVE",
    attestation_text: "",
  });

  const load = useCallback(async () => {
    setScans(await api.get<Execution[]>("/api/scans").catch(() => []));
    setTargets(await api.get<Target[]>("/api/targets").catch(() => []));
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

  const targetName = (id: string) => targets.find((t) => t.id === id)?.value ?? id.slice(0, 8);
  const isActiveProfile = form.profile !== "PASSIVE";

  async function submitScan(e: FormEvent) {
    e.preventDefault();
    setError("");
    const body: Record<string, unknown> = {
      profile: form.profile,
      rate_choice: form.rate_choice,
    };
    if (mode === "pick") {
      if (!form.target_id) {
        setError("Choose a target.");
        return;
      }
      body.target_id = form.target_id;
    } else {
      if (!form.target_value.trim()) {
        setError("Type a host, IP, or CIDR.");
        return;
      }
      body.target_value = form.target_value.trim();
    }
    if (isActiveProfile) body.attestation_text = form.attestation_text;
    try {
      await api.post("/api/scans", body);
      setForm({ ...form, target_value: "", attestation_text: "" });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not start the scan");
    }
  }

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

      {isAdmin && stop?.active && (
        <section className="card">
          <p>
            <span className="badge bad status-dot">Emergency stop {stop.active.state}</span>{" "}
            <span className="muted">{stop.active.note}</span>
          </p>
          <button className="secondary" onClick={() => void clearStop(stop.active!.id)}>
            Clear emergency stop
          </button>
        </section>
      )}

      <section className="card">
        <h3>New Scan</h3>
        <p className="muted">
          Defining a target does not queue anything. Choose one of your targets, or type a host,
          IP, or network in CIDR notation. Active profiles need the typed attestation and a fresh
          administrator approval.
        </p>
        <form onSubmit={submitScan}>
          <div className="seg" role="group" aria-label="Target source">
            <button
              type="button"
              className={mode === "pick" ? "on" : ""}
              onClick={() => setMode("pick")}
            >
              Choose a target
            </button>
            <button
              type="button"
              className={mode === "type" ? "on" : ""}
              onClick={() => setMode("type")}
            >
              Type host / IP / CIDR
            </button>
          </div>

          <div className="row" style={{ marginTop: "0.6rem" }}>
            {mode === "pick" ? (
              <div>
                <label htmlFor="tgt">Target</label>
                <select
                  id="tgt"
                  value={form.target_id}
                  onChange={(e) => setForm({ ...form, target_id: e.target.value })}
                >
                  <option value="">Select…</option>
                  {targets
                    .filter((t) => t.is_active)
                    .map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.value} ({t.kind})
                      </option>
                    ))}
                </select>
              </div>
            ) : (
              <div>
                <label htmlFor="tv">Host, IP, or CIDR</label>
                <input
                  id="tv"
                  value={form.target_value}
                  onChange={(e) => setForm({ ...form, target_value: e.target.value })}
                  placeholder="10.10.5.20  ·  10.10.0.0/24  ·  host.lab.example.com"
                />
              </div>
            )}
            <div>
              <label htmlFor="prof">Profile</label>
              <select
                id="prof"
                value={form.profile}
                onChange={(e) => setForm({ ...form, profile: e.target.value })}
              >
                <option value="PASSIVE">Passive</option>
                <option value="SAFE_ACTIVE">Safe active</option>
                <option value="STANDARD_ACTIVE">Standard active</option>
              </select>
            </div>
            {isActiveProfile && (
              <div>
                <label htmlFor="rate">Rate</label>
                <select
                  id="rate"
                  value={form.rate_choice}
                  onChange={(e) => setForm({ ...form, rate_choice: e.target.value })}
                >
                  <option value="CONSERVATIVE">Conservative</option>
                  <option value="MODERATE">Moderate</option>
                </select>
              </div>
            )}
          </div>

          {isActiveProfile && (
            <>
              <label htmlFor="att">Type exactly: “{ACTIVE_ATTESTATION}”</label>
              <textarea
                id="att"
                rows={3}
                value={form.attestation_text}
                onChange={(e) => setForm({ ...form, attestation_text: e.target.value })}
              />
            </>
          )}

          <button
            type="submit"
            style={{ marginTop: "0.7rem" }}
            disabled={isActiveProfile && form.attestation_text.trim() !== ACTIVE_ATTESTATION}
          >
            {isActiveProfile ? "Submit for Approval" : "Start Passive Scan"}
          </button>
        </form>
      </section>

      {isAdmin && !stop?.active && (
        <section className="card">
          <button className="danger" onClick={() => void emergencyStop()}>
            Emergency Stop — Terminate All Active Scans
          </button>
        </section>
      )}

      <section className="card">
        <h3>Scan History</h3>
        <div style={{ overflowX: "auto" }}>
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
                    <Link to={`/targets/${s.target_id}`}>{targetName(s.target_id)}</Link>
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
                    {(s.stages ?? []).map((st) => `${st.stage}${st.ok ? "" : "✗"}`).join(", ")}
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
        </div>
      </section>
    </div>
  );
}
