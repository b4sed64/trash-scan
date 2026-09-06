import { FormEvent, useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError, EmergencyStopStatus, Execution, Target } from "../api";
import { useAuth } from "../auth";

const TERMINAL = ["COMPLETED", "FAILED", "TIMED_OUT", "DENIED", "EXPIRED", "CANCELLED"];
const ACTIVE_ATTESTATION =
  "I attest this scan is authorized and will be used only for ethical, " +
  "non-exploitative reconnaissance";

const PROFILE_LABELS: Record<string, string> = {
  PASSIVE: "Passive",
  SAFE_ACTIVE: "Safe Active",
  STANDARD_ACTIVE: "Standard Active",
};
const PRESET_LABELS: Record<string, string> = {
  PROFILE_DEFAULT: "Profile default",
  WEB: "Web ports",
  COMMON: "Common services",
  TOP_1024: "Ports 1–1024",
  CUSTOM: "Custom…",
};

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
  const [presets, setPresets] = useState<Record<string, string>>({});
  const [stop, setStop] = useState<EmergencyStopStatus | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [pickedIds, setPickedIds] = useState<string[]>([]);
  const [typed, setTyped] = useState("");
  const [profile, setProfile] = useState("PASSIVE");
  const [rate, setRate] = useState("CONSERVATIVE");
  const [portPreset, setPortPreset] = useState("PROFILE_DEFAULT");
  const [customPorts, setCustomPorts] = useState("");
  const [attestation, setAttestation] = useState("");

  const load = useCallback(async () => {
    setScans(await api.get<Execution[]>("/api/scans").catch(() => []));
    setTargets(await api.get<Target[]>("/api/targets").catch(() => []));
    if (isAdmin) {
      setStop(await api.get<EmergencyStopStatus>("/api/emergency-stop").catch(() => null));
    }
  }, [isAdmin]);

  useEffect(() => {
    void load();
    void api
      .get<{ presets: Record<string, string> }>("/api/scans/port-presets")
      .then((r) => setPresets(r.presets))
      .catch(() => undefined);
  }, [load]);

  useEffect(() => {
    const active = () => scans.some((s) => !TERMINAL.includes(s.state));
    const id = setInterval(() => active() && void load(), 4000);
    return () => clearInterval(id);
  }, [load, scans]);

  const targetName = (id: string) => targets.find((t) => t.id === id)?.value ?? id.slice(0, 8);
  const isActive = profile !== "PASSIVE";

  function togglePick(id: string) {
    setPickedIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  }

  async function submitScan(e: FormEvent) {
    e.preventDefault();
    setError("");
    setNotice("");
    const values = typed
      .split(/[\n,]/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (pickedIds.length === 0 && values.length === 0) {
      setError("Select at least one target, or type a host, IP, or CIDR.");
      return;
    }
    const body: Record<string, unknown> = {
      target_ids: pickedIds,
      target_values: values,
      profile,
      rate_choice: rate,
    };
    if (isActive) {
      body.attestation_text = attestation;
      body.port_preset = portPreset;
      if (portPreset === "CUSTOM") body.ports = customPorts;
    }
    try {
      const r = await api.post<{ executions: Execution[] }>("/api/scans", body);
      const n = r.executions.length;
      setNotice(
        isActive
          ? `${n} active scan${n === 1 ? "" : "s"} submitted for administrator approval.`
          : `${n} passive scan${n === 1 ? "" : "s"} queued.`,
      );
      setTyped("");
      setPickedIds([]);
      setAttestation("");
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
      {notice && <p className="notice">{notice}</p>}

      {isAdmin && stop?.active && (
        <section className="card">
          <p>
            <span className="badge bad status-dot">Emergency stop {stop.active.state}</span>{" "}
            <span className="muted">{stop.active.note}</span>
          </p>
          <button className="secondary" onClick={() => void clearStop(stop.active!.id)}>
            Clear Emergency Stop
          </button>
        </section>
      )}

      <section className="card">
        <h3>New Scan</h3>
        <p className="muted">
          Defining a target does not queue anything. Pick any of your targets and/or type
          additional hosts, IPs, or networks (CIDR) — one scan runs per target. Active profiles
          need the typed attestation and a fresh administrator approval.
        </p>
        <form onSubmit={submitScan}>
          <label>Select from your targets ({pickedIds.length} selected)</label>
          <div className="chip-row">
            {targets.filter((t) => t.is_active).length === 0 && (
              <span className="muted" style={{ fontSize: "0.85rem" }}>
                No defined targets yet.
              </span>
            )}
            {targets
              .filter((t) => t.is_active)
              .map((t) => (
                <button
                  key={t.id}
                  type="button"
                  className={`chip ${pickedIds.includes(t.id) ? "on" : ""}`}
                  aria-pressed={pickedIds.includes(t.id)}
                  onClick={() => togglePick(t.id)}
                >
                  {t.value}
                </button>
              ))}
          </div>

          <label htmlFor="typed" style={{ marginTop: "0.7rem" }}>
            …and/or type hosts, IPs, or CIDRs (one per line or comma-separated)
          </label>
          <textarea
            id="typed"
            rows={2}
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder="10.10.5.20&#10;10.10.0.0/24&#10;host.lab.example.com"
          />

          <div className="row" style={{ marginTop: "0.7rem" }}>
            <div>
              <label htmlFor="prof">Profile</label>
              <select id="prof" value={profile} onChange={(e) => setProfile(e.target.value)}>
                {Object.entries(PROFILE_LABELS).map(([v, l]) => (
                  <option key={v} value={v}>
                    {l}
                  </option>
                ))}
              </select>
            </div>
            {isActive && (
              <>
                <div>
                  <label htmlFor="rate">Rate</label>
                  <select id="rate" value={rate} onChange={(e) => setRate(e.target.value)}>
                    <option value="CONSERVATIVE">Conservative</option>
                    <option value="MODERATE">Moderate</option>
                  </select>
                </div>
                <div>
                  <label htmlFor="pp">Ports</label>
                  <select id="pp" value={portPreset} onChange={(e) => setPortPreset(e.target.value)}>
                    {["PROFILE_DEFAULT", "WEB", "COMMON", "TOP_1024", "CUSTOM"].map((k) => (
                      <option key={k} value={k} title={presets[k] || ""}>
                        {PRESET_LABELS[k]}
                        {presets[k] ? ` — ${presets[k]}` : ""}
                      </option>
                    ))}
                  </select>
                </div>
              </>
            )}
          </div>

          {isActive && portPreset === "CUSTOM" && (
            <>
              <label htmlFor="cp">Custom ports (e.g. 22,80,443,8000-8100)</label>
              <input
                id="cp"
                value={customPorts}
                onChange={(e) => setCustomPorts(e.target.value)}
                placeholder="22,80,443,8000-8100"
              />
            </>
          )}

          {isActive && (
            <>
              <label htmlFor="att">Type exactly: “{ACTIVE_ATTESTATION}”</label>
              <textarea
                id="att"
                rows={3}
                value={attestation}
                onChange={(e) => setAttestation(e.target.value)}
              />
            </>
          )}

          <button
            type="submit"
            style={{ marginTop: "0.7rem" }}
            disabled={isActive && attestation.trim() !== ACTIVE_ATTESTATION}
          >
            {isActive ? "Submit for Approval" : "Start Passive Scan"}
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
                    {PROFILE_LABELS[s.profile] ?? s.profile}
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
