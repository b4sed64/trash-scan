import { FormEvent, useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  api,
  ApiError,
  Execution,
  ObservationRow,
  OccurrenceRow,
  ScheduleRow,
  Target,
  TimelineEntry,
} from "../api";
import { useAuth } from "../auth";
import { stateBadge } from "./Scans";

interface ScopePreview {
  allowed: boolean;
  reason: string;
  canonical_target: string;
  resolved_addresses: string[];
  matched_deny_rule: string | null;
}
interface Account {
  id: string;
  username: string;
  role: string;
  is_active: boolean;
}

const TERMINAL = ["COMPLETED", "FAILED", "TIMED_OUT", "DENIED", "EXPIRED", "CANCELLED"];

export function TargetDetail() {
  const { id = "" } = useParams();
  const { me } = useAuth();
  const isAdmin = me?.role === "ADMINISTRATOR";
  const navigate = useNavigate();

  const [target, setTarget] = useState<Target | null>(null);
  const [scope, setScope] = useState<ScopePreview | null>(null);
  const [scans, setScans] = useState<Execution[]>([]);
  const [observations, setObservations] = useState<ObservationRow[]>([]);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [schedules, setSchedules] = useState<ScheduleRow[]>([]);
  const [occurrences, setOccurrences] = useState<Record<string, OccurrenceRow[]>>({});
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [assignUser, setAssignUser] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [confirmValue, setConfirmValue] = useState("");
  const [sched, setSched] = useState({
    recurrence: "INTERVAL",
    interval_minutes: 60,
    at_time: "03:00",
    timezone: "UTC",
    overlap_policy: "SKIP",
  });

  const load = useCallback(async () => {
    setTarget(await api.get<Target>(`/api/targets/${id}`));
    setScope(await api.get<ScopePreview>(`/api/targets/${id}/scope-preview`));
    setScans((await api.get<Execution[]>("/api/scans")).filter((s) => s.target_id === id));
    setObservations(await api.get<ObservationRow[]>(`/api/targets/${id}/observations`));
    setTimeline(await api.get<TimelineEntry[]>(`/api/targets/${id}/timeline`));
    const sl = await api.get<ScheduleRow[]>(`/api/targets/${id}/schedules`);
    setSchedules(sl);
    const occ: Record<string, OccurrenceRow[]> = {};
    for (const s of sl) {
      occ[s.id] = await api.get<OccurrenceRow[]>(`/api/schedules/${s.id}/occurrences`);
    }
    setOccurrences(occ);
    if (isAdmin) setAccounts(await api.get<Account[]>("/api/admin/accounts"));
  }, [id, isAdmin]);

  useEffect(() => {
    void load().catch((e) => setError(e instanceof ApiError ? e.message : "Failed to load"));
  }, [load]);

  useEffect(() => {
    if (!scans.some((s) => !TERMINAL.includes(s.state))) return;
    const t = setInterval(() => void load(), 4000);
    return () => clearInterval(t);
  }, [scans, load]);

  async function runPassive() {
    setBusy(true);
    setError("");
    try {
      await api.post(`/api/targets/${id}/scans`, { profile: "PASSIVE" });
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not queue passive discovery");
    } finally {
      setBusy(false);
    }
  }

  async function createSchedule(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const body: Record<string, unknown> = {
        profile: "PASSIVE",
        recurrence: sched.recurrence,
        timezone: sched.timezone,
        overlap_policy: sched.overlap_policy,
      };
      if (sched.recurrence === "INTERVAL") body.interval_minutes = Number(sched.interval_minutes);
      else body.at_time = sched.at_time;
      await api.post(`/api/targets/${id}/schedules`, body);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create schedule");
    }
  }

  const call = (fn: () => Promise<unknown>) => async () => {
    setError("");
    try {
      await fn();
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Request failed");
    }
  };

  async function remove() {
    try {
      await api.post(`/api/targets/${id}/delete`, { confirm_value: confirmValue });
      navigate("/targets");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Delete failed");
    }
  }

  if (!target) return <p>{error || "Loading…"}</p>;
  const scanners = accounts.filter((a) => a.role === "SCANNER");

  return (
    <div>
      <h2>{target.value}</h2>
      <p className="muted">
        {target.kind} · {target.is_public ? "Public (attested)" : "Private"} ·{" "}
        {target.is_active ? "Active" : "Archived"}
      </p>
      {error && <p className="error">{error}</p>}

      {target.attestation && (
        <section className="card">
          <h3>Public-target authorization</h3>
          <p className="muted">
            Attested by user {target.attestation.by} at {target.attestation.at}
          </p>
          <p>“{target.attestation.text}”</p>
        </section>
      )}

      <section className="card">
        <h3>Active-scope check</h3>
        {scope && (
          <>
            <p>
              <span className={`badge ${scope.allowed ? "ok" : "bad"} status-dot`}>
                {scope.allowed ? "Within approved scope" : "Blocked"}
              </span>
            </p>
            <p className="muted">{scope.reason}</p>
            {scope.matched_deny_rule && (
              <p className="error">Matched deny rule: {scope.matched_deny_rule}</p>
            )}
            {scope.resolved_addresses.length > 0 && (
              <p className="muted">Resolved now: {scope.resolved_addresses.join(", ")}</p>
            )}
          </>
        )}
        <p className="notice">
          Phase 2 provides passive discovery (Subfinder, dnsx). Active scanning requires a typed
          attestation and a fresh administrator approval (Phase 3).
        </p>
      </section>

      <section className="card">
        <div style={{ display: "flex", justifyContent: "space-between" }}>
          <h3>Assets ({target.assets.length})</h3>
          <button onClick={() => void runPassive()} disabled={busy || !target.is_active}>
            {busy ? "Queuing…" : "Run passive discovery"}
          </button>
        </div>
        <p className="muted">
          Discovered assets are recorded unapproved and never inherit target authorization.
        </p>
        <table>
          <thead>
            <tr>
              <th>Asset</th>
              <th>Kind</th>
              <th>Source</th>
              <th>In private scope</th>
              <th>Approved</th>
            </tr>
          </thead>
          <tbody>
            {target.assets.map((a) => (
              <tr key={a.id}>
                <td>{a.value}</td>
                <td>{a.kind}</td>
                <td>{a.source}</td>
                <td>{a.in_scope ? "Yes" : "No"}</td>
                <td>
                  <span className={`badge ${a.approved ? "ok" : "warn"}`}>
                    {a.approved ? "Approved" : "Unapproved"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h3>Recent scans</h3>
        <table>
          <thead>
            <tr>
              <th>Created</th>
              <th>Profile</th>
              <th>State</th>
              <th>Stages</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {scans.slice(0, 10).map((s) => (
              <tr key={s.id}>
                <td className="muted">{new Date(s.created_at).toLocaleString()}</td>
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
                    <button
                      className="secondary"
                      onClick={call(() => api.post(`/api/scans/${s.id}/cancel`, { reason: "" }))}
                    >
                      Cancel
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {scans.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  No scans yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h3>Observations ({observations.length})</h3>
        <table>
          <thead>
            <tr>
              <th>Kind</th>
              <th>Key</th>
              <th>Value</th>
              <th>Tool</th>
            </tr>
          </thead>
          <tbody>
            {observations.slice(0, 50).map((o) => (
              <tr key={o.id}>
                <td>{o.kind}</td>
                <td>{o.key}</td>
                <td style={{ wordBreak: "break-all" }}>{o.value}</td>
                <td>{o.source_tool}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h3>Passive schedules</h3>
        <table>
          <thead>
            <tr>
              <th>Recurrence</th>
              <th>Next run</th>
              <th>State</th>
              <th>Recent occurrences</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {schedules.map((s) => (
              <tr key={s.id}>
                <td>
                  {s.recurrence === "INTERVAL"
                    ? `every ${s.interval_minutes} min`
                    : `daily ${s.at_time} ${s.timezone}`}
                </td>
                <td className="muted">
                  {s.next_run_at ? new Date(s.next_run_at).toLocaleString() : "—"}
                </td>
                <td>
                  <span className={`badge ${s.enabled ? "ok" : "warn"}`}>
                    {s.enabled ? "Enabled" : "Disabled"}
                  </span>
                </td>
                <td className="muted">
                  {(occurrences[s.id] ?? [])
                    .slice(0, 4)
                    .map((o) => o.state)
                    .join(", ") || "—"}
                </td>
                <td>
                  <button
                    className="secondary"
                    onClick={call(() =>
                      api.patch(`/api/schedules/${s.id}`, { enabled: !s.enabled }),
                    )}
                  >
                    {s.enabled ? "Disable" : "Enable"}
                  </button>{" "}
                  <button className="danger" onClick={call(() => api.del(`/api/schedules/${s.id}`))}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
            {schedules.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  No schedules.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <form className="row" onSubmit={createSchedule}>
          <div>
            <label>Recurrence</label>
            <select
              value={sched.recurrence}
              onChange={(e) => setSched({ ...sched, recurrence: e.target.value })}
            >
              <option value="INTERVAL">Interval</option>
              <option value="DAILY">Daily</option>
            </select>
          </div>
          {sched.recurrence === "INTERVAL" ? (
            <div>
              <label>Every N minutes (≥ 15)</label>
              <input
                type="number"
                min={15}
                value={sched.interval_minutes}
                onChange={(e) => setSched({ ...sched, interval_minutes: Number(e.target.value) })}
              />
            </div>
          ) : (
            <div>
              <label>At time (HH:MM)</label>
              <input
                value={sched.at_time}
                onChange={(e) => setSched({ ...sched, at_time: e.target.value })}
              />
            </div>
          )}
          <div>
            <label>Timezone</label>
            <input
              value={sched.timezone}
              onChange={(e) => setSched({ ...sched, timezone: e.target.value })}
            />
          </div>
          <button type="submit">Add passive schedule</button>
        </form>
      </section>

      <section className="card">
        <h3>Timeline</h3>
        <ul>
          {timeline
            .slice()
            .reverse()
            .slice(0, 40)
            .map((e, i) => (
              <li key={i}>
                <span className="muted">{new Date(e.at).toLocaleString()} · </span>
                <strong>{e.kind}</strong> — {e.detail}
              </li>
            ))}
        </ul>
      </section>

      {isAdmin && (
        <section className="card">
          <h3>Assignments</h3>
          <ul>
            {target.assignments.map((uid) => {
              const u = accounts.find((a) => a.id === uid);
              return (
                <li key={uid}>
                  {u ? u.username : uid}{" "}
                  <button
                    className="secondary"
                    onClick={call(() => api.del(`/api/targets/${id}/assignments/${uid}`))}
                  >
                    Remove
                  </button>
                </li>
              );
            })}
            {target.assignments.length === 0 && <li className="muted">No scanners assigned.</li>}
          </ul>
          <div className="row">
            <div>
              <label htmlFor="asg">Assign a scanner</label>
              <select id="asg" value={assignUser} onChange={(e) => setAssignUser(e.target.value)}>
                <option value="">Select…</option>
                {scanners.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.username} {s.is_active ? "" : "(disabled)"}
                  </option>
                ))}
              </select>
            </div>
            <button
              onClick={call(() =>
                api.post(`/api/targets/${id}/assignments`, { user_id: assignUser }),
              )}
              disabled={!assignUser}
            >
              Assign
            </button>
          </div>
        </section>
      )}

      {isAdmin && (
        <section className="card">
          <h3>Danger zone</h3>
          <button
            className="secondary"
            onClick={call(() => api.post(`/api/targets/${id}/archive`))}
            disabled={!target.is_active}
          >
            Archive target
          </button>
          <div style={{ marginTop: "1rem" }}>
            <label htmlFor="cv">
              Type the target value <code>{target.value}</code> to permanently delete it and its
              results
            </label>
            <input id="cv" value={confirmValue} onChange={(e) => setConfirmValue(e.target.value)} />
            <button
              className="danger"
              style={{ marginTop: "0.5rem" }}
              disabled={confirmValue !== target.value}
              onClick={() => void remove()}
            >
              Delete target and results
            </button>
          </div>
        </section>
      )}
    </div>
  );
}
