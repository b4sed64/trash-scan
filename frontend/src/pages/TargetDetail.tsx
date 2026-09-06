import { FormEvent, useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  api,
  ApiError,
  ComparisonResult,
  FindingRow,
  ObservationRow,
  OccurrenceRow,
  ReportRow,
  ScanGroup,
  ScheduleRow,
  ServiceRow,
  Target,
  TimelineEntry,
} from "../api";

const CLASS_LABEL: Record<string, string> = {
  NEW: "bad",
  CHANGED: "warn",
  STILL_OBSERVED: "",
  NOT_OBSERVED: "ok",
};

const ACTIVE_ATTESTATION =
  "I attest this scan is authorized and will be used only for ethical, " +
  "non-exploitative reconnaissance";
import { useAuth } from "../auth";
import { PauseIcon, PlayIcon, StopIcon } from "../components/icons";
import { stateBadge, stateLabel } from "./Scans";

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
const LIVE = ["QUEUED", "RUNNING", "CANCELLING"];

export function TargetDetail() {
  const { id = "" } = useParams();
  const { me } = useAuth();
  const isAdmin = me?.role === "ADMINISTRATOR";
  const navigate = useNavigate();

  const [target, setTarget] = useState<Target | null>(null);
  const [scope, setScope] = useState<ScopePreview | null>(null);
  const [scans, setScans] = useState<ScanGroup[]>([]);
  const [observations, setObservations] = useState<ObservationRow[]>([]);
  const [services, setServices] = useState<ServiceRow[]>([]);
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const [reports, setReports] = useState<ReportRow[]>([]);
  const [comparison, setComparison] = useState<ComparisonResult | null>(null);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [active, setActive] = useState({
    profile: "SAFE_ACTIVE",
    rate_choice: "CONSERVATIVE",
    attestation_text: "",
  });
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
    setScans(
      (await api.get<ScanGroup[]>("/api/scans")).filter((s) =>
        s.targets.some((t) => t.id === id),
      ),
    );
    setObservations(await api.get<ObservationRow[]>(`/api/targets/${id}/observations`));
    setServices(await api.get<ServiceRow[]>(`/api/targets/${id}/services`));
    setFindings(await api.get<FindingRow[]>(`/api/targets/${id}/findings`));
    setReports(await api.get<ReportRow[]>(`/api/targets/${id}/reports`).catch(() => []));
    setComparison(
      await api
        .get<ComparisonResult>(`/api/targets/${id}/comparison`)
        .catch(() => null),
    );
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
    if (!scans.some((s) => LIVE.includes(s.state))) return;
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

  async function makeReport(format: "PDF" | "CSV_ZIP") {
    setError("");
    try {
      await api.post(`/api/targets/${id}/reports`, { format });
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Report generation failed");
    }
  }

  async function requestActive(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api.post(`/api/targets/${id}/scans`, {
        profile: active.profile,
        rate_choice: active.rate_choice,
        attestation_text: active.attestation_text,
      });
      setActive({ ...active, attestation_text: "" });
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not submit active scan request");
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
          <h3>Public-Target Authorization</h3>
          <p className="muted">
            Attested by user {target.attestation.by} at {target.attestation.at}
          </p>
          <p>“{target.attestation.text}”</p>
        </section>
      )}

      <section className="card">
        <h3>Active-Scope Check</h3>
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
            {busy ? "Queuing…" : "Run Passive Discovery"}
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
        <h3>Request an Active Scan</h3>
        <p className="notice">
          Active scanning sends observable traffic. It requires this typed attestation and a
          fresh administrator approval before anything runs. SYN scan and OS detection only
          run where the deployment has proven raw-packet capability.
        </p>
        <form onSubmit={requestActive}>
          <div className="row">
            <div>
              <label>Profile</label>
              <select
                value={active.profile}
                onChange={(e) => setActive({ ...active, profile: e.target.value })}
              >
                <option value="SAFE_ACTIVE">Safe Active</option>
                <option value="STANDARD_ACTIVE">Standard Active</option>
              </select>
            </div>
            <div>
              <label>Rate</label>
              <select
                value={active.rate_choice}
                onChange={(e) => setActive({ ...active, rate_choice: e.target.value })}
              >
                <option value="CONSERVATIVE">Conservative</option>
                <option value="MODERATE">Moderate</option>
              </select>
            </div>
          </div>
          <label htmlFor="att">Type exactly: “{ACTIVE_ATTESTATION}”</label>
          <textarea
            id="att"
            rows={3}
            value={active.attestation_text}
            onChange={(e) => setActive({ ...active, attestation_text: e.target.value })}
          />
          <button
            type="submit"
            style={{ marginTop: "0.6rem" }}
            disabled={active.attestation_text.trim() !== ACTIVE_ATTESTATION || !target.is_active}
          >
            Submit for Approval
          </button>
        </form>
      </section>

      <section className="card">
        <h3>Services ({services.length})</h3>
        <table>
          <thead>
            <tr>
              <th>Port</th>
              <th>Proto</th>
              <th>State</th>
              <th>Product</th>
              <th>Version</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {services.map((s) => (
              <tr key={s.id}>
                <td>{s.port}</td>
                <td>{s.protocol}</td>
                <td>{s.state}</td>
                <td>{s.product || "—"}</td>
                <td>{s.version || "—"}</td>
                <td className="muted">{s.confidence || "—"}</td>
              </tr>
            ))}
            {services.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  No services observed yet (run an approved active scan).
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h3>Findings ({findings.length})</h3>
        <p className="notice">
          Automated findings are <strong>indicators that require human validation</strong>, not
          proof of exploitability. "Not observed" means only that the latest compatible scan
          did not see it — never that it is resolved.
        </p>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Finding</th>
              <th>Asset</th>
              <th>Status</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td>
                  <span className={`sev-tag sev-${f.severity}`}>{f.severity}</span>
                </td>
                <td title={f.rule_id}>{f.name}</td>
                <td>
                  {f.asset_value}
                  {f.port ? `:${f.port}` : ""}
                </td>
                <td>
                  <span className={`badge ${f.status === "NOT_OBSERVED" ? "ok" : ""}`}>
                    {f.status}
                  </span>
                </td>
                <td className="muted" style={{ wordBreak: "break-all" }}>
                  {f.evidence_summary}
                </td>
              </tr>
            ))}
            {findings.length === 0 && (
              <tr>
                <td colSpan={5} className="muted">
                  No findings (run an approved active scan).
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      {comparison && (
        <section className="card">
          <h3>Change Since Previous Compatible Scan</h3>
          {!comparison.eligible ? (
            <p className="muted">
              {comparison.summary.note ?? "No compatible baseline scan yet."}
            </p>
          ) : (
            <>
              <p>
                {(["NEW", "CHANGED", "STILL_OBSERVED", "NOT_OBSERVED"] as const).map((k) => (
                  <span key={k} className={`badge ${CLASS_LABEL[k]}`} style={{ marginRight: 6 }}>
                    {k.replace("_", " ")}: {comparison.summary.counts?.[k] ?? 0}
                  </span>
                ))}
              </p>
              {comparison.limitations.length > 0 && (
                <ul className="muted">
                  {comparison.limitations.map((l, i) => (
                    <li key={i}>{l}</li>
                  ))}
                </ul>
              )}
              <table>
                <thead>
                  <tr>
                    <th>Classification</th>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>Asset</th>
                  </tr>
                </thead>
                <tbody>
                  {comparison.details.map((d) => (
                    <tr key={d.finding_id}>
                      <td>
                        <span className={`badge ${CLASS_LABEL[d.classification] ?? ""}`}>
                          {d.classification.replace("_", " ")}
                        </span>
                      </td>
                      <td>{d.severity}</td>
                      <td>{d.name}</td>
                      <td>{d.asset}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </section>
      )}

      <section className="card">
        <h3>Recent Scans</h3>
        <table>
          <thead>
            <tr>
              <th>Created</th>
              <th>Profile</th>
              <th>Scan State</th>
              <th>This Target</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {scans.slice(0, 10).map((s) => {
              const here = s.targets.find((t) => t.id === id);
              return (
                <tr key={s.scan_id}>
                  <td className="muted">{new Date(s.created_at).toLocaleString()}</td>
                  <td>
                    {s.profile}
                    {s.schedule_id ? " · scheduled" : ""}
                    {s.target_count > 1 ? ` · ${s.target_count} Targets` : ""}
                  </td>
                  <td>
                    <Link to={`/scans/${s.scan_id}`}>
                      <span className={`badge ${stateBadge(s.state)} status-dot`}>
                        {stateLabel(s.state)}
                      </span>
                    </Link>
                  </td>
                  <td>
                    <span className={`badge ${stateBadge(here?.state ?? "")}`}>
                      {here ? stateLabel(here.state) : "—"}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: "flex", gap: "0.4rem", flexWrap: "wrap" }}>
                      {(s.state === "APPROVED" || s.state === "DRAFT") && (
                        <button
                          className="pill-btn"
                          onClick={call(() => api.post(`/api/scans/${s.scan_id}/start`))}
                        >
                          <PlayIcon /> Start
                        </button>
                      )}
                      {s.state === "QUEUED" && (
                        <button
                          className="pill-btn secondary"
                          onClick={call(() => api.post(`/api/scans/${s.scan_id}/pause`))}
                        >
                          <PauseIcon /> Pause
                        </button>
                      )}
                      {!TERMINAL.includes(s.state) && (
                        <button
                          className="pill-btn secondary"
                          onClick={call(() =>
                            api.post(`/api/scans/${s.scan_id}/stop`, { reason: "" }),
                          )}
                        >
                          <StopIcon /> Stop
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
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
        <h3>Passive Schedules</h3>
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
          <button type="submit">Add Passive Schedule</button>
        </form>
      </section>

      <section className="card">
        <h3>Reports &amp; Exports</h3>
        <div className="row">
          <button onClick={() => void makeReport("PDF")}>Generate PDF Report</button>
          <button className="secondary" onClick={() => void makeReport("CSV_ZIP")}>
            Export CSV (.zip)
          </button>
        </div>
        <table>
          <thead>
            <tr>
              <th>Created</th>
              <th>Format</th>
              <th>File</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {reports.map((r) => (
              <tr key={r.id}>
                <td className="muted">{new Date(r.created_at).toLocaleString()}</td>
                <td>{r.format}</td>
                <td>{r.filename}</td>
                <td>
                  <button
                    className="secondary"
                    onClick={() =>
                      void api
                        .download(`/api/reports/${r.id}/download`, r.filename)
                        .catch((e) =>
                          setError(e instanceof ApiError ? e.message : "Download failed"),
                        )
                    }
                  >
                    Download
                  </button>
                </td>
              </tr>
            ))}
            {reports.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  No reports for this target yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
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
          <h3>Danger Zone</h3>
          <button
            className="secondary"
            onClick={call(() => api.post(`/api/targets/${id}/archive`))}
            disabled={!target.is_active}
          >
            Archive Target
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
              Delete Target and Results
            </button>
          </div>
        </section>
      )}
    </div>
  );
}
