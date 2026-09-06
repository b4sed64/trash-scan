import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, ApiError, ScanGroupDetail } from "../api";
import { stateBadge } from "./Scans";

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
const SEV_VAR: Record<string, string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
  INFO: "var(--sev-info)",
};
const PROFILE_LABELS: Record<string, string> = {
  PASSIVE: "Passive",
  SAFE_ACTIVE: "Safe Active",
  STANDARD_ACTIVE: "Standard Active",
};
const TERMINAL = ["COMPLETED", "FAILED", "TIMED_OUT", "DENIED", "EXPIRED", "CANCELLED", "PARTIAL"];

export function ScanDetail() {
  const { id = "" } = useParams();
  const [scan, setScan] = useState<ScanGroupDetail | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setScan(await api.get<ScanGroupDetail>(`/api/scans/${id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load the scan");
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!scan || TERMINAL.includes(scan.state)) return;
    const t = setInterval(() => void load(), 4000);
    return () => clearInterval(t);
  }, [scan, load]);

  async function control(verb: "start" | "stop") {
    setError("");
    try {
      await api.post(`/api/scans/${id}/${verb}`, verb === "stop" ? { reason: "stopped from scan view" } : undefined);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : `${verb} failed`);
    }
  }

  if (error && !scan) return <p className="error">{error}</p>;
  if (!scan) return <p className="muted">Loading scan…</p>;

  const counts = scan.summary.severity_counts;
  const total = scan.summary.total_findings;
  const canStart = scan.state === "APPROVED";
  const canStop = !TERMINAL.includes(scan.state);

  return (
    <div>
      <h2>
        Scan {scan.scan_id.slice(0, 8)} —{" "}
        <span className={`badge ${stateBadge(scan.state)} status-dot`}>{scan.state}</span>
      </h2>
      {error && <p className="error">{error}</p>}
      <p className="muted">
        <Link to="/scans">← All Scans</Link>
      </p>

      <section className="card">
        <div className="row" style={{ alignItems: "flex-start" }}>
          <div>
            <div className="muted">Profile</div>
            <div>
              {PROFILE_LABELS[scan.profile] ?? scan.profile}
              {scan.schedule_id ? " · scheduled" : ""}
            </div>
          </div>
          <div>
            <div className="muted">Targets</div>
            <div>{scan.target_count}</div>
          </div>
          <div>
            <div className="muted">Created</div>
            <div>{new Date(scan.created_at).toLocaleString()}</div>
          </div>
          <div>
            <div className="muted">Started</div>
            <div>{scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}</div>
          </div>
          <div>
            <div className="muted">Finished</div>
            <div>{scan.finished_at ? new Date(scan.finished_at).toLocaleString() : "—"}</div>
          </div>
        </div>

        {scan.approval && (
          <p className="muted" style={{ marginTop: "0.7rem" }}>
            Approval: {scan.approval.state}
            {scan.approval.expires_at
              ? ` · press Start before ${new Date(scan.approval.expires_at).toLocaleString()}`
              : ""}
            {scan.approval.decision_reason ? ` · ${scan.approval.decision_reason}` : ""}
          </p>
        )}

        <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.7rem", flexWrap: "wrap" }}>
          {canStart && <button onClick={() => void control("start")}>Start Scan</button>}
          {canStop && (
            <button className="secondary" onClick={() => void control("stop")}>
              Stop Scan
            </button>
          )}
        </div>
      </section>

      <div className="stat-row">
        <div className={`stat ${scan.summary.needs_attention > 0 ? "alert" : ""}`}>
          <div className="label">Needs attention</div>
          <div className="value">{scan.summary.needs_attention}</div>
          <div className="sub">Critical + High Severity</div>
        </div>
        <div className="stat">
          <div className="label">Total findings</div>
          <div className="value">{total}</div>
        </div>
        <div className="stat">
          <div className="label">Hosts completed</div>
          <div className="value">
            {scan.summary.hosts_completed}/{scan.summary.hosts_total}
          </div>
        </div>
      </div>

      <section className="card">
        <h3>Findings by Severity</h3>
        {total === 0 ? (
          <p className="muted">No findings recorded for this scan yet.</p>
        ) : (
          <>
            <div
              className="sev-bar"
              role="img"
              aria-label={SEV_ORDER.filter((s) => counts[s] > 0)
                .map((s) => `${counts[s]} ${s.toLowerCase()}`)
                .join(", ")}
            >
              {SEV_ORDER.map((s) =>
                counts[s] > 0 ? (
                  <span key={s} style={{ flexGrow: counts[s], background: SEV_VAR[s] }} title={`${s}: ${counts[s]}`} />
                ) : null,
              )}
            </div>
            <div className="sev-legend">
              {SEV_ORDER.map((s) => (
                <span key={s}>
                  <span className="swatch" style={{ background: SEV_VAR[s] }} />
                  {s[0] + s.slice(1).toLowerCase()}: <strong>{counts[s] ?? 0}</strong>
                </span>
              ))}
            </div>
          </>
        )}
      </section>

      <h3>Results per Host</h3>
      {scan.hosts.map((h) => (
        <section className="card" key={h.execution_id}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "0.6rem", flexWrap: "wrap" }}>
            <h3 style={{ margin: 0 }}>
              <Link to={`/targets/${h.target.id}`}>{h.target.value}</Link>{" "}
              <span className="muted" style={{ fontSize: "0.8rem" }}>({h.target.kind})</span>
            </h3>
            <span className={`badge ${stateBadge(h.state)} status-dot`}>{h.state}</span>
          </div>
          {h.error && <p className="error">{h.error}</p>}

          {(h.stages ?? []).length > 0 && (
            <p className="muted" style={{ fontSize: "0.82rem" }}>
              Stages:{" "}
              {(h.stages ?? [])
                .map((st) => `${st.stage}${st.ok ? "" : " ✗"}${st.incomplete ? " (incomplete)" : ""}`)
                .join(", ")}
            </p>
          )}

          <h4>Findings ({h.findings.length})</h4>
          {h.findings.length === 0 ? (
            <p className="muted">Nothing flagged on this host.</p>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table>
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>Asset</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {h.findings.map((f) => (
                    <tr key={f.id}>
                      <td>
                        <span className={`sev-tag sev-${f.severity}`}>{f.severity}</span>
                      </td>
                      <td title={f.rule_id}>
                        {f.name}
                        <div className="muted" style={{ fontSize: "0.8rem" }}>
                          {f.evidence_summary}
                        </div>
                      </td>
                      <td>
                        {f.asset_value}
                        {f.port ? `:${f.port}` : ""}
                      </td>
                      <td>
                        <span className={`badge ${f.status === "NOT_OBSERVED" ? "ok" : ""}`}>
                          {f.status.replace("_", " ")}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {h.services.length > 0 && (
            <>
              <h4>Services ({h.services.length})</h4>
              <div style={{ overflowX: "auto" }}>
                <table>
                  <thead>
                    <tr>
                      <th>Port</th>
                      <th>Protocol</th>
                      <th>State</th>
                      <th>Product</th>
                    </tr>
                  </thead>
                  <tbody>
                    {h.services.map((s) => (
                      <tr key={`${s.protocol}-${s.port}`}>
                        <td>{s.port}</td>
                        <td>{s.protocol}</td>
                        <td>{s.state}</td>
                        <td className="muted">
                          {[s.product, s.version].filter(Boolean).join(" ") || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {h.assets.length > 0 && (
            <>
              <h4>Assets ({h.assets.length})</h4>
              <div style={{ overflowX: "auto" }}>
                <table>
                  <thead>
                    <tr>
                      <th>Kind</th>
                      <th>Value</th>
                      <th>Source</th>
                      <th>Scope</th>
                    </tr>
                  </thead>
                  <tbody>
                    {h.assets.map((a) => (
                      <tr key={`${a.kind}-${a.value}`}>
                        <td>{a.kind}</td>
                        <td>{a.value}</td>
                        <td className="muted">{a.source}</td>
                        <td>
                          <span className={`badge ${a.approved ? "" : "warn"}`}>
                            {a.approved ? "approved" : "unapproved"}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </section>
      ))}
    </div>
  );
}
