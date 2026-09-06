import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError, Execution, FindingRow, ReportRow, Target } from "../api";
import { useAuth } from "../auth";
import { Raccoon } from "../components/Raccoon";

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
const SEV_VAR: Record<string, string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
  INFO: "var(--sev-info)",
};
const ACTIVE_STATES = ["DRAFT", "AWAITING_APPROVAL", "APPROVED", "QUEUED", "RUNNING", "CANCELLING"];

type AggFinding = FindingRow & { target_id?: string; target_value?: string };

export function Dashboard() {
  const { me } = useAuth();
  const isAdmin = me?.role === "ADMINISTRATOR";

  const [targets, setTargets] = useState<Target[]>([]);
  const [findings, setFindings] = useState<AggFinding[]>([]);
  const [scans, setScans] = useState<Execution[]>([]);
  const [pendingApprovals, setPendingApprovals] = useState(0);
  const [reports, setReports] = useState<ReportRow[]>([]);
  const [hideNotObserved, setHideNotObserved] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setTargets(await api.get<Target[]>("/api/targets").catch(() => []));
    setFindings(await api.get<AggFinding[]>("/api/findings").catch(() => []));
    setScans(await api.get<Execution[]>("/api/scans").catch(() => []));
    setReports(await api.get<ReportRow[]>("/api/reports").catch(() => []));
    if (isAdmin) {
      const q = await api
        .get<{ state: string }[]>("/api/approvals?include_decided=false")
        .catch(() => []);
      setPendingApprovals(q.filter((a) => a.state === "AWAITING_APPROVAL").length);
    }
  }, [isAdmin]);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 8000);
    return () => clearInterval(t);
  }, [load]);

  const counts = useMemo(() => {
    const c: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const f of findings)
      if (f.status !== "NOT_OBSERVED") c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [findings]);

  const totalOpen = SEV_ORDER.reduce((n, s) => n + counts[s], 0);
  const needsAttention = counts.CRITICAL + counts.HIGH;
  const runningScans = scans.filter((s) => ACTIVE_STATES.includes(s.state)).length;
  const visibleFindings = hideNotObserved
    ? findings.filter((f) => f.status !== "NOT_OBSERVED")
    : findings;

  async function exportAllCsv() {
    setBusy(true);
    setError("");
    try {
      await api.post("/api/reports/csv");
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Export failed");
    } finally {
      setBusy(false);
    }
  }

  async function download(r: ReportRow) {
    try {
      await api.download(`/api/reports/${r.id}/download`, r.filename);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Download failed");
    }
  }

  return (
    <div>
      <h2>Dashboard</h2>
      {error && <p className="error">{error}</p>}

      <div className="stat-row">
        <div className="stat">
          <div className="label">Open findings</div>
          <div className="value">{totalOpen}</div>
          <div className="sub">Observed in the Latest Scans</div>
        </div>
        <div className={`stat ${needsAttention > 0 ? "alert" : ""}`}>
          <div className="label">Needs attention</div>
          <div className="value">{needsAttention}</div>
          <div className="sub">Critical + High Severity</div>
        </div>
        <div className="stat">
          <div className="label">Targets in scope</div>
          <div className="value">{targets.length}</div>
        </div>
        <div className="stat">
          <div className="label">Scans running</div>
          <div className="value">{runningScans}</div>
        </div>
        {isAdmin && (
          <div className={`stat ${pendingApprovals > 0 ? "alert" : ""}`}>
            <div className="label">Pending approvals</div>
            <div className="value">{pendingApprovals}</div>
            <div className="sub">
              <Link to="/approvals">Review Queue</Link>
            </div>
          </div>
        )}
      </div>

      <section className="card">
        <h3>Findings by Severity</h3>
        {totalOpen === 0 ? (
          <p className="muted">No open findings across your targets.</p>
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
                  <span
                    key={s}
                    style={{ flexGrow: counts[s], background: SEV_VAR[s] }}
                    title={`${s}: ${counts[s]}`}
                  />
                ) : null,
              )}
            </div>
            <div className="sev-legend">
              {SEV_ORDER.map((s) => (
                <span key={s}>
                  <span className="swatch" style={{ background: SEV_VAR[s] }} />
                  {s[0] + s.slice(1).toLowerCase()}: <strong>{counts[s]}</strong>
                </span>
              ))}
            </div>
          </>
        )}
      </section>

      <section className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h3>Threats &amp; Vulnerabilities</h3>
          <label style={{ margin: 0, display: "flex", gap: "0.4rem", alignItems: "center" }}>
            <input
              type="checkbox"
              style={{ width: "auto" }}
              checked={hideNotObserved}
              onChange={(e) => setHideNotObserved(e.target.checked)}
            />
            Hide &ldquo;Not Observed&rdquo;
          </label>
        </div>
        <p className="notice">
          Automated indicators that require human validation, ranked by severity. "Not observed"
          means the latest compatible scan did not see it — never that it is resolved.
        </p>
        {visibleFindings.length === 0 ? (
          <div className="empty-state">
            <Raccoon size={44} />
            <p>The bin's clean — nothing flagged yet. Run an approved active scan to surface findings.</p>
            <p className="muted" style={{ fontSize: "0.85rem" }}>
              🦝 keeps watch anyway.
            </p>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Target</th>
                  <th>Asset</th>
                  <th>Status</th>
                  <th>First seen</th>
                </tr>
              </thead>
              <tbody>
                {visibleFindings.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <span className={`sev-tag sev-${f.severity}`}>{f.severity}</span>
                    </td>
                    <td>
                      <Link to={`/targets/${f.target_id}`} title={f.rule_id}>
                        {f.name}
                      </Link>
                      <div className="muted" style={{ fontSize: "0.8rem" }}>
                        {f.evidence_summary}
                      </div>
                    </td>
                    <td>{f.target_value}</td>
                    <td>
                      {f.asset_value}
                      {f.port ? `:${f.port}` : ""}
                    </td>
                    <td>
                      <span className={`badge ${f.status === "NOT_OBSERVED" ? "ok" : ""}`}>
                        {f.status.replace("_", " ")}
                      </span>
                    </td>
                    <td className="muted">{new Date(f.first_seen_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card">
        <h3>Targets in Your Scope ({targets.length})</h3>
        {targets.length === 0 ? (
          <div className="empty-state">
            <Raccoon size={44} />
            <p>No targets in your scope yet — ask an administrator to assign one.</p>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Kind</th>
                <th>Scope</th>
                <th>Assets</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((t) => (
                <tr key={t.id}>
                  <td>
                    <Link to={`/targets/${t.id}`}>{t.value}</Link>
                  </td>
                  <td>{t.kind}</td>
                  <td>
                    {t.is_public ? (
                      <span className="badge warn">Public · attested</span>
                    ) : (
                      <span className="badge">Private</span>
                    )}
                  </td>
                  <td>{t.assets.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h3>Reports &amp; Exports</h3>
          <button onClick={() => void exportAllCsv()} disabled={busy}>
            {busy ? "Preparing…" : "Export All Visible Data (CSV .zip)"}
          </button>
        </div>
        <p className="muted">
          CSV cells beginning with <code>= + - @</code> are neutralised. Exports respect your target
          assignments and every download is recorded in the audit trail. Generate a PDF from a
          target's page.
        </p>
        <table>
          <thead>
            <tr>
              <th>Created</th>
              <th>Kind</th>
              <th>Format</th>
              <th>File</th>
              <th>Size</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {reports.map((r) => (
              <tr key={r.id}>
                <td className="muted">{new Date(r.created_at).toLocaleString()}</td>
                <td>{r.kind}</td>
                <td>{r.format}</td>
                <td>{r.filename}</td>
                <td className="muted">{(r.size_bytes / 1024).toFixed(1)} KB</td>
                <td>
                  <button className="secondary" onClick={() => void download(r)}>
                    Download
                  </button>
                </td>
              </tr>
            ))}
            {reports.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  No reports generated yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
