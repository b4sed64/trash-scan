import { useCallback, useEffect, useState } from "react";
import { api, ApiError, ReportRow } from "../api";

export function Reports() {
  const [reports, setReports] = useState<ReportRow[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(
    () => api.get<ReportRow[]>("/api/reports").then(setReports).catch(() => undefined),
    [],
  );
  useEffect(() => {
    void load();
  }, [load]);

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
      <h2>Reports &amp; exports</h2>
      {error && <p className="error">{error}</p>}
      <section className="card">
        <button onClick={() => void exportAllCsv()} disabled={busy}>
          {busy ? "Preparing…" : "Export all visible data (CSV .zip)"}
        </button>
        <p className="muted">
          CSV cells beginning with <code>= + - @</code> are neutralised. Exports respect your
          target assignments and every download is recorded in the audit trail.
        </p>
      </section>
      <section className="card">
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
                  No reports yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
