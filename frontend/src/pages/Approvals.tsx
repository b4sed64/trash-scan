import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError, Approval } from "../api";

export function Approvals() {
  const [items, setItems] = useState<Approval[]>([]);
  const [error, setError] = useState("");
  const [reason, setReason] = useState<Record<string, string>>({});

  const load = useCallback(
    () => api.get<Approval[]>("/api/approvals").then(setItems).catch(() => undefined),
    [],
  );
  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 6000);
    return () => clearInterval(t);
  }, [load]);

  const act = (id: string, verb: "approve" | "deny") => async () => {
    setError("");
    try {
      await api.post(`/api/approvals/${id}/${verb}`, verb === "deny" ? { reason: reason[id] ?? "" } : {});
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Request failed");
    }
  };

  const pending = items.filter((a) => a.state === "AWAITING_APPROVAL");
  const decided = items.filter((a) => a.state !== "AWAITING_APPROVAL");

  return (
    <div>
      <h2>Approvals</h2>
      {error && <p className="error">{error}</p>}
      <p className="notice">
        Every active execution — including every scheduled occurrence — needs a fresh
        approval. An approval authorizes exactly one run and expires if it has not started
        within two hours.
      </p>

      <section className="card">
        <h3>Pending ({pending.length})</h3>
        {pending.length === 0 && <p className="muted">Nothing awaiting approval.</p>}
        {pending.map((a) => (
          <div key={a.id} className="card" style={{ background: "var(--charcoal)" }}>
            <p>
              <strong>{a.profile}</strong> on{" "}
              <Link to={`/targets/${a.target?.id}`}>{a.target?.value}</Link> — requested by{" "}
              {a.requested_by ?? "?"}
              {a.schedule_id ? " · scheduled occurrence" : ""}
            </p>
            <p className="muted">Attestation: “{a.attestation_text}”</p>
            <p className="muted">
              Scope at request:{" "}
              {a.scope_at_request?.allowed ? "within approved scope" : "—"}
              {a.scope_at_request?.resolved_addresses?.length
                ? ` · resolves to ${a.scope_at_request.resolved_addresses.join(", ")}`
                : ""}
            </p>
            <p className="muted">
              Rate: {String(a.requested_options?.rate_choice ?? "—")} · Ports:{" "}
              {String(a.requested_options?.ports ?? "profile default")}
            </p>
            <div className="row">
              <button onClick={act(a.id, "approve")}>Approve (One Run, 2h to Start)</button>
              <input
                placeholder="denial reason"
                value={reason[a.id] ?? ""}
                onChange={(e) => setReason({ ...reason, [a.id]: e.target.value })}
              />
              <button className="danger" onClick={act(a.id, "deny")}>
                Deny
              </button>
            </div>
          </div>
        ))}
      </section>

      <section className="card">
        <h3>Recent Decisions</h3>
        <table>
          <thead>
            <tr>
              <th>Target</th>
              <th>Profile</th>
              <th>Approval</th>
              <th>Execution</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {decided.map((a) => (
              <tr key={a.id}>
                <td>{a.target?.value}</td>
                <td>{a.profile}</td>
                <td>{a.state}</td>
                <td>
                  <Link to={`/scans`}>{a.execution_state}</Link>
                </td>
                <td className="muted">{a.decision_reason || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
