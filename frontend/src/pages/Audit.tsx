import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { api, ApiError, AuditEvent } from "../api";
import { useAuth } from "../auth";

interface VerifyResult {
  ok: boolean;
  checked: number;
  total: number;
  failed_seq?: number;
  reason?: string;
}

export function Audit() {
  const { me } = useAuth();
  const isAdmin = me?.role === "ADMINISTRATOR";

  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [allActions, setAllActions] = useState<string[]>([]);
  const [selectedActions, setSelectedActions] = useState<string[]>([]);
  const [q, setQ] = useState("");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const [expanded, setExpanded] = useState<number | null>(null);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [error, setError] = useState("");

  const query = useMemo(() => {
    const p = new URLSearchParams();
    p.set("limit", "1000");
    p.set("order", order);
    if (q.trim()) p.set("q", q.trim());
    for (const a of selectedActions) p.append("action", a);
    return p.toString();
  }, [order, q, selectedActions]);

  const load = useCallback(async () => {
    setEvents(await api.get<AuditEvent[]>(`/api/audit/events?${query}`).catch(() => []));
  }, [query]);

  useEffect(() => {
    void api.get<string[]>("/api/audit/actions").then(setAllActions).catch(() => undefined);
  }, []);

  useEffect(() => {
    const t = setTimeout(() => void load(), q ? 250 : 0); // debounce the text field
    return () => clearTimeout(t);
  }, [load, q]);

  async function runVerify() {
    setError("");
    try {
      setVerify(await api.post<VerifyResult>("/api/audit/verify"));
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Verification failed");
    }
  }

  function toggleAction(a: string) {
    setSelectedActions((prev) =>
      prev.includes(a) ? prev.filter((x) => x !== a) : [...prev, a],
    );
  }

  const filtersActive = selectedActions.length > 0 || q.trim() !== "";

  return (
    <div>
      <h2>Logs</h2>
      <p className="notice">
        Tamper-evident audit chain — every security-relevant event, hash-linked. It is
        tamper-evident, not tamper-proof: a database or host administrator with direct storage
        access can still rewrite history.
      </p>

      {isAdmin && (
        <section className="card">
          <button onClick={() => void runVerify()}>Verify Chain Now</button>
          {error && <p className="error">{error}</p>}
          {verify && (
            <p>
              <span className={`badge ${verify.ok ? "ok" : "bad"} status-dot`}>
                {verify.ok ? "Chain intact" : "CHAIN VERIFICATION FAILED"}
              </span>{" "}
              <span className="muted">
                checked {verify.checked}/{verify.total}
                {verify.reason ? ` — ${verify.reason} (seq ${verify.failed_seq})` : ""}
              </span>
            </p>
          )}
        </section>
      )}

      <section className="card">
        <div className="log-filters">
          <div style={{ flex: "1 1 260px" }}>
            <label htmlFor="q">Search (scan ID, object ID, or any value)</label>
            <input
              id="q"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="e.g. a scan execution id"
            />
          </div>
          <div>
            <label htmlFor="ord">Order</label>
            <select id="ord" value={order} onChange={(e) => setOrder(e.target.value as "asc" | "desc")}>
              <option value="desc">Newest First</option>
              <option value="asc">Oldest First</option>
            </select>
          </div>
          {filtersActive && (
            <button
              className="secondary"
              onClick={() => {
                setSelectedActions([]);
                setQ("");
              }}
            >
              Clear Filters
            </button>
          )}
        </div>

        <label style={{ marginTop: "0.6rem" }}>
          Filter by action {selectedActions.length > 0 && `(${selectedActions.length})`}
        </label>
        <div className="chip-row">
          {allActions.map((a) => (
            <button
              key={a}
              type="button"
              className={`chip ${selectedActions.includes(a) ? "on" : ""}`}
              aria-pressed={selectedActions.includes(a)}
              onClick={() => toggleAction(a)}
            >
              {a}
            </button>
          ))}
        </div>
      </section>

      <section className="card">
        <p className="muted">
          {events.length} event{events.length === 1 ? "" : "s"}
          {filtersActive ? " (filtered)" : ""}
        </p>
        <div style={{ overflowX: "auto" }}>
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Time (UTC)</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Object</th>
                <th>Hash</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <Fragment key={e.seq}>
                  <tr
                    onClick={() => setExpanded(expanded === e.seq ? null : e.seq)}
                    style={{ cursor: "pointer" }}
                  >
                    <td>{e.seq}</td>
                    <td className="muted">{new Date(e.ts).toISOString().replace(".000", "")}</td>
                    <td>{e.actor}</td>
                    <td>{e.action}</td>
                    <td className="muted">
                      {e.object_type}
                      {e.object_id ? `:${e.object_id.slice(0, 8)}` : ""}
                    </td>
                    <td className="muted" title={e.curr_hash}>
                      {e.curr_hash.slice(0, 12)}…
                    </td>
                  </tr>
                  {expanded === e.seq && (
                    <tr>
                      <td colSpan={6} style={{ background: "var(--charcoal-sunk)" }}>
                        <div className="muted" style={{ fontSize: "0.8rem" }}>
                          object: {e.object_type} {e.object_id}
                        </div>
                        <pre style={{ margin: "0.4rem 0 0", whiteSpace: "pre-wrap", fontSize: "0.8rem" }}>
                          {JSON.stringify(e.payload, null, 2)}
                        </pre>
                        <div className="muted" style={{ fontSize: "0.75rem", marginTop: "0.4rem" }}>
                          prev {e.prev_hash.slice(0, 20)}… → curr {e.curr_hash.slice(0, 20)}…
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
              {events.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    No events match the current filters.
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
