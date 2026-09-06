import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api, ApiError, Target } from "../api";
import { useAuth } from "../auth";

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

export function TargetDetail() {
  const { id = "" } = useParams();
  const { me } = useAuth();
  const isAdmin = me?.role === "ADMINISTRATOR";
  const navigate = useNavigate();

  const [target, setTarget] = useState<Target | null>(null);
  const [scope, setScope] = useState<ScopePreview | null>(null);
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [assignUser, setAssignUser] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [confirmValue, setConfirmValue] = useState("");

  const load = useCallback(async () => {
    setTarget(await api.get<Target>(`/api/targets/${id}`));
    setScope(await api.get<ScopePreview>(`/api/targets/${id}/scope-preview`));
    if (isAdmin) {
      setAccounts(await api.get<Account[]>("/api/admin/accounts"));
    }
  }, [id, isAdmin]);

  useEffect(() => {
    void load().catch((e) =>
      setError(e instanceof ApiError ? e.message : "Failed to load target"),
    );
  }, [load]);

  async function runPassive() {
    setBusy(true);
    setError("");
    try {
      await api.post(`/api/targets/${id}/passive-scan`);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Passive discovery failed");
    } finally {
      setBusy(false);
    }
  }

  async function assign() {
    if (!assignUser) return;
    await api.post(`/api/targets/${id}/assignments`, { user_id: assignUser });
    setAssignUser("");
    await load();
  }

  async function unassign(userId: string) {
    await api.del(`/api/targets/${id}/assignments/${userId}`);
    await load();
  }

  async function archive() {
    await api.post(`/api/targets/${id}/archive`);
    await load();
  }

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
              <p className="muted">
                Resolved now: {scope.resolved_addresses.join(", ")} (re-checked immediately before
                any active stage)
              </p>
            )}
          </>
        )}
        <p className="notice">
          Phase 1 supports passive discovery only. Active scanning requires a typed attestation and
          a fresh administrator approval (coming in Phase 3).
        </p>
      </section>

      <section className="card">
        <div style={{ display: "flex", justifyContent: "space-between" }}>
          <h3>Assets ({target.assets.length})</h3>
          <button onClick={() => void runPassive()} disabled={busy || !target.is_active}>
            {busy ? "Running…" : "Run passive discovery"}
          </button>
        </div>
        <p className="muted">
          Discovered assets are recorded as unapproved and never inherit target authorization.
        </p>
        <table>
          <thead>
            <tr>
              <th>Asset</th>
              <th>Kind</th>
              <th>Source</th>
              <th>In private scope</th>
              <th>Approved</th>
              <th>First seen</th>
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
                <td className="muted">{new Date(a.first_seen_at).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
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
                  <button className="secondary" onClick={() => void unassign(uid)}>
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
            <button onClick={() => void assign()}>Assign</button>
          </div>
        </section>
      )}

      {isAdmin && (
        <section className="card">
          <h3>Danger zone</h3>
          <button className="secondary" onClick={() => void archive()} disabled={!target.is_active}>
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
