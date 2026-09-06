import { type SyntheticEvent, useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { PasswordInput } from "../components/PasswordInput";

interface Account {
  id: string;
  username: string;
  role: string;
  is_active: boolean;
  created_at: string;
}
interface PrivateCidr {
  id: string;
  cidr: string;
  note: string;
}
interface DenyRule {
  id: string;
  rule_type: string;
  value: string;
  category: string;
  is_builtin: boolean;
}
interface PortSet {
  id: string;
  name: string;
  spec: string;
  note: string;
}
interface Maintenance {
  current: {
    tool_versions: Record<string, string>;
    template_set_ok: boolean;
    template_set_hash: string;
    templates: Record<string, string>;
  };
  proposals: {
    id: string;
    state: string;
    note: string;
    created_at: string;
    decision_note: string;
  }[];
}

export function Admin() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [cidrs, setCidrs] = useState<PrivateCidr[]>([]);
  const [denies, setDenies] = useState<DenyRule[]>([]);
  const [portSets, setPortSets] = useState<PortSet[]>([]);
  const [nps, setNps] = useState({ name: "", spec: "", note: "" });
  const [error, setError] = useState("");

  const [maint, setMaint] = useState<Maintenance | null>(null);
  const [nu, setNu] = useState({ username: "", password: "", role: "SCANNER" });
  const [nc, setNc] = useState({ cidr: "", note: "" });
  const [nd, setNd] = useState({ rule_type: "DOMAIN_SUFFIX", value: "", category: "CUSTOM" });
  const [proposalNote, setProposalNote] = useState("");

  async function loadAll() {
    setAccounts(await api.get<Account[]>("/api/admin/accounts"));
    setCidrs(await api.get<PrivateCidr[]>("/api/admin/private-cidrs"));
    setDenies(await api.get<DenyRule[]>("/api/admin/deny-rules"));
    setPortSets(await api.get<PortSet[]>("/api/admin/port-sets").catch(() => []));
    setMaint(await api.get<Maintenance>("/api/admin/maintenance").catch(() => null));
  }
  useEffect(() => {
    void loadAll();
  }, []);

  const wrap = (fn: () => Promise<unknown>) => async (e?: SyntheticEvent) => {
    e?.preventDefault();
    setError("");
    try {
      await fn();
      await loadAll();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Request failed");
    }
  };

  return (
    <div>
      <h2>Administration</h2>
      {error && <p className="error">{error}</p>}

      <section className="card">
        <h3>Accounts</h3>
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Role</th>
              <th>State</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {accounts.map((a) => (
              <tr key={a.id}>
                <td>{a.username}</td>
                <td>{a.role}</td>
                <td>
                  <span className={`badge ${a.is_active ? "ok" : "bad"}`}>
                    {a.is_active ? "Enabled" : "Disabled"}
                  </span>
                </td>
                <td>
                  <button
                    className="secondary"
                    onClick={wrap(() =>
                      api.patch(`/api/admin/accounts/${a.id}`, { is_active: !a.is_active }),
                    )}
                  >
                    {a.is_active ? "Disable" : "Enable"}
                  </button>{" "}
                  <button
                    className="secondary"
                    onClick={wrap(async () => {
                      const pw = window.prompt(
                        `Set a new password for ${a.username} (min 12 characters). ` +
                          "Their active sessions will be signed out.",
                      );
                      if (!pw) return;
                      if (pw.length < 12) {
                        window.alert("Password must be at least 12 characters.");
                        return;
                      }
                      await api.post(`/api/admin/accounts/${a.id}/reset-password`, {
                        new_password: pw,
                      });
                      window.alert(`Password reset for ${a.username}.`);
                    })}
                  >
                    Reset Password
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <form className="row" onSubmit={wrap(() => api.post("/api/admin/accounts", nu))}>
          <div>
            <label>Username</label>
            <input
              value={nu.username}
              onChange={(e) => setNu({ ...nu, username: e.target.value })}
              required
            />
          </div>
          <div>
            <label htmlFor="np">Password (min 12)</label>
            <PasswordInput
              id="np"
              value={nu.password}
              onChange={(v) => setNu({ ...nu, password: v })}
              minLength={12}
              required
              autoComplete="new-password"
            />
          </div>
          <div>
            <label>Role</label>
            <select value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value })}>
              <option value="SCANNER">SCANNER</option>
              <option value="ADMINISTRATOR">ADMINISTRATOR</option>
            </select>
          </div>
          <button type="submit">Create (Disabled)</button>
        </form>
        <p className="muted">New accounts are created disabled and must be enabled explicitly.</p>
      </section>

      <section className="card">
        <h3>Private Scope (Allowed RFC1918 Ranges)</h3>
        <ul>
          {cidrs.map((c) => (
            <li key={c.id}>
              <code>{c.cidr}</code> {c.note}{" "}
              <button
                className="secondary"
                onClick={wrap(() => api.del(`/api/admin/private-cidrs/${c.id}`))}
              >
                Remove
              </button>
            </li>
          ))}
          {cidrs.length === 0 && (
            <li className="muted">
              No private range configured yet — active scanning will reject every target.
            </li>
          )}
        </ul>
        <form className="row" onSubmit={wrap(() => api.post("/api/admin/private-cidrs", nc))}>
          <div>
            <label>CIDR</label>
            <input
              value={nc.cidr}
              onChange={(e) => setNc({ ...nc, cidr: e.target.value })}
              placeholder="10.10.0.0/16"
              required
            />
          </div>
          <div>
            <label>Note</label>
            <input value={nc.note} onChange={(e) => setNc({ ...nc, note: e.target.value })} />
          </div>
          <button type="submit">Add Range</button>
        </form>
      </section>

      <section className="card">
        <h3>Deny Rules</h3>
        <p className="notice">
          Allow rules never override deny rules. Built-in government, military and healthcare rules
          reduce risk but cannot identify every prohibited organization.
        </p>
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>Category</th>
              <th>Origin</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {denies.map((d) => (
              <tr key={d.id}>
                <td>{d.rule_type}</td>
                <td>{d.value}</td>
                <td>{d.category}</td>
                <td>{d.is_builtin ? "Built-in" : "Custom"}</td>
                <td>
                  {!d.is_builtin && (
                    <button
                      className="secondary"
                      onClick={wrap(() => api.del(`/api/admin/deny-rules/${d.id}`))}
                    >
                      Remove
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <form className="row" onSubmit={wrap(() => api.post("/api/admin/deny-rules", nd))}>
          <div>
            <label>Type</label>
            <select
              value={nd.rule_type}
              onChange={(e) => setNd({ ...nd, rule_type: e.target.value })}
            >
              <option>DOMAIN_EXACT</option>
              <option>DOMAIN_SUFFIX</option>
              <option>IP</option>
              <option>CIDR</option>
            </select>
          </div>
          <div>
            <label>Value</label>
            <input
              value={nd.value}
              onChange={(e) => setNd({ ...nd, value: e.target.value })}
              required
            />
          </div>
          <div>
            <label>Category</label>
            <select
              value={nd.category}
              onChange={(e) => setNd({ ...nd, category: e.target.value })}
            >
              <option>CUSTOM</option>
              <option>GOVERNMENT</option>
              <option>MILITARY</option>
              <option>HEALTHCARE</option>
            </select>
          </div>
          <button type="submit">Add Deny Rule</button>
        </form>
      </section>

      <section className="card">
        <h3>Port Sets</h3>
        <p className="notice">
          Reusable named port selections. Scanners pick these on the Scans page for active
          scans, alongside the built-in presets or a typed list.
        </p>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Ports</th>
              <th>Note</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {portSets.map((p) => (
              <tr key={p.id}>
                <td>{p.name}</td>
                <td>
                  <code>{p.spec}</code>
                </td>
                <td className="muted">{p.note}</td>
                <td>
                  <button
                    className="secondary"
                    onClick={wrap(() => api.del(`/api/admin/port-sets/${p.id}`))}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
            {portSets.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  No port sets defined.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <form
          className="row"
          onSubmit={wrap(() =>
            api.post("/api/admin/port-sets", nps).then(() => setNps({ name: "", spec: "", note: "" })),
          )}
        >
          <div>
            <label htmlFor="psn">Name</label>
            <input
              id="psn"
              value={nps.name}
              onChange={(e) => setNps({ ...nps, name: e.target.value })}
              placeholder="Databases"
              required
            />
          </div>
          <div>
            <label htmlFor="pss">Ports (list and ranges)</label>
            <input
              id="pss"
              value={nps.spec}
              onChange={(e) => setNps({ ...nps, spec: e.target.value })}
              placeholder="1433,1521,3306,5432,6379,27017"
              required
            />
          </div>
          <div>
            <label htmlFor="psnote">Note</label>
            <input
              id="psnote"
              value={nps.note}
              onChange={(e) => setNps({ ...nps, note: e.target.value })}
            />
          </div>
          <button type="submit">Add Port Set</button>
        </form>
      </section>

      <section className="card">
        <h3>Tool &amp; Template Maintenance</h3>
        <p className="notice">
          The application never updates tools or templates itself. Approving a proposal
          records the review; an operator then rebuilds the worker image and redeploys.
        </p>
        {maint && (
          <>
            <table>
              <thead>
                <tr>
                  <th>Tool</th>
                  <th>Running version</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(maint.current.tool_versions).map(([t, v]) => (
                  <tr key={t}>
                    <td>{t}</td>
                    <td className="muted">{v}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="muted">
              Nuclei template set:{" "}
              <span className={`badge ${maint.current.template_set_ok ? "ok" : "bad"}`}>
                {maint.current.template_set_ok ? "verified" : "MISMATCH"}
              </span>{" "}
              hash <code>{maint.current.template_set_hash.slice(0, 16)}…</code> ·{" "}
              {Object.keys(maint.current.templates).length} templates
            </p>
            <form
              onSubmit={wrap(() =>
                api
                  .post("/api/admin/maintenance/proposals", { note: proposalNote })
                  .then(() => setProposalNote("")),
              )}
            >
              <label htmlFor="pn">Propose a tool/template change (describe what and why)</label>
              <textarea
                id="pn"
                rows={2}
                value={proposalNote}
                onChange={(e) => setProposalNote(e.target.value)}
                required
              />
              <button type="submit" style={{ marginTop: "0.5rem" }}>
                Submit Proposal
              </button>
            </form>
            <table>
              <thead>
                <tr>
                  <th>Created</th>
                  <th>State</th>
                  <th>Note</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {maint.proposals.map((p) => (
                  <tr key={p.id}>
                    <td className="muted">{new Date(p.created_at).toLocaleString()}</td>
                    <td>{p.state}</td>
                    <td>{p.note}</td>
                    <td>
                      {p.state === "PROPOSED" && (
                        <>
                          <button
                            className="secondary"
                            onClick={wrap(() =>
                              api.post(`/api/admin/maintenance/proposals/${p.id}/approve`, {
                                decision_note: "",
                              }),
                            )}
                          >
                            Approve
                          </button>{" "}
                          <button
                            className="danger"
                            onClick={wrap(() =>
                              api.post(`/api/admin/maintenance/proposals/${p.id}/reject`, {
                                decision_note: "",
                              }),
                            )}
                          >
                            Reject
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </section>
    </div>
  );
}
