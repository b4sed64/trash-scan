import { type SyntheticEvent, useEffect, useState } from "react";
import { api, ApiError } from "../api";

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

export function Admin() {
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [cidrs, setCidrs] = useState<PrivateCidr[]>([]);
  const [denies, setDenies] = useState<DenyRule[]>([]);
  const [error, setError] = useState("");

  const [nu, setNu] = useState({ username: "", password: "", role: "SCANNER" });
  const [nc, setNc] = useState({ cidr: "", note: "" });
  const [nd, setNd] = useState({ rule_type: "DOMAIN_SUFFIX", value: "", category: "CUSTOM" });

  async function loadAll() {
    setAccounts(await api.get<Account[]>("/api/admin/accounts"));
    setCidrs(await api.get<PrivateCidr[]>("/api/admin/private-cidrs"));
    setDenies(await api.get<DenyRule[]>("/api/admin/deny-rules"));
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
            <label>Password (min 12)</label>
            <input
              type="password"
              minLength={12}
              value={nu.password}
              onChange={(e) => setNu({ ...nu, password: e.target.value })}
              required
            />
          </div>
          <div>
            <label>Role</label>
            <select value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value })}>
              <option value="SCANNER">SCANNER</option>
              <option value="ADMINISTRATOR">ADMINISTRATOR</option>
            </select>
          </div>
          <button type="submit">Create (disabled)</button>
        </form>
        <p className="muted">New accounts are created disabled and must be enabled explicitly.</p>
      </section>

      <section className="card">
        <h3>Private scope (allowed RFC1918 ranges)</h3>
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
          <button type="submit">Add range</button>
        </form>
      </section>

      <section className="card">
        <h3>Deny rules</h3>
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
          <button type="submit">Add deny rule</button>
        </form>
      </section>
    </div>
  );
}
