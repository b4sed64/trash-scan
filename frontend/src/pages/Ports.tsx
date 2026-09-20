import { FormEvent, useEffect, useState } from "react";
import { api, ApiError, PortSet } from "../api";
import { useAuth } from "../auth";

export function Ports() {
  const { me } = useAuth();
  const isAdmin = me?.role === "ADMINISTRATOR";
  const [portSets, setPortSets] = useState<PortSet[]>([]);
  const [name, setName] = useState("");
  const [protocol, setProtocol] = useState<"TCP" | "UDP">("TCP");
  const [spec, setSpec] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState("");

  // Open to every authenticated user (the same set a Scanner picks from on the
  // Scans page) — only create/delete are Administrator-only, enforced by the API.
  const load = () => api.get<{ port_sets: PortSet[] }>("/api/scans/port-presets").then((r) => setPortSets(r.port_sets));
  useEffect(() => {
    void load();
  }, []);

  async function create(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api.post("/api/admin/port-sets", { name, protocol, spec, note });
      setName("");
      setProtocol("TCP");
      setSpec("");
      setNote("");
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to create port profile");
    }
  }

  async function remove(id: string) {
    setError("");
    try {
      await api.del(`/api/admin/port-sets/${id}`);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to remove port profile");
    }
  }

  const tcpSets = portSets.filter((p) => p.protocol !== "UDP");
  const udpSets = portSets.filter((p) => p.protocol === "UDP");

  return (
    <div>
      <h2>Ports</h2>
      <p className="muted">
        Reusable, named port profiles — TCP profiles are offered alongside the built-in
        presets when starting an active scan; UDP profiles replace the default UDP port
        list for a Standard Active scan (only scanned at all when UDP scanning is enabled —
        see Administration).
      </p>
      {error && <p className="error">{error}</p>}

      {isAdmin && (
        <form className="card" onSubmit={create}>
          <h3>Add Port Profile</h3>
          <div className="row">
            <div>
              <label htmlFor="pn">Name</label>
              <input
                id="pn"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Databases"
                required
              />
            </div>
            <div>
              <label htmlFor="pp">Protocol</label>
              <select id="pp" value={protocol} onChange={(e) => setProtocol(e.target.value as "TCP" | "UDP")}>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
              </select>
            </div>
          </div>
          <label htmlFor="ps">Ports (list and ranges)</label>
          <input
            id="ps"
            value={spec}
            onChange={(e) => setSpec(e.target.value)}
            placeholder="1433,3306,5432,6379,27017"
            required
          />
          <label htmlFor="pnote">Note</label>
          <input id="pnote" value={note} onChange={(e) => setNote(e.target.value)} />
          <button type="submit" style={{ marginTop: "0.7rem" }}>
            Add Port Profile
          </button>
        </form>
      )}

      <section className="card">
        <h3>TCP Profiles</h3>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Ports</th>
              <th>Note</th>
              {isAdmin && <th></th>}
            </tr>
          </thead>
          <tbody>
            {tcpSets.map((p) => (
              <tr key={p.id}>
                <td>{p.name}</td>
                <td>
                  <code>{p.spec}</code>
                </td>
                <td className="muted">{p.note}</td>
                {isAdmin && (
                  <td>
                    <button className="secondary" onClick={() => void remove(p.id)}>
                      Remove
                    </button>
                  </td>
                )}
              </tr>
            ))}
            {tcpSets.length === 0 && (
              <tr>
                <td colSpan={isAdmin ? 4 : 3} className="muted">
                  No TCP port profiles defined.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h3>UDP Profiles</h3>
        <p className="notice">
          UDP scanning only runs in the Standard Active profile, and only when an
          administrator has enabled raw-packet capability. Without that, these profiles are
          defined but never scanned.
        </p>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Ports</th>
              <th>Note</th>
              {isAdmin && <th></th>}
            </tr>
          </thead>
          <tbody>
            {udpSets.map((p) => (
              <tr key={p.id}>
                <td>{p.name}</td>
                <td>
                  <code>{p.spec}</code>
                </td>
                <td className="muted">{p.note}</td>
                {isAdmin && (
                  <td>
                    <button className="secondary" onClick={() => void remove(p.id)}>
                      Remove
                    </button>
                  </td>
                )}
              </tr>
            ))}
            {udpSets.length === 0 && (
              <tr>
                <td colSpan={isAdmin ? 4 : 3} className="muted">
                  No UDP port profiles defined.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
