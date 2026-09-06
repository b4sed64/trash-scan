import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, ApiError, Target } from "../api";
import { useAuth } from "../auth";

const PUBLIC_ATTESTATION =
  "I confirm this team owns or has written authorization to scan this target";

export function Targets() {
  const { me } = useAuth();
  const isAdmin = me?.role === "ADMINISTRATOR";
  const [targets, setTargets] = useState<Target[]>([]);
  const [value, setValue] = useState("");
  const [isPublic, setIsPublic] = useState(false);
  const [checkbox, setCheckbox] = useState(false);
  const [attestation, setAttestation] = useState("");
  const [error, setError] = useState("");

  const load = () => api.get<Target[]>("/api/targets").then(setTargets);
  useEffect(() => {
    void load();
  }, []);

  async function create(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api.post("/api/targets", {
        value,
        is_public: isPublic,
        attestation_checkbox: checkbox,
        attestation_text: isPublic ? attestation : null,
      });
      setValue("");
      setIsPublic(false);
      setCheckbox(false);
      setAttestation("");
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to create target");
    }
  }

  return (
    <div>
      <h2>Targets</h2>

      {isAdmin && (
        <form className="card" onSubmit={create}>
          <h3>Add target</h3>
          <label htmlFor="tv">IPv4 address, IPv4 CIDR, or domain</label>
          <input
            id="tv"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="10.10.5.20 or lab.example.com"
            required
          />
          <div className="inline-check" style={{ marginTop: "0.6rem" }}>
            <input
              id="pub"
              type="checkbox"
              checked={isPublic}
              onChange={(e) => setIsPublic(e.target.checked)}
            />
            <label htmlFor="pub" style={{ margin: 0 }}>
              This is a public target the team owns
            </label>
          </div>

          {isPublic && (
            <div style={{ marginTop: "0.6rem" }}>
              <p className="notice">
                Sector classification cannot guarantee identification of every prohibited
                organization. The private-only default and this explicit approval are the primary
                safeguards. Discovered related assets never inherit this authorization.
              </p>
              <div className="inline-check">
                <input
                  id="own"
                  type="checkbox"
                  checked={checkbox}
                  onChange={(e) => setCheckbox(e.target.checked)}
                />
                <label htmlFor="own" style={{ margin: 0 }}>
                  I have verified ownership / written authorization for this exact target.
                </label>
              </div>
              <label htmlFor="att">Type exactly: “{PUBLIC_ATTESTATION}”</label>
              <input
                id="att"
                value={attestation}
                onChange={(e) => setAttestation(e.target.value)}
              />
            </div>
          )}

          {error && <p className="error">{error}</p>}
          <button type="submit" style={{ marginTop: "0.8rem" }}>
            Add target
          </button>
        </form>
      )}

      <section className="card">
        <h3>All visible targets</h3>
        <table>
          <thead>
            <tr>
              <th>Target</th>
              <th>Kind</th>
              <th>Type</th>
              <th>State</th>
            </tr>
          </thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.id}>
                <td>
                  <Link to={`/targets/${t.id}`}>{t.value}</Link>
                </td>
                <td>{t.kind}</td>
                <td>{t.is_public ? "Public (attested)" : "Private"}</td>
                <td>{t.is_active ? "Active" : "Archived"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
