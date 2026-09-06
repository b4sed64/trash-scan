import { FormEvent, useState } from "react";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import { Raccoon } from "../components/Raccoon";

export function Setup() {
  const { refresh } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await api.post("/api/auth/setup", { username, password });
      await refresh();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Setup failed");
    }
  }

  return (
    <div className="center-page">
      <form className="card" onSubmit={submit}>
        <div className="brand" style={{ justifyContent: "center", marginBottom: "0.5rem" }}>
          <Raccoon size={40} />
          <h1 style={{ fontSize: "1.3rem" }}>First-Run Setup</h1>
        </div>
        <p className="muted" style={{ textAlign: "center" }}>
          Create the initial administrator account.
        </p>
        <label htmlFor="u">Username</label>
        <input id="u" value={username} onChange={(e) => setUsername(e.target.value)} required />
        <label htmlFor="p">Password (min 12 characters)</label>
        <input
          id="p"
          type="password"
          value={password}
          minLength={12}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        {error && <p className="error">{error}</p>}
        <button type="submit" style={{ marginTop: "1rem" }}>
          Create administrator
        </button>
      </form>
    </div>
  );
}
