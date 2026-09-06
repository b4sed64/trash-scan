import { FormEvent, useState } from "react";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import { PasswordInput } from "../components/PasswordInput";
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
      setError(err instanceof ApiError ? err.message : "Setup Failed");
    }
  }

  return (
    <div className="center-page" style={{ flexDirection: "column" }}>
      <div className="login-mark" aria-hidden="true">
        <Raccoon size={52} />
      </div>
      <form className="card" onSubmit={submit}>
        <h1 style={{ fontSize: "1.3rem", textAlign: "center", margin: "0 0 0.2rem" }}>
          First-Run Setup
        </h1>
        <p className="muted" style={{ textAlign: "center" }}>
          Create the initial administrator account.
        </p>
        <label htmlFor="u">Username</label>
        <input id="u" value={username} onChange={(e) => setUsername(e.target.value)} required />
        <label htmlFor="p">Password (min 12 characters)</label>
        <PasswordInput id="p" value={password} onChange={setPassword} minLength={12} required
                       autoComplete="new-password" />
        {error && <p className="error">{error}</p>}
        <button type="submit" style={{ marginTop: "1rem" }}>
          Create Administrator
        </button>
      </form>
    </div>
  );
}
