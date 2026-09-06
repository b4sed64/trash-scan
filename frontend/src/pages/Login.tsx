import { FormEvent, useState } from "react";
import { ApiError } from "../api";
import { useAuth } from "../auth";
import { Raccoon } from "../components/Raccoon";

export function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    try {
      await login(username, password);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed");
    }
  }

  return (
    <div className="center-page">
      <form className="card" onSubmit={submit}>
        <div className="brand" style={{ justifyContent: "center", marginBottom: "0.5rem" }}>
          <Raccoon size={40} />
          <h1 style={{ fontSize: "1.4rem" }}>Trash Scan</h1>
        </div>
        <p className="muted" style={{ textAlign: "center", marginTop: 0 }}>
          Authorized Reconnaissance Dashboard
        </p>
        <label htmlFor="u">Username</label>
        <input id="u" value={username} onChange={(e) => setUsername(e.target.value)} required />
        <label htmlFor="p">Password</label>
        <input
          id="p"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        {error && <p className="error">{error}</p>}
        <button type="submit" style={{ marginTop: "1rem" }}>
          Log in
        </button>
      </form>
    </div>
  );
}
