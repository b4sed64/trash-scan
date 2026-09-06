import { FormEvent, useState } from "react";
import { ApiError } from "../api";
import { useAuth } from "../auth";
import { PasswordInput } from "../components/PasswordInput";
import { RaccoonMark } from "../components/RaccoonMark";

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
      setError(err instanceof ApiError ? err.message : "Login Failed");
    }
  }

  return (
    <div className="center-page" style={{ flexDirection: "column" }}>
      <div className="login-mark">
        <RaccoonMark size={104} />
      </div>
      <form className="card" onSubmit={submit}>
        <h1 style={{ textAlign: "center", margin: "0 0 0.1rem" }}>Trash Scan</h1>
        <p className="muted" style={{ textAlign: "center", marginTop: 0 }}>
          Authorized Reconnaissance Dashboard
        </p>
        <label htmlFor="u">Username</label>
        <input id="u" value={username} onChange={(e) => setUsername(e.target.value)} required />
        <label htmlFor="p">Password</label>
        <PasswordInput id="p" value={password} onChange={setPassword} required
                       autoComplete="current-password" />
        {error && <p className="error">{error}</p>}
        <button type="submit" style={{ marginTop: "1rem" }}>
          Log In
        </button>
      </form>
    </div>
  );
}
