import { FormEvent, useState } from "react";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";

export function Account() {
  const { me } = useAuth();
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setMsg("");
    if (next !== confirm) {
      setError("New password and confirmation do not match.");
      return;
    }
    try {
      await api.post("/api/auth/change-password", {
        current_password: cur,
        new_password: next,
      });
      setMsg("Password changed. Other sessions for your account have been signed out.");
      setCur("");
      setNext("");
      setConfirm("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not change password");
    }
  }

  return (
    <div>
      <h2>Your Account</h2>
      <section className="card">
        <p className="muted">
          {me?.username} · {me?.role}
        </p>
      </section>

      <section className="card" style={{ maxWidth: 460 }}>
        <h3>Change Password</h3>
        <form onSubmit={submit}>
          <label htmlFor="cur">Current password</label>
          <input
            id="cur"
            type="password"
            value={cur}
            onChange={(e) => setCur(e.target.value)}
            required
          />
          <label htmlFor="next">New password (min 12 characters)</label>
          <input
            id="next"
            type="password"
            minLength={12}
            value={next}
            onChange={(e) => setNext(e.target.value)}
            required
          />
          <label htmlFor="confirm">Confirm new password</label>
          <input
            id="confirm"
            type="password"
            minLength={12}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
          />
          {error && <p className="error">{error}</p>}
          {msg && <p className="notice">{msg}</p>}
          <button type="submit" style={{ marginTop: "0.8rem" }}>
            Change password
          </button>
        </form>
      </section>
    </div>
  );
}
