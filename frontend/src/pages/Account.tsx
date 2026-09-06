import { FormEvent, useState } from "react";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import { PasswordInput } from "../components/PasswordInput";

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
          <PasswordInput id="cur" value={cur} onChange={setCur} required
                         autoComplete="current-password" />
          <label htmlFor="next">New password (min 12 characters)</label>
          <PasswordInput id="next" value={next} onChange={setNext} minLength={12} required
                         autoComplete="new-password" />
          <label htmlFor="confirm">Confirm new password</label>
          <PasswordInput id="confirm" value={confirm} onChange={setConfirm} minLength={12} required
                         autoComplete="new-password" />
          {error && <p className="error">{error}</p>}
          {msg && <p className="notice">{msg}</p>}
          <button type="submit" style={{ marginTop: "0.8rem" }}>
            Change Password
          </button>
        </form>
      </section>
    </div>
  );
}
