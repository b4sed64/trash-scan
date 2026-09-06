import { type ReactNode, useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { api, NotificationItem } from "../api";
import { useAuth } from "../auth";

export function Layout({ children }: { children: ReactNode }) {
  const { me, logout } = useAuth();
  const [unread, setUnread] = useState(0);

  useEffect(() => {
    let active = true;
    const poll = () =>
      api
        .get<{ unread: number; items: NotificationItem[] }>("/api/notifications")
        .then((n) => active && setUnread(n.unread))
        .catch(() => undefined);
    void poll();
    const id = setInterval(poll, 15000);
    return () => {
      active = false;
      clearInterval(id);
    };
  }, []);

  return (
    <div className="layout">
      <aside className="sidebar">
        <h1>🦝 Trash Scan</h1>
        <nav aria-label="Primary">
          <NavLink to="/" end>
            Dashboard
          </NavLink>
          <NavLink to="/targets">Targets</NavLink>
          <NavLink to="/audit">Audit trail</NavLink>
          {me?.role === "ADMINISTRATOR" && <NavLink to="/admin">Administration</NavLink>}
        </nav>
        <hr style={{ borderColor: "var(--border)", margin: "1rem 0" }} />
        <p className="muted">
          {me?.username} · {me?.role}
        </p>
        <p className="muted" aria-live="polite">
          {unread} unread notification{unread === 1 ? "" : "s"}
        </p>
        <button className="secondary" onClick={() => void logout()}>
          Log out
        </button>
      </aside>
      <main className="content">{children}</main>
    </div>
  );
}
