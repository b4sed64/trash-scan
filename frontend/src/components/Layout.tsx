import { type ReactNode } from "react";
import { Link, NavLink } from "react-router-dom";
import { useAuth } from "../auth";
import { NotificationBell } from "./NotificationBell";
import { Raccoon } from "./Raccoon";

export function Layout({ children }: { children: ReactNode }) {
  const { me, logout } = useAuth();

  return (
    <div className="layout">
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-text">
            <h1>Trash Scan</h1>
            <small>Authorized Recon</small>
          </div>
          <Raccoon size={30} />
        </div>

        <Link to="/account" className="brand-account">
          <strong>{me?.username}</strong>
          <br />
          {me?.role}
        </Link>

        <NotificationBell />

        <nav aria-label="Primary" style={{ marginTop: "0.6rem" }}>
          <NavLink to="/" end>
            Dashboard
          </NavLink>
          <NavLink to="/targets">Targets</NavLink>
          <NavLink to="/scans">Scans</NavLink>
          {me?.role === "ADMINISTRATOR" && <NavLink to="/approvals">Approvals</NavLink>}
          <NavLink to="/audit">Logs</NavLink>
          {me?.role === "ADMINISTRATOR" && <NavLink to="/admin">Administration</NavLink>}
        </nav>

        <div className="spacer" />

        <button className="secondary" onClick={() => void logout()}>
          Log Out
        </button>

        <span className="sidebar-watermark" aria-hidden="true">
          🦝
        </span>
      </aside>

      <main className="content" id="main-content" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}
