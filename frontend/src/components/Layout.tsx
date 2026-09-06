import { type ReactNode } from "react";
import { Link, NavLink } from "react-router-dom";
import { useAuth } from "../auth";
import { NotificationBell } from "./NotificationBell";
import { RaccoonMask } from "./Raccoon";

export function Layout({ children }: { children: ReactNode }) {
  const { me, logout } = useAuth();

  return (
    <div className="layout">
      <a href="#main-content" className="skip-link">
        Skip to main content
      </a>
      <aside className="sidebar">
        <div className="brand">
          <RaccoonMask size={30} />
          <div>
            <h1>Trash Scan</h1>
            <small>Authorized recon</small>
          </div>
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
          <NavLink to="/audit">Audit trail</NavLink>
          {me?.role === "ADMINISTRATOR" && <NavLink to="/admin">Administration</NavLink>}
        </nav>

        <div className="spacer" />

        <button className="secondary" onClick={() => void logout()}>
          Log out
        </button>

        <div className="sidebar-watermark" aria-hidden="true">
          <RaccoonMask size={150} title="" />
        </div>
      </aside>

      <main className="content" id="main-content" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}
