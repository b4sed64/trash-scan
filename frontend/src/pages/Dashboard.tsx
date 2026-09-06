import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, NotificationItem, Target } from "../api";
import { RaccoonMask } from "../components/Raccoon";

export function Dashboard() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [notes, setNotes] = useState<NotificationItem[]>([]);

  useEffect(() => {
    void api.get<Target[]>("/api/targets").then(setTargets);
    void api
      .get<{ items: NotificationItem[] }>("/api/notifications")
      .then((n) => setNotes(n.items));
  }, []);

  async function markAll() {
    await api.post("/api/notifications/read-all");
    const n = await api.get<{ items: NotificationItem[] }>("/api/notifications");
    setNotes(n.items);
  }

  return (
    <div>
      <h2>Dashboard</h2>

      <section className="card">
        <h3>Targets in your scope ({targets.length})</h3>
        {targets.length === 0 ? (
          <div className="empty-state">
            <RaccoonMask size={56} />
            <p>No targets in your scope yet — ask an administrator to assign one.</p>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Kind</th>
                <th>Scope</th>
                <th>Assets</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((t) => (
                <tr key={t.id}>
                  <td>
                    <Link to={`/targets/${t.id}`}>{t.value}</Link>
                  </td>
                  <td>{t.kind}</td>
                  <td>
                    {t.is_public ? (
                      <span className="badge warn">Public · attested</span>
                    ) : (
                      <span className="badge">Private</span>
                    )}
                  </td>
                  <td>{t.assets.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card">
        <div style={{ display: "flex", justifyContent: "space-between" }}>
          <h3>Notifications</h3>
          <button className="secondary" onClick={() => void markAll()}>
            Mark all read
          </button>
        </div>
        {notes.length === 0 && <p className="muted">Nothing here yet.</p>}
        <ul>
          {notes.map((n) => (
            <li key={n.id} style={{ opacity: n.read_at ? 0.5 : 1 }}>
              <strong>{n.title}</strong>
              {n.body ? ` — ${n.body}` : ""}
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
