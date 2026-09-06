import { useCallback, useEffect, useRef, useState } from "react";
import { api, NotificationItem } from "../api";

export function NotificationBell() {
  const [items, setItems] = useState<NotificationItem[]>([]);
  const [unread, setUnread] = useState(0);
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      const n = await api.get<{ unread: number; items: NotificationItem[] }>("/api/notifications");
      setItems(n.items);
      setUnread(n.unread);
    } catch {
      /* ignore transient errors */
    }
  }, []);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 15000);
    return () => clearInterval(t);
  }, [load]);

  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  async function markAll() {
    await api.post("/api/notifications/read-all");
    await load();
  }

  async function markOne(id: string) {
    await api.post(`/api/notifications/${id}/read`);
    await load();
  }

  return (
    <div className="bell-wrap" ref={wrapRef}>
      <button
        className="bell-btn"
        aria-haspopup="true"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true">
          <path
            fill="currentColor"
            d="M12 22a2.5 2.5 0 0 0 2.45-2h-4.9A2.5 2.5 0 0 0 12 22Zm7-6-1.6-1.6V9a5.4 5.4 0 0 0-4-5.2V3a1.4 1.4 0 0 0-2.8 0v.8A5.4 5.4 0 0 0 6.6 9v5.4L5 16a1 1 0 0 0 .7 1.7h12.6A1 1 0 0 0 19 16Z"
          />
        </svg>
        <span>Notifications</span>
        {unread > 0 && (
          <span className="bell-badge" aria-label={`${unread} unread`}>
            {unread}
          </span>
        )}
      </button>

      {open && (
        <div className="bell-panel" role="region" aria-label="Notifications">
          <header>
            <span>
              {items.length} notification{items.length === 1 ? "" : "s"}
            </span>
            {unread > 0 && (
              <button className="secondary" onClick={() => void markAll()}>
                Mark All Read
              </button>
            )}
          </header>
          <ul>
            {items.length === 0 && (
              <li className="b">Nothing to show. New activity lands here.</li>
            )}
            {items.slice(0, 40).map((n) => (
              <li
                key={n.id}
                className={n.read_at ? "" : "unread"}
                onClick={() => !n.read_at && void markOne(n.id)}
              >
                <span className="t">{n.title}</span>
                {n.body && <span className="b">{n.body}</span>}
                <span className="b" style={{ display: "block", fontSize: "0.75rem" }}>
                  {new Date(n.created_at).toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
