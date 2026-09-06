import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import { api, ApiError, Me } from "./api";

interface AuthState {
  me: Me | null;
  loading: boolean;
  needsSetup: boolean;
  refresh: () => Promise<void>;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [needsSetup, setNeedsSetup] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const status = await api.get<{ needs_setup: boolean }>("/api/auth/setup-status");
      setNeedsSetup(status.needs_setup);
      if (!status.needs_setup) {
        try {
          setMe(await api.get<Me>("/api/auth/me"));
        } catch (e) {
          if (e instanceof ApiError && e.status === 401) setMe(null);
          else throw e;
        }
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const login = useCallback(async (username: string, password: string) => {
    await api.post<Me>("/api/auth/login", { username, password });
    setMe(await api.get<Me>("/api/auth/me"));
  }, []);

  const logout = useCallback(async () => {
    await api.post("/api/auth/logout");
    setMe(null);
  }, []);

  return (
    <Ctx.Provider value={{ me, loading, needsSetup, refresh, login, logout }}>
      {children}
    </Ctx.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth outside provider");
  return ctx;
}
