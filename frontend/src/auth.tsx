import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { clearTokens, getTokens, jget, jpost, setTokens } from './api';

export type AuthUser = { id: string; username: string; role: string; organization_id: string | null };

type AuthCtx = {
  user: AuthUser | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (username: string, password: string) => Promise<void>;
  logout: () => void;
};

const Ctx = createContext<AuthCtx>({ user: null, loading: true, login: async () => {}, register: async () => {}, logout: () => {} });

export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchMe = useCallback(async () => {
    if (!getTokens()) {
      setUser(null);
      setLoading(false);
      return;
    }
    try {
      setUser(await jget('/auth/me'));
    } catch {
      clearTokens();
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchMe();
    const on401 = () => {
      clearTokens();
      setUser(null);
    };
    window.addEventListener('soc:unauthorized', on401);
    return () => window.removeEventListener('soc:unauthorized', on401);
  }, [fetchMe]);

  const login = async (username: string, password: string) => {
    const pair = await jpost('/auth/login', { username, password }, { auth: false });
    setTokens(pair);
    setUser(await jget('/auth/me'));
  };

  const register = async (username: string, password: string) => {
    const pair = await jpost('/auth/register', { username, password }, { auth: false });
    setTokens(pair);
    setUser(await jget('/auth/me'));
  };

  const logout = () => {
    clearTokens();
    setUser(null);
  };

  return <Ctx.Provider value={{ user, loading, login, register, logout }}>{children}</Ctx.Provider>;
}
