import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { supabase } from './supabaseClient';
import { jget } from './api';

export type AuthUser = { id: string; email: string; role: string; organization_id: string | null };

type AuthCtx = {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<{ needsConfirmation: boolean }>;
  logout: () => Promise<void>;
};

const Ctx = createContext<AuthCtx>({ user: null, loading: true, login: async () => {}, register: async () => ({ needsConfirmation: true }), logout: async () => {} });

export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const hydrateUser = useCallback(async () => {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) { setUser(null); setLoading(false); return; }
    try {
      // Fetch app-level role + org from our public users table via the backend
      const profile = await jget('/auth/me');
      setUser(profile);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    hydrateUser();
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, _session) => {
      hydrateUser();
    });
    return () => subscription.unsubscribe();
  }, [hydrateUser]);

  const login = async (email: string, password: string) => {
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw new Error(error.message);
    await hydrateUser();
  };

  const register = async (email: string, password: string) => {
    const { error } = await supabase.auth.signUp({ email, password });
    if (error) throw new Error(error.message);
    return { needsConfirmation: true }; // User must verify email before logging in
  };

  const logout = async () => {
    await supabase.auth.signOut();
    setUser(null);
  };

  return <Ctx.Provider value={{ user, loading, login, register, logout }}>{children}</Ctx.Provider>;
}
