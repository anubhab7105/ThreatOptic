import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { supabase, isSupabaseConfigured } from './supabaseClient';
import { jget } from './api';

export type AuthUser = { id: string; email: string; role: string; organization_id: string | null };

type AuthCtx = {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<{ needsConfirmation: boolean }>;
  logout: () => Promise<void>;
};

// Seeded local dev tokens signed with backend dev secret (dev_secret_key_local_development_super_secure_32_bytes_min)
// Only used when Supabase is completely unconfigured for offline local dev
const DEV_TOKENS: Record<string, string> = {
  admin: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI4MjZlNTdjYi03OGIyLTQ5OWItYTQxMS0xMWVlMjdmMzYzMDgiLCJlbWFpbCI6ImFkbWluIiwicm9sZSI6IkFkbWluIiwiYXVkIjoiYXV0aGVudGljYXRlZCIsImV4cCI6MTgyMjAxNjYwNX0.0Ji48Z_BIaUIMx749qp2yxQiW8C4h8QzPQXoOGQwZ8o',
  analyst: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzNTU0YmQxZC01MDQ2LTQ0NjctOWU5Zi1lOWIxNDQxODJkOGIiLCJlbWFpbCI6ImFuYWx5c3QiLCJyb2xlIjoiQW5hbHlzdCIsImF1ZCI6ImF1dGhlbnRpY2F0ZWQiLCJleHAiOjE4MjIwMTY2Mzd9.YQnR806pYZUR6nMaCBP95MbzjwJqpi8CQtQhsXKRXPQ',
};

const Ctx = createContext<AuthCtx>({ user: null, loading: true, login: async () => {}, register: async () => ({ needsConfirmation: true }), logout: async () => {} });

export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const hydrateUser = useCallback(async () => {
    // 1. If Supabase is configured, check Supabase session first
    if (isSupabaseConfigured) {
      try {
        const { data: { session } } = await supabase.auth.getSession();
        if (!session) { setUser(null); setLoading(false); return; }
        const profile = await jget('/auth/me');
        setUser(profile);
      } catch {
        setUser(null);
      } finally {
        setLoading(false);
      }
      return;
    }

    // 2. Fallback to local dev token only when Supabase is not configured
    const devToken = localStorage.getItem('soc-dev-token');
    if (devToken) {
      try {
        const profile = await jget('/auth/me');
        setUser(profile);
        setLoading(false);
        return;
      } catch {
        localStorage.removeItem('soc-dev-token');
      }
    }

    setUser(null);
    setLoading(false);
  }, []);

  useEffect(() => {
    hydrateUser();
    if (isSupabaseConfigured) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, _session) => {
        hydrateUser();
      });
      return () => subscription.unsubscribe();
    }
  }, [hydrateUser]);

  const login = async (email: string, password: string) => {
    if (password.length > 128) {
      throw new Error('Password must not exceed 128 characters.');
    }
    const trimmed = email.trim().toLowerCase();

    if (isSupabaseConfigured) {
      localStorage.removeItem('soc-dev-token');
      try {
        const { error } = await supabase.auth.signInWithPassword({ email: email.trim(), password });
        if (error) throw new Error(error.message);
        await hydrateUser();
        return;
      } catch (err: any) {
        if (err?.message?.includes('Failed to fetch')) {
          throw new Error('Could not connect to Supabase (Failed to fetch). Please check your internet connection or Supabase settings.');
        }
        throw err;
      }
    }

    // Fallback only when Supabase is unconfigured (offline local dev mode)
    const devToken = DEV_TOKENS[trimmed] || (trimmed === 'admin' ? DEV_TOKENS.admin : trimmed === 'analyst' ? DEV_TOKENS.analyst : null);
    if (devToken) {
      localStorage.setItem('soc-dev-token', devToken);
      await hydrateUser();
      return;
    }
    throw new Error('Supabase cloud auth is not configured. Configure SUPABASE_URL and SUPABASE_ANON_KEY in your environment.');
  };

  const register = async (email: string, password: string) => {
    if (password.length > 128) {
      throw new Error('Password must not exceed 128 characters.');
    }
    if (!isSupabaseConfigured) {
      throw new Error('Supabase cloud auth is not configured. Configure SUPABASE_URL and SUPABASE_ANON_KEY in your environment.');
    }
    const { error } = await supabase.auth.signUp({ email: email.trim(), password });
    if (error) throw new Error(error.message);
    return { needsConfirmation: true }; // User must verify email before logging in
  };

  const logout = async () => {
    localStorage.removeItem('soc-dev-token');
    if (isSupabaseConfigured) {
      try {
        await supabase.auth.signOut();
      } catch {
        /* ignore */
      }
    }
    setUser(null);
  };

  return <Ctx.Provider value={{ user, loading, login, register, logout }}>{children}</Ctx.Provider>;
}
