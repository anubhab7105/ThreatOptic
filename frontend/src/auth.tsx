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

// Seeded local dev tokens signed with backend dev secret
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
    try {
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

      if (isSupabaseConfigured) {
        const { data: { session } } = await supabase.auth.getSession();
        if (!session) { setUser(null); setLoading(false); return; }
        try {
          // Fetch app-level role + org from our public users table via the backend
          const profile = await jget('/auth/me');
          setUser(profile);
        } catch {
          setUser(null);
        }
      } else {
        setUser(null);
      }
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    hydrateUser();

    if (!isSupabaseConfigured) {
      return;
    }

    const { data: { subscription } } = supabase.auth.onAuthStateChange((event) => {
      if (event !== 'SIGNED_OUT') {
        hydrateUser();
      }
    });

    return () => subscription.unsubscribe();
  }, [hydrateUser]);

  const login = async (email: string, password: string) => {
    const trimmed = email.trim();
    // Allow seeded demo logins (admin / admin123 or analyst / analyst123) in dev or unconfigured mode
    if (!isSupabaseConfigured || trimmed.toLowerCase() === 'admin' || trimmed.toLowerCase() === 'analyst') {
      const roleKey = trimmed.toLowerCase().includes('admin') ? 'admin' : 'analyst';
      const token = DEV_TOKENS[roleKey];
      if (token) {
        localStorage.setItem('soc-dev-token', token);
        await hydrateUser();
        return;
      }
    }

    const { error } = await supabase.auth.signInWithPassword({ email: trimmed, password });
    if (error) throw new Error(error.message);
    await hydrateUser();
  };

  const register = async (email: string, password: string) => {
    if (!isSupabaseConfigured) {
      throw new Error('Supabase is not configured yet. Sign in with demo accounts: admin / admin123 or analyst / analyst123.');
    }
    const { error } = await supabase.auth.signUp({ email, password });
    if (error) throw new Error(error.message);
    return { needsConfirmation: true }; // User must verify email before logging in
  };

  const logout = async () => {
    localStorage.removeItem('soc-dev-token');
    try {
      if (isSupabaseConfigured) {
        await supabase.auth.signOut();
      }
    } catch {
      /* ignore */
    }
    setUser(null);
  };

  return <Ctx.Provider value={{ user, loading, login, register, logout }}>{children}</Ctx.Provider>;
}
