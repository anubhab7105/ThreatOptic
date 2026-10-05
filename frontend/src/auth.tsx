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

// Offline dev fallback (LOCAL DEVELOPMENT ONLY — never for a deployed frontend).
// There are no hard-coded tokens or passwords here. When Supabase is completely
// unconfigured, login() below accepts the credentials provisioned via the root
// .env (Vite only exposes VITE_-prefixed keys to the browser):
//
//   VITE_ALLOW_DEV_AUTH=1          # explicit opt-in; fallback stays disabled without it
//   VITE_DEV_ADMIN_TOKEN=<jwt>     # dev-only JWT for username "admin"
//   VITE_DEV_ADMIN_PASSWORD=<pw>   # required — the username alone never authenticates
//   VITE_DEV_ANALYST_TOKEN=<jwt>   # dev-only JWT for username "analyst"
//   VITE_DEV_ANALYST_PASSWORD=<pw>
//
// The fallback additionally requires a dev build (import.meta.env.DEV), so a
// production build never honors these variables even if they were baked in by
// accident. The dev JWTs are signed with a local-only secret that a real
// deployment (with its own SUPABASE_JWT_SECRET) rejects, but do not rely on
// that alone: configure VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY in any
// deployed frontend and leave VITE_ALLOW_DEV_AUTH unset.
function readEnv(key: string): string {
  try {
    return ((import.meta as any).env?.[key] as string) || '';
  } catch {
    return '';
  }
}

function isTruthyFlag(value: string): boolean {
  return ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase());
}

function isDevFallbackAllowed(): boolean {
  try {
    const isDevBuild = Boolean((import.meta as any).env?.DEV);
    return !isSupabaseConfigured && isDevBuild && isTruthyFlag(readEnv('VITE_ALLOW_DEV_AUTH'));
  } catch {
    return false;
  }
}

type DevCredential = { username: string; token: string; password: string };

function getDevCredentials(): DevCredential[] {
  return [
    { username: 'admin', token: readEnv('VITE_DEV_ADMIN_TOKEN'), password: readEnv('VITE_DEV_ADMIN_PASSWORD') },
    { username: 'analyst', token: readEnv('VITE_DEV_ANALYST_TOKEN'), password: readEnv('VITE_DEV_ANALYST_PASSWORD') },
  ];
}

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

    // 2. Offline dev fallback: only when Supabase is unconfigured AND this is a
    // dev build with VITE_ALLOW_DEV_AUTH=1. Anything else clears a stale token
    // so a dev credential can never survive into a deployed session.
    if (!isDevFallbackAllowed()) {
      localStorage.removeItem('soc-dev-token');
      setUser(null);
      setLoading(false);
      return;
    }
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

    // Offline dev fallback only: Supabase unconfigured + dev build + explicit
    // VITE_ALLOW_DEV_AUTH=1. The password is always verified against the
    // matching VITE_DEV_*_PASSWORD — a username alone never authenticates.
    if (!isDevFallbackAllowed()) {
      throw new Error('Supabase cloud auth is not configured. Configure VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in your environment.');
    }
    const configured = getDevCredentials().filter((c) => c.token && c.password);
    if (configured.length === 0) {
      throw new Error('Supabase cloud auth is not configured, and offline dev login is not provisioned (missing VITE_DEV_*_TOKEN / VITE_DEV_*_PASSWORD).');
    }
    const match = configured.find((c) => c.username === trimmed);
    if (!match || password !== match.password) {
      throw new Error('Invalid username or password.');
    }
    localStorage.setItem('soc-dev-token', match.token);
    await hydrateUser();
    return;
  };

  const register = async (email: string, password: string) => {
    if (password.length > 128) {
      throw new Error('Password must not exceed 128 characters.');
    }
    if (!isSupabaseConfigured) {
      throw new Error('Supabase cloud auth is not configured. Configure VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in your environment.');
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
