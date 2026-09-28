import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

export type Theme = 'light' | 'dark';

/** Canonical storage key per Design.md §3. `soc-theme` is the legacy key (migrated). */
export const THEME_KEY = 'theme';
const LEGACY_KEY = 'soc-theme';

function readStored(): Theme | null {
  try {
    const v = localStorage.getItem(THEME_KEY);
    if (v === 'light' || v === 'dark') return v;
    // One-way migration from the pre-redesign key.
    const legacy = localStorage.getItem(LEGACY_KEY);
    if (legacy === 'light' || legacy === 'dark') {
      localStorage.setItem(THEME_KEY, legacy);
      return legacy;
    }
  } catch {
    /* storage unavailable */
  }
  return null;
}

function systemTheme(): Theme {
  try {
    if (typeof window !== 'undefined' && window.matchMedia) {
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
  } catch {
    /* ignore */
  }
  return 'light';
}

export function resolveTheme(): Theme {
  return readStored() ?? systemTheme();
}

export function applyTheme(t: Theme) {
  document.documentElement.setAttribute('data-theme', t);
  document.documentElement.style.colorScheme = t;
}

type ThemeCtx = { theme: Theme; setTheme: (t: Theme) => void };

const Ctx = createContext<ThemeCtx>({ theme: 'light', setTheme: () => {} });

export const useTheme = () => useContext(Ctx);

/** Provides `theme`/`setTheme`. Only JS-reading consumers (charts/map/graph) re-render. */
export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => {
    try {
      return resolveTheme();
    } catch {
      return 'light';
    }
  });

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  // Follow the OS only while the user has no stored preference.
  const [hasStored, setHasStored] = useState<boolean>(() => readStored() !== null);
  useEffect(() => {
    if (hasStored) return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = (e: MediaQueryListEvent) => setThemeState(e.matches ? 'dark' : 'light');
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [hasStored]);

  const setTheme = useCallback((t: Theme) => {
    try {
      localStorage.setItem(THEME_KEY, t);
      localStorage.setItem(LEGACY_KEY, t); // keep legacy readers in sync during migration
    } catch {
      /* storage unavailable */
    }
    setHasStored(true);
    setThemeState(t);
  }, []);

  const value = useMemo(() => ({ theme, setTheme }), [theme, setTheme]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
