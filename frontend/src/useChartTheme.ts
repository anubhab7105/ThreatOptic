import { useMemo } from 'react';
import { useTheme } from './theme';





export type ChartTokens = {
  theme: 'light' | 'dark';
  charts: [string, string, string, string, string, string];
  risk: { critical: string; high: string; medium: string; low: string };
  accentInfo: string;
  textPrimary: string;
  textMuted: string;
  grid: string;
  surfaceInset: string;
  surfaceRaised: string;
  border: string;
  onBright: string;
  entity: Record<string, string>;
};

function readVar(name: string, fallback: string): string {
  try {
    const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    return v || fallback;
  } catch {
    return fallback;
  }
}

export function readChartTokens(theme: 'light' | 'dark'): ChartTokens {
  const charts: [string, string, string, string, string, string] = [
    readVar('--chart-1', '#4F46E5'), readVar('--chart-2', '#0369A1'),
    readVar('--chart-3', '#6D28D9'), readVar('--chart-4', '#0F766E'),
    readVar('--chart-5', '#B45309'), readVar('--chart-6', '#BE123C'),
  ];


  const entity: Record<string, string> = {
    IP_Address: readVar('--teal', charts[3]),
    Domain: readVar('--correlation', charts[2]),
    Email_Address: readVar('--high', charts[4]),
    Threat_Campaign: readVar('--critical', charts[5]),
    Entity: readVar('--muted', '#8792A8'),
  };
  return {
    theme,
    charts,
    risk: {
      critical: readVar('--risk-critical', charts[5]),
      high: readVar('--risk-high', charts[4]),
      medium: readVar('--risk-medium', '#A16207'),
      low: readVar('--risk-low', charts[3]),
    },
    accentInfo: readVar('--accent-info', charts[1]),
    textPrimary: readVar('--text-primary', theme === 'dark' ? '#E6EAF3' : '#1B2333'),
    textMuted: readVar('--text-muted', theme === 'dark' ? '#8792A8' : '#56637A'),
    grid: readVar('--border-subtle', theme === 'dark' ? 'rgba(230,234,243,0.12)' : 'rgba(27,35,51,0.14)'),
    surfaceInset: readVar('--surface-inset', theme === 'dark' ? '#131824' : '#DDE3ED'),
    surfaceRaised: readVar('--surface-raised', theme === 'dark' ? '#202738' : '#E9EEF6'),
    border: readVar('--border-subtle', theme === 'dark' ? 'rgba(230,234,243,0.12)' : 'rgba(27,35,51,0.14)'),
    onBright: readVar('--text-on-bright', '#101828'),
    entity,
  };
}

export function useChartTheme(): ChartTokens {
  const { theme } = useTheme();


  return useMemo(() => {
    try {
      return readChartTokens(theme);
    } catch {
      return readChartTokens('light');
    }
  }, [theme]);
}
