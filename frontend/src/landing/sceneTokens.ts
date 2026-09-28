export type SceneTokens = {
  bg: string;
  clay: string;
  shade: string;
  accent: string;
  line: string;
  risk: string;
};

/**
 * Single source for --scene-* fallback values (Landing_Design.md §3, light
 * theme). Used only when the CSS variables cannot be read; the themed
 * variables on :root[data-theme] remain authoritative.
 */
export const SCENE_TOKEN_FALLBACKS: SceneTokens = {
  bg: '#DDE3ED',
  clay: '#E9EEF6',
  shade: '#BFC9DA',
  accent: '#4F46E5',
  line: 'rgba(27,35,51,0.35)',
  risk: '#B91C1C',
};
