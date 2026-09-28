import { useEffect, useState } from 'react';

export type SceneTokens = {
  bg: string;
  clay: string;
  shade: string;
  accent: string;
  line: string;
  risk: string;
};

function readTokens(): SceneTokens {
  const cs = getComputedStyle(document.documentElement);
  const get = (name: string, fallback: string) => cs.getPropertyValue(name).trim() || fallback;
  return {
    bg: get('--scene-bg', '#DDE3ED'),
    clay: get('--scene-clay', '#E9EEF6'),
    shade: get('--scene-clay-shade', '#BFC9DA'),
    accent: get('--scene-accent', '#4F46E5'),
    line: get('--scene-line', 'rgba(27,35,51,0.35)'),
    risk: get('--scene-risk', '#B91C1C'),
  };
}

/** Reads --scene-* CSS vars and updates on theme change without remounting the canvas. */
export function useSceneTokens(): SceneTokens {
  const [tokens, setTokens] = useState<SceneTokens>(() => {
    try {
      return readTokens();
    } catch {
      return { bg: '#DDE3ED', clay: '#E9EEF6', shade: '#BFC9DA', accent: '#4F46E5', line: 'rgba(27,35,51,0.35)', risk: '#B91C1C' };
    }
  });
  useEffect(() => {
    const update = () => {
      try {
        setTokens(readTokens());
      } catch {
        /* keep last */
      }
    };
    const mo = new MutationObserver(update);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => mo.disconnect();
  }, []);
  return tokens;
}
