import { useEffect, useState } from 'react';
import { SCENE_TOKEN_FALLBACKS, type SceneTokens } from './sceneTokens';

export type { SceneTokens };

function readTokens(): SceneTokens {
  const cs = getComputedStyle(document.documentElement);
  const get = (name: string, fallback: string) => cs.getPropertyValue(name).trim() || fallback;
  return {
    bg: get('--scene-bg', SCENE_TOKEN_FALLBACKS.bg),
    clay: get('--scene-clay', SCENE_TOKEN_FALLBACKS.clay),
    shade: get('--scene-clay-shade', SCENE_TOKEN_FALLBACKS.shade),
    accent: get('--scene-accent', SCENE_TOKEN_FALLBACKS.accent),
    line: get('--scene-line', SCENE_TOKEN_FALLBACKS.line),
    risk: get('--scene-risk', SCENE_TOKEN_FALLBACKS.risk),
  };
}


export function useSceneTokens(): SceneTokens {
  const [tokens, setTokens] = useState<SceneTokens>(() => {
    try {
      return readTokens();
    } catch {
      /* storage/DOM unavailable during SSR or tests */
      return { ...SCENE_TOKEN_FALLBACKS };
    }
  });
  useEffect(() => {
    const update = () => {
      try {
        setTokens(readTokens());
      } catch {
        /* keep last-known tokens when DOM is unavailable */
      }
    };
    const mo = new MutationObserver(update);
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
    return () => mo.disconnect();
  }, []);
  return tokens;
}
