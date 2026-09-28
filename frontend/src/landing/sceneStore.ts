import { create } from 'zustand';

/** Scroll progress 0..1 driving the pinned pipeline scene (M3). */
type SceneState = {
  progress: number;
  setProgress: (p: number) => void;
};

export const useSceneStore = create<SceneState>((set) => ({
  progress: 0,
  setProgress: (p) => set({ progress: Math.min(1, Math.max(0, p)) }),
}));
